//! Threshold-driven Prepare; participation continues until epoch retirement.
use super::certificate_service::CertificateStore;
use super::materials::CertifiedMaterialCache;
use super::{EpochProtocols, PreparedEpoch, SilkSampleContext};
use crate::beacon::message_flow::{
    protocol_error, scoped_protocol, take_protocol_available_bounded,
};
use crate::beacon::observation::{measured, unix_time_ns};
use crate::beacon::transport::BackgroundSender;
use crate::beacon::{AutonomousConfig, DistributedError, DistributedMessage, SharedNode};
use ::silk_beacon::protocol::proposal_encoding::certificate_id;
use ::silk_beacon::protocol::{
    DealerPublicTranscript, PUBLIC_PROTOCOL, PrivateRow, ROW_PROTOCOL, SilkProtocol, SilkSharing,
};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{
    Arc, Condvar, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

pub(super) struct PreparationState {
    pub sharing: SilkSharing,
    pub materials: CertifiedMaterialCache,
    pub wanted_publics: BTreeSet<u32>,
    pub error: Option<String>,
}
pub(super) type SharedPreparation = Arc<(Mutex<PreparationState>, Condvar)>;
pub(super) struct PreparationService {
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<Result<Vec<serde_json::Value>, DistributedError>>>,
}
impl PreparationService {
    pub fn finish(mut self) -> Result<Vec<serde_json::Value>, DistributedError> {
        self.stop.store(true, Ordering::Release);
        self.handle
            .take()
            .expect("preparation service")
            .join()
            .map_err(|_| protocol_error("preparation service panicked"))?
    }
}
impl Drop for PreparationService {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

pub(super) fn prepare(
    context: &mut SilkSampleContext<'_>,
    silk: &Arc<SilkProtocol>,
    store: &CertificateStore,
) -> Result<PreparedEpoch, DistributedError> {
    let shared_state = Arc::new((
        Mutex::new(PreparationState {
            sharing: silk.begin_sharing(),
            materials: CertifiedMaterialCache::new(),
            wanted_publics: BTreeSet::new(),
            error: None,
        }),
        Condvar::new(),
    ));
    let service = measured(
        context.shared,
        context.config,
        context.logger,
        context.process_start,
        context.sample,
        "share-private-rows-and-publish-dictionaries",
        None,
        None,
        || {
            let (public, rows) = silk.dealer_share().map_err(protocol_error)?;
            let stop = Arc::new(AtomicBool::new(false));
            let worker_stop = Arc::clone(&stop);
            let state = Arc::clone(&shared_state);
            let network = Arc::clone(context.shared);
            let config = context.config.clone();
            let sample = context.sample;
            let silk = Arc::clone(silk);
            let store = Arc::clone(store);
            let handle = std::thread::Builder::new()
                .name(format!("silk-prepare-{}-{sample}", config.node.node_id))
                .spawn(move || {
                    let result = serve(
                        &network,
                        &config,
                        sample,
                        silk,
                        &state,
                        &store,
                        &worker_stop,
                        public,
                        rows,
                    );
                    if let Err(error) = &result {
                        state.0.lock().expect("preparation state").error = Some(error.to_string());
                        state.1.notify_all();
                    }
                    result
                })?;
            Ok((
                PreparationService {
                    stop,
                    handle: Some(handle),
                },
                None,
            ))
        },
    )?;
    let materials = measured(
        context.shared,
        context.config,
        context.logger,
        context.process_start,
        context.sample,
        "incremental-parverify-approval-sign-send",
        None,
        None,
        || {
            let deadline = Instant::now() + Duration::from_secs(300);
            let mut state = shared_state
                .0
                .lock()
                .map_err(|_| protocol_error("preparation state poisoned"))?;
            loop {
                if let Some(error) = &state.error {
                    return Err(protocol_error(error));
                }
                if state.materials.len() > context.config.node.t {
                    break;
                }
                let now = Instant::now();
                if now >= deadline {
                    return Err(protocol_error("Silk preparation quorum timed out"));
                }
                state = shared_state
                    .1
                    .wait_timeout(state, deadline - now)
                    .map_err(|_| protocol_error("preparation state poisoned"))?
                    .0;
            }
            Ok((state.materials.clone(), None))
        },
    )?;
    Ok(PreparedEpoch {
        state: shared_state,
        certified_materials: materials,
        service,
    })
}

#[allow(clippy::too_many_arguments)]
fn serve(
    network: &SharedNode,
    config: &AutonomousConfig,
    sample: u32,
    silk: Arc<SilkProtocol>,
    state: &SharedPreparation,
    store: &CertificateStore,
    stop: &AtomicBool,
    public: DealerPublicTranscript,
    initial_rows: Vec<PrivateRow>,
) -> Result<Vec<serde_json::Value>, DistributedError> {
    let cpu = cpu_time::ThreadTime::now();
    let protocols = EpochProtocols::new(sample);
    let public_protocol = scoped_protocol(PUBLIC_PROTOCOL, sample, 0);
    let row_protocol = scoped_protocol(ROW_PROTOCOL, sample, 0);
    let receivers = (0..config.node.n as u32).collect::<Vec<_>>();
    let pump = BackgroundSender::get(network)?;
    pump.enqueue_labeled(
        network,
        config,
        &public_protocol,
        &DistributedMessage::BeaconPublicTranscript {
            sample,
            transcript: public,
        },
        &receivers,
        "prepare-public",
    )?;
    for row in initial_rows {
        let receiver = row.receiver;
        pump.enqueue_labeled(
            network,
            config,
            &row_protocol,
            &DistributedMessage::BeaconPrivateRow { sample, row },
            &[receiver],
            "prepare-row",
        )?;
    }
    let mut publics = BTreeMap::<u32, DealerPublicTranscript>::new();
    let mut rows = BTreeMap::new();
    let mut approved = BTreeSet::new();
    let mut pending = BTreeSet::new();
    let mut jobs = crate::beacon::compute_queue::ComputeQueue::new(network);
    let mut approvals = BTreeMap::new();
    let mut issued = false;
    let mut certificates = BTreeMap::new();
    let mut verified_certificates = BTreeSet::new();
    let mut trace = Vec::new();
    loop {
        if stop.load(Ordering::Acquire) {
            break;
        } else {
            for (sender, message) in
                take_protocol_available_bounded(network, &public_protocol, Duration::ZERO, 1)?
            {
                if let DistributedMessage::BeaconPublicTranscript {
                    sample: got,
                    transcript,
                } = message
                    && got == sample
                    && sender == transcript.dealer
                    && (sender as usize) < config.node.n
                    && !approved.contains(&sender)
                {
                    publics.insert(sender, transcript);
                }
            }
            for (sender, message) in
                take_protocol_available_bounded(network, &row_protocol, Duration::ZERO, 1)?
            {
                if let DistributedMessage::BeaconPrivateRow { sample: got, row } = message
                    && got == sample
                    && sender == row.dealer
                    && (sender as usize) < config.node.n
                    && !approved.contains(&sender)
                {
                    rows.entry(sender).or_insert(row);
                }
            }
            for (dealer, result) in jobs.drain()? {
                pending.remove(&dealer);
                if let Ok((verified, statement, event)) = result {
                    // Public-only material may arrive while row verification
                    // is in flight. A dealer's conflicting transcript is a
                    // rejected input, not a fatal preparation-service error.
                    if silk
                        .merge_verified_sharing(
                            &mut state.0.lock().map_err(protocol_error)?.sharing,
                            verified,
                        )
                        .is_err()
                    {
                        continue;
                    }
                    pump.enqueue_labeled(
                        network,
                        config,
                        &protocols.validation,
                        &DistributedMessage::BeaconValidationStatement { sample, statement },
                        &[dealer],
                        "prepare-approval",
                    )?;
                    approved.insert(dealer);
                    publics.remove(&dealer);
                    trace.push(event);
                }
            }
            while jobs.has_capacity()
                && let Some(dealer) = publics
                    .keys()
                    .find(|dealer| rows.contains_key(dealer) && !pending.contains(*dealer))
                    .copied()
            {
                let public = publics.get(&dealer).expect("public").clone();
                let row = rows.remove(&dealer).expect("row");
                let silk = Arc::clone(&silk);
                pending.insert(dealer);
                jobs.submit(move || {
                    let result = (|| {
                        let start = unix_time_ns()?;
                        let timer = cpu_time::ThreadTime::now();
                        let mut verified = silk.begin_sharing();
                        silk.accept_dealer_sharing(&mut verified, dealer, public, row).map_err(protocol_error)?;
                        let verify_end = unix_time_ns()?;
                        let verify_cpu = timer.elapsed().as_nanos() as u64;
                        let timer = cpu_time::ThreadTime::now();
                        let statement = silk.validation_statement(&verified, dealer).map_err(protocol_error)?;
                        let sign_end = unix_time_ns()?;
                        let sign_cpu = timer.elapsed().as_nanos() as u64;
                        let event = serde_json::json!({"event":"prepare-dealer-verified-approved", "dealer":dealer,
                            "start_unix_ns":start,"verify_end_unix_ns":verify_end,"sign_end_unix_ns":sign_end,
                            "unix_ns":sign_end,"verify_cpu_ns":verify_cpu,"sign_cpu_ns":sign_cpu,
                            "send_boundary":"worker complete; queued after verified state merge"});
                        Ok::<_, DistributedError>((verified, statement, event))
                    })();
                    (dealer, result)
                });
            }
            for (sender, message) in
                take_protocol_available_bounded(network, &protocols.validation, Duration::ZERO, 1)?
            {
                if !issued
                    && !approvals.contains_key(&sender)
                    && let DistributedMessage::BeaconValidationStatement {
                        sample: got,
                        statement,
                    } = message
                    && got == sample
                    && let Ok(statement) =
                        silk.accept_validation_statement(config.node.node_id, sender, statement)
                {
                    approvals.insert(sender, statement);
                }
            }
            if !issued && approvals.len() == config.node.n - config.node.t {
                let statements = silk
                    .accept_validation_statements_preverified(
                        config.node.node_id,
                        std::mem::take(&mut approvals).into_values().collect(),
                    )
                    .map_err(protocol_error)?;
                let entry = ::silk_beacon::CertifiedTranscript {
                    dealer: config.node.node_id,
                    transcript_id: statements[0].transcript_id,
                };
                store
                    .lock()
                    .map_err(|_| protocol_error("certificate store poisoned"))?
                    .insert(
                        certificate_id(sample as u64 + 1, &entry, &statements)
                            .map_err(protocol_error)?,
                        statements.clone(),
                    );
                pump.enqueue_labeled(
                    network,
                    config,
                    &protocols.certified_dealer,
                    &DistributedMessage::BeaconCertifiedDealer {
                        sample,
                        dealer: config.node.node_id,
                        statements,
                    },
                    &receivers,
                    "prepare-certificate",
                )?;
                issued = true;
            }
            for (sender, message) in take_protocol_available_bounded(
                network,
                &protocols.certified_dealer,
                Duration::ZERO,
                1,
            )? {
                if let DistributedMessage::BeaconCertifiedDealer {
                    sample: got,
                    dealer,
                    statements,
                } = message
                    && got == sample
                    && sender == dealer
                    && (dealer as usize) < config.node.n
                    && statements.len() == config.node.n - config.node.t
                    && !certificates.contains_key(&dealer)
                    && !verified_certificates.contains(&dealer)
                    && statements.iter().all(|statement| {
                        statement.dealer == dealer
                            && statement.transcript_id == statements[0].transcript_id
                            && (statement.signer as usize) < config.node.n
                    })
                    && statements
                        .iter()
                        .map(|statement| statement.signer)
                        .collect::<BTreeSet<_>>()
                        .len()
                        == statements.len()
                {
                    let entry = ::silk_beacon::CertifiedTranscript {
                        dealer,
                        transcript_id: statements[0].transcript_id,
                    };
                    let id = certificate_id(sample as u64 + 1, &entry, &statements)
                        .map_err(protocol_error)?;
                    store
                        .lock()
                        .map_err(|_| protocol_error("certificate store poisoned"))?
                        .entry(id)
                        .or_insert_with(|| statements.clone());
                    certificates.entry(dealer).or_insert(statements);
                }
            }
            let mut data = state
                .0
                .lock()
                .map_err(|_| protocol_error("preparation state poisoned"))?;
            let wanted = data
                .wanted_publics
                .iter()
                .copied()
                .chain(
                    certificates
                        .keys()
                        .copied()
                        .filter(|_| data.materials.len() <= config.node.t),
                )
                .collect::<BTreeSet<_>>();
            for dealer in wanted {
                if let Some(public) = publics.get(&dealer)
                    && !silk.has_public_materials(&data.sharing, &[dealer])
                    && silk
                        .accept_public_material(&mut data.sharing, dealer, public.clone())
                        .is_err()
                {
                    publics.remove(&dealer);
                }
            }
            if data.materials.len() <= config.node.t {
                let ready = certificates
                    .keys()
                    .copied()
                    .filter(|dealer| {
                        silk.has_public_materials(&data.sharing, &[*dealer])
                            && !data.materials.keys().any(|entry| entry.dealer == *dealer)
                    })
                    .collect::<Vec<_>>();
                drop(data);
                for dealer in ready {
                    if state.0.lock().map_err(protocol_error)?.materials.len() > config.node.t {
                        break;
                    }
                    let statements = certificates.remove(&dealer).expect("certificate");
                    let entry = ::silk_beacon::CertifiedTranscript {
                        dealer,
                        transcript_id: statements[0].transcript_id,
                    };
                    let id = certificate_id(sample as u64 + 1, &entry, &statements)
                        .map_err(protocol_error)?;
                    if let Ok(material) = silk.accept_validation_certificate(dealer, statements)
                        && let Ok(entry) = silk.certified_transcript(&material)
                    {
                        state
                            .0
                            .lock()
                            .map_err(protocol_error)?
                            .materials
                            .insert(entry, material);
                        verified_certificates.insert(dealer);
                    } else {
                        store
                            .lock()
                            .map_err(|_| protocol_error("certificate store poisoned"))?
                            .remove(&id);
                    }
                }
            } else {
                drop(data);
            }
            state.1.notify_all();
        }
        pump.check_error()?;
        if approved.len() == config.node.n
            && issued
            && certificates.len() + verified_certificates.len() == config.node.n
        {
            break;
        }
        {
            jobs.wait(&[
                &public_protocol,
                &row_protocol,
                &protocols.validation,
                &protocols.certified_dealer,
            ])?;
        }
    }

    trace.push(serde_json::json!({"event":"preparation-service-cpu", "thread_cpu_ns":cpu.elapsed().as_nanos() as u64,
        "approved_dealers":approved.len(),"issued_certificate":issued}));
    Ok(trace)
}
