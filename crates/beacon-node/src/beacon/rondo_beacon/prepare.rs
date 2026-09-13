//! Breeze sharing reception, parallel verification, and resource sizing.

use super::*;

pub(in crate::beacon) fn rondo_parallel_workers() -> usize {
    protocol_support::compute::workers()
}

use crate::beacon::message_flow::take_protocol_available_bounded;
use crate::beacon::transport::BackgroundSender;
use ::rondo_beacon::protocol::VerifiedDealerMaterial;
use std::sync::atomic::{AtomicBool, Ordering};

pub(super) struct PreparationState {
    pub rows: BTreeMap<usize, RetainedDealer>,
    pub materials: BTreeMap<usize, VerifiedDealerMaterial>,
    pub error: Option<String>,
}
pub(super) struct RondoPreparation {
    pub setup: Arc<RondoSetup>,
    pub state: Arc<(Mutex<PreparationState>, Condvar)>,
    stop: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<Result<Vec<serde_json::Value>, DistributedError>>>,
}
impl Drop for RondoPreparation {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}
impl RondoPreparation {
    pub fn start(
        shared: &SharedNode,
        config: &AutonomousConfig,
        sample: u32,
        setup: RondoSetup,
    ) -> Result<Self, DistributedError> {
        let setup = Arc::new(setup);
        let state = Arc::new((
            Mutex::new(PreparationState {
                rows: BTreeMap::new(),
                materials: BTreeMap::new(),
                error: None,
            }),
            Condvar::new(),
        ));
        let stop = Arc::new(AtomicBool::new(false));
        let worker_setup = Arc::clone(&setup);
        let worker_state = Arc::clone(&state);
        let worker_stop = Arc::clone(&stop);
        let shared = Arc::clone(shared);
        let config = config.clone();
        let handle = std::thread::Builder::new()
            .name(format!("rondo-prepare-{}-{sample}", config.node.node_id))
            .spawn(move || {
                let result = serve_preparation(
                    &shared,
                    &config,
                    sample,
                    worker_setup,
                    &worker_state,
                    &worker_stop,
                );
                if let Err(error) = &result {
                    worker_state.0.lock().expect("preparation state").error =
                        Some(error.to_string());
                    worker_state.1.notify_all();
                }
                result
            })?;
        Ok(Self {
            setup,
            state,
            stop,
            handle: Some(handle),
        })
    }
    pub fn finish(mut self) -> Result<Vec<serde_json::Value>, DistributedError> {
        self.stop.store(true, Ordering::Release);
        self.handle
            .take()
            .expect("preparation service")
            .join()
            .map_err(|_| protocol_error("Rondo preparation panicked"))?
    }
    pub fn candidate(&self, threshold: usize) -> Result<RondoEpoch, DistributedError> {
        let deadline = Instant::now() + Duration::from_secs(300);
        let mut state = self
            .state
            .0
            .lock()
            .map_err(|_| protocol_error("Rondo preparation poisoned"))?;
        loop {
            if let Some(error) = &state.error {
                return Err(protocol_error(error));
            }
            if state.materials.len() >= threshold {
                break;
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(protocol_error("Rondo certified-dealer quorum timed out"));
            }
            state = self
                .state
                .1
                .wait_timeout(state, deadline - now)
                .map_err(|_| protocol_error("Rondo preparation poisoned"))?
                .0;
        }
        self.setup
            .finish_preverified_epoch(
                &state.rows,
                state.materials.values().take(threshold).cloned().collect(),
            )
            .map_err(protocol_error)
    }
    pub fn proposal_epoch(
        &self,
        request: &::rondo_beacon::bft::Request,
        publics: Vec<::rondo_beacon::protocol::BreezePublicData>,
    ) -> Result<RondoEpoch, DistributedError> {
        let payload: ::rondo_beacon::FirstRoundPayload = canonical_deserialize(&request.payload)?;
        if publics.len() != payload.entries.len()
            || publics.len() != self.setup.local_public().params.d
        {
            return Err(protocol_error("Rondo first proposal public set mismatch"));
        }
        let mut materials = Vec::new();
        for (entry, public) in payload.entries.iter().zip(publics) {
            if entry.dealer_id != public.dealer_id
                || entry.commitment_root != public.commitment_root
            {
                return Err(protocol_error(
                    "Rondo first proposal public binding mismatch",
                ));
            }
            let cached = self
                .state
                .0
                .lock()
                .map_err(|_| protocol_error("Rondo preparation poisoned"))?
                .materials
                .get(&entry.dealer_id)
                .filter(|cached| {
                    cached.qc() == &entry.validation
                        && canonical_serialize(cached.public()).ok()
                            == canonical_serialize(&public).ok()
                })
                .cloned();
            materials.push(match cached {
                Some(cached) => cached,
                None => self
                    .setup
                    .verify_dealer_material(public, entry.validation.clone())
                    .map_err(protocol_error)?,
            });
        }
        let epoch = self
            .setup
            .finish_preverified_epoch(
                &self.state.0.lock().map_err(protocol_error)?.rows,
                materials,
            )
            .map_err(protocol_error)?;
        if !epoch.validate_request(request) {
            return Err(protocol_error(
                "Rondo first proposal failed external validity",
            ));
        }
        Ok(epoch)
    }
}

fn serve_preparation(
    shared: &SharedNode,
    config: &AutonomousConfig,
    sample: u32,
    setup: Arc<RondoSetup>,
    state: &Arc<(Mutex<PreparationState>, Condvar)>,
    stop: &AtomicBool,
) -> Result<Vec<serde_json::Value>, DistributedError> {
    let cpu = cpu_time::ThreadTime::now();
    let share_protocol = scoped_protocol(SHARE_PROTOCOL, sample, 0);
    let validation_protocol = scoped_protocol(VALIDATION_PROTOCOL, sample, 0);
    let validated_protocol = scoped_protocol(VALIDATED_PROTOCOL, sample, 0);
    let receivers = (0..config.node.n as u32).collect::<Vec<_>>();
    let pump = BackgroundSender::get(shared)?;
    for receiver in &receivers {
        let share = setup.local_share(*receiver).map_err(protocol_error)?;
        pump.enqueue_labeled(
            shared,
            config,
            &share_protocol,
            &DistributedMessage::RondoShare {
                sample,
                public: share.public,
                row: share.row,
                proof: Box::new(share.proof),
            },
            &[*receiver],
            "rondo-prepare-share",
        )?;
    }
    let mut store = ProtocolStore::open(config.node.store_root.join("rondo-breeze-rows.bin"))?;
    let mut approved = BTreeSet::new();
    let mut pending = BTreeSet::new();
    type ShareResult = (
        u32,
        Result<
            (
                RetainedDealer,
                ::rondo_beacon::protocol::BreezeValidationCertificate,
            ),
            ::rondo_beacon::protocol::RondoError,
        >,
    );
    enum Completion {
        Share(Box<ShareResult>),
        Approval(
            u32,
            Result<
                ::rondo_beacon::protocol::VerifiedLocalValidationCertificate,
                ::rondo_beacon::protocol::RondoError,
            >,
        ),
        Material(
            u32,
            Box<Result<VerifiedDealerMaterial, ::rondo_beacon::protocol::RondoError>>,
        ),
    }
    let mut pending_approvals = BTreeSet::new();
    let mut pending_materials = BTreeSet::new();
    let mut jobs: crate::beacon::compute_queue::ComputeQueue<Completion> =
        crate::beacon::compute_queue::ComputeQueue::new(shared);
    let mut approvals = BTreeMap::new();
    let mut issued = false;
    loop {
        if stop.load(Ordering::Acquire) {
            break;
        } else {
            for completed in jobs.drain()? {
                let (sender, result) = match completed {
                    Completion::Share(share) => *share,
                    Completion::Approval(sender, result) => {
                        pending_approvals.remove(&sender);
                        if !issued
                            && approvals.len() < config.node.n - config.node.t
                            && let Ok(certificate) = result
                        {
                            approvals.insert(sender, certificate);
                        }
                        continue;
                    }
                    Completion::Material(sender, result) => {
                        pending_materials.remove(&sender);
                        if let Ok(material) = *result {
                            let mut data = state.0.lock().map_err(protocol_error)?;
                            if data.materials.len() <= config.node.t {
                                data.materials
                                    .entry(material.dealer_id())
                                    .or_insert(material);
                            }
                        }
                        state.1.notify_all();
                        continue;
                    }
                };
                pending.remove(&sender);
                if let Ok((retained, certificate)) = result {
                    retained.persist(&mut store).map_err(protocol_error)?;
                    state
                        .0
                        .lock()
                        .map_err(protocol_error)?
                        .rows
                        .insert(retained.dealer_id(), retained);
                    pump.enqueue_labeled(
                        shared,
                        config,
                        &validation_protocol,
                        &DistributedMessage::RondoValidation {
                            sample,
                            certificate,
                        },
                        &[sender],
                        "rondo-prepare-approval",
                    )?;
                    approved.insert(sender);
                }
            }
            if jobs.has_capacity() {
                for (sender, message) in
                    take_protocol_available_bounded(shared, &share_protocol, Duration::ZERO, 1)?
                {
                    if !approved.contains(&sender)
                        && !pending.contains(&sender)
                        && let DistributedMessage::RondoShare {
                            sample: got,
                            public,
                            row,
                            proof,
                        } = message
                        && got == sample
                    {
                        let setup = Arc::clone(&setup);
                        pending.insert(sender);
                        jobs.submit(move || {
                            Completion::Share(Box::new((
                                sender,
                                setup.accept_share(
                                    sender,
                                    RondoShare {
                                        public,
                                        row,
                                        proof: *proof,
                                    },
                                ),
                            )))
                        });
                    }
                }
            }
            for (sender, message) in take_protocol_available_bounded(
                shared,
                &validation_protocol,
                Duration::ZERO,
                usize::from(jobs.has_capacity()),
            )? {
                if !issued
                    && !approvals.contains_key(&sender)
                    && !pending_approvals.contains(&sender)
                    && let DistributedMessage::RondoValidation {
                        sample: got,
                        certificate,
                    } = message
                    && got == sample
                {
                    let setup = Arc::clone(&setup);
                    pending_approvals.insert(sender);
                    jobs.submit(move || {
                        Completion::Approval(
                            sender,
                            setup.accept_local_validation_certificate(sender, certificate),
                        )
                    });
                }
            }
            if !issued && approvals.len() == config.node.n - config.node.t {
                let qc = setup
                    .collect_validation_qc(std::mem::take(&mut approvals).into_values().collect())
                    .map_err(protocol_error)?;
                pump.enqueue_labeled(
                    shared,
                    config,
                    &validated_protocol,
                    &DistributedMessage::RondoValidated {
                        sample,
                        public: setup.local_public().clone(),
                        qc,
                    },
                    &receivers,
                    "rondo-prepare-certificate",
                )?;
                issued = true;
            }
            for (sender, message) in take_protocol_available_bounded(
                shared,
                &validated_protocol,
                Duration::ZERO,
                usize::from(jobs.has_capacity()),
            )? {
                let data = state
                    .0
                    .lock()
                    .map_err(|_| protocol_error("Rondo preparation poisoned"))?;
                let needed = data.materials.len() <= config.node.t
                    && !data.materials.contains_key(&(sender as usize));
                drop(data);
                if needed
                    && !pending_materials.contains(&sender)
                    && let DistributedMessage::RondoValidated {
                        sample: got,
                        public,
                        qc,
                    } = message
                    && got == sample
                    && sender as usize == public.dealer_id
                {
                    let setup = Arc::clone(&setup);
                    pending_materials.insert(sender);
                    jobs.submit(move || {
                        Completion::Material(
                            sender,
                            Box::new(setup.verify_dealer_material(public, qc)),
                        )
                    });
                }
                state.1.notify_all();
            }
        }
        pump.check_error()?;
        if approved.len() == config.node.n
            && issued
            && state.0.lock().map_err(protocol_error)?.materials.len() > config.node.t
        {
            // All local retention and dissemination obligations are complete.
            // Proposal validation can still use the shared immutable cache.
            break;
        }
        {
            if jobs.has_capacity() {
                jobs.wait(&[&share_protocol, &validation_protocol, &validated_protocol])?;
            } else {
                jobs.wait(&[])?;
            }
        }
    }
    let mut trace = Vec::new();
    trace.push(
        serde_json::json!({"event":"preparation-service-cpu", "approved_dealers":approved.len(),
        "issued_certificate":issued,"thread_cpu_ns":cpu.elapsed().as_nanos() as u64}),
    );
    Ok(trace)
}
