//! Exact-certificate retrieval remains available until all replicas finish
//! the epoch. A hash reference alone never authorizes a BFT vote.
use super::super::message_flow::{protocol_error, scoped_protocol, take_protocol_available};
use super::super::transport::BackgroundSender;
use super::super::{AutonomousConfig, DistributedError, DistributedMessage, SharedNode};
use ::silk_beacon::ValidationStatement;
use ::silk_beacon::protocol::proposal_encoding::CertificateId;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::thread::JoinHandle;
use std::time::Duration;

pub(super) type CertificateStore = Arc<Mutex<BTreeMap<CertificateId, Vec<ValidationStatement>>>>;
type ServiceResult = Result<Vec<serde_json::Value>, DistributedError>;

pub(super) fn request_scope(sample: u32) -> String {
    scoped_protocol("silk/beacon/certificate-request/v1", sample, 0)
}
pub(super) fn response_scope(sample: u32) -> String {
    scoped_protocol("silk/beacon/certificate-response/v1", sample, 0)
}

pub(super) struct CertificateService {
    pub store: CertificateStore,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<ServiceResult>>,
}

impl CertificateService {
    pub fn start(
        shared: &SharedNode,
        config: &AutonomousConfig,
        sample: u32,
    ) -> Result<Self, DistributedError> {
        let store = CertificateStore::default();
        let stop = Arc::new(AtomicBool::new(false));
        let service_store = Arc::clone(&store);
        let service_stop = Arc::clone(&stop);
        let shared = Arc::clone(shared);
        let config = config.clone();
        let handle = std::thread::Builder::new()
            .name(format!("silk-cert-{}-{sample}", config.node.node_id))
            .spawn(move || serve(&shared, &config, sample, &service_store, &service_stop))?;
        Ok(Self {
            store,
            stop,
            handle: Some(handle),
        })
    }

    pub fn finish(mut self) -> ServiceResult {
        self.stop.store(true, Ordering::Release);
        self.handle
            .take()
            .expect("certificate service")
            .join()
            .map_err(|_| protocol_error("certificate service panicked"))?
    }
}

impl Drop for CertificateService {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn serve(
    shared: &SharedNode,
    config: &AutonomousConfig,
    sample: u32,
    store: &CertificateStore,
    stop: &AtomicBool,
) -> ServiceResult {
    let cpu = cpu_time::ThreadTime::now();
    let request = request_scope(sample);
    let response = response_scope(sample);
    let mut pending = BTreeMap::<u32, BTreeSet<CertificateId>>::new();
    let mut served = BTreeMap::<u32, BTreeSet<CertificateId>>::new();
    let pump = BackgroundSender::get(shared)?;
    while !stop.load(Ordering::Acquire) {
        {
            let wait = if !pending.is_empty() {
                Duration::from_millis(1)
            } else {
                Duration::from_millis(20)
            };
            for (sender, message) in take_protocol_available(shared, &request, wait)? {
                if let DistributedMessage::BeaconCertificateRequest {
                    sample: received,
                    ids,
                } = message
                    && received == sample
                    && (sender as usize) < config.node.n
                    && ids.len() <= config.node.n
                {
                    let have = served.entry(sender).or_default();
                    let wanted = pending.entry(sender).or_default();
                    for id in ids {
                        // Bound unauthenticated requests, including never-resolved IDs.
                        if have.len() + wanted.len() < config.node.n * 16 && !have.contains(&id) {
                            wanted.insert(id);
                        }
                    }
                }
            }
            let mut responses = Vec::new();
            {
                let certificates = store
                    .lock()
                    .map_err(|_| protocol_error("certificate store poisoned"))?;
                for (sender, wanted) in &mut pending {
                    wanted.retain(|id| {
                        if let Some(statements) = certificates.get(id) {
                            responses.push((*sender, *id, statements.clone()));
                            served.entry(*sender).or_default().insert(*id);
                            false
                        } else {
                            true
                        }
                    });
                }
                // Empty sender entries must not keep the service in its
                // active 1-ms polling path after all requests were served.
                pending.retain(|_, wanted| !wanted.is_empty());
            }
            for (sender, id, statements) in responses {
                pump.enqueue_labeled(
                    shared,
                    config,
                    &response,
                    &DistributedMessage::BeaconCertificateResponse {
                        sample,
                        id,
                        statements,
                    },
                    &[sender],
                    "certificate-fetch-response",
                )?;
            }
        }
        pump.check_error()?;
    }
    let mut trace = Vec::new();
    trace.push(serde_json::json!({"event":"certificate-service-cpu", "thread_cpu_ns":cpu.elapsed().as_nanos() as u64}));
    Ok(trace)
}
