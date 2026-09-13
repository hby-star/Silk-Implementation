//! Compact aggregate-share broadcast and threshold-set reconstruction.

use super::*;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;

const FALLBACK_SERVICE_POLL: Duration = Duration::from_millis(100);
const FALLBACK_COLLECTION_TIMEOUT: Duration = Duration::from_secs(300);

pub(super) struct FallbackService {
    shared: SharedNode,
    stop: Arc<AtomicBool>,
    error: Arc<Mutex<Option<String>>>,
    handle: Option<JoinHandle<()>>,
}

impl FallbackService {
    pub(super) fn stop(mut self) -> Result<(), DistributedError> {
        self.stop_and_join();
        if let Some(error) = self
            .error
            .lock()
            .map_err(|_| DistributedError::Protocol("fallback service lock poisoned".into()))?
            .take()
        {
            return Err(DistributedError::Protocol(error));
        }
        Ok(())
    }

    fn stop_and_join(&mut self) {
        self.stop.store(true, Ordering::Release);
        self.shared.1.notify_all();
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for FallbackService {
    fn drop(&mut self) {
        self.stop_and_join();
    }
}

pub(super) fn start_fallback_service(
    shared: &SharedNode,
    config: &AutonomousConfig,
    sample: u32,
    epoch: Arc<RondoEpoch>,
) -> Result<FallbackService, DistributedError> {
    let request_protocol = scoped_protocol(FALLBACK_REQUEST_PROTOCOL, sample, 0);
    let service_shared = Arc::clone(shared);
    let service_config = config.clone();
    let stop = Arc::new(AtomicBool::new(false));
    let service_stop = Arc::clone(&stop);
    let error = Arc::new(Mutex::new(None));
    let service_error = Arc::clone(&error);
    let handle = std::thread::Builder::new()
        .name(format!("rondo-fallback-{}-{sample}", config.node.node_id))
        .spawn(move || {
            let result = run_fallback_service(
                &service_shared,
                &service_config,
                sample,
                &request_protocol,
                epoch.as_ref(),
                &service_stop,
            );
            if let Err(error) = result
                && let Ok(mut stored) = service_error.lock()
            {
                *stored = Some(error.to_string());
            }
        })?;
    Ok(FallbackService {
        shared: Arc::clone(shared),
        stop,
        error,
        handle: Some(handle),
    })
}

fn run_fallback_service(
    shared: &SharedNode,
    config: &AutonomousConfig,
    sample: u32,
    request_protocol: &str,
    epoch: &RondoEpoch,
    stop: &AtomicBool,
) -> Result<(), DistributedError> {
    let verifier = epoch
        .bft_replica(config.node.node_id, config.node.seed)
        .map_err(protocol_error)?;
    let mut served = BTreeSet::new();
    while !stop.load(Ordering::Acquire) {
        let requests = take_protocol_available(shared, request_protocol, FALLBACK_SERVICE_POLL)?;
        for (sender, message) in requests {
            let DistributedMessage::RondoFallbackRequest {
                sample: message_sample,
                slot,
                proof,
            } = message
            else {
                continue;
            };
            if message_sample != sample
                || sender as usize >= config.node.n
                || served.contains(&slot)
                || verifier.verify_decision_proof(&proof).is_err()
                || proof.block().request.sequence != slot as u64 + 1
                || !epoch.validate_request(&proof.block().request)
            {
                continue;
            }
            let Some(share) = epoch
                .fallback_share(config.node.node_id, proof.block().height, slot)
                .map_err(protocol_error)?
            else {
                served.insert(slot);
                continue;
            };
            let share_protocol = scoped_protocol(FALLBACK_SHARE_PROTOCOL, sample, slot);
            broadcast_same(
                shared,
                config,
                &share_protocol,
                DistributedMessage::RondoFallbackShare {
                    sample,
                    share: Box::new(share),
                },
                config.node.n as u32,
            )?;
            served.insert(slot);
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(super) fn broadcast_aggregate_share(
    shared: &SharedNode,
    config: &AutonomousConfig,
    logger: &mut dyn NodeObserver,
    process_start: &Instant,
    sample: u32,
    slot: u32,
    proof: &DecisionProof,
    epoch: &RondoEpoch,
) -> Result<(), DistributedError> {
    let aggregate_protocol = scoped_protocol(AGGREGATE_PROTOCOL, sample, slot);
    let reconstruction_holders = epoch.aggregate_holders();
    measured_for(
        shared,
        config,
        logger,
        process_start,
        sample,
        "rondo-beacon",
        "rondo-aggregate-share-broadcast",
        Some(slot),
        None,
        || {
            if reconstruction_holders.contains(&config.node.node_id) {
                let aggregate = epoch
                    .aggregate_share(config.node.node_id, proof.block().height, slot)
                    .map_err(protocol_error)?;
                if let Some(aggregate) = aggregate {
                    broadcast_same(
                        shared,
                        config,
                        &aggregate_protocol,
                        DistributedMessage::RondoAggregate {
                            sample,
                            share: aggregate,
                        },
                        config.node.n as u32,
                    )?;
                }
            }
            Ok(((), None))
        },
    )
}

#[allow(clippy::too_many_arguments)]
pub(super) fn finalize_reconstruction_slot(
    shared: &SharedNode,
    config: &AutonomousConfig,
    logger: &mut dyn NodeObserver,
    process_start: &Instant,
    sample: u32,
    slot: u32,
    proof: &DecisionProof,
    epoch: &RondoEpoch,
) -> Result<[u8; 32], DistributedError> {
    let aggregate_protocol = scoped_protocol(AGGREGATE_PROTOCOL, sample, slot);
    let reconstruction_holders = epoch.aggregate_holders();
    measured_for(
        shared,
        config,
        logger,
        process_start,
        sample,
        "rondo-beacon",
        "rondo-aggregate-verify-reconstruct-output-durable",
        Some(slot),
        Some("beacon-output"),
        || {
            let normal_result =
                (if reconstruction_holders.len() < config.node.t + 1 {
                    Err(protocol_error(
                        "certified holder intersection is below reconstruction threshold",
                    ))
                } else {
                    collect_protocol_valid(
                        shared,
                        &aggregate_protocol,
                        config.node.t + 1,
                        fixed_holder_timeout(),
                        |sender, message| match message {
                            DistributedMessage::RondoAggregate { sample: got, share }
                                if got == sample
                                    && reconstruction_holders.contains(&sender)
                                    && sender == share.holder
                                    && share.slot == slot
                                    && share.height == proof.block().height =>
                            {
                                Ok(Some(DistributedMessage::RondoAggregate {
                                    sample: got,
                                    share,
                                }))
                            }
                            _ => Ok(None),
                        },
                    )
                    .map(|collection| collection.into_messages(&aggregate_protocol))
                })
                .and_then(|messages| {
                    decode_messages(messages, sample, "Rondo aggregate share", |message| {
                        match message {
                            DistributedMessage::RondoAggregate { sample, share } => {
                                Some((sample, share))
                            }
                            _ => None,
                        }
                    })
                })
                .and_then(|shares| {
                    epoch
                        .reconstruct(
                            shares,
                            proof,
                            slot,
                            config.node.store_root.join("rondo-outputs.bin"),
                        )
                        .map_err(protocol_error)
                });
            let output = match normal_result {
                Ok(output) => output,
                Err(normal_error) => {
                    eprintln!(
                        "Rondo slot {slot} entering verified dealer-row fallback: {normal_error}"
                    );
                    reconstruct_with_fallback(shared, config, sample, slot, proof, epoch)?
                }
            };
            Ok((output, Some(output)))
        },
    )
}

fn fixed_holder_timeout() -> Duration {
    std::env::var("RONDO_FIXED_HOLDER_TIMEOUT_MS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|millis| *millis != 0)
        .map(Duration::from_millis)
        .unwrap_or(Duration::from_secs(5))
}

fn reconstruct_with_fallback(
    shared: &SharedNode,
    config: &AutonomousConfig,
    sample: u32,
    slot: u32,
    proof: &DecisionProof,
    epoch: &RondoEpoch,
) -> Result<[u8; 32], DistributedError> {
    let request_protocol = scoped_protocol(FALLBACK_REQUEST_PROTOCOL, sample, 0);
    broadcast_same(
        shared,
        config,
        &request_protocol,
        DistributedMessage::RondoFallbackRequest {
            sample,
            slot,
            proof: Box::new(proof.clone()),
        },
        config.node.n as u32,
    )?;

    let share_protocol = scoped_protocol(FALLBACK_SHARE_PROTOCOL, sample, slot);
    let mut reconstruction = epoch
        .fallback_reconstruction(proof.block().height, slot)
        .map_err(protocol_error)?;
    let deadline = Instant::now() + FALLBACK_COLLECTION_TIMEOUT;
    let mut rejected = 0usize;
    while !reconstruction.is_ready() {
        let now = Instant::now();
        if now >= deadline {
            return Err(DistributedError::Protocol(format!(
                "Rondo fallback slot {slot} collected {} authenticated senders without per-dealer threshold coverage",
                reconstruction.accepted_senders().len()
            )));
        }
        let messages = take_protocol_available(
            shared,
            &share_protocol,
            deadline.saturating_duration_since(now),
        )?;
        for (sender, message) in messages {
            match message {
                DistributedMessage::RondoFallbackShare {
                    sample: message_sample,
                    share,
                } if message_sample == sample => {
                    if reconstruction.accept(sender, &share).is_err() {
                        rejected += 1;
                    }
                }
                _ => rejected += 1,
            }
        }
    }
    if rejected != 0 {
        eprintln!("protocol {share_protocol} ignored {rejected} invalid fallback messages");
    }
    reconstruction
        .finish(proof, config.node.store_root.join("rondo-outputs.bin"))
        .map_err(protocol_error)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn finalize_ready_reconstructions(
    shared: &SharedNode,
    config: &AutonomousConfig,
    logger: &mut dyn NodeObserver,
    process_start: &Instant,
    sample: u32,
    epoch: &RondoEpoch,
    decisions: &[Option<DecisionProof>],
    pending: &mut BTreeSet<usize>,
    outputs: &mut [Option<[u8; 32]>],
) -> Result<(), DistributedError> {
    let reconstruction_holders = epoch.aggregate_holders();
    let mut ready = Vec::new();
    for slot in pending.iter().copied() {
        let protocol = scoped_protocol(AGGREGATE_PROTOCOL, sample, slot as u32);
        if reconstruction_holders.len() < config.node.t + 1
            || crate::beacon::message_flow::protocol_has_quorum(
                shared,
                &protocol,
                &reconstruction_holders,
                config.node.t + 1,
            )?
        {
            ready.push(slot);
        }
    }
    for slot in ready {
        let output = finalize_reconstruction_slot(
            shared,
            config,
            logger,
            process_start,
            sample,
            slot as u32,
            pipeline_ref(decisions, slot, "decision proof")?,
            epoch,
        )?;
        if outputs[slot].replace(output).is_some() || !pending.remove(&slot) {
            return Err(DistributedError::Protocol(format!(
                "Rondo reconstruction finalized slot {slot} more than once"
            )));
        }
    }
    Ok(())
}
