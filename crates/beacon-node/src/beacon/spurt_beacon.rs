//! Distributed Spurt normal path used by the beacon-performance matrix.

mod agreement;
mod prepare;
mod reconstruct;

use super::message_flow::{discard_protocols, protocol_error, scoped_protocol};
use super::*;
use ::spurt_beacon::{
    AGREEMENT_PROTOCOL, BEACON_PROTOCOL, CONTRIBUTION_PROTOCOL, RECONSTRUCTION_PROTOCOL,
    ReceiverProposal, SpurtProtocol, SpurtSetup,
};

use prepare::{preaggregate_future_epoch, receive_preaggregated_proposal};
use reconstruct::run_ready_epoch;

pub(super) struct SpurtSampleResult {
    pub(super) outputs: Vec<[u8; 32]>,
    pub(super) agreement_steps: usize,
    pub(super) committed_requests: usize,
}

struct PreparedSpurtEpoch {
    slot: u32,
    protocol: SpurtProtocol,
    proposal: ReceiverProposal,
}

pub(super) fn run_spurt_sample(
    shared: &SharedNode,
    config: &AutonomousConfig,
    logger: &mut dyn NodeObserver,
    process_start: &Instant,
    sample: u32,
    setup: &SpurtSetup,
) -> Result<SpurtSampleResult, DistributedError> {
    let mut future_epochs = Vec::with_capacity(config.node.slots);
    for slot in 0..config.node.slots {
        let height = (sample as u64)
            .checked_mul(config.node.slots as u64)
            .and_then(|offset| offset.checked_add(slot as u64 + 1))
            .ok_or_else(|| DistributedError::Protocol("Spurt height overflow".into()))?;
        let protocol = setup.protocol(height, height).map_err(protocol_error)?;
        preaggregate_future_epoch(
            shared,
            config,
            logger,
            process_start,
            sample,
            slot as u32,
            &protocol,
        )?;
        future_epochs.push((slot as u32, protocol));
    }

    let mut prepared = Vec::with_capacity(config.node.slots);
    for (slot, protocol) in future_epochs {
        let proposal = receive_preaggregated_proposal(
            shared,
            config,
            logger,
            process_start,
            sample,
            slot,
            &protocol,
        )?;
        prepared.push(PreparedSpurtEpoch {
            slot,
            protocol,
            proposal,
        });
    }
    // Agreement has its own 2t+1 quorum; it does not require every
    // replica to finish local PVSS validation before the first vote.

    let mut outputs = Vec::with_capacity(config.node.slots);
    for epoch in prepared {
        outputs.push(run_ready_epoch(
            shared,
            config,
            logger,
            process_start,
            sample,
            epoch,
        )?);
    }
    coordination::sample_barrier(shared, config, sample, "spurt-beacon-retention-barrier")?;
    let mut late_protocols = BTreeSet::new();
    for slot in 0..config.node.slots as u32 {
        late_protocols.insert(scoped_protocol(CONTRIBUTION_PROTOCOL, sample, slot));
        late_protocols.insert(scoped_protocol(BEACON_PROTOCOL, sample, slot));
        late_protocols.insert(scoped_protocol(RECONSTRUCTION_PROTOCOL, sample, slot));
        let agreement = scoped_protocol(AGREEMENT_PROTOCOL, sample, slot);
        for phase in ["prepare", "precommit", "commit", "finalize"] {
            late_protocols.insert(format!("{agreement}/{phase}"));
        }
    }
    discard_protocols(shared, &late_protocols)?;
    Ok(SpurtSampleResult {
        agreement_steps: outputs.len(),
        committed_requests: outputs.len(),
        outputs,
    })
}
