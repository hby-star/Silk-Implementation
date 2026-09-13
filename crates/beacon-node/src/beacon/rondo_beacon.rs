//! Complete distributed Rondo baseline used by the beacon-performance matrix.
//!
//! Each process executes one Breeze receiver/dealer, one explicit four-phase
//! Rondo-BFT replica, and one aggregate-share reconstruction path. This is
//! deliberately separate from the Silk driver: a matrix cell selects exactly
//! one complete implementation.

mod agreement;
mod pipeline;
mod prepare;
mod reconstruct;

use super::message_flow::{
    broadcast_same, collect_protocol_valid, decode_messages, decode_one, discard_protocols,
    protocol_error, scoped_protocol, send, take_protocol, take_protocol_available,
};
use super::observation::measured_for;
use super::*;
use ::rondo_beacon::bft::normal::{
    DecisionProof, NormalReplica, Proposal, QcKind, QuorumCertificate, pipeline_waves,
};
use ::rondo_beacon::protocol::{
    AGGREGATE_PROTOCOL, FALLBACK_REQUEST_PROTOCOL, FALLBACK_SHARE_PROTOCOL, PROPOSAL_PROTOCOL,
    QC_PROTOCOL, RetainedDealer, RondoEpoch, RondoSetup, RondoShare, SHARE_PROTOCOL,
    VALIDATED_PROTOCOL, VALIDATION_PROTOCOL, VOTE_PROTOCOL,
};
use protocol_support::store::ProtocolStore;

use agreement::{RondoSlotProtocols, collect_vote_qc, pipeline_ref, rondo_height};
use pipeline::run_pipeline;
use prepare::RondoPreparation;
pub(super) use prepare::rondo_parallel_workers;
use reconstruct::{
    broadcast_aggregate_share, finalize_ready_reconstructions, finalize_reconstruction_slot,
    start_fallback_service,
};

pub(super) struct RondoSampleResult {
    pub(super) outputs: Vec<[u8; 32]>,
    pub(super) preparation_trace: Vec<serde_json::Value>,
    pub(super) agreement_steps: usize,
    pub(super) committed_requests: usize,
}

pub(super) fn run_rondo_sample(
    shared: &SharedNode,
    config: &AutonomousConfig,
    logger: &mut dyn NodeObserver,
    process_start: &Instant,
    sample: u32,
    seed: u64,
) -> Result<RondoSampleResult, DistributedError> {
    rondo_parallel_workers();
    let epoch = sample as u64 + 1;
    let bootstrap = RondoSetup::bootstrap(
        config.node.n,
        config.node.t,
        config.node.slots,
        epoch,
        seed,
        config.node.node_id,
    )
    .map_err(protocol_error)?;
    let validation_protocol = scoped_protocol(VALIDATION_PROTOCOL, sample, 0);

    let setup = measured_for(
        shared,
        config,
        logger,
        process_start,
        sample,
        "rondo-beacon",
        "breeze-dealer-prepare-all-proofs",
        None,
        None,
        || {
            // Committee/key bootstrap is outside the window for both
            // implementations. Breeze commitment, sharing, and proofs begin
            // the measured Commitment span.
            let setup = bootstrap.prepare_sharing().map_err(protocol_error)?;
            Ok((setup, None))
        },
    )?;

    let preparation = measured_for(
        shared,
        config,
        logger,
        process_start,
        sample,
        "rondo-beacon",
        "breeze-share-broadcast",
        None,
        None,
        || {
            Ok((
                RondoPreparation::start(shared, config, sample, setup)?,
                None,
            ))
        },
    )?;
    let epoch_state = measured_for(
        shared,
        config,
        logger,
        process_start,
        sample,
        "rondo-beacon",
        "breeze-receiver-verify-and-persist",
        None,
        None,
        || Ok((preparation.candidate(config.node.t + 1)?, None)),
    )?;
    let requests = epoch_state.requests().map_err(protocol_error)?;
    if requests.len() != config.node.slots {
        return Err(DistributedError::Protocol(format!(
            "Rondo epoch produced {}/{} BFT requests",
            requests.len(),
            config.node.slots
        )));
    }
    let agreement_steps = requests.len();
    let pipeline = run_pipeline(
        shared,
        config,
        logger,
        process_start,
        sample,
        epoch,
        requests,
        epoch_state,
        &preparation,
    )?;

    coordination::sample_barrier(shared, config, sample, "rondo-beacon-retention-barrier")?;
    pipeline.fallback_service.stop()?;
    let preparation_trace = preparation.finish()?;
    let mut late_protocols = BTreeSet::from([validation_protocol]);
    late_protocols.insert(scoped_protocol(FALLBACK_REQUEST_PROTOCOL, sample, 0));
    for slot in 0..config.node.slots as u32 {
        let votes = scoped_protocol(VOTE_PROTOCOL, sample, slot);
        late_protocols.insert(format!("{votes}/prepare"));
        late_protocols.insert(format!("{votes}/precommit"));
        late_protocols.insert(format!("{votes}/commit"));
        late_protocols.insert(scoped_protocol(AGGREGATE_PROTOCOL, sample, slot));
        late_protocols.insert(scoped_protocol(FALLBACK_SHARE_PROTOCOL, sample, slot));
    }
    discard_protocols(shared, &late_protocols)?;
    Ok(RondoSampleResult {
        preparation_trace,
        outputs: pipeline.outputs,
        agreement_steps,
        committed_requests: pipeline.committed_requests,
    })
}
