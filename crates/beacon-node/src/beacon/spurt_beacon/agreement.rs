//! Spurt's Prepare, Pre-Commit, Commit, and FINALIZE normal path.

use super::super::message_flow::{broadcast_same, collect_protocol_valid, protocol_error};
use super::super::observation::measured_for;
use super::super::*;
use ::spurt_beacon::{
    AgreementDecision, AgreementPhase, AgreementReplica, SpurtProtocol, VerifiedAgreementMessage,
};

#[allow(clippy::too_many_arguments)]
pub(super) fn run_agreement(
    shared: &SharedNode,
    config: &AutonomousConfig,
    logger: &mut dyn NodeObserver,
    process_start: &Instant,
    sample: u32,
    slot: u32,
    agreement_protocol: &str,
    protocol: &SpurtProtocol,
    digest: [u8; 32],
) -> Result<AgreementDecision, DistributedError> {
    let mut replica = protocol.agreement(digest).map_err(protocol_error)?;
    run_prepare(
        shared,
        config,
        logger,
        process_start,
        sample,
        slot,
        agreement_protocol,
        &mut replica,
    )?;
    run_precommit(
        shared,
        config,
        logger,
        process_start,
        sample,
        slot,
        agreement_protocol,
        &mut replica,
    )?;
    run_commit(
        shared,
        config,
        logger,
        process_start,
        sample,
        slot,
        agreement_protocol,
        &mut replica,
    )?;
    run_finalize(
        shared,
        config,
        logger,
        process_start,
        sample,
        slot,
        agreement_protocol,
        &mut replica,
    )
}

#[allow(clippy::too_many_arguments)]
fn run_prepare(
    shared: &SharedNode,
    config: &AutonomousConfig,
    logger: &mut dyn NodeObserver,
    process_start: &Instant,
    sample: u32,
    slot: u32,
    agreement_protocol: &str,
    replica: &mut AgreementReplica,
) -> Result<(), DistributedError> {
    let phase_protocol = format!("{agreement_protocol}/prepare");
    measured_for(
        shared,
        config,
        logger,
        process_start,
        sample,
        "spurt-beacon",
        "spurt-agreement-prepare",
        Some(slot),
        None,
        || {
            let message = replica.prepare_message().map_err(protocol_error)?;
            broadcast_agreement(shared, config, &phase_protocol, sample, message)?;
            let messages = collect_agreement(
                shared,
                &phase_protocol,
                sample,
                2 * config.node.t + 1,
                replica,
                AgreementPhase::Prepare,
            )?;
            replica
                .accept_prepare_preverified(messages)
                .map_err(protocol_error)?;
            Ok(((), None))
        },
    )
}

#[allow(clippy::too_many_arguments)]
fn run_precommit(
    shared: &SharedNode,
    config: &AutonomousConfig,
    logger: &mut dyn NodeObserver,
    process_start: &Instant,
    sample: u32,
    slot: u32,
    agreement_protocol: &str,
    replica: &mut AgreementReplica,
) -> Result<(), DistributedError> {
    let phase_protocol = format!("{agreement_protocol}/precommit");
    measured_for(
        shared,
        config,
        logger,
        process_start,
        sample,
        "spurt-beacon",
        "spurt-agreement-precommit",
        Some(slot),
        None,
        || {
            let message = replica.precommit_message().map_err(protocol_error)?;
            broadcast_agreement(shared, config, &phase_protocol, sample, message)?;
            let messages = collect_agreement(
                shared,
                &phase_protocol,
                sample,
                2 * config.node.t + 1,
                replica,
                AgreementPhase::PreCommit,
            )?;
            replica
                .accept_precommit_preverified(messages)
                .map_err(protocol_error)?;
            Ok(((), None))
        },
    )
}

#[allow(clippy::too_many_arguments)]
fn run_commit(
    shared: &SharedNode,
    config: &AutonomousConfig,
    logger: &mut dyn NodeObserver,
    process_start: &Instant,
    sample: u32,
    slot: u32,
    agreement_protocol: &str,
    replica: &mut AgreementReplica,
) -> Result<(), DistributedError> {
    let phase_protocol = format!("{agreement_protocol}/commit");
    measured_for(
        shared,
        config,
        logger,
        process_start,
        sample,
        "spurt-beacon",
        "spurt-agreement-commit",
        Some(slot),
        None,
        || {
            let message = replica.commit_message().map_err(protocol_error)?;
            broadcast_agreement(shared, config, &phase_protocol, sample, message)?;
            let messages = collect_agreement(
                shared,
                &phase_protocol,
                sample,
                2 * config.node.t + 1,
                replica,
                AgreementPhase::Commit,
            )?;
            replica
                .accept_commit_preverified(messages)
                .map_err(protocol_error)?;
            Ok(((), None))
        },
    )
}

#[allow(clippy::too_many_arguments)]
fn run_finalize(
    shared: &SharedNode,
    config: &AutonomousConfig,
    logger: &mut dyn NodeObserver,
    process_start: &Instant,
    sample: u32,
    slot: u32,
    agreement_protocol: &str,
    replica: &mut AgreementReplica,
) -> Result<AgreementDecision, DistributedError> {
    let phase_protocol = format!("{agreement_protocol}/finalize");
    measured_for(
        shared,
        config,
        logger,
        process_start,
        sample,
        "spurt-beacon",
        "spurt-agreement-finalize-decide",
        Some(slot),
        Some("bft-finality"),
        || {
            let message = replica.finalize_after_commit().map_err(protocol_error)?;
            broadcast_agreement(shared, config, &phase_protocol, sample, message)?;
            let messages = collect_agreement(
                shared,
                &phase_protocol,
                sample,
                2 * config.node.t + 1,
                replica,
                AgreementPhase::Finalize,
            )?;
            let decision = replica
                .decide_preverified(messages)
                .map_err(protocol_error)?;
            Ok((decision, None))
        },
    )
}

fn broadcast_agreement(
    shared: &SharedNode,
    config: &AutonomousConfig,
    protocol: &str,
    sample: u32,
    message: ::spurt_beacon::SignedAgreementMessage,
) -> Result<(), DistributedError> {
    broadcast_same(
        shared,
        config,
        protocol,
        DistributedMessage::SpurtAgreement { sample, message },
        config.node.n as u32,
    )
}

fn collect_agreement(
    shared: &SharedNode,
    protocol: &str,
    sample: u32,
    threshold: usize,
    replica: &AgreementReplica,
    phase: AgreementPhase,
) -> Result<Vec<VerifiedAgreementMessage>, DistributedError> {
    Ok(collect_protocol_valid(
        shared,
        protocol,
        threshold,
        Duration::from_secs(300),
        |sender, message| match message {
            DistributedMessage::SpurtAgreement {
                sample: message_sample,
                message,
            } if message_sample == sample => {
                Ok(replica.accept_message(phase, sender, message).ok())
            }
            _ => Ok(None),
        },
    )?
    .into_messages(protocol)
    .into_iter()
    .map(|(_, message)| message)
    .collect())
}
