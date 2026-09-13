//! Future-epoch PVSS preparation and leader aggregation.

use super::super::message_flow::{
    broadcast, collect_protocol_valid, decode_one, protocol_error, scoped_protocol, send,
    take_protocol,
};
use super::super::observation::measured_for;
use super::super::*;
use ::spurt_beacon::{CONTRIBUTION_PROTOCOL, PROPOSAL_PROTOCOL, ReceiverProposal, SpurtProtocol};

#[allow(clippy::too_many_arguments)]
pub(super) fn preaggregate_future_epoch(
    shared: &SharedNode,
    config: &AutonomousConfig,
    logger: &mut dyn NodeObserver,
    process_start: &Instant,
    sample: u32,
    slot: u32,
    protocol: &SpurtProtocol,
) -> Result<(), DistributedError> {
    let contribution_protocol = scoped_protocol(CONTRIBUTION_PROTOCOL, sample, slot);
    let proposal_protocol = scoped_protocol(PROPOSAL_PROTOCOL, sample, slot);
    let leader = protocol.leader();

    let contributions = measured_for(
        shared,
        config,
        logger,
        process_start,
        sample,
        "spurt-beacon",
        "spurt-commitment-pvss-share-to-leader",
        Some(slot),
        None,
        || {
            let contribution = protocol.contribution().map_err(protocol_error)?;
            send(
                shared,
                config,
                &contribution_protocol,
                leader,
                DistributedMessage::SpurtContribution {
                    sample,
                    contribution,
                },
            )?;
            if config.node.node_id != leader {
                return Ok((None, None));
            }
            let contributions = collect_protocol_valid(
                shared,
                &contribution_protocol,
                config.node.t + 1,
                Duration::from_secs(300),
                |sender, message| match message {
                    DistributedMessage::SpurtContribution {
                        sample: message_sample,
                        contribution,
                    } if message_sample == sample => Ok(protocol
                        .accept_contribution_for_aggregation(sender, contribution)
                        .ok()),
                    _ => Ok(None),
                },
            )?
            .into_messages(&contribution_protocol)
            .into_iter()
            .map(|(_, contribution)| contribution)
            .collect::<Vec<_>>();
            Ok((Some(contributions), None))
        },
    )?;

    measured_for(
        shared,
        config,
        logger,
        process_start,
        sample,
        "spurt-beacon",
        "spurt-aggregation-verify-build-private-proposals",
        Some(slot),
        None,
        || {
            if config.node.node_id == leader {
                let mut proposals = protocol
                    .aggregate_preverified(contributions.ok_or_else(|| {
                        DistributedError::Protocol(
                            "Spurt leader has no collected contributions".into(),
                        )
                    })?)
                    .map_err(protocol_error)?;
                proposals.sort_by_key(|proposal| proposal.receiver);
                if proposals.len() != config.node.n
                    || proposals
                        .iter()
                        .enumerate()
                        .any(|(receiver, proposal)| proposal.receiver as usize != receiver)
                {
                    return Err(DistributedError::Protocol(
                        "Spurt private proposals do not cover the configured receivers".into(),
                    ));
                }
                broadcast(
                    shared,
                    config,
                    &proposal_protocol,
                    |receiver| DistributedMessage::SpurtProposal {
                        sample,
                        proposal: proposals[receiver as usize].clone(),
                    },
                    config.node.n as u32,
                )?;
            }
            Ok(((), None))
        },
    )
}

#[allow(clippy::too_many_arguments)]
pub(super) fn receive_preaggregated_proposal(
    shared: &SharedNode,
    config: &AutonomousConfig,
    logger: &mut dyn NodeObserver,
    process_start: &Instant,
    sample: u32,
    slot: u32,
    protocol: &SpurtProtocol,
) -> Result<ReceiverProposal, DistributedError> {
    let proposal_protocol = scoped_protocol(PROPOSAL_PROTOCOL, sample, slot);
    let leader = protocol.leader();
    measured_for(
        shared,
        config,
        logger,
        process_start,
        sample,
        "spurt-beacon",
        "spurt-agreement-propose-verify-private-transcript",
        Some(slot),
        None,
        || {
            let messages = take_protocol(shared, &proposal_protocol, 1, Duration::from_secs(300))?;
            let (sender, proposal) = decode_one(
                messages,
                sample,
                "Spurt private aggregate proposal",
                |message| match message {
                    DistributedMessage::SpurtProposal { sample, proposal } => {
                        Some((sample, proposal))
                    }
                    _ => None,
                },
            )?;
            if sender != leader || proposal.leader != leader {
                return Err(DistributedError::Protocol(
                    "Spurt proposal sender mismatch".into(),
                ));
            }
            protocol
                .verify_proposal(&proposal)
                .map_err(protocol_error)?;
            Ok((proposal, None))
        },
    )
}
