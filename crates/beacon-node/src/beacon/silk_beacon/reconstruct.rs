//! Reconstruct: direct first output, then QR-gated later outputs.

use super::{BeaconSampleResult, EpochProtocols, SilkNetworkContext, SilkSampleContext};
use crate::beacon::coordination;
use crate::beacon::message_flow::{
    broadcast_same, collect_protocol_valid, discard_protocols, protocol_error, scoped_protocol,
};
use crate::beacon::observation::{measured, measured_gc};
use crate::beacon::{DistributedError, DistributedMessage};
use ::silk_beacon::protocol::{
    COMMIT_PROTOCOL, ECHO_PROTOCOL, READY_PROTOCOL, RECONSTRUCTION_PROTOCOL, RELEASE_PROTOCOL,
    SilkProtocol, VerifiedCertifiedEpoch,
};
use ::silk_beacon::{BeaconNode, EpochCompletion, QrSupport, ReconstructionMessage};
use std::collections::BTreeSet;
use std::time::Duration;

#[allow(clippy::too_many_arguments)]
pub(super) fn reconstruct(
    context: &mut SilkSampleContext<'_>,
    silk: &SilkProtocol,
    protocols: EpochProtocols,
    preparation: &super::prepare::SharedPreparation,
    certified: VerifiedCertifiedEpoch,
    epoch: u64,
    slots: usize,
    predecessor: Option<&EpochCompletion>,
) -> Result<BeaconSampleResult, DistributedError> {
    let network = context.network();
    let store = context.config.node.store_root.join(format!(
        "beacon-performance-sample-{}-node.bin",
        context.sample
    ));
    let mut node = silk
        .build_node_preverified(
            certified,
            &preparation
                .0
                .lock()
                .map_err(|_| protocol_error("preparation state poisoned"))?
                .sharing,
            store,
        )
        .map_err(protocol_error)?;
    let first_reconstruction_protocol = scoped_protocol(RECONSTRUCTION_PROTOCOL, context.sample, 1);
    measured(
        context.shared,
        context.config,
        context.logger,
        context.process_start,
        context.sample,
        "index-1-reconstruction-send",
        Some(0),
        None,
        || {
            let local = node
                .install_epoch_after(predecessor)
                .map_err(protocol_error)?;
            broadcast_same(
                context.shared,
                context.config,
                &first_reconstruction_protocol,
                DistributedMessage::BeaconReconstruction {
                    sample: context.sample,
                    message: local,
                },
                context.config.node.n as u32,
            )?;
            Ok(((), None))
        },
    )?;
    let first_output = measured(
        context.shared,
        context.config,
        context.logger,
        context.process_start,
        context.sample,
        "index-1-point-verify-threshold-reconstruct-output-persist",
        Some(0),
        Some("beacon-output"),
        || {
            let output = collect_valid_reconstruction(
                network,
                &first_reconstruction_protocol,
                1,
                silk,
                &mut node,
            )?;
            Ok((output, Some(output)))
        },
    )?;
    measured_gc(
        context.shared,
        context.config,
        context.logger,
        context.process_start,
        context.sample,
        "index-retention-gc",
        Some(0),
        || node.compact_index(1).map_err(protocol_error),
    )?;
    discard_protocols(
        context.shared,
        &BTreeSet::from([first_reconstruction_protocol.clone()]),
    )?;

    let mut outputs = vec![first_output];
    let mut supports = Vec::with_capacity(slots.saturating_sub(1));
    for index in 2..=slots as u32 {
        let release_protocol = scoped_protocol(RELEASE_PROTOCOL, context.sample, index);
        let reconstruction_protocol =
            scoped_protocol(RECONSTRUCTION_PROTOCOL, context.sample, index);
        measured(
            context.shared,
            context.config,
            context.logger,
            context.process_start,
            context.sample,
            "qr-sign-send",
            Some(index - 1),
            None,
            || {
                let announcement = node.begin_qr(index).map_err(protocol_error)?;
                broadcast_same(
                    context.shared,
                    context.config,
                    &release_protocol,
                    DistributedMessage::BeaconRelease {
                        sample: context.sample,
                        announcement,
                    },
                    context.config.node.n as u32,
                )?;
                Ok(((), None))
            },
        )?;
        let local_reconstruction = measured(
            context.shared,
            context.config,
            context.logger,
            context.process_start,
            context.sample,
            "qr-quorum-wait-qrout-persist",
            Some(index - 1),
            None,
            || {
                let (reconstruction, support) =
                    collect_valid_releases(network, &release_protocol, index, silk, &mut node)?;
                Ok(((reconstruction, support), None))
            },
        )?;
        supports.push(local_reconstruction.1);
        let reconstruction = local_reconstruction.0;
        measured(
            context.shared,
            context.config,
            context.logger,
            context.process_start,
            context.sample,
            "reconstruction-send",
            Some(index - 1),
            None,
            || {
                broadcast_same(
                    context.shared,
                    context.config,
                    &reconstruction_protocol,
                    DistributedMessage::BeaconReconstruction {
                        sample: context.sample,
                        message: reconstruction,
                    },
                    context.config.node.n as u32,
                )?;
                Ok(((), None))
            },
        )?;
        let output = measured(
            context.shared,
            context.config,
            context.logger,
            context.process_start,
            context.sample,
            "point-verify-threshold-reconstruct-output-persist",
            Some(index - 1),
            Some("beacon-output"),
            || {
                let output = collect_valid_reconstruction(
                    network,
                    &reconstruction_protocol,
                    index,
                    silk,
                    &mut node,
                )?;
                Ok((output, Some(output)))
            },
        )?;
        outputs.push(output);
        measured_gc(
            context.shared,
            context.config,
            context.logger,
            context.process_start,
            context.sample,
            "index-retention-gc",
            Some(index - 1),
            || node.compact_index(index).map_err(protocol_error),
        )?;
        discard_protocols(
            context.shared,
            &BTreeSet::from([release_protocol, reconstruction_protocol]),
        )?;
    }

    // The last output is publicly verifiable too. Its verified quorum also
    // supplies the gate for the next epoch. Keep this in the measured window.
    let final_protocol = scoped_protocol(RELEASE_PROTOCOL, context.sample, slots as u32 + 1);
    measured(
        context.shared,
        context.config,
        context.logger,
        context.process_start,
        context.sample,
        "qr-final-sign-send",
        Some(slots as u32 - 1),
        None,
        || {
            let announcement = node.sign_release(slots as u32).map_err(protocol_error)?;
            broadcast_same(
                context.shared,
                context.config,
                &final_protocol,
                DistributedMessage::BeaconRelease {
                    sample: context.sample,
                    announcement,
                },
                context.config.node.n as u32,
            )?;
            Ok(((), None))
        },
    )?;
    let completion = measured(
        context.shared,
        context.config,
        context.logger,
        context.process_start,
        context.sample,
        "qr-final-quorum-verify",
        Some(slots as u32 - 1),
        None,
        || {
            collect_protocol_valid(
                network.shared,
                &final_protocol,
                network.config.node.n - network.config.node.t,
                Duration::from_secs(300),
                |sender, message| match message {
                    DistributedMessage::BeaconRelease {
                        sample,
                        announcement,
                    } if sample == network.sample => Ok(silk
                        .accept_release(&mut node, slots as u32 + 1, sender, announcement)
                        .ok()),
                    _ => Ok(None),
                },
            )?;
            Ok((node.completed_epoch().map_err(protocol_error)?, None))
        },
    )?;
    discard_protocols(context.shared, &BTreeSet::from([final_protocol]))?;

    coordination::sample_barrier(
        context.shared,
        context.config,
        context.sample,
        "beacon-performance-retention-barrier",
    )?;
    let mut late_protocols = BTreeSet::from([
        protocols.validation,
        protocols.certified_dealer,
        scoped_protocol(ECHO_PROTOCOL, context.sample, 0),
        scoped_protocol(READY_PROTOCOL, context.sample, 0),
        scoped_protocol(COMMIT_PROTOCOL, context.sample, 0),
        protocols.decision_signature,
    ]);
    for index in 1..=slots as u32 {
        late_protocols.insert(scoped_protocol(
            RECONSTRUCTION_PROTOCOL,
            context.sample,
            index,
        ));
        if index > 1 {
            late_protocols.insert(scoped_protocol(RELEASE_PROTOCOL, context.sample, index));
        }
    }
    discard_protocols(context.shared, &late_protocols)?;
    measured_gc(
        context.shared,
        context.config,
        context.logger,
        context.process_start,
        context.sample,
        "epoch-retention-gc",
        None,
        || node.retire_epoch(epoch + 1).map_err(protocol_error),
    )?;
    Ok(BeaconSampleResult {
        agreement_trace: Vec::new(),
        outputs,
        qr_support: supports,
        completion,
    })
}

fn collect_valid_releases(
    network: SilkNetworkContext<'_>,
    message_protocol: &str,
    index: u32,
    silk: &SilkProtocol,
    node: &mut BeaconNode,
) -> Result<(ReconstructionMessage, QrSupport), DistributedError> {
    let accepted = collect_protocol_valid(
        network.shared,
        message_protocol,
        network.config.node.n - network.config.node.t,
        Duration::from_secs(300),
        |sender, message| match message {
            DistributedMessage::BeaconRelease {
                sample: message_sample,
                announcement,
            } if message_sample == network.sample => {
                Ok(silk.accept_release(node, index, sender, announcement).ok())
            }
            _ => Ok(None),
        },
    )?
    .into_messages(message_protocol);
    let reconstruction = accepted
        .into_iter()
        .filter_map(|(_, reconstruction)| reconstruction)
        .next_back();
    silk.finish_releases(node, index, reconstruction)
        .map_err(protocol_error)
}

fn collect_valid_reconstruction(
    network: SilkNetworkContext<'_>,
    message_protocol: &str,
    index: u32,
    silk: &SilkProtocol,
    node: &mut BeaconNode,
) -> Result<[u8; 32], DistributedError> {
    let mut accepted_senders = BTreeSet::new();
    let deadline = std::time::Instant::now() + Duration::from_secs(300);
    let mut first = true;
    while accepted_senders.len() < network.config.node.n {
        let threshold = if first { network.config.node.t + 1 } else { 1 };
        first = false;
        let messages = collect_protocol_valid(
            network.shared,
            message_protocol,
            threshold,
            deadline.saturating_duration_since(std::time::Instant::now()),
            |sender, message| match message {
                DistributedMessage::BeaconReconstruction {
                    sample: message_sample,
                    message,
                } if message_sample == network.sample && !accepted_senders.contains(&sender) => {
                    Ok(silk
                        .accept_reconstruction_candidate(node, index, sender, message)
                        .ok())
                }
                _ => Ok(None),
            },
        )?
        .into_messages(message_protocol)
        .into_iter()
        .map(|(sender, message)| {
            accepted_senders.insert(sender);
            message
        })
        .collect::<Vec<_>>();
        if let Some(output) = silk
            .accept_reconstruction_preverified_batch(node, index, messages)
            .map_err(protocol_error)?
        {
            return Ok(output);
        }
    }
    Err(DistributedError::Protocol(format!(
        "Silk reconstruction {index} exhausted all authenticated senders without exact per-dealer thresholds"
    )))
}
