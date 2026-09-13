//! Spurt reconstruction, durable output, and signed BEACON relay.

use super::super::message_flow::{
    broadcast_same, collect_protocol_valid, discard_protocols, protocol_error, scoped_protocol,
};
use super::super::observation::measured_for;
use super::super::*;
use super::PreparedSpurtEpoch;
use super::agreement::run_agreement;
use ::spurt_beacon::{
    AGREEMENT_PROTOCOL, BEACON_PROTOCOL, CONTRIBUTION_PROTOCOL, RECONSTRUCTION_PROTOCOL,
};

#[allow(clippy::too_many_arguments)]
pub(super) fn run_ready_epoch(
    shared: &SharedNode,
    config: &AutonomousConfig,
    logger: &mut dyn NodeObserver,
    process_start: &Instant,
    sample: u32,
    prepared: PreparedSpurtEpoch,
) -> Result<[u8; 32], DistributedError> {
    let PreparedSpurtEpoch {
        slot,
        protocol,
        proposal,
    } = prepared;
    let contribution_protocol = scoped_protocol(CONTRIBUTION_PROTOCOL, sample, slot);
    let agreement_protocol = scoped_protocol(AGREEMENT_PROTOCOL, sample, slot);
    let reconstruction_protocol = scoped_protocol(RECONSTRUCTION_PROTOCOL, sample, slot);
    let beacon_protocol = scoped_protocol(BEACON_PROTOCOL, sample, slot);

    let decision = run_agreement(
        shared,
        config,
        logger,
        process_start,
        sample,
        slot,
        &agreement_protocol,
        &protocol,
        proposal.aggregate.digest,
    )?;

    let reconstruction_shares = measured_for(
        shared,
        config,
        logger,
        process_start,
        sample,
        "spurt-beacon",
        "spurt-reconstruction-share-broadcast",
        Some(slot),
        None,
        || {
            let share = protocol
                .reconstruction_share(&proposal.aggregate, &decision)
                .map_err(protocol_error)?;
            broadcast_same(
                shared,
                config,
                &reconstruction_protocol,
                DistributedMessage::SpurtReconstruction { sample, share },
                config.node.n as u32,
            )?;
            let shares = collect_protocol_valid(
                shared,
                &reconstruction_protocol,
                config.node.t + 1,
                Duration::from_secs(300),
                |sender, message| match message {
                    DistributedMessage::SpurtReconstruction {
                        sample: message_sample,
                        share,
                    } if message_sample == sample => Ok(protocol
                        .accept_reconstruction_share(sender, &proposal.aggregate, share)
                        .ok()),
                    _ => Ok(None),
                },
            )?
            .into_messages(&reconstruction_protocol)
            .into_iter()
            .map(|(_, share)| share)
            .collect::<Vec<_>>();
            Ok((shares, None))
        },
    )?;

    let output = measured_for(
        shared,
        config,
        logger,
        process_start,
        sample,
        "spurt-beacon",
        "spurt-reconstruction-pairing-output-durable",
        Some(slot),
        Some("beacon-output"),
        || {
            let value = protocol
                .reconstruct_preverified(&proposal.aggregate, &decision, reconstruction_shares)
                .map_err(protocol_error)?;
            let beacon = protocol.beacon_message(&value).map_err(protocol_error)?;
            broadcast_same(
                shared,
                config,
                &beacon_protocol,
                DistributedMessage::SpurtBeacon {
                    sample,
                    message: Box::new(beacon),
                },
                config.node.n as u32,
            )?;
            let output = protocol
                .persist_reconstructed_output(
                    &proposal.aggregate,
                    &decision,
                    &value,
                    config.node.store_root.join("spurt-outputs.bin"),
                )
                .map_err(protocol_error)?;
            Ok(((output, value), Some(output)))
        },
    )?;

    let late_message_protocols = BTreeSet::from([
        contribution_protocol,
        format!("{agreement_protocol}/prepare"),
        format!("{agreement_protocol}/precommit"),
        format!("{agreement_protocol}/commit"),
        format!("{agreement_protocol}/finalize"),
        reconstruction_protocol,
        beacon_protocol.clone(),
    ]);
    measured_for(
        shared,
        config,
        logger,
        process_start,
        sample,
        "spurt-beacon",
        "spurt-beacon-certificate-relay",
        Some(slot),
        None,
        || {
            let beacons = collect_protocol_valid(
                shared,
                &beacon_protocol,
                config.node.t + 1,
                Duration::from_secs(300),
                |sender, message| match message {
                    DistributedMessage::SpurtBeacon {
                        sample: message_sample,
                        message,
                    } if message_sample == sample => Ok(protocol
                        .accept_beacon_message(sender, &output.1, *message)
                        .ok()),
                    _ => Ok(None),
                },
            )?
            .into_messages(&beacon_protocol)
            .into_iter()
            .map(|(_, message)| message)
            .collect::<Vec<_>>();
            protocol
                .finalize_beacon_preverified(
                    &output.1,
                    beacons,
                    config.node.store_root.join("spurt-certificates.bin"),
                )
                .map_err(protocol_error)?;
            discard_protocols(shared, &late_message_protocols)?;
            Ok(((), None))
        },
    )?;
    Ok(output.0)
}
