//! Canonical Spurt signing payloads and content digests.

use protocol_support::wire::canonical_serialize;

use crate::SpurtError;
use crate::types::{
    BeaconMessage, BeaconValue, DealerContribution, ReceiverProposal, ReconstructionShare,
};

pub(super) fn contribution_payload(
    contribution: &DealerContribution,
) -> Result<Vec<u8>, SpurtError> {
    Ok(canonical_serialize(&(
        "Spurt-contribution-v1",
        contribution.epoch,
        contribution.height,
        contribution.dealer,
        &contribution.commitments,
        &contribution.ciphertexts,
        &contribution.proofs,
    ))?)
}

pub(super) fn proposal_payload(proposal: &ReceiverProposal) -> Result<Vec<u8>, SpurtError> {
    Ok(canonical_serialize(&(
        "Spurt-private-proposal-v1",
        proposal.leader,
        proposal.receiver,
        &proposal.aggregate,
        &proposal.column,
    ))?)
}

pub(super) fn reconstruction_payload(message: &ReconstructionShare) -> Result<Vec<u8>, SpurtError> {
    Ok(canonical_serialize(&(
        "Spurt-reconstruction-share-v1",
        message.epoch,
        message.height,
        message.digest,
        message.holder,
        message.share,
    ))?)
}

pub(super) fn beacon_payload(message: &BeaconMessage) -> Result<Vec<u8>, SpurtError> {
    Ok(canonical_serialize(&(
        "Spurt-beacon-message-v1",
        &message.value,
        message.signer,
    ))?)
}

pub(super) fn aggregate_digest(
    epoch: u64,
    height: u64,
    dealer_ids: &[u32],
    commitments: &[blstrs::G2Projective],
    ciphertexts: &[blstrs::G1Projective],
) -> Result<[u8; 32], SpurtError> {
    let encoded = canonical_serialize(&(
        "Spurt-aggregate-transcript-v1",
        epoch,
        height,
        dealer_ids,
        commitments,
        ciphertexts,
    ))?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"Spurt-aggregate-digest-v1");
    hasher.update(&encoded);
    Ok(*hasher.finalize().as_bytes())
}

pub(super) fn output_digest(value: &BeaconValue) -> Result<[u8; 32], SpurtError> {
    let encoded = canonical_serialize(value)?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"Spurt-beacon-output-digest-v1");
    hasher.update(&encoded);
    Ok(*hasher.finalize().as_bytes())
}
