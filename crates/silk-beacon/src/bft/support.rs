use super::Proposal;
use protocol_support::wire::canonical_serialize;
use thiserror::Error;

pub fn proposal_digest(proposal: &Proposal) -> [u8; 32] {
    crypto_primitives::hash::hash(&canonical_serialize(proposal).expect("proposal serializes"))
}

pub fn decision_message(epoch: u64, proposal: &Proposal) -> Vec<u8> {
    PreparedDecision::new(epoch, proposal).message
}

/// Immutable binding of one proposal to its signing context. Payload encoding
/// and hashing happen once, independently of the number of quorum signatures.
pub(crate) struct PreparedDecision {
    pub(crate) epoch: u64,
    pub(crate) instance: u64,
    pub(crate) digest: [u8; 32],
    pub(crate) message: Vec<u8>,
}

impl PreparedDecision {
    pub(crate) fn new(epoch: u64, proposal: &Proposal) -> Self {
        let digest = proposal_digest(proposal);
        Self {
            epoch,
            instance: proposal.instance,
            digest,
            message: encode_decision_message(epoch, proposal.instance, digest),
        }
    }
}

fn encode_decision_message(epoch: u64, instance: u64, digest: [u8; 32]) -> Vec<u8> {
    canonical_serialize(&("silk/epoch-decision/v1", epoch, instance, digest))
        .expect("decision statement serializes")
}

#[derive(Debug, Error)]
pub enum BftError {
    #[error("invalid BFT parameters")]
    InvalidParameters,
    #[error("invalid public decision certificate")]
    InvalidDecisionCertificate,
}
