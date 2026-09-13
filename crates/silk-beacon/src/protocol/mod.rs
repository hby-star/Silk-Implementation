//! Distributed Silk facade in the paper's Prepare--Agree--Reconstruct order.
//!
//! Transport adapters hand decoded messages to these phase modules. They own
//! sender, context, deduplication, quorum, and certificate checks; process
//! lifecycle and measurement remain in `experiment-runner`.

mod agree;
mod prepare;
pub mod proposal_encoding;
mod quorum_release;
mod reconstruct;

use crate::{BeaconCommittee, BeaconError};
use silk_bavss_po::ProtocolParams;

pub use agree::{
    COMMIT_PROTOCOL, DECISION_SIGNATURE_PROTOCOL, ECHO_PROTOCOL, PROPOSAL_PROTOCOL, READY_PROTOCOL,
    VerifiedCertifiedEpoch, VerifiedDecisionSignature, VerifiedEpochCommand, VerifiedProposal,
};
pub use prepare::{
    CERTIFIED_DEALER_PROTOCOL, DealerPublicTranscript, PUBLIC_PROTOCOL, PrivateRow, ROW_PROTOCOL,
    SilkSharing, VALIDATION_PROTOCOL, VerifiedDealerCertificate, VerifiedEpochValidation,
    VerifiedValidationStatement,
};
pub use quorum_release::RELEASE_PROTOCOL;
pub use reconstruct::{RECONSTRUCTION_PROTOCOL, VerifiedReconstructionMessage};

pub struct SilkProtocol {
    committee: BeaconCommittee,
    node_id: u32,
    approved_transcripts: std::sync::Mutex<std::collections::BTreeMap<u32, [u8; 32]>>,
}

impl SilkProtocol {
    pub fn new(
        n: usize,
        t: usize,
        slots: usize,
        epoch: u64,
        seed: u64,
        node_id: u32,
    ) -> Result<Self, BeaconError> {
        let params = ProtocolParams::new(n, t, slots, 1)?;
        if node_id as usize >= n {
            return Err(BeaconError::InvalidValidation);
        }
        Ok(Self {
            committee: BeaconCommittee::derive(params, epoch, seed, 1)?,
            node_id,
            approved_transcripts: std::sync::Mutex::new(std::collections::BTreeMap::new()),
        })
    }

    pub(super) fn params(&self) -> ProtocolParams {
        self.committee.config.params
    }

    pub fn slots(&self) -> usize {
        self.params().l
    }

    pub(super) fn verification_context(&self) -> [u8; 32] {
        self.committee.config.context.config_digest
    }

    pub(super) fn require_sharing_context(&self, sharing: &SilkSharing) -> Result<(), BeaconError> {
        if sharing.context != self.verification_context() || sharing.replica != self.node_id {
            return Err(BeaconError::InvalidValidation);
        }
        Ok(())
    }
}
