//! Spurt's DBDH-PVSS beacon and fault-free agreement path.
//!
//! Network transport, process orchestration, and measurement are intentionally
//! outside this crate. This crate owns the cryptographic transcript, protocol
//! validation, signed agreement transitions, reconstruction, and output
//! certificate.

#![forbid(unsafe_code)]

mod agreement;
mod error;
mod protocol;
mod pvss;
mod types;

pub use agreement::{
    AgreementDecision, AgreementPhase, AgreementReplica, VerifiedAgreementMessage,
};
pub use error::SpurtError;
pub use protocol::{
    AGREEMENT_PROTOCOL, BEACON_PROTOCOL, CONTRIBUTION_PROTOCOL, PROPOSAL_PROTOCOL,
    RECONSTRUCTION_PROTOCOL, SpurtProtocol, SpurtSetup, VerifiedBeaconMessage,
    VerifiedDealerContribution, VerifiedReconstructionShare,
};
pub use types::{
    AggregateTranscript, BeaconMessage, BeaconValue, DealerContribution, DleqProof,
    PublicParameters, ReceiverProposal, ReconstructionShare, SignedAgreementMessage,
};

pub const FIDELITY: &str = "F2";
pub const PROFILE: &str = "spurt-beacon";
pub const COVERAGE: &str = "fixed-committee-honest-leader-normal-path-only";
pub const CLAIM_SCOPE: &str = "normal-path-performance";
