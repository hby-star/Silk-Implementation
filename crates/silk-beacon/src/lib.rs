//! Silk fixed-committee beacon protocol.

#![forbid(unsafe_code)]

pub mod bft;
mod canonical;
pub mod protocol;
pub mod simple_it;
mod support;

pub(crate) use canonical::BeaconCommittee;
pub use canonical::{
    AuthenticatedPoint, BFT_PROFILE, BeaconConfiguration, BeaconNode, CertifiedEpoch,
    CertifiedTranscript, DealerPointSet, DealerValidationCertificate, DurableNodeState,
    EpochCertificate, EpochCommand, EpochCompletion, EpochValidationData, GcMode, GcStats,
    QrSupport, RELEASE_PROFILE, ReconstructionMessage, ReleaseAnnouncement, ValidationStatement,
    verify_beacon, verify_certified_epoch, verify_epoch_certificate, verify_epoch_command,
};
pub use silk_bavss_po::{PROTOCOL_REVISION, VALIDATION_PROFILE, WIRE_PROFILE};
pub use support::BeaconError;

pub const IMPLEMENTATION_PROFILE: &str = "silk-beacon";
