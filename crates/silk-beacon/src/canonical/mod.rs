//! Canonical Silk epoch, Quorum Release, reconstruction, and certificate path.
//!
//! This is the only Silk beacon lifecycle used by the experiment runner.

use crate::BeaconError;
use crate::bft::{
    BftParams, BrachaCommittee, DecisionCertificate, DecisionSignature, Proposal, proposal_digest,
    verify_decision_certificate,
};
use crate::support::{mldsa_key, mldsa_verifying_keys};
use crypto_primitives::hash::{hash, hash_len_prefixed};
use crypto_primitives::mldsa::{SigningKey65, VerifyingKey65, public_key_bytes};
use protocol_support::{
    derive_seed,
    store::ProtocolStore,
    wire::{canonical_serialize, wire_len},
};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};
use silk_bavss_po::{
    CompactReconstructionItem, CompactReconstructionPlan, Dealer, DealerPublicTranscript,
    PrivateRow, ProtocolContext, ProtocolParams, build_dealer_certificate, compact_item_from_row,
    par_verify, sign_validation_statement, validate_params, verify_dealer_certificate,
    verify_public_transcript, verify_validation_statement, verify_validation_statement_preparsed,
};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

type ReconstructionPlans = BTreeMap<Vec<u32>, CompactReconstructionPlan>;

pub use silk_bavss_po::{DealerValidationCertificate, EpochValidationData, ValidationStatement};

pub const RELEASE_PROFILE: &str = "mldsa65-signed-release";
pub const BFT_PROFILE: &str = "simple-it-s-holder-priority";

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct CertifiedTranscript {
    pub dealer: u32,
    pub transcript_id: [u8; 32],
}

/// Minimal epoch command `E_e`: one epoch and an ordered set of exactly
/// `t + 1` certified transcript identities.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EpochCommand {
    pub epoch: u64,
    pub transcripts: Vec<CertifiedTranscript>,
    pub approvals: Vec<Vec<ValidationStatement>>,
}

/// Transferable once-per-epoch evidence.  The validation witness is checked
/// by BFT External Validity and is deliberately not repeated here.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EpochCertificate {
    pub command: EpochCommand,
    pub decision_certificate: DecisionCertificate,
}

/// Installed epoch state.  `validation_witness` is local reconstruction
/// context, not part of the public epoch certificate.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CertifiedEpoch {
    pub epoch_certificate: EpochCertificate,
    pub validation_witness: EpochValidationData,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BeaconConfiguration {
    pub sid: Vec<u8>,
    pub epoch: u64,
    pub params: ProtocolParams,
    pub reconstruction_window: u64,
    pub registry_digest: [u8; 32],
    pub context: ProtocolContext,
    pub validation_public_keys: Vec<Vec<u8>>,
    pub decision_public_keys: Vec<Vec<u8>>,
}

impl BeaconConfiguration {
    pub fn verify(&self) -> Result<(), BeaconError> {
        validate_params(self.params)?;
        if self.epoch == 0
            || self.epoch.checked_mul(self.params.l as u64).is_none()
            || self.epoch != self.context.epoch
            || self.validation_public_keys.len() != self.params.n
            || self.decision_public_keys.len() != self.params.n
            || registry_digest(&self.validation_public_keys, &self.decision_public_keys)
                != self.registry_digest
            || ProtocolContext::derive(
                &self.sid,
                self.epoch,
                self.registry_digest,
                self.params,
                self.reconstruction_window,
            )? != self.context
        {
            return Err(BeaconError::InvalidEpoch);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ReleaseAnnouncement {
    pub sender: u32,
    pub sid: Vec<u8>,
    pub epoch: u64,
    pub round: u64,
    pub tau: [u8; 32],
    pub output: [u8; 32],
    pub signature: Vec<u8>,
}

/// Grouped online reconstruction payload.  Sender authentication comes from
/// the authenticated channel, so the payload carries no extra signature,
/// predecessor link, release digest, or validation witness.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ReconstructionMessage {
    pub sender: u32,
    pub index: u32,
    pub items: Vec<CompactReconstructionItem>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AuthenticatedPoint {
    pub sender: u32,
    pub item: CompactReconstructionItem,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DealerPointSet {
    pub dealer: u32,
    pub points: Vec<AuthenticatedPoint>,
}

/// Local evidence that the previous epoch completed and its final release
/// quorum was verified. Fields are private so callers cannot bypass the gate.
pub struct EpochCompletion {
    replica: u32,
    sid: Vec<u8>,
    epoch: u64,
    registry_digest: [u8; 32],
    params: ProtocolParams,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct DurableNodeState {
    pub installed_epoch: Option<[u8; 32]>,
    pub signed_releases: BTreeMap<u32, ReleaseAnnouncement>,
    pub qrout: BTreeMap<u32, [u8; 32]>,
    pub released: BTreeMap<u32, ReconstructionMessage>,
    pub outputs: BTreeMap<u32, [u8; 32]>,
    pub retention_watermark: Option<u64>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub enum GcMode {
    #[default]
    Enabled,
    Off,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct GcStats {
    pub mode: GcMode,
    pub before_bytes: u64,
    pub after_bytes: u64,
    pub reclaimed_bytes: u64,
    pub discarded_objects: u64,
    pub persistent_before_bytes: u64,
    pub persistent_after_bytes: u64,
    pub persistent_bytes_written: u64,
    pub retained_due_to_service_window_bytes: u64,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct QrSupport {
    pub matching_senders: Vec<u32>,
    pub guaranteed_correct_predecessor_completers: usize,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
enum DurableRecord {
    Install {
        epoch: u64,
        decision_digest: [u8; 32],
    },
    SignedRelease {
        index: u32,
        announcement: ReleaseAnnouncement,
    },
    QrOut {
        index: u32,
        digest: [u8; 32],
    },
    Released {
        index: u32,
        message: ReconstructionMessage,
    },
    CompletedOutput {
        index: u32,
        output: [u8; 32],
    },
    RetentionWatermark {
        epoch: u64,
        mode: GcMode,
    },
}

pub struct BeaconNode {
    pub id: u32,
    config: BeaconConfiguration,
    certified_epoch: CertifiedEpoch,
    release_key: SigningKey65,
    release_verifying_keys: Arc<[VerifyingKey65]>,
    epoch_digest: [u8; 32],
    retained_rows: BTreeMap<u32, PrivateRow>,
    durable: DurableNodeState,
    matching: BTreeMap<(u32, [u8; 32]), BTreeSet<u32>>,
    pending_reconstruction: BTreeMap<u32, BTreeMap<u32, ReconstructionMessage>>,
    reconstruction_plans: ReconstructionPlans,

    release_evidence: BTreeMap<u32, BTreeMap<u32, ReleaseAnnouncement>>,
    store_path: PathBuf,
}

pub(crate) struct BeaconCommittee {
    pub config: BeaconConfiguration,
    validation_keys: Vec<SigningKey65>,
    validation_verifying_keys: Arc<[VerifyingKey65]>,
    bft: BrachaCommittee,
    seed: u64,
}

mod committee;
mod lifecycle;
mod quorum_release;
mod reconstruction;
mod retention;

mod verification;

pub(crate) use verification::certified_transcript;
use verification::{
    beacon_output, epoch_tau, gc_stats, proposal_payload, qr_digest, registry_digest,
    release_message, remove_matching_index, remove_pending_index, transcript_for,
};
pub use verification::{
    verify_beacon, verify_certified_epoch, verify_epoch_certificate, verify_epoch_command,
};
