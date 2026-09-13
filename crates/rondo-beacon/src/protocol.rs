//! Per-replica Rondo beacon state and pure protocol transitions.

mod agree;
mod prepare;
mod reconstruct;

use std::collections::BTreeMap;
use std::path::Path;

use protocol_support::store::{ProtocolStore, StoreError};
use protocol_support::wire::WireError;
use rondo_bavss_po::BreezeError;
use rondo_bavss_po::protocol::breeze_reconstruct::CompactAggregateReconstructor;
use rondo_bavss_po::protocol::breeze_verify::{BreezeEvaluationVerifier, BreezeReceiver};
use rondo_bavss_po::protocol::types::ProtocolParams;
pub use rondo_bavss_po::protocol::types::{
    BatchEvaluationProof, BreezePublicData, BreezeQc, BreezeRowData, BreezeValidationCertificate,
};
use thiserror::Error;

use crate::bft::BftError;

pub const SHARE_PROTOCOL: &str = "rondo/beacon/breeze-share/v2";
pub const VALIDATION_PROTOCOL: &str = "rondo/beacon/breeze-validation/v2";
pub const VALIDATED_PROTOCOL: &str = "rondo/beacon/breeze-validated/v2";
pub const PROPOSAL_PROTOCOL: &str = "rondo/beacon/bft-proposal/v1";
pub const VOTE_PROTOCOL: &str = "rondo/beacon/bft-vote/v1";
pub const QC_PROTOCOL: &str = "rondo/beacon/bft-qc/v1";
pub const AGGREGATE_PROTOCOL: &str = "rondo/beacon/aggregate-share/v2";
pub const FALLBACK_REQUEST_PROTOCOL: &str = "rondo/beacon/fallback-request/v1";
pub const FALLBACK_SHARE_PROTOCOL: &str = "rondo/beacon/fallback-share/v1";

#[derive(Debug, Error)]
pub enum RondoError {
    #[error(transparent)]
    Breeze(#[from] BreezeError),
    #[error(transparent)]
    Bft(#[from] BftError),
    #[error(transparent)]
    Wire(#[from] WireError),
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error("invalid Rondo protocol state: {0}")]
    Invalid(&'static str),
}

#[derive(Clone)]
pub struct RondoShare {
    pub public: BreezePublicData,
    pub row: BreezeRowData,
    pub proof: BatchEvaluationProof,
}

#[derive(Clone)]
pub struct RetainedDealer {
    public: BreezePublicData,
    row: BreezeRowData,
    proof: BatchEvaluationProof,
}

#[derive(Clone)]
pub struct ValidatedDealer {
    pub sender: u32,
    pub dealer_id: usize,
    pub commitment_root: [u8; 32],
    pub qc: BreezeQc,
}

#[derive(Clone)]
pub struct VerifiedDealerMaterial {
    context: [u8; 32],
    public: BreezePublicData,
    qc: BreezeQc,
}
impl VerifiedDealerMaterial {
    pub fn dealer_id(&self) -> usize {
        self.public.dealer_id
    }
    pub fn public(&self) -> &BreezePublicData {
        &self.public
    }
    pub fn qc(&self) -> &BreezeQc {
        &self.qc
    }
}

pub struct VerifiedLocalValidationCertificate {
    verification_context: [u8; 32],
    certificate: BreezeValidationCertificate,
}

pub struct RondoSetup {
    params: ProtocolParams,
    epoch: u64,
    node_id: u32,
    committee: BTreeMap<usize, Vec<u8>>,
    receiver: BreezeReceiver,
    local_public: BreezePublicData,
    local_rows: Vec<BreezeRowData>,
    local_proofs: Vec<BatchEvaluationProof>,
    verification_context: [u8; 32],
}

pub struct RondoSetupBootstrap {
    params: ProtocolParams,
    epoch: u64,
    seed: u64,
    node_id: u32,
    committee: BTreeMap<usize, Vec<u8>>,
    receiver: BreezeReceiver,
}

#[derive(Clone)]
struct StoredDealer {
    public: BreezePublicData,
    retained: Option<RetainedDealer>,
    qc: BreezeQc,
}

pub struct RondoEpoch {
    params: ProtocolParams,
    epoch: u64,
    selected: BTreeMap<usize, StoredDealer>,
    subset: [u8; 32],
    aggregate_reconstructors: std::sync::Mutex<BTreeMap<Vec<u32>, CompactAggregateReconstructor>>,
    fallback_verifier: BreezeEvaluationVerifier,
}

pub struct FallbackReconstruction<'a> {
    epoch: &'a RondoEpoch,
    height: u64,
    slot: u32,
    accepted_senders: std::collections::BTreeSet<u32>,
    shares: BTreeMap<
        usize,
        BTreeMap<
            u32,
            (
                curve25519_dalek::scalar::Scalar,
                curve25519_dalek::scalar::Scalar,
            ),
        >,
    >,
}

impl RondoEpoch {
    pub fn subset_digest(&self) -> [u8; 32] {
        self.subset
    }

    pub fn persist(&self, path: impl AsRef<Path>) -> Result<u64, RondoError> {
        Ok(ProtocolStore::open(path)?.persist(&(
            self.epoch,
            self.subset,
            self.selected.keys().copied().collect::<Vec<_>>(),
        ))?)
    }
}
