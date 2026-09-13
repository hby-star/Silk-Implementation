use curve25519_dalek::scalar::Scalar;
use rondo_bavss_po::protocol::types::{BatchEvaluationProof, BreezeQc, BreezeRowData};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AggregateShare {
    pub epoch: u64,
    pub round: u64,
    pub height: u64,
    pub slot: u32,
    pub holder: u32,
    pub share: Scalar,
}

/// One dealer row carried only on the fault-recovery path. The proof binds
/// the complete row, so a receiver can authenticate the requested slot before
/// accepting the dealer share.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DealerFallbackShare {
    pub dealer_id: usize,
    pub row: BreezeRowData,
    pub proof: BatchEvaluationProof,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FallbackShare {
    pub epoch: u64,
    pub round: u64,
    pub height: u64,
    pub slot: u32,
    pub holder: u32,
    pub dealers: Vec<DealerFallbackShare>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CommonSubsetEntry {
    pub dealer_id: usize,
    pub commitment_root: [u8; 32],
    pub validation: BreezeQc,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FirstRoundPayload {
    pub tag: String,
    pub epoch: u64,
    pub round: u64,
    pub slot: u32,
    pub entries: Vec<CommonSubsetEntry>,
}
