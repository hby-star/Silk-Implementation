use crate::primitives::merkle::MerkleProof;
use serde::{Deserialize, Serialize};

/// One recursion round in Rondo Fig. 7--8 for a receiver's proof member.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BatchEvalProofRound {
    pub removed_scalar: Option<[u8; 32]>,
    pub l_point: [u8; 32],
    pub r_point: [u8; 32],
    pub transcript_root: [u8; 32],
    pub transcript_branch: MerkleProof,
}

/// One receiver's member of the `BatchEval` proof vector. All members share
/// every recursive challenge.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BatchEvalProofMember {
    pub statement_index: u32,
    pub statement_count: u32,
    pub rounds: Vec<BatchEvalProofRound>,
    pub final_scalar: [u8; 32],
}
