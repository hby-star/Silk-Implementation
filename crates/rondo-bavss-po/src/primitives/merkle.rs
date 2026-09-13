use crate::BreezeError;
use crypto_primitives::hash::hash_concat;
use crypto_primitives::merkle as shared;
use serde::{Deserialize, Serialize};

const NODE_DOMAIN: &[u8] = b"Rondo-Breeze-merkle-node-v1";

pub use shared::MerkleSibling;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct MerkleProof(shared::MerkleProof);

impl MerkleProof {
    pub(crate) fn verify(&self, root: &[u8; 32], leaf: &[u8; 32]) -> bool {
        self.0.verify(NODE_DOMAIN, root, leaf)
    }

    pub(crate) fn index(&self) -> usize {
        self.0.index
    }

    pub fn leaf_count(&self) -> usize {
        self.0.leaf_count
    }
}

#[derive(Clone, Debug)]
pub(crate) struct MerkleTree(shared::MerkleTree);

impl MerkleTree {
    pub(crate) fn new(leaves: Vec<[u8; 32]>) -> Result<Self, BreezeError> {
        shared::MerkleTree::new(NODE_DOMAIN, leaves)
            .map(Self)
            .map_err(map_error)
    }

    pub(crate) fn root(&self) -> [u8; 32] {
        self.0.root()
    }

    pub(crate) fn proof(&self, index: usize) -> Result<MerkleProof, BreezeError> {
        self.0.proof(index).map(MerkleProof).map_err(map_error)
    }
}

pub(crate) fn commitment_leaf(index: usize, compressed: &[u8; 32]) -> [u8; 32] {
    hash_concat(
        b"Rondo-Breeze-commitment-leaf-v1",
        &[&(index as u64).to_le_bytes(), compressed],
    )
}

fn map_error(error: shared::MerkleError) -> BreezeError {
    match error {
        shared::MerkleError::EmptyTree => BreezeError::EmptyCommitmentVector,
        shared::MerkleError::InvalidIndex => BreezeError::InvalidBeaconIndex,
    }
}
