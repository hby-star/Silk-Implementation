use crate::hash::hash_concat;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MerkleSibling {
    pub hash: [u8; 32],
    pub is_left: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MerkleProof {
    pub index: usize,
    pub leaf_count: usize,
    pub siblings: Vec<MerkleSibling>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MerkleProofNode {
    pub level: usize,
    pub index: usize,
    pub hash: [u8; 32],
}

/// Canonical proof for a sorted set of leaves in one Merkle tree.
///
/// Siblings shared by two selected leaves appear once.  The `(level, index)`
/// coordinates make duplicate, missing, reordered, and unused proof nodes
/// fail closed during verification.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MerkleMultiProof {
    pub leaf_count: usize,
    pub indices: Vec<usize>,
    pub siblings: Vec<MerkleProofNode>,
}

impl MerkleProof {
    pub fn verify(&self, node_domain: &[u8], root: &[u8; 32], leaf: &[u8; 32]) -> bool {
        if self.leaf_count == 0 || self.index >= self.leaf_count {
            return false;
        }
        let value = self.siblings.iter().fold(*leaf, |current, sibling| {
            if sibling.is_left {
                parent(node_domain, &sibling.hash, &current)
            } else {
                parent(node_domain, &current, &sibling.hash)
            }
        });
        value == *root
    }
}

impl MerkleMultiProof {
    pub fn verify(
        &self,
        node_domain: &[u8],
        root: &[u8; 32],
        leaves: &[(usize, [u8; 32])],
    ) -> bool {
        if self.leaf_count == 0
            || self.indices.is_empty()
            || self.indices.iter().any(|index| *index >= self.leaf_count)
            || !strictly_sorted(&self.indices)
            || leaves.len() != self.indices.len()
            || leaves
                .iter()
                .zip(&self.indices)
                .any(|((index, _), expected)| index != expected)
        {
            return false;
        }
        let mut proof_nodes = BTreeMap::new();
        for sibling in &self.siblings {
            if proof_nodes
                .insert((sibling.level, sibling.index), sibling.hash)
                .is_some()
            {
                return false;
            }
        }
        let mut current = leaves.iter().copied().collect::<BTreeMap<_, _>>();
        let mut width = self.leaf_count;
        let mut level = 0usize;
        while width > 1 {
            let selected = current.keys().copied().collect::<BTreeSet<_>>();
            let mut parents = BTreeMap::new();
            for index in selected.iter().copied() {
                let parent_index = index / 2;
                if parents.contains_key(&parent_index) {
                    continue;
                }
                let left_index = parent_index * 2;
                let right_index = left_index + 1;
                let Some(left) =
                    node_for_verification(level, left_index, width, &current, &mut proof_nodes)
                else {
                    return false;
                };
                let right = if right_index >= width {
                    left
                } else {
                    let Some(right) = node_for_verification(
                        level,
                        right_index,
                        width,
                        &current,
                        &mut proof_nodes,
                    ) else {
                        return false;
                    };
                    right
                };
                parents.insert(parent_index, parent(node_domain, &left, &right));
            }
            current = parents;
            width = width.div_ceil(2);
            level += 1;
        }
        proof_nodes.is_empty() && current.get(&0) == Some(root)
    }
}

fn node_for_verification(
    level: usize,
    index: usize,
    width: usize,
    selected: &BTreeMap<usize, [u8; 32]>,
    proof_nodes: &mut BTreeMap<(usize, usize), [u8; 32]>,
) -> Option<[u8; 32]> {
    if index >= width {
        return None;
    }
    selected
        .get(&index)
        .copied()
        .or_else(|| proof_nodes.remove(&(level, index)))
}

fn strictly_sorted<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

#[derive(Clone, Debug)]
pub struct MerkleTree {
    node_domain: Vec<u8>,
    levels: Vec<Vec<[u8; 32]>>,
}

impl MerkleTree {
    pub fn new(node_domain: &[u8], leaves: Vec<[u8; 32]>) -> Result<Self, MerkleError> {
        if leaves.is_empty() {
            return Err(MerkleError::EmptyTree);
        }
        let mut levels = vec![leaves];
        while levels.last().expect("level exists").len() > 1 {
            let previous = levels.last().expect("level exists");
            levels.push(
                previous
                    .chunks(2)
                    .map(|chunk| parent(node_domain, &chunk[0], chunk.get(1).unwrap_or(&chunk[0])))
                    .collect(),
            );
        }
        Ok(Self {
            node_domain: node_domain.to_vec(),
            levels,
        })
    }

    /// Compute a root in one reusable buffer, without storing proof levels.
    pub fn root_only(node_domain: &[u8], leaves: &[[u8; 32]]) -> Result<[u8; 32], MerkleError> {
        if leaves.is_empty() {
            return Err(MerkleError::EmptyTree);
        }
        let mut level = leaves.to_vec();
        let mut width = level.len();
        while width > 1 {
            for i in 0..width.div_ceil(2) {
                level[i] = parent(
                    node_domain,
                    &level[2 * i],
                    &level[(2 * i + 1).min(width - 1)],
                );
            }
            width = width.div_ceil(2);
        }
        Ok(level[0])
    }

    pub fn root(&self) -> [u8; 32] {
        self.levels.last().expect("root exists")[0]
    }

    pub fn proof(&self, index: usize) -> Result<MerkleProof, MerkleError> {
        let leaf_count = self.levels[0].len();
        if index >= leaf_count {
            return Err(MerkleError::InvalidIndex);
        }
        let mut cursor = index;
        let mut siblings = Vec::with_capacity(self.levels.len().saturating_sub(1));
        for level in self.levels.iter().take(self.levels.len() - 1) {
            let sibling_index = if cursor.is_multiple_of(2) {
                cursor + 1
            } else {
                cursor - 1
            };
            siblings.push(MerkleSibling {
                hash: *level.get(sibling_index).unwrap_or(&level[cursor]),
                is_left: sibling_index < cursor,
            });
            cursor /= 2;
        }
        Ok(MerkleProof {
            index,
            leaf_count,
            siblings,
        })
    }

    pub fn multi_proof(&self, indices: &[usize]) -> Result<MerkleMultiProof, MerkleError> {
        let leaf_count = self.levels[0].len();
        if indices.is_empty()
            || indices.iter().any(|index| *index >= leaf_count)
            || !strictly_sorted(indices)
        {
            return Err(MerkleError::InvalidIndex);
        }
        let mut selected = indices.iter().copied().collect::<BTreeSet<_>>();
        let mut siblings = Vec::new();
        for (level_index, level) in self
            .levels
            .iter()
            .take(self.levels.len().saturating_sub(1))
            .enumerate()
        {
            let mut next = BTreeSet::new();
            for index in selected.iter().copied() {
                let sibling = if index.is_multiple_of(2) {
                    index + 1
                } else {
                    index - 1
                };
                if sibling < level.len() && !selected.contains(&sibling) {
                    siblings.push(MerkleProofNode {
                        level: level_index,
                        index: sibling,
                        hash: level[sibling],
                    });
                }
                next.insert(index / 2);
            }
            selected = next;
        }
        siblings.sort_by_key(|node| (node.level, node.index));
        Ok(MerkleMultiProof {
            leaf_count,
            indices: indices.to_vec(),
            siblings,
        })
    }

    pub fn verify(&self, proof: &MerkleProof, root: &[u8; 32], leaf: &[u8; 32]) -> bool {
        proof.verify(&self.node_domain, root, leaf)
    }
}

fn parent(domain: &[u8], left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    hash_concat(domain, &[left, right])
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum MerkleError {
    #[error("empty Merkle tree")]
    EmptyTree,
    #[error("invalid Merkle index")]
    InvalidIndex,
}
