//! Rondo-BFT normal-path messages, certificates, and pipeline schedule.

use std::collections::BTreeMap;

use protocol_support::wire::canonical_serialize;
use serde::{Deserialize, Serialize};

use super::super::Request;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum QcKind {
    Prepare,
    PreCommit,
    Commit,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Block {
    pub parent_hash: [u8; 32],
    pub view: u64,
    pub height: u64,
    pub request: Request,
}

impl Block {
    pub fn hash(&self) -> [u8; 32] {
        crypto_primitives::hash::hash(
            &canonical_serialize(&("rondo/bft/block/v1", self)).expect("block serializes"),
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Vote {
    pub signer: u32,
    pub kind: QcKind,
    pub block_hash: [u8; 32],
    pub view: u64,
    pub height: u64,
    pub signature: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct QuorumCertificate {
    pub kind: QcKind,
    pub block_hash: [u8; 32],
    pub view: u64,
    pub height: u64,
    pub signers: Vec<u32>,
    pub aggregate_signature: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Proposal {
    pub leader: u32,
    pub block: Block,
    pub high_qc: Option<QuorumCertificate>,
    pub signature: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DecisionProof {
    pub proposal: Proposal,
    pub prepare_qc: QuorumCertificate,
    pub precommit_qc: QuorumCertificate,
    pub commit_qc: QuorumCertificate,
}

impl DecisionProof {
    pub fn block(&self) -> &Block {
        &self.proposal.block
    }
}

/// The active block slots in one normal-case pipeline wave.
///
/// Wave `w` proposes block `w`, advances block `w-1` through Pre-Commit,
/// block `w-2` through Commit, and block `w-3` through Decide. The final three
/// waves drain the outstanding blocks without adding no-op blocks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PipelineWave {
    pub index: usize,
    pub propose_slot: Option<usize>,
    pub precommit_slot: Option<usize>,
    pub commit_slot: Option<usize>,
    pub decide_slot: Option<usize>,
}

pub fn pipeline_waves(blocks: usize) -> impl ExactSizeIterator<Item = PipelineWave> {
    let waves = if blocks == 0 {
        0
    } else {
        blocks.saturating_add(3)
    };
    (0..waves).map(move |index| PipelineWave {
        index,
        propose_slot: (index < blocks).then_some(index),
        precommit_slot: index.checked_sub(1).filter(|slot| *slot < blocks),
        commit_slot: index.checked_sub(2).filter(|slot| *slot < blocks),
        decide_slot: index.checked_sub(3).filter(|slot| *slot < blocks),
    })
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ReplicaState {
    pub cview: u64,
    pub next_height: u64,
    pub high_qc: Option<QuorumCertificate>,
    pub locked_qc: Option<QuorumCertificate>,
    pub confirm_qc: Option<QuorumCertificate>,
    pub last_voted: BTreeMap<QcKind, (u64, u64, [u8; 32])>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) enum DurableRecord {
    VoteIntent {
        proposal: Box<Proposal>,
        kind: QcKind,
        phase_qc: Option<QuorumCertificate>,
    },
    Decided(Box<DecisionProof>),
    Pruned {
        delivered_height: u64,
    },
}
