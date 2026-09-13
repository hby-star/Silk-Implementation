//! Fixed-committee normal-case Rondo-BFT from Meng et al., Figure 9.
//!
//! Every block executes the paper's explicit Prepare, Pre-Commit, Commit, and
//! Decide phases. Consecutive blocks use the paper's HotStuff-style normal-case
//! pipeline: a child proposal extends the parent's prepareQC while older blocks
//! continue through Pre-Commit, Commit, and Decide. View change,
//! reconfiguration, catch-up, and state transfer remain outside this research
//! profile.

use super::{BftError, BftParams, Request};
use crypto_primitives::bls::{self, PublicKey, SecretKey};
use protocol_support::wire::canonical_serialize;
use std::collections::BTreeMap;
use std::path::Path;

mod durable;
mod types;

use durable::persist;
use types::DurableRecord;
pub use types::{
    Block, DecisionProof, PipelineWave, Proposal, QcKind, QuorumCertificate, ReplicaState, Vote,
    pipeline_waves,
};

const DST: &[u8] = b"RONDO-BFT-BLS12381G2-XMD:SHA-256_SSWU_RO_NORMAL_V1";
pub const PROFILE: &str = "rondo-hotstuff-four-phase";

pub struct NormalReplica {
    params: BftParams,
    node_id: u32,
    key: SecretKey,
    public_keys: Vec<PublicKey>,
    state: ReplicaState,
    pending: BTreeMap<[u8; 32], Block>,
    delivered: BTreeMap<u64, Block>,
    verified_phase_qcs: BTreeMap<(QcKind, [u8; 32]), QuorumCertificate>,
}

impl NormalReplica {
    pub fn new(
        params: BftParams,
        node_id: u32,
        seed: [u8; 32],
        initial_height: u64,
    ) -> Result<Self, BftError> {
        if node_id as usize >= params.n || initial_height == 0 {
            return Err(BftError::InvalidParameters);
        }
        let mut keys = Vec::with_capacity(params.n);
        let mut public_keys = Vec::with_capacity(params.n);
        for node in 0..params.n {
            let key = bls::derive_secret_key(
                &seed,
                b"Rondo-BFT-normal-path-key-v1",
                &[&(node as u64).to_be_bytes()],
            )
            .map_err(|_| BftError::Crypto("BLS key generation".into()))?;
            public_keys.push(bls::public_key(&key));
            keys.push(key);
        }
        Ok(Self {
            params,
            node_id,
            key: keys
                .get(node_id as usize)
                .ok_or(BftError::InvalidParameters)?
                .clone(),
            public_keys,
            state: ReplicaState {
                cview: 0,
                next_height: initial_height,
                high_qc: None,
                locked_qc: None,
                confirm_qc: None,
                last_voted: BTreeMap::new(),
            },
            pending: BTreeMap::new(),
            delivered: BTreeMap::new(),
            verified_phase_qcs: BTreeMap::new(),
        })
    }

    pub fn leader(&self, view: u64) -> u32 {
        (view as usize % self.params.n) as u32
    }

    pub fn propose(&self, view: u64, height: u64, request: Request) -> Result<Proposal, BftError> {
        if self.node_id != self.leader(view)
            || view != self.state.cview
            || height != self.next_phase_height(QcKind::Prepare)?
        {
            return Err(BftError::InvalidBlock);
        }
        let parent_hash = self
            .state
            .high_qc
            .as_ref()
            .map_or([0; 32], |qc| qc.block_hash);
        if let Some(high_qc) = &self.state.high_qc {
            if high_qc.kind != QcKind::Prepare
                || high_qc.height.checked_add(1) != Some(height)
                || high_qc.view > view
            {
                return Err(BftError::InvalidBlock);
            }
        } else if height != self.state.next_height {
            return Err(BftError::InvalidBlock);
        }
        let block = Block {
            parent_hash,
            view,
            height,
            request,
        };
        let mut proposal = Proposal {
            leader: self.node_id,
            high_qc: self.state.high_qc.clone(),
            block,
            signature: Vec::new(),
        };
        proposal.signature = bls::sign(&self.key, &proposal_message(&proposal), DST, &[]);
        Ok(proposal)
    }

    pub fn vote<F: Fn(&Request) -> bool>(
        &mut self,
        proposal: &Proposal,
        kind: QcKind,
        phase_qc: Option<&QuorumCertificate>,
        valid: F,
        store_path: impl AsRef<Path>,
    ) -> Result<Vote, BftError> {
        let record = DurableRecord::VoteIntent {
            proposal: Box::new(proposal.clone()),
            kind,
            phase_qc: phase_qc.cloned(),
        };
        self.validate_vote_intent(proposal, kind, phase_qc, &valid)?;
        persist(store_path.as_ref(), &record)?;
        self.apply_verified_vote_intent(proposal.clone(), kind, phase_qc.cloned())?;
        let block_hash = proposal.block.hash();
        Ok(Vote {
            signer: self.node_id,
            kind,
            block_hash,
            view: proposal.block.view,
            height: proposal.block.height,
            signature: bls::sign(
                &self.key,
                &vote_message(kind, block_hash, proposal.block.view, proposal.block.height),
                DST,
                &[],
            ),
        })
    }

    /// Builds a QC from exactly one canonical quorum and validates the whole
    /// aggregate with one BLS fast-aggregate verification. All votes in a
    /// phase sign the same message, so this is equivalent to verifying every
    /// signature separately on the measured fault-free normal path. Invalid
    /// aggregate quorums fail closed; the profile has no per-vote slow path.
    pub fn aggregate_qc_checked(
        &self,
        proposal: &Proposal,
        kind: QcKind,
        votes: &[(u32, Vote)],
    ) -> Result<QuorumCertificate, BftError> {
        if self.node_id != proposal.leader || votes.len() != self.params.quorum() {
            return Err(BftError::InvalidVote);
        }
        let block_hash = proposal.block.hash();
        let mut selected = votes
            .iter()
            .map(|(sender, vote)| {
                if vote.signer != *sender
                    || vote.signer as usize >= self.params.n
                    || vote.kind != kind
                    || vote.block_hash != block_hash
                    || vote.view != proposal.block.view
                    || vote.height != proposal.block.height
                {
                    return Err(BftError::InvalidVote);
                }
                Ok(vote.clone())
            })
            .collect::<Result<Vec<_>, _>>()?;
        selected.sort_by_key(|vote| vote.signer);
        if selected
            .windows(2)
            .any(|pair| pair[0].signer == pair[1].signer)
        {
            return Err(BftError::InvalidVote);
        }
        let qc = self.build_qc_from_verified(proposal, kind, selected)?;
        self.verify_qc(&qc).map_err(|_| BftError::InvalidVote)?;
        Ok(qc)
    }

    fn build_qc_from_verified(
        &self,
        proposal: &Proposal,
        kind: QcKind,
        selected: Vec<Vote>,
    ) -> Result<QuorumCertificate, BftError> {
        let block_hash = proposal.block.hash();
        Ok(QuorumCertificate {
            kind,
            block_hash,
            view: proposal.block.view,
            height: proposal.block.height,
            signers: selected.iter().map(|vote| vote.signer).collect(),
            aggregate_signature: bls::aggregate(
                &selected
                    .iter()
                    .map(|vote| vote.signature.clone())
                    .collect::<Vec<_>>(),
            )
            .map_err(|_| BftError::Crypto("aggregate signature".into()))?,
        })
    }

    pub fn decide(
        &mut self,
        proposal: &Proposal,
        prepare_qc: &QuorumCertificate,
        precommit_qc: &QuorumCertificate,
        commit_qc: &QuorumCertificate,
        store_path: impl AsRef<Path>,
    ) -> Result<DecisionProof, BftError> {
        let proof = DecisionProof {
            proposal: proposal.clone(),
            prepare_qc: prepare_qc.clone(),
            precommit_qc: precommit_qc.clone(),
            commit_qc: commit_qc.clone(),
        };
        self.verify_decision_with_cached_qcs(&proof)?;
        if self.pending.get(&proposal.block.hash()) != Some(&proposal.block) {
            return Err(BftError::InvalidBlock);
        }
        persist(
            store_path.as_ref(),
            &DurableRecord::Decided(Box::new(proof.clone())),
        )?;
        self.apply_verified_decision(proof.clone())?;
        Ok(proof)
    }

    pub fn verify_qc(&self, qc: &QuorumCertificate) -> Result<(), BftError> {
        if qc.signers.len() != self.params.quorum() {
            return Err(BftError::InvalidQc);
        }
        let mut canonical = qc.signers.clone();
        canonical.sort_unstable();
        canonical.dedup();
        if canonical != qc.signers
            || canonical
                .iter()
                .any(|signer| *signer as usize >= self.params.n)
        {
            return Err(BftError::InvalidQc);
        }
        let keys = qc
            .signers
            .iter()
            .map(|signer| &self.public_keys[*signer as usize])
            .collect::<Vec<_>>();
        bls::fast_aggregate_verify(
            &keys,
            &qc.aggregate_signature,
            &vote_message(qc.kind, qc.block_hash, qc.view, qc.height),
            DST,
        )
        .map_err(|_| BftError::InvalidQc)
    }

    pub fn verify_decision_proof(&self, proof: &DecisionProof) -> Result<(), BftError> {
        self.verify_proposal_envelope(&proof.proposal)?;
        let block = &proof.proposal.block;
        let block_hash = block.hash();
        for (expected, qc) in [
            (QcKind::Prepare, &proof.prepare_qc),
            (QcKind::PreCommit, &proof.precommit_qc),
            (QcKind::Commit, &proof.commit_qc),
        ] {
            self.verify_qc(qc)?;
            if qc.kind != expected
                || qc.block_hash != block_hash
                || qc.view != block.view
                || qc.height != block.height
            {
                return Err(BftError::InvalidQc);
            }
        }
        Ok(())
    }

    fn verify_decision_with_cached_qcs(&self, proof: &DecisionProof) -> Result<(), BftError> {
        self.verify_proposal_envelope(&proof.proposal)?;
        let block = &proof.proposal.block;
        let block_hash = block.hash();
        if self.pending.get(&block_hash) != Some(block)
            || self.verified_phase_qcs.get(&(QcKind::Prepare, block_hash))
                != Some(&proof.prepare_qc)
            || self
                .verified_phase_qcs
                .get(&(QcKind::PreCommit, block_hash))
                != Some(&proof.precommit_qc)
        {
            return Err(BftError::InvalidQc);
        }
        for (expected, qc) in [
            (QcKind::Prepare, &proof.prepare_qc),
            (QcKind::PreCommit, &proof.precommit_qc),
            (QcKind::Commit, &proof.commit_qc),
        ] {
            if qc.kind != expected
                || qc.block_hash != block_hash
                || qc.view != block.view
                || qc.height != block.height
            {
                return Err(BftError::InvalidQc);
            }
        }
        // Prepare and PreCommit were verified before this replica emitted its
        // later-phase votes and are pinned in the local state above. Commit is
        // the only newly received QC at decision time.
        self.verify_qc(&proof.commit_qc)
    }

    fn validate_vote_intent<F: Fn(&Request) -> bool>(
        &self,
        proposal: &Proposal,
        kind: QcKind,
        phase_qc: Option<&QuorumCertificate>,
        valid: &F,
    ) -> Result<(), BftError> {
        let block = &proposal.block;
        let block_hash = block.hash();
        if !valid(&block.request)
            || block.view != self.state.cview
            || block.height != self.next_phase_height(kind)?
            || self
                .state
                .last_voted
                .get(&kind)
                .is_some_and(|(view, height, _)| (*view, *height) >= (block.view, block.height))
        {
            return Err(BftError::UnsafeProposal);
        }
        match kind {
            QcKind::Prepare => {
                self.verify_proposal_envelope(proposal)?;
                if phase_qc.is_some() {
                    return Err(BftError::InvalidQc);
                }
                if proposal.high_qc != self.state.high_qc
                    || self.state.locked_qc.as_ref().is_some_and(|locked| {
                        block.parent_hash != locked.block_hash
                            && proposal.high_qc.as_ref().is_none_or(|high| {
                                (high.view, high.height) <= (locked.view, locked.height)
                            })
                    })
                {
                    return Err(BftError::UnsafeProposal);
                }
                match &proposal.high_qc {
                    Some(high) => {
                        self.verify_qc(high)?;
                        if high.kind != QcKind::Prepare
                            || high.block_hash != block.parent_hash
                            || high.height.checked_add(1) != Some(block.height)
                            || high.view > block.view
                        {
                            return Err(BftError::InvalidQc);
                        }
                    }
                    None if block.parent_hash == [0; 32]
                        && block.height == self.state.next_height => {}
                    None => return Err(BftError::UnsafeProposal),
                }
            }
            QcKind::PreCommit => {
                self.verify_phase_qc(phase_qc, QcKind::Prepare, block_hash, block)?;
                if self.pending.get(&block_hash) != Some(block) {
                    return Err(BftError::InvalidBlock);
                }
            }
            QcKind::Commit => {
                self.verify_phase_qc(phase_qc, QcKind::PreCommit, block_hash, block)?;
                if self.pending.get(&block_hash) != Some(block) {
                    return Err(BftError::InvalidBlock);
                }
            }
        }
        Ok(())
    }

    fn verify_phase_qc(
        &self,
        qc: Option<&QuorumCertificate>,
        expected: QcKind,
        block_hash: [u8; 32],
        block: &Block,
    ) -> Result<(), BftError> {
        let qc = qc.ok_or(BftError::InvalidQc)?;
        self.verify_qc(qc)?;
        if qc.kind != expected
            || qc.block_hash != block_hash
            || qc.view != block.view
            || qc.height != block.height
        {
            return Err(BftError::InvalidQc);
        }
        Ok(())
    }

    fn apply_vote_intent(
        &mut self,
        proposal: Proposal,
        kind: QcKind,
        phase_qc: Option<QuorumCertificate>,
    ) -> Result<(), BftError> {
        self.validate_vote_intent(&proposal, kind, phase_qc.as_ref(), &|_| true)?;
        self.apply_verified_vote_intent(proposal, kind, phase_qc)
    }

    fn apply_verified_vote_intent(
        &mut self,
        proposal: Proposal,
        kind: QcKind,
        phase_qc: Option<QuorumCertificate>,
    ) -> Result<(), BftError> {
        let block_hash = proposal.block.hash();
        match kind {
            QcKind::Prepare => {
                self.pending.insert(block_hash, proposal.block.clone());
            }
            QcKind::PreCommit => {
                let qc = phase_qc.ok_or(BftError::InvalidQc)?;
                self.verified_phase_qcs
                    .insert((QcKind::Prepare, block_hash), qc.clone());
                update_highest_qc(&mut self.state.high_qc, qc);
            }
            QcKind::Commit => {
                let qc = phase_qc.ok_or(BftError::InvalidQc)?;
                self.verified_phase_qcs
                    .insert((QcKind::PreCommit, block_hash), qc.clone());
                update_highest_qc(&mut self.state.locked_qc, qc);
            }
        }
        self.state.last_voted.insert(
            kind,
            (proposal.block.view, proposal.block.height, block_hash),
        );
        Ok(())
    }

    fn apply_decision(&mut self, proof: DecisionProof) -> Result<(), BftError> {
        self.verify_decision_proof(&proof)?;
        self.apply_verified_decision(proof)
    }

    fn apply_verified_decision(&mut self, proof: DecisionProof) -> Result<(), BftError> {
        let block = proof.proposal.block.clone();
        let block_hash = block.hash();
        if self.pending.remove(&block_hash) != Some(block.clone())
            || block.height != self.state.next_height
        {
            return Err(BftError::InvalidBlock);
        }
        self.verified_phase_qcs
            .remove(&(QcKind::Prepare, block_hash));
        self.verified_phase_qcs
            .remove(&(QcKind::PreCommit, block_hash));
        update_highest_qc(&mut self.state.high_qc, proof.prepare_qc);
        update_highest_qc(&mut self.state.locked_qc, proof.precommit_qc);
        update_highest_qc(&mut self.state.confirm_qc, proof.commit_qc);
        self.state.next_height = self
            .state
            .next_height
            .checked_add(1)
            .ok_or(BftError::InvalidBlock)?;
        self.delivered.insert(block.height, block);
        Ok(())
    }

    fn next_phase_height(&self, kind: QcKind) -> Result<u64, BftError> {
        self.state
            .last_voted
            .get(&kind)
            .map_or(Ok(self.state.next_height), |(_, height, _)| {
                height.checked_add(1).ok_or(BftError::InvalidBlock)
            })
    }

    fn verify_proposal_envelope(&self, proposal: &Proposal) -> Result<(), BftError> {
        if proposal.leader as usize >= self.params.n
            || proposal.leader != self.leader(proposal.block.view)
        {
            return Err(BftError::InvalidBlock);
        }
        bls::verify(
            &self.public_keys[proposal.leader as usize],
            &proposal.signature,
            &proposal_message(proposal),
            DST,
            &[],
        )
        .map_err(|_| BftError::InvalidBlock)
    }
}

fn update_highest_qc(current: &mut Option<QuorumCertificate>, candidate: QuorumCertificate) {
    if current.as_ref().is_none_or(|existing| {
        (candidate.view, candidate.height) > (existing.view, existing.height)
    }) {
        *current = Some(candidate);
    }
}

fn proposal_message(proposal: &Proposal) -> Vec<u8> {
    canonical_serialize(&(
        "rondo/bft/proposal/v2",
        proposal.leader,
        &proposal.block,
        &proposal.high_qc,
    ))
    .expect("proposal serializes")
}

fn vote_message(kind: QcKind, block_hash: [u8; 32], view: u64, height: u64) -> Vec<u8> {
    canonical_serialize(&("rondo/bft/vote/v1", kind, block_hash, view, height))
        .expect("vote serializes")
}
