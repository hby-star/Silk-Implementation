//! Spurt's modified HotStuff normal path and FINALIZE amplification.

use std::collections::BTreeMap;
use std::sync::Arc;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use protocol_support::wire::canonical_serialize;
use serde::{Deserialize, Serialize};

use crate::SpurtError;
use crate::types::SignedAgreementMessage;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum AgreementPhase {
    Prepare,
    PreCommit,
    Commit,
    Finalize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AgreementStage {
    ProposalValidated,
    Prepared,
    PreCommitted,
    Committed,
    Finalizing,
    Decided,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AgreementDecision {
    pub epoch: u64,
    pub height: u64,
    pub digest: [u8; 32],
    pub finalize_certificate: Vec<SignedAgreementMessage>,
}

#[derive(Clone, Debug)]
pub struct VerifiedAgreementMessage {
    verification_context: [u8; 32],
    phase: AgreementPhase,
    message: SignedAgreementMessage,
}

pub struct AgreementReplica {
    n: usize,
    t: usize,
    epoch: u64,
    height: u64,
    digest: [u8; 32],
    node_id: u32,
    signing_key: Arc<SigningKey>,
    verifying_keys: Arc<BTreeMap<u32, VerifyingKey>>,
    stage: AgreementStage,
    verification_context: [u8; 32],
}

impl AgreementReplica {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        n: usize,
        t: usize,
        epoch: u64,
        height: u64,
        digest: [u8; 32],
        node_id: u32,
        signing_key: Arc<SigningKey>,
        verifying_keys: Arc<BTreeMap<u32, VerifyingKey>>,
    ) -> Result<Self, SpurtError> {
        if n < 3 * t + 1 || node_id as usize >= n || verifying_keys.len() != n {
            return Err(SpurtError::Parameter(
                "agreement requires n >= 3t+1 and a complete committee",
            ));
        }
        let verification_context = *blake3::hash(&canonical_serialize(&(
            "Spurt-agreement-verified-context-v1",
            n,
            t,
            epoch,
            height,
            digest,
            verifying_keys
                .iter()
                .map(|(node, key)| (*node, key.to_bytes()))
                .collect::<Vec<_>>(),
        ))?)
        .as_bytes();
        Ok(Self {
            n,
            t,
            epoch,
            height,
            digest,
            node_id,
            signing_key,
            verifying_keys,
            stage: AgreementStage::ProposalValidated,
            verification_context,
        })
    }

    pub fn prepare_message(&self) -> Result<SignedAgreementMessage, SpurtError> {
        if self.stage != AgreementStage::ProposalValidated {
            return Err(SpurtError::Agreement(
                "PREPARE is only valid after proposal validation",
            ));
        }
        self.sign(AgreementPhase::Prepare)
    }

    pub fn accept_prepare_preverified(
        &mut self,
        messages: Vec<VerifiedAgreementMessage>,
    ) -> Result<(), SpurtError> {
        if self.stage != AgreementStage::ProposalValidated {
            return Err(SpurtError::Agreement("unexpected PREPARE quorum"));
        }
        self.preverified_quorum(AgreementPhase::Prepare, messages, self.quorum())?;
        self.stage = AgreementStage::Prepared;
        Ok(())
    }

    pub fn precommit_message(&self) -> Result<SignedAgreementMessage, SpurtError> {
        if self.stage != AgreementStage::Prepared {
            return Err(SpurtError::Agreement("PRECOMMIT requires a PREPARE quorum"));
        }
        self.sign(AgreementPhase::PreCommit)
    }

    pub fn accept_precommit_preverified(
        &mut self,
        messages: Vec<VerifiedAgreementMessage>,
    ) -> Result<(), SpurtError> {
        if self.stage != AgreementStage::Prepared {
            return Err(SpurtError::Agreement("unexpected PRECOMMIT quorum"));
        }
        self.preverified_quorum(AgreementPhase::PreCommit, messages, self.quorum())?;
        self.stage = AgreementStage::PreCommitted;
        Ok(())
    }

    pub fn commit_message(&self) -> Result<SignedAgreementMessage, SpurtError> {
        if self.stage != AgreementStage::PreCommitted {
            return Err(SpurtError::Agreement("COMMIT requires a PRECOMMIT quorum"));
        }
        self.sign(AgreementPhase::Commit)
    }

    pub fn accept_commit_preverified(
        &mut self,
        messages: Vec<VerifiedAgreementMessage>,
    ) -> Result<(), SpurtError> {
        if self.stage != AgreementStage::PreCommitted {
            return Err(SpurtError::Agreement("unexpected COMMIT quorum"));
        }
        self.preverified_quorum(AgreementPhase::Commit, messages, self.quorum())?;
        self.stage = AgreementStage::Committed;
        Ok(())
    }

    pub fn finalize_after_commit(&mut self) -> Result<SignedAgreementMessage, SpurtError> {
        if self.stage != AgreementStage::Committed {
            return Err(SpurtError::Agreement("FINALIZE requires a COMMIT quorum"));
        }
        let message = self.sign(AgreementPhase::Finalize)?;
        self.stage = AgreementStage::Finalizing;
        Ok(message)
    }

    pub fn decide_preverified(
        &mut self,
        messages: Vec<VerifiedAgreementMessage>,
    ) -> Result<AgreementDecision, SpurtError> {
        if self.stage == AgreementStage::Decided {
            return Err(SpurtError::Agreement("duplicate agreement decision"));
        }
        let certificate =
            self.preverified_quorum(AgreementPhase::Finalize, messages, self.quorum())?;
        self.stage = AgreementStage::Decided;
        Ok(AgreementDecision {
            epoch: self.epoch,
            height: self.height,
            digest: self.digest,
            finalize_certificate: certificate,
        })
    }

    fn verify_message(
        &self,
        phase: AgreementPhase,
        sender: u32,
        message: &SignedAgreementMessage,
    ) -> Result<(), SpurtError> {
        if message.signer != sender {
            return Err(SpurtError::Agreement("agreement sender mismatch"));
        }
        self.verify_one(phase, message)
    }

    pub fn accept_message(
        &self,
        phase: AgreementPhase,
        sender: u32,
        message: SignedAgreementMessage,
    ) -> Result<VerifiedAgreementMessage, SpurtError> {
        self.verify_message(phase, sender, &message)?;
        Ok(VerifiedAgreementMessage {
            verification_context: self.verification_context,
            phase,
            message,
        })
    }

    fn quorum(&self) -> usize {
        2 * self.t + 1
    }

    fn sign(&self, phase: AgreementPhase) -> Result<SignedAgreementMessage, SpurtError> {
        let payload = agreement_payload(self.epoch, self.height, self.digest, phase, self.node_id)?;
        Ok(SignedAgreementMessage {
            epoch: self.epoch,
            height: self.height,
            digest: self.digest,
            phase,
            signer: self.node_id,
            signature: self.signing_key.sign(&payload).to_bytes().to_vec(),
        })
    }

    fn preverified_quorum(
        &self,
        phase: AgreementPhase,
        messages: Vec<VerifiedAgreementMessage>,
        threshold: usize,
    ) -> Result<Vec<SignedAgreementMessage>, SpurtError> {
        if threshold > self.n || messages.len() < threshold {
            return Err(SpurtError::Agreement("agreement quorum is below threshold"));
        }
        let mut accepted = BTreeMap::new();
        for verified in messages {
            let message = verified.message;
            if verified.verification_context != self.verification_context
                || verified.phase != phase
                || message.epoch != self.epoch
                || message.height != self.height
                || message.digest != self.digest
                || message.phase != phase
                || message.signer as usize >= self.n
                || accepted.insert(message.signer, message).is_some()
            {
                return Err(SpurtError::Agreement(
                    "agreement message context or signer set is invalid",
                ));
            }
        }
        if accepted.len() < threshold {
            return Err(SpurtError::Agreement("agreement quorum is below threshold"));
        }
        Ok(accepted.into_values().take(threshold).collect())
    }

    fn verify_one(
        &self,
        phase: AgreementPhase,
        message: &SignedAgreementMessage,
    ) -> Result<(), SpurtError> {
        if message.epoch != self.epoch
            || message.height != self.height
            || message.digest != self.digest
            || message.phase != phase
            || message.signer as usize >= self.n
        {
            return Err(SpurtError::Agreement(
                "agreement message context or signer set is invalid",
            ));
        }
        let key = self
            .verifying_keys
            .get(&message.signer)
            .ok_or(SpurtError::Agreement("unknown agreement signer"))?;
        let signature = Signature::from_slice(&message.signature)
            .map_err(|_| SpurtError::Verification("invalid agreement signature encoding"))?;
        let payload = agreement_payload(
            message.epoch,
            message.height,
            message.digest,
            message.phase,
            message.signer,
        )?;
        key.verify(&payload, &signature)
            .map_err(|_| SpurtError::Verification("invalid agreement signature"))
    }
}

fn agreement_payload(
    epoch: u64,
    height: u64,
    digest: [u8; 32],
    phase: AgreementPhase,
    signer: u32,
) -> Result<Vec<u8>, SpurtError> {
    Ok(canonical_serialize(&(
        "Spurt-agreement-message-v1",
        epoch,
        height,
        digest,
        phase,
        signer,
    ))?)
}
