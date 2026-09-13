//! Decision-key and certificate layer for Silk's Bracha normal path.
//!
//! The distributed ECHO--READY--COMMIT flow is driven by `SilkProtocol` and
//! its transport adapter. This module owns only the signed decision evidence
//! that follows agreement; it deliberately contains no second in-memory BFT
//! implementation.

mod support;
mod types;

pub(crate) use support::PreparedDecision;
pub use support::{BftError, decision_message, proposal_digest};
pub use types::{BftParams, DecisionCertificate, DecisionSignature, Proposal};

use crypto_primitives::mldsa::{
    SigningKey65, VerifyingKey65, key_from_seed, public_key_bytes, sign, verify, verify_with_key,
    verifying_key_from_bytes,
};

/// Committee keys used to certify the value delivered by the Bracha path.
#[derive(Debug)]
pub struct BrachaCommittee {
    params: BftParams,
    epoch: u64,
    signing_keys: Vec<SigningKey65>,
    public_keys: Vec<Vec<u8>>,
    verifying_keys: Vec<VerifyingKey65>,
}

impl BrachaCommittee {
    pub fn for_epoch(params: BftParams, seed: [u8; 32], epoch: u64) -> Self {
        let signing_keys = (0..params.n)
            .map(|node| {
                let key_seed = crypto_primitives::hash::hash_len_prefixed(
                    b"silk/epoch-decision-key/v1",
                    &[&seed, &(node as u64).to_be_bytes()],
                );
                key_from_seed(key_seed).expect("ML-DSA accepts a 32-byte seed")
            })
            .collect::<Vec<_>>();
        let public_keys = signing_keys
            .iter()
            .map(public_key_bytes)
            .collect::<Vec<_>>();
        let verifying_keys = public_keys
            .iter()
            .map(|key| {
                verifying_key_from_bytes(key)
                    .expect("generated ML-DSA public key has a valid encoding")
            })
            .collect();
        Self {
            params,
            epoch,
            signing_keys,
            public_keys,
            verifying_keys,
        }
    }

    pub fn public_keys(&self) -> &[Vec<u8>] {
        &self.public_keys
    }

    pub fn decision_signature(
        &self,
        signer: u32,
        proposal: &Proposal,
    ) -> Result<DecisionSignature, BftError> {
        self.sign_prepared(signer, &PreparedDecision::new(self.epoch, proposal))
    }

    pub(crate) fn sign_prepared(
        &self,
        signer: u32,
        statement: &PreparedDecision,
    ) -> Result<DecisionSignature, BftError> {
        if statement.epoch != self.epoch {
            return Err(BftError::InvalidDecisionCertificate);
        }
        let key = self
            .signing_keys
            .get(signer as usize)
            .ok_or(BftError::InvalidDecisionCertificate)?;
        Ok(DecisionSignature {
            signer,
            signature: sign(key, &statement.message),
        })
    }

    pub fn verify_decision_signature(
        &self,
        proposal: &Proposal,
        signature: &DecisionSignature,
    ) -> Result<(), BftError> {
        self.verify_prepared(&PreparedDecision::new(self.epoch, proposal), signature)
    }

    pub(crate) fn verify_prepared(
        &self,
        statement: &PreparedDecision,
        signature: &DecisionSignature,
    ) -> Result<(), BftError> {
        if statement.epoch != self.epoch {
            return Err(BftError::InvalidDecisionCertificate);
        }
        verify_prepared_signature(self.params, &self.verifying_keys, statement, signature)
    }

    pub fn verify_decision_certificate(
        &self,
        proposal: &Proposal,
        certificate: &DecisionCertificate,
    ) -> Result<(), BftError> {
        verify_decision_certificate_preparsed(
            self.params,
            &self.verifying_keys,
            self.epoch,
            proposal,
            certificate,
        )
    }
}

pub fn verify_decision_certificate(
    params: BftParams,
    public_keys: &[Vec<u8>],
    epoch: u64,
    proposal: &Proposal,
    certificate: &DecisionCertificate,
) -> Result<(), BftError> {
    validate_certificate(params, epoch, proposal, certificate)?;
    if public_keys.len() != params.n {
        return Err(BftError::InvalidDecisionCertificate);
    }
    let message = decision_message(epoch, proposal);
    for signature in &certificate.signatures {
        verify(
            &public_keys[signature.signer as usize],
            &signature.signature,
            &message,
        )
        .map_err(|_| BftError::InvalidDecisionCertificate)?;
    }
    Ok(())
}

fn verify_decision_certificate_preparsed(
    params: BftParams,
    public_keys: &[VerifyingKey65],
    epoch: u64,
    proposal: &Proposal,
    certificate: &DecisionCertificate,
) -> Result<(), BftError> {
    validate_certificate(params, epoch, proposal, certificate)?;
    if public_keys.len() != params.n {
        return Err(BftError::InvalidDecisionCertificate);
    }
    let statement = PreparedDecision::new(epoch, proposal);
    for signature in &certificate.signatures {
        verify_prepared_signature(params, public_keys, &statement, signature)?;
    }
    Ok(())
}

fn validate_certificate(
    params: BftParams,
    epoch: u64,
    proposal: &Proposal,
    certificate: &DecisionCertificate,
) -> Result<(), BftError> {
    if certificate.epoch != epoch
        || certificate.instance != proposal.instance
        || certificate.proposal_digest != proposal_digest(proposal)
        || certificate.signatures.len() != params.quorum()
        || !certificate
            .signatures
            .windows(2)
            .all(|pair| pair[0].signer < pair[1].signer)
        || certificate
            .signatures
            .iter()
            .any(|signature| signature.signer as usize >= params.n)
    {
        return Err(BftError::InvalidDecisionCertificate);
    }
    Ok(())
}

pub fn verify_decision_signature(
    params: BftParams,
    public_keys: &[Vec<u8>],
    epoch: u64,
    proposal: &Proposal,
    signature: &DecisionSignature,
) -> Result<(), BftError> {
    if public_keys.len() != params.n || signature.signer as usize >= params.n {
        return Err(BftError::InvalidDecisionCertificate);
    }
    verify(
        &public_keys[signature.signer as usize],
        &signature.signature,
        &decision_message(epoch, proposal),
    )
    .map_err(|_| BftError::InvalidDecisionCertificate)
}

fn verify_prepared_signature(
    params: BftParams,
    public_keys: &[VerifyingKey65],
    statement: &PreparedDecision,
    signature: &DecisionSignature,
) -> Result<(), BftError> {
    if public_keys.len() != params.n || signature.signer as usize >= params.n {
        return Err(BftError::InvalidDecisionCertificate);
    }
    verify_with_key(
        &public_keys[signature.signer as usize],
        &signature.signature,
        &statement.message,
    )
    .map_err(|_| BftError::InvalidDecisionCertificate)
}
