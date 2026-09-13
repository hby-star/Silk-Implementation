use super::transcript::{params_digest, transcript_id};
use super::validate_params;
use crate::{ProtocolParams, SilkError};
use crypto_primitives::hash::hash_len_prefixed;
use curve25519_dalek::scalar::Scalar;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProtocolContext {
    pub epoch: u64,
    pub config_digest: [u8; 32],
    pub params_digest: [u8; 32],
    pub retention_policy_digest: [u8; 32],
}

impl ProtocolContext {
    pub fn derive(
        sid: &[u8],
        epoch: u64,
        config_digest: [u8; 32],
        params: ProtocolParams,
        reconstruction_window: u64,
    ) -> Result<Self, SilkError> {
        validate_params(params)?;
        let params_digest = params_digest(params);
        let retention_policy_digest = hash_len_prefixed(
            b"silk/retention-policy/v1",
            &[
                &reconstruction_window.to_be_bytes(),
                b"serve-all-installed-indices-before-retirement",
            ],
        );
        let expected_config = hash_len_prefixed(
            b"silk/config/v1",
            &[sid, &epoch.to_be_bytes(), &params_digest, &config_digest],
        );
        Ok(Self {
            epoch,
            config_digest: expected_config,
            params_digest,
            retention_policy_digest,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PrivateSlot {
    pub index: u32,
    pub share: Scalar,
    pub masks: Vec<Scalar>,
    pub salt: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PrivateRow {
    pub sid: Vec<u8>,
    pub context: ProtocolContext,
    pub dealer: u32,
    pub receiver: u32,
    pub slots: Vec<PrivateSlot>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ResponsePolynomialSet {
    pub index: u32,
    pub polynomials: Vec<Vec<Scalar>>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LeafDigestMatrix {
    /// Recipient-major, then batch-index-major.
    pub rows: Vec<Vec<[u8; 32]>>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DealerPublicTranscript {
    pub sid: Vec<u8>,
    pub context: ProtocolContext,
    pub dealer: u32,
    pub params: ProtocolParams,
    pub message_root: [u8; 32],
    pub leaf_digests: LeafDigestMatrix,
    pub response_digest: [u8; 32],
    pub responses: Vec<ResponsePolynomialSet>,
}

impl DealerPublicTranscript {
    pub fn transcript_id(&self) -> [u8; 32] {
        transcript_id(self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CompactReconstructionItem {
    pub dealer: u32,
    pub share: Scalar,
    pub salt: [u8; 32],
}
