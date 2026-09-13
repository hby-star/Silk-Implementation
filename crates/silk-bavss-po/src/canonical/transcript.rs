//! Frozen Mulberry transcript, Merkle, and Fiat--Shamir encodings.
//!
//! Domain strings in this module are wire identities and must remain stable
//! across source-only refactors.

use super::{
    DealerPublicTranscript, LeafDigestMatrix, PrivateSlot, ProtocolContext, ResponsePolynomialSet,
};
use crate::{ProtocolParams, SilkError};
use crypto_primitives::hash::{HashTranscript, hash_len_prefixed};
use crypto_primitives::merkle::MerkleTree;
use curve25519_dalek::scalar::Scalar;
use protocol_support::wire::canonical_serialize;
use serde::{Serialize, ser::SerializeSeq};

pub(super) const BATCH_NODE_DOMAIN: &[u8] = b"silk/share-node/batch/v1";
pub(super) const OUTER_NODE_DOMAIN: &[u8] = b"silk/share-node/outer/v1";

pub(super) fn params_digest(params: ProtocolParams) -> [u8; 32] {
    hash_len_prefixed(
        b"silk/params/v1",
        &[
            &(params.n as u64).to_be_bytes(),
            &(params.t as u64).to_be_bytes(),
            &(params.l as u64).to_be_bytes(),
            &(params.r as u64).to_be_bytes(),
            &params.kappa.to_be_bytes(),
            b"curve25519-dalek-scalar-field-v1",
            b"mldsa65-v1",
            b"postcard-canonical-v1",
            b"service-window-then-epoch-retirement-v1",
        ],
    )
}

pub(super) fn transcript_id(public: &DealerPublicTranscript) -> [u8; 32] {
    transcript_id_from_roots(
        &public.sid,
        public.context,
        public.dealer,
        public.message_root,
        public.response_digest,
    )
}

pub(super) fn transcript_id_from_roots(
    sid: &[u8],
    context: ProtocolContext,
    dealer: u32,
    message_root: [u8; 32],
    response_digest: [u8; 32],
) -> [u8; 32] {
    hash_len_prefixed(
        b"silk/dealer-transcript/v1",
        &[
            sid,
            &context.config_digest,
            &context.epoch.to_be_bytes(),
            &dealer.to_be_bytes(),
            &message_root,
            &response_digest,
            &context.params_digest,
            &context.retention_policy_digest,
        ],
    )
}

pub(super) fn share_leaf_digest(
    sid: &[u8],
    context: ProtocolContext,
    dealer: u32,
    receiver: u32,
    slot: &PrivateSlot,
) -> [u8; 32] {
    let masks = canonical_serialize(&slot.masks).expect("masks serialize");
    hash_len_prefixed(
        b"silk/share-leaf/batch/v1",
        &[
            sid,
            &context.config_digest,
            &context.epoch.to_be_bytes(),
            &dealer.to_be_bytes(),
            &receiver.to_be_bytes(),
            &slot.index.to_be_bytes(),
            &slot.salt,
            &slot.share.to_bytes(),
            &masks,
        ],
    )
}

pub(super) fn share_leaf_prefix(
    sid: &[u8],
    context: ProtocolContext,
    dealer: u32,
) -> HashTranscript {
    let mut transcript = HashTranscript::new(b"silk/share-leaf/batch/v1");
    update_len_prefixed(&mut transcript, sid);
    update_len_prefixed(&mut transcript, &context.config_digest);
    update_len_prefixed(&mut transcript, &context.epoch.to_be_bytes());
    update_len_prefixed(&mut transcript, &dealer.to_be_bytes());
    transcript
}

pub(super) fn share_leaf_digest_single_mask(
    prefix: &HashTranscript,
    receiver: u32,
    index: u32,
    share: Scalar,
    salt: [u8; 32],
    mask: Scalar,
) -> [u8; 32] {
    let mut mask_buffer = [0u8; 64];
    let encoded_mask = postcard::to_slice(&SingletonMask(mask), &mut mask_buffer)
        .expect("one scalar mask has a bounded canonical encoding");
    let mut transcript = prefix.clone();
    update_len_prefixed(&mut transcript, &receiver.to_be_bytes());
    update_len_prefixed(&mut transcript, &index.to_be_bytes());
    update_len_prefixed(&mut transcript, &salt);
    update_len_prefixed(&mut transcript, &share.to_bytes());
    update_len_prefixed(&mut transcript, encoded_mask);
    transcript.finalize()
}

fn update_len_prefixed(transcript: &mut HashTranscript, bytes: &[u8]) {
    transcript.update(&(bytes.len() as u64).to_le_bytes());
    transcript.update(bytes);
}

pub(super) struct SingletonMask(pub(super) Scalar);

impl Serialize for SingletonMask {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut sequence = serializer.serialize_seq(Some(1))?;
        sequence.serialize_element(&self.0)?;
        sequence.end()
    }
}

pub(super) fn outer_leaf_digest(
    sid: &[u8],
    context: ProtocolContext,
    dealer: u32,
    receiver: u32,
    batch_root: [u8; 32],
) -> [u8; 32] {
    hash_len_prefixed(
        b"silk/share-leaf/outer/v1",
        &[
            sid,
            &context.config_digest,
            &context.epoch.to_be_bytes(),
            &dealer.to_be_bytes(),
            &receiver.to_be_bytes(),
            &batch_root,
        ],
    )
}

pub(super) fn message_root(
    sid: &[u8],
    context: ProtocolContext,
    dealer: u32,
    matrix: &LeafDigestMatrix,
) -> Result<[u8; 32], SilkError> {
    if matrix.rows.is_empty() || matrix.rows.iter().any(Vec::is_empty) {
        return Err(SilkError::EmptyMerkleTree);
    }
    let outer_leaves = matrix
        .rows
        .iter()
        .enumerate()
        .map(|(receiver, row)| {
            let batch_root = MerkleTree::root_only(BATCH_NODE_DOMAIN, row)
                .map_err(|_| SilkError::EmptyMerkleTree)?;
            Ok(outer_leaf_digest(
                sid,
                context,
                dealer,
                receiver as u32,
                batch_root,
            ))
        })
        .collect::<Result<Vec<_>, SilkError>>()?;
    MerkleTree::root_only(OUTER_NODE_DOMAIN, &outer_leaves).map_err(|_| SilkError::EmptyMerkleTree)
}

// The whole response vector is bound once; no response Merkle tree or
// public reconstruction opening is required by the signed-release protocol.
pub(super) fn response_digest(
    sid: &[u8],
    context: ProtocolContext,
    dealer: u32,
    responses: &[ResponsePolynomialSet],
) -> Result<[u8; 32], SilkError> {
    let encoded = canonical_serialize(responses).expect("responses serialize");
    Ok(hash_len_prefixed(
        b"silk/responses/v2",
        &[
            sid,
            &context.config_digest,
            &context.epoch.to_be_bytes(),
            &dealer.to_be_bytes(),
            &encoded,
        ],
    ))
}

pub(super) fn challenge(
    sid: &[u8],
    context: ProtocolContext,
    dealer: u32,
    index: u32,
    repetition: u32,
    message_root: [u8; 32],
) -> Scalar {
    let mut transcript = HashTranscript::new(b"silk/share-chal/v1");
    transcript.update(&(sid.len() as u64).to_be_bytes());
    transcript.update(sid);
    transcript.update(&context.config_digest);
    transcript.update(&context.epoch.to_be_bytes());
    transcript.update(&dealer.to_be_bytes());
    transcript.update(&index.to_be_bytes());
    transcript.update(&repetition.to_be_bytes());
    transcript.update(&message_root);
    let mut wide = [0u8; 64];
    transcript.fill_xof(&mut wide);
    Scalar::from_bytes_mod_order_wide(&wide)
}

pub(super) fn evaluation_point(receiver: usize) -> Result<Scalar, SilkError> {
    let index = u64::try_from(receiver).map_err(|_| SilkError::InvalidReceiver)?;
    Ok(Scalar::from(index + 1))
}
