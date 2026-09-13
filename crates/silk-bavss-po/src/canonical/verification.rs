//! Mulberry's `ParVerify` and public-transcript checks.

use super::transcript::{
    challenge, evaluation_point, message_root, params_digest, response_digest,
    share_leaf_digest_single_mask, share_leaf_prefix,
};
use super::{DealerPublicTranscript, PrivateRow, RESPONSE_REPETITIONS};
use crate::{ProtocolParams, SilkError};
use crypto_primitives::polynomial::evaluate;

pub fn validate_params(params: ProtocolParams) -> Result<(), SilkError> {
    params.validate()?;
    if params.r != RESPONSE_REPETITIONS {
        return Err(SilkError::InvalidParameters);
    }
    Ok(())
}

pub fn par_verify(
    expected_sid: &[u8],
    expected_context: super::ProtocolContext,
    params: ProtocolParams,
    row: &PrivateRow,
    public: &DealerPublicTranscript,
) -> Result<(), SilkError> {
    validate_params(params)?;
    if row.sid != expected_sid
        || public.sid != expected_sid
        || row.context != expected_context
        || public.context != expected_context
        || public.params != params
        || row.dealer != public.dealer
        || row.receiver as usize >= params.n
        || row.slots.len() != params.l
    {
        return Err(SilkError::InvalidParameters);
    }
    validate_public_shape(public)?;
    if message_root(
        &public.sid,
        public.context,
        public.dealer,
        &public.leaf_digests,
    )? != public.message_root
        || response_digest(
            &public.sid,
            public.context,
            public.dealer,
            &public.responses,
        )? != public.response_digest
    {
        return Err(SilkError::InvalidMerkleProof);
    }

    let leaf_prefix = share_leaf_prefix(&row.sid, row.context, row.dealer);
    let receiver = row.receiver as usize;
    let point = evaluation_point(receiver)?;
    for (index, slot) in row.slots.iter().enumerate() {
        if slot.index as usize != index || slot.masks.len() != RESPONSE_REPETITIONS {
            return Err(SilkError::InvalidShareCount {
                got: slot.masks.len(),
                expected: RESPONSE_REPETITIONS,
            });
        }
        let expected_leaf = public.leaf_digests.rows[receiver][index];
        if share_leaf_digest_single_mask(
            &leaf_prefix,
            row.receiver,
            index as u32,
            slot.share,
            slot.salt,
            slot.masks[0],
        ) != expected_leaf
        {
            return Err(SilkError::InvalidMerkleProof);
        }
        let response = &public.responses[index];
        let theta = challenge(
            &public.sid,
            public.context,
            public.dealer,
            index as u32,
            0,
            public.message_root,
        );
        let h_at_point = evaluate(&response.polynomials[0], point);
        if h_at_point != slot.masks[0] + theta * slot.share {
            return Err(SilkError::InvalidRowCheck);
        }
    }
    Ok(())
}

pub fn verify_public_transcript(
    params: ProtocolParams,
    public: &DealerPublicTranscript,
) -> Result<(), SilkError> {
    validate_params(params)?;
    if public.params != params {
        return Err(SilkError::InvalidParameters);
    }
    validate_public_shape(public)?;
    if message_root(
        &public.sid,
        public.context,
        public.dealer,
        &public.leaf_digests,
    )? != public.message_root
        || response_digest(
            &public.sid,
            public.context,
            public.dealer,
            &public.responses,
        )? != public.response_digest
    {
        return Err(SilkError::InvalidMerkleProof);
    }
    Ok(())
}

pub(super) fn validate_public_shape(public: &DealerPublicTranscript) -> Result<(), SilkError> {
    let params = public.params;
    validate_params(params)?;
    if public.dealer as usize >= params.n
        || public.context.params_digest != params_digest(params)
        || public.leaf_digests.rows.len() != params.n
        || public
            .leaf_digests
            .rows
            .iter()
            .any(|row| row.len() != params.l)
        || public.responses.len() != params.l
    {
        return Err(SilkError::InvalidParameters);
    }
    for (index, response) in public.responses.iter().enumerate() {
        if response.index as usize != index
            || response.polynomials.len() != RESPONSE_REPETITIONS
            || response
                .polynomials
                .iter()
                .any(|coefficients| coefficients.len() != params.d)
        {
            return Err(SilkError::InvalidResponseCount {
                got: response.polynomials.len(),
                expected: RESPONSE_REPETITIONS,
            });
        }
    }
    Ok(())
}
