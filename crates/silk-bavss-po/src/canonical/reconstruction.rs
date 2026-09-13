//! Compact per-position items, `PointVerify`, and interpolation.

use super::transcript::{
    challenge, evaluation_point, share_leaf_digest, share_leaf_digest_single_mask,
    share_leaf_prefix,
};
use super::verification::validate_public_shape;
use super::{
    CompactReconstructionItem, DealerPublicTranscript, PrivateRow, PrivateSlot,
    RESPONSE_REPETITIONS, validate_params,
};
use crate::{ProtocolParams, SilkError};
use crypto_primitives::hash::HashTranscript;
use crypto_primitives::polynomial::{
    MultipointEvaluationPlan, PolynomialOpCounts, evaluate, interpolate_at_zero_fast,
    multipoint_evaluate,
};
use curve25519_dalek::scalar::Scalar;

pub fn compact_item_from_row(
    public: &DealerPublicTranscript,
    row: &PrivateRow,
    index: usize,
) -> Result<CompactReconstructionItem, SilkError> {
    if public.dealer != row.dealer
        || public.sid != row.sid
        || public.context != row.context
        || index >= public.params.l
    {
        return Err(SilkError::CertificateMismatch);
    }
    let slot = row.slots.get(index).ok_or(SilkError::InvalidIndex)?;
    if slot.index as usize != index {
        return Err(SilkError::InvalidIndex);
    }
    Ok(CompactReconstructionItem {
        dealer: public.dealer,
        share: slot.share,
        salt: slot.salt,
    })
}

/// Verifies one compact opening after the enclosing epoch record has already
/// validated the public transcript. This avoids re-hashing the full dense
/// transcript for every reconstruction message.
pub fn point_verify_compact_prevalidated(
    params: ProtocolParams,
    public: &DealerPublicTranscript,
    sender: u32,
    index: usize,
    item: &CompactReconstructionItem,
) -> Result<(Scalar, Scalar), SilkError> {
    CompactPointVerifier::new_prevalidated(params, public, index)?.verify(sender, item)
}

/// Reusable verifier for the compact openings of one dealer and batch index.
///
/// The enclosing epoch verifier has already authenticated the public
/// transcript. This context therefore derives the transcript identifier and
/// Fiat--Shamir challenge once, then applies the same independent salted-leaf
/// predicate to every sender opening.
pub struct CompactPointVerifier<'a> {
    params: ProtocolParams,
    public: &'a DealerPublicTranscript,
    index: usize,
    theta: Scalar,
    response_coefficients: &'a [Scalar],
    leaf_prefix: HashTranscript,
}

/// Reusable normal-path plan for one exact sender set.
///
/// The plan does not require different dealers to share a holder set. A beacon
/// receiver may create one plan for each distinct exact sender set it observes.
/// Dealers that happen to use the same set reuse the product tree and the
/// interpolation weights, while sparse or fault-recovery sets remain separate.
#[derive(Clone, Debug)]
pub struct CompactReconstructionPlan {
    params: ProtocolParams,
    senders: Vec<u32>,
    evaluation: MultipointEvaluationPlan,
    interpolation_weights: Vec<Scalar>,
}

impl CompactReconstructionPlan {
    pub fn new(params: ProtocolParams, senders: &[u32]) -> Result<Self, SilkError> {
        validate_params(params)?;
        if senders.len() != params.d {
            return Err(SilkError::InvalidShareCount {
                got: senders.len(),
                expected: params.d,
            });
        }
        if senders.windows(2).any(|pair| pair[0] >= pair[1])
            || senders.iter().any(|sender| *sender as usize >= params.n)
        {
            return Err(SilkError::DuplicateEvaluationPoint);
        }
        let points = senders
            .iter()
            .map(|sender| evaluation_point(*sender as usize))
            .collect::<Result<Vec<_>, _>>()?;
        let (evaluation, _) = MultipointEvaluationPlan::new(&points)?;
        let (interpolation_weights, _) = evaluation.interpolation_weights_at_zero()?;
        Ok(Self {
            params,
            senders: senders.to_vec(),
            evaluation,
            interpolation_weights,
        })
    }

    pub fn senders(&self) -> &[u32] {
        &self.senders
    }

    pub fn points(&self) -> &[Scalar] {
        self.evaluation.points()
    }

    /// Verifies exactly one item per planned sender after the enclosing epoch
    /// verifier has already authenticated the dealer transcript.
    pub fn verify_prevalidated(
        &self,
        public: &DealerPublicTranscript,
        index: usize,
        items: &[(u32, CompactReconstructionItem)],
    ) -> Result<Vec<(Scalar, Scalar)>, SilkError> {
        if public.params != self.params || index >= self.params.l || items.len() != self.params.d {
            return Err(SilkError::InvalidParameters);
        }
        let response = public.responses.get(index).ok_or(SilkError::InvalidIndex)?;
        let coefficients = response
            .polynomials
            .first()
            .filter(|coefficients| coefficients.len() == self.params.d)
            .ok_or(SilkError::InvalidResponseCount {
                got: response.polynomials.len(),
                expected: RESPONSE_REPETITIONS,
            })?;
        if response.index as usize != index || response.polynomials.len() != RESPONSE_REPETITIONS {
            return Err(SilkError::InvalidResponseCount {
                got: response.polynomials.len(),
                expected: RESPONSE_REPETITIONS,
            });
        }
        let (evaluations, _) = self.evaluation.evaluate(coefficients)?;
        let theta = challenge(
            &public.sid,
            public.context,
            public.dealer,
            index as u32,
            0,
            public.message_root,
        );
        let leaf_prefix = share_leaf_prefix(&public.sid, public.context, public.dealer);
        let mut accepted = Vec::with_capacity(items.len());
        for (position, (((expected_sender, point), h_at_point), (sender, item))) in self
            .senders
            .iter()
            .zip(self.evaluation.points())
            .zip(evaluations)
            .zip(items)
            .enumerate()
        {
            if sender != expected_sender || item.dealer != public.dealer {
                return Err(SilkError::CertificateMismatch);
            }
            let expected_leaf = public
                .leaf_digests
                .rows
                .get(*sender as usize)
                .and_then(|row| row.get(index))
                .ok_or(SilkError::InvalidIndex)?;
            let recovered_mask = h_at_point - theta * item.share;
            let actual_leaf = share_leaf_digest_single_mask(
                &leaf_prefix,
                *sender,
                index as u32,
                item.share,
                item.salt,
                recovered_mask,
            );
            if actual_leaf != *expected_leaf {
                return Err(SilkError::InvalidRowCheck);
            }
            debug_assert_eq!(self.senders[position], *sender);
            accepted.push((*point, item.share));
        }
        Ok(accepted)
    }

    pub fn interpolate_shares(&self, shares: &[Scalar]) -> Result<Scalar, SilkError> {
        if shares.len() != self.params.d {
            return Err(SilkError::InvalidShareCount {
                got: shares.len(),
                expected: self.params.d,
            });
        }
        Ok(self
            .interpolation_weights
            .iter()
            .zip(shares)
            .fold(Scalar::ZERO, |sum, (weight, share)| sum + weight * share))
    }
}

impl<'a> CompactPointVerifier<'a> {
    pub fn new_prevalidated(
        params: ProtocolParams,
        public: &'a DealerPublicTranscript,
        index: usize,
    ) -> Result<Self, SilkError> {
        validate_params(params)?;
        if public.params != params || index >= params.l {
            return Err(SilkError::InvalidParameters);
        }
        let response = public.responses.get(index).ok_or(SilkError::InvalidIndex)?;
        let response_coefficients = response
            .polynomials
            .first()
            .filter(|coefficients| coefficients.len() == params.d)
            .ok_or(SilkError::InvalidResponseCount {
                got: response.polynomials.len(),
                expected: RESPONSE_REPETITIONS,
            })?;
        if response.index as usize != index || response.polynomials.len() != RESPONSE_REPETITIONS {
            return Err(SilkError::InvalidResponseCount {
                got: response.polynomials.len(),
                expected: RESPONSE_REPETITIONS,
            });
        }
        let theta = challenge(
            &public.sid,
            public.context,
            public.dealer,
            index as u32,
            0,
            public.message_root,
        );
        let leaf_prefix = share_leaf_prefix(&public.sid, public.context, public.dealer);
        Ok(Self {
            params,
            public,
            index,
            theta,
            response_coefficients,
            leaf_prefix,
        })
    }

    pub fn verify(
        &self,
        sender: u32,
        item: &CompactReconstructionItem,
    ) -> Result<(Scalar, Scalar), SilkError> {
        if sender as usize >= self.params.n {
            return Err(SilkError::InvalidIndex);
        }
        if item.dealer != self.public.dealer {
            return Err(SilkError::CertificateMismatch);
        }
        let sender_index = sender as usize;
        let expected_leaf = self
            .public
            .leaf_digests
            .rows
            .get(sender_index)
            .and_then(|row| row.get(self.index))
            .ok_or(SilkError::InvalidIndex)?;
        let point = evaluation_point(sender_index)?;
        let recovered_mask = evaluate(self.response_coefficients, point) - self.theta * item.share;
        let actual_leaf = share_leaf_digest_single_mask(
            &self.leaf_prefix,
            sender,
            self.index as u32,
            item.share,
            item.salt,
            recovered_mask,
        );
        if actual_leaf != *expected_leaf {
            return Err(SilkError::InvalidRowCheck);
        }
        Ok((point, item.share))
    }
}

pub fn point_verify_compact_batch_fast(
    params: ProtocolParams,
    public: &DealerPublicTranscript,
    index: usize,
    items: &[(u32, CompactReconstructionItem)],
) -> Result<(Vec<(Scalar, Scalar)>, PolynomialOpCounts), SilkError> {
    validate_params(params)?;
    validate_public_shape(public)?;
    if public.params != params || index >= params.l {
        return Err(SilkError::InvalidParameters);
    }
    if items.is_empty() {
        return Err(SilkError::InsufficientShares {
            have: 0,
            need: params.d,
        });
    }
    let mut previous = None;
    let mut points = Vec::with_capacity(items.len());
    for (sender, item) in items {
        if *sender as usize >= params.n {
            return Err(SilkError::InvalidIndex);
        }
        if previous.is_some_and(|value| value >= *sender) || item.dealer != public.dealer {
            return Err(SilkError::CertificateMismatch);
        }
        previous = Some(*sender);
        points.push(evaluation_point(*sender as usize)?);
    }
    let response = &public.responses[index];
    let (evaluations, counts) = multipoint_evaluate(&response.polynomials[0], &points)?;
    let theta = challenge(
        &public.sid,
        public.context,
        public.dealer,
        index as u32,
        0,
        public.message_root,
    );
    let mut accepted = Vec::with_capacity(items.len());
    for (((sender, item), point), h_at_point) in items.iter().zip(points).zip(evaluations) {
        let slot = PrivateSlot {
            index: index as u32,
            share: item.share,
            masks: vec![h_at_point - theta * item.share],
            salt: item.salt,
        };
        if share_leaf_digest(&public.sid, public.context, public.dealer, *sender, &slot)
            != public.leaf_digests.rows[*sender as usize][index]
        {
            return Err(SilkError::InvalidRowCheck);
        }
        accepted.push((point, item.share));
    }
    Ok((accepted, counts))
}

pub fn reconstruct_secret(
    params: ProtocolParams,
    points: &[(Scalar, Scalar)],
) -> Result<(Scalar, PolynomialOpCounts), SilkError> {
    validate_params(params)?;
    Ok(interpolate_at_zero_fast(points, params.d)?)
}
