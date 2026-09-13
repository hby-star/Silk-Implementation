//! Mulberry's dealer-side `Share` construction.

use super::transcript::{
    challenge, message_root, response_digest, share_leaf_digest_single_mask, share_leaf_prefix,
};
use super::{
    DealerPublicTranscript, LeafDigestMatrix, PrivateRow, PrivateSlot, ProtocolContext,
    ResponsePolynomialSet,
};
use crate::{ProtocolParams, SilkError};
use crypto_primitives::polynomial::{
    add, evaluate_consecutive, random_scalar, sample_polynomial, sample_random_polynomial,
};
use curve25519_dalek::scalar::Scalar;
use rand::RngCore;

#[derive(Clone, Debug)]
pub struct Dealer {
    sid: Vec<u8>,
    context: ProtocolContext,
    dealer: u32,
    params: ProtocolParams,
    secrets: Vec<Scalar>,
}

impl Dealer {
    pub fn new(
        sid: Vec<u8>,
        context: ProtocolContext,
        dealer: u32,
        params: ProtocolParams,
        secrets: Vec<Scalar>,
    ) -> Result<Self, SilkError> {
        super::validate_params(params)?;
        if dealer as usize >= params.n {
            return Err(SilkError::InvalidDealer);
        }
        if secrets.len() != params.l
            || context.params_digest != super::transcript::params_digest(params)
        {
            return Err(SilkError::InvalidParameters);
        }
        Ok(Self {
            sid,
            context,
            dealer,
            params,
            secrets,
        })
    }

    pub fn random<R: RngCore + ?Sized>(
        sid: Vec<u8>,
        context: ProtocolContext,
        dealer: u32,
        params: ProtocolParams,
        rng: &mut R,
    ) -> Result<Self, SilkError> {
        let secrets = (0..params.l).map(|_| random_scalar(rng)).collect();
        Self::new(sid, context, dealer, params, secrets)
    }

    pub fn share<R: RngCore + ?Sized>(
        &self,
        rng: &mut R,
    ) -> Result<(DealerPublicTranscript, Vec<PrivateRow>), SilkError> {
        let sharing_polynomials = self
            .secrets
            .iter()
            .copied()
            .map(|secret| sample_polynomial(secret, self.params.d, rng))
            .collect::<Result<Vec<_>, _>>()?;
        let mask_polynomials = (0..self.params.l)
            .map(|_| sample_random_polynomial(self.params.d, rng).map(|poly| vec![poly]))
            .collect::<Result<Vec<_>, _>>()?;

        let share_evaluations = sharing_polynomials
            .iter()
            .map(|poly| evaluate_consecutive(poly, self.params.n))
            .collect::<Vec<_>>();
        let mask_evaluations = mask_polynomials
            .iter()
            .map(|poly| evaluate_consecutive(&poly[0], self.params.n))
            .collect::<Vec<_>>();
        let leaf_prefix = share_leaf_prefix(&self.sid, self.context, self.dealer);
        let mut private_rows = Vec::with_capacity(self.params.n);
        let mut matrix = Vec::with_capacity(self.params.n);
        for receiver in 0..self.params.n {
            let mut slots = Vec::with_capacity(self.params.l);
            let mut digest_row = Vec::with_capacity(self.params.l);
            for index in 0..self.params.l {
                let share = share_evaluations[index][receiver];
                let masks = vec![mask_evaluations[index][receiver]];
                let mut salt = [0u8; 32];
                rng.fill_bytes(&mut salt);
                let slot = PrivateSlot {
                    index: index as u32,
                    share,
                    masks,
                    salt,
                };
                digest_row.push(share_leaf_digest_single_mask(
                    &leaf_prefix,
                    receiver as u32,
                    index as u32,
                    slot.share,
                    slot.salt,
                    slot.masks[0],
                ));
                slots.push(slot);
            }
            matrix.push(digest_row);
            private_rows.push(PrivateRow {
                sid: self.sid.clone(),
                context: self.context,
                dealer: self.dealer,
                receiver: receiver as u32,
                slots,
            });
        }

        let leaf_digests = LeafDigestMatrix { rows: matrix };
        let message_root = message_root(&self.sid, self.context, self.dealer, &leaf_digests)?;
        let responses = (0..self.params.l)
            .map(|index| {
                let theta = challenge(
                    &self.sid,
                    self.context,
                    self.dealer,
                    index as u32,
                    0,
                    message_root,
                );
                ResponsePolynomialSet {
                    index: index as u32,
                    polynomials: vec![add(
                        &mask_polynomials[index][0],
                        &sharing_polynomials[index],
                        theta,
                    )],
                }
            })
            .collect::<Vec<_>>();
        let response_digest = response_digest(&self.sid, self.context, self.dealer, &responses)?;

        Ok((
            DealerPublicTranscript {
                sid: self.sid.clone(),
                context: self.context,
                dealer: self.dealer,
                params: self.params,
                message_root,
                leaf_digests,
                response_digest,
                responses,
            },
            private_rows,
        ))
    }
}
