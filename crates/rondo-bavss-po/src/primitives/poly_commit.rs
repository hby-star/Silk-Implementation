use crate::BreezeError;
use crate::primitives::merkle::MerkleTree;
use crypto_primitives::hash::HashTranscript;
use crypto_primitives::polynomial::{evaluate, powers};
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::MultiscalarMul;

mod ipa;
mod types;

use ipa::*;
pub use types::{BatchEvalProofMember, BatchEvalProofRound};

/// Pedersen vector commitment to polynomial coefficients with Bulletproof-style IPA openings.
#[derive(Clone, Debug)]
pub struct PolyCommitment {
    coeff_len: usize,
    generators: Vec<RistrettoPoint>,
    u: RistrettoPoint,
}

impl PolyCommitment {
    /// Creates a commitment scheme for polynomials with `coeff_len` coefficients.
    pub fn new(coeff_len: usize) -> Result<Self, BreezeError> {
        if coeff_len == 0 {
            return Err(BreezeError::InvalidThreshold);
        }

        let mut generators = Vec::with_capacity(coeff_len);
        for idx in 0..coeff_len {
            generators.push(hash_to_point(b"Rondo-Breeze-IPA-G", idx as u64));
        }

        Ok(Self {
            coeff_len,
            generators,
            u: hash_to_point(b"Rondo-Breeze-IPA-U", 0),
        })
    }

    /// Commits one coefficient vector as used by Breeze `BatchCommit`.
    pub fn commit(&self, coeffs: &[Scalar]) -> Result<RistrettoPoint, BreezeError> {
        if coeffs.len() != self.coeff_len {
            return Err(BreezeError::InvalidPolynomialLength {
                got: coeffs.len(),
                max: self.coeff_len,
            });
        }
        Ok(RistrettoPoint::multiscalar_mul(
            coeffs.iter(),
            self.generators.iter(),
        ))
    }

    /// Breeze `BatchCommit` over all `B` coefficient vectors.
    pub(crate) fn batch_commit(
        &self,
        polynomials: &[Vec<Scalar>],
    ) -> Result<Vec<RistrettoPoint>, BreezeError> {
        protocol_support::compute::map(polynomials.len(), |i| self.commit(&polynomials[i]))
            .into_iter()
            .collect()
    }

    /// Rondo Fig. 7 `BatchEval`: one proof-vector member per receiver, with
    /// one shared recursive challenge per level.
    pub(crate) fn batch_eval(
        &self,
        commitment: RistrettoPoint,
        coeffs: &[Scalar],
        eval_points: &[Scalar],
        claimed_values: &[Scalar],
    ) -> Result<Vec<BatchEvalProofMember>, BreezeError> {
        if coeffs.len() != self.coeff_len {
            return Err(BreezeError::InvalidPolynomialLength {
                got: coeffs.len(),
                max: self.coeff_len,
            });
        }
        if eval_points.is_empty() || eval_points.len() != claimed_values.len() {
            return Err(BreezeError::InvalidShareCount {
                got: claimed_values.len(),
                expected: eval_points.len(),
            });
        }
        for (point, value) in eval_points.iter().zip(claimed_values) {
            if evaluate(coeffs, *point) != *value {
                return Err(BreezeError::InvalidClaimedEvaluation);
            }
        }

        let statement_count = eval_points.len();
        let mut a = coeffs.to_vec();
        let mut b_vectors = eval_points
            .iter()
            .map(|point| powers(*point, coeffs.len()))
            .collect::<Vec<_>>();
        let mut generators = self.generators[..coeffs.len()].to_vec();
        let statement_challenges = b_vectors
            .iter()
            .zip(claimed_values)
            .map(|(public_vector, value)| {
                multi_statement_challenge(&commitment, public_vector, *value)
            })
            .collect::<Vec<_>>();
        let (u_points, mut statements): (Vec<_>, Vec<_>) =
            protocol_support::compute::map(statement_count, |index| {
                let challenge = statement_challenges[index];
                (
                    challenge * self.u,
                    commitment + (challenge * claimed_values[index]) * self.u,
                )
            })
            .into_iter()
            .unzip();
        let mut proof_rounds = vec![Vec::new(); statement_count];

        while a.len() > 1 {
            let removed_scalar = if a.len() % 2 == 1 {
                let removed = -*a.last().expect("odd vector has last coefficient");
                let removed_generator = *generators
                    .last()
                    .expect("generator vector matches coefficient vector");
                a.pop();
                generators.pop();
                let common_correction = removed * removed_generator;
                statements = protocol_support::compute::map(statement_count, |index| {
                    let removed_public = *b_vectors[index]
                        .last()
                        .expect("public vector matches coefficients");
                    statements[index]
                        + common_correction
                        + (removed * removed_public) * u_points[index]
                });
                for b in &mut b_vectors {
                    b.pop();
                }
                Some(removed)
            } else {
                None
            };

            let half = a.len() / 2;
            let (a_l, a_r) = a.split_at(half);
            let (g_l, g_r) = generators.split_at(half);
            let points = protocol_support::compute::map(statement_count, |index| {
                let b = &b_vectors[index];
                let u_point = u_points[index];
                let (b_l, b_r) = b.split_at(half);
                (
                    msm_with_u(a_l, g_r, inner_product(a_l, b_r), u_point),
                    msm_with_u(a_r, g_l, inner_product(a_r, b_l), u_point),
                )
            });
            let (l_points, r_points): (Vec<_>, Vec<_>) = points.into_iter().unzip();
            let leaves = protocol_support::compute::map(statement_count, |index| {
                multi_round_leaf(
                    a.len(),
                    &generators,
                    &u_points[index],
                    &b_vectors[index],
                    &statements[index],
                    &l_points[index],
                    &r_points[index],
                    removed_scalar,
                )
            });
            let tree = MerkleTree::new(leaves)?;
            let root = tree.root();
            let challenge = multi_round_challenge(&root);
            let challenge_inv = challenge.invert();

            let updates = protocol_support::compute::map(statement_count, |index| {
                let proof = BatchEvalProofRound {
                    removed_scalar: removed_scalar.map(|value| value.to_bytes()),
                    l_point: l_points[index].compress().to_bytes(),
                    r_point: r_points[index].compress().to_bytes(),
                    transcript_root: root,
                    transcript_branch: tree.proof(index)?,
                };
                let statement = statements[index]
                    + challenge * challenge * l_points[index]
                    + challenge_inv * challenge_inv * r_points[index];
                Ok::<_, BreezeError>((proof, statement))
            })
            .into_iter()
            .collect::<Result<Vec<_>, _>>()?;
            for (index, (proof, statement)) in updates.into_iter().enumerate() {
                proof_rounds[index].push(proof);
                statements[index] = statement;
            }
            a = fold_scalars(a_l, a_r, challenge, challenge_inv);
            generators = fold_points(g_l, g_r, challenge_inv, challenge);
            for b in &mut b_vectors {
                let (b_l, b_r) = b.split_at(half);
                *b = fold_scalars(b_l, b_r, challenge_inv, challenge);
            }
        }

        Ok(proof_rounds
            .into_iter()
            .enumerate()
            .map(|(index, rounds)| BatchEvalProofMember {
                statement_index: index as u32,
                statement_count: statement_count as u32,
                rounds,
                final_scalar: a[0].to_bytes(),
            })
            .collect())
    }

    /// Rondo Fig. 8 `BatchVerifyEval` for one member of the proof vector.
    pub(crate) fn batch_verify_eval(
        &self,
        commitment: RistrettoPoint,
        eval_point: Scalar,
        claimed_value: Scalar,
        statement_index: usize,
        statement_count: usize,
        proof: &BatchEvalProofMember,
    ) -> Result<(), BreezeError> {
        if statement_count == 0
            || statement_index >= statement_count
            || proof.statement_index as usize != statement_index
            || proof.statement_count as usize != statement_count
        {
            return Err(BreezeError::MalformedProof);
        }
        let mut b = powers(eval_point, self.coeff_len);
        let statement_challenge = multi_statement_challenge(&commitment, &b, claimed_value);
        let u_point = statement_challenge * self.u;
        let mut statement = commitment + claimed_value * u_point;
        let mut generators = self.generators[..self.coeff_len].to_vec();
        let mut round_index = 0usize;

        while generators.len() > 1 {
            let round = proof
                .rounds
                .get(round_index)
                .ok_or(BreezeError::MalformedProof)?;
            let removed_scalar = if generators.len() % 2 == 1 {
                let bytes = round.removed_scalar.ok_or(BreezeError::MalformedProof)?;
                let removed = Scalar::from_canonical_bytes(bytes)
                    .into_option()
                    .ok_or(BreezeError::MalformedProof)?;
                let removed_generator = generators.pop().expect("odd generator vector");
                let removed_public = b.pop().expect("odd public vector");
                statement += removed * removed_generator + (removed * removed_public) * u_point;
                Some(removed)
            } else {
                if round.removed_scalar.is_some() {
                    return Err(BreezeError::MalformedProof);
                }
                None
            };
            let l_point = decompress_point(&round.l_point)?;
            let r_point = decompress_point(&round.r_point)?;
            if round.transcript_branch.index() != statement_index
                || round.transcript_branch.leaf_count() != statement_count
            {
                return Err(BreezeError::MalformedProof);
            }
            let leaf = multi_round_leaf(
                generators.len(),
                &generators,
                &u_point,
                &b,
                &statement,
                &l_point,
                &r_point,
                removed_scalar,
            );
            if !round
                .transcript_branch
                .verify(&round.transcript_root, &leaf)
            {
                return Err(BreezeError::InvalidBatchEvalProof);
            }
            let challenge = multi_round_challenge(&round.transcript_root);
            let challenge_inv = challenge.invert();
            statement += challenge * challenge * l_point + challenge_inv * challenge_inv * r_point;
            let half = generators.len() / 2;
            let (g_l, g_r) = generators.split_at(half);
            generators = fold_points(g_l, g_r, challenge_inv, challenge);
            let (b_l, b_r) = b.split_at(half);
            b = fold_scalars(b_l, b_r, challenge_inv, challenge);
            round_index += 1;
        }
        if proof.rounds.len() != round_index || b.len() != 1 || generators.len() != 1 {
            return Err(BreezeError::MalformedProof);
        }
        let final_scalar = Scalar::from_canonical_bytes(proof.final_scalar)
            .into_option()
            .ok_or(BreezeError::MalformedProof)?;
        let expected = final_scalar * generators[0] + (final_scalar * b[0]) * u_point;
        if expected == statement {
            Ok(())
        } else {
            Err(BreezeError::InvalidBatchEvalProof)
        }
    }
}

fn multi_statement_challenge(
    commitment: &RistrettoPoint,
    public_vector: &[Scalar],
    claimed_value: Scalar,
) -> Scalar {
    let mut transcript = HashTranscript::new(b"Rondo-Breeze-multi-statement-v1");
    transcript.update(&commitment.compress().to_bytes());
    transcript.update(&(public_vector.len() as u64).to_le_bytes());
    for value in public_vector {
        transcript.update(&value.to_bytes());
    }
    transcript.update(&claimed_value.to_bytes());
    hash_to_nonzero_scalar(&transcript.finalize())
}

#[allow(clippy::too_many_arguments)]
fn multi_round_leaf(
    vector_len: usize,
    generators: &[RistrettoPoint],
    u_point: &RistrettoPoint,
    public_vector: &[Scalar],
    statement: &RistrettoPoint,
    l_point: &RistrettoPoint,
    r_point: &RistrettoPoint,
    removed_scalar: Option<Scalar>,
) -> [u8; 32] {
    let mut transcript = HashTranscript::new(b"Rondo-Breeze-multi-round-leaf-v1");
    transcript.update(&(vector_len as u64).to_le_bytes());
    for generator in generators {
        transcript.update(&generator.compress().to_bytes());
    }
    transcript.update(&u_point.compress().to_bytes());
    for value in public_vector {
        transcript.update(&value.to_bytes());
    }
    transcript.update(&statement.compress().to_bytes());
    transcript.update(&l_point.compress().to_bytes());
    transcript.update(&r_point.compress().to_bytes());
    match removed_scalar {
        Some(value) => {
            transcript.update(&[1]);
            transcript.update(&value.to_bytes());
        }
        None => {
            transcript.update(&[0]);
        }
    }
    transcript.finalize()
}

fn multi_round_challenge(root: &[u8; 32]) -> Scalar {
    hash_to_nonzero_scalar(root)
}
