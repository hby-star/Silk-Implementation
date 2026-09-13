//! The pairing-based `Pi_DBDH` PVSS used by Spurt.

use blstrs::{G1Projective, G2Projective, Scalar};
use ff::Field;
use group::Group;
use protocol_support::wire::canonical_serialize;
use rand::RngCore;

use crate::SpurtError;
use crate::types::{DealerContribution, DleqProof, PublicParameters};

pub(crate) struct DleqBatchItem<'a> {
    pub public_key: G1Projective,
    pub commitment: G2Projective,
    pub ciphertext: G1Projective,
    pub proof: &'a DleqProof,
    pub epoch: u64,
    pub height: u64,
    pub dealer: u32,
    pub receiver: u32,
}

pub(crate) fn sample_nonzero_scalar(rng: &mut impl RngCore) -> Scalar {
    loop {
        let value = Scalar::random(&mut *rng);
        if !bool::from(value.is_zero()) {
            return value;
        }
    }
}

pub(crate) fn setup(rng: &mut impl RngCore) -> PublicParameters {
    PublicParameters {
        g0: G1Projective::generator() * sample_nonzero_scalar(rng),
        h0: G1Projective::generator() * sample_nonzero_scalar(rng),
        g1: G2Projective::generator() * sample_nonzero_scalar(rng),
        h1: G2Projective::generator() * sample_nonzero_scalar(rng),
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn share(
    parameters: &PublicParameters,
    public_keys: &[G1Projective],
    n: usize,
    t: usize,
    epoch: u64,
    height: u64,
    dealer: u32,
    rng: &mut impl RngCore,
) -> Result<DealerContribution, SpurtError> {
    if public_keys.len() != n || dealer as usize >= n {
        return Err(SpurtError::Transcript("PVSS sharing context mismatch"));
    }
    let polynomial = (0..=t)
        .map(|_| Scalar::random(&mut *rng))
        .collect::<Vec<_>>();
    let mut commitments = Vec::with_capacity(n);
    let mut ciphertexts = Vec::with_capacity(n);
    let mut proofs = Vec::with_capacity(n);
    // Draw nonces in canonical receiver order, preserving the original RNG
    // stream while keeping randomness independent of worker scheduling.
    let nonces = (0..n)
        .map(|_| sample_nonzero_scalar(rng))
        .collect::<Vec<_>>();
    let generated = protocol_support::compute::map(n, |receiver| {
        let public_key = public_keys[receiver];
        let point = Scalar::from(receiver as u64 + 1);
        let evaluation = evaluate(&polynomial, point);
        let commitment = parameters.g1 * evaluation;
        let ciphertext = public_key * evaluation;
        let proof = prove_dleq(
            parameters,
            public_key,
            commitment,
            ciphertext,
            evaluation,
            epoch,
            height,
            dealer,
            receiver as u32,
            nonces[receiver],
        )?;
        Ok::<_, SpurtError>((commitment, ciphertext, proof))
    });
    for generated in generated {
        let (commitment, ciphertext, proof) = generated?;
        commitments.push(commitment);
        ciphertexts.push(ciphertext);
        proofs.push(proof);
    }
    Ok(DealerContribution {
        epoch,
        height,
        dealer,
        commitments,
        ciphertexts,
        proofs,
        signature: Vec::new(),
    })
}

pub(crate) fn verify_contribution(
    parameters: &PublicParameters,
    public_keys: &[G1Projective],
    n: usize,
    t: usize,
    dual_weights: &[Scalar],
    contribution: &DealerContribution,
) -> Result<(), SpurtError> {
    verify_shape(n, contribution)?;
    let context = canonical_serialize(&(
        "Spurt-contribution-degree-check-v1",
        contribution.epoch,
        contribution.height,
        contribution.dealer,
    ))?;
    degree_check(&contribution.commitments, n, t, dual_weights, &context)?;
    let items = public_keys
        .iter()
        .enumerate()
        .map(|(receiver, public_key)| DleqBatchItem {
            public_key: *public_key,
            commitment: contribution.commitments[receiver],
            ciphertext: contribution.ciphertexts[receiver],
            proof: &contribution.proofs[receiver],
            epoch: contribution.epoch,
            height: contribution.height,
            dealer: contribution.dealer,
            receiver: receiver as u32,
        })
        .collect::<Vec<_>>();
    verify_dleq_batch(parameters, &items)
}

pub(crate) fn degree_check(
    commitments: &[G2Projective],
    n: usize,
    t: usize,
    dual_weights: &[Scalar],
    context: &[u8],
) -> Result<(), SpurtError> {
    if commitments.len() != n || dual_weights.len() != n || n < t + 2 {
        return Err(SpurtError::Transcript(
            "degree-check commitment vector has the wrong length",
        ));
    }

    // A random word of the dual [n,t+1] Reed-Solomon code has coordinates
    // lambda_i f(i), where deg(f) <= n-t-2 and
    // lambda_i = 1 / product_{j != i}(i-j). Derive f after binding the
    // complete commitment vector, so the public experiment seed cannot make
    // the verifier challenge predictable before the statement is fixed.
    let seed = *blake3::hash(&canonical_serialize(&(
        "Spurt-RS-degree-check-transcript-v1",
        n,
        t,
        context,
        commitments,
    ))?)
    .as_bytes();
    let dual_polynomial = (0..(n - t - 1))
        .map(|coefficient| degree_check_coefficient(seed, coefficient as u64))
        .collect::<Vec<_>>();
    let dual_coordinates = commitments
        .iter()
        .enumerate()
        .map(|(index, _)| {
            let x_i = Scalar::from(index as u64 + 1);
            dual_weights[index] * evaluate(&dual_polynomial, x_i)
        })
        .collect::<Vec<_>>();
    let accumulated = G2Projective::multi_exp(commitments, &dual_coordinates);
    if bool::from(accumulated.is_identity()) {
        Ok(())
    } else {
        Err(SpurtError::Verification(
            "commitments do not encode a degree-t polynomial",
        ))
    }
}

pub(crate) fn degree_check_weights(n: usize) -> Result<Vec<Scalar>, SpurtError> {
    if n < 2 {
        return Err(SpurtError::Transcript(
            "degree-check evaluation domain is too small",
        ));
    }
    let mut factorials = vec![Scalar::ONE; n];
    for index in 1..n {
        factorials[index] = factorials[index - 1] * Scalar::from(index as u64);
    }
    let mut inverse_factorials = vec![Scalar::ONE; n];
    inverse_factorials[n - 1] = Option::<Scalar>::from(factorials[n - 1].invert()).ok_or(
        SpurtError::Transcript("degree-check factorial is not invertible"),
    )?;
    for index in (1..n).rev() {
        inverse_factorials[index - 1] = inverse_factorials[index] * Scalar::from(index as u64);
    }
    Ok((0..n)
        .map(|index| {
            let weight = inverse_factorials[index] * inverse_factorials[n - 1 - index];
            if (n - 1 - index).is_multiple_of(2) {
                weight
            } else {
                -weight
            }
        })
        .collect())
}

pub(crate) fn verify_dleq_batch(
    parameters: &PublicParameters,
    items: &[DleqBatchItem<'_>],
) -> Result<(), SpurtError> {
    if items.is_empty() {
        return Err(SpurtError::Transcript("empty DLEQ verification batch"));
    }
    let batch_transcript = items
        .iter()
        .map(|item| {
            canonical_serialize(&(
                item.public_key,
                item.commitment,
                item.ciphertext,
                item.proof,
                item.epoch,
                item.height,
                item.dealer,
                item.receiver,
            ))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let seed = *blake3::hash(&canonical_serialize(&(
        "Spurt-DBDH-DLEQ-batch-v1",
        batch_transcript,
    ))?)
    .as_bytes();

    let mut g1_points = Vec::with_capacity(3 * items.len());
    let mut g1_scalars = Vec::with_capacity(3 * items.len());
    let mut g2_points = Vec::with_capacity(3 * items.len());
    let mut g2_scalars = Vec::with_capacity(3 * items.len());
    for (index, item) in items.iter().enumerate() {
        let challenge = dleq_challenge(
            parameters,
            item.public_key,
            item.commitment,
            item.ciphertext,
            item.proof.commitment_g1,
            item.proof.commitment_g2,
            item.epoch,
            item.height,
            item.dealer,
            item.receiver,
        )?;
        let weight = batch_weight(seed, index as u64);
        let weighted_response = weight * item.proof.response;
        let weighted_challenge = weight * challenge;

        g1_points.extend([item.public_key, item.proof.commitment_g1, item.ciphertext]);
        g1_scalars.extend([weighted_response, -weight, -weighted_challenge]);
        g2_points.extend([parameters.g1, item.proof.commitment_g2, item.commitment]);
        g2_scalars.extend([weighted_response, -weight, -weighted_challenge]);
    }
    let checks = protocol_support::compute::map(2, |index| {
        if index == 0 {
            bool::from(G1Projective::multi_exp(&g1_points, &g1_scalars).is_identity())
        } else {
            bool::from(G2Projective::multi_exp(&g2_points, &g2_scalars).is_identity())
        }
    });
    if checks.into_iter().all(|valid| valid) {
        Ok(())
    } else {
        Err(SpurtError::Verification("invalid batched DLEQ proof"))
    }
}

fn verify_shape(n: usize, contribution: &DealerContribution) -> Result<(), SpurtError> {
    if contribution.dealer as usize >= n
        || contribution.commitments.len() != n
        || contribution.ciphertexts.len() != n
        || contribution.proofs.len() != n
    {
        return Err(SpurtError::Transcript(
            "PVSS contribution has the wrong dimensions",
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn prove_dleq(
    parameters: &PublicParameters,
    public_key: G1Projective,
    commitment: G2Projective,
    ciphertext: G1Projective,
    witness: Scalar,
    epoch: u64,
    height: u64,
    dealer: u32,
    receiver: u32,
    nonce: Scalar,
) -> Result<DleqProof, SpurtError> {
    let commitment_g1 = public_key * nonce;
    let commitment_g2 = parameters.g1 * nonce;
    let challenge = dleq_challenge(
        parameters,
        public_key,
        commitment,
        ciphertext,
        commitment_g1,
        commitment_g2,
        epoch,
        height,
        dealer,
        receiver,
    )?;
    Ok(DleqProof {
        commitment_g1,
        commitment_g2,
        response: nonce + challenge * witness,
    })
}

#[allow(clippy::too_many_arguments)]
fn dleq_challenge(
    parameters: &PublicParameters,
    public_key: G1Projective,
    commitment: G2Projective,
    ciphertext: G1Projective,
    proof_commitment_g1: G1Projective,
    proof_commitment_g2: G2Projective,
    epoch: u64,
    height: u64,
    dealer: u32,
    receiver: u32,
) -> Result<Scalar, SpurtError> {
    let transcript = canonical_serialize(&(
        "Spurt-DBDH-DLEQ-v1",
        epoch,
        height,
        dealer,
        receiver,
        parameters.g1,
        public_key,
        commitment,
        ciphertext,
        proof_commitment_g1,
        proof_commitment_g2,
    ))?;
    Ok(hash_to_scalar(&transcript))
}

fn hash_to_scalar(transcript: &[u8]) -> Scalar {
    for counter in 0u32.. {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"Spurt-hash-to-scalar-v1");
        hasher.update(transcript);
        hasher.update(&counter.to_le_bytes());
        let candidate = *hasher.finalize().as_bytes();
        if let Some(scalar) = Option::<Scalar>::from(Scalar::from_bytes_le(&candidate)) {
            return scalar;
        }
    }
    unreachable!("32-bit rejection counter exhausted")
}

fn batch_weight(seed: [u8; 32], index: u64) -> Scalar {
    for counter in 0u32.. {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"Spurt-DBDH-DLEQ-batch-weight-v1");
        hasher.update(&seed);
        hasher.update(&index.to_le_bytes());
        hasher.update(&counter.to_le_bytes());
        let candidate = *hasher.finalize().as_bytes();
        if let Some(scalar) = Option::<Scalar>::from(Scalar::from_bytes_le(&candidate))
            && !bool::from(scalar.is_zero())
        {
            return scalar;
        }
    }
    unreachable!("32-bit batch-weight rejection counter exhausted")
}

fn degree_check_coefficient(seed: [u8; 32], index: u64) -> Scalar {
    for counter in 0u32.. {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"Spurt-RS-degree-check-coefficient-v1");
        hasher.update(&seed);
        hasher.update(&index.to_le_bytes());
        hasher.update(&counter.to_le_bytes());
        let candidate = *hasher.finalize().as_bytes();
        if let Some(scalar) = Option::<Scalar>::from(Scalar::from_bytes_le(&candidate))
            && !bool::from(scalar.is_zero())
        {
            return scalar;
        }
    }
    unreachable!("32-bit degree-check coefficient rejection counter exhausted")
}

fn evaluate(coefficients: &[Scalar], point: Scalar) -> Scalar {
    coefficients
        .iter()
        .rev()
        .fold(Scalar::ZERO, |value, coefficient| {
            value * point + coefficient
        })
}
