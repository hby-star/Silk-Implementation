use crate::BreezeError;
use crate::primitives::poly_commit::PolyCommitment;
use crate::protocol::types::ProtocolParams;
use crypto_primitives::hash::HashTranscript;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;

/// Reconstructs a degree-`t` aggregate polynomial from the fixed normal-path
/// holder set and checks it against the homomorphic sum of the selected
/// dealers' coefficient-vector commitments.
///
/// A malformed member makes the recovered polynomial fail the commitment
/// check. Holder replacement is outside the prototype's fixed-holder path.
#[derive(Clone, Debug)]
pub struct CompactAggregateReconstructor {
    points: Vec<Scalar>,
    coefficient_weights: Vec<Vec<Scalar>>,
    poly_commit: PolyCommitment,
}

impl CompactAggregateReconstructor {
    pub fn new(params: ProtocolParams, points: &[Scalar]) -> Result<Self, BreezeError> {
        params.validate()?;
        if points.len() != params.d {
            return Err(BreezeError::InsufficientShares {
                have: points.len(),
                need: params.d,
            });
        }
        if points.contains(&Scalar::ZERO) {
            return Err(BreezeError::DuplicateEvaluationPoint);
        }

        // coefficient_weights[degree][holder] is the coefficient of X^degree
        // in the holder's Lagrange basis polynomial.
        let mut coefficient_weights = vec![vec![Scalar::ZERO; params.d]; params.d];
        for (holder, point) in points.iter().copied().enumerate() {
            let mut basis = vec![Scalar::ONE];
            let mut denominator = Scalar::ONE;
            for (other_holder, other) in points.iter().copied().enumerate() {
                if holder == other_holder {
                    continue;
                }
                let difference = point - other;
                if difference == Scalar::ZERO {
                    return Err(BreezeError::DuplicateEvaluationPoint);
                }
                denominator *= difference;
                basis = multiply_by_linear_factor(&basis, -other);
            }
            let denominator_inverse = denominator.invert();
            for (degree, coefficient) in basis.into_iter().enumerate() {
                coefficient_weights[degree][holder] = coefficient * denominator_inverse;
            }
        }

        Ok(Self {
            points: points.to_vec(),
            coefficient_weights,
            poly_commit: PolyCommitment::new(params.d)?,
        })
    }

    pub fn reconstruct(
        &self,
        shares: &[(Scalar, Scalar)],
        aggregate_commitment: RistrettoPoint,
    ) -> Result<Scalar, BreezeError> {
        if shares.len() != self.points.len() {
            return Err(BreezeError::InsufficientShares {
                have: shares.len(),
                need: self.points.len(),
            });
        }
        if shares
            .iter()
            .zip(self.points.iter())
            .any(|((point, _), expected)| point != expected)
        {
            return Err(BreezeError::InvalidReceiver);
        }

        let coefficients = self
            .coefficient_weights
            .iter()
            .map(|weights| {
                weights
                    .iter()
                    .zip(shares.iter())
                    .fold(Scalar::ZERO, |sum, (weight, (_, share))| {
                        sum + weight * share
                    })
            })
            .collect::<Vec<_>>();
        let recovered_commitment = self.poly_commit.commit(&coefficients)?;
        if recovered_commitment != aggregate_commitment {
            return Err(BreezeError::AggregateCommitmentMismatch);
        }
        Ok(coefficients[0])
    }
}

fn multiply_by_linear_factor(polynomial: &[Scalar], constant: Scalar) -> Vec<Scalar> {
    let mut product = vec![Scalar::ZERO; polynomial.len() + 1];
    for (degree, coefficient) in polynomial.iter().copied().enumerate() {
        product[degree] += constant * coefficient;
        product[degree + 1] += coefficient;
    }
    product
}

pub fn aggregate_dealer_secrets(secrets: &[Scalar]) -> Scalar {
    secrets
        .iter()
        .fold(Scalar::ZERO, |aggregate, secret| aggregate + secret)
}

pub fn beacon_output(
    sid: &[u8],
    beacon_idx: usize,
    tau_s: &[u8],
    aggregate_secret: Scalar,
) -> [u8; 32] {
    let mut hasher = HashTranscript::new(b"Rondo-beacon");
    hasher.update(&(sid.len() as u64).to_le_bytes());
    hasher.update(sid);
    hasher.update(&(beacon_idx as u64).to_le_bytes());
    hasher.update(&(tau_s.len() as u64).to_le_bytes());
    hasher.update(tau_s);
    hasher.update(&aggregate_secret.to_bytes());
    hasher.finalize()
}
