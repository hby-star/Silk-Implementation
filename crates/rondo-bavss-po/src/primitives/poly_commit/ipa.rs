use crate::BreezeError;
use crypto_primitives::hash::HashTranscript;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::{Identity, MultiscalarMul};

pub(super) fn hash_to_point(domain: &[u8], idx: u64) -> RistrettoPoint {
    let mut wide = [0u8; 64];
    let mut hasher = HashTranscript::new(domain);
    hasher.update(&idx.to_le_bytes());
    hasher.fill_xof(&mut wide);
    RistrettoPoint::from_uniform_bytes(&wide)
}

pub(super) fn hash_to_nonzero_scalar(bytes: &[u8]) -> Scalar {
    let mut counter = 0u64;
    loop {
        let mut wide = [0u8; 64];
        let mut hasher = HashTranscript::new(b"Rondo-Breeze-scalar");
        hasher.update(bytes);
        hasher.update(&counter.to_le_bytes());
        hasher.fill_xof(&mut wide);
        let scalar = Scalar::from_bytes_mod_order_wide(&wide);
        if scalar != Scalar::ZERO {
            return scalar;
        }
        counter += 1;
    }
}

pub(super) fn inner_product(left: &[Scalar], right: &[Scalar]) -> Scalar {
    left.iter()
        .zip(right.iter())
        .fold(Scalar::ZERO, |acc, (l, r)| acc + l * r)
}

pub(super) fn msm_with_u(
    scalars: &[Scalar],
    points: &[RistrettoPoint],
    u_scalar: Scalar,
    u: RistrettoPoint,
) -> RistrettoPoint {
    let mut all_scalars = Vec::with_capacity(scalars.len() + 1);
    all_scalars.extend_from_slice(scalars);
    all_scalars.push(u_scalar);

    let mut all_points = Vec::with_capacity(points.len() + 1);
    all_points.extend_from_slice(points);
    all_points.push(u);

    if all_scalars.is_empty() {
        RistrettoPoint::identity()
    } else {
        RistrettoPoint::multiscalar_mul(all_scalars, all_points)
    }
}

pub(super) fn fold_scalars(
    left: &[Scalar],
    right: &[Scalar],
    left_weight: Scalar,
    right_weight: Scalar,
) -> Vec<Scalar> {
    left.iter()
        .zip(right.iter())
        .map(|(l, r)| left_weight * l + right_weight * r)
        .collect()
}

pub(super) fn fold_points(
    left: &[RistrettoPoint],
    right: &[RistrettoPoint],
    left_weight: Scalar,
    right_weight: Scalar,
) -> Vec<RistrettoPoint> {
    left.iter()
        .zip(right.iter())
        .map(|(l, r)| left_weight * l + right_weight * r)
        .collect()
}

pub(super) fn decompress_point(bytes: &[u8; 32]) -> Result<RistrettoPoint, BreezeError> {
    CompressedRistretto(*bytes)
        .decompress()
        .ok_or(BreezeError::MalformedProof)
}
