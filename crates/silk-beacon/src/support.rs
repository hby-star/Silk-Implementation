use crypto_primitives::mldsa::{
    SigningKey65, VerifyingKey65, key_from_seed, verifying_key_from_bytes,
};
use protocol_support::derive_seed;
use thiserror::Error;

pub(crate) fn mldsa_key(seed: u64, role: &[u8], node: usize) -> Result<SigningKey65, BeaconError> {
    let mut label = role.to_vec();
    label.extend_from_slice(&(node as u64).to_le_bytes());
    let bytes = derive_seed(seed, &label);
    key_from_seed(bytes).map_err(|_| BeaconError::MlDsa)
}

pub(crate) fn mldsa_verifying_keys(
    public_keys: &[Vec<u8>],
) -> Result<Vec<VerifyingKey65>, BeaconError> {
    public_keys
        .iter()
        .map(|key| verifying_key_from_bytes(key).map_err(|_| BeaconError::MlDsa))
        .collect()
}

#[derive(Debug, Error)]
pub enum BeaconError {
    #[error("invalid lifecycle state")]
    InvalidState,
    #[error("invalid or non-sequential slot")]
    InvalidSlot,
    #[error("invalid validation data")]
    InvalidValidation,
    #[error("invalid certified epoch")]
    InvalidEpoch,
    #[error("invalid Quorum Release message or state")]
    InvalidRelease,
    #[error("invalid authenticated reconstruction message")]
    InvalidReconstruction,
    #[error("invalid beacon certificate")]
    InvalidBeaconCertificate,
    #[error("ML-DSA operation failed")]
    MlDsa,
    #[error(transparent)]
    Primitive(#[from] silk_bavss_po::SilkError),
    #[error(transparent)]
    Bft(#[from] crate::bft::BftError),
    #[error(transparent)]
    Wire(#[from] protocol_support::wire::WireError),
    #[error(transparent)]
    Store(#[from] protocol_support::store::StoreError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}
