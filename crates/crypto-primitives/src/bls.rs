use blst::BLST_ERROR;
use blst::min_pk::{AggregateSignature, Signature};
use thiserror::Error;

pub use blst::min_pk::{PublicKey, SecretKey};

/// Derives deterministic experiment keys while leaving domain separation to
/// the calling protocol.
pub fn derive_secret_key(
    seed: &[u8; 32],
    domain: &[u8],
    parts: &[&[u8]],
) -> Result<SecretKey, BlsError> {
    let mut hasher = blake3::Hasher::new_keyed(seed);
    hasher.update(domain);
    for part in parts {
        hasher.update(part);
    }
    key_gen(hasher.finalize().as_bytes(), &[])
}

pub fn key_gen(ikm: &[u8], key_info: &[u8]) -> Result<SecretKey, BlsError> {
    SecretKey::key_gen(ikm, key_info).map_err(|_| BlsError::KeyGeneration)
}

pub fn public_key(secret_key: &SecretKey) -> PublicKey {
    secret_key.sk_to_pk()
}

pub fn sign(secret_key: &SecretKey, message: &[u8], dst: &[u8], augmentation: &[u8]) -> Vec<u8> {
    secret_key
        .sign(message, dst, augmentation)
        .to_bytes()
        .to_vec()
}

pub fn verify(
    public_key: &PublicKey,
    signature: &[u8],
    message: &[u8],
    dst: &[u8],
    augmentation: &[u8],
) -> Result<(), BlsError> {
    let signature = Signature::from_bytes(signature).map_err(|_| BlsError::SignatureEncoding)?;
    if signature.verify(true, message, dst, augmentation, public_key, true)
        == BLST_ERROR::BLST_SUCCESS
    {
        Ok(())
    } else {
        Err(BlsError::Verification)
    }
}

pub fn aggregate(signatures: &[Vec<u8>]) -> Result<Vec<u8>, BlsError> {
    if signatures.is_empty() {
        return Err(BlsError::EmptyAggregate);
    }
    let signatures = signatures
        .iter()
        .map(|signature| Signature::from_bytes(signature))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| BlsError::SignatureEncoding)?;
    let references = signatures.iter().collect::<Vec<_>>();
    AggregateSignature::aggregate(&references, true)
        .map(|aggregate| aggregate.to_signature().to_bytes().to_vec())
        .map_err(|_| BlsError::Aggregation)
}

pub fn fast_aggregate_verify(
    public_keys: &[&PublicKey],
    aggregate_signature: &[u8],
    message: &[u8],
    dst: &[u8],
) -> Result<(), BlsError> {
    if public_keys.is_empty() {
        return Err(BlsError::EmptyAggregate);
    }
    let signature =
        Signature::from_bytes(aggregate_signature).map_err(|_| BlsError::SignatureEncoding)?;
    if signature.fast_aggregate_verify(true, message, dst, public_keys) == BLST_ERROR::BLST_SUCCESS
    {
        Ok(())
    } else {
        Err(BlsError::Verification)
    }
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum BlsError {
    #[error("BLS key generation failed")]
    KeyGeneration,
    #[error("invalid BLS signature encoding")]
    SignatureEncoding,
    #[error("BLS signature verification failed")]
    Verification,
    #[error("cannot aggregate an empty BLS signature set")]
    EmptyAggregate,
    #[error("BLS signature aggregation failed")]
    Aggregation,
}
