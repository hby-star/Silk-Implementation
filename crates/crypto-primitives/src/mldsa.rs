use ml_dsa::{
    EncodedVerifyingKey, Keypair, MlDsa65, Seed, Signature, SignatureEncoding, Signer, SigningKey,
    Verifier, VerifyingKey,
};
use thiserror::Error;

/// Native keys retain only encoded key material, avoiding unused RustCrypto
/// matrix expansion on the accelerated path. Both paths implement FIPS 204.
#[derive(Clone)]
pub struct SigningKey65(SigningBackend);

#[derive(Clone)]
enum SigningBackend {
    Native(mldsa_native65::SigningKey),
    Portable(Box<SigningKey<MlDsa65>>),
}

impl std::fmt::Debug for SigningKey65 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SigningKey65").finish_non_exhaustive()
    }
}

#[derive(Clone, Debug)]
pub struct VerifyingKey65(VerifyingBackend);

#[derive(Clone, Debug)]
enum VerifyingBackend {
    Native(mldsa_native65::VerifyingKey),
    Portable(Box<VerifyingKey<MlDsa65>>),
}

pub fn backend_name() -> &'static str {
    if mldsa_native65::is_available() {
        "mldsa-native-2.0.0-avx2"
    } else {
        "rustcrypto-0.1.1"
    }
}

pub fn key_from_seed(seed: [u8; 32]) -> Result<SigningKey65, MlDsaError> {
    if mldsa_native65::is_available() {
        return mldsa_native65::SigningKey::from_seed(&seed)
            .map(|key| SigningKey65(SigningBackend::Native(key)))
            .map_err(|_| MlDsaError::Backend);
    }
    let seed = Seed::try_from(seed.as_slice()).map_err(|_| MlDsaError::Seed)?;
    Ok(SigningKey65(SigningBackend::Portable(Box::new(
        SigningKey::<MlDsa65>::from_seed(&seed),
    ))))
}

pub fn public_key_bytes(key: &SigningKey65) -> Vec<u8> {
    match &key.0 {
        SigningBackend::Native(key) => key.public_key().as_bytes().to_vec(),
        SigningBackend::Portable(key) => key.verifying_key().encode().as_slice().to_vec(),
    }
}

pub fn sign(key: &SigningKey65, message: &[u8]) -> Vec<u8> {
    match &key.0 {
        // Deterministic FIPS 204 mode, empty context. Protocol domain
        // separation stays in M. Never return a partial signature on error.
        SigningBackend::Native(key) => key.sign(message).expect("ML-DSA signing failed"),
        SigningBackend::Portable(key) => key.sign(message).to_bytes().as_slice().to_vec(),
    }
}

pub fn verifying_key_from_bytes(public_key: &[u8]) -> Result<VerifyingKey65, MlDsaError> {
    if public_key.len() != mldsa_native65::PUBLIC_KEY_BYTES {
        return Err(MlDsaError::PublicKey);
    }
    if mldsa_native65::is_available() {
        return mldsa_native65::VerifyingKey::from_bytes(public_key)
            .map(|key| VerifyingKey65(VerifyingBackend::Native(key)))
            .map_err(|_| MlDsaError::PublicKey);
    }
    let encoded =
        EncodedVerifyingKey::<MlDsa65>::try_from(public_key).map_err(|_| MlDsaError::PublicKey)?;
    Ok(VerifyingKey65(VerifyingBackend::Portable(Box::new(
        VerifyingKey::<MlDsa65>::decode(&encoded),
    ))))
}

pub fn verify_with_key(
    key: &VerifyingKey65,
    signature: &[u8],
    message: &[u8],
) -> Result<(), MlDsaError> {
    if signature.len() != mldsa_native65::SIGNATURE_BYTES {
        return Err(MlDsaError::Signature);
    }
    match &key.0 {
        VerifyingBackend::Native(key) => key
            .verify(signature, message, b"")
            .map_err(|_| MlDsaError::Verification),
        VerifyingBackend::Portable(key) => {
            let signature =
                Signature::<MlDsa65>::try_from(signature).map_err(|_| MlDsaError::Signature)?;
            key.verify(message, &signature)
                .map_err(|_| MlDsaError::Verification)
        }
    }
}

pub fn verify(public_key: &[u8], signature: &[u8], message: &[u8]) -> Result<(), MlDsaError> {
    let key = verifying_key_from_bytes(public_key)?;
    verify_with_key(&key, signature, message)
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum MlDsaError {
    #[error("invalid ML-DSA seed")]
    Seed,
    #[error("invalid ML-DSA public key")]
    PublicKey,
    #[error("invalid ML-DSA signature")]
    Signature,
    #[error("ML-DSA verification failed")]
    Verification,
    #[error("ML-DSA backend failed")]
    Backend,
}
