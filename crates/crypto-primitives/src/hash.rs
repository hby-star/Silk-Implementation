use sha2::{Digest, Sha256};

/// Incremental BLAKE3 transcript. Protocol crates own the domain and field
/// order; this type owns only the hash-engine mechanics.
#[derive(Clone)]
pub struct HashTranscript(blake3::Hasher);

impl HashTranscript {
    pub fn new(domain: &[u8]) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(domain);
        Self(hasher)
    }

    pub fn update(&mut self, bytes: &[u8]) -> &mut Self {
        self.0.update(bytes);
        self
    }

    pub fn finalize(&self) -> [u8; 32] {
        *self.0.finalize().as_bytes()
    }

    pub fn fill_xof(&self, output: &mut [u8]) {
        self.0.finalize_xof().fill(output);
    }
}

/// Hashes one already-framed byte string.
pub fn hash(bytes: &[u8]) -> [u8; 32] {
    *blake3::hash(bytes).as_bytes()
}

/// Computes a SHA-256 digest for manifests, artifacts, and build provenance.
pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// Hashes a domain followed by the supplied byte strings without extra framing.
pub fn hash_concat(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = HashTranscript::new(domain);
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize()
}

/// Hashes length-delimited byte strings under an explicit protocol domain.
pub fn hash_len_prefixed(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = HashTranscript::new(domain);
    for part in parts {
        hasher.update(&(part.len() as u64).to_le_bytes());
        hasher.update(part);
    }
    hasher.finalize()
}
