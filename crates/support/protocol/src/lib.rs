//! Shared wire encoding, storage, transport, and measurement.

#![forbid(unsafe_code)]

pub mod compute;
pub mod measurement;
pub mod store;
pub mod transport;
pub mod wire;

/// Derives an independent deterministic 32-byte seed from a run seed and a
/// length-delimited label. Protocols may further expand it with ChaCha20.
pub fn derive_seed(seed: u64, label: &[u8]) -> [u8; 32] {
    let mut hasher = crypto_primitives::hash::HashTranscript::new(b"Silk-bench-seed-v1");
    hasher.update(&seed.to_le_bytes());
    hasher.update(&(label.len() as u64).to_le_bytes());
    hasher.update(label);
    hasher.finalize()
}
