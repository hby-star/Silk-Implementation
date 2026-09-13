use serde::{Serialize, de::DeserializeOwned};
use thiserror::Error;

/// Canonical wire-format failures.
#[derive(Debug, Error)]
pub enum WireError {
    #[error("canonical serialization failed: {0}")]
    Serialize(#[source] postcard::Error),
    #[error("canonical deserialization failed: {0}")]
    Deserialize(#[source] postcard::Error),
    #[error("wire payload is not in canonical form")]
    NonCanonical,
}

/// Serializes a value using Postcard's deterministic, schema-driven encoding.
/// The returned buffer is the exact payload used by transports and byte
/// counters; no `size_of` or modelled size is involved.
pub fn canonical_serialize<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>, WireError> {
    postcard::to_allocvec(value).map_err(WireError::Serialize)
}

/// Decodes a value encoded by [`canonical_serialize`], rejecting alternate
/// byte strings that Postcard may otherwise accept for the same value.
pub fn canonical_deserialize<T: DeserializeOwned + Serialize>(
    bytes: &[u8],
) -> Result<T, WireError> {
    let value: T = postcard::from_bytes(bytes).map_err(WireError::Deserialize)?;
    let canonical = canonical_serialize(&value)?;
    if canonical != bytes {
        return Err(WireError::NonCanonical);
    }
    Ok(value)
}

/// Decodes one exactly framed value without an encode-roundtrip.
///
/// This is reserved for transport envelopes whose payload remains opaque at
/// this layer. Cryptographic protocol values must continue to use
/// [`canonical_deserialize`].
pub fn framing_deserialize<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, WireError> {
    let (value, remaining) = postcard::take_from_bytes(bytes).map_err(WireError::Deserialize)?;
    if !remaining.is_empty() {
        return Err(WireError::NonCanonical);
    }
    Ok(value)
}

/// Returns the exact canonical serialized payload length.
pub fn wire_len<T: Serialize + ?Sized>(value: &T) -> Result<u64, WireError> {
    Ok(canonical_serialize(value)?.len() as u64)
}
