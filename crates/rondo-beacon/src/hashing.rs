use crypto_primitives::hash::{HashTranscript, hash};
use curve25519_dalek::scalar::Scalar;
use protocol_support::wire::canonical_serialize;

/// Bind the epoch and ordered validation transcripts to Rondo's common subset.
pub fn subset_digest(epoch: u64, transcripts: &[[u8; 32]]) -> [u8; 32] {
    let mut hasher = HashTranscript::new(b"Rondo-common-subset-v1");
    hasher.update(&epoch.to_le_bytes());
    for transcript in transcripts {
        hasher.update(transcript);
    }
    hasher.finalize()
}

/// Bind a reconstructed secret to the committed Rondo beacon position.
pub fn output_hash(
    epoch: u64,
    round: u64,
    height: u64,
    slot: u32,
    subset: [u8; 32],
    secret: Scalar,
) -> [u8; 32] {
    hash(
        &canonical_serialize(&(
            "Rondo-beacon-output-v1",
            epoch,
            round,
            height,
            slot,
            subset,
            secret,
        ))
        .expect("output serialization"),
    )
}
