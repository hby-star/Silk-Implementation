//! Mulberry bAVSS-PO.

mod reconstruction;
mod sharing;
mod transcript;
mod types;
mod verification;

pub const WIRE_PROFILE: &str = "dense-response-digest-compact-item-v2";
pub const PROTOCOL_REVISION: &str = "silk";
pub const RESPONSE_REPETITIONS: usize = 1;

pub use reconstruction::{
    CompactPointVerifier, CompactReconstructionPlan, compact_item_from_row,
    point_verify_compact_batch_fast, point_verify_compact_prevalidated, reconstruct_secret,
};
pub use sharing::Dealer;
pub use types::{
    CompactReconstructionItem, DealerPublicTranscript, LeafDigestMatrix, PrivateRow, PrivateSlot,
    ProtocolContext, ResponsePolynomialSet,
};
pub use verification::{par_verify, validate_params, verify_public_transcript};
