//! Rondo-BFT agreement, wire types, and deterministic bindings for the distributed Rondo beacon.
//!
//! Node execution and transport are implemented in `beacon-node`.

#![forbid(unsafe_code)]

pub mod bft;
mod hashing;
pub mod protocol;
mod types;

pub use hashing::{output_hash, subset_digest};
pub use types::{
    AggregateShare, CommonSubsetEntry, DealerFallbackShare, FallbackShare, FirstRoundPayload,
};

pub const BREEZE_FIDELITY: &str = "F2";
pub const BREEZE_PROFILE: &str = rondo_bavss_po::IMPLEMENTATION_PROFILE;
pub const RECONSTRUCTION_FIDELITY: &str =
    "compact-aggregate-certified-holder-quorum-verified-per-dealer-row-fallback-v5";
pub const BFT_PATH_FIDELITY: &str = bft::PATH_FIDELITY;
pub const BFT_SIGNATURE_PROFILE: &str = bft::SIGNATURE_PROFILE;
pub const IMPLEMENTATION_PROFILE: &str = "rondo-beacon";
