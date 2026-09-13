//! Rondo Breeze bAVSS-PO normal-primitive research implementation (F2).
//!
//! `BatchCommit`, `BatchEval` and `BatchVerifyEval` cover every polynomial in a
//! receiver row using an evaluation-bound Fiat--Shamir linear combination and
//! a logarithmic IPA. The commitment and evaluation vectors are Merkle-bound,
//! validation data carries an independent-key BLS aggregate signature, and
//! reconstruction checks the recovered polynomial against the selected
//! coefficient-vector commitments.

#![forbid(unsafe_code)]

mod error;
pub mod primitives;
pub mod protocol;

pub use error::BreezeError;
pub use protocol::types::ProtocolParams;

pub const IMPLEMENTATION_PROFILE: &str = "breeze-bavss";
pub const RECONSTRUCTION_PROFILE: &str = "compact-single-dealer-set";
