//! Rondo-BFT fixed-committee normal path used by the beacon composition.
//!
//! View change, leader replacement, dynamic membership, forwarding and state
//! transfer are outside the measured profile.

mod error;
pub mod normal;
mod types;

pub use error::BftError;
pub use types::{BftParams, Request};

pub const PATH_FIDELITY: &str = "F2";
/// Every replica owns an independent BLS key. QCs aggregate ordinary
/// signatures on one message and carry the canonical signer identities; no
/// shared public key, DKG, threshold shares, or threshold combine is used.
pub const SIGNATURE_PROFILE: &str =
    "independent-bls-fast-aggregate-signature-with-signer-identities-v1";
