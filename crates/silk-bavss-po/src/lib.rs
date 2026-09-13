//! Hash-based Silk bAVSS-PO.

#![forbid(unsafe_code)]

mod canonical;
mod error;
mod params;
mod validation;

pub use canonical::{
    CompactPointVerifier, CompactReconstructionItem, CompactReconstructionPlan, Dealer,
    DealerPublicTranscript, LeafDigestMatrix, PROTOCOL_REVISION, PrivateRow, PrivateSlot,
    ProtocolContext, RESPONSE_REPETITIONS, ResponsePolynomialSet, WIRE_PROFILE,
    compact_item_from_row, par_verify, point_verify_compact_batch_fast,
    point_verify_compact_prevalidated, reconstruct_secret, validate_params,
    verify_public_transcript,
};

pub const IMPLEMENTATION_PROFILE: &str = "silk-bavss";
pub const VALIDATION_PROFILE: &str = "per-dealer-validation-statement-v2";
pub use error::SilkError;
pub use params::ProtocolParams;
pub use validation::{
    DealerValidationCertificate, EpochValidationData, ValidationStatement,
    build_dealer_certificate, sign_validation_statement, verify_dealer_certificate,
    verify_validation_statement, verify_validation_statement_preparsed,
};
