//! Validation data for the bAVSS-PO partial-output interface.
//!
//! This module owns the signed holder statements and their compact
//! per-dealer projections. Beacon composition may carry these objects, but
//! their construction and verification do not depend on BFT or Quorum
//! Release.

use crate::{DealerPublicTranscript, ProtocolContext, ProtocolParams, SilkError};
use crypto_primitives::hash::hash_len_prefixed;
use crypto_primitives::mldsa::{SigningKey65, VerifyingKey65, sign, verify, verify_with_key};
use protocol_support::wire::canonical_serialize;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ValidationStatement {
    pub signer: u32,
    pub sequence: u64,
    pub dealer: u32,
    pub transcript_id: [u8; 32],
    pub root: [u8; 32],
    pub signature: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DealerValidationCertificate {
    pub dealer: u32,
    pub transcript_id: [u8; 32],
    pub references: Vec<u32>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EpochValidationData {
    pub transcripts: Vec<DealerPublicTranscript>,
    pub statements: Vec<ValidationStatement>,
    pub dealer_certificates: Vec<DealerValidationCertificate>,
}

pub fn sign_validation_statement(
    sid: &[u8],
    context: ProtocolContext,
    signer: u32,
    sequence: u64,
    dealer: u32,
    transcript_id: [u8; 32],
    key: &SigningKey65,
) -> Result<ValidationStatement, SilkError> {
    let root = validation_statement_digest(dealer, transcript_id);
    Ok(ValidationStatement {
        signer,
        sequence,
        dealer,
        transcript_id,
        root,
        signature: sign(
            key,
            &validation_message(sid, context, signer, sequence, root),
        ),
    })
}

pub fn verify_validation_statement(
    params: ProtocolParams,
    sid: &[u8],
    context: ProtocolContext,
    public_keys: &[Vec<u8>],
    statement: &ValidationStatement,
) -> Result<(), SilkError> {
    validate_statement_shape(params, public_keys.len(), statement)?;
    verify(
        &public_keys[statement.signer as usize],
        &statement.signature,
        &validation_message(
            sid,
            context,
            statement.signer,
            statement.sequence,
            statement.root,
        ),
    )
    .map_err(|_| SilkError::CertificateMismatch)
}

/// Verifies a validation statement with committee keys parsed at
/// configuration load time. ML-DSA public-key decoding expands the public
/// matrix, so repeating it for every statement is avoidable protocol-engine
/// overhead rather than signature verification work.
pub fn verify_validation_statement_preparsed(
    params: ProtocolParams,
    sid: &[u8],
    context: ProtocolContext,
    public_keys: &[VerifyingKey65],
    statement: &ValidationStatement,
) -> Result<(), SilkError> {
    validate_statement_shape(params, public_keys.len(), statement)?;
    verify_with_key(
        &public_keys[statement.signer as usize],
        &statement.signature,
        &validation_message(
            sid,
            context,
            statement.signer,
            statement.sequence,
            statement.root,
        ),
    )
    .map_err(|_| SilkError::CertificateMismatch)
}

fn validate_statement_shape(
    params: ProtocolParams,
    public_key_count: usize,
    statement: &ValidationStatement,
) -> Result<(), SilkError> {
    if public_key_count != params.n
        || statement.signer as usize >= params.n
        || statement.dealer as usize >= params.n
        || validation_statement_digest(statement.dealer, statement.transcript_id) != statement.root
    {
        return Err(SilkError::CertificateMismatch);
    }
    Ok(())
}

pub fn build_dealer_certificate(
    params: ProtocolParams,
    dealer: u32,
    transcript_id: [u8; 32],
    statements: &[ValidationStatement],
) -> Result<DealerValidationCertificate, SilkError> {
    if dealer as usize >= params.n {
        return Err(SilkError::InvalidDealer);
    }
    let references = statements
        .iter()
        .enumerate()
        .filter_map(|(statement, signed)| {
            (signed.dealer == dealer && signed.transcript_id == transcript_id)
                .then_some(statement as u32)
        })
        .take(params.qc_threshold())
        .collect::<Vec<_>>();
    if references.len() != params.qc_threshold() {
        return Err(SilkError::InsufficientCertificates {
            have: references.len(),
            need: params.qc_threshold(),
        });
    }
    Ok(DealerValidationCertificate {
        dealer,
        transcript_id,
        references,
    })
}

pub fn verify_dealer_certificate(
    params: ProtocolParams,
    certificate: &DealerValidationCertificate,
    statements: &[ValidationStatement],
) -> Result<BTreeSet<u32>, SilkError> {
    let mut holders = BTreeSet::new();
    for reference in &certificate.references {
        let statement = statements
            .get(*reference as usize)
            .ok_or(SilkError::CertificateMismatch)?;
        if statement.dealer != certificate.dealer
            || statement.transcript_id != certificate.transcript_id
            || !holders.insert(statement.signer)
        {
            return Err(SilkError::CertificateMismatch);
        }
    }
    if certificate.dealer as usize >= params.n
        || holders.iter().any(|id| *id as usize >= params.n)
        || holders.len() != params.qc_threshold()
    {
        return Err(SilkError::InsufficientCertificates {
            have: holders.len(),
            need: params.qc_threshold(),
        });
    }
    Ok(holders)
}

fn validation_statement_digest(dealer: u32, transcript_id: [u8; 32]) -> [u8; 32] {
    hash_len_prefixed(
        b"silk/validation-statement/v2",
        &[
            &canonical_serialize(&(dealer, transcript_id))
                .expect("validation statement serializes"),
        ],
    )
}

fn validation_message(
    sid: &[u8],
    context: ProtocolContext,
    signer: u32,
    sequence: u64,
    root: [u8; 32],
) -> Vec<u8> {
    canonical_serialize(&(
        "silk/validation-root/v1",
        sid,
        context.config_digest,
        context.epoch,
        signer,
        sequence,
        root,
    ))
    .expect("validation statement serializes")
}
