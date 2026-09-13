//! Prepare: Mulberry sharing, validation statements, and dealer certificates.

use super::SilkProtocol;
use crate::{BeaconError, ValidationStatement};
pub use silk_bavss_po::{DealerPublicTranscript, PrivateRow};
use std::collections::BTreeMap;

pub const PUBLIC_PROTOCOL: &str = "silk/beacon/public-transcript/v1";
pub const ROW_PROTOCOL: &str = "silk/beacon/private-row/v1";
pub const VALIDATION_PROTOCOL: &str = "silk/beacon/validation-statement/v2";
pub const CERTIFIED_DEALER_PROTOCOL: &str = "silk/beacon/certified-dealer/v1";

pub struct SilkSharing {
    pub(super) context: [u8; 32],
    pub(super) replica: u32,
    pub(super) transcripts: BTreeMap<u32, DealerPublicTranscript>,
    pub(super) rows: BTreeMap<u32, PrivateRow>,
}

impl SilkSharing {
    /// Immutable proposal input without copying or authorizing private rows.
    pub fn public_snapshot(&self, dealers: &[u32]) -> Self {
        Self {
            context: self.context,
            replica: self.replica,
            transcripts: dealers
                .iter()
                .filter_map(|dealer| {
                    self.transcripts
                        .get(dealer)
                        .cloned()
                        .map(|public| (*dealer, public))
                })
                .collect(),
            rows: BTreeMap::new(),
        }
    }
}

pub struct VerifiedValidationStatement {
    pub(super) context: [u8; 32],
    pub(super) dealer: u32,
    pub(super) sender: u32,
    pub(super) statement: ValidationStatement,
}

#[derive(Clone)]
pub struct VerifiedDealerCertificate {
    pub(super) context: [u8; 32],
    pub(super) dealer: u32,
    pub(super) statements: Vec<ValidationStatement>,
}

impl VerifiedDealerCertificate {
    pub fn statements(&self) -> &[ValidationStatement] {
        &self.statements
    }
}

pub struct VerifiedEpochValidation {
    pub(super) context: [u8; 32],
    pub(super) statements: Vec<ValidationStatement>,
}

impl SilkProtocol {
    pub fn begin_sharing(&self) -> SilkSharing {
        SilkSharing {
            context: self.verification_context(),
            replica: self.node_id,
            transcripts: BTreeMap::new(),
            rows: BTreeMap::new(),
        }
    }

    /// Merge replica-local state that has already passed this protocol's
    /// verification API. Fields are private, so unverified rows cannot be
    /// manufactured by the transport adapter.
    pub fn merge_verified_sharing(
        &self,
        target: &mut SilkSharing,
        verified: SilkSharing,
    ) -> Result<(), BeaconError> {
        self.require_sharing_context(target)?;
        self.require_sharing_context(&verified)?;
        for (dealer, public) in &verified.transcripts {
            if target
                .transcripts
                .get(dealer)
                .is_some_and(|old| old != public)
                || target.rows.contains_key(dealer)
                || !verified.rows.contains_key(dealer)
            {
                return Err(BeaconError::InvalidValidation);
            }
        }
        target.transcripts.extend(verified.transcripts);
        target.rows.extend(verified.rows);
        Ok(())
    }

    /// Verify and retain one dealer's row as soon as its two objects arrive.
    /// The verified state is replica-local and cannot authorize another
    /// replica's approval or accept a second sharing for the same dealer.
    pub fn accept_dealer_sharing(
        &self,
        sharing: &mut SilkSharing,
        sender: u32,
        public: DealerPublicTranscript,
        row: PrivateRow,
    ) -> Result<(), BeaconError> {
        self.require_sharing_context(sharing)?;
        if sender as usize >= self.params().n
            || public.dealer != sender
            || row.dealer != sender
            || row.receiver != self.node_id
            || sharing
                .transcripts
                .get(&sender)
                .is_some_and(|cached| cached != &public)
            || sharing.rows.contains_key(&sender)
        {
            return Err(BeaconError::InvalidValidation);
        }
        self.committee.verify_row(&row, &public)?;
        sharing.transcripts.insert(sender, public);
        sharing.rows.insert(sender, row);
        Ok(())
    }

    pub fn accept_public_material(
        &self,
        sharing: &mut SilkSharing,
        sender: u32,
        public: DealerPublicTranscript,
    ) -> Result<(), BeaconError> {
        self.require_sharing_context(sharing)?;
        if sender as usize >= self.params().n
            || public.dealer != sender
            || public.sid != self.committee.config.sid
            || public.context != self.committee.config.context
        {
            return Err(BeaconError::InvalidValidation);
        }
        if let Some(cached) = sharing.transcripts.get(&sender) {
            return if cached == &public {
                Ok(())
            } else {
                Err(BeaconError::InvalidValidation)
            };
        }
        silk_bavss_po::verify_public_transcript(self.params(), &public)?;
        sharing.transcripts.insert(sender, public);
        Ok(())
    }

    pub fn has_public_materials(&self, sharing: &SilkSharing, dealers: &[u32]) -> bool {
        self.require_sharing_context(sharing).is_ok()
            && dealers
                .iter()
                .all(|dealer| sharing.transcripts.contains_key(dealer))
    }

    pub fn verified_sharing_count(&self, sharing: &SilkSharing) -> Result<usize, BeaconError> {
        self.require_sharing_context(sharing)?;
        Ok(sharing.rows.len())
    }

    pub fn validation_statement(
        &self,
        sharing: &SilkSharing,
        dealer: u32,
    ) -> Result<ValidationStatement, BeaconError> {
        self.require_sharing_context(sharing)?;
        if !sharing.rows.contains_key(&dealer) {
            return Err(BeaconError::InvalidValidation);
        }
        let transcript = sharing
            .transcripts
            .get(&dealer)
            .ok_or(BeaconError::InvalidValidation)?;
        let digest = transcript.transcript_id();
        let mut approved = self
            .approved_transcripts
            .lock()
            .map_err(|_| BeaconError::InvalidState)?;
        if approved
            .get(&dealer)
            .is_some_and(|previous| *previous != digest)
        {
            return Err(BeaconError::InvalidValidation);
        }
        approved.insert(dealer, digest);
        drop(approved);
        self.committee
            .sign_validation_statement(self.node_id, u64::from(dealer), dealer, digest)
    }

    pub fn dealer_share(&self) -> Result<(DealerPublicTranscript, Vec<PrivateRow>), BeaconError> {
        protocol_support::compute::run(|| self.committee.dealer_share(self.node_id))
    }

    pub fn accept_sharing(
        &self,
        public_messages: Vec<(u32, DealerPublicTranscript)>,
        row_messages: Vec<(u32, PrivateRow)>,
    ) -> Result<SilkSharing, BeaconError> {
        let mut transcripts = BTreeMap::new();
        for (sender, transcript) in public_messages {
            if transcript.dealer != sender
                || sender as usize >= self.params().n
                || transcript.sid != self.committee.config.sid
                || transcript.context != self.committee.config.context
                || transcripts.contains_key(&sender)
            {
                return Err(BeaconError::InvalidValidation);
            }
            transcripts.insert(sender, transcript);
        }

        let mut rows = BTreeMap::new();
        for (sender, row) in row_messages {
            let public = transcripts
                .get(&sender)
                .ok_or(BeaconError::InvalidValidation)?;
            if row.dealer != sender || row.receiver != self.node_id || rows.contains_key(&sender) {
                return Err(BeaconError::InvalidValidation);
            }
            self.committee.verify_row(&row, public)?;
            rows.insert(sender, row);
        }
        if transcripts.len() != self.params().n || rows.len() != self.params().n {
            return Err(BeaconError::InvalidValidation);
        }
        Ok(SilkSharing {
            context: self.verification_context(),
            replica: self.node_id,
            transcripts,
            rows,
        })
    }

    pub fn validation_statements(
        &self,
        sharing: &SilkSharing,
    ) -> Result<Vec<ValidationStatement>, BeaconError> {
        self.require_sharing_context(sharing)?;
        let mut approved = self
            .approved_transcripts
            .lock()
            .map_err(|_| BeaconError::InvalidState)?;
        for transcript in sharing.transcripts.values() {
            if !sharing.rows.contains_key(&transcript.dealer) {
                return Err(BeaconError::InvalidValidation);
            }
            if approved
                .get(&transcript.dealer)
                .is_some_and(|digest| *digest != transcript.transcript_id())
            {
                return Err(BeaconError::InvalidValidation);
            }
        }
        for transcript in sharing.transcripts.values() {
            approved.insert(transcript.dealer, transcript.transcript_id());
        }
        sharing
            .transcripts
            .values()
            .map(|transcript| {
                self.committee.sign_validation_statement(
                    self.node_id,
                    u64::from(transcript.dealer),
                    transcript.dealer,
                    transcript.transcript_id(),
                )
            })
            .collect()
    }

    pub fn accept_validation_statement(
        &self,
        dealer: u32,
        sender: u32,
        statement: ValidationStatement,
    ) -> Result<VerifiedValidationStatement, BeaconError> {
        protocol_support::compute::run(|| {
            self.verify_validation_statement(dealer, sender, &statement)?;
            Ok(VerifiedValidationStatement {
                context: self.verification_context(),
                dealer,
                sender,
                statement,
            })
        })
    }

    pub fn accept_validation_statements_preverified(
        &self,
        dealer: u32,
        statements: Vec<VerifiedValidationStatement>,
    ) -> Result<Vec<ValidationStatement>, BeaconError> {
        let mut accepted = BTreeMap::new();
        for statement in statements {
            if statement.context != self.verification_context()
                || statement.dealer != dealer
                || statement.sender as usize >= self.params().n
                || statement.statement.signer != statement.sender
                || accepted
                    .insert(statement.sender, statement.statement)
                    .is_some()
            {
                return Err(BeaconError::InvalidValidation);
            }
        }
        self.require_validation_quorum(accepted)
    }

    pub fn accept_validation_certificate(
        &self,
        dealer: u32,
        statements: Vec<ValidationStatement>,
    ) -> Result<VerifiedDealerCertificate, BeaconError> {
        protocol_support::compute::run(|| {
            if statements.len() != self.params().qc_threshold() {
                return Err(BeaconError::InvalidValidation);
            }
            let mut verified = BTreeMap::new();
            for statement in statements {
                let sender = statement.signer;
                if verified.contains_key(&sender) {
                    return Err(BeaconError::InvalidValidation);
                }
                verified.insert(sender, statement);
            }
            let ordered = verified.values().collect::<Vec<_>>();
            for result in protocol_support::compute::map(ordered.len(), |index| {
                let statement = ordered[index];
                self.verify_validation_statement(dealer, statement.signer, statement)
            }) {
                result?;
            }
            let statements = self.require_validation_quorum(verified)?;
            Ok(VerifiedDealerCertificate {
                context: self.verification_context(),
                dealer,
                statements,
            })
        })
    }

    pub fn accept_validation_certificates_preverified(
        &self,
        messages: Vec<VerifiedDealerCertificate>,
    ) -> Result<VerifiedEpochValidation, BeaconError> {
        let mut certificates = BTreeMap::new();
        for certificate in messages {
            if certificate.context != self.verification_context()
                || certificate.dealer as usize >= self.params().n
                || certificate.statements.len() != self.params().qc_threshold()
                || certificates
                    .insert(certificate.dealer, certificate.statements)
                    .is_some()
            {
                return Err(BeaconError::InvalidValidation);
            }
        }
        if certificates.len() < self.params().d {
            return Err(BeaconError::InvalidValidation);
        }
        Ok(VerifiedEpochValidation {
            context: self.verification_context(),
            statements: certificates
                .into_values()
                .take(self.params().d)
                .flatten()
                .collect(),
        })
    }

    fn verify_validation_statement(
        &self,
        dealer: u32,
        sender: u32,
        statement: &ValidationStatement,
    ) -> Result<(), BeaconError> {
        if statement.signer != sender
            || sender as usize >= self.params().n
            || statement.dealer != dealer
        {
            return Err(BeaconError::InvalidValidation);
        }
        self.committee.verify_validation_statement(statement)
    }

    fn require_validation_quorum(
        &self,
        statements: BTreeMap<u32, ValidationStatement>,
    ) -> Result<Vec<ValidationStatement>, BeaconError> {
        if statements.len() < self.params().qc_threshold() {
            return Err(BeaconError::InvalidValidation);
        }
        Ok(statements
            .into_values()
            .take(self.params().qc_threshold())
            .collect())
    }
}
