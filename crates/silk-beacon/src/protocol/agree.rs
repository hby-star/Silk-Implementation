//! Agree: proposal-carried approvals, local public transcripts, and a
//! transferable decision certificate.

use super::SilkProtocol;
use super::prepare::{SilkSharing, VerifiedDealerCertificate, VerifiedEpochValidation};
use crate::bft::{DecisionSignature, PreparedDecision, Proposal};
use crate::{
    BeaconError, BeaconNode, CertifiedEpoch, CertifiedTranscript, EpochCommand, EpochValidationData,
};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

pub const PROPOSAL_PROTOCOL: &str = "silk/beacon/epoch-command/v2";
pub const ECHO_PROTOCOL: &str = "silk/beacon/bft-echo/v1";
pub const READY_PROTOCOL: &str = "silk/beacon/bft-ready/v1";
pub const COMMIT_PROTOCOL: &str = "silk/beacon/bft-commit/v1";
pub const DECISION_SIGNATURE_PROTOCOL: &str = "silk/beacon/decision-signature/v1";

pub struct VerifiedEpochCommand {
    pub(super) context: [u8; 32],
    pub(super) command: EpochCommand,
    pub(super) witness: EpochValidationData,
}

impl VerifiedEpochCommand {
    pub fn command(&self) -> &EpochCommand {
        &self.command
    }
}

pub struct VerifiedProposal {
    pub(super) context: [u8; 32],
    pub(super) command: EpochCommand,
    pub(super) witness: EpochValidationData,
    pub(super) proposal: Proposal,
    decision: PreparedDecision,
}

impl VerifiedProposal {
    pub fn proposal(&self) -> &Proposal {
        &self.proposal
    }

    pub fn digest(&self) -> [u8; 32] {
        self.decision.digest
    }
}

pub struct VerifiedDecisionSignature {
    context: [u8; 32],
    proposal_digest: [u8; 32],
    sender: u32,
    signature: DecisionSignature,
}

pub struct VerifiedCertifiedEpoch {
    context: [u8; 32],
    certified: CertifiedEpoch,
}

impl SilkProtocol {
    pub fn assemble_epoch_preverified(
        &self,
        sharing: &SilkSharing,
        validation: VerifiedEpochValidation,
    ) -> Result<VerifiedEpochCommand, BeaconError> {
        self.require_sharing_context(sharing)?;
        if validation.context != self.verification_context() {
            return Err(BeaconError::InvalidValidation);
        }
        let (command, witness) = self.committee.assemble_epoch_candidate_preverified(
            validation
                .statements
                .iter()
                .map(|statement| statement.dealer)
                .collect::<BTreeSet<_>>()
                .into_iter()
                .filter_map(|dealer| sharing.transcripts.get(&dealer).cloned())
                .collect(),
            validation.statements,
        )?;
        Ok(VerifiedEpochCommand {
            context: self.verification_context(),
            command,
            witness,
        })
    }

    pub fn certified_transcript(
        &self,
        certificate: &VerifiedDealerCertificate,
    ) -> Result<CertifiedTranscript, BeaconError> {
        if certificate.context != self.verification_context()
            || certificate.dealer as usize >= self.params().n
        {
            return Err(BeaconError::InvalidValidation);
        }
        let first = certificate
            .statements
            .first()
            .ok_or(BeaconError::InvalidValidation)?;
        if certificate.statements.len() != self.params().qc_threshold()
            || certificate.statements.iter().any(|statement| {
                statement.dealer != certificate.dealer
                    || statement.transcript_id != first.transcript_id
            })
        {
            return Err(BeaconError::InvalidValidation);
        }
        Ok(CertifiedTranscript {
            dealer: certificate.dealer,
            transcript_id: first.transcript_id,
        })
    }

    pub fn accept_proposal(
        &self,
        sender: u32,
        command: EpochCommand,
        local_candidate: &VerifiedEpochCommand,
        sharing: &SilkSharing,
        materials: Vec<VerifiedDealerCertificate>,
    ) -> Result<VerifiedProposal, BeaconError> {
        self.accept_round_proposal(1, sender, command, local_candidate, sharing, materials)
    }

    pub fn accept_round_proposal(
        &self,
        round: u64,
        sender: u32,
        command: EpochCommand,
        local_candidate: &VerifiedEpochCommand,
        sharing: &SilkSharing,
        materials: Vec<VerifiedDealerCertificate>,
    ) -> Result<VerifiedProposal, BeaconError> {
        self.require_sharing_context(sharing)?;
        crate::verify_epoch_command(&self.committee.config, &command)?;
        if round == 0
            || sender as u64 != (round - 1) % self.params().n as u64
            || local_candidate.context != self.verification_context()
        {
            return Err(BeaconError::InvalidEpoch);
        }

        let (command, witness) = if command == local_candidate.command {
            if !materials.is_empty() {
                return Err(BeaconError::InvalidEpoch);
            }
            (command, local_candidate.witness.clone())
        } else {
            // Certificates in the proposal are sufficient evidence. Reuse a
            // cached check only for identical bytes in the same context; a
            // different valid signer subset must not depend on another broadcast.
            let certificates = command
                .transcripts
                .iter()
                .zip(&command.approvals)
                .map(|(entry, approvals)| {
                    let certificate = match materials.iter().find(|material| {
                        material.context == self.verification_context()
                            && material.dealer == entry.dealer
                            && material.statements == *approvals
                    }) {
                        Some(material) => material.clone(),
                        None => {
                            self.accept_validation_certificate(entry.dealer, approvals.clone())?
                        }
                    };
                    if self.certified_transcript(&certificate)? != *entry {
                        return Err(BeaconError::InvalidEpoch);
                    }
                    Ok(certificate)
                })
                .collect::<Result<Vec<_>, _>>()?;
            let validation = self.accept_validation_certificates_preverified(certificates)?;
            let resolved = self.assemble_epoch_preverified(sharing, validation)?;
            if resolved.command != command {
                return Err(BeaconError::InvalidEpoch);
            }
            (command, resolved.witness)
        };
        let proposal = self.committee.proposal_from_command(&command)?;
        let decision = PreparedDecision::new(self.committee.config.epoch, &proposal);
        Ok(VerifiedProposal {
            context: self.verification_context(),
            command,
            witness,
            proposal,
            decision,
        })
    }

    pub fn accept_acknowledgements(
        &self,
        digest: [u8; 32],
        messages: Vec<(u32, [u8; 32])>,
    ) -> Result<(), BeaconError> {
        let mut senders = BTreeSet::new();
        for (sender, received) in messages {
            if sender as usize >= self.params().n || received != digest || !senders.insert(sender) {
                return Err(BeaconError::InvalidEpoch);
            }
        }
        if senders.len() < self.params().qc_threshold() {
            return Err(BeaconError::InvalidEpoch);
        }
        Ok(())
    }

    pub fn decision_signature(
        &self,
        proposal: &VerifiedProposal,
    ) -> Result<DecisionSignature, BeaconError> {
        self.require_proposal_context(proposal)?;
        self.committee
            .sign_prepared_decision(self.node_id, &proposal.decision)
    }

    pub fn accept_decision_signature(
        &self,
        sender: u32,
        proposal: &VerifiedProposal,
        signature: DecisionSignature,
    ) -> Result<VerifiedDecisionSignature, BeaconError> {
        self.require_proposal_context(proposal)?;
        self.committee
            .verify_prepared_decision(sender, &proposal.decision, &signature)?;
        Ok(VerifiedDecisionSignature {
            context: self.verification_context(),
            proposal_digest: proposal.digest(),
            sender,
            signature,
        })
    }

    /// Single-height decision dissemination. With t+1 distinct verified
    /// signatures, at least one correct replica has already decided this value
    /// (or relayed support rooted in such a decision). It is safe to relay our
    /// signature. A final n-t certificate then supplies t+1 correct relays to
    /// every lagging replica, so terminating the Simple-IT service cannot
    /// strand it waiting for a later committed descendant.
    pub fn relay_decision_signature(
        &self,
        proposal: &VerifiedProposal,
        support: &[&VerifiedDecisionSignature],
    ) -> Result<DecisionSignature, BeaconError> {
        self.require_proposal_context(proposal)?;
        let mut senders = BTreeSet::new();
        for evidence in support {
            if evidence.context != self.verification_context()
                || evidence.proposal_digest != proposal.digest()
                || evidence.sender as usize >= self.params().n
                || !senders.insert(evidence.sender)
            {
                return Err(BeaconError::InvalidEpoch);
            }
        }
        if senders.len() <= self.params().t {
            return Err(BeaconError::InvalidEpoch);
        }
        self.decision_signature(proposal)
    }

    pub fn certify_epoch_preverified(
        &self,
        proposal: VerifiedProposal,
        messages: Vec<VerifiedDecisionSignature>,
    ) -> Result<VerifiedCertifiedEpoch, BeaconError> {
        if proposal.context != self.verification_context() {
            return Err(BeaconError::InvalidEpoch);
        }
        let digest = proposal.digest();
        let mut signatures = BTreeMap::new();
        for message in messages {
            if message.context != self.verification_context()
                || message.proposal_digest != digest
                || message.sender as usize >= self.params().n
                || message.signature.signer != message.sender
                || signatures
                    .insert(message.sender, message.signature)
                    .is_some()
            {
                return Err(BeaconError::InvalidEpoch);
            }
        }
        if signatures.len() < self.params().qc_threshold() {
            return Err(BeaconError::InvalidEpoch);
        }
        let certified = self.committee.certify_epoch_preverified(
            proposal.command,
            proposal.witness,
            signatures
                .into_values()
                .take(self.params().qc_threshold())
                .collect(),
        )?;
        Ok(VerifiedCertifiedEpoch {
            context: self.verification_context(),
            certified,
        })
    }

    pub fn build_node_preverified(
        &self,
        certified_epoch: VerifiedCertifiedEpoch,
        sharing: &SilkSharing,
        store_path: impl AsRef<Path>,
    ) -> Result<BeaconNode, BeaconError> {
        self.require_sharing_context(sharing)?;
        if certified_epoch.context != self.verification_context() {
            return Err(BeaconError::InvalidEpoch);
        }
        let rows = sharing
            .rows
            .iter()
            .filter(|(dealer, _)| {
                certified_epoch
                    .certified
                    .epoch_certificate
                    .command
                    .transcripts
                    .iter()
                    .any(|entry| entry.dealer == **dealer)
            })
            .map(|(dealer, row)| (*dealer, row.clone()))
            .collect();
        self.committee.build_node_preverified(
            self.node_id,
            certified_epoch.certified,
            rows,
            store_path,
        )
    }

    fn require_proposal_context(&self, proposal: &VerifiedProposal) -> Result<(), BeaconError> {
        if proposal.context != self.verification_context()
            || proposal.decision.epoch != self.committee.config.epoch
            || proposal.decision.instance != proposal.proposal.instance
        {
            return Err(BeaconError::InvalidEpoch);
        }
        Ok(())
    }
}
