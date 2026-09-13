//! Content-addressed encoding of the full certified proposal.
//!
//! A reference is never validation evidence. Expansion requires the exact
//! certificate bytes, then the ordinary proposal validator checks signatures,
//! context and public objects before the BFT validation callback succeeds.
use crate::{BeaconError, CertifiedTranscript, EpochCommand, ValidationStatement};
use crypto_primitives::hash::hash_len_prefixed;
use protocol_support::wire::canonical_serialize;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub type CertificateId = [u8; 32];

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncodedEpochProposal {
    pub epoch: u64,
    pub entries: Vec<(CertifiedTranscript, CertificateId)>,
}

pub fn certificate_id(
    epoch: u64,
    entry: &CertifiedTranscript,
    approvals: &[ValidationStatement],
) -> Result<CertificateId, BeaconError> {
    Ok(hash_len_prefixed(
        b"silk/certified-proposal/certificate/v1",
        &[&canonical_serialize(&(epoch, entry, approvals))?],
    ))
}

impl EncodedEpochProposal {
    pub fn encode(command: &EpochCommand) -> Result<Self, BeaconError> {
        if command.transcripts.len() != command.approvals.len() {
            return Err(BeaconError::InvalidEpoch);
        }
        Ok(Self {
            epoch: command.epoch,
            entries: command
                .transcripts
                .iter()
                .zip(&command.approvals)
                .map(|(entry, approvals)| {
                    Ok((*entry, certificate_id(command.epoch, entry, approvals)?))
                })
                .collect::<Result<_, BeaconError>>()?,
        })
    }

    pub fn check_shape(&self, epoch: u64, n: usize, selected: usize) -> bool {
        self.epoch == epoch
            && self.entries.len() == selected
            && self
                .entries
                .iter()
                .all(|(entry, _)| (entry.dealer as usize) < n)
            && self
                .entries
                .windows(2)
                .all(|pair| pair[0].0.dealer < pair[1].0.dealer)
    }

    pub fn expand(
        &self,
        certificates: &BTreeMap<CertificateId, Vec<ValidationStatement>>,
    ) -> Result<Option<EpochCommand>, BeaconError> {
        let mut approvals = Vec::with_capacity(self.entries.len());
        for (entry, id) in &self.entries {
            let Some(statements) = certificates.get(id) else {
                return Ok(None);
            };
            if certificate_id(self.epoch, entry, statements)? != *id {
                return Err(BeaconError::InvalidValidation);
            }
            approvals.push(statements.clone());
        }
        Ok(Some(EpochCommand {
            epoch: self.epoch,
            transcripts: self.entries.iter().map(|(entry, _)| *entry).collect(),
            approvals,
        }))
    }
}
