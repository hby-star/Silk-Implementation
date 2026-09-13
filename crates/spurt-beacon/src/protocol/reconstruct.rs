//! Spurt reconstruction and signed BEACON relay.

use std::path::Path;

use blstrs::{G1Affine, G1Projective, G2Affine, Scalar, pairing};
use ed25519_dalek::Signer;
use ff::Field;
use protocol_support::store::ProtocolStore;

use super::transcript::{beacon_payload, output_digest, reconstruction_payload};
use super::*;
use crate::agreement::AgreementDecision;
use crate::types::{AggregateTranscript, BeaconValue};

impl SpurtProtocol {
    pub fn reconstruction_share(
        &self,
        aggregate: &AggregateTranscript,
        decision: &AgreementDecision,
    ) -> Result<ReconstructionShare, SpurtError> {
        protocol_support::compute::run(|| {
            self.verify_decision_context(aggregate, decision)?;
            let inverse = Option::<Scalar>::from(self.secret_key.invert())
                .ok_or(SpurtError::Verification("PVSS secret key is zero"))?;
            let share = aggregate.ciphertexts[self.node_id as usize] * inverse;
            let mut message = ReconstructionShare {
                epoch: self.epoch,
                height: self.height,
                digest: aggregate.digest,
                holder: self.node_id,
                share,
                signature: Vec::new(),
            };
            message.signature = self
                .signing_key
                .sign(&reconstruction_payload(&message)?)
                .to_bytes()
                .to_vec();
            Ok(message)
        })
    }

    fn verify_reconstruction_share(
        &self,
        aggregate: &AggregateTranscript,
        message: &ReconstructionShare,
    ) -> Result<(), SpurtError> {
        if aggregate.epoch != self.epoch
            || aggregate.height != self.height
            || message.epoch != self.epoch
            || message.height != self.height
            || message.digest != aggregate.digest
            || message.holder as usize >= self.n
            || aggregate.commitments.len() != self.n
        {
            return Err(SpurtError::Transcript(
                "reconstruction share context mismatch",
            ));
        }
        self.verify_signature(
            message.holder,
            &reconstruction_payload(message)?,
            &message.signature,
        )?;
        let pairings = protocol_support::compute::map(2, |index| {
            if index == 0 {
                pairing(
                    &G1Affine::from(message.share),
                    &G2Affine::from(self.parameters.g1),
                )
            } else {
                pairing(
                    &G1Affine::from(self.parameters.h0),
                    &G2Affine::from(aggregate.commitments[message.holder as usize]),
                )
            }
        });
        if pairings[0] != pairings[1] {
            return Err(SpurtError::Verification(
                "decrypted reconstruction share failed the pairing check",
            ));
        }
        Ok(())
    }

    pub fn accept_reconstruction_share(
        &self,
        sender: u32,
        aggregate: &AggregateTranscript,
        message: ReconstructionShare,
    ) -> Result<VerifiedReconstructionShare, SpurtError> {
        protocol_support::compute::run(|| {
            if message.holder != sender {
                return Err(SpurtError::Transcript(
                    "reconstruction share sender mismatch",
                ));
            }
            self.verify_reconstruction_share(aggregate, &message)?;
            Ok(VerifiedReconstructionShare {
                verification_context: self.verification_context,
                message,
            })
        })
    }

    pub fn reconstruct_preverified(
        &self,
        aggregate: &AggregateTranscript,
        decision: &AgreementDecision,
        valid: Vec<VerifiedReconstructionShare>,
    ) -> Result<BeaconValue, SpurtError> {
        protocol_support::compute::run(|| {
            self.verify_decision_context(aggregate, decision)?;
            let mut valid = valid
                .into_iter()
                .map(|verified| {
                    if verified.verification_context != self.verification_context {
                        return Err(SpurtError::Transcript(
                            "preverified reconstruction context mismatch",
                        ));
                    }
                    Ok(verified.message)
                })
                .collect::<Result<Vec<_>, _>>()?;
            valid.sort_by_key(|message| message.holder);
            if valid.len() < self.t + 1
                || valid
                    .windows(2)
                    .any(|pair| pair[0].holder == pair[1].holder)
                || valid.iter().any(|message| {
                    message.epoch != self.epoch
                        || message.height != self.height
                        || message.digest != aggregate.digest
                        || message.holder as usize >= self.n
                })
            {
                return Err(SpurtError::Transcript(
                    "preverified reconstruction share set is invalid",
                ));
            }
            valid.truncate(self.t + 1);
            let reconstructed = interpolate_at_zero(&valid)?;
            Ok(BeaconValue {
                epoch: self.epoch,
                height: self.height,
                digest: aggregate.digest,
                value: pairing(
                    &G1Affine::from(reconstructed),
                    &G2Affine::from(self.parameters.h1),
                ),
            })
        })
    }

    pub fn beacon_message(&self, value: &BeaconValue) -> Result<BeaconMessage, SpurtError> {
        self.verify_value_context(value)?;
        let mut message = BeaconMessage {
            value: value.clone(),
            signer: self.node_id,
            signature: Vec::new(),
        };
        message.signature = self
            .signing_key
            .sign(&beacon_payload(&message)?)
            .to_bytes()
            .to_vec();
        Ok(message)
    }

    pub fn persist_reconstructed_output(
        &self,
        aggregate: &AggregateTranscript,
        decision: &AgreementDecision,
        value: &BeaconValue,
        output_store: impl AsRef<Path>,
    ) -> Result<[u8; 32], SpurtError> {
        self.verify_decision_context(aggregate, decision)?;
        self.verify_value_context(value)?;
        if value.digest != aggregate.digest {
            return Err(SpurtError::Transcript("beacon value digest mismatch"));
        }
        let output = output_digest(value)?;
        ProtocolStore::open(output_store)?.persist(&(value, output))?;
        Ok(output)
    }

    pub fn finalize_beacon_preverified(
        &self,
        expected: &BeaconValue,
        valid: Vec<VerifiedBeaconMessage>,
        output_store: impl AsRef<Path>,
    ) -> Result<[u8; 32], SpurtError> {
        self.verify_value_context(expected)?;
        let mut valid = valid
            .into_iter()
            .map(|verified| {
                if verified.verification_context != self.verification_context {
                    return Err(SpurtError::Transcript(
                        "preverified BEACON context mismatch",
                    ));
                }
                Ok(verified.message)
            })
            .collect::<Result<Vec<_>, _>>()?;
        valid.sort_by_key(|message| message.signer);
        if valid.len() < self.t + 1
            || valid
                .windows(2)
                .any(|pair| pair[0].signer == pair[1].signer)
            || valid
                .iter()
                .any(|message| message.value != *expected || message.signer as usize >= self.n)
        {
            return Err(SpurtError::Transcript(
                "preverified BEACON certificate is invalid",
            ));
        }
        valid.truncate(self.t + 1);
        let output = output_digest(expected)?;
        ProtocolStore::open(output_store)?.persist(&(expected, valid, output))?;
        Ok(output)
    }

    fn verify_beacon_message(
        &self,
        expected: &BeaconValue,
        message: &BeaconMessage,
    ) -> Result<(), SpurtError> {
        self.verify_value_context(expected)?;
        if message.value != *expected || message.signer as usize >= self.n {
            return Err(SpurtError::Transcript("invalid BEACON signer or value"));
        }
        self.verify_signature(
            message.signer,
            &beacon_payload(message)?,
            &message.signature,
        )
    }

    pub fn accept_beacon_message(
        &self,
        sender: u32,
        expected: &BeaconValue,
        message: BeaconMessage,
    ) -> Result<VerifiedBeaconMessage, SpurtError> {
        if message.signer != sender {
            return Err(SpurtError::Transcript("BEACON sender mismatch"));
        }
        self.verify_beacon_message(expected, &message)?;
        Ok(VerifiedBeaconMessage {
            verification_context: self.verification_context,
            message,
        })
    }

    fn verify_decision_context(
        &self,
        aggregate: &AggregateTranscript,
        decision: &AgreementDecision,
    ) -> Result<(), SpurtError> {
        if aggregate.epoch != self.epoch
            || aggregate.height != self.height
            || aggregate.digest != decision.digest
            || decision.epoch != self.epoch
            || decision.height != self.height
            || aggregate.commitments.len() != self.n
            || aggregate.ciphertexts.len() != self.n
        {
            return Err(SpurtError::Transcript(
                "agreement decision context mismatch",
            ));
        }
        Ok(())
    }

    fn verify_value_context(&self, value: &BeaconValue) -> Result<(), SpurtError> {
        if value.epoch != self.epoch || value.height != self.height {
            return Err(SpurtError::Transcript("beacon value context mismatch"));
        }
        Ok(())
    }
}

fn interpolate_at_zero(messages: &[ReconstructionShare]) -> Result<G1Projective, SpurtError> {
    let mut coefficients = Vec::with_capacity(messages.len());
    for (index, message) in messages.iter().enumerate() {
        let x_i = Scalar::from(message.holder as u64 + 1);
        let mut numerator = Scalar::ONE;
        let mut denominator = Scalar::ONE;
        for (other_index, other) in messages.iter().enumerate() {
            if other_index != index {
                let x_j = Scalar::from(other.holder as u64 + 1);
                numerator *= x_j;
                denominator *= x_j - x_i;
            }
        }
        let inverse = Option::<Scalar>::from(denominator.invert()).ok_or(
            SpurtError::Transcript("duplicate reconstruction evaluation points"),
        )?;
        coefficients.push(numerator * inverse);
    }
    let shares = messages
        .iter()
        .map(|message| message.share)
        .collect::<Vec<_>>();
    Ok(G1Projective::multi_exp(&shares, &coefficients))
}
