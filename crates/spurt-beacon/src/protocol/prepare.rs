//! Spurt PVSS contribution, aggregation, and proposal verification.

use blstrs::{G1Projective, G2Projective};
use ed25519_dalek::Signer;
use group::Group;
use protocol_support::wire::canonical_serialize;

use super::transcript::{aggregate_digest, contribution_payload, proposal_payload};
use super::*;
use crate::pvss::{DleqBatchItem, degree_check, share, verify_contribution, verify_dleq_batch};
use crate::types::{AggregateTranscript, ReceiverColumnEntry, ReceiverProposal};

impl SpurtProtocol {
    pub fn contribution(&self) -> Result<DealerContribution, SpurtError> {
        protocol_support::compute::run(|| {
            let mut rng = self.rng(&format!(
                "spurt-contribution-v1-{}-{}-{}",
                self.epoch, self.height, self.node_id
            ));
            let mut contribution = share(
                self.parameters.as_ref(),
                self.public_keys.as_slice(),
                self.n,
                self.t,
                self.epoch,
                self.height,
                self.node_id,
                &mut rng,
            )?;
            contribution.signature = self
                .signing_key
                .sign(&contribution_payload(&contribution)?)
                .to_bytes()
                .to_vec();
            Ok(contribution)
        })
    }

    fn verify_contribution_for_aggregation(
        &self,
        contribution: &DealerContribution,
    ) -> Result<(), SpurtError> {
        self.verify_contribution_context_and_signature(contribution)?;
        verify_contribution(
            self.parameters.as_ref(),
            self.public_keys.as_slice(),
            self.n,
            self.t,
            self.degree_check_weights.as_slice(),
            contribution,
        )
    }

    pub fn accept_contribution_for_aggregation(
        &self,
        sender: u32,
        contribution: DealerContribution,
    ) -> Result<VerifiedDealerContribution, SpurtError> {
        protocol_support::compute::run(|| {
            if contribution.dealer != sender {
                return Err(SpurtError::Transcript("PVSS contribution sender mismatch"));
            }
            self.verify_contribution_for_aggregation(&contribution)?;
            Ok(VerifiedDealerContribution {
                verification_context: self.verification_context,
                contribution,
            })
        })
    }

    pub fn aggregate_preverified(
        &self,
        valid: Vec<VerifiedDealerContribution>,
    ) -> Result<Vec<ReceiverProposal>, SpurtError> {
        protocol_support::compute::run(|| {
            if self.node_id != self.leader() {
                return Err(SpurtError::Transcript(
                    "only the designated leader may aggregate",
                ));
            }
            let mut valid = valid
                .into_iter()
                .map(|verified| {
                    if verified.verification_context != self.verification_context {
                        return Err(SpurtError::Transcript(
                            "preverified PVSS contribution context mismatch",
                        ));
                    }
                    Ok(verified.contribution)
                })
                .collect::<Result<Vec<_>, _>>()?;
            valid.sort_by_key(|contribution| contribution.dealer);
            if valid.len() < self.t + 1
                || valid
                    .windows(2)
                    .any(|pair| pair[0].dealer == pair[1].dealer)
                || valid
                    .iter()
                    .any(|contribution| self.verify_contribution_context(contribution).is_err())
            {
                return Err(SpurtError::Transcript(
                    "preverified PVSS contribution set is invalid",
                ));
            }
            valid.truncate(self.t + 1);
            let selected = valid;

            let (commitments, ciphertexts): (Vec<_>, Vec<_>) =
                protocol_support::compute::map(self.n, |receiver| {
                    selected.iter().fold(
                        (G2Projective::identity(), G1Projective::identity()),
                        |(commitment, ciphertext), contribution| {
                            (
                                commitment + contribution.commitments[receiver],
                                ciphertext + contribution.ciphertexts[receiver],
                            )
                        },
                    )
                })
                .into_iter()
                .unzip();
            let dealer_ids = selected
                .iter()
                .map(|contribution| contribution.dealer)
                .collect::<Vec<_>>();
            let digest = aggregate_digest(
                self.epoch,
                self.height,
                &dealer_ids,
                &commitments,
                &ciphertexts,
            )?;
            let aggregate = AggregateTranscript {
                epoch: self.epoch,
                height: self.height,
                dealer_ids,
                commitments,
                ciphertexts,
                digest,
            };

            protocol_support::compute::map(self.n, |receiver| {
                let column = selected
                    .iter()
                    .map(|contribution| ReceiverColumnEntry {
                        dealer: contribution.dealer,
                        commitment: contribution.commitments[receiver],
                        ciphertext: contribution.ciphertexts[receiver],
                        proof: contribution.proofs[receiver].clone(),
                    })
                    .collect::<Vec<_>>();
                let mut proposal = ReceiverProposal {
                    leader: self.node_id,
                    receiver: receiver as u32,
                    aggregate: aggregate.clone(),
                    column,
                    signature: Vec::new(),
                };
                proposal.signature = self
                    .signing_key
                    .sign(&proposal_payload(&proposal)?)
                    .to_bytes()
                    .to_vec();
                Ok(proposal)
            })
            .into_iter()
            .collect()
        })
    }

    pub fn verify_proposal(&self, proposal: &ReceiverProposal) -> Result<(), SpurtError> {
        protocol_support::compute::run(|| {
            if proposal.leader != self.leader()
                || proposal.receiver != self.node_id
                || proposal.aggregate.epoch != self.epoch
                || proposal.aggregate.height != self.height
                || proposal.aggregate.dealer_ids.len() != self.t + 1
                || proposal.aggregate.commitments.len() != self.n
                || proposal.aggregate.ciphertexts.len() != self.n
                || proposal.column.len() != self.t + 1
            {
                return Err(SpurtError::Transcript("receiver proposal context mismatch"));
            }
            if proposal
                .aggregate
                .dealer_ids
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
                || proposal
                    .aggregate
                    .dealer_ids
                    .iter()
                    .any(|dealer| *dealer as usize >= self.n)
            {
                return Err(SpurtError::Transcript(
                    "receiver proposal dealer set is invalid",
                ));
            }
            self.verify_signature(
                proposal.leader,
                &proposal_payload(proposal)?,
                &proposal.signature,
            )?;
            if proposal.aggregate.digest
                != aggregate_digest(
                    self.epoch,
                    self.height,
                    &proposal.aggregate.dealer_ids,
                    &proposal.aggregate.commitments,
                    &proposal.aggregate.ciphertexts,
                )?
            {
                return Err(SpurtError::Verification(
                    "aggregate proposal digest mismatch",
                ));
            }

            let degree_context = canonical_serialize(&(
                "Spurt-aggregate-degree-check-v1",
                proposal.aggregate.epoch,
                proposal.aggregate.height,
                &proposal.aggregate.dealer_ids,
                proposal.aggregate.digest,
            ))?;
            degree_check(
                &proposal.aggregate.commitments,
                self.n,
                self.t,
                self.degree_check_weights.as_slice(),
                &degree_context,
            )?;

            let receiver = self.node_id as usize;
            let mut aggregate_commitment = G2Projective::identity();
            let mut aggregate_ciphertext = G1Projective::identity();
            let mut dleq_items = Vec::with_capacity(proposal.column.len());
            for (expected_dealer, entry) in
                proposal.aggregate.dealer_ids.iter().zip(&proposal.column)
            {
                if expected_dealer != &entry.dealer {
                    return Err(SpurtError::Transcript(
                        "receiver-specific column has the wrong dealer order",
                    ));
                }
                dleq_items.push(DleqBatchItem {
                    public_key: self.public_keys[receiver],
                    commitment: entry.commitment,
                    ciphertext: entry.ciphertext,
                    proof: &entry.proof,
                    epoch: self.epoch,
                    height: self.height,
                    dealer: entry.dealer,
                    receiver: self.node_id,
                });
                aggregate_commitment += entry.commitment;
                aggregate_ciphertext += entry.ciphertext;
            }
            verify_dleq_batch(self.parameters.as_ref(), &dleq_items)?;
            if aggregate_commitment != proposal.aggregate.commitments[receiver]
                || aggregate_ciphertext != proposal.aggregate.ciphertexts[receiver]
            {
                return Err(SpurtError::Verification(
                    "receiver-specific column was aggregated incorrectly",
                ));
            }
            Ok(())
        })
    }

    fn verify_contribution_context_and_signature(
        &self,
        contribution: &DealerContribution,
    ) -> Result<(), SpurtError> {
        self.verify_contribution_context(contribution)?;
        self.verify_signature(
            contribution.dealer,
            &contribution_payload(contribution)?,
            &contribution.signature,
        )
    }

    fn verify_contribution_context(
        &self,
        contribution: &DealerContribution,
    ) -> Result<(), SpurtError> {
        if contribution.epoch != self.epoch
            || contribution.height != self.height
            || contribution.dealer as usize >= self.n
        {
            return Err(SpurtError::Transcript("PVSS contribution context mismatch"));
        }
        Ok(())
    }
}
