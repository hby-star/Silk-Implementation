//! Rondo-BFT requests and external-validity checks.

use protocol_support::derive_seed;
use protocol_support::wire::{canonical_deserialize, canonical_serialize};

use super::*;
use crate::bft::normal::NormalReplica;
use crate::bft::{BftParams, Request};
use crate::{CommonSubsetEntry, FirstRoundPayload};

impl RondoEpoch {
    pub fn requests(&self) -> Result<Vec<Request>, RondoError> {
        (0..self.params.l)
            .map(|slot| {
                let slot = slot as u32;
                let round = slot as u64 + 1;
                let payload = if slot == 0 {
                    canonical_serialize(&FirstRoundPayload {
                        tag: "Rondo-beacon-first-round-v2".into(),
                        epoch: self.epoch,
                        round,
                        slot,
                        entries: self
                            .selected
                            .values()
                            .map(|dealer| CommonSubsetEntry {
                                dealer_id: dealer.public.dealer_id,
                                commitment_root: dealer.public.commitment_root,
                                validation: dealer.qc.clone(),
                            })
                            .collect(),
                    })?
                } else {
                    canonical_serialize(&(
                        "Rondo-beacon-round-v1",
                        self.epoch,
                        round,
                        slot,
                        self.subset,
                    ))?
                };
                Ok(Request {
                    client_id: 0,
                    sequence: round,
                    payload,
                })
            })
            .collect()
    }

    pub fn bft_replica(
        &self,
        node_id: u32,
        committee_seed: u64,
    ) -> Result<NormalReplica, RondoError> {
        let initial_height = self
            .epoch
            .checked_sub(1)
            .and_then(|epoch| epoch.checked_mul(self.params.l as u64))
            .and_then(|height| height.checked_add(1))
            .ok_or(RondoError::Invalid("BFT height overflow"))?;
        Ok(NormalReplica::new(
            BftParams::new(self.params.n, self.params.t)?,
            node_id,
            derive_seed(committee_seed, b"rondo-bft-normal-path"),
            initial_height,
        )?)
    }

    pub fn validate_request(&self, request: &Request) -> bool {
        let Some(slot) = request.sequence.checked_sub(1) else {
            return false;
        };
        if slot >= self.params.l as u64 {
            return false;
        }
        if slot == 0 {
            let Ok(payload) = canonical_deserialize::<FirstRoundPayload>(&request.payload) else {
                return false;
            };
            if payload.tag != "Rondo-beacon-first-round-v2"
                || payload.epoch != self.epoch
                || payload.round != request.sequence
                || payload.slot != 0
                || payload.entries.len() < self.params.d
            {
                return false;
            }
            let mut previous = None;
            payload.entries.iter().all(|entry| {
                if previous.is_some_and(|dealer| dealer >= entry.dealer_id) {
                    return false;
                }
                previous = Some(entry.dealer_id);
                self.selected.get(&entry.dealer_id).is_some_and(|dealer| {
                    dealer.public.commitment_root == entry.commitment_root
                        && dealer.qc == entry.validation
                })
            })
        } else {
            canonical_deserialize::<(String, u64, u64, u32, [u8; 32])>(&request.payload).is_ok_and(
                |(tag, epoch, round, got_slot, subset)| {
                    tag == "Rondo-beacon-round-v1"
                        && epoch == self.epoch
                        && round == request.sequence
                        && got_slot as u64 == slot
                        && subset == self.subset
                },
            )
        }
    }
}
