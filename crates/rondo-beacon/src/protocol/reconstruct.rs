//! Aggregate-share verification, compact reconstruction, and durable output.

use std::collections::BTreeMap;
use std::path::Path;

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use protocol_support::store::ProtocolStore;
use rondo_bavss_po::protocol::breeze_reconstruct::aggregate_dealer_secrets;

use super::*;
use crate::bft::normal::DecisionProof;
use crate::output_hash;
use crate::{AggregateShare, DealerFallbackShare, FallbackShare};

impl RondoEpoch {
    /// Any authenticated replica may open an aggregate. The resulting secret
    /// is still checked against the sum of the selected public commitments.
    pub fn aggregate_holders(&self) -> std::collections::BTreeSet<u32> {
        (0..self.params.n as u32).collect()
    }
    pub fn public_materials(&self) -> Vec<BreezePublicData> {
        self.selected
            .values()
            .map(|dealer| dealer.public.clone())
            .collect()
    }

    pub fn aggregate_share(
        &self,
        holder: u32,
        height: u64,
        slot: u32,
    ) -> Result<Option<AggregateShare>, RondoError> {
        if holder as usize >= self.params.n || slot as usize >= self.params.l {
            return Err(RondoError::Invalid("aggregate context out of range"));
        }
        let mut shares = Vec::with_capacity(self.selected.len());
        for dealer in self.selected.values() {
            let Some(retained) = &dealer.retained else {
                return Ok(None);
            };
            if retained.row.receiver_id != holder as usize
                || retained.row.eval_point != Scalar::from(holder as u64 + 1)
            {
                return Err(RondoError::Invalid("aggregate holder row mismatch"));
            }
            shares.push(
                retained
                    .row
                    .shares
                    .get(slot as usize)
                    .copied()
                    .ok_or(RondoError::Invalid("aggregate slot out of range"))?,
            );
        }
        Ok(Some(AggregateShare {
            epoch: self.epoch,
            round: slot as u64 + 1,
            height,
            slot,
            holder,
            share: aggregate_dealer_secrets(&shares),
        }))
    }

    /// Builds this holder's fault-recovery contribution. Only dealer rows for
    /// which the holder signed the validation QC are eligible; this is the
    /// availability set certified by the protocol.
    pub fn fallback_share(
        &self,
        holder: u32,
        height: u64,
        slot: u32,
    ) -> Result<Option<FallbackShare>, RondoError> {
        if holder as usize >= self.params.n || slot as usize >= self.params.l {
            return Err(RondoError::Invalid("fallback context out of range"));
        }
        let mut dealers = Vec::new();
        for dealer in self.selected.values() {
            if !dealer.qc.signer_ids.contains(&(holder as usize)) {
                continue;
            }
            let Some(retained) = &dealer.retained else {
                continue;
            };
            if retained.row.receiver_id != holder as usize
                || retained.row.dealer_id != dealer.public.dealer_id
                || retained.proof.receiver_id != holder as usize
                || retained.proof.dealer_id != dealer.public.dealer_id
            {
                return Err(RondoError::Invalid("fallback holder row mismatch"));
            }
            dealers.push(DealerFallbackShare {
                dealer_id: dealer.public.dealer_id,
                row: retained.row.clone(),
                proof: retained.proof.clone(),
            });
        }
        if dealers.is_empty() {
            return Ok(None);
        }
        Ok(Some(FallbackShare {
            epoch: self.epoch,
            round: slot as u64 + 1,
            height,
            slot,
            holder,
            dealers,
        }))
    }

    pub fn fallback_reconstruction(
        &self,
        height: u64,
        slot: u32,
    ) -> Result<FallbackReconstruction<'_>, RondoError> {
        if slot as usize >= self.params.l {
            return Err(RondoError::Invalid("fallback slot out of range"));
        }
        Ok(FallbackReconstruction {
            epoch: self,
            height,
            slot,
            accepted_senders: Default::default(),
            shares: self
                .selected
                .keys()
                .copied()
                .map(|dealer| (dealer, BTreeMap::new()))
                .collect(),
        })
    }

    pub fn reconstruct(
        &self,
        mut messages: Vec<(u32, AggregateShare)>,
        proof: &DecisionProof,
        slot: u32,
        output_store: impl AsRef<Path>,
    ) -> Result<[u8; 32], RondoError> {
        messages.sort_by_key(|(_, share)| share.holder);
        if messages
            .iter()
            .any(|(sender, share)| sender != &share.holder)
            || messages
                .windows(2)
                .any(|pair| pair[0].1.holder == pair[1].1.holder)
        {
            return Err(RondoError::Invalid("invalid aggregate sender set"));
        }
        let mut shares = messages
            .into_iter()
            .map(|(_, share)| share)
            .collect::<Vec<_>>();
        shares.truncate(self.params.d);
        let verified = shares
            .iter()
            .map(|share| self.verify_aggregate(share, proof.block().height, slot))
            .collect::<Result<Vec<_>, _>>()?;
        let senders = shares.iter().map(|share| share.holder).collect::<Vec<_>>();
        let mut plans = self
            .aggregate_reconstructors
            .lock()
            .map_err(|_| RondoError::Invalid("aggregate plan lock poisoned"))?;
        if !plans.contains_key(&senders) {
            plans.insert(
                senders.clone(),
                CompactAggregateReconstructor::new(
                    self.params,
                    &verified.iter().map(|(x, _)| *x).collect::<Vec<_>>(),
                )?,
            );
        }
        let reconstructed =
            plans[&senders].reconstruct(&verified, self.aggregate_commitment(slot as usize)?)?;
        self.persist_output(reconstructed, proof.block().height, slot, output_store)
    }

    fn verify_aggregate(
        &self,
        aggregate: &AggregateShare,
        height: u64,
        slot: u32,
    ) -> Result<(Scalar, Scalar), RondoError> {
        if aggregate.epoch != self.epoch
            || aggregate.round != slot as u64 + 1
            || aggregate.height != height
            || aggregate.slot != slot
            || aggregate.holder as usize >= self.params.n
        {
            return Err(RondoError::Invalid("aggregate context mismatch"));
        }
        Ok((Scalar::from(aggregate.holder as u64 + 1), aggregate.share))
    }

    fn aggregate_commitment(&self, slot: usize) -> Result<RistrettoPoint, RondoError> {
        let mut commitments = self.selected.values().map(|dealer| {
            dealer
                .public
                .commitments
                .get(slot)
                .copied()
                .ok_or(RondoError::Invalid(
                    "aggregate commitment slot out of range",
                ))
        });
        let first = commitments
            .next()
            .ok_or(RondoError::Invalid("empty selected dealer set"))??;
        commitments.try_fold(first, |sum, commitment| Ok(sum + commitment?))
    }

    fn persist_output(
        &self,
        reconstructed: Scalar,
        height: u64,
        slot: u32,
        output_store: impl AsRef<Path>,
    ) -> Result<[u8; 32], RondoError> {
        let round = slot as u64 + 1;
        let output = output_hash(self.epoch, round, height, slot, self.subset, reconstructed);
        ProtocolStore::open(output_store)?.persist(&(self.epoch, round, height, slot, output))?;
        Ok(output)
    }
}

impl FallbackReconstruction<'_> {
    /// Verifies one authenticated sender message and commits all of its dealer
    /// points atomically. A malformed message cannot occupy a sender slot, so
    /// a later valid retry remains possible.
    pub fn accept(&mut self, sender: u32, message: &FallbackShare) -> Result<(), RondoError> {
        if sender != message.holder
            || message.epoch != self.epoch.epoch
            || message.round != self.slot as u64 + 1
            || message.height != self.height
            || message.slot != self.slot
            || sender as usize >= self.epoch.params.n
            || self.accepted_senders.contains(&sender)
        {
            return Err(RondoError::Invalid("fallback message context mismatch"));
        }
        let expected_dealers = self
            .epoch
            .selected
            .values()
            .filter(|dealer| dealer.qc.signer_ids.contains(&(sender as usize)))
            .map(|dealer| dealer.public.dealer_id)
            .collect::<Vec<_>>();
        let got_dealers = message
            .dealers
            .iter()
            .map(|dealer| dealer.dealer_id)
            .collect::<Vec<_>>();
        if expected_dealers.is_empty() || got_dealers != expected_dealers {
            return Err(RondoError::Invalid("fallback dealer set mismatch"));
        }

        let mut verified = Vec::with_capacity(message.dealers.len());
        for opening in &message.dealers {
            let dealer = self
                .epoch
                .selected
                .get(&opening.dealer_id)
                .ok_or(RondoError::Invalid("unknown fallback dealer"))?;
            self.epoch.fallback_verifier.verify_batch_eval(
                &opening.row,
                &dealer.public,
                &opening.proof,
            )?;
            let share = opening
                .row
                .shares
                .get(self.slot as usize)
                .copied()
                .ok_or(RondoError::Invalid("fallback slot out of range"))?;
            verified.push((opening.dealer_id, opening.row.eval_point, share));
        }
        for (dealer, point, share) in verified {
            self.shares
                .get_mut(&dealer)
                .ok_or(RondoError::Invalid("unknown fallback dealer"))?
                .insert(sender, (point, share));
        }
        self.accepted_senders.insert(sender);
        Ok(())
    }

    pub fn is_ready(&self) -> bool {
        self.shares
            .values()
            .all(|shares| shares.len() >= self.epoch.params.d)
    }

    pub fn accepted_senders(&self) -> &std::collections::BTreeSet<u32> {
        &self.accepted_senders
    }

    pub fn finish(
        self,
        proof: &DecisionProof,
        output_store: impl AsRef<Path>,
    ) -> Result<[u8; 32], RondoError> {
        if !self.is_ready()
            || proof.block().height != self.height
            || proof.block().request.sequence != self.slot as u64 + 1
            || !self.epoch.validate_request(&proof.block().request)
        {
            return Err(RondoError::Invalid("fallback reconstruction is incomplete"));
        }

        let mut reconstructors = BTreeMap::new();
        let mut aggregate = Scalar::ZERO;
        for (dealer_id, dealer_shares) in self.shares {
            let selected = self
                .epoch
                .selected
                .get(&dealer_id)
                .ok_or(RondoError::Invalid("unknown fallback dealer"))?;
            let exact = dealer_shares
                .into_iter()
                .take(self.epoch.params.d)
                .collect::<Vec<_>>();
            let holders = exact.iter().map(|(holder, _)| *holder).collect::<Vec<_>>();
            let points = exact.iter().map(|(_, point)| point.0).collect::<Vec<_>>();
            if !reconstructors.contains_key(&holders) {
                reconstructors.insert(
                    holders.clone(),
                    CompactAggregateReconstructor::new(self.epoch.params, &points)?,
                );
            }
            let shares = exact
                .into_iter()
                .map(|(_, point)| point)
                .collect::<Vec<_>>();
            let commitment = selected
                .public
                .commitments
                .get(self.slot as usize)
                .copied()
                .ok_or(RondoError::Invalid("fallback commitment slot out of range"))?;
            aggregate += reconstructors
                .get(&holders)
                .ok_or(RondoError::Invalid("missing fallback reconstructor"))?
                .reconstruct(&shares, commitment)?;
        }
        self.epoch
            .persist_output(aggregate, self.height, self.slot, output_store)
    }
}
