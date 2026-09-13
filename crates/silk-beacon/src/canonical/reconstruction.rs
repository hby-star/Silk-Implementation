use super::*;

type ReconstructionPoint = (
    curve25519_dalek::scalar::Scalar,
    curve25519_dalek::scalar::Scalar,
);
type SelectedDealerPoints = (DealerPointSet, Vec<ReconstructionPoint>);
impl BeaconNode {
    pub(crate) fn receive_reconstruction_batch_preverified(
        &mut self,
        verification_context: [u8; 32],
        mut messages: Vec<ReconstructionMessage>,
    ) -> Result<Option<[u8; 32]>, BeaconError> {
        self.ensure_active()?;
        if verification_context != self.config.context.config_digest || messages.is_empty() {
            return Err(BeaconError::InvalidReconstruction);
        }
        messages.sort_by_key(|message| message.sender);
        if messages
            .windows(2)
            .any(|pair| pair[0].sender >= pair[1].sender)
        {
            return Err(BeaconError::InvalidReconstruction);
        }
        let index = messages[0].index;
        if messages.iter().any(|message| message.index != index) {
            return Err(BeaconError::InvalidReconstruction);
        }
        let gate_ready = if index == 1 {
            self.durable.installed_epoch.is_some()
        } else {
            self.durable.qrout.contains_key(&index)
        };
        if !gate_ready {
            return Err(BeaconError::InvalidState);
        }
        self.process_reconstruction_batch(index, messages)
    }

    pub fn releases(&self, index: u32) -> Result<Vec<ReleaseAnnouncement>, BeaconError> {
        let releases = self
            .release_evidence
            .get(&index)
            .ok_or(BeaconError::InvalidState)?;
        if releases.len() < self.config.params.qc_threshold() {
            return Err(BeaconError::InvalidState);
        }
        Ok(releases
            .values()
            .take(self.config.params.qc_threshold())
            .cloned()
            .collect())
    }

    pub(super) fn create_reconstruction_message(
        &mut self,
        index: u32,
    ) -> Result<ReconstructionMessage, BeaconError> {
        if let Some(existing) = self.durable.released.get(&index) {
            return Ok(existing.clone());
        }
        self.require_index(index)?;
        if (index == 1 && self.durable.installed_epoch.is_none())
            || (index > 1 && !self.durable.qrout.contains_key(&index))
        {
            return Err(BeaconError::InvalidState);
        }
        let mut items = Vec::new();
        for entry in &self.certified_epoch.epoch_certificate.command.transcripts {
            let Some(row) = self.retained_rows.get(&entry.dealer) else {
                continue;
            };
            let public = transcript_for(&self.certified_epoch, entry.dealer)?;
            items.push(compact_item_from_row(public, row, (index - 1) as usize)?);
        }
        let message = ReconstructionMessage {
            sender: self.id,
            index,
            items,
        };
        self.persist(&DurableRecord::Released {
            index,
            message: message.clone(),
        })?;
        self.durable.released.insert(index, message.clone());
        Ok(message)
    }

    fn process_reconstruction_batch(
        &mut self,
        index: u32,
        messages: Vec<ReconstructionMessage>,
    ) -> Result<Option<[u8; 32]>, BeaconError> {
        if let Some(output) = self.durable.outputs.get(&index) {
            return Ok(Some(*output));
        }
        for message in messages {
            self.verify_reconstruction_envelope(&message)?;
            let pending = self.pending_reconstruction.entry(index).or_default();
            if let Some(existing) = pending.get(&message.sender) {
                if existing != &message {
                    return Err(BeaconError::InvalidReconstruction);
                }
            } else {
                pending.insert(message.sender, message);
            }
        }

        let mut plans = std::mem::take(&mut self.reconstruction_plans);
        let result = (|| {
            let pending = self
                .pending_reconstruction
                .get(&index)
                .ok_or(BeaconError::InvalidReconstruction)?;
            let mut point_sets = Vec::with_capacity(self.config.params.d);
            let mut grouped_shares =
                BTreeMap::<Vec<u32>, Vec<curve25519_dalek::scalar::Scalar>>::new();
            for entry in &self.certified_epoch.epoch_certificate.command.transcripts {
                let candidates = pending
                    .values()
                    .filter_map(|message| {
                        message
                            .items
                            .iter()
                            .find(|item| item.dealer == entry.dealer)
                            .cloned()
                            .map(|item| (message.sender, item))
                    })
                    .collect::<Vec<_>>();
                let Some((point_set, points)) =
                    self.select_exact_valid_points(entry.dealer, index, &candidates, &mut plans)?
                else {
                    return Ok(None);
                };
                let senders = point_set
                    .points
                    .iter()
                    .map(|point| point.sender)
                    .collect::<Vec<_>>();
                let shares = grouped_shares
                    .entry(senders)
                    .or_insert_with(|| vec![curve25519_dalek::scalar::Scalar::ZERO; points.len()]);
                if shares.len() != points.len() {
                    return Err(BeaconError::InvalidReconstruction);
                }
                for (aggregate_share, (_, dealer_share)) in shares.iter_mut().zip(points) {
                    *aggregate_share += dealer_share;
                }
                point_sets.push(point_set);
            }
            let mut aggregate = curve25519_dalek::scalar::Scalar::ZERO;
            for (senders, shares) in grouped_shares {
                let plan = reconstruction_plan(self.config.params, &senders, &mut plans)?;
                aggregate += plan.interpolate_shares(&shares)?;
            }
            let output = beacon_output(&self.config, self.epoch_digest, index, aggregate);
            Ok(Some((output, point_sets)))
        })();
        self.reconstruction_plans = plans;
        let Some((output, point_sets)) = result? else {
            return Ok(None);
        };
        self.persist_completed_output(index, output, point_sets)?;
        Ok(Some(output))
    }

    fn select_exact_valid_points(
        &self,
        dealer: u32,
        index: u32,
        candidates: &[(u32, CompactReconstructionItem)],
        plans: &mut ReconstructionPlans,
    ) -> Result<Option<SelectedDealerPoints>, BeaconError> {
        if candidates.len() < self.config.params.d {
            return Ok(None);
        }
        let public = transcript_for(&self.certified_epoch, dealer)?;
        let normal_path = candidates
            .iter()
            .take(self.config.params.d)
            .cloned()
            .collect::<Vec<_>>();
        let normal_senders = normal_path
            .iter()
            .map(|(sender, _)| *sender)
            .collect::<Vec<_>>();
        let plan = reconstruction_plan(self.config.params, &normal_senders, plans)?;
        if let Ok(points) = plan.verify_prevalidated(public, (index - 1) as usize, &normal_path) {
            return Ok(Some((dealer_point_set(dealer, &normal_path), points)));
        }

        // Fault-only fallback: locate invalid openings without imposing a
        // second verification pass on the failure-free measured path.
        let verifier = silk_bavss_po::CompactPointVerifier::new_prevalidated(
            self.config.params,
            public,
            (index - 1) as usize,
        )?;
        let mut accepted_items = Vec::with_capacity(self.config.params.d);
        let mut valid_points = Vec::with_capacity(self.config.params.d);
        for (sender, item) in candidates {
            if let Ok(point) = verifier.verify(*sender, item) {
                accepted_items.push((*sender, item.clone()));
                valid_points.push(point);
                if accepted_items.len() == self.config.params.d {
                    break;
                }
            }
        }
        if accepted_items.len() != self.config.params.d {
            return Ok(None);
        }
        Ok(Some((
            dealer_point_set(dealer, &accepted_items),
            valid_points,
        )))
    }

    fn persist_completed_output(
        &mut self,
        index: u32,
        output: [u8; 32],
        point_sets: Vec<DealerPointSet>,
    ) -> Result<(), BeaconError> {
        self.persist(&DurableRecord::CompletedOutput { index, output })?;

        let _ = point_sets;
        self.pending_reconstruction.remove(&index);
        self.durable.outputs.insert(index, output);
        Ok(())
    }

    pub(crate) fn verify_reconstruction_envelope(
        &self,
        message: &ReconstructionMessage,
    ) -> Result<(), BeaconError> {
        self.require_index(message.index)?;
        let command = &self.certified_epoch.epoch_certificate.command;
        if message.sender as usize >= self.config.params.n
            || !message
                .items
                .windows(2)
                .all(|pair| pair[0].dealer < pair[1].dealer)
            || message.items.len() > command.transcripts.len()
            || message.items.iter().any(|item| {
                command
                    .transcripts
                    .iter()
                    .all(|entry| item.dealer != entry.dealer)
            })
        {
            return Err(BeaconError::InvalidReconstruction);
        }
        Ok(())
    }
}

fn reconstruction_plan<'a>(
    params: ProtocolParams,
    senders: &[u32],
    plans: &'a mut ReconstructionPlans,
) -> Result<&'a CompactReconstructionPlan, BeaconError> {
    if !plans.contains_key(senders) {
        plans.insert(
            senders.to_vec(),
            CompactReconstructionPlan::new(params, senders)?,
        );
    }
    plans.get(senders).ok_or(BeaconError::InvalidReconstruction)
}

fn dealer_point_set(dealer: u32, items: &[(u32, CompactReconstructionItem)]) -> DealerPointSet {
    DealerPointSet {
        dealer,
        points: items
            .iter()
            .map(|(sender, item)| AuthenticatedPoint {
                sender: *sender,
                item: item.clone(),
            })
            .collect(),
    }
}
