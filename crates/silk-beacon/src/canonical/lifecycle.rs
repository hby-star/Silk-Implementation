use super::*;

impl BeaconNode {
    pub(super) fn new_preverified(
        id: u32,
        config: BeaconConfiguration,
        certified_epoch: CertifiedEpoch,
        release_key: SigningKey65,
        retained_rows: BTreeMap<u32, PrivateRow>,
        store_path: PathBuf,
    ) -> Result<Self, BeaconError> {
        let selected = certified_epoch
            .epoch_certificate
            .command
            .transcripts
            .iter()
            .map(|entry| entry.dealer)
            .collect::<BTreeSet<_>>();
        if id as usize >= config.params.n
            || retained_rows.iter().any(|(dealer, row)| {
                !selected.contains(dealer) || row.dealer != *dealer || row.receiver != id
            })
        {
            return Err(BeaconError::InvalidValidation);
        }
        let release_verifying_keys =
            Arc::from(mldsa_verifying_keys(&config.validation_public_keys)?);
        let epoch_digest = epoch_tau(&config, &certified_epoch.epoch_certificate.command);
        Ok(Self {
            id,
            config,
            certified_epoch,
            release_key,
            release_verifying_keys,
            epoch_digest,
            retained_rows,
            durable: DurableNodeState::default(),
            matching: BTreeMap::new(),
            pending_reconstruction: BTreeMap::new(),
            reconstruction_plans: ReconstructionPlans::new(),

            release_evidence: BTreeMap::new(),
            store_path,
        })
    }

    pub fn output(&self, index: u32) -> Option<[u8; 32]> {
        self.durable.outputs.get(&index).copied()
    }

    pub fn qr_support(&self, index: u32) -> QrSupport {
        let Some(digest) = self.durable.qrout.get(&index) else {
            return QrSupport::default();
        };
        let matching_senders = self
            .matching
            .get(&(index, *digest))
            .map(|senders| senders.iter().copied().collect::<Vec<_>>())
            .unwrap_or_default();
        QrSupport {
            guaranteed_correct_predecessor_completers: matching_senders
                .len()
                .saturating_sub(self.config.params.t),
            matching_senders,
        }
    }

    pub fn install_epoch(&mut self) -> Result<ReconstructionMessage, BeaconError> {
        self.install_epoch_after(None)
    }

    pub fn install_epoch_after(
        &mut self,
        predecessor: Option<&EpochCompletion>,
    ) -> Result<ReconstructionMessage, BeaconError> {
        self.ensure_active()?;
        if self.config.epoch > 1
            && predecessor.is_none_or(|previous| {
                previous.replica != self.id
                    || previous.epoch + 1 != self.config.epoch
                    || previous.sid != self.config.sid
                    || previous.registry_digest != self.config.registry_digest
                    || previous.params != self.config.params
            })
        {
            return Err(BeaconError::InvalidState);
        }
        let decision_digest = self
            .certified_epoch
            .epoch_certificate
            .decision_certificate
            .proposal_digest;
        if let Some(existing) = self.durable.installed_epoch {
            if existing != decision_digest {
                return Err(BeaconError::InvalidEpoch);
            }
            return self.create_reconstruction_message(1);
        }
        self.persist(&DurableRecord::Install {
            epoch: self.config.epoch,
            decision_digest,
        })?;
        self.durable.installed_epoch = Some(decision_digest);
        self.create_reconstruction_message(1)
    }
}

impl BeaconNode {
    pub fn completed_epoch(&self) -> Result<EpochCompletion, BeaconError> {
        if self.durable.outputs.len() != self.config.params.l
            || self
                .release_evidence
                .get(&(self.config.params.l as u32))
                .is_none_or(|releases| releases.len() < self.config.params.qc_threshold())
        {
            return Err(BeaconError::InvalidState);
        }
        Ok(EpochCompletion {
            replica: self.id,
            sid: self.config.sid.clone(),
            epoch: self.config.epoch,
            registry_digest: self.config.registry_digest,
            params: self.config.params,
        })
    }
}
