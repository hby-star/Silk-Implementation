use super::*;

impl BeaconCommittee {
    pub fn derive(
        params: ProtocolParams,
        epoch: u64,
        seed: u64,
        reconstruction_window: u64,
    ) -> Result<Self, BeaconError> {
        validate_params(params)?;
        let sid = format!("silk-session-{seed}").into_bytes();
        let validation_keys = (0..params.n)
            .map(|node| mldsa_key(seed, b"validation-v1", node))
            .collect::<Result<Vec<_>, _>>()?;
        let validation_public_keys = validation_keys
            .iter()
            .map(public_key_bytes)
            .collect::<Vec<_>>();
        let validation_verifying_keys = Arc::from(mldsa_verifying_keys(&validation_public_keys)?);
        let bft_seed = derive_seed(seed, b"silk-current-epoch-bft");
        let bft = BrachaCommittee::for_epoch(BftParams::new(params.n, params.t)?, bft_seed, epoch);
        let decision_public_keys = bft.public_keys().to_vec();
        let registry_digest = registry_digest(&validation_public_keys, &decision_public_keys);
        let context =
            ProtocolContext::derive(&sid, epoch, registry_digest, params, reconstruction_window)?;
        let config = BeaconConfiguration {
            sid,
            epoch,
            params,
            reconstruction_window,
            registry_digest,
            context,
            validation_public_keys,
            decision_public_keys,
        };
        config.verify()?;
        Ok(Self {
            config,
            validation_keys,
            validation_verifying_keys,
            bft,
            seed,
        })
    }

    pub fn dealer_share(
        &self,
        dealer: u32,
    ) -> Result<(DealerPublicTranscript, Vec<PrivateRow>), BeaconError> {
        if dealer as usize >= self.config.params.n {
            return Err(BeaconError::InvalidValidation);
        }
        let mut rng = ChaCha20Rng::from_seed(derive_seed(
            self.seed,
            format!("silk-current-epoch-{}-dealer-{dealer}", self.config.epoch).as_bytes(),
        ));
        let generator = Dealer::random(
            self.config.sid.clone(),
            self.config.context,
            dealer,
            self.config.params,
            &mut rng,
        )?;
        Ok(generator.share(&mut rng)?)
    }

    pub fn verify_row(
        &self,
        row: &PrivateRow,
        public: &DealerPublicTranscript,
    ) -> Result<(), BeaconError> {
        Ok(par_verify(
            &self.config.sid,
            self.config.context,
            self.config.params,
            row,
            public,
        )?)
    }

    pub fn sign_validation_statement(
        &self,
        signer: u32,
        sequence: u64,
        dealer: u32,
        transcript_id: [u8; 32],
    ) -> Result<ValidationStatement, BeaconError> {
        let key = self
            .validation_keys
            .get(signer as usize)
            .ok_or(BeaconError::InvalidValidation)?;
        Ok(sign_validation_statement(
            &self.config.sid,
            self.config.context,
            signer,
            sequence,
            dealer,
            transcript_id,
            key,
        )?)
    }

    pub fn verify_validation_statement(
        &self,
        statement: &ValidationStatement,
    ) -> Result<(), BeaconError> {
        verify_validation_statement_preparsed(
            self.config.params,
            &self.config.sid,
            self.config.context,
            &self.validation_verifying_keys,
            statement,
        )
        .map_err(BeaconError::from)
    }

    pub(crate) fn assemble_epoch_candidate_preverified(
        &self,
        mut transcripts: Vec<DealerPublicTranscript>,
        mut statements: Vec<ValidationStatement>,
    ) -> Result<(EpochCommand, EpochValidationData), BeaconError> {
        transcripts.sort_by_key(|transcript| transcript.dealer);
        statements.sort_by_key(|statement| (statement.dealer, statement.signer));
        if transcripts.len() < self.config.params.d
            || transcripts.len() > self.config.params.n
            || !transcripts
                .windows(2)
                .all(|pair| pair[0].dealer < pair[1].dealer)
            || !statements
                .windows(2)
                .all(|pair| (pair[0].dealer, pair[0].signer) < (pair[1].dealer, pair[1].signer))
        {
            return Err(BeaconError::InvalidValidation);
        }

        let mut grouped = BTreeMap::<u32, Vec<ValidationStatement>>::new();
        for statement in statements {
            grouped.entry(statement.dealer).or_default().push(statement);
        }
        let selected_dealers = grouped
            .iter()
            .filter(|(_, dealer_statements)| {
                dealer_statements.len() == self.config.params.qc_threshold()
            })
            .map(|(dealer, _)| *dealer)
            .take(self.config.params.d)
            .collect::<Vec<_>>();
        if selected_dealers.len() != self.config.params.d {
            return Err(BeaconError::InvalidValidation);
        }

        let selected_transcripts = selected_dealers
            .iter()
            .map(|dealer| {
                transcripts
                    .iter()
                    .find(|transcript| transcript.dealer == *dealer)
                    .cloned()
                    .ok_or(BeaconError::InvalidValidation)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let selected_statements = selected_dealers
            .iter()
            .flat_map(|dealer| grouped.remove(dealer).unwrap_or_default())
            .collect::<Vec<_>>();
        let mut dealer_certificates = Vec::with_capacity(selected_dealers.len());
        for transcript in &selected_transcripts {
            dealer_certificates.push(build_dealer_certificate(
                self.config.params,
                transcript.dealer,
                transcript.transcript_id(),
                &selected_statements,
            )?);
        }
        let witness = EpochValidationData {
            transcripts: selected_transcripts,
            statements: selected_statements,
            dealer_certificates,
        };
        let command = EpochCommand {
            epoch: self.config.epoch,
            approvals: witness
                .statements
                .chunks(self.config.params.qc_threshold())
                .map(|s| s.to_vec())
                .collect(),
            transcripts: witness
                .transcripts
                .iter()
                .map(certified_transcript)
                .collect(),
        };
        verify_epoch_command(&self.config, &command)?;
        Ok((command, witness))
    }

    pub(crate) fn proposal_from_command(
        &self,
        command: &EpochCommand,
    ) -> Result<Proposal, BeaconError> {
        Ok(Proposal {
            instance: self.config.epoch,
            payload: proposal_payload(command)?,
        })
    }

    pub(crate) fn sign_prepared_decision(
        &self,
        signer: u32,
        statement: &crate::bft::PreparedDecision,
    ) -> Result<DecisionSignature, BeaconError> {
        Ok(self.bft.sign_prepared(signer, statement)?)
    }

    pub(crate) fn verify_prepared_decision(
        &self,
        sender: u32,
        statement: &crate::bft::PreparedDecision,
        signature: &DecisionSignature,
    ) -> Result<(), BeaconError> {
        if signature.signer != sender {
            return Err(BeaconError::InvalidEpoch);
        }
        self.bft.verify_prepared(statement, signature)?;
        Ok(())
    }

    pub(crate) fn certify_epoch_preverified(
        &self,
        command: EpochCommand,
        validation_witness: EpochValidationData,
        mut signatures: Vec<DecisionSignature>,
    ) -> Result<CertifiedEpoch, BeaconError> {
        let proposal = self.proposal_from_command(&command)?;
        signatures.sort_by_key(|signature| signature.signer);
        if signatures.len() != self.config.params.qc_threshold()
            || signatures
                .windows(2)
                .any(|pair| pair[0].signer >= pair[1].signer)
            || signatures
                .iter()
                .any(|signature| signature.signer as usize >= self.config.params.n)
        {
            return Err(BeaconError::InvalidEpoch);
        }
        let decision_certificate = DecisionCertificate {
            epoch: self.config.epoch,
            instance: proposal.instance,
            proposal_digest: proposal_digest(&proposal),
            signatures,
        };
        Ok(CertifiedEpoch {
            epoch_certificate: EpochCertificate {
                command,
                decision_certificate,
            },
            validation_witness,
        })
    }

    pub(crate) fn build_node_preverified(
        &self,
        id: u32,
        certified_epoch: CertifiedEpoch,
        mut rows: BTreeMap<u32, PrivateRow>,
        store_path: impl AsRef<Path>,
    ) -> Result<BeaconNode, BeaconError> {
        let selected = certified_epoch
            .epoch_certificate
            .command
            .transcripts
            .iter()
            .map(|entry| entry.dealer)
            .collect::<BTreeSet<_>>();
        rows.retain(|dealer, _| selected.contains(dealer));
        BeaconNode::new_preverified(
            id,
            self.config.clone(),
            certified_epoch,
            self.validation_keys[id as usize].clone(),
            rows,
            store_path.as_ref().to_path_buf(),
        )
    }
}
