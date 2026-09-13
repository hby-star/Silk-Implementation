use super::*;

/// Verify matching public signatures only. No Mulberry transcript,
/// reconstruction points or BFT decision proof is required.
pub fn verify_beacon(
    config: &BeaconConfiguration,
    releases: &[ReleaseAnnouncement],
) -> Result<(), BeaconError> {
    config.verify()?;
    if releases.len() != config.params.qc_threshold() {
        return Err(BeaconError::InvalidBeaconCertificate);
    }
    let first = &releases[0];
    let first_round = (config.epoch - 1) * config.params.l as u64 + 1;
    let last_round = config.epoch * config.params.l as u64;
    let mut senders = BTreeSet::new();
    for release in releases {
        if release.sid != config.sid
            || release.epoch != config.epoch
            || !(first_round..=last_round).contains(&release.round)
            || release.round != first.round
            || release.tau != first.tau
            || release.output != first.output
            || release.sender as usize >= config.params.n
            || !senders.insert(release.sender)
        {
            return Err(BeaconError::InvalidBeaconCertificate);
        }
        crypto_primitives::mldsa::verify(
            &config.validation_public_keys[release.sender as usize],
            &release.signature,
            &release_message(release)?,
        )
        .map_err(|_| BeaconError::InvalidBeaconCertificate)?;
    }
    Ok(())
}

pub(crate) fn certified_transcript(public: &DealerPublicTranscript) -> CertifiedTranscript {
    CertifiedTranscript {
        dealer: public.dealer,
        transcript_id: public.transcript_id(),
    }
}

pub(crate) fn proposal_payload(command: &EpochCommand) -> Result<Vec<u8>, BeaconError> {
    Ok(canonical_serialize(&("silk/epoch-command/v2", command))?)
}

pub(super) fn qr_digest(
    config: &BeaconConfiguration,
    tau: [u8; 32],
    index: u32,
    previous: [u8; 32],
) -> [u8; 32] {
    hash_len_prefixed(
        b"silk/qr/v2",
        &[
            &config.sid,
            &config.context.config_digest,
            &((config.epoch - 1) * config.params.l as u64 + u64::from(index)).to_be_bytes(),
            &tau,
            &previous,
        ],
    )
}

pub(super) fn beacon_output(
    config: &BeaconConfiguration,
    tau: [u8; 32],
    index: u32,
    aggregate: curve25519_dalek::scalar::Scalar,
) -> [u8; 32] {
    hash_len_prefixed(
        b"silk/beacon-output/v2",
        &[
            &config.sid,
            &config.context.config_digest,
            &config.epoch.to_be_bytes(),
            &((config.epoch - 1) * config.params.l as u64 + u64::from(index)).to_be_bytes(),
            &tau,
            &aggregate.to_bytes(),
        ],
    )
}

pub(super) fn release_message(release: &ReleaseAnnouncement) -> Result<Vec<u8>, BeaconError> {
    Ok(canonical_serialize(&(
        "silk/release/v3",
        &release.sid,
        release.epoch,
        release.round,
        release.tau,
        release.output,
    ))?)
}

pub(super) fn transcript_for(
    certified: &CertifiedEpoch,
    dealer: u32,
) -> Result<&DealerPublicTranscript, BeaconError> {
    certified
        .validation_witness
        .transcripts
        .iter()
        .find(|transcript| transcript.dealer == dealer)
        .ok_or(BeaconError::InvalidValidation)
}

pub(super) fn remove_matching_index(
    values: &mut BTreeMap<(u32, [u8; 32]), BTreeSet<u32>>,
    index: u32,
) -> u64 {
    let keys = values
        .keys()
        .filter(|(stored_index, _)| *stored_index == index)
        .copied()
        .collect::<Vec<_>>();
    let mut removed = 0;
    for key in keys {
        if let Some(value) = values.remove(&key) {
            removed += value.len() as u64;
        }
    }
    removed
}

pub(super) fn remove_pending_index(
    values: &mut BTreeMap<u32, BTreeMap<u32, ReconstructionMessage>>,
    index: u32,
) -> u64 {
    values
        .remove(&index)
        .map_or(0, |messages| messages.len() as u64)
}

pub(super) fn gc_stats(
    mode: GcMode,
    before_bytes: u64,
    after_bytes: u64,
    persistent_before_bytes: u64,
    persistent_after_bytes: u64,
    discarded_objects: u64,
    retained_due_to_service_window_bytes: u64,
) -> GcStats {
    GcStats {
        mode,
        before_bytes,
        after_bytes,
        reclaimed_bytes: before_bytes.saturating_sub(after_bytes),
        discarded_objects,
        persistent_before_bytes,
        persistent_after_bytes,
        persistent_bytes_written: persistent_after_bytes.saturating_sub(persistent_before_bytes),
        retained_due_to_service_window_bytes,
    }
}

pub fn verify_certified_epoch(
    config: &BeaconConfiguration,
    certified: &CertifiedEpoch,
) -> Result<(), BeaconError> {
    verify_epoch_certificate(config, &certified.epoch_certificate)?;
    verify_validation_witness(
        config,
        &certified.epoch_certificate.command,
        &certified.validation_witness,
    )
}

pub fn verify_epoch_certificate(
    config: &BeaconConfiguration,
    certificate: &EpochCertificate,
) -> Result<(), BeaconError> {
    verify_epoch_command(config, &certificate.command)?;
    let proposal = Proposal {
        instance: certificate.command.epoch,
        payload: proposal_payload(&certificate.command)?,
    };
    verify_decision_certificate(
        BftParams::new(config.params.n, config.params.t)?,
        &config.decision_public_keys,
        config.epoch,
        &proposal,
        &certificate.decision_certificate,
    )?;
    Ok(())
}

pub fn verify_epoch_command(
    config: &BeaconConfiguration,
    command: &EpochCommand,
) -> Result<(), BeaconError> {
    config.verify()?;
    if command.epoch != config.epoch
        || command.approvals.len() != config.params.d
        || command.transcripts.len() != config.params.d
        || !command
            .transcripts
            .windows(2)
            .all(|pair| pair[0].dealer < pair[1].dealer)
        || command
            .transcripts
            .iter()
            .any(|entry| entry.dealer as usize >= config.params.n)
    {
        return Err(BeaconError::InvalidEpoch);
    }
    for (entry, approvals) in command.transcripts.iter().zip(&command.approvals) {
        if approvals.len() != config.params.qc_threshold()
            || approvals
                .windows(2)
                .any(|pair| pair[0].signer >= pair[1].signer)
            || approvals.iter().any(|approval| {
                approval.dealer != entry.dealer
                    || approval.transcript_id != entry.transcript_id
                    || approval.signer as usize >= config.params.n
            })
        {
            return Err(BeaconError::InvalidValidation);
        }
    }
    Ok(())
}

fn verify_validation_witness(
    config: &BeaconConfiguration,
    command: &EpochCommand,
    witness: &EpochValidationData,
) -> Result<(), BeaconError> {
    if witness.transcripts.len() != config.params.d
        || witness.dealer_certificates.len() != config.params.d
        || witness.statements.len() != config.params.d * config.params.qc_threshold()
    {
        return Err(BeaconError::InvalidValidation);
    }

    if command
        .approvals
        .iter()
        .flatten()
        .cloned()
        .collect::<Vec<_>>()
        != witness.statements
    {
        return Err(BeaconError::InvalidValidation);
    }
    let mut transcript_by_dealer = BTreeMap::new();
    for transcript in &witness.transcripts {
        verify_public_transcript(config.params, transcript)?;
        if transcript.sid != config.sid
            || transcript.context != config.context
            || transcript_by_dealer
                .insert(transcript.dealer, transcript)
                .is_some()
        {
            return Err(BeaconError::InvalidValidation);
        }
    }
    if command.transcripts.iter().any(|entry| {
        transcript_by_dealer
            .get(&entry.dealer)
            .is_none_or(|transcript| transcript.transcript_id() != entry.transcript_id)
    }) {
        return Err(BeaconError::InvalidValidation);
    }

    let selected = command
        .transcripts
        .iter()
        .map(|entry| entry.dealer)
        .collect::<BTreeSet<_>>();
    let mut statement_signers = BTreeSet::new();
    let mut statement_counts = BTreeMap::<u32, usize>::new();
    for statement in &witness.statements {
        if !selected.contains(&statement.dealer)
            || !statement_signers.insert((statement.dealer, statement.signer))
        {
            return Err(BeaconError::InvalidValidation);
        }
        verify_validation_statement(
            config.params,
            &config.sid,
            config.context,
            &config.validation_public_keys,
            statement,
        )?;
        *statement_counts.entry(statement.dealer).or_default() += 1;
    }
    if selected
        .iter()
        .any(|dealer| statement_counts.get(dealer).copied() != Some(config.params.qc_threshold()))
    {
        return Err(BeaconError::InvalidValidation);
    }

    let mut certified = BTreeSet::new();
    for certificate in &witness.dealer_certificates {
        if !certified.insert(certificate.dealer)
            || !selected.contains(&certificate.dealer)
            || certificate.references.len() != config.params.qc_threshold()
        {
            return Err(BeaconError::InvalidValidation);
        }
        let transcript = transcript_by_dealer
            .get(&certificate.dealer)
            .ok_or(BeaconError::InvalidValidation)?;
        if transcript.transcript_id() != certificate.transcript_id
            || verify_dealer_certificate(config.params, certificate, &witness.statements)?.len()
                != config.params.qc_threshold()
        {
            return Err(BeaconError::InvalidValidation);
        }
    }
    Ok(())
}

pub(super) fn epoch_tau(config: &BeaconConfiguration, command: &EpochCommand) -> [u8; 32] {
    let encoded = canonical_serialize(&("silk/epoch-command/v2", command))
        .expect("epoch command has a canonical encoding");
    hash_len_prefixed(
        b"silk/epoch/v2",
        &[&config.sid, &config.context.config_digest, &encoded],
    )
}

pub(super) fn registry_digest(validation: &[Vec<u8>], decision: &[Vec<u8>]) -> [u8; 32] {
    hash(
        &canonical_serialize(&("silk/committee-registry/v2", validation, decision))
            .expect("registry serializes"),
    )
}
