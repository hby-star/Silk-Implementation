use super::*;
use crypto_primitives::mldsa::{sign, verify_with_key};

impl BeaconNode {
    /// Sign each locally completed output once, including the epoch's last output.
    pub fn sign_release(&mut self, index: u32) -> Result<ReleaseAnnouncement, BeaconError> {
        self.ensure_active()?;
        self.require_index(index)?;
        let output = self.output(index).ok_or(BeaconError::InvalidState)?;
        if let Some(existing) = self.durable.signed_releases.get(&index) {
            return Ok(existing.clone());
        }
        let mut announcement = ReleaseAnnouncement {
            sender: self.id,
            sid: self.config.sid.clone(),
            epoch: self.config.epoch,
            round: (self.config.epoch - 1) * self.config.params.l as u64 + u64::from(index),
            tau: self.epoch_digest,
            output,
            signature: Vec::new(),
        };
        announcement.signature = sign(&self.release_key, &release_message(&announcement)?);
        self.persist(&DurableRecord::SignedRelease {
            index,
            announcement: announcement.clone(),
        })?;
        self.durable
            .signed_releases
            .insert(index, announcement.clone());
        self.release_evidence
            .entry(index)
            .or_default()
            .insert(self.id, announcement.clone());
        Ok(announcement)
    }

    pub fn begin_qr(&mut self, index: u32) -> Result<ReleaseAnnouncement, BeaconError> {
        self.require_later_index(index)?;
        self.sign_release(index - 1)
    }

    pub fn receive_release(
        &mut self,
        announcement: ReleaseAnnouncement,
    ) -> Result<Option<ReconstructionMessage>, BeaconError> {
        self.ensure_active()?;
        let index = self.release_index(&announcement)?;
        if self.output(index) != Some(announcement.output) {
            return Err(BeaconError::InvalidState);
        }
        if self
            .release_evidence
            .get(&index)
            .is_some_and(|messages| messages.contains_key(&announcement.sender))
        {
            return Ok(None);
        }
        self.verify_release_envelope(&announcement)?;
        let evidence = self.release_evidence.entry(index).or_default();
        evidence.insert(announcement.sender, announcement);
        if evidence.len() < self.config.params.qc_threshold()
            || index as usize == self.config.params.l
        {
            return Ok(None);
        }
        let next = index + 1;
        if self.durable.qrout.contains_key(&next) {
            return Ok(None);
        }
        let senders = evidence.keys().copied().collect();
        let digest = qr_digest(
            &self.config,
            self.epoch_digest,
            next,
            self.output(index).ok_or(BeaconError::InvalidState)?,
        );
        self.persist(&DurableRecord::QrOut {
            index: next,
            digest,
        })?;
        self.durable.qrout.insert(next, digest);
        self.matching.insert((next, digest), senders);
        Ok(Some(self.create_reconstruction_message(next)?))
    }

    pub(super) fn release_index(
        &self,
        announcement: &ReleaseAnnouncement,
    ) -> Result<u32, BeaconError> {
        let start = (self.config.epoch - 1) * self.config.params.l as u64;
        let index = announcement
            .round
            .checked_sub(start)
            .and_then(|value| u32::try_from(value).ok())
            .ok_or(BeaconError::InvalidRelease)?;
        self.require_index(index)?;
        if announcement.sender as usize >= self.config.params.n
            || announcement.sid != self.config.sid
            || announcement.epoch != self.config.epoch
            || announcement.tau != self.epoch_digest
        {
            return Err(BeaconError::InvalidRelease);
        }
        Ok(index)
    }

    pub(super) fn verify_release_envelope(
        &self,
        announcement: &ReleaseAnnouncement,
    ) -> Result<(), BeaconError> {
        self.release_index(announcement)?;
        verify_with_key(
            &self.release_verifying_keys[announcement.sender as usize],
            &announcement.signature,
            &release_message(announcement)?,
        )
        .map_err(|_| BeaconError::InvalidRelease)
    }
}
