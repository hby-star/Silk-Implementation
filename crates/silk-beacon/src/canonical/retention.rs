use super::*;

impl BeaconNode {
    pub fn compact_index(&mut self, index: u32) -> Result<GcStats, BeaconError> {
        self.compact_index_with_mode(index, GcMode::Enabled)
    }

    pub(super) fn compact_index_with_mode(
        &mut self,
        index: u32,
        mode: GcMode,
    ) -> Result<GcStats, BeaconError> {
        self.require_index(index)?;
        if !self.durable.outputs.contains_key(&index) {
            return Err(BeaconError::InvalidState);
        }
        let before = self.hot_state_bytes()?;
        let persistent_before = self.stored_bytes();
        let mut discarded = 0u64;
        if mode == GcMode::Enabled {
            discarded += remove_matching_index(&mut self.matching, index);
            discarded += remove_pending_index(&mut self.pending_reconstruction, index);
        }
        let after = self.hot_state_bytes()?;
        let persistent_after = self.stored_bytes();
        Ok(gc_stats(
            mode,
            before,
            after,
            persistent_before,
            persistent_after,
            discarded,
            0,
        ))
    }

    pub fn retire_epoch(&mut self, watermark: u64) -> Result<GcStats, BeaconError> {
        self.retire_epoch_with_mode(watermark, GcMode::Enabled)
    }

    pub(super) fn retire_epoch_with_mode(
        &mut self,
        watermark: u64,
        mode: GcMode,
    ) -> Result<GcStats, BeaconError> {
        let initial_before = self.total_state_bytes()?;
        let initial_persistent = self.stored_bytes();
        if let Some(existing) = self.durable.retention_watermark {
            if watermark < existing {
                return Err(BeaconError::InvalidState);
            }
            if watermark == existing {
                return Ok(gc_stats(
                    mode,
                    initial_before,
                    initial_before,
                    initial_persistent,
                    initial_persistent,
                    0,
                    0,
                ));
            }
            self.persist(&DurableRecord::RetentionWatermark {
                epoch: watermark,
                mode,
            })?;
            self.durable.retention_watermark = Some(watermark);
            let persistent_after = self.stored_bytes();
            return Ok(gc_stats(
                mode,
                initial_before,
                initial_before,
                initial_persistent,
                persistent_after,
                0,
                0,
            ));
        }
        let required = self
            .config
            .epoch
            .saturating_add(self.config.reconstruction_window);
        if self.durable.outputs.len() != self.config.params.l || watermark < required {
            return Err(BeaconError::InvalidState);
        }
        if (1..=self.config.params.l as u32).any(|index| !self.durable.outputs.contains_key(&index))
        {
            return Err(BeaconError::InvalidState);
        }
        let before = self.total_state_bytes()?;
        let persistent_before = self.stored_bytes();
        let discarded = (self.retained_rows.len()
            + self.matching.len()
            + self.pending_reconstruction.len()
            + self.durable.qrout.len()
            + self.durable.released.len()) as u64;
        self.persist(&DurableRecord::RetentionWatermark {
            epoch: watermark,
            mode,
        })?;
        self.durable.retention_watermark = Some(watermark);
        if mode == GcMode::Enabled {
            self.retained_rows.clear();
            self.matching.clear();
            self.pending_reconstruction.clear();
            self.reconstruction_plans.clear();
            self.durable.qrout.clear();
            self.durable.released.clear();
        }
        let after = self.total_state_bytes()?;
        let persistent_after = self.stored_bytes();
        Ok(gc_stats(
            mode,
            before,
            after,
            persistent_before,
            persistent_after,
            if mode == GcMode::Enabled {
                discarded
            } else {
                0
            },
            0,
        ))
    }

    fn stored_bytes(&self) -> u64 {
        std::fs::metadata(&self.store_path).map_or(0, |metadata| metadata.len())
    }

    pub(super) fn persist(&self, record: &DurableRecord) -> Result<(), BeaconError> {
        ProtocolStore::open(&self.store_path)?.persist(record)?;
        Ok(())
    }

    pub(super) fn require_index(&self, index: u32) -> Result<(), BeaconError> {
        if index == 0 || index as usize > self.config.params.l {
            Err(BeaconError::InvalidSlot)
        } else {
            Ok(())
        }
    }

    pub(super) fn require_later_index(&self, index: u32) -> Result<(), BeaconError> {
        self.require_index(index)?;
        if index == 1 {
            Err(BeaconError::InvalidRelease)
        } else {
            Ok(())
        }
    }

    pub(super) fn ensure_active(&self) -> Result<(), BeaconError> {
        if self.durable.retention_watermark.is_some() {
            Err(BeaconError::InvalidState)
        } else {
            Ok(())
        }
    }

    pub(super) fn hot_state_bytes(&self) -> Result<u64, BeaconError> {
        Ok(wire_len(&(&self.matching, &self.pending_reconstruction))?)
    }

    pub(super) fn total_state_bytes(&self) -> Result<u64, BeaconError> {
        Ok(wire_len(&(
            &self.retained_rows,
            &self.durable,
            &self.matching,
            &self.pending_reconstruction,
            &self.release_evidence,
        ))?)
    }
}
