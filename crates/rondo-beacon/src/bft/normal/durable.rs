//! Write-ahead vote intents, decided blocks, replay, and committed-prefix pruning.

use std::path::Path;

use protocol_support::store::ProtocolStore;

use super::*;

impl NormalReplica {
    pub fn reload(
        params: BftParams,
        node_id: u32,
        seed: [u8; 32],
        initial_height: u64,
        store_path: impl AsRef<Path>,
    ) -> Result<Self, BftError> {
        let mut replica = Self::new(params, node_id, seed, initial_height)?;
        let records = ProtocolStore::replay::<DurableRecord>(store_path.as_ref())
            .map_err(|error| BftError::Store(error.to_string()))?;
        for record in records {
            replica.apply_record(record)?;
        }
        Ok(replica)
    }

    pub fn prune_committed_prefix_durable(
        &mut self,
        store_path: impl AsRef<Path>,
    ) -> Result<usize, BftError> {
        let delivered_height = self.state.next_height.saturating_sub(1);
        persist(
            store_path.as_ref(),
            &DurableRecord::Pruned { delivered_height },
        )?;
        Ok(self.prune(delivered_height))
    }

    fn apply_record(&mut self, record: DurableRecord) -> Result<(), BftError> {
        match record {
            DurableRecord::VoteIntent {
                proposal,
                kind,
                phase_qc,
            } => self.apply_vote_intent(*proposal, kind, phase_qc),
            DurableRecord::Decided(proof) => self.apply_decision(*proof),
            DurableRecord::Pruned { delivered_height } => {
                if delivered_height != self.state.next_height.saturating_sub(1) {
                    return Err(BftError::InvalidBlock);
                }
                self.prune(delivered_height);
                Ok(())
            }
        }
    }

    fn prune(&mut self, delivered_height: u64) -> usize {
        let before = self.delivered.len();
        self.delivered
            .retain(|height, _| *height >= delivered_height);
        before.saturating_sub(self.delivered.len())
    }
}

pub(super) fn persist(path: &Path, record: &DurableRecord) -> Result<(), BftError> {
    ProtocolStore::open(path)
        .and_then(|mut store| store.persist(record))
        .map(|_| ())
        .map_err(|error| BftError::Store(error.to_string()))
}
