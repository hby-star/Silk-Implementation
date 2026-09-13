//! Quorum Release for every noninitial beacon round.

use super::SilkProtocol;
use crate::{BeaconError, BeaconNode, QrSupport, ReconstructionMessage, ReleaseAnnouncement};

pub const RELEASE_PROTOCOL: &str = "silk/beacon/signed-release/v3";

impl SilkProtocol {
    pub fn accept_release(
        &self,
        node: &mut BeaconNode,
        index: u32,
        sender: u32,
        announcement: ReleaseAnnouncement,
    ) -> Result<Option<ReconstructionMessage>, BeaconError> {
        if announcement.sender != sender
            || announcement.round
                != (self.committee.config.epoch - 1) * self.params().l as u64 + u64::from(index - 1)
        {
            return Err(BeaconError::InvalidRelease);
        }
        node.receive_release(announcement)
    }

    pub fn finish_releases(
        &self,
        node: &BeaconNode,
        index: u32,
        reconstruction: Option<ReconstructionMessage>,
    ) -> Result<(ReconstructionMessage, QrSupport), BeaconError> {
        let support = node.qr_support(index);
        if support.matching_senders.len() < self.params().qc_threshold()
            || support.guaranteed_correct_predecessor_completers
                < self.params().n - 2 * self.params().t
        {
            return Err(BeaconError::InvalidRelease);
        }
        Ok((reconstruction.ok_or(BeaconError::InvalidRelease)?, support))
    }
}
