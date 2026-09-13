//! Authenticated, unsigned reconstruction messages and durable outputs.

use super::SilkProtocol;
use crate::{BeaconError, BeaconNode, ReconstructionMessage};

pub const RECONSTRUCTION_PROTOCOL: &str = "silk/beacon/reconstruction/v2";

pub struct VerifiedReconstructionMessage {
    context: [u8; 32],
    index: u32,
    sender: u32,
    message: ReconstructionMessage,
}

impl SilkProtocol {
    pub fn accept_reconstruction_candidate(
        &self,
        node: &BeaconNode,
        index: u32,
        sender: u32,
        message: ReconstructionMessage,
    ) -> Result<VerifiedReconstructionMessage, BeaconError> {
        if message.sender != sender || message.index != index {
            return Err(BeaconError::InvalidReconstruction);
        }
        node.verify_reconstruction_envelope(&message)?;
        Ok(VerifiedReconstructionMessage {
            context: self.verification_context(),
            index,
            sender,
            message,
        })
    }

    pub fn accept_reconstruction_preverified_batch(
        &self,
        node: &mut BeaconNode,
        index: u32,
        messages: Vec<VerifiedReconstructionMessage>,
    ) -> Result<Option<[u8; 32]>, BeaconError> {
        if messages.is_empty()
            || messages.iter().any(|message| {
                message.context != self.verification_context()
                    || message.index != index
                    || message.sender != message.message.sender
            })
        {
            return Err(BeaconError::InvalidReconstruction);
        }
        node.receive_reconstruction_batch_preverified(
            self.verification_context(),
            messages
                .into_iter()
                .map(|message| message.message)
                .collect(),
        )
    }
}
