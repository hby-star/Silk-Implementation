//! Rondo-BFT pipeline identities, quorum collection, and slot bookkeeping.

use super::*;

#[derive(Debug)]
pub(super) struct RondoSlotProtocols {
    pub(super) proposal: String,
    pub(super) prepare_vote: String,
    pub(super) precommit_vote: String,
    pub(super) commit_vote: String,
    pub(super) prepare_qc: String,
    pub(super) precommit_qc: String,
    pub(super) commit_qc: String,
}

impl RondoSlotProtocols {
    pub(super) fn new(sample: u32, slot: usize) -> Self {
        let proposal = scoped_protocol(PROPOSAL_PROTOCOL, sample, slot as u32);
        let vote = scoped_protocol(VOTE_PROTOCOL, sample, slot as u32);
        let qc = scoped_protocol(QC_PROTOCOL, sample, slot as u32);
        Self {
            proposal,
            prepare_vote: format!("{vote}/prepare"),
            precommit_vote: format!("{vote}/precommit"),
            commit_vote: format!("{vote}/commit"),
            prepare_qc: format!("{qc}/prepare"),
            precommit_qc: format!("{qc}/precommit"),
            commit_qc: format!("{qc}/commit"),
        }
    }
}

pub(super) fn rondo_height(epoch: u64, slots: usize, slot: usize) -> Result<u64, DistributedError> {
    epoch
        .checked_sub(1)
        .and_then(|epoch| epoch.checked_mul(slots as u64))
        .and_then(|height| height.checked_add(slot as u64 + 1))
        .ok_or_else(|| DistributedError::Protocol("Rondo BFT height overflow".into()))
}

pub(super) fn pipeline_ref<'a, T>(
    values: &'a [Option<T>],
    slot: usize,
    value_name: &str,
) -> Result<&'a T, DistributedError> {
    values.get(slot).and_then(Option::as_ref).ok_or_else(|| {
        DistributedError::Protocol(format!(
            "Rondo pipeline wave is missing {value_name} for slot {slot}"
        ))
    })
}

#[allow(clippy::too_many_arguments)]
pub(super) fn collect_vote_qc(
    shared: &SharedNode,
    protocol: &str,
    sample: u32,
    threshold: usize,
    timeout: Duration,
    replica: &NormalReplica,
    proposal: &Proposal,
    kind: QcKind,
) -> Result<QuorumCertificate, DistributedError> {
    let block_hash = proposal.block.hash();
    let votes =
        collect_protocol_valid(
            shared,
            protocol,
            threshold,
            timeout,
            |sender, message| match message {
                DistributedMessage::RondoVote {
                    sample: message_sample,
                    vote,
                } if message_sample == sample
                    && vote.signer == sender
                    && vote.kind == kind
                    && vote.block_hash == block_hash
                    && vote.view == proposal.block.view
                    && vote.height == proposal.block.height =>
                {
                    Ok(Some(vote))
                }
                _ => Ok(None),
            },
        )?
        .into_messages(protocol)
        .into_iter()
        .collect::<Vec<_>>();
    replica
        .aggregate_qc_checked(proposal, kind, &votes)
        .map_err(protocol_error)
}
