//! Four-phase Rondo-BFT pipeline with overlapped aggregate reconstruction.

use super::*;

pub(super) struct PipelineResult {
    pub(super) outputs: Vec<[u8; 32]>,
    pub(super) fallback_service: super::reconstruct::FallbackService,
    pub(super) committed_requests: usize,
}

#[allow(clippy::too_many_arguments)]
pub(super) fn run_pipeline(
    shared: &SharedNode,
    config: &AutonomousConfig,
    logger: &mut dyn NodeObserver,
    process_start: &Instant,
    sample: u32,
    epoch: u64,
    mut requests: Vec<::rondo_beacon::bft::Request>,
    initial_epoch: RondoEpoch,
    preparation: &RondoPreparation,
) -> Result<PipelineResult, DistributedError> {
    let mut epoch_state = Arc::new(initial_epoch);
    let mut fallback_service = None;
    let bft_store = config
        .node
        .store_root
        .join(format!("rondo-bft-{sample}.bin"));
    let mut replica = epoch_state
        .bft_replica(config.node.node_id, config.node.seed)
        .map_err(protocol_error)?;
    let slots = requests.len();
    let protocols = (0..slots)
        .map(|slot| RondoSlotProtocols::new(sample, slot))
        .collect::<Vec<_>>();
    let mut proposals: Vec<Option<Proposal>> = vec![None; slots];
    let mut prepare_qcs: Vec<Option<QuorumCertificate>> = vec![None; slots];
    let mut precommit_qcs: Vec<Option<QuorumCertificate>> = vec![None; slots];
    let mut commit_qcs: Vec<Option<QuorumCertificate>> = vec![None; slots];
    let mut decisions: Vec<Option<DecisionProof>> = vec![None; slots];
    let mut outputs: Vec<Option<[u8; 32]>> = vec![None; slots];
    let mut pending_reconstructions = BTreeSet::new();
    let mut committed_requests = 0;
    let view = 0;
    let leader = replica.leader(view);

    for wave in pipeline_waves(slots) {
        measured_for(
            shared,
            config,
            logger,
            process_start,
            sample,
            "rondo-beacon",
            "rondo-bft-pipeline-dispatch",
            None,
            None,
            || {
                if config.node.node_id != leader {
                    return Ok(((), None));
                }

                if let Some(slot) = wave.decide_slot {
                    let qc = pipeline_ref(&commit_qcs, slot, "commit QC")?;
                    broadcast_same(
                        shared,
                        config,
                        &protocols[slot].commit_qc,
                        DistributedMessage::RondoQc {
                            sample,
                            qc: qc.clone(),
                        },
                        config.node.n as u32,
                    )?;
                }

                if let Some(slot) = wave.commit_slot {
                    let qc = pipeline_ref(&precommit_qcs, slot, "precommit QC")?;
                    broadcast_same(
                        shared,
                        config,
                        &protocols[slot].precommit_qc,
                        DistributedMessage::RondoQc {
                            sample,
                            qc: qc.clone(),
                        },
                        config.node.n as u32,
                    )?;
                }

                if let Some(slot) = wave.precommit_slot {
                    let proposal = pipeline_ref(&proposals, slot, "proposal")?;
                    let qc = pipeline_ref(&prepare_qcs, slot, "prepare QC")?;
                    broadcast_same(
                        shared,
                        config,
                        &protocols[slot].prepare_qc,
                        DistributedMessage::RondoQc {
                            sample,
                            qc: qc.clone(),
                        },
                        config.node.n as u32,
                    )?;

                    // Advance the leader's highQC before constructing the next
                    // proposal. Its vote travels through the same inbox path as
                    // every follower vote and is collected in the phase below.
                    let vote = replica
                        .vote(proposal, QcKind::PreCommit, Some(qc), |_| true, &bft_store)
                        .map_err(protocol_error)?;
                    send(
                        shared,
                        config,
                        &protocols[slot].precommit_vote,
                        leader,
                        DistributedMessage::RondoVote { sample, vote },
                    )?;
                }

                if let Some(slot) = wave.propose_slot {
                    let height = rondo_height(epoch, slots, slot)?;
                    let proposal = replica
                        .propose(view, height, requests[slot].clone())
                        .map_err(protocol_error)?;
                    broadcast_same(
                        shared,
                        config,
                        &protocols[slot].proposal,
                        DistributedMessage::RondoProposal {
                            sample,
                            proposal: proposal.clone(),
                            publics: if slot == 0 {
                                epoch_state.public_materials()
                            } else {
                                Vec::new()
                            },
                        },
                        config.node.n as u32,
                    )?;
                }
                Ok(((), None))
            },
        )?;

        if let Some(slot) = wave.decide_slot {
            let proposal = pipeline_ref(&proposals, slot, "proposal")?;
            let prepare_qc = pipeline_ref(&prepare_qcs, slot, "prepare QC")?;
            let precommit_qc = pipeline_ref(&precommit_qcs, slot, "precommit QC")?;
            let proof = measured_for(
                shared,
                config,
                logger,
                process_start,
                sample,
                "rondo-beacon",
                "rondo-bft-decide",
                Some(slot as u32),
                Some("bft-finality"),
                || {
                    let messages = take_protocol(
                        shared,
                        &protocols[slot].commit_qc,
                        1,
                        Duration::from_secs(300),
                    )?;
                    let (sender, commit_qc) = decode_one(
                        messages,
                        sample,
                        "Rondo commit QC",
                        |message| match message {
                            DistributedMessage::RondoQc { sample, qc } => Some((sample, qc)),
                            _ => None,
                        },
                    )?;
                    if sender != leader || commit_qc.kind != QcKind::Commit {
                        return Err(DistributedError::Protocol(
                            "Rondo decide phase QC context mismatch".into(),
                        ));
                    }
                    let proof = replica
                        .decide(proposal, prepare_qc, precommit_qc, &commit_qc, &bft_store)
                        .map_err(protocol_error)?;
                    Ok((proof, Some(commit_qc.block_hash)))
                },
            )?;
            if proof.block().request != requests[slot] {
                return Err(DistributedError::Protocol(
                    "Rondo decided request mismatch".into(),
                ));
            }
            decisions[slot] = Some(proof);
            broadcast_aggregate_share(
                shared,
                config,
                logger,
                process_start,
                sample,
                slot as u32,
                pipeline_ref(&decisions, slot, "decision proof")?,
                epoch_state.as_ref(),
            )?;
            pending_reconstructions.insert(slot);
            committed_requests += 1;
        }

        if let Some(slot) = wave.commit_slot {
            let proposal = pipeline_ref(&proposals, slot, "proposal")?;
            let (qc, commit_qc) = measured_for(
                shared,
                config,
                logger,
                process_start,
                sample,
                "rondo-beacon",
                "rondo-bft-commit",
                Some(slot as u32),
                None,
                || {
                    let messages = take_protocol(
                        shared,
                        &protocols[slot].precommit_qc,
                        1,
                        Duration::from_secs(300),
                    )?;
                    let (sender, qc) = decode_one(
                        messages,
                        sample,
                        "Rondo precommit QC",
                        |message| match message {
                            DistributedMessage::RondoQc { sample, qc } => Some((sample, qc)),
                            _ => None,
                        },
                    )?;
                    if sender != leader || qc.kind != QcKind::PreCommit {
                        return Err(DistributedError::Protocol(
                            "Rondo commit phase QC context mismatch".into(),
                        ));
                    }
                    let vote = replica
                        .vote(proposal, QcKind::Commit, Some(&qc), |_| true, &bft_store)
                        .map_err(protocol_error)?;
                    send(
                        shared,
                        config,
                        &protocols[slot].commit_vote,
                        leader,
                        DistributedMessage::RondoVote { sample, vote },
                    )?;
                    if config.node.node_id != leader {
                        return Ok(((qc, None), None));
                    }
                    let commit_qc = collect_vote_qc(
                        shared,
                        &protocols[slot].commit_vote,
                        sample,
                        config.node.n - config.node.t,
                        Duration::from_secs(300),
                        &replica,
                        proposal,
                        QcKind::Commit,
                    )?;
                    Ok(((qc, Some(commit_qc)), None))
                },
            )?;
            precommit_qcs[slot] = Some(qc);
            commit_qcs[slot] = commit_qc;
        }

        if let Some(slot) = wave.precommit_slot {
            let proposal = pipeline_ref(&proposals, slot, "proposal")?;
            let (qc, precommit_qc) = measured_for(
                shared,
                config,
                logger,
                process_start,
                sample,
                "rondo-beacon",
                "rondo-bft-precommit",
                Some(slot as u32),
                None,
                || {
                    let messages = take_protocol(
                        shared,
                        &protocols[slot].prepare_qc,
                        1,
                        Duration::from_secs(300),
                    )?;
                    let (sender, qc) = decode_one(
                        messages,
                        sample,
                        "Rondo prepare QC",
                        |message| match message {
                            DistributedMessage::RondoQc { sample, qc } => Some((sample, qc)),
                            _ => None,
                        },
                    )?;
                    if sender != leader || qc.kind != QcKind::Prepare {
                        return Err(DistributedError::Protocol(
                            "Rondo precommit phase QC context mismatch".into(),
                        ));
                    }
                    if config.node.node_id != leader {
                        let vote = replica
                            .vote(proposal, QcKind::PreCommit, Some(&qc), |_| true, &bft_store)
                            .map_err(protocol_error)?;
                        send(
                            shared,
                            config,
                            &protocols[slot].precommit_vote,
                            leader,
                            DistributedMessage::RondoVote { sample, vote },
                        )?;
                        return Ok(((qc, None), None));
                    }
                    let precommit_qc = collect_vote_qc(
                        shared,
                        &protocols[slot].precommit_vote,
                        sample,
                        config.node.n - config.node.t,
                        Duration::from_secs(300),
                        &replica,
                        proposal,
                        QcKind::PreCommit,
                    )?;
                    Ok(((qc, Some(precommit_qc)), None))
                },
            )?;
            prepare_qcs[slot] = Some(qc);
            precommit_qcs[slot] = precommit_qc;
        }

        if let Some(slot) = wave.propose_slot {
            let proposal = measured_for(
                shared,
                config,
                logger,
                process_start,
                sample,
                "rondo-beacon",
                "rondo-bft-propose",
                Some(slot as u32),
                None,
                || {
                    let messages = take_protocol(
                        shared,
                        &protocols[slot].proposal,
                        1,
                        Duration::from_secs(300),
                    )?;
                    let (sender, (proposal, publics)) = decode_one(
                        messages,
                        sample,
                        "Rondo proposal",
                        |message| match message {
                            DistributedMessage::RondoProposal {
                                sample,
                                proposal,
                                publics,
                            } => Some((sample, (proposal, publics))),
                            _ => None,
                        },
                    )?;
                    if sender != leader || proposal.leader != leader {
                        return Err(DistributedError::Protocol(
                            "Rondo proposal context mismatch".into(),
                        ));
                    }
                    if slot == 0 {
                        epoch_state =
                            Arc::new(preparation.proposal_epoch(&proposal.block.request, publics)?);
                        requests = epoch_state.requests().map_err(protocol_error)?;
                        fallback_service = Some(start_fallback_service(
                            shared,
                            config,
                            sample,
                            Arc::clone(&epoch_state),
                        )?);
                    } else if !publics.is_empty() {
                        return Err(protocol_error("unexpected later-round public objects"));
                    }
                    Ok((proposal, None))
                },
            )?;
            proposals[slot] = Some(proposal);

            let proposal = pipeline_ref(&proposals, slot, "proposal")?;
            let prepare_qc = measured_for(
                shared,
                config,
                logger,
                process_start,
                sample,
                "rondo-beacon",
                "rondo-bft-prepare-vote",
                Some(slot as u32),
                None,
                || {
                    let vote = replica
                        .vote(
                            proposal,
                            QcKind::Prepare,
                            None,
                            |request| epoch_state.validate_request(request),
                            &bft_store,
                        )
                        .map_err(protocol_error)?;
                    send(
                        shared,
                        config,
                        &protocols[slot].prepare_vote,
                        leader,
                        DistributedMessage::RondoVote { sample, vote },
                    )?;
                    if config.node.node_id != leader {
                        return Ok((None, None));
                    }
                    let prepare_qc = collect_vote_qc(
                        shared,
                        &protocols[slot].prepare_vote,
                        sample,
                        config.node.n - config.node.t,
                        Duration::from_secs(300),
                        &replica,
                        proposal,
                        QcKind::Prepare,
                    )?;
                    Ok((Some(prepare_qc), None))
                },
            )?;
            prepare_qcs[slot] = prepare_qc;
        }

        finalize_ready_reconstructions(
            shared,
            config,
            logger,
            process_start,
            sample,
            epoch_state.as_ref(),
            &decisions,
            &mut pending_reconstructions,
            &mut outputs,
        )?;
    }

    // Only the pipeline tail is allowed to block. Every earlier wave merely
    // harvested aggregate shares that were already complete, allowing WAN
    // reconstruction latency to overlap subsequent BFT work.
    for slot in pending_reconstructions.iter().copied().collect::<Vec<_>>() {
        outputs[slot] = Some(finalize_reconstruction_slot(
            shared,
            config,
            logger,
            process_start,
            sample,
            slot as u32,
            pipeline_ref(&decisions, slot, "decision proof")?,
            epoch_state.as_ref(),
        )?);
        pending_reconstructions.remove(&slot);
    }
    if !pending_reconstructions.is_empty() {
        return Err(DistributedError::Protocol(
            "Rondo reconstruction pipeline did not drain".into(),
        ));
    }

    for (slot, protocol) in protocols.iter().enumerate() {
        discard_protocols(
            shared,
            &BTreeSet::from([
                protocol.prepare_vote.clone(),
                protocol.precommit_vote.clone(),
                protocol.commit_vote.clone(),
                scoped_protocol(AGGREGATE_PROTOCOL, sample, slot as u32),
            ]),
        )?;
    }
    let outputs = outputs
        .into_iter()
        .enumerate()
        .map(|(slot, output)| {
            output.ok_or_else(|| {
                DistributedError::Protocol(format!(
                    "Rondo reconstruction pipeline is missing output for slot {slot}"
                ))
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    if committed_requests != config.node.slots {
        return Err(DistributedError::Protocol(format!(
            "Rondo-BFT committed {committed_requests}/{} requests",
            config.node.slots
        )));
    }
    measured_for(
        shared,
        config,
        logger,
        process_start,
        sample,
        "rondo-beacon",
        "rondo-bft-retention-gc",
        None,
        None,
        || {
            replica
                .prune_committed_prefix_durable(&bft_store)
                .map_err(protocol_error)?;
            Ok(((), None))
        },
    )?;
    Ok(PipelineResult {
        fallback_service: fallback_service
            .ok_or_else(|| protocol_error("Rondo first proposal was not installed"))?,
        outputs,
        committed_requests,
    })
}
