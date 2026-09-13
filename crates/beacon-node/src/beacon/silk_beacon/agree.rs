//! Simple-IT S with dispersed Bracha RBC and transferable epoch evidence.

use super::certificate_service::{CertificateStore, request_scope, response_scope};
use super::materials::first_distinct_materials;
use super::{EpochProtocols, PreparedEpoch, SilkSampleContext};
use crate::beacon::message_flow::{
    discard_protocols, protocol_error, scoped_protocol, take_protocol_available,
};
use crate::beacon::observation::{measured, unix_time_ns};
use crate::beacon::transport::BackgroundSender;
use crate::beacon::{DistributedError, DistributedMessage};
use ::silk_beacon::protocol::proposal_encoding::{EncodedEpochProposal, certificate_id};
use ::silk_beacon::protocol::{
    SilkProtocol, VerifiedCertifiedEpoch, VerifiedDecisionSignature, VerifiedEpochCommand,
    VerifiedProposal,
};
use ::silk_beacon::simple_it::{Action, Body, Params, SimpleIt};
use cpu_time::ThreadTime;
use crypto_primitives::hash::hash_len_prefixed;
use protocol_support::wire::{canonical_deserialize, canonical_serialize};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::time::{Duration, Instant};

const SIMPLE_IT_PROTOCOL: &str = "silk/beacon/simple-it-s-certificate-references/v2";

struct CertificateFetch {
    peers: Vec<u32>,
    next_peer: usize,
    next_attempt: Instant,
}

impl CertificateFetch {
    fn new(dealer: u32, leader: u32, local: u32, n: usize, now: Instant) -> Self {
        // A leader that proposed these exact IDs already has their bytes and
        // has published them to its service. The issuing dealer may still be
        // completing Prepare, so it is the next fallback, not a readiness gate.
        // Service connections are nonblocking, avoiding serialized handshakes
        // when several replicas fetch from the same known holder.
        let mut peers = Vec::with_capacity(n - 1);
        for peer in [leader, dealer].into_iter().chain(0..n as u32) {
            if peer != local && !peers.contains(&peer) {
                peers.push(peer);
            }
        }
        Self {
            peers,
            next_peer: 0,
            next_attempt: now,
        }
    }

    fn poll(&mut self, now: Instant) -> Option<u32> {
        if now < self.next_attempt {
            return None;
        }
        let peer = self.peers[self.next_peer];
        self.next_peer = (self.next_peer + 1) % self.peers.len();
        self.next_attempt = now + Duration::from_millis(500);
        Some(peer)
    }
}

pub(super) fn agree(
    context: &mut SilkSampleContext<'_>,
    silk: &SilkProtocol,
    protocols: &EpochProtocols,
    prepared: &mut PreparedEpoch,
    store: &CertificateStore,
) -> Result<(VerifiedCertifiedEpoch, Vec<serde_json::Value>), DistributedError> {
    let local = measured(
        context.shared,
        context.config,
        context.logger,
        context.process_start,
        context.sample,
        "epoch-external-validity",
        None,
        None,
        || {
            let validation = silk
                .accept_validation_certificates_preverified(first_distinct_materials(
                    &prepared.certified_materials,
                    context.config.node.t + 1,
                )?)
                .map_err(protocol_error)?;
            let command = silk
                .assemble_epoch_preverified(
                    &prepared
                        .state
                        .0
                        .lock()
                        .map_err(|_| protocol_error("preparation state poisoned"))?
                        .sharing,
                    validation,
                )
                .map_err(protocol_error)?;
            Ok((command, None))
        },
    )?;
    // This wall/CPU/wire span includes coding, canonical checks, proposal
    // validation, protocol work, evidence and ALL queued socket writes.
    // Enqueue is never treated as send completion.
    let network = context.network();
    let (proposal, signatures, trace) = measured(
        context.shared,
        context.config,
        context.logger,
        context.process_start,
        context.sample,
        "epoch-bft-simple-it",
        None,
        None,
        || {
            Ok((
                run_simple_it(network, silk, protocols, prepared, &local, store)?,
                None,
            ))
        },
    )?;
    let digest = proposal.digest();
    let certified = measured(
        context.shared,
        context.config,
        context.logger,
        context.process_start,
        context.sample,
        "epoch-bft-certificate-assemble-persist",
        None,
        Some("epoch-installed"),
        || {
            Ok((
                silk.certify_epoch_preverified(proposal, signatures)
                    .map_err(protocol_error)?,
                Some(digest),
            ))
        },
    )?;
    Ok((certified, trace))
}

type AgreementResult = (
    VerifiedProposal,
    Vec<VerifiedDecisionSignature>,
    Vec<serde_json::Value>,
);

fn run_simple_it(
    network: super::SilkNetworkContext<'_>,
    silk: &SilkProtocol,
    protocols: &EpochProtocols,
    prepared: &PreparedEpoch,
    local: &VerifiedEpochCommand,
    store: &CertificateStore,
) -> Result<AgreementResult, DistributedError> {
    let config = network.config;
    let params = Params::new(config.node.n, config.node.t).map_err(protocol_error)?;
    let scope = scoped_protocol(SIMPLE_IT_PROTOCOL, network.sample, 0);
    let binding = canonical_serialize(&(
        config.run_id.as_str(),
        config.node.seed,
        network.sample,
        config.node.n,
        config.node.t,
        config.node.slots,
    ))?;
    let instance = hash_len_prefixed(b"silk/simple-it/epoch/v1", &[&binding]);
    let encoded = EncodedEpochProposal::encode(local.command()).map_err(protocol_error)?;
    let mut certificates = BTreeMap::new();
    for (entry, material) in &prepared.certified_materials {
        let id = certificate_id(local.command().epoch, entry, material.statements())
            .map_err(protocol_error)?;
        certificates.insert(id, material.statements().to_vec());
    }
    // Publishing does not authorize a proposal. Expansion and the ordinary
    // validator still check all exact bytes and signatures before a BFT vote.
    store
        .lock()
        .map_err(|_| protocol_error("certificate store poisoned"))?
        .extend(certificates.clone());
    let mut core = SimpleIt::new(
        params,
        instance,
        config.node.node_id,
        canonical_serialize(&encoded)?,
    )
    .map_err(protocol_error)?;
    let pump = BackgroundSender::get(network.shared)?;
    let mut work = VecDeque::from(core.start().map_err(protocol_error)?);
    let receivers = (0..params.n as u32).collect::<Vec<_>>();
    let mut proposals = BTreeMap::<[u8; 32], VerifiedProposal>::new();
    let mut candidate_digests = BTreeMap::new();
    let mut pending_candidates = BTreeMap::new();
    let mut requested = BTreeMap::<[u8; 32], CertificateFetch>::new();
    let requests = request_scope(network.sample);
    let responses = response_scope(network.sample);
    let mut pending_signatures =
        BTreeMap::<[u8; 32], BTreeMap<u32, ::silk_beacon::bft::DecisionSignature>>::new();
    let mut verified = BTreeMap::<[u8; 32], BTreeMap<u32, VerifiedDecisionSignature>>::new();
    let mut trace = Vec::new();
    let mut decided = None;
    let mut signed = None;
    let mut timer_round = 1;
    let mut round_deadline = Instant::now() + Duration::from_secs(5);
    let deadline = Instant::now() + Duration::from_secs(300);
    let mut cpu = BTreeMap::<&str, u64>::new();
    let mut iterations = 0u64;
    loop {
        iterations += 1;
        if Instant::now() >= deadline {
            return Err(protocol_error("Simple-IT epoch timed out"));
        }
        let stage = ThreadTime::now();
        while let Some(action) = work.pop_front() {
            match action {
                Action::Send { receiver, message } => {
                    let kind = match &message.body {
                        Body::Disperse(_) => "disperse",
                        Body::Echo(_) => "echo",
                        Body::Ready(_) => "ready",
                        Body::Commit => "commit",
                        Body::TimeoutVote => "timeout-vote",
                        Body::TimeoutAccept => "timeout-accept",
                    };
                    let label = format!("round-{}-{kind}", message.round);
                    trace.push(serde_json::json!({"event":"enqueue", "label":label, "unix_ns":unix_time_ns()?}));
                    let targets = receiver.map_or_else(|| receivers.clone(), |node| vec![node]);
                    pump.enqueue_labeled(
                        network.shared,
                        config,
                        &scope,
                        &DistributedMessage::BeaconSimpleIt {
                            sample: network.sample,
                            message,
                        },
                        &targets,
                        &label,
                    )?;
                }
                Action::Validate { round, root, value } => {
                    let start = unix_time_ns()?;
                    match canonical_deserialize::<EncodedEpochProposal>(&value) {
                        Ok(encoded)
                            if encoded.check_shape(
                                local.command().epoch,
                                params.n,
                                params.t + 1,
                            ) =>
                        {
                            pending_candidates.insert((round, root), (value, encoded, start));
                        }
                        _ => work.extend(
                            core.accept_candidate(round, root, false)
                                .map_err(protocol_error)?,
                        ),
                    }
                }
                Action::EnterRound(round) => {
                    timer_round = round;
                    // Common size-independent timeout. Old RBC/RN stays live.
                    round_deadline =
                        Instant::now() + Duration::from_secs(5 * (1u64 << (round - 1).min(4)));
                    trace.push(serde_json::json!({"event":"enter-round", "round":round, "unix_ns":unix_time_ns()?}));
                }
                Action::RbDelivered(round) => {
                    trace.push(serde_json::json!({"event":"rbc-delivered", "round":round, "unix_ns":unix_time_ns()?}));
                }
                Action::Decide {
                    proposal_round,
                    commit_round,
                    value,
                } => {
                    // An equivocating leader can create multiple decoded
                    // candidates in one round. Bind the exact decided bytes,
                    // never the first candidate encountered for that round.
                    let digest = *candidate_digests.get(&value_key(&value)).ok_or_else(|| {
                        protocol_error("decided proposal was not externally verified")
                    })?;
                    if signed.is_some_and(|previous| previous != digest) {
                        return Err(protocol_error("conflicting Simple-IT decision"));
                    }
                    decided = Some(digest);
                    trace.push(serde_json::json!({"event":"simple-it-decide", "proposal_round":proposal_round,
                        "commit_round":commit_round, "unix_ns":unix_time_ns()?}));
                }
            }
        }
        {
            let available = store
                .lock()
                .map_err(|_| protocol_error("certificate store poisoned"))?;
            for (_, encoded, _) in pending_candidates.values() {
                for (_, id) in &encoded.entries {
                    if !certificates.contains_key(id)
                        && let Some(statements) = available.get(id)
                    {
                        certificates.insert(*id, statements.clone());
                    }
                }
            }
        }
        for (sender, message) in
            take_protocol_available(network.shared, &responses, Duration::ZERO)?
        {
            if let DistributedMessage::BeaconCertificateResponse {
                sample,
                id,
                statements,
            } = message
                && sample == network.sample
                && (sender as usize) < params.n
                && requested.contains_key(&id)
                && !certificates.contains_key(&id)
                && statements.len() == params.quorum()
            {
                for (_, encoded, _) in pending_candidates.values() {
                    if let Some((entry, _)) =
                        encoded.entries.iter().find(|(_, wanted)| *wanted == id)
                        && certificate_id(encoded.epoch, entry, &statements)
                            .map_err(protocol_error)?
                            == id
                    {
                        certificates.insert(id, statements.clone());
                        break;
                    }
                }
            }
        }
        let mut complete = Vec::new();
        for ((round, root), (value, encoded, start)) in &pending_candidates {
            let missing = encoded
                .entries
                .iter()
                .filter(|(_, id)| !certificates.contains_key(id))
                .map(|(entry, id)| (entry.dealer, *id))
                .collect::<Vec<_>>();
            if !missing.is_empty() {
                let mut by_peer = BTreeMap::<u32, Vec<[u8; 32]>>::new();
                for (dealer, id) in missing {
                    let now = Instant::now();
                    let fetch = requested.entry(id).or_insert_with(|| {
                        CertificateFetch::new(
                            dealer,
                            params.leader(*round),
                            config.node.node_id,
                            params.n,
                            now,
                        )
                    });
                    if let Some(peer) = fetch.poll(now) {
                        by_peer.entry(peer).or_default().push(id);
                    }
                }
                // Already-received Prepare messages were consumed above. Do
                // not add a fixed grace delay for bytes that are still absent.
                // A missing certificate is fetched from one holder at a time;
                // broadcasting the same request creates n duplicate replies.
                for (peer, ids) in by_peer {
                    trace.push(serde_json::json!({"event":"certificate-fetch", "round":round, "count":ids.len(), "receivers":1, "peer":peer, "unix_ns":unix_time_ns()?}));
                    pump.enqueue_labeled(
                        network.shared,
                        config,
                        &requests,
                        &DistributedMessage::BeaconCertificateRequest {
                            sample: network.sample,
                            ids,
                        },
                        &[peer],
                        "certificate-fetch-request",
                    )?;
                }
                continue;
            }
            {
                let mut data = prepared
                    .state
                    .0
                    .lock()
                    .map_err(|_| protocol_error("preparation state poisoned"))?;
                if let Some(error) = &data.error {
                    return Err(protocol_error(error));
                }
                let dealers = encoded
                    .entries
                    .iter()
                    .map(|(entry, _)| entry.dealer)
                    .collect::<Vec<_>>();
                if !silk.has_public_materials(&data.sharing, &dealers) {
                    data.wanted_publics.extend(dealers);
                    network.shared.1.notify_all();
                    continue;
                }
            }
            let validation_start = unix_time_ns()?;
            let candidate = encoded
                .expand(&certificates)
                .ok()
                .flatten()
                .and_then(|command| {
                    let materials = if command == *local.command() {
                        Vec::new()
                    } else {
                        command
                            .transcripts
                            .iter()
                            .filter_map(|entry| prepared.certified_materials.get(entry).cloned())
                            .collect()
                    };
                    // Proposal verification can wait on the crypto pool. Keep
                    // only the referenced public inputs, releasing Prepare's
                    // state lock before checking signatures.
                    let sharing = prepared.state.0.lock().ok()?.sharing.public_snapshot(
                        &command
                            .transcripts
                            .iter()
                            .map(|entry| entry.dealer)
                            .collect::<Vec<_>>(),
                    );
                    silk.accept_round_proposal(
                        *round,
                        params.leader(*round),
                        command,
                        local,
                        &sharing,
                        materials,
                    )
                    .ok()
                });
            let accepted = candidate.is_some();
            if let Some(proposal) = candidate {
                let mut available = store
                    .lock()
                    .map_err(|_| protocol_error("certificate store poisoned"))?;
                for (_, id) in &encoded.entries {
                    available
                        .entry(*id)
                        .or_insert_with(|| certificates[id].clone());
                }
                candidate_digests.insert(value_key(value), proposal.digest());
                proposals.entry(proposal.digest()).or_insert(proposal);
            }
            trace.push(serde_json::json!({"event":"payload-validation", "round":round, "accepted":accepted,
                "payload_bytes":value.len(), "start_unix_ns":start, "validation_start_unix_ns":validation_start, "unix_ns":unix_time_ns()?}));
            work.extend(
                core.accept_candidate(*round, *root, accepted)
                    .map_err(protocol_error)?,
            );
            complete.push((*round, *root));
        }
        for key in complete {
            pending_candidates.remove(&key);
        }
        *cpu.entry("actions").or_default() += stage.elapsed().as_nanos() as u64;
        let stage = ThreadTime::now();
        for (digest, proposal) in &proposals {
            if let Some(pending) = pending_signatures.remove(digest) {
                let accepted = verified.entry(*digest).or_default();
                for (sender, signature) in pending {
                    if !accepted.contains_key(&sender)
                        && let Ok(signature) =
                            silk.accept_decision_signature(sender, proposal, signature)
                    {
                        accepted.insert(sender, signature);
                    }
                }
            }
        }
        if signed.is_none() {
            let supported = decided.or_else(|| {
                verified
                    .iter()
                    .find(|(_, v)| v.len() > params.t)
                    .map(|(digest, _)| *digest)
            });
            if let Some(digest) = supported {
                let proposal = &proposals[&digest];
                let signature = if decided == Some(digest) {
                    silk.decision_signature(proposal)
                } else {
                    silk.relay_decision_signature(
                        proposal,
                        &verified[&digest].values().collect::<Vec<_>>(),
                    )
                }
                .map_err(protocol_error)?;
                signed = Some(digest);
                trace.push(serde_json::json!({"event":"decision-signature", "relayed":decided != Some(digest), "unix_ns":unix_time_ns()?}));
                pump.enqueue_labeled(
                    network.shared,
                    config,
                    &protocols.decision_signature,
                    &DistributedMessage::BeaconSimpleItSignature {
                        sample: network.sample,
                        digest,
                        signature,
                    },
                    &receivers,
                    "decision-signature",
                )?;
            }
        }
        *cpu.entry("decision-evidence").or_default() += stage.elapsed().as_nanos() as u64;
        let stage = ThreadTime::now();
        pump.check_error()?;
        *cpu.entry("pump").or_default() += stage.elapsed().as_nanos() as u64;
        if let Some(digest) = signed
            && verified
                .get(&digest)
                .is_some_and(|v| v.len() >= params.quorum())
        {
            trace.push(serde_json::json!({"event":"decision-quorum", "unix_ns":unix_time_ns()?}));
            // Decision relay continues after local decision; a slow socket
            // cannot turn this quorum condition into an all-peer send fence.
            trace.push(
                serde_json::json!({"event":"decision-send-handoff", "unix_ns":unix_time_ns()?}),
            );
            trace.push(serde_json::json!({"event":"event-loop-cpu", "thread_cpu_ns":cpu, "iterations":iterations}));
            discard_protocols(
                network.shared,
                &BTreeSet::from([scope, protocols.decision_signature.clone()]),
            )?;
            return Ok((
                proposals.remove(&digest).expect("signed proposal"),
                verified
                    .remove(&digest)
                    .expect("verified quorum")
                    .into_values()
                    .take(params.quorum())
                    .collect(),
                trace,
            ));
        }
        let wait = Duration::from_millis(1);
        let stage = ThreadTime::now();
        let incoming = take_protocol_available(network.shared, &scope, wait)?;
        *cpu.entry("receive-decode").or_default() += stage.elapsed().as_nanos() as u64;
        let stage = ThreadTime::now();
        for (sender, message) in incoming {
            if let DistributedMessage::BeaconSimpleIt { sample, message } = message
                && sample == network.sample
            {
                let body = match &message.body {
                    Body::Echo(_) => "core-echo",
                    Body::Disperse(_) => "core-disperse",
                    Body::Ready(_) => "core-ready",
                    _ => "core-control",
                };
                let before = ThreadTime::now();
                let actions = core.receive(sender, message).map_err(protocol_error)?;
                let elapsed = before.elapsed().as_nanos() as u64;
                *cpu.entry(body).or_default() += elapsed;
                if actions.iter().any(|a| matches!(a, Action::Validate { .. })) {
                    *cpu.entry("core-payload-decode-step").or_default() += elapsed;
                }
                work.extend(actions);
            }
        }
        *cpu.entry("core-receive").or_default() += stage.elapsed().as_nanos() as u64;
        let stage = ThreadTime::now();
        for (sender, message) in take_protocol_available(
            network.shared,
            &protocols.decision_signature,
            Duration::ZERO,
        )? {
            if let DistributedMessage::BeaconSimpleItSignature {
                sample,
                digest,
                signature,
            } = message
                && sample == network.sample
                && (sender as usize) < params.n
                && sender == signature.signer
                && !verified
                    .get(&digest)
                    .is_some_and(|v| v.contains_key(&sender))
            {
                pending_signatures
                    .entry(digest)
                    .or_default()
                    .entry(sender)
                    .or_insert(signature);
            }
        }
        *cpu.entry("evidence-receive-decode").or_default() += stage.elapsed().as_nanos() as u64;
        // receive() can already enter a new round while its EnterRound action
        // is still queued. An expired timer belongs only to its original round.
        if core.current_round() == timer_round && Instant::now() >= round_deadline {
            trace.push(serde_json::json!({"event":"timer-expired", "round":core.current_round(), "unix_ns":unix_time_ns()?}));
            work.extend(core.timeout(core.current_round()).map_err(protocol_error)?);
            round_deadline = deadline;
        }
    }
}

fn value_key(value: &[u8]) -> [u8; 32] {
    hash_len_prefixed(b"silk/simple-it/application-value/v1", &[value])
}
