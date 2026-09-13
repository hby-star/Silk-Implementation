//! Canonical protocol-message fan-out and inbox selection.
//!
//! This module owns the mechanics shared by beacon phases: framed send/fan-out,
//! inbox selection, and experiment-sample decoding. Beacon crates validate
//! protocol semantics.

use super::*;

pub(super) fn scoped_protocol(base: &str, sample: u32, sequence: u32) -> String {
    format!("{base}/sample-{sample}/sequence-{sequence}")
}

pub(super) fn send(
    shared: &SharedNode,
    config: &AutonomousConfig,
    protocol: &str,
    receiver: u32,
    message: DistributedMessage,
) -> Result<(), DistributedError> {
    let sender = shared.0.lock().map_err(protocol_error)?.sender.clone();
    if let Some(sender) = sender {
        return sender.enqueue(shared, config, protocol, &message, &[receiver]);
    }
    deliver_outgoing(
        shared,
        config.node.node_id,
        &config.node.peers,
        Outgoing {
            protocol: protocol.into(),
            receiver,
            message,
        },
    )
}

pub(super) fn broadcast<F>(
    shared: &SharedNode,
    config: &AutonomousConfig,
    protocol: &str,
    message: F,
    receivers: u32,
) -> Result<(), DistributedError>
where
    F: Fn(u32) -> DistributedMessage,
{
    let messages = (0..receivers)
        .map(|receiver| (receiver, message(receiver)))
        .collect();
    fanout(shared, config, protocol, messages)
}

pub(super) fn broadcast_same(
    shared: &SharedNode,
    config: &AutonomousConfig,
    protocol: &str,
    message: DistributedMessage,
    receivers: u32,
) -> Result<(), DistributedError> {
    let sender = shared.0.lock().map_err(protocol_error)?.sender.clone();
    if let Some(sender) = sender {
        return sender.enqueue(
            shared,
            config,
            protocol,
            &message,
            &(0..receivers).collect::<Vec<_>>(),
        );
    }
    deliver_same_outgoing_batch(
        shared,
        config.node.node_id,
        &config.node.peers,
        protocol,
        &message,
        receivers,
    )
}

pub(super) fn fanout(
    shared: &SharedNode,
    config: &AutonomousConfig,
    protocol: &str,
    messages: Vec<(u32, DistributedMessage)>,
) -> Result<(), DistributedError> {
    let sender = shared.0.lock().map_err(protocol_error)?.sender.clone();
    if let Some(sender) = sender {
        for (receiver, message) in messages {
            sender.enqueue(shared, config, protocol, &message, &[receiver])?;
        }
        return Ok(());
    }
    let outgoing = messages
        .into_iter()
        .map(|(receiver, message)| Outgoing {
            protocol: protocol.into(),
            receiver,
            message,
        })
        .collect();
    deliver_outgoing_batch(shared, config.node.node_id, &config.node.peers, outgoing)
}

#[derive(Debug)]
pub(super) struct ValidCollection<T> {
    pub(super) messages: Vec<(u32, T)>,
    pub(super) rejected: usize,
    pub(super) duplicates: usize,
}

impl<T> ValidCollection<T> {
    pub(super) fn into_messages(self, protocol: &str) -> Vec<(u32, T)> {
        if self.rejected != 0 || self.duplicates != 0 {
            eprintln!(
                "protocol {protocol} ignored {} invalid and {} duplicate messages",
                self.rejected, self.duplicates
            );
        }
        self.messages
    }
}

/// Collects a quorum of messages that have passed caller-supplied protocol
/// validation. Invalid messages and duplicates from an already accepted
/// sender are consumed but never occupy a quorum slot.
pub(super) fn collect_protocol_valid<T>(
    shared: &SharedNode,
    protocol: &str,
    threshold: usize,
    timeout: Duration,
    mut validate: impl FnMut(u32, DistributedMessage) -> Result<Option<T>, DistributedError>,
) -> Result<ValidCollection<T>, DistributedError> {
    if threshold == 0 {
        return Err(DistributedError::Protocol(format!(
            "protocol {protocol} has a zero collection threshold"
        )));
    }
    let deadline = Instant::now() + timeout;
    let mut accepted = BTreeMap::new();
    let mut rejected = 0usize;
    let mut duplicates = 0usize;

    while accepted.len() < threshold {
        if Instant::now() >= deadline {
            return Err(protocol_error(format!(
                "protocol {protocol} collected {}/{} valid senders before deadline",
                accepted.len(),
                threshold
            )));
        }
        // Never remove candidates that this invocation cannot consume. In
        // particular, sparse reconstruction may need another batch after the
        // envelope threshold has been reached.
        let available = take_protocol_available_bounded(
            shared,
            protocol,
            deadline.saturating_duration_since(Instant::now()),
            threshold - accepted.len(),
        )?;
        for (sender, message) in available {
            if accepted.contains_key(&sender) {
                duplicates += 1;
                continue;
            }
            match validate(sender, message)? {
                Some(value) => {
                    accepted.insert(sender, value);
                    if accepted.len() == threshold {
                        break;
                    }
                }
                None => rejected += 1,
            }
        }
    }

    Ok(ValidCollection {
        messages: accepted.into_iter().collect(),
        rejected,
        duplicates,
    })
}

pub(super) fn take_protocol(
    shared: &SharedNode,
    protocol: &str,
    expected: usize,
    timeout: Duration,
) -> Result<Vec<(u32, DistributedMessage)>, DistributedError> {
    coordination::wait_for_messages(shared, protocol, expected, timeout)?;
    drain_protocol(shared, protocol, None, expected)
}

pub(super) fn protocol_has_quorum(
    shared: &SharedNode,
    protocol: &str,
    eligible: &BTreeSet<u32>,
    threshold: usize,
) -> Result<bool, DistributedError> {
    let state = shared
        .0
        .lock()
        .map_err(|_| protocol_error("worker lock poisoned"))?;
    let senders = state
        .inbox
        .iter()
        .filter(|item| {
            item.envelope.protocol == protocol && eligible.contains(&item.envelope.sender)
        })
        .map(|item| item.envelope.sender)
        .collect::<BTreeSet<_>>();
    Ok(senders.len() >= threshold)
}

pub(super) fn discard_protocols(
    shared: &SharedNode,
    protocols: &BTreeSet<String>,
) -> Result<usize, DistributedError> {
    let mut state = shared
        .0
        .lock()
        .map_err(|_| DistributedError::Protocol("worker lock poisoned".into()))?;
    let mut retained = VecDeque::new();
    let mut discarded = 0usize;
    state.retired_protocols.extend(protocols.iter().cloned());
    while let Some(received) = state.inbox.pop_front() {
        if protocols.contains(&received.envelope.protocol) {
            if received.network_wire_bytes != 0 {
                state.counters.messages_received += 1;
                state.counters.bytes_received += received.network_wire_bytes;
                state.consumed_receive_cpu_ns += received.receive_deserialize_cpu_ns;
            }
            discarded += 1;
        } else {
            retained.push_back(received);
        }
    }
    state.inbox = retained;
    Ok(discarded)
}

fn drain_protocol(
    shared: &SharedNode,
    protocol: &str,
    expected_senders: Option<&BTreeSet<u32>>,
    expected: usize,
) -> Result<Vec<(u32, DistributedMessage)>, DistributedError> {
    let mut state = shared
        .0
        .lock()
        .map_err(|_| DistributedError::Protocol("worker lock poisoned".into()))?;
    let available = drain_available_protocol(&mut state, protocol);
    drop(state);
    let mut selected = Vec::new();
    let mut selected_senders = BTreeSet::new();
    for (sender, message) in decode_available(available)? {
        if expected_senders.is_none_or(|senders| senders.contains(&sender))
            && selected_senders.insert(sender)
        {
            selected.push((sender, message));
        }
    }
    if selected.len() < expected {
        return Err(DistributedError::Protocol(format!(
            "protocol {protocol} expected at least {expected} messages, found {}",
            selected.len()
        )));
    }
    selected.truncate(expected);
    Ok(selected)
}

/// Waits briefly for any message on a protocol and drains the currently
/// available batch. An empty batch is a normal timeout, which lets background
/// fault-recovery responders also observe a shutdown flag.
pub(super) fn take_protocol_available(
    shared: &SharedNode,
    protocol: &str,
    timeout: Duration,
) -> Result<Vec<(u32, DistributedMessage)>, DistributedError> {
    take_protocol_available_bounded(shared, protocol, timeout, usize::MAX)
}

/// Leave excess envelopes in the inbox, including their unconsumed receive
/// counters. A caller can stop at a valid quorum without decoding or losing
/// certificates needed by a later proposal.
pub(super) fn take_protocol_available_bounded(
    shared: &SharedNode,
    protocol: &str,
    timeout: Duration,
    maximum: usize,
) -> Result<Vec<(u32, DistributedMessage)>, DistributedError> {
    if maximum == 0 {
        return Ok(Vec::new());
    }
    let deadline = Instant::now() + timeout;
    let mut state = shared
        .0
        .lock()
        .map_err(|_| DistributedError::Protocol("worker lock poisoned".into()))?;
    loop {
        if state
            .inbox
            .iter()
            .any(|received| received.envelope.protocol == protocol)
        {
            let available = drain_available_protocol_bounded(&mut state, protocol, maximum);
            drop(state);
            return decode_available(available);
        }
        let now = Instant::now();
        if now >= deadline {
            return Ok(Vec::new());
        }
        let (guard, _) = shared
            .1
            .wait_timeout(state, deadline.saturating_duration_since(now))
            .map_err(|_| DistributedError::Protocol("worker lock poisoned".into()))?;
        state = guard;
    }
}

fn drain_available_protocol(state: &mut WorkerState, protocol: &str) -> Vec<(u32, Vec<u8>)> {
    drain_available_protocol_bounded(state, protocol, usize::MAX)
}

fn drain_available_protocol_bounded(
    state: &mut WorkerState,
    protocol: &str,
    maximum: usize,
) -> Vec<(u32, Vec<u8>)> {
    let mut retained = VecDeque::new();
    let mut available = Vec::new();
    while let Some(received) = state.inbox.pop_front() {
        if received.envelope.protocol == protocol && available.len() < maximum {
            if received.network_wire_bytes != 0 {
                state.counters.messages_received += 1;
                state.counters.bytes_received += received.network_wire_bytes;
                state.consumed_receive_cpu_ns += received.receive_deserialize_cpu_ns;
            }
            available.push((received.envelope.sender, received.envelope.payload));
        } else {
            retained.push_back(received);
        }
    }
    state.inbox = retained;
    available
}

fn decode_available(
    available: Vec<(u32, Vec<u8>)>,
) -> Result<Vec<(u32, DistributedMessage)>, DistributedError> {
    // Canonical decode/re-encode of large fragments must not hold the shared
    // inbox mutex: network readers and transport counters also need that lock.
    available
        .into_iter()
        .map(|(sender, payload)| Ok((sender, canonical_deserialize(&payload)?)))
        .collect()
}

pub(super) fn protocol_error(error: impl std::fmt::Display) -> DistributedError {
    DistributedError::Protocol(error.to_string())
}

pub(super) fn decode_messages<T>(
    messages: Vec<(u32, DistributedMessage)>,
    expected_sample: u32,
    kind: &str,
    mut decode: impl FnMut(DistributedMessage) -> Option<(u32, T)>,
) -> Result<Vec<(u32, T)>, DistributedError> {
    messages
        .into_iter()
        .map(|(sender, message)| match decode(message) {
            Some((sample, value)) if sample == expected_sample => Ok((sender, value)),
            _ => Err(DistributedError::Protocol(format!(
                "unexpected or cross-sample {kind}"
            ))),
        })
        .collect()
}

pub(super) fn decode_one<T>(
    messages: Vec<(u32, DistributedMessage)>,
    expected_sample: u32,
    kind: &str,
    decode: impl FnMut(DistributedMessage) -> Option<(u32, T)>,
) -> Result<(u32, T), DistributedError> {
    let mut decoded = decode_messages(messages, expected_sample, kind, decode)?;
    if decoded.len() != 1 {
        return Err(DistributedError::Protocol(format!(
            "expected one {kind} message"
        )));
    }
    Ok(decoded.pop().expect("length checked"))
}
