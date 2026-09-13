use super::*;
use std::ops::Bound::{Excluded, Unbounded};

pub(super) fn wait_for_peers(
    peers: &BTreeMap<u32, String>,
    local: u32,
    timeout: Duration,
) -> Result<(), DistributedError> {
    let deadline = Instant::now() + timeout;
    for (node, endpoint) in peer_probe_order(peers, local) {
        loop {
            match ping(endpoint) {
                Ok(()) => break,
                Err(error) if Instant::now() >= deadline => {
                    return Err(DistributedError::Protocol(format!(
                        "peer {node} at {endpoint} did not become reachable: {error}"
                    )));
                }
                Err(_) => {}
            }
            std::thread::sleep(Duration::from_millis(25));
        }
    }
    Ok(())
}

pub(super) fn peer_probe_order(
    peers: &BTreeMap<u32, String>,
    local: u32,
) -> impl Iterator<Item = (&u32, &String)> {
    peers
        .range((Excluded(local), Unbounded))
        .chain(peers.range(..local))
}

pub(super) fn sample_barrier(
    shared: &SharedNode,
    config: &AutonomousConfig,
    sample: u32,
    barrier: &str,
) -> Result<(), DistributedError> {
    let deadline = Instant::now() + Duration::from_secs(300);
    broadcast_sample_ready(shared, config, sample, barrier)?;
    loop {
        let state = shared
            .0
            .lock()
            .map_err(|_| DistributedError::Protocol("worker lock poisoned".into()))?;
        let ready = sample_ready_senders(&state.inbox, sample, &config.experiment_id, barrier)?;
        if ready.len() == config.node.n {
            drop(state);
            let mut state = shared
                .0
                .lock()
                .map_err(|_| DistributedError::Protocol("worker lock poisoned".into()))?;
            retain_other_samples(&mut state.inbox, sample, &config.experiment_id, barrier)?;
            return Ok(());
        }
        let now = Instant::now();
        if now >= deadline {
            return Err(DistributedError::Protocol(format!(
                "node {} sample barrier has {}/{} ready replicas",
                config.node.node_id,
                ready.len(),
                config.node.n
            )));
        }
        let wait = Duration::from_millis(50).min(deadline.saturating_duration_since(now));
        let (next, _) = shared
            .1
            .wait_timeout(state, wait)
            .map_err(|_| DistributedError::Protocol("worker lock poisoned".into()))?;
        drop(next);
    }
}

fn broadcast_sample_ready(
    shared: &SharedNode,
    config: &AutonomousConfig,
    sample: u32,
    barrier: &str,
) -> Result<(), DistributedError> {
    for receiver in 0..config.node.n as u32 {
        message_flow::send(
            shared,
            config,
            "experiment-sample-ready-v1",
            receiver,
            DistributedMessage::SampleReady {
                sample,
                experiment: config.experiment_id.clone(),
                barrier: barrier.into(),
            },
        )?;
    }
    Ok(())
}

fn sample_ready_senders(
    inbox: &VecDeque<InboxEnvelope>,
    sample: u32,
    experiment: &str,
    barrier: &str,
) -> Result<BTreeSet<u32>, DistributedError> {
    let mut senders = BTreeSet::new();
    for received in inbox
        .iter()
        .filter(|received| received.envelope.protocol == "experiment-sample-ready-v1")
    {
        if let DistributedMessage::SampleReady {
            sample: message_sample,
            experiment: message_experiment,
            barrier: message_barrier,
        } = canonical_deserialize(&received.envelope.payload)?
            && message_sample == sample
            && message_experiment == experiment
            && message_barrier == barrier
        {
            senders.insert(received.envelope.sender);
        }
    }
    Ok(senders)
}

fn retain_other_samples(
    inbox: &mut VecDeque<InboxEnvelope>,
    sample: u32,
    experiment: &str,
    barrier: &str,
) -> Result<(), DistributedError> {
    let mut retained = VecDeque::new();
    while let Some(received) = inbox.pop_front() {
        let matching = if received.envelope.protocol == "experiment-sample-ready-v1" {
            matches!(
                canonical_deserialize::<DistributedMessage>(&received.envelope.payload)?,
                DistributedMessage::SampleReady {
                    sample: message_sample,
                    experiment: message_experiment,
                    barrier: message_barrier,
                } if message_sample == sample
                    && message_experiment == experiment
                    && message_barrier == barrier
            )
        } else {
            false
        };
        if !matching {
            retained.push_back(received);
        }
    }
    *inbox = retained;
    Ok(())
}

pub(super) fn wait_for_messages(
    shared: &SharedNode,
    protocol: &str,
    expected: usize,
    timeout: Duration,
) -> Result<(), DistributedError> {
    let deadline = Instant::now() + timeout;
    let mut state = shared
        .0
        .lock()
        .map_err(|_| DistributedError::Protocol("worker lock poisoned".into()))?;
    loop {
        let count = state
            .inbox
            .iter()
            .filter(|received| received.envelope.protocol == protocol)
            .count();
        if count >= expected {
            return Ok(());
        }
        let now = Instant::now();
        if now >= deadline {
            return Err(expected_messages(state.node_id, protocol, expected, count));
        }
        let remaining = deadline.saturating_duration_since(now);
        let (guard, _) = shared
            .1
            .wait_timeout(state, remaining)
            .map_err(|_| DistributedError::Protocol("worker lock poisoned".into()))?;
        state = guard;
    }
}

fn expected_messages(
    node_id: u32,
    protocol: &str,
    expected: usize,
    actual: usize,
) -> DistributedError {
    DistributedError::Protocol(format!(
        "node {node_id} expected {expected} {protocol} messages, received {actual}"
    ))
}
