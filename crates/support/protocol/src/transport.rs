use crate::wire::{WireError, canonical_deserialize, canonical_serialize};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, VecDeque};
use thiserror::Error;

pub const FRAME_PREFIX_BYTES: u64 = 4;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct WireEnvelope {
    pub protocol: String,
    pub version: u16,
    pub sender: u32,
    pub receiver: u32,
    pub sequence: u64,
    pub payload: Vec<u8>,
}

/// Exact outer request serialized by the TCP experiment transport.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum FramedRequest {
    Ping,
    Deliver(WireEnvelope),
}

pub fn framed_request_len(request: &FramedRequest) -> Result<u64, WireError> {
    Ok(canonical_serialize(request)?.len() as u64 + FRAME_PREFIX_BYTES)
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct TransportCounters {
    pub messages_sent: u64,
    pub messages_received: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub actual_wire_bytes: u64,
}

#[derive(Debug, Error)]
pub enum TransportError {
    #[error(transparent)]
    Wire(#[from] WireError),
    #[error("receiver {0} has no queued message")]
    Empty(u32),
}

pub trait ProtocolTransport {
    fn send<T: Serialize + ?Sized>(
        &mut self,
        protocol: &str,
        sender: u32,
        receiver: u32,
        payload: &T,
    ) -> Result<u64, TransportError>;

    fn receive<T: DeserializeOwned + Serialize>(
        &mut self,
        receiver: u32,
    ) -> Result<(WireEnvelope, T), TransportError>;

    fn total_counters(&self) -> TransportCounters;
}

/// Deterministic all-data-available transport used by local-process studies.
/// It queues the exact serialized envelope that a socket transport would send.
#[derive(Debug, Default)]
pub struct InMemoryTransport {
    queues: BTreeMap<u32, VecDeque<Vec<u8>>>,
    counters: BTreeMap<u32, TransportCounters>,
    next_sequence: BTreeMap<u32, u64>,
}

impl InMemoryTransport {
    pub fn send<T: Serialize + ?Sized>(
        &mut self,
        protocol: &str,
        sender: u32,
        receiver: u32,
        payload: &T,
    ) -> Result<u64, TransportError> {
        let payload = canonical_serialize(payload)?;
        let sequence = self.next_sequence.entry(sender).or_default();
        let envelope = WireEnvelope {
            protocol: protocol.to_owned(),
            version: 1,
            sender,
            receiver,
            sequence: *sequence,
            payload,
        };
        *sequence += 1;
        let wire = canonical_serialize(&envelope)?;
        let wire_bytes = wire.len() as u64;
        self.queues.entry(receiver).or_default().push_back(wire);
        let sent = self.counters.entry(sender).or_default();
        sent.messages_sent += 1;
        sent.bytes_sent += wire_bytes;
        sent.actual_wire_bytes += wire_bytes;
        Ok(wire_bytes)
    }

    pub fn receive<T: serde::de::DeserializeOwned + Serialize>(
        &mut self,
        receiver: u32,
    ) -> Result<(WireEnvelope, T), TransportError> {
        let wire = self
            .queues
            .entry(receiver)
            .or_default()
            .pop_front()
            .ok_or(TransportError::Empty(receiver))?;
        let wire_bytes = wire.len() as u64;
        let envelope: WireEnvelope = canonical_deserialize(&wire)?;
        let payload = canonical_deserialize(&envelope.payload)?;
        let received = self.counters.entry(receiver).or_default();
        received.messages_received += 1;
        received.bytes_received += wire_bytes;
        Ok((envelope, payload))
    }

    pub fn counters(&self, node: u32) -> TransportCounters {
        self.counters.get(&node).copied().unwrap_or_default()
    }

    pub fn total_counters(&self) -> TransportCounters {
        self.counters
            .values()
            .fold(TransportCounters::default(), |mut total, value| {
                total.messages_sent += value.messages_sent;
                total.messages_received += value.messages_received;
                total.bytes_sent += value.bytes_sent;
                total.bytes_received += value.bytes_received;
                total.actual_wire_bytes += value.actual_wire_bytes;
                total
            })
    }
}

impl ProtocolTransport for InMemoryTransport {
    fn send<T: Serialize + ?Sized>(
        &mut self,
        protocol: &str,
        sender: u32,
        receiver: u32,
        payload: &T,
    ) -> Result<u64, TransportError> {
        InMemoryTransport::send(self, protocol, sender, receiver, payload)
    }

    fn receive<T: DeserializeOwned + Serialize>(
        &mut self,
        receiver: u32,
    ) -> Result<(WireEnvelope, T), TransportError> {
        InMemoryTransport::receive(self, receiver)
    }

    fn total_counters(&self) -> TransportCounters {
        InMemoryTransport::total_counters(self)
    }
}
