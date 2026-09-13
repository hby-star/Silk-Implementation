use super::*;
use mio::{Events, Interest, Poll, Token};
use serde::de::DeserializeOwned;
use std::cell::RefCell;
use std::io::{ErrorKind, IoSlice, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};

mod pump;
pub(super) use pump::ProtocolPump;
mod sender;
pub(super) use sender::{BackgroundSender, SenderService};

const MAX_FRAME_BYTES: usize = 64 * 1024 * 1024;
const OUTBOUND_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const OUTBOUND_WRITE_TIMEOUT: Duration = Duration::from_secs(300);
const WRITE_QUANTUM_BYTES: usize = 64 * 1024;
const DELIVER_FRAMING_BYTES: u64 = protocol_support::transport::FRAME_PREFIX_BYTES + 1;

thread_local! {
    static OUTBOUND_STREAMS: RefCell<BTreeMap<String, TcpStream>> = const {
        RefCell::new(BTreeMap::new())
    };
}

struct EncodedOutgoing {
    protocol: String,
    receiver: u32,
    payload: Arc<[u8]>,
}

#[allow(dead_code)]
#[derive(Serialize)]
enum BorrowedFramedRequest<'a> {
    Ping,
    Deliver(DeliverHeader<'a>),
}

#[derive(Serialize)]
struct DeliverHeader<'a> {
    protocol: &'a str,
    version: u16,
    sender: u32,
    receiver: u32,
    sequence: u64,
    // Postcard encodes Vec<u8> as its varint length followed by raw bytes.
    // This is the exact envelope prefix; the immutable payload follows it.
    payload_len: usize,
}

struct OutboundFrame {
    header: Vec<u8>,
    payload: Arc<[u8]>,
    written: usize,
}

impl OutboundFrame {
    fn new(
        protocol: &str,
        sender: u32,
        receiver: u32,
        sequence: u64,
        payload: Arc<[u8]>,
    ) -> Result<Self, DistributedError> {
        let encoded = canonical_serialize(&BorrowedFramedRequest::Deliver(DeliverHeader {
            protocol,
            version: 1,
            sender,
            receiver,
            sequence,
            payload_len: payload.len(),
        }))?;
        let length = encoded
            .len()
            .checked_add(payload.len())
            .filter(|n| *n <= MAX_FRAME_BYTES)
            .ok_or_else(|| DistributedError::Protocol("control frame exceeds limit".into()))?;
        let mut header = Vec::with_capacity(4 + encoded.len());
        header.extend_from_slice(&(length as u32).to_be_bytes());
        header.extend_from_slice(&encoded);
        Ok(Self {
            header,
            payload,
            written: 0,
        })
    }

    fn wire_bytes(&self) -> usize {
        self.header.len() + self.payload.len()
    }

    fn complete(&self) -> bool {
        self.written == self.wire_bytes()
    }

    // One bounded syscall per ready peer. Retain the cursor across both the
    // framing header and payload, including partial writes at their boundary.
    fn write_once(&mut self, stream: &mut impl Write) -> std::io::Result<usize> {
        let header_offset = self.written.min(self.header.len());
        let header = &self.header[header_offset..];
        let header = &header[..header.len().min(WRITE_QUANTUM_BYTES)];
        let payload_offset = self.written.saturating_sub(self.header.len());
        let payload = &self.payload[payload_offset..];
        let payload = &payload[..payload.len().min(WRITE_QUANTUM_BYTES - header.len())];
        let written = stream.write_vectored(&[IoSlice::new(header), IoSlice::new(payload)])?;
        if written == 0 {
            return Err(std::io::Error::new(
                ErrorKind::WriteZero,
                "peer write made no progress",
            ));
        }
        self.written += written;
        Ok(written)
    }
}

struct PendingSend {
    endpoint: String,
    stream: Option<mio::net::TcpStream>,
    frame: OutboundFrame,
}

impl PendingSend {
    fn new(endpoint: String, frame: OutboundFrame) -> Result<Self, DistributedError> {
        let stream = clone_outbound_stream(&endpoint)?;
        stream.set_nonblocking(true)?;
        Ok(Self {
            endpoint,
            stream: Some(mio::net::TcpStream::from_std(stream)),
            frame,
        })
    }

    fn restore_blocking(&mut self) -> std::io::Result<()> {
        if let Some(stream) = self.stream.take() {
            let stream: TcpStream = stream.into();
            if let Err(error) = stream.set_nonblocking(false) {
                remove_outbound_stream(&self.endpoint);
                return Err(error);
            }
        }
        Ok(())
    }
}

impl Drop for PendingSend {
    fn drop(&mut self) {
        let _ = self.restore_blocking();
        // Never reuse a connection containing an incomplete frame after an
        // error/timeout. Later messages would otherwise corrupt its framing.
        if !self.frame.complete() {
            remove_outbound_stream(&self.endpoint);
        }
    }
}

fn write_pending_frames(pending: &mut [PendingSend]) -> std::io::Result<()> {
    if pending.is_empty() {
        return Ok(());
    }
    let mut poll = Poll::new()?;
    for (index, send) in pending.iter_mut().enumerate() {
        poll.registry().register(
            send.stream.as_mut().expect("pending stream"),
            Token(index),
            Interest::WRITABLE,
        )?;
    }
    let mut events = Events::with_capacity(pending.len());
    let mut ready: BTreeSet<usize> = (0..pending.len()).collect();
    let mut remaining = pending.len();
    let deadline = Instant::now() + OUTBOUND_WRITE_TIMEOUT;
    while remaining != 0 {
        if Instant::now() >= deadline {
            return Err(std::io::Error::new(
                ErrorKind::TimedOut,
                "peer fanout write timed out",
            ));
        }
        for index in std::mem::take(&mut ready) {
            let send = &mut pending[index];
            match send
                .frame
                .write_once(send.stream.as_mut().expect("pending stream"))
            {
                Ok(_) if send.frame.complete() => {
                    poll.registry()
                        .deregister(send.stream.as_mut().expect("pending stream"))?;
                    remaining -= 1;
                }
                Ok(_) => {
                    ready.insert(index);
                }
                Err(error) if error.kind() == ErrorKind::Interrupted => {
                    ready.insert(index);
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => {}
                Err(error) => return Err(error),
            }
        }
        if remaining == 0 {
            break;
        }
        // Keep budget-limited peers runnable even with edge-triggered epoll.
        // Only wait when every unfinished socket reported WouldBlock.
        let timeout = if ready.is_empty() {
            deadline.saturating_duration_since(Instant::now())
        } else {
            Duration::ZERO
        };
        match poll.poll(&mut events, Some(timeout)) {
            Ok(()) => {}
            Err(error) if error.kind() == ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
        for event in events.iter() {
            let index = event.token().0;
            if !pending[index].frame.complete() {
                ready.insert(index);
            }
        }
    }
    Ok(())
}

pub(super) fn handle_connection(
    mut stream: TcpStream,
    shared: &SharedNode,
) -> Result<(), DistributedError> {
    loop {
        let (request, receive_deserialize_cpu_ns, encoded_request_bytes): (
            FramedRequest,
            u64,
            usize,
        ) = match read_frame_measured(&mut stream) {
            Ok(request) => request,
            Err(DistributedError::Io(error))
                if matches!(
                    error.kind(),
                    ErrorKind::UnexpectedEof
                        | ErrorKind::ConnectionReset
                        | ErrorKind::ConnectionAborted
                        | ErrorKind::BrokenPipe
                ) =>
            {
                return Ok(());
            }
            Err(error) => return Err(error),
        };
        match request {
            FramedRequest::Deliver(envelope) => {
                let mut state = shared
                    .0
                    .lock()
                    .map_err(|_| DistributedError::Protocol("worker lock poisoned".into()))?;
                if envelope.receiver != state.node_id {
                    return Err(DistributedError::Protocol(
                        "envelope routed to the wrong node".into(),
                    ));
                }
                let bytes = encoded_request_bytes
                    .checked_sub(1)
                    .ok_or_else(|| DistributedError::Protocol("empty deliver frame".into()))?
                    as u64;
                let retired = state.retired_protocols.contains(&envelope.protocol);
                if retired {
                    state.counters.messages_received += 1;
                    state.counters.bytes_received += bytes;
                    state.consumed_receive_cpu_ns += receive_deserialize_cpu_ns;
                } else {
                    state.inbox.push_back(InboxEnvelope {
                        envelope,
                        network_wire_bytes: bytes,
                        receive_deserialize_cpu_ns,
                    });
                }
                drop(state);
                if !retired {
                    shared.1.notify_all();
                }
            }
            FramedRequest::Ping => {
                write_frame(&mut stream, &NodeResponse::Ack)?;
            }
        }
    }
}

pub(super) fn deliver_outgoing(
    shared: &SharedNode,
    node_id: u32,
    peers: &BTreeMap<u32, String>,
    outgoing: Outgoing,
) -> Result<(), DistributedError> {
    let payload = canonical_serialize(&outgoing.message)?;
    let sequence = {
        let mut state = shared
            .0
            .lock()
            .map_err(|_| DistributedError::Protocol("worker lock poisoned".into()))?;
        let sequence = state.envelope_sequence;
        state.envelope_sequence += 1;
        sequence
    };
    if outgoing.receiver == node_id {
        let mut state = shared
            .0
            .lock()
            .map_err(|_| DistributedError::Protocol("worker lock poisoned".into()))?;
        let retired = state.retired_protocols.contains(&outgoing.protocol);
        if !retired {
            state.inbox.push_back(InboxEnvelope {
                envelope: WireEnvelope {
                    protocol: outgoing.protocol,
                    version: 1,
                    sender: node_id,
                    receiver: outgoing.receiver,
                    sequence,
                    payload,
                },
                network_wire_bytes: 0,
                receive_deserialize_cpu_ns: 0,
            });
        }
        drop(state);
        if !retired {
            shared.1.notify_all();
        }
        return Ok(());
    }
    let mut frame = OutboundFrame::new(
        &outgoing.protocol,
        node_id,
        outgoing.receiver,
        sequence,
        Arc::from(payload),
    )?;
    let actual_wire_bytes = frame.wire_bytes() as u64;
    let wire_bytes = actual_wire_bytes - DELIVER_FRAMING_BYTES;
    let endpoint = peers
        .get(&outgoing.receiver)
        .ok_or_else(|| DistributedError::Protocol("missing peer endpoint".into()))?;
    OUTBOUND_STREAMS.with(|streams| -> Result<(), DistributedError> {
        let mut streams = streams.borrow_mut();
        if !streams.contains_key(endpoint) {
            streams.insert(endpoint.clone(), connect_outbound(endpoint)?);
        }
        let stream = streams.get_mut(endpoint).expect("persistent peer stream");
        while !frame.complete() {
            match frame.write_once(stream) {
                Ok(_) => {}
                Err(error) if error.kind() == ErrorKind::Interrupted => {}
                Err(error) => {
                    streams.remove(endpoint);
                    return Err(error.into());
                }
            }
        }
        Ok(())
    })?;
    let mut state = shared
        .0
        .lock()
        .map_err(|_| DistributedError::Protocol("worker lock poisoned".into()))?;
    state.counters.messages_sent += 1;
    state.counters.bytes_sent += wire_bytes;
    state.counters.actual_wire_bytes += actual_wire_bytes;
    Ok(())
}

pub(super) fn deliver_outgoing_batch(
    shared: &SharedNode,
    node_id: u32,
    peers: &BTreeMap<u32, String>,
    outgoing: Vec<Outgoing>,
) -> Result<(), DistributedError> {
    let outgoing = outgoing
        .into_iter()
        .map(|outgoing| {
            Ok(EncodedOutgoing {
                protocol: outgoing.protocol,
                receiver: outgoing.receiver,
                payload: Arc::from(canonical_serialize(&outgoing.message)?),
            })
        })
        .collect::<Result<Vec<_>, DistributedError>>()?;
    deliver_encoded_outgoing_batch(shared, node_id, peers, outgoing)
}

pub(super) fn deliver_same_outgoing_batch(
    shared: &SharedNode,
    node_id: u32,
    peers: &BTreeMap<u32, String>,
    protocol: &str,
    message: &DistributedMessage,
    receivers: u32,
) -> Result<(), DistributedError> {
    let payload: Arc<[u8]> = Arc::from(canonical_serialize(message)?);
    let outgoing = (0..receivers)
        .map(|receiver| EncodedOutgoing {
            protocol: protocol.into(),
            receiver,
            payload: Arc::clone(&payload),
        })
        .collect();
    deliver_encoded_outgoing_batch(shared, node_id, peers, outgoing)
}

fn deliver_encoded_outgoing_batch(
    shared: &SharedNode,
    node_id: u32,
    peers: &BTreeMap<u32, String>,
    outgoing: Vec<EncodedOutgoing>,
) -> Result<(), DistributedError> {
    let mut receivers = BTreeSet::new();
    if outgoing
        .iter()
        .any(|message| !receivers.insert(message.receiver))
    {
        return Err(DistributedError::Protocol(
            "parallel fan-out contains a duplicate receiver".into(),
        ));
    }
    let sequence_start = {
        let mut state = shared
            .0
            .lock()
            .map_err(|_| DistributedError::Protocol("worker lock poisoned".into()))?;
        let start = state.envelope_sequence;
        state.envelope_sequence = state
            .envelope_sequence
            .checked_add(outgoing.len() as u64)
            .ok_or_else(|| DistributedError::Protocol("envelope sequence exhausted".into()))?;
        start
    };
    let mut remote = Vec::new();
    let mut endpoints = BTreeSet::new();
    let mut delivered_to_self = false;
    for (offset, outgoing) in outgoing.into_iter().enumerate() {
        let sequence = sequence_start + offset as u64;
        if outgoing.receiver == node_id {
            let mut state = shared
                .0
                .lock()
                .map_err(|_| DistributedError::Protocol("worker lock poisoned".into()))?;
            if !state.retired_protocols.contains(&outgoing.protocol) {
                state.inbox.push_back(InboxEnvelope {
                    envelope: WireEnvelope {
                        protocol: outgoing.protocol,
                        version: 1,
                        sender: node_id,
                        receiver: outgoing.receiver,
                        sequence,
                        payload: outgoing.payload.to_vec(),
                    },
                    network_wire_bytes: 0,
                    receive_deserialize_cpu_ns: 0,
                });
                delivered_to_self = true;
            }
            continue;
        }
        let frame = OutboundFrame::new(
            &outgoing.protocol,
            node_id,
            outgoing.receiver,
            sequence,
            outgoing.payload,
        )?;
        let endpoint = peers
            .get(&outgoing.receiver)
            .ok_or_else(|| DistributedError::Protocol("missing peer endpoint".into()))?
            .clone();
        if !endpoints.insert(endpoint.clone()) {
            return Err(DistributedError::Protocol(
                "fanout contains a duplicate peer endpoint".into(),
            ));
        }
        remote.push(PendingSend::new(endpoint, frame)?);
    }
    if delivered_to_self {
        shared.1.notify_all();
    }

    let mut write_result = write_pending_frames(&mut remote);
    let mut messages_sent = 0u64;
    let mut bytes_sent = 0u64;
    let mut actual_wire_bytes = 0u64;
    for send in &mut remote {
        if send.frame.complete() {
            messages_sent += 1;
            actual_wire_bytes += send.frame.wire_bytes() as u64;
            bytes_sent += send.frame.wire_bytes() as u64 - DELIVER_FRAMING_BYTES;
        }
        let restored = send.restore_blocking();
        if write_result.is_ok() {
            write_result = restored;
        }
    }

    let mut state = shared
        .0
        .lock()
        .map_err(|_| DistributedError::Protocol("worker lock poisoned".into()))?;
    state.counters.messages_sent += messages_sent;
    state.counters.bytes_sent += bytes_sent;
    state.counters.actual_wire_bytes += actual_wire_bytes;
    drop(state);
    write_result?;
    Ok(())
}

pub(super) fn ping(endpoint: &str) -> Result<(), DistributedError> {
    match exchange(endpoint, &FramedRequest::Ping) {
        Ok(NodeResponse::Ack) => Ok(()),
        Err(error) => {
            OUTBOUND_STREAMS.with(|streams| {
                streams.borrow_mut().remove(endpoint);
            });
            Err(error)
        }
    }
}

fn clone_outbound_stream(address: &str) -> Result<TcpStream, DistributedError> {
    OUTBOUND_STREAMS.with(|streams| {
        let mut streams = streams.borrow_mut();
        if !streams.contains_key(address) {
            streams.insert(address.to_owned(), connect_outbound(address)?);
        }
        streams
            .get(address)
            .ok_or_else(|| DistributedError::Protocol("missing persistent peer stream".into()))?
            .try_clone()
            .map_err(Into::into)
    })
}

fn remove_outbound_stream(address: &str) {
    OUTBOUND_STREAMS.with(|streams| {
        streams.borrow_mut().remove(address);
    });
}

pub(super) fn exchange(
    address: &str,
    request: &FramedRequest,
) -> Result<NodeResponse, DistributedError> {
    OUTBOUND_STREAMS.with(|streams| {
        let mut streams = streams.borrow_mut();
        if !streams.contains_key(address) {
            let stream = connect_outbound(address)?;
            streams.insert(address.to_owned(), stream);
        }
        let stream = streams
            .get_mut(address)
            .ok_or_else(|| DistributedError::Protocol("missing persistent peer stream".into()))?;
        write_frame(stream, request)?;
        read_frame(stream)
    })
}

fn connect_outbound(address: &str) -> Result<TcpStream, DistributedError> {
    let mut last_error = None;
    for socket in address.to_socket_addrs()? {
        match TcpStream::connect_timeout(&socket, OUTBOUND_CONNECT_TIMEOUT) {
            Ok(stream) => {
                stream.set_nodelay(true)?;
                return Ok(stream);
            }
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error
        .unwrap_or_else(|| {
            std::io::Error::new(
                ErrorKind::InvalidInput,
                format!("peer endpoint {address:?} resolved to no socket addresses"),
            )
        })
        .into())
}

pub(super) fn write_frame<T: Serialize>(
    stream: &mut TcpStream,
    value: &T,
) -> Result<u64, DistributedError> {
    let bytes = canonical_serialize(value)?;
    write_encoded_frame(stream, &bytes)
}

fn write_encoded_frame(stream: &mut TcpStream, bytes: &[u8]) -> Result<u64, DistributedError> {
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(DistributedError::Protocol(
            "control frame exceeds limit".into(),
        ));
    }
    stream.write_all(&(bytes.len() as u32).to_be_bytes())?;
    stream.write_all(bytes)?;
    Ok(bytes.len() as u64 + protocol_support::transport::FRAME_PREFIX_BYTES)
}

pub(super) fn read_frame<T: DeserializeOwned + Serialize>(
    stream: &mut TcpStream,
) -> Result<T, DistributedError> {
    let mut length = [0; 4];
    stream.read_exact(&mut length)?;
    let length = u32::from_be_bytes(length) as usize;
    if length > MAX_FRAME_BYTES {
        return Err(DistributedError::Protocol(
            "control frame exceeds limit".into(),
        ));
    }
    let mut bytes = vec![0; length];
    stream.read_exact(&mut bytes)?;
    canonical_deserialize(&bytes).map_err(Into::into)
}

pub(super) fn read_frame_measured<T: DeserializeOwned>(
    stream: &mut TcpStream,
) -> Result<(T, u64, usize), DistributedError> {
    let mut length = [0; 4];
    stream.read_exact(&mut length)?;
    let length = u32::from_be_bytes(length) as usize;
    if length > MAX_FRAME_BYTES {
        return Err(DistributedError::Protocol(
            "control frame exceeds limit".into(),
        ));
    }
    let mut bytes = vec![0; length];
    stream.read_exact(&mut bytes)?;
    let timer = ThreadTime::now();
    let value = framing_deserialize(&bytes)?;
    Ok((value, nanos(timer.elapsed()), length))
}
