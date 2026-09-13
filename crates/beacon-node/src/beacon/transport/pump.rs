//! Nonblocking, per-peer ordered sends advanced by a protocol event loop.
//! Enqueue is not a successful write. Counters advance only on complete frames.

use super::*;

struct PeerQueue {
    endpoint: String,
    stream: Option<mio::net::TcpStream>,
    frames: VecDeque<(OutboundFrame, String)>,
    registered: bool,
    connecting: Option<(Instant, u64)>,
    retry_at: Option<Instant>,
}

impl Drop for PeerQueue {
    fn drop(&mut self) {
        if let Some(stream) = self.stream.take() {
            let stream: TcpStream = stream.into();
            if stream.set_nonblocking(false).is_err() || !self.frames.is_empty() {
                remove_outbound_stream(&self.endpoint);
            }
        }
    }
}

pub(in crate::beacon) struct ProtocolPump {
    poll: Poll,
    events: Events,
    peers: Vec<PeerQueue>,
    by_endpoint: BTreeMap<String, usize>,
    ready: BTreeSet<usize>,
    pub(in crate::beacon) writes: Vec<serde_json::Value>,
    pub(in crate::beacon) connections: Vec<serde_json::Value>,
    async_connect: bool,
}

impl ProtocolPump {
    pub(in crate::beacon) fn new() -> Result<Self, DistributedError> {
        Ok(Self {
            poll: Poll::new()?,
            events: Events::with_capacity(128),
            peers: Vec::new(),
            by_endpoint: BTreeMap::new(),
            ready: BTreeSet::new(),
            writes: Vec::new(),
            connections: Vec::new(),
            async_connect: false,
        })
    }

    /// The certificate service owns fresh sockets on its own thread. Start
    /// their TCP handshakes together rather than blocking once per requester.
    pub(in crate::beacon) fn with_async_connections() -> Result<Self, DistributedError> {
        let mut pump = Self::new()?;
        pump.async_connect = true;
        Ok(pump)
    }

    /// Transfer the startup probe's idle streams, never clone a socket with
    /// another writer. All protocol traffic then shares one ordered peer queue.
    pub(in crate::beacon) fn with_startup_connections() -> Result<Self, DistributedError> {
        let mut pump = Self::with_async_connections()?;
        let streams = OUTBOUND_STREAMS.with(|streams| std::mem::take(&mut *streams.borrow_mut()));
        for (endpoint, stream) in streams {
            stream.set_nonblocking(true)?;
            let index = pump.peers.len();
            pump.by_endpoint.insert(endpoint.clone(), index);
            pump.peers.push(PeerQueue {
                endpoint,
                stream: Some(mio::net::TcpStream::from_std(stream)),
                frames: VecDeque::new(),
                registered: false,
                connecting: None,
                retry_at: None,
            });
        }
        Ok(pump)
    }

    pub(in crate::beacon) fn enqueue(
        &mut self,
        shared: &SharedNode,
        config: &AutonomousConfig,
        protocol: &str,
        message: &DistributedMessage,
        receivers: &[u32],
        label: &str,
    ) -> Result<(), DistributedError> {
        let mut unique = BTreeSet::new();
        let mut endpoints = BTreeSet::new();
        for receiver in receivers {
            if *receiver as usize >= config.node.n
                || !unique.insert(*receiver)
                || (*receiver != config.node.node_id
                    && !endpoints.insert(
                        config.node.peers.get(receiver).ok_or_else(|| {
                            DistributedError::Protocol("missing queued peer".into())
                        })?,
                    ))
            {
                return Err(DistributedError::Protocol(
                    "invalid or duplicate queued receiver/endpoint".into(),
                ));
            }
        }
        let payload: Arc<[u8]> = Arc::from(canonical_serialize(message)?);
        let start = {
            let mut state = shared
                .0
                .lock()
                .map_err(|_| DistributedError::Protocol("worker lock poisoned".into()))?;
            let start = state.envelope_sequence;
            state.envelope_sequence = start
                .checked_add(receivers.len() as u64)
                .ok_or_else(|| DistributedError::Protocol("envelope sequence exhausted".into()))?;
            start
        };
        for (offset, receiver) in receivers.iter().enumerate() {
            let sequence = start + offset as u64;
            if *receiver == config.node.node_id {
                let mut state = shared
                    .0
                    .lock()
                    .map_err(|_| DistributedError::Protocol("worker lock poisoned".into()))?;
                state.inbox.push_back(InboxEnvelope {
                    envelope: WireEnvelope {
                        protocol: protocol.into(),
                        version: 1,
                        sender: config.node.node_id,
                        receiver: *receiver,
                        sequence,
                        payload: payload.to_vec(),
                    },
                    network_wire_bytes: 0,
                    receive_deserialize_cpu_ns: 0,
                });
                drop(state);
                shared.1.notify_all();
                continue;
            }
            let endpoint = config
                .node
                .peers
                .get(receiver)
                .ok_or_else(|| DistributedError::Protocol("missing queued peer".into()))?;
            let index = match self.by_endpoint.get(endpoint) {
                Some(index) => *index,
                None => {
                    let (socket, connecting) = if self.async_connect {
                        let address = endpoint.parse::<std::net::SocketAddr>().map_err(|_| {
                            DistributedError::Protocol(
                                "async service requires a numeric peer address".into(),
                            )
                        })?;
                        let started = (Instant::now(), super::super::observation::unix_time_ns()?);
                        match mio::net::TcpStream::connect(address) {
                            Ok(socket) => (Some(socket), Some(started)),
                            Err(_) => (None, None),
                        }
                    } else {
                        let socket = clone_outbound_stream(endpoint)?;
                        socket.set_nonblocking(true)?;
                        (Some(mio::net::TcpStream::from_std(socket)), None)
                    };
                    let index = self.peers.len();
                    let retry_at = socket.is_none().then(Instant::now);
                    self.peers.push(PeerQueue {
                        endpoint: endpoint.clone(),
                        stream: socket,
                        frames: VecDeque::new(),
                        registered: false,
                        connecting,
                        retry_at,
                    });
                    self.by_endpoint.insert(endpoint.clone(), index);
                    index
                }
            };
            let peer = &mut self.peers[index];
            let frame = OutboundFrame::new(
                protocol,
                config.node.node_id,
                *receiver,
                sequence,
                Arc::clone(&payload),
            )?;
            if peer
                .frames
                .iter()
                .map(|(f, _)| f.wire_bytes())
                .sum::<usize>()
                + frame.wire_bytes()
                > 64 * 1024 * 1024
            {
                return Err(DistributedError::Protocol(
                    "protocol sender queue exceeds resource limit".into(),
                ));
            }
            peer.frames.push_back((frame, label.into()));
            if !peer.registered
                && let Some(stream) = peer.stream.as_mut()
            {
                if let Err(error) =
                    self.poll
                        .registry()
                        .register(stream, Token(index), Interest::WRITABLE)
                {
                    self.retry_peer(index, &error.to_string())?;
                    continue;
                }
                peer.registered = true;
            }
            if peer.connecting.is_none() && peer.stream.is_some() {
                self.ready.insert(index);
            }
        }
        Ok(())
    }

    /// At most one 64-KiB write per ready peer; return to the protocol even
    /// when a peer is blocked. No global write-completion barrier is here.
    pub(in crate::beacon) fn advance(
        &mut self,
        shared: &SharedNode,
    ) -> Result<(), DistributedError> {
        for index in 0..self.peers.len() {
            if self.peers[index]
                .connecting
                .is_some_and(|(start, _)| start.elapsed() >= OUTBOUND_CONNECT_TIMEOUT)
            {
                self.retry_peer(index, "connect timeout")?;
            }
            let peer = &mut self.peers[index];
            if peer.retry_at.is_some_and(|retry| Instant::now() >= retry) && !peer.frames.is_empty()
            {
                let address = peer
                    .endpoint
                    .parse::<std::net::SocketAddr>()
                    .map_err(message_flow::protocol_error)?;
                match mio::net::TcpStream::connect(address) {
                    Ok(mut socket) => {
                        if self
                            .poll
                            .registry()
                            .register(&mut socket, Token(index), Interest::WRITABLE)
                            .is_err()
                        {
                            peer.retry_at = Some(Instant::now() + Duration::from_millis(250));
                            continue;
                        }
                        peer.stream = Some(socket);
                        peer.registered = true;
                        peer.connecting =
                            Some((Instant::now(), super::super::observation::unix_time_ns()?));
                        peer.retry_at = None;
                    }
                    Err(_) => peer.retry_at = Some(Instant::now() + Duration::from_millis(250)),
                }
            }
        }
        match self.poll.poll(&mut self.events, Some(Duration::ZERO)) {
            Ok(()) => {}
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) => return Err(e.into()),
        }
        for event in self.events.iter() {
            let index = event.token().0;
            if !self.peers[index].frames.is_empty() && self.peers[index].stream.is_some() {
                self.ready.insert(index);
            }
        }
        let mut messages = 0;
        let mut wire = 0;
        let result = (|| -> Result<(), DistributedError> {
            for index in std::mem::take(&mut self.ready) {
                let peer = &mut self.peers[index];
                if let Some((_, start)) = peer.connecting.take() {
                    if let Some(error) = peer
                        .stream
                        .as_ref()
                        .expect("connecting stream")
                        .take_error()?
                    {
                        self.retry_peer(index, &error.to_string())?;
                        continue;
                    }
                    if let Err(error) = peer
                        .stream
                        .as_ref()
                        .expect("connected stream")
                        .set_nodelay(true)
                    {
                        self.retry_peer(index, &error.to_string())?;
                        continue;
                    }
                    self.connections.push(
                        serde_json::json!({"event":"certificate-service-connect",
                        "endpoint":peer.endpoint,"start_unix_ns":start,
                        "unix_ns":super::super::observation::unix_time_ns()?}),
                    );
                }
                let Some((frame, _)) = peer.frames.front_mut() else {
                    continue;
                };
                match frame.write_once(peer.stream.as_mut().expect("queued stream")) {
                    Ok(_) => {
                        if frame.complete() {
                            let (frame, label) = peer.frames.pop_front().expect("completed frame");
                            messages += 1;
                            wire += frame.wire_bytes() as u64;
                            self.writes.push(serde_json::json!({"label":label,"endpoint":peer.endpoint,
                            "framed_bytes":frame.wire_bytes(),"socket_write_complete_unix_ns": super::super::observation::unix_time_ns()?}));
                        }
                        if peer.frames.is_empty() {
                            self.poll
                                .registry()
                                .deregister(peer.stream.as_mut().expect("queued stream"))?;
                            peer.registered = false;
                        } else {
                            self.ready.insert(index);
                        }
                    }
                    Err(e) if e.kind() == ErrorKind::Interrupted => {
                        self.ready.insert(index);
                    }
                    Err(e) if e.kind() == ErrorKind::WouldBlock => {}
                    Err(e) => self.retry_peer(index, &e.to_string())?,
                }
            }
            Ok(())
        })();
        if messages != 0 {
            let mut state = shared
                .0
                .lock()
                .map_err(|_| DistributedError::Protocol("worker lock poisoned".into()))?;
            state.counters.messages_sent += messages;
            state.counters.actual_wire_bytes += wire;
            state.counters.bytes_sent += wire - messages * DELIVER_FRAMING_BYTES;
        }
        result
    }

    pub(in crate::beacon) fn is_empty(&self) -> bool {
        self.peers.iter().all(|p| p.frames.is_empty())
    }
    /// A failed peer is retried independently. Its queued frame is restarted
    /// on a fresh stream; incomplete writes never enter the wire counters.
    fn retry_peer(&mut self, index: usize, reason: &str) -> Result<(), DistributedError> {
        let peer = &mut self.peers[index];
        if let Some(mut stream) = peer.stream.take()
            && peer.registered
        {
            let _ = self.poll.registry().deregister(&mut stream);
        }
        peer.registered = false;
        peer.connecting = None;
        peer.retry_at = Some(Instant::now() + Duration::from_millis(250));
        if let Some((frame, _)) = peer.frames.front_mut() {
            frame.written = 0;
        }
        self.ready.remove(&index);
        self.connections.push(
            serde_json::json!({"event":"peer-send-retry", "endpoint":peer.endpoint,
            "reason":reason, "unix_ns":super::super::observation::unix_time_ns()?}),
        );
        Ok(())
    }
    pub(in crate::beacon) fn runnable(&self) -> bool {
        !self.ready.is_empty()
    }
}
