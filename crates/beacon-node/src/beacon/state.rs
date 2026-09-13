use super::*;

pub(super) struct WorkerState {
    pub(super) node_id: u32,
    pub(super) store_root: PathBuf,
    pub(super) inbox: VecDeque<InboxEnvelope>,
    pub(super) retired_protocols: BTreeSet<String>,
    pub(super) envelope_sequence: u64,
    pub(super) counters: TransportCounters,
    pub(super) consumed_receive_cpu_ns: u64,
    pub(super) sender: Option<BackgroundSender>,
}

impl WorkerState {
    pub(super) fn new(config: &NodeConfig) -> Result<Self, DistributedError> {
        if config.n == 0
            || config.slots == 0
            || config.node_id as usize >= config.n
            || 3 * config.t >= config.n
            || config.peers.len() != config.n
        {
            return Err(DistributedError::Protocol(
                "invalid node configuration".into(),
            ));
        }
        fs::create_dir_all(&config.store_root)?;
        Ok(Self {
            node_id: config.node_id,
            store_root: config.store_root.clone(),
            inbox: VecDeque::new(),
            retired_protocols: BTreeSet::new(),
            envelope_sequence: 0,
            counters: TransportCounters::default(),
            consumed_receive_cpu_ns: 0,
            sender: None,
        })
    }
}
