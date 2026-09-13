//! Epoch-local ordered dissemination. A slow socket never gates quorum reception.
use super::*;
use std::sync::atomic::{AtomicBool, Ordering};

#[derive(Clone)]
pub(in crate::beacon) struct BackgroundSender {
    pump: Arc<Mutex<Vec<ProtocolPump>>>,
    worker: std::thread::Thread,
    error: Arc<Mutex<Option<String>>>,
}

impl BackgroundSender {
    pub(in crate::beacon) fn get(shared: &SharedNode) -> Result<Self, DistributedError> {
        shared
            .0
            .lock()
            .map_err(message_flow::protocol_error)?
            .sender
            .clone()
            .ok_or_else(|| message_flow::protocol_error("missing protocol sender service"))
    }
    pub(in crate::beacon) fn check_error(&self) -> Result<(), DistributedError> {
        if let Some(error) = &*self.error.lock().map_err(message_flow::protocol_error)? {
            return Err(message_flow::protocol_error(error));
        }
        Ok(())
    }

    pub(in crate::beacon) fn enqueue(
        &self,
        shared: &SharedNode,
        config: &AutonomousConfig,
        protocol: &str,
        message: &DistributedMessage,
        receivers: &[u32],
    ) -> Result<(), DistributedError> {
        self.enqueue_labeled(shared, config, protocol, message, receivers, protocol)
    }
    #[allow(clippy::too_many_arguments)]
    pub(in crate::beacon) fn enqueue_labeled(
        &self,
        shared: &SharedNode,
        config: &AutonomousConfig,
        protocol: &str,
        message: &DistributedMessage,
        receivers: &[u32],
        label: &str,
    ) -> Result<(), DistributedError> {
        self.check_error()?;
        self.pump.lock().map_err(message_flow::protocol_error)?[0]
            .enqueue(shared, config, protocol, message, receivers, label)?;
        self.worker.unpark();
        Ok(())
    }
}

pub(in crate::beacon) struct SenderService {
    shared: SharedNode,
    stop: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<Result<Vec<serde_json::Value>, DistributedError>>>,
}

impl SenderService {
    pub(in crate::beacon) fn start(shared: &SharedNode) -> Result<Self, DistributedError> {
        let pump = Arc::new(Mutex::new(vec![ProtocolPump::with_startup_connections()?]));
        let stop = Arc::new(AtomicBool::new(false));
        let error = Arc::new(Mutex::new(None));
        let (worker_pump, worker_stop, worker_error, network) = (
            Arc::clone(&pump),
            Arc::clone(&stop),
            Arc::clone(&error),
            Arc::clone(shared),
        );
        let handle = std::thread::Builder::new().name("protocol-sender".into()).spawn(move || {
            let cpu = cpu_time::ThreadTime::now();
            let result = (|| {
                let mut stopping = None;
                loop {
                    let mut pump = worker_pump.lock().map_err(message_flow::protocol_error)?;
                    if worker_stop.load(Ordering::Acquire) {
                        if pump.iter().all(ProtocolPump::is_empty) { break; }
                        if stopping.get_or_insert_with(Instant::now).elapsed() > Duration::from_secs(10) {
                            return Err(message_flow::protocol_error("protocol sender retirement drain timed out"));
                        }
                    }
                    for pending in pump.iter_mut() { pending.advance(&network)?; }
                    let (empty, runnable) = (pump.iter().all(ProtocolPump::is_empty), pump.iter().any(ProtocolPump::runnable));
                    drop(pump);
                    if !runnable {
                        // unpark is remembered even if enqueue precedes this park.
                        std::thread::park_timeout(if empty { Duration::from_secs(1) } else { Duration::from_millis(1) });
                    }
                }
                let mut pump = worker_pump.lock().map_err(message_flow::protocol_error)?;
                let mut trace = Vec::new();
                for pending in pump.iter_mut() {
                    trace.extend(std::mem::take(&mut pending.writes));
                    trace.extend(std::mem::take(&mut pending.connections));
                }
                trace.push(serde_json::json!({"event":"protocol-sender-cpu","thread_cpu_ns":cpu.elapsed().as_nanos() as u64}));
                Ok(trace)
            })();
            if let Err(ref failure) = result {
                *worker_error.lock().expect("sender error") = Some(failure.to_string());
                network.1.notify_all();
            }
            result
        })?;
        shared
            .0
            .lock()
            .map_err(message_flow::protocol_error)?
            .sender = Some(BackgroundSender {
            pump,
            worker: handle.thread().clone(),
            error,
        });
        Ok(Self {
            shared: Arc::clone(shared),
            stop,
            handle: Some(handle),
        })
    }

    pub(in crate::beacon) fn finish(mut self) -> Result<Vec<serde_json::Value>, DistributedError> {
        self.stop.store(true, Ordering::Release);
        let handle = self.handle.take().expect("sender thread");
        handle.thread().unpark();
        let result = handle
            .join()
            .map_err(|_| message_flow::protocol_error("protocol sender panicked"))?;
        self.shared
            .0
            .lock()
            .map_err(message_flow::protocol_error)?
            .sender = None;
        result
    }
    /// Experiment retirement only. Preserve connections after draining the
    /// sample's sends; no epoch's protocol work is carried into the next one.
    pub(in crate::beacon) fn take_sample_trace(
        &self,
    ) -> Result<Vec<serde_json::Value>, DistributedError> {
        let sender = BackgroundSender::get(&self.shared)?;
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            sender.check_error()?;
            let mut pumps = sender.pump.lock().map_err(message_flow::protocol_error)?;
            if pumps.iter().all(ProtocolPump::is_empty) {
                let mut trace = Vec::new();
                for pump in pumps.iter_mut() {
                    trace.extend(std::mem::take(&mut pump.writes));
                    trace.extend(std::mem::take(&mut pump.connections));
                }
                return Ok(trace);
            }
            drop(pumps);
            if Instant::now() >= deadline {
                return Err(message_flow::protocol_error(
                    "sample sender drain timed out",
                ));
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }
}
impl Drop for SenderService {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(handle) = self.handle.take() {
            handle.thread().unpark();
            let _ = handle.join();
        }
        if let Ok(mut state) = self.shared.0.lock() {
            state.sender = None;
        }
    }
}
