//! Bounded asynchronous verification with a shared network/completion wakeup.
use super::message_flow::protocol_error;
use super::{DistributedError, SharedNode};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub(super) struct ComputeQueue<T: Send + 'static> {
    network: SharedNode,
    ready: Arc<Mutex<VecDeque<Result<T, String>>>>,
    pending: usize,
}
impl<T: Send + 'static> ComputeQueue<T> {
    pub fn new(network: &SharedNode) -> Self {
        Self {
            network: Arc::clone(network),
            ready: Arc::new(Mutex::new(VecDeque::new())),
            pending: 0,
        }
    }
    pub fn has_capacity(&self) -> bool {
        self.pending < protocol_support::compute::workers() * 2
    }
    pub fn submit(&mut self, job: impl FnOnce() -> T + Send + 'static) {
        assert!(self.has_capacity());
        self.pending += 1;
        let ready = Arc::clone(&self.ready);
        let network = Arc::clone(&self.network);
        protocol_support::compute::spawn(move || {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(job))
                .map_err(|_| "cryptographic worker panicked".to_owned());
            // Same lock order as wait(): completion cannot race past the
            // predicate check and cause a lost notification.
            let _network = network.0.lock().expect("network state");
            ready.lock().expect("compute completions").push_back(result);
            network.1.notify_all();
        });
    }
    pub fn drain(&mut self) -> Result<Vec<T>, DistributedError> {
        let items = self
            .ready
            .lock()
            .map_err(protocol_error)?
            .drain(..)
            .collect::<Vec<_>>();
        self.pending -= items.len();
        items
            .into_iter()
            .map(|item| item.map_err(protocol_error))
            .collect()
    }
    pub fn wait(&self, protocols: &[&str]) -> Result<(), DistributedError> {
        let state = self.network.0.lock().map_err(protocol_error)?;
        if self.ready.lock().map_err(protocol_error)?.is_empty()
            && !state
                .inbox
                .iter()
                .any(|item| protocols.contains(&item.envelope.protocol.as_str()))
        {
            drop(
                self.network
                    .1
                    .wait_timeout(state, Duration::from_millis(100))
                    .map_err(protocol_error)?,
            );
        }
        Ok(())
    }
}
impl<T: Send + 'static> Drop for ComputeQueue<T> {
    fn drop(&mut self) {
        // Epoch retirement must not leave crypto jobs touching old state.
        while self.pending > 0 {
            let _ = self.drain();
            if self.pending > 0 {
                let _ = self.wait(&[]);
            }
        }
    }
}
