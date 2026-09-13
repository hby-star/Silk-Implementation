//! Bounded cryptographic work, separate from transport threads.
//!
//! One process-wide pool uses at most two cores. A CPU-time token bucket
//! targets 80% of their capacity, with a small burst allowance. This is a
//! cooperative average budget, not an instantaneous operating-system quota.
use cpu_time::ThreadTime;
use rayon::prelude::*;
use std::cell::RefCell;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

thread_local! {
    static LAST_CPU: RefCell<Option<ThreadTime>> = const { RefCell::new(None) };
}
static CPU_NS: AtomicU64 = AtomicU64::new(0);
static PARK_NS: AtomicU64 = AtomicU64::new(0);
const BURST_NS: f64 = 4_000_000.0;

pub fn workers() -> usize {
    static WORKERS: OnceLock<usize> = OnceLock::new();
    *WORKERS.get_or_init(|| {
        std::thread::available_parallelism()
            .map(usize::from)
            .unwrap_or(1)
            .clamp(1, 2)
    })
}

struct Budget {
    at: Instant,
    tokens: f64,
}
impl Budget {
    fn charge(&mut self, now: Instant, cpu_ns: u64, capacity: f64) -> Duration {
        // CPU is charged retrospectively at a checkpoint. Credit the elapsed
        // interval against that work before limiting unused burst credit;
        // capping first incorrectly throttles even long single-core jobs.
        self.tokens = (self.tokens + now.duration_since(self.at).as_nanos() as f64 * capacity
            - cpu_ns as f64)
            .min(BURST_NS);
        self.at = now;
        Duration::from_nanos((-self.tokens / capacity).max(0.0).ceil() as u64)
    }
}

fn budget() -> &'static Mutex<Budget> {
    static BUDGET: OnceLock<Mutex<Budget>> = OnceLock::new();
    BUDGET.get_or_init(|| {
        Mutex::new(Budget {
            at: Instant::now(),
            tokens: BURST_NS,
        })
    })
}

fn checkpoint() {
    let elapsed = LAST_CPU.with(|last| {
        let now = ThreadTime::now();
        let mut last = last.borrow_mut();
        let elapsed = last
            .as_ref()
            .map(|previous| previous.elapsed().as_nanos() as u64)
            .unwrap_or(0);
        *last = Some(now);
        elapsed
    });
    CPU_NS.fetch_add(elapsed, Ordering::Relaxed);
    let delay = budget().lock().expect("compute budget").charge(
        Instant::now(),
        elapsed,
        workers() as f64 * 0.8,
    );
    if !delay.is_zero() {
        let start = Instant::now();
        std::thread::sleep(delay);
        PARK_NS.fetch_add(start.elapsed().as_nanos() as u64, Ordering::Relaxed);
    }
}

fn pool() -> &'static rayon::ThreadPool {
    static POOL: OnceLock<rayon::ThreadPool> = OnceLock::new();
    POOL.get_or_init(|| {
        // Start wall credit before any worker can execute its first job.
        // Initializing at the first completion loses that entire interval.
        let _ = budget();
        rayon::ThreadPoolBuilder::new()
            .num_threads(workers())
            .thread_name(|i| format!("beacon-crypto-{i}"))
            .start_handler(|_| LAST_CPU.with(|last| *last.borrow_mut() = Some(ThreadTime::now())))
            .build()
            .expect("bounded crypto pool")
    })
}

pub fn run<T: Send>(job: impl FnOnce() -> T + Send) -> T {
    pool().install(|| {
        let result = job();
        checkpoint();
        result
    })
}

/// Ordered results preserve transcript indices despite out-of-order execution.
pub fn map<T: Send>(len: usize, job: impl Fn(usize) -> T + Send + Sync) -> Vec<T> {
    pool().install(|| {
        (0..len)
            .into_par_iter()
            .map(|index| {
                let result = job(index);
                checkpoint();
                result
            })
            .collect()
    })
}

/// Callers must bound outstanding jobs and must not hold shared state locks.
pub fn spawn(job: impl FnOnce() + Send + 'static) {
    pool().spawn(move || {
        job();
        checkpoint();
    });
}

pub fn counters() -> (u64, u64) {
    (
        CPU_NS.load(Ordering::Relaxed),
        PARK_NS.load(Ordering::Relaxed),
    )
}
