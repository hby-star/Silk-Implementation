use cpu_time::ProcessTime;
use serde::{Deserialize, Serialize};
use std::time::Instant;
use sysinfo::{Pid, ProcessesToUpdate, System};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct PhaseMeasurement {
    pub wall_ns: u64,
    pub cpu_ns: u64,
    pub rss_start_bytes: u64,
    pub rss_end_bytes: u64,
    pub rss_peak_bytes: u64,
}

#[derive(Debug)]
pub struct PhaseTimer {
    wall: Instant,
    cpu: ProcessTime,
    rss_start_bytes: u64,
    rss_peak_bytes: u64,
}

impl PhaseTimer {
    pub fn start() -> Self {
        let rss = process_rss_bytes();
        Self {
            wall: Instant::now(),
            cpu: ProcessTime::now(),
            rss_start_bytes: rss,
            rss_peak_bytes: rss,
        }
    }

    /// Samples RSS during a long-running operation so callers can retain a
    /// peak instead of relying only on start and end snapshots.
    pub fn sample_rss(&mut self) -> u64 {
        let rss = process_rss_bytes();
        self.rss_peak_bytes = self.rss_peak_bytes.max(rss);
        rss
    }

    pub fn finish(mut self) -> PhaseMeasurement {
        let rss_end_bytes = self.sample_rss();
        PhaseMeasurement {
            wall_ns: nanos_u64(self.wall.elapsed().as_nanos()),
            cpu_ns: nanos_u64(self.cpu.elapsed().as_nanos()),
            rss_start_bytes: self.rss_start_bytes,
            rss_end_bytes,
            rss_peak_bytes: self.rss_peak_bytes,
        }
    }
}

pub fn process_rss_bytes() -> u64 {
    let pid = Pid::from_u32(std::process::id());
    let mut system = System::new();
    system.refresh_processes(ProcessesToUpdate::Some(&[pid]), true);
    system.process(pid).map_or(0, |process| process.memory())
}

fn nanos_u64(value: u128) -> u64 {
    value.min(u64::MAX as u128) as u64
}
