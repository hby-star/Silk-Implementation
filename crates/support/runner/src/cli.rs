use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "experiment-runner",
    version,
    about = "Canonical Silk experiment node and primitive runner"
)]
pub(crate) struct Cli {
    #[command(subcommand)]
    pub(crate) command: Command,
}

#[derive(Subcommand)]
pub(crate) enum Command {
    /// Print immutable source identity embedded in this runner.
    BuildInfo,
    /// Run one config-driven bAVSS-PO phase-cost workload.
    Run {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        run_id: String,
        #[arg(long, default_value = "output/experiments/raw/bavss-phase-cost")]
        output: PathBuf,
        #[arg(long, default_value_t = 4)]
        n: usize,
        #[arg(long, default_value_t = 1)]
        t: usize,
        #[arg(long, default_value_t = 10)]
        slots: usize,
        #[arg(long, default_value_t = 1)]
        samples: u32,
        #[arg(long)]
        seed: u64,
    },
    /// Keep a container alive until the canonical executor starts its node process.
    Idle,
    /// Run one autonomous protocol replica; no coordinator can advance phases.
    DistributedRun {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        run_id: String,
        /// Select one full beacon implementation for this matrix cell.
        #[arg(long)]
        implementation: String,
        #[arg(long)]
        node_id: u32,
        #[arg(long)]
        n: usize,
        #[arg(long)]
        t: usize,
        #[arg(long)]
        slots: usize,
        #[arg(long, default_value = "0.0.0.0:7000")]
        listen: String,
        #[arg(long, default_value = "/state")]
        store_root: PathBuf,
        #[arg(long, default_value = "/node-results")]
        output: PathBuf,
        #[arg(long, default_value_t = 1)]
        samples: u32,
        #[arg(long)]
        seed: u64,
    },
}
