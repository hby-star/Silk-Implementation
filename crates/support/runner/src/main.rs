#![recursion_limit = "256"]

use experiment_records as artifacts;
mod bavss;
use beacon_node as beacon;
mod cli;
mod config;

use crate::beacon::BeaconImplementation;
use crate::cli::{Cli, Command};
use crate::config::{
    ExecutionMode, ExperimentConfig, ExperimentKind, distributed_endpoints, require_execution_mode,
};
use clap::Parser;
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    match Cli::parse().command {
        Command::BuildInfo => {
            println!(
                "{}",
                serde_json::json!({
                    "schema_id": "silk-build-info/v1",
                    "git_commit": env!("GIT_COMMIT"),
                    "git_dirty": env!("GIT_DIRTY") == "true",
                    "source_fingerprint": env!("SOURCE_FINGERPRINT"),
                })
            );
            Ok(())
        }
        Command::Idle => loop {
            std::thread::park();
        },
        Command::DistributedRun {
            config,
            run_id,
            implementation,
            node_id,
            n,
            t,
            slots,
            listen,
            store_root,
            output,
            samples,
            seed,
        } => {
            let config_bytes = std::fs::read(&config)?;
            let experiment: ExperimentConfig = toml::from_str(std::str::from_utf8(&config_bytes)?)?;
            let experiment = experiment.resolve()?;
            require_execution_mode(experiment, ExecutionMode::Distributed)?;
            let peers = distributed_endpoints()?
                .ok_or("SILK_NODE_ENDPOINTS_JSON is required for distributed-run")?;
            let implementation = implementation.parse::<BeaconImplementation>()?;
            let autonomous = beacon::AutonomousConfig {
                observation_labels: [
                    "SILK_SAMPLE_ROLE",
                    "SILK_EXECUTOR",
                    "SILK_NETWORK_SCENARIO",
                    "SILK_RESOURCE_PROFILE",
                ]
                .into_iter()
                .filter_map(|key| std::env::var(key).ok().map(|value| (key.into(), value)))
                .collect(),
                build_git_commit: env!("GIT_COMMIT").into(),
                build_source_fingerprint: env!("SOURCE_FINGERPRINT").into(),
                node: beacon::NodeConfig {
                    node_id,
                    n,
                    t,
                    slots,
                    seed,
                    listen,
                    peers,
                    store_root,
                },
                run_id,
                experiment_id: experiment.as_str().to_owned(),
                implementation,
                samples,
                output_root: output,
            };
            match experiment {
                ExperimentKind::BeaconPerformance => {
                    let output_root = autonomous.output_root.clone();
                    let node_root = output_root.join(format!("node-{}", autonomous.node.node_id));
                    let mut observer =
                        artifacts::NodeLogger::create(&node_root, autonomous.node.node_id)?;
                    beacon::run_beacon_performance(autonomous, &mut observer)?;
                    // Executor retirement is outside protocol execution and measurement.
                    if std::env::var("SILK_EXECUTOR_RETIREMENT").as_deref() == Ok("all-complete-v1")
                    {
                        let deadline =
                            std::time::Instant::now() + std::time::Duration::from_secs(3600);
                        while !output_root.join("executor-release").is_file() {
                            if std::time::Instant::now() >= deadline {
                                return Err("executor retirement release timed out".into());
                            }
                            std::thread::sleep(std::time::Duration::from_millis(50));
                        }
                    }
                    Ok(())
                }
                ExperimentKind::BavssPhaseCost => {
                    Err("bavss-phase-cost cannot be dispatched through distributed-run".into())
                }
            }
        }
        Command::Run {
            config,
            run_id,
            output,
            n,
            t,
            slots,
            samples,
            seed,
        } => bavss::run(config, run_id, output, n, t, slots, samples, seed),
    }
}
