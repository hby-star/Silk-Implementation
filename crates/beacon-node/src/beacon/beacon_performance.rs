//! Process lifecycle and implementation dispatch for beacon-performance.

use super::rondo_beacon::{rondo_parallel_workers, run_rondo_sample};
use super::silk_beacon::run_silk_sample;
use super::spurt_beacon::run_spurt_sample;
use super::*;
use crate::observer::{NODE_LOG_SCHEMA, TRANSPORT_PROFILE, WIRE_ACCOUNTING_MODE};

pub fn run_beacon_performance(
    config: AutonomousConfig,
    logger: &mut dyn NodeObserver,
) -> Result<(), DistributedError> {
    if config.experiment_id != "beacon-performance"
        || config.samples == 0
        || config.run_id.trim().is_empty()
    {
        return Err(DistributedError::Protocol(
            "beacon-performance requires a non-empty canonical distributed run".into(),
        ));
    }
    let listener = TcpListener::bind(&config.node.listen)?;
    let shared = Arc::new((Mutex::new(WorkerState::new(&config.node)?), Condvar::new()));
    let listener_shared = Arc::clone(&shared);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            match stream {
                Ok(stream) => {
                    let state = Arc::clone(&listener_shared);
                    std::thread::spawn(move || {
                        if let Err(error) = handle_connection(stream, &state) {
                            eprintln!("beacon node connection: {error}");
                        }
                    });
                }
                Err(error) => {
                    eprintln!("beacon node listener: {error}");
                    break;
                }
            }
        }
    });
    coordination::wait_for_peers(
        &config.node.peers,
        config.node.node_id,
        Duration::from_secs(180),
    )?;

    let spurt_setup = if config.implementation == BeaconImplementation::Spurt {
        Some(
            ::spurt_beacon::SpurtSetup::new(
                config.node.n,
                config.node.t,
                config.node.seed,
                config.node.node_id,
            )
            .map_err(message_flow::protocol_error)?,
        )
    } else {
        None
    };

    let process_start = Instant::now();
    logger.artifact(
        "node.json",
        &
        serde_json::to_vec_pretty(&serde_json::json!({
            "schema_version": NODE_LOG_SCHEMA,
            "run_id": config.run_id,
            "experiment_id": config.experiment_id,
            "implementation": config.implementation.as_str(),
            "node_id": config.node.node_id,
            "role": "replica",
            "n": config.node.n,
            "t": config.node.t,
            "epoch_slots": config.node.slots,
            "seed": config.node.seed,
            "sample_role": config.observation_labels.get("SILK_SAMPLE_ROLE").cloned().unwrap_or_else(|| "smoke".into()),
            "executor": config.observation_labels.get("SILK_EXECUTOR").cloned().unwrap_or_else(|| "unknown".into()),
            "network_scenario": config.observation_labels.get("SILK_NETWORK_SCENARIO").cloned().unwrap_or_else(|| "unspecified".into()),
            "resource_profile": config.observation_labels.get("SILK_RESOURCE_PROFILE").cloned().unwrap_or_else(|| "unspecified".into()),
            "clock_source": "process-relative-monotonic-plus-system-time-unix-ns",
            "listen": config.node.listen,
            "peers": config.node.peers,
            "process_id": std::process::id(),
            "protocol_processes_in_container": 1,
            "protocol_processes_expected": config.node.n,
            "coordinator_processes_expected": 0,
            "log_scope": "single-replica",
            "distributed_contract": "no-coordinator-beacon-v1",
            "execution_model": "beacon-autonomous-message-driven-v1",
            "transport_connection_mode": TRANSPORT_PROFILE,
            "broadcast_fanout_profile": "persistent-background-ordered-per-peer-protocol-pump-v4",
            "quorum_collection_profile": "valid-distinct-sender-early-stop-v1",
            "wire_accounting_mode": WIRE_ACCOUNTING_MODE,
            "paired_execution_order_policy": "not-applicable",
            "external_phase_control": "rejected",
            "protocol_revision": ::silk_beacon::PROTOCOL_REVISION,
            "silk_profile": if config.implementation == BeaconImplementation::Silk {
                ::silk_beacon::IMPLEMENTATION_PROFILE
            } else {
                "not-applicable"
            },
            "silk_release_profile": if config.implementation == BeaconImplementation::Silk {
                ::silk_beacon::RELEASE_PROFILE
            } else {
                "not-applicable"
            },
            "silk_wire_profile": if config.implementation == BeaconImplementation::Silk {
                ::silk_beacon::WIRE_PROFILE
            } else {
                "not-applicable"
            },
            "silk_validation_profile": if config.implementation == BeaconImplementation::Silk {
                ::silk_beacon::VALIDATION_PROFILE
            } else {
                "not-applicable"
            },
            "silk_bft_profile": if config.implementation == BeaconImplementation::Silk {
                ::silk_beacon::BFT_PROFILE
            } else {
                "not-applicable"
            },
            "silk_reconstruction_backend": if config.implementation == BeaconImplementation::Silk {
                "compact-holder-set-adaptive-multipoint"
            } else {
                "not-applicable"
            },
            "silk_reconstruction_authentication": if config.implementation == BeaconImplementation::Silk {
                "authenticated-channel-no-payload-signature-v1"
            } else {
                "not-applicable"
            },
            "silk_response_repetitions": if config.implementation == BeaconImplementation::Silk {
                1
            } else {
                0
            },
            "rondo_breeze_profile": if config.implementation == BeaconImplementation::Rondo {
                ::rondo_beacon::BREEZE_PROFILE
            } else {
                "not-applicable"
            },
            "rondo_bft_profile": if config.implementation == BeaconImplementation::Rondo {
                ::rondo_beacon::bft::normal::PROFILE
            } else {
                "not-applicable"
            },
            "rondo_bft_signature_profile": if config.implementation == BeaconImplementation::Rondo {
                ::rondo_beacon::BFT_SIGNATURE_PROFILE
            } else {
                "not-applicable"
            },
            "rondo_reconstruction_profile": if config.implementation == BeaconImplementation::Rondo {
                ::rondo_beacon::RECONSTRUCTION_FIDELITY
            } else {
                "not-applicable"
            },
            "rondo_fallback_trigger_profile": if config.implementation == BeaconImplementation::Rondo {
                "decision-proof-request-on-fixed-holder-timeout-or-aggregate-failure-v1"
            } else {
                "not-applicable"
            },
            "rondo_reconstruction_pipeline_window": if config.implementation == BeaconImplementation::Rondo {
                config.node.slots
            } else {
                0
            },
            "rondo_breeze_workers": if config.implementation == BeaconImplementation::Rondo {
                rondo_parallel_workers()
            } else {
                0
            },
            "spurt_profile": if config.implementation == BeaconImplementation::Spurt {
                ::spurt_beacon::PROFILE
            } else {
                "not-applicable"
            },
            "spurt_fidelity": if config.implementation == BeaconImplementation::Spurt {
                ::spurt_beacon::FIDELITY
            } else {
                "not-applicable"
            },
            "spurt_setup_profile": if config.implementation == BeaconImplementation::Spurt {
                "long-lived-committee-parameters-and-keys-v1"
            } else {
                "not-applicable"
            },
            "spurt_pipeline_profile": if config.implementation == BeaconImplementation::Spurt {
                "future-epoch-preaggregation-window-v1"
            } else {
                "not-applicable"
            },
            "spurt_preaggregation_window": if config.implementation == BeaconImplementation::Spurt {
                config.node.slots
            } else {
                0
            },
            "coverage": if config.implementation == BeaconImplementation::Spurt {
                ::spurt_beacon::COVERAGE
            } else {
                "fixed-committee-normal-path-only"
            },
            "claim_scope": if config.implementation == BeaconImplementation::Spurt {
                ::spurt_beacon::CLAIM_SCOPE
            } else {
                "normal-path-performance"
            }
        }))
        .map_err(|error| DistributedError::Protocol(error.to_string()))?,
    )?;

    let mut all_outputs = Vec::new();
    let mut all_support = Vec::new();
    let mut bft_trace = Vec::new();
    let mut silk_predecessor = None;
    let sender = SenderService::start(&shared)?;
    for sample in 0..config.samples {
        coordination::sample_barrier(&shared, &config, sample, "beacon-performance-start")?;
        let _startup_writes = sender.take_sample_trace()?;
        let before = shared
            .0
            .lock()
            .map_err(message_flow::protocol_error)?
            .counters;

        let compute_before = protocol_support::compute::counters();
        let compute_window = Instant::now();
        match config.implementation {
            BeaconImplementation::Silk => {
                let result = run_silk_sample(
                    &shared,
                    &config,
                    logger,
                    &process_start,
                    sample,
                    silk_predecessor.as_ref(),
                )?;
                silk_predecessor = Some(result.completion);
                bft_trace
                    .push(serde_json::json!({"sample":sample, "events":result.agreement_trace}));
                for (slot, output) in result.outputs.iter().enumerate() {
                    all_outputs.push(serde_json::json!({
                        "sample": sample,
                        "epoch": sample as u64 + 1,
                        "slot": slot,
                        "implementation": config.implementation.as_str(),
                        "output_kind": "beacon-output",
                        "execution_order_index": null,
                        "digest": hex::encode(output)
                    }));
                }
                for (offset, support) in result.qr_support.iter().enumerate() {
                    all_support.push(serde_json::json!({
                        "sample": sample,
                        "epoch": sample as u64 + 1,
                        "index": offset + 2,
                        "matching_senders": support.matching_senders,
                        "matching_sender_count": support.matching_senders.len(),
                        "guaranteed_correct_predecessor_completers":
                            support.guaranteed_correct_predecessor_completers,
                        "required_n_minus_2t": config.node.n - 2 * config.node.t
                    }));
                }
            }
            BeaconImplementation::Rondo => {
                let result = run_rondo_sample(
                    &shared,
                    &config,
                    logger,
                    &process_start,
                    sample,
                    config.node.seed.wrapping_add(sample as u64),
                )?;
                for (slot, output) in result.outputs.iter().enumerate() {
                    all_outputs.push(serde_json::json!({
                        "sample": sample,
                        "epoch": sample as u64 + 1,
                        "slot": slot,
                        "implementation": config.implementation.as_str(),
                        "output_kind": "beacon-output",
                        "execution_order_index": null,
                        "digest": hex::encode(output)
                    }));
                }
                bft_trace.push(serde_json::json!({
                    "sample": sample,
                    "events": result.preparation_trace,
                    "requested_blocks": config.node.slots,
                    "agreement_steps": result.agreement_steps,
                    "committed_requests": result.committed_requests
                }));
            }
            BeaconImplementation::Spurt => {
                let setup = spurt_setup.as_ref().ok_or_else(|| {
                    DistributedError::Protocol("Spurt setup was not initialized".into())
                })?;
                let result =
                    run_spurt_sample(&shared, &config, logger, &process_start, sample, setup)?;
                for (slot, output) in result.outputs.iter().enumerate() {
                    all_outputs.push(serde_json::json!({
                        "sample": sample,
                        "epoch": sample as u64 + 1,
                        "slot": slot,
                        "implementation": config.implementation.as_str(),
                        "output_kind": "beacon-output",
                        "execution_order_index": null,
                        "digest": hex::encode(output)
                    }));
                }
                bft_trace.push(serde_json::json!({
                    "sample": sample,
                    "requested_blocks": config.node.slots,
                    "agreement_steps": result.agreement_steps,
                    "committed_requests": result.committed_requests
                }));
            }
        }
        let sender_trace = sender.take_sample_trace()?;
        bft_trace.last_mut().expect("sample trace")["sender_events"] =
            serde_json::json!(sender_trace);
        let sample_trace = bft_trace.last_mut().expect("sample trace");
        let compute_after = protocol_support::compute::counters();
        sample_trace["compute_runtime"] = serde_json::json!({
            "worker_cpu_ns": compute_after.0 - compute_before.0,
            "worker_park_ns": compute_after.1 - compute_before.1,
            "sample_lifecycle_wall_ns":compute_window.elapsed().as_nanos() as u64,
            "workers":protocol_support::compute::workers(), "target_cpu_fraction":0.8
        });
        let writes = ["events", "sender_events"]
            .into_iter()
            .flat_map(|key| sample_trace[key].as_array().into_iter().flatten())
            .filter(|event| {
                event.get("socket_write_complete_unix_ns").is_some()
                    && event["label"] != "experiment-sample-ready-v1"
            })
            .collect::<Vec<_>>();
        let protocol_wire: u64 = writes
            .iter()
            .map(|event| event["framed_bytes"].as_u64().expect("write bytes"))
            .sum();
        let after = shared
            .0
            .lock()
            .map_err(message_flow::protocol_error)?
            .counters;
        let lifecycle_messages = config.node.n as u64 - 1;
        if after.messages_sent - before.messages_sent != writes.len() as u64 + lifecycle_messages {
            return Err(message_flow::protocol_error(
                "completed protocol writes do not reconcile with transport counters",
            ));
        }
        sample_trace["send_accounting"] = serde_json::json!({
            "schema":"completed-protocol-frames/v1", "protocol_framed_bytes":protocol_wire,
            "protocol_messages":writes.len(), "counter_messages_delta":after.messages_sent-before.messages_sent,
            "counter_framed_bytes_delta":after.actual_wire_bytes-before.actual_wire_bytes,
            "excluded_lifecycle_messages":lifecycle_messages,
            "excluded_lifecycle_framed_bytes":after.actual_wire_bytes-before.actual_wire_bytes-protocol_wire,
            "scope":"all completed protocol frames including background writes outside phase spans; excludes sample barriers"
        });
    }
    let sender_retirement_trace = sender.finish()?;
    let node_log_sha256 = logger.finish()?;
    logger.artifact(
        "summary.json",
        &
        serde_json::to_vec_pretty(&serde_json::json!({
            "success": true,
            "run_id": config.run_id,
            "experiment_id": config.experiment_id,
            "implementation": config.implementation.as_str(),
            "node_id": config.node.node_id,
            "node_log_sha256": node_log_sha256,
            "paired_execution_order_policy": "not-applicable",
            "outputs": all_outputs,
            "qr_support": all_support,
            "bft_trace": bft_trace,
            "sender_retirement_trace":sender_retirement_trace,
            "compute_runtime": {
                "profile":"bounded-crypto-pool-cpu-budget-v1",
                "workers":protocol_support::compute::workers(),
                "target_cpu_fraction":0.8,
                "burst_cpu_ns":4_000_000,
                "worker_cpu_ns":protocol_support::compute::counters().0,
                "worker_park_ns":protocol_support::compute::counters().1,
                "scope":"cooperative aggregate worker CPU budget; excludes transport threads; not an instantaneous hard quota"
            }
        }))
        .map_err(|error| DistributedError::Protocol(error.to_string()))?,
    )?;
    logger.artifact("complete", b"ok\n")?;
    Ok(())
}
