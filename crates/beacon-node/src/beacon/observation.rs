use super::{AutonomousConfig, DistributedError, NodeEvent, NodeObserver, SharedNode, nanos};
use crate::observer::{NODE_LOG_SCHEMA, TRANSPORT_PROFILE, WIRE_ACCOUNTING_MODE};
use protocol_support::measurement::PhaseTimer;
use protocol_support::transport::TransportCounters;
use silk_beacon::GcStats;
use std::fs;
use std::path::Path;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

#[allow(clippy::too_many_arguments)]
pub(super) fn measured<T, F>(
    shared: &SharedNode,
    config: &AutonomousConfig,
    logger: &mut dyn NodeObserver,
    process_start: &Instant,
    sample: u32,
    phase: &str,
    slot: Option<u32>,
    output_kind: Option<&str>,
    action: F,
) -> Result<T, DistributedError>
where
    F: FnOnce() -> Result<(T, Option<[u8; 32]>), DistributedError>,
{
    measured_for(
        shared,
        config,
        logger,
        process_start,
        sample,
        "silk-beacon",
        phase,
        slot,
        output_kind,
        action,
    )
}

#[allow(clippy::too_many_arguments)]
pub(super) fn measured_gc<F>(
    shared: &SharedNode,
    config: &AutonomousConfig,
    logger: &mut dyn NodeObserver,
    process_start: &Instant,
    sample: u32,
    phase: &str,
    slot: Option<u32>,
    action: F,
) -> Result<GcStats, DistributedError>
where
    F: FnOnce() -> Result<GcStats, DistributedError>,
{
    measured_for_with_gc(
        shared,
        config,
        logger,
        process_start,
        sample,
        "silk-beacon",
        phase,
        slot,
        None,
        || {
            let stats = action()?;
            Ok((stats, None, Some(stats)))
        },
    )
}

#[allow(clippy::too_many_arguments)]
pub(super) fn measured_for<T, F>(
    shared: &SharedNode,
    config: &AutonomousConfig,
    logger: &mut dyn NodeObserver,
    process_start: &Instant,
    sample: u32,
    implementation: &str,
    phase: &str,
    slot: Option<u32>,
    output_kind: Option<&str>,
    action: F,
) -> Result<T, DistributedError>
where
    F: FnOnce() -> Result<(T, Option<[u8; 32]>), DistributedError>,
{
    measured_for_with_gc(
        shared,
        config,
        logger,
        process_start,
        sample,
        implementation,
        phase,
        slot,
        output_kind,
        || {
            let (value, output) = action()?;
            Ok((value, output, None))
        },
    )
}

#[allow(clippy::too_many_arguments)]
fn measured_for_with_gc<T, F>(
    shared: &SharedNode,
    config: &AutonomousConfig,
    logger: &mut dyn NodeObserver,
    process_start: &Instant,
    sample: u32,
    implementation: &str,
    phase: &str,
    slot: Option<u32>,
    output_kind: Option<&str>,
    action: F,
) -> Result<T, DistributedError>
where
    F: FnOnce() -> Result<(T, Option<[u8; 32]>, Option<GcStats>), DistributedError>,
{
    let unix_start_ns = unix_time_ns()?;
    let relative_start_ns = nanos(process_start.elapsed());
    let timer = PhaseTimer::start();
    let (before, before_receive_cpu) = {
        let state = shared
            .0
            .lock()
            .map_err(|_| DistributedError::Protocol("worker lock poisoned".into()))?;
        (state.counters, state.consumed_receive_cpu_ns)
    };
    let (value, output, gc) = action()?;
    let measurement = timer.finish();
    let relative_end_ns = nanos(process_start.elapsed());
    let unix_end_ns = unix_time_ns()?;
    let (transport, receive_deserialize_cpu_ns, storage) = {
        let state = shared
            .0
            .lock()
            .map_err(|_| DistributedError::Protocol("worker lock poisoned".into()))?;
        (
            transport_delta(before, state.counters),
            state
                .consumed_receive_cpu_ns
                .saturating_sub(before_receive_cpu),
            directory_bytes(&state.store_root)?,
        )
    };
    logger.record(&NodeEvent {
        schema_version: NODE_LOG_SCHEMA.into(),
        node_sequence: 0,
        event_kind: if output_kind == Some("beacon-output") {
            "beacon_output_durable"
        } else {
            "phase_span"
        }
        .into(),
        run_id: config.run_id.clone(),
        experiment_id: config.experiment_id.clone(),
        sample_id: format!("sample-{sample:04}"),
        sample_role: config
            .observation_labels
            .get("SILK_SAMPLE_ROLE")
            .cloned()
            .unwrap_or_else(|| "smoke".into()),
        implementation: implementation.into(),
        implementation_profile: match implementation {
            "silk-beacon" => ::silk_beacon::IMPLEMENTATION_PROFILE,
            "rondo-beacon" => ::rondo_beacon::IMPLEMENTATION_PROFILE,
            "spurt-beacon" => ::spurt_beacon::PROFILE,
            _ => "unknown",
        }
        .into(),
        protocol_revision: ::silk_beacon::PROTOCOL_REVISION.into(),
        build_git_commit: config.build_git_commit.clone(),
        build_source_fingerprint: config.build_source_fingerprint.clone(),
        node_id: config.node.node_id,
        role: "replica".into(),
        n: config.node.n as u32,
        t: config.node.t as u32,
        epoch_slots: config.node.slots as u32,
        seed: config.node.seed,
        executor: config
            .observation_labels
            .get("SILK_EXECUTOR")
            .cloned()
            .unwrap_or_else(|| "unknown".into()),
        network_scenario: config
            .observation_labels
            .get("SILK_NETWORK_SCENARIO")
            .cloned()
            .unwrap_or_else(|| "unspecified".into()),
        resource_profile: config
            .observation_labels
            .get("SILK_RESOURCE_PROFILE")
            .cloned()
            .unwrap_or_else(|| "unspecified".into()),
        clock_source: "process-relative-monotonic-plus-system-time-unix-ns".into(),
        wire_accounting_mode: WIRE_ACCOUNTING_MODE.into(),
        transport_profile: TRANSPORT_PROFILE.into(),
        sample,
        epoch: Some(sample as u64 + 1),
        slot,
        output_kind: output_kind.map(str::to_owned),
        phase: phase.into(),
        headline_phase: headline_phase(phase).into(),
        relative_start_ns,
        relative_end_ns,
        monotonic_start_ns: relative_start_ns,
        monotonic_end_ns: relative_end_ns,
        unix_start_ns,
        unix_end_ns,
        wall_ns: relative_end_ns.saturating_sub(relative_start_ns),
        process_cpu_ns: measurement.cpu_ns,
        cpu_ns: measurement.cpu_ns,
        receive_deserialize_cpu_ns,
        bytes_sent: transport.bytes_sent,
        bytes_received: transport.bytes_received,
        actual_wire_bytes: transport.actual_wire_bytes,
        protocol_wire_bytes_sent: transport.actual_wire_bytes,
        protocol_wire_bytes_received: transport.bytes_received,
        messages_sent: transport.messages_sent,
        messages_received: transport.messages_received,
        rss_peak_bytes: measurement.rss_peak_bytes,
        protocol_storage_bytes: storage,
        actual_reconstruction_backend: match implementation {
            "silk-beacon" => "compact-holder-set-adaptive-multipoint",
            "rondo-beacon" => {
                "breeze-compact-certified-holder-quorum-verified-dealer-row-fallback-v5"
            }
            "spurt-beacon" => "dbdh-pairing-lagrange-v1",
            _ => "unknown",
        }
        .into(),
        certificate_encoding: match implementation {
            "silk-beacon" => "matching-mldsa65-release-signatures-v3",
            "rondo-beacon" => "breeze-qc-plus-four-phase-decision-proof-v1",
            "spurt-beacon" => "t-plus-one-signed-beacon-messages-v1",
            _ => "unknown",
        }
        .into(),
        gc_mode: match implementation {
            "silk-beacon" => "enabled",
            "rondo-beacon" => "rondo-bft-prune",
            "spurt-beacon" => "per-output-protocol-drop",
            _ => "unknown",
        }
        .into(),
        gc_before_bytes: gc.map(|value| value.before_bytes),
        gc_after_bytes: gc.map(|value| value.after_bytes),
        gc_reclaimed_bytes: gc.map(|value| value.reclaimed_bytes),
        gc_discarded_objects: gc.map(|value| value.discarded_objects),
        gc_persistent_before_bytes: gc.map(|value| value.persistent_before_bytes),
        gc_persistent_after_bytes: gc.map(|value| value.persistent_after_bytes),
        gc_persistent_bytes_written: gc.map(|value| value.persistent_bytes_written),
        gc_retained_due_to_service_window_bytes: gc
            .map(|value| value.retained_due_to_service_window_bytes),
        output_digest: output,
        success: true,
        status: "completed".into(),
        error_class: None,
        rondo_breeze_fidelity: if implementation == "rondo-beacon" {
            ::rondo_beacon::BREEZE_FIDELITY
        } else {
            "not-applicable"
        }
        .into(),
        rondo_bft_path_fidelity: if implementation == "rondo-beacon" {
            ::rondo_beacon::BFT_PATH_FIDELITY
        } else {
            "not-applicable"
        }
        .into(),
        rondo_breeze_profile: if implementation == "rondo-beacon" {
            ::rondo_beacon::BREEZE_PROFILE
        } else {
            "not-applicable"
        }
        .into(),
        rondo_bft_profile: if implementation == "rondo-beacon" {
            ::rondo_beacon::bft::normal::PROFILE
        } else {
            "not-applicable"
        }
        .into(),
        rondo_bft_signature_profile: if implementation == "rondo-beacon" {
            ::rondo_beacon::BFT_SIGNATURE_PROFILE
        } else {
            "not-applicable"
        }
        .into(),
        spurt_fidelity: if implementation == "spurt-beacon" {
            ::spurt_beacon::FIDELITY
        } else {
            "not-applicable"
        }
        .into(),
        coverage: match implementation {
            "spurt-beacon" => ::spurt_beacon::COVERAGE,
            _ => "fixed-committee-normal-path-only",
        }
        .into(),
        claim_scope: match implementation {
            "spurt-beacon" => ::spurt_beacon::CLAIM_SCOPE,
            _ => "normal-path-performance",
        }
        .into(),
        host_id: std::env::var("HOSTNAME")
            .or_else(|_| std::env::var("COMPUTERNAME"))
            .unwrap_or_else(|_| "unknown-host".into()),
        container_id: std::env::var("HOSTNAME").ok(),
    })?;
    Ok(value)
}

pub(super) fn unix_time_ns() -> Result<u64, DistributedError> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| DistributedError::Protocol(format!("system clock before epoch: {error}")))?
        .as_nanos();
    Ok(nanos.min(u128::from(u64::MAX)) as u64)
}

fn headline_phase(phase: &str) -> &'static str {
    if phase.starts_with("qr-") {
        "quorum_release"
    } else if phase.contains("retention-gc") || phase.contains("deferred-batch-verify") {
        "framework_overhead"
    } else if phase.starts_with("epoch-bft-")
        || phase.starts_with("rondo-bft-")
        || phase.starts_with("spurt-agreement-")
    {
        "agreement"
    } else if phase.contains("reconstruct")
        || phase.contains("point-verify")
        || phase.contains("certificate-materialize")
        || phase == "rondo-aggregate-share-broadcast"
        || phase == "spurt-beacon-certificate-relay"
    {
        "reconstruction"
    } else {
        "commitment"
    }
}

fn directory_bytes(root: &Path) -> Result<u64, DistributedError> {
    let mut total = 0u64;
    if !root.exists() {
        return Ok(0);
    }
    let mut pending = vec![root.to_path_buf()];
    while let Some(path) = pending.pop() {
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            let metadata = entry.metadata()?;
            if metadata.is_dir() {
                pending.push(entry.path());
            } else if metadata.is_file() {
                total = total.saturating_add(metadata.len());
            }
        }
    }
    Ok(total)
}

fn transport_delta(before: TransportCounters, after: TransportCounters) -> TransportCounters {
    TransportCounters {
        messages_sent: after.messages_sent.saturating_sub(before.messages_sent),
        messages_received: after
            .messages_received
            .saturating_sub(before.messages_received),
        bytes_sent: after.bytes_sent.saturating_sub(before.bytes_sent),
        bytes_received: after.bytes_received.saturating_sub(before.bytes_received),
        actual_wire_bytes: after
            .actual_wire_bytes
            .saturating_sub(before.actual_wire_bytes),
    }
}
