mod rondo;
mod silk;

use crate::artifacts::{
    ClaimScope, Coverage, Fidelity, MeasurementKind, RawEvent, RunManifest, RunRecorder,
    SCHEMA_VERSION,
};
use protocol_support::{
    measurement::{PhaseMeasurement, process_rss_bytes},
    transport::{FramedRequest, WireEnvelope, framed_request_len},
    wire::{WireError, canonical_serialize},
};
use std::collections::BTreeMap;
use std::error::Error;
use std::path::{Path, PathBuf};

const EXPERIMENT_ID: &str = "bavss-phase-cost";

#[derive(serde::Deserialize)]
struct BavssExperimentConfig {
    schema_version: u32,
    experiment_id: String,
}

fn validate_config(config_bytes: &[u8]) -> Result<(), Box<dyn Error>> {
    let config: BavssExperimentConfig = toml::from_str(std::str::from_utf8(config_bytes)?)?;
    if config.schema_version != 1 {
        return Err(format!(
            "unsupported experiment config schema_version {}; expected 1",
            config.schema_version
        )
        .into());
    }
    if config.experiment_id != EXPERIMENT_ID {
        return Err(format!(
            "bavss-experiment requires experiment_id {EXPERIMENT_ID:?}, got {:?}",
            config.experiment_id
        )
        .into());
    }
    Ok(())
}

fn environment_map(name: &str) -> Option<BTreeMap<String, String>> {
    std::env::var(name)
        .ok()
        .and_then(|value| serde_json::from_str(&value).ok())
}

#[derive(Clone)]
struct EventContext {
    run_id: String,
    experiment_id: String,
    sample_role: String,
    implementation: String,
    profile: String,
    scenario: String,
    n: u32,
    t: u32,
    slots: u32,
    seed: u64,
    sample: u32,
    slot: Option<u32>,
    breeze: Fidelity,
    bft: Fidelity,
    coverage: Coverage,
    claim: ClaimScope,
    paired_execution_order_policy: String,
    execution_order_index: Option<u8>,
    git_commit: String,
    host_id: String,
}

#[derive(Clone, Copy)]
struct SampleContext<'a> {
    run_id: &'a str,
    n: usize,
    t: usize,
    slots: usize,
    seed: u64,
    sample: u32,
    manifest: &'a RunManifest,
    store_root: &'a Path,
}

impl SampleContext<'_> {
    fn event(self, implementation: &str, profile: &str) -> EventContext {
        let is_rondo = implementation.starts_with("rondo");
        EventContext {
            run_id: self.run_id.into(),
            experiment_id: EXPERIMENT_ID.into(),
            sample_role: std::env::var("SILK_SAMPLE_ROLE").unwrap_or_else(|_| "smoke".into()),
            implementation: implementation.into(),
            profile: profile.into(),
            scenario: std::env::var("SILK_SCENARIO").unwrap_or_else(|_| "normal".into()),
            n: self.n as u32,
            t: self.t as u32,
            slots: self.slots as u32,
            seed: self.seed,
            sample: self.sample,
            slot: None,
            breeze: if is_rondo {
                Fidelity::F2
            } else {
                Fidelity::NotApplicable
            },
            bft: Fidelity::NotApplicable,
            coverage: Coverage::Primitive,
            claim: ClaimScope::PrimitivePerformance,
            paired_execution_order_policy: "seed-parity-counterbalanced-v1".into(),
            execution_order_index: Some(
                if implementation.starts_with("silk") == self.seed.is_multiple_of(2) {
                    0
                } else {
                    1
                },
            ),
            git_commit: self.manifest.git_commit.clone(),
            host_id: self.manifest.host_id.clone(),
        }
    }

    fn event_at(self, implementation: &str, profile: &str, slot: u32) -> EventContext {
        let mut event = self.event(implementation, profile);
        event.slot = Some(slot);
        event
    }

    fn store_path(self, implementation: &str) -> PathBuf {
        self.store_root
            .join(format!("{implementation}-sample-{:04}.bin", self.sample))
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct WireMeasurement {
    payload_bytes: u64,
    framed_bytes: u64,
    messages: u64,
}

#[derive(Default)]
struct FramedWireCounter {
    next_sequence: BTreeMap<u32, u64>,
}

impl FramedWireCounter {
    fn send<T: serde::Serialize + ?Sized>(
        &mut self,
        protocol: &str,
        sender: u32,
        receiver: u32,
        message: &T,
    ) -> Result<WireMeasurement, WireError> {
        let payload = canonical_serialize(message)?;
        self.send_encoded(protocol, sender, receiver, payload)
    }

    /// Mirror the distributed transport's encode-once broadcast for identical
    /// payloads. Every recipient still gets its exact, separately framed bytes.
    fn broadcast<T: serde::Serialize + ?Sized>(
        &mut self,
        protocol: &str,
        sender: u32,
        n: usize,
        message: &T,
    ) -> Result<WireMeasurement, WireError> {
        let payload = canonical_serialize(message)?;
        let mut result = WireMeasurement::default();
        for receiver in 0..n as u32 {
            if receiver != sender {
                result += self.send_encoded(protocol, sender, receiver, payload.clone())?;
            }
        }
        Ok(result)
    }

    fn send_encoded(
        &mut self,
        protocol: &str,
        sender: u32,
        receiver: u32,
        payload: Vec<u8>,
    ) -> Result<WireMeasurement, WireError> {
        let sequence = self.next_sequence.entry(sender).or_default();
        let envelope = WireEnvelope {
            protocol: protocol.into(),
            version: 1,
            sender,
            receiver,
            sequence: *sequence,
            payload,
        };
        *sequence += 1;
        Ok(WireMeasurement {
            payload_bytes: envelope.payload.len() as u64,
            framed_bytes: framed_request_len(&FramedRequest::Deliver(envelope))?,
            messages: 1,
        })
    }
}

impl std::ops::AddAssign for WireMeasurement {
    fn add_assign(&mut self, rhs: Self) {
        self.payload_bytes = self.payload_bytes.saturating_add(rhs.payload_bytes);
        self.framed_bytes = self.framed_bytes.saturating_add(rhs.framed_bytes);
        self.messages = self.messages.saturating_add(rhs.messages);
    }
}

#[allow(clippy::too_many_arguments)]
pub fn run(
    config_path: PathBuf,
    run_id: String,
    output: PathBuf,
    n: usize,
    t: usize,
    slots: usize,
    samples: u32,
    seed: u64,
) -> Result<(), Box<dyn Error>> {
    if n == 0 || slots == 0 || samples == 0 || 3 * t >= n {
        return Err("invalid n/t/B/samples".into());
    }
    let config_bytes = std::fs::read(&config_path)?;
    validate_config(&config_bytes)?;
    let experiment_id = EXPERIMENT_ID;
    let git_commit = env!("GIT_COMMIT").to_owned();
    let mut manifest = RunManifest::new(
        &run_id,
        experiment_id,
        std::env::var("SILK_EXECUTOR").unwrap_or_else(|_| "docker-aggregate".into()),
        seed,
        &git_commit,
    );
    if !matches!(
        manifest.executor.as_str(),
        "docker-aggregate" | "aws-aggregate"
    ) {
        return Err(format!(
            "unsupported aggregate bAVSS executor {:?}",
            manifest.executor
        )
        .into());
    }
    manifest.rustc_version = env!("RUSTC_VERSION").into();
    if manifest.executor == "aws-aggregate"
        && (std::env::var("SILK_INVENTORY_SHA256").map_or(true, |v| v.len() != 64)
            || std::env::var("SILK_RESOURCE_PROFILE").as_deref()
                != Ok("aws-t3a-medium-aggregate-v1"))
    {
        return Err("AWS aggregate requires bound inventory and native resource profile".into());
    }
    manifest.cargo_lock_sha256 = env!("CARGO_LOCK_SHA256").into();
    manifest.config_sha256 = hex::encode(crypto_primitives::hash::sha256(&config_bytes));
    manifest.inventory_sha256 = std::env::var("SILK_INVENTORY_SHA256").unwrap_or_else(|_| {
        hex::encode(crypto_primitives::hash::sha256(
            b"docker-aggregate-inventory-v1",
        ))
    });
    manifest.resolved_parameters.extend([
        ("n".into(), n.to_string()),
        ("t".into(), t.to_string()),
        ("epoch_slots".into(), slots.to_string()),
        ("silk_response_repetitions".into(), "1".into()),
        (
            "security_parameter_validated".into(),
            std::env::var("SILK_SECURITY_PARAMETER_VALIDATED").unwrap_or_else(|_| "false".into()),
        ),
        (
            "parameter_audit_schema".into(),
            std::env::var("SILK_PARAMETER_AUDIT_SCHEMA")
                .unwrap_or_else(|_| "silk-parameter-audit-v1".into()),
        ),
        (
            "parameter_audit_sha256".into(),
            std::env::var("SILK_PARAMETER_AUDIT_SHA256").unwrap_or_else(|_| "unavailable".into()),
        ),
        (
            "protocol_revision".into(),
            ::silk_bavss_po::PROTOCOL_REVISION.into(),
        ),
        (
            "silk_profile".into(),
            ::silk_bavss_po::IMPLEMENTATION_PROFILE.into(),
        ),
        ("silk_release_profile".into(), "not-applicable".into()),
        (
            "silk_wire_profile".into(),
            ::silk_bavss_po::WIRE_PROFILE.into(),
        ),
        (
            "silk_validation_profile".into(),
            ::silk_bavss_po::VALIDATION_PROFILE.into(),
        ),
        ("silk_bft_profile".into(), "not-applicable".into()),
        (
            "silk_reconstruction_backend".into(),
            "compact-adaptive-multipoint".into(),
        ),
        ("silk_certificate_encoding".into(), "not-applicable".into()),
        (
            "rondo_breeze_profile".into(),
            rondo_bavss_po::IMPLEMENTATION_PROFILE.into(),
        ),
        (
            "rondo_reconstruction_profile".into(),
            rondo_bavss_po::RECONSTRUCTION_PROFILE.into(),
        ),
        ("rondo_bft_profile".into(), "not-applicable".into()),
        ("samples".into(), samples.to_string()),
        (
            "sample_role".into(),
            std::env::var("SILK_SAMPLE_ROLE").unwrap_or_else(|_| "smoke".into()),
        ),
        ("coverage".into(), "primitive".into()),
        ("claim_scope".into(), "primitive-performance".into()),
        ("os".into(), std::env::consts::OS.into()),
        ("arch".into(), std::env::consts::ARCH.into()),
        ("silk_signature".into(), "ML-DSA-65".into()),
        ("rondo_signature".into(), "BLS12-381".into()),
        ("wire_encoding".into(), "postcard-canonical-v1".into()),
        ("git_dirty".into(), env!("GIT_DIRTY").into()),
        (
            "source_fingerprint".into(),
            env!("SOURCE_FINGERPRINT").into(),
        ),
        (
            "transport".into(),
            "in-memory-framed-node-request-v1".into(),
        ),
        (
            "wire_accounting_mode".into(),
            "sender-side-framed-node-request/v1".into(),
        ),
        (
            "execution_model".into(),
            "primitive-local-process-v1".into(),
        ),
        (
            "resource_profile".into(),
            std::env::var("SILK_RESOURCE_PROFILE").unwrap_or_else(|_| "local-host".into()),
        ),
        (
            "timing_semantics".into(),
            "single-process-aggregate-workload-v1".into(),
        ),
        (
            "paired_execution_order_policy".into(),
            "seed-parity-counterbalanced-v1".into(),
        ),
    ]);
    manifest.placement = environment_map("SILK_PLACEMENT_JSON").unwrap_or_else(|| {
        let host = std::env::var("HOSTNAME").unwrap_or_else(|_| "local".into());
        (0..n)
            .map(|node| (node.to_string(), host.clone()))
            .collect()
    });
    manifest.network_profile = environment_map("SILK_NETWORK_PROFILE_JSON").unwrap_or_else(|| {
        [
            ("loss_percent".into(), "0".into()),
            ("delivery".into(), "all-data-available".into()),
            ("leader".into(), "deterministic-honest".into()),
        ]
        .into_iter()
        .collect()
    });
    manifest.artifacts.expected_files = vec![
        "manifest.toml".into(),
        "events.jsonl".into(),
        "samples.csv".into(),
        "checksums.sha256".into(),
    ];
    let root = output.join(&run_id);
    let mut recorder = RunRecorder::create(&root, &manifest)?;
    for sample in 0..samples {
        let sample_seed = seed.wrapping_add(u64::from(sample));
        run_bavss_phase_cost(
            &mut recorder,
            &run_id,
            n,
            t,
            slots,
            sample_seed,
            sample,
            &manifest,
            &root,
        )?;
    }
    let count = recorder.finish()?;
    println!(
        "run_id={run_id} experiment={experiment_id} records={count} path={}",
        root.display()
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn run_bavss_phase_cost(
    recorder: &mut RunRecorder,
    run_id: &str,
    n: usize,
    t: usize,
    slots: usize,
    seed: u64,
    sample: u32,
    manifest: &RunManifest,
    store_root: &Path,
) -> Result<(), Box<dyn Error>> {
    let sample_context = SampleContext {
        run_id,
        n,
        t,
        slots,
        seed,
        sample,
        manifest,
        store_root,
    };
    if seed.is_multiple_of(2) {
        silk::run(recorder, sample_context)?;
        rondo::run(recorder, sample_context)?;
    } else {
        rondo::run(recorder, sample_context)?;
        silk::run(recorder, sample_context)?;
    }
    Ok(())
}

fn record_measurement(
    recorder: &mut RunRecorder,
    context: EventContext,
    phase: &str,
    measurement: PhaseMeasurement,
    wire: WireMeasurement,
    storage: u64,
) -> Result<(), Box<dyn Error>> {
    let span = format!(
        "{}-{}-{}-{}",
        context.implementation,
        phase,
        context.sample,
        context
            .slot
            .map_or_else(|| "all".into(), |slot| slot.to_string())
    );
    recorder.record(&RawEvent {
        schema_version: SCHEMA_VERSION.into(),
        run_id: context.run_id.clone(),
        experiment_id: context.experiment_id,
        sample_role: context.sample_role,
        implementation: context.implementation.clone(),
        rondo_breeze_fidelity: context.breeze,
        rondo_bft_path_fidelity: context.bft,
        rondo_bft_coverage: context.coverage,
        claim_scope: context.claim,
        profile: context.profile,
        protocol_revision: ::silk_bavss_po::PROTOCOL_REVISION.into(),
        scenario: context.scenario,
        coverage: context.coverage,
        n: context.n,
        t: context.t,
        epoch_slots: context.slots,
        dealers: 1,
        slot: context.slot,
        phase: phase.into(),
        sample: context.sample,
        seed: context.seed,
        measured_or_modelled: MeasurementKind::Measured,
        trace_id: format!(
            "{}-{}-{}",
            context.run_id, context.sample, context.implementation
        ),
        span_id: span,
        parent_span_id: None,
        timing_semantics: "single-process-aggregate-workload-v1".into(),
        critical_path: false,
        wall_ns: measurement.wall_ns,
        cpu_ns: measurement.cpu_ns,
        bytes_sent: wire.payload_bytes,
        bytes_received: wire.payload_bytes,
        actual_wire_bytes: wire.framed_bytes,
        message_count: wire.messages,
        transport_connection_mode: "in-memory-framed-node-request-v1".into(),
        wire_accounting_mode: "sender-side-framed-node-request/v1".into(),
        paired_execution_order_policy: context.paired_execution_order_policy,
        execution_order_index: context.execution_order_index,
        rss_peak_bytes: measurement.rss_peak_bytes.max(process_rss_bytes()),
        protocol_storage_bytes: storage,
        actual_reconstruction_backend: if matches!(
            context.implementation.as_str(),
            "silk-bavss-po" | "silk-beacon"
        ) {
            "compact-adaptive-multipoint".into()
        } else if matches!(
            context.implementation.as_str(),
            "rondo-bavss-po" | "rondo-beacon"
        ) {
            "breeze-aggregate-lagrange".into()
        } else {
            "not-applicable".into()
        },
        certificate_encoding: if matches!(
            context.implementation.as_str(),
            "silk-bavss-po" | "silk-beacon"
        ) {
            "not-applicable".into()
        } else if matches!(
            context.implementation.as_str(),
            "rondo-bavss-po" | "rondo-beacon"
        ) {
            "breeze".into()
        } else {
            "not-applicable".into()
        },
        gc_mode: "enabled".into(),
        gc_before_bytes: None,
        gc_after_bytes: None,
        gc_reclaimed_bytes: None,
        gc_discarded_objects: None,
        gc_persistent_before_bytes: None,
        gc_persistent_after_bytes: None,
        gc_persistent_bytes_written: None,
        gc_retained_due_to_service_window_bytes: None,
        success: true,
        error_class: None,
        git_commit: context.git_commit,
        build_source_fingerprint: env!("SOURCE_FINGERPRINT").into(),
        build_profile: if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        }
        .into(),
        host_id: context.host_id,
        container_id: std::env::var("HOSTNAME").ok(),
    })?;
    Ok(())
}
