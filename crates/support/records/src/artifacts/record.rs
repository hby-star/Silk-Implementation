use super::manifest::RunManifest;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use thiserror::Error;

pub const SCHEMA_VERSION: &str = "silk-experiment-v2";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Fidelity {
    NotApplicable,
    F0,
    F1,
    F2,
    F3,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Coverage {
    Primitive,
    NormalPathOnly,
    FullPath,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ClaimScope {
    PrimitivePerformance,
    NormalPathPerformance,
    DevelopmentOnly,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MeasurementKind {
    Measured,
    Modelled,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RawEvent {
    pub schema_version: String,
    pub run_id: String,
    pub experiment_id: String,
    pub sample_role: String,
    pub implementation: String,
    pub rondo_breeze_fidelity: Fidelity,
    pub rondo_bft_path_fidelity: Fidelity,
    pub rondo_bft_coverage: Coverage,
    pub claim_scope: ClaimScope,
    pub profile: String,
    pub protocol_revision: String,
    pub scenario: String,
    pub coverage: Coverage,
    pub n: u32,
    pub t: u32,
    pub epoch_slots: u32,
    pub dealers: u32,
    pub slot: Option<u32>,
    pub phase: String,
    pub sample: u32,
    pub seed: u64,
    pub measured_or_modelled: MeasurementKind,
    pub trace_id: String,
    pub span_id: String,
    pub parent_span_id: Option<String>,
    pub timing_semantics: String,
    pub critical_path: bool,
    pub wall_ns: u64,
    pub cpu_ns: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub actual_wire_bytes: u64,
    pub message_count: u64,
    pub transport_connection_mode: String,
    pub wire_accounting_mode: String,
    pub paired_execution_order_policy: String,
    pub execution_order_index: Option<u8>,
    pub rss_peak_bytes: u64,
    pub protocol_storage_bytes: u64,
    pub actual_reconstruction_backend: String,
    pub certificate_encoding: String,
    pub gc_mode: String,
    pub gc_before_bytes: Option<u64>,
    pub gc_after_bytes: Option<u64>,
    pub gc_reclaimed_bytes: Option<u64>,
    pub gc_discarded_objects: Option<u64>,
    pub gc_persistent_before_bytes: Option<u64>,
    pub gc_persistent_after_bytes: Option<u64>,
    pub gc_persistent_bytes_written: Option<u64>,
    pub gc_retained_due_to_service_window_bytes: Option<u64>,
    pub success: bool,
    pub error_class: Option<String>,
    pub git_commit: String,
    pub build_source_fingerprint: String,
    pub build_profile: String,
    pub host_id: String,
    pub container_id: Option<String>,
}

impl RawEvent {
    pub fn validate(&self) -> Result<(), RecordError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(RecordError::Validation("unsupported schema version".into()));
        }
        for (field, value) in [
            ("run_id", self.run_id.as_str()),
            ("experiment_id", self.experiment_id.as_str()),
            ("sample_role", self.sample_role.as_str()),
            ("implementation", self.implementation.as_str()),
            ("profile", self.profile.as_str()),
            ("protocol_revision", self.protocol_revision.as_str()),
            ("phase", self.phase.as_str()),
            ("timing_semantics", self.timing_semantics.as_str()),
            (
                "transport_connection_mode",
                self.transport_connection_mode.as_str(),
            ),
            ("wire_accounting_mode", self.wire_accounting_mode.as_str()),
            (
                "actual_reconstruction_backend",
                self.actual_reconstruction_backend.as_str(),
            ),
            ("certificate_encoding", self.certificate_encoding.as_str()),
            ("gc_mode", self.gc_mode.as_str()),
            (
                "paired_execution_order_policy",
                self.paired_execution_order_policy.as_str(),
            ),
            ("git_commit", self.git_commit.as_str()),
            (
                "build_source_fingerprint",
                self.build_source_fingerprint.as_str(),
            ),
            ("host_id", self.host_id.as_str()),
        ] {
            if value.trim().is_empty() {
                return Err(RecordError::Validation(format!("{field} is empty")));
            }
        }
        if self.n == 0 || 3 * self.t >= self.n || self.epoch_slots == 0 {
            return Err(RecordError::Validation("invalid n/t/B".into()));
        }
        let implementation = self.implementation.to_ascii_lowercase();
        if implementation == "rondo-bft" && self.rondo_breeze_fidelity != Fidelity::NotApplicable {
            return Err(RecordError::Validation(
                "Rondo-BFT records must not claim Breeze fidelity".into(),
            ));
        }
        if matches!(implementation.as_str(), "rondo-bavss-po" | "rondo-beacon")
            && self.rondo_breeze_fidelity != Fidelity::F2
        {
            return Err(RecordError::Validation(
                "current Rondo Breeze records require F2 fidelity".into(),
            ));
        }
        let expected_profile = match implementation.as_str() {
            "silk-bavss-po" => Some(::silk_bavss_po::IMPLEMENTATION_PROFILE),
            "silk-beacon" => Some(::silk_beacon::IMPLEMENTATION_PROFILE),
            "rondo-bavss-po" => Some(::rondo_bavss_po::IMPLEMENTATION_PROFILE),
            "rondo-beacon" => Some(::rondo_beacon::IMPLEMENTATION_PROFILE),
            _ => None,
        };
        if expected_profile.is_some_and(|expected| self.profile != expected) {
            return Err(RecordError::Validation(
                "protocol records must declare the current implementation profile".into(),
            ));
        }
        if implementation.contains("rondo")
            && self.claim_scope == ClaimScope::NormalPathPerformance
            && self.rondo_bft_path_fidelity != Fidelity::F2
        {
            return Err(RecordError::Validation(
                "Rondo normal-path records require F2 BFT path fidelity".into(),
            ));
        }
        if self.claim_scope == ClaimScope::NormalPathPerformance
            && (self.coverage != Coverage::NormalPathOnly
                || self.rondo_bft_coverage != Coverage::NormalPathOnly)
        {
            return Err(RecordError::Validation(
                "normal-path claims require normal-path-only coverage labels".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum RecordError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Csv(#[from] csv::Error),
    #[error(transparent)]
    Toml(#[from] toml::ser::Error),
    #[error("record validation failed: {0}")]
    Validation(String),
}

pub struct RunRecorder {
    root: PathBuf,
    events: BufWriter<File>,
    samples: csv::Writer<File>,
    event_count: u64,
    last_critical_span: BTreeMap<String, String>,
}

impl RunRecorder {
    pub fn create(root: impl AsRef<Path>, manifest: &RunManifest) -> Result<Self, RecordError> {
        let root = root.as_ref().to_path_buf();
        if root.is_dir() && root.read_dir()?.next().is_some() {
            return Err(RecordError::Io(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("run directory is not empty: {}", root.display()),
            )));
        }
        std::fs::create_dir_all(&root)?;
        std::fs::write(
            root.join("manifest.toml"),
            toml::to_string_pretty(manifest)?,
        )?;
        let events = BufWriter::new(File::create(root.join("events.jsonl"))?);
        let samples = csv::Writer::from_path(root.join("samples.csv"))?;
        Ok(Self {
            root,
            events,
            samples,
            event_count: 0,
            last_critical_span: BTreeMap::new(),
        })
    }

    pub fn record(&mut self, event: &RawEvent) -> Result<(), RecordError> {
        let mut event = event.clone();
        if event.critical_path {
            if event.parent_span_id.is_none() {
                event.parent_span_id = self.last_critical_span.get(&event.trace_id).cloned();
            }
            self.last_critical_span
                .insert(event.trace_id.clone(), event.span_id.clone());
        }
        event.validate()?;
        serde_json::to_writer(&mut self.events, &event)?;
        self.events.write_all(b"\n")?;
        self.samples.serialize(&event)?;
        self.event_count += 1;
        Ok(())
    }

    pub fn finish(mut self) -> Result<u64, RecordError> {
        self.events.flush()?;
        self.samples.flush()?;
        std::fs::write(self.root.join("complete"), self.event_count.to_string())?;
        let mut output = String::new();
        let mut files = Vec::new();
        collect_files(&self.root, &mut files)?;
        files.sort();
        for path in files {
            if path
                .file_name()
                .is_some_and(|name| name == "checksums.sha256")
            {
                continue;
            }
            let bytes = std::fs::read(&path)?;
            let digest = crypto_primitives::hash::sha256(&bytes);
            let relative = path
                .strip_prefix(&self.root)
                .expect("collected path is under run root")
                .to_string_lossy()
                .replace('\\', "/");
            output.push_str(&format!("{}  {}\n", hex::encode(digest), relative));
        }
        std::fs::write(self.root.join("checksums.sha256"), output)?;
        Ok(self.event_count)
    }
}

fn collect_files(root: &Path, output: &mut Vec<PathBuf>) -> io::Result<()> {
    for entry in std::fs::read_dir(root)? {
        let path = entry?.path();
        if path.is_dir() {
            collect_files(&path, output)?;
        } else if path.is_file() {
            output.push(path);
        }
    }
    Ok(())
}
