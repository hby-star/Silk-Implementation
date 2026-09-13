//! Experiment artifact manifests, raw-event schema, validation, and recording.

#![forbid(unsafe_code)]

pub mod manifest;
mod node_log;
pub mod record;

pub use manifest::RunManifest;
pub use node_log::{
    NODE_LOG_SCHEMA, NodeEvent, NodeLogger, TRANSPORT_PROFILE, WIRE_ACCOUNTING_MODE,
};
pub use record::{
    ClaimScope, Coverage, Fidelity, MeasurementKind, RawEvent, RecordError, RunRecorder,
    SCHEMA_VERSION,
};
