use super::record::SCHEMA_VERSION;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ArtifactSet {
    pub expected_nodes: Vec<String>,
    pub expected_files: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RunManifest {
    pub schema_version: String,
    pub run_id: String,
    pub experiment_id: String,
    pub executor: String,
    pub config_sha256: String,
    pub inventory_sha256: String,
    pub git_commit: String,
    pub cargo_lock_sha256: String,
    pub build_profile: String,
    pub rustc_version: String,
    pub host_id: String,
    pub container_id: Option<String>,
    pub deterministic_seed: u64,
    pub resolved_parameters: BTreeMap<String, String>,
    pub placement: BTreeMap<String, String>,
    pub network_profile: BTreeMap<String, String>,
    pub artifacts: ArtifactSet,
    pub measured_only: bool,
}

impl RunManifest {
    pub fn new(
        run_id: impl Into<String>,
        experiment_id: impl Into<String>,
        executor: impl Into<String>,
        seed: u64,
        git_commit: impl Into<String>,
    ) -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            run_id: run_id.into(),
            experiment_id: experiment_id.into(),
            executor: executor.into(),
            config_sha256: String::new(),
            inventory_sha256: String::new(),
            git_commit: git_commit.into(),
            cargo_lock_sha256: String::new(),
            build_profile: if cfg!(debug_assertions) {
                "debug"
            } else {
                "release"
            }
            .into(),
            rustc_version: option_env!("RUSTC_VERSION").unwrap_or("unknown").into(),
            host_id: hostname::get()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_else(|_| "unknown".into()),
            container_id: std::env::var("HOSTNAME").ok(),
            deterministic_seed: seed,
            resolved_parameters: BTreeMap::new(),
            placement: BTreeMap::new(),
            network_profile: BTreeMap::new(),
            artifacts: ArtifactSet::default(),
            measured_only: true,
        }
    }
}
