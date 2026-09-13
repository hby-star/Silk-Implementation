use serde::Deserialize;
use std::collections::BTreeMap;
use std::error::Error as StdError;
use std::fmt;
use thiserror::Error;

#[derive(Deserialize)]
pub(crate) struct ExperimentConfig {
    schema_version: u32,
    experiment_id: String,
}

impl ExperimentConfig {
    pub(crate) fn resolve(&self) -> Result<ExperimentKind, ConfigError> {
        if self.schema_version != 1 {
            return Err(ConfigError::UnsupportedSchema(self.schema_version));
        }
        ExperimentKind::parse(&self.experiment_id)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ExperimentKind {
    BavssPhaseCost,
    BeaconPerformance,
}

impl ExperimentKind {
    const ALL: [Self; 2] = [Self::BavssPhaseCost, Self::BeaconPerformance];

    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::BavssPhaseCost => "bavss-phase-cost",
            Self::BeaconPerformance => "beacon-performance",
        }
    }

    pub(crate) const fn execution_mode(self) -> ExecutionMode {
        match self {
            Self::BavssPhaseCost => ExecutionMode::LocalProcess,
            Self::BeaconPerformance => ExecutionMode::Distributed,
        }
    }

    fn parse(id: &str) -> Result<Self, ConfigError> {
        Self::ALL
            .into_iter()
            .find(|kind| kind.as_str() == id)
            .ok_or_else(|| ConfigError::UnsupportedExperiment(id.to_owned()))
    }
}

impl fmt::Display for ExperimentKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ExecutionMode {
    LocalProcess,
    Distributed,
}

impl fmt::Display for ExecutionMode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LocalProcess => formatter.write_str("run"),
            Self::Distributed => formatter.write_str("distributed-run"),
        }
    }
}

#[derive(Debug, Error)]
pub(crate) enum ConfigError {
    #[error("unsupported experiment config schema_version {0}; expected 1")]
    UnsupportedSchema(u32),
    #[error(
        "unsupported experiment_id {0:?}; supported IDs are bavss-phase-cost and beacon-performance"
    )]
    UnsupportedExperiment(String),
    #[error("experiment {experiment} requires `{required}` instead of `{actual}`")]
    WrongExecutionMode {
        experiment: ExperimentKind,
        required: ExecutionMode,
        actual: ExecutionMode,
    },
}

pub(crate) fn require_execution_mode(
    experiment: ExperimentKind,
    actual: ExecutionMode,
) -> Result<(), ConfigError> {
    let required = experiment.execution_mode();
    if required == actual {
        Ok(())
    } else {
        Err(ConfigError::WrongExecutionMode {
            experiment,
            required,
            actual,
        })
    }
}

pub(crate) fn distributed_endpoints() -> Result<Option<BTreeMap<u32, String>>, Box<dyn StdError>> {
    let Some(value) = std::env::var_os("SILK_NODE_ENDPOINTS_JSON") else {
        return Ok(None);
    };
    let string_map: BTreeMap<String, String> = serde_json::from_str(&value.to_string_lossy())?;
    let endpoints = string_map
        .into_iter()
        .map(|(node, endpoint)| Ok((node.parse::<u32>()?, endpoint)))
        .collect::<Result<BTreeMap<_, _>, std::num::ParseIntError>>()?;
    Ok(Some(endpoints))
}
