//! Multi-process normal-path execution support.
//!
//! Every replica owns its listener, protocol state, cryptographic keys,
//! persistence, and event log. Protocol progress is driven only by peer
//! messages and local quorum conditions; executors cannot advance phases.

mod beacon_performance;
mod compute_queue;
mod coordination;
mod message_flow;
mod observation;
mod rondo_beacon;
mod silk_beacon;
mod spurt_beacon;
mod state;

mod transport;

use crate::observer::{NodeEvent, NodeObserver};
pub use beacon_performance::run_beacon_performance;
use state::*;
use transport::*;

use ::silk_beacon::bft::DecisionSignature;
use ::silk_beacon::protocol::{DealerPublicTranscript, PrivateRow};
use ::silk_beacon::{
    EpochCommand, ReconstructionMessage, ReleaseAnnouncement, ValidationStatement,
};
use cpu_time::ThreadTime;
use protocol_support::{
    transport::{FramedRequest, TransportCounters, WireEnvelope},
    wire::{canonical_deserialize, canonical_serialize, framing_deserialize},
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs;
use std::net::TcpListener;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};
use thiserror::Error;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BeaconImplementation {
    Silk,
    Rondo,
    Spurt,
}

impl BeaconImplementation {
    pub const ALL: [Self; 3] = [Self::Silk, Self::Rondo, Self::Spurt];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Silk => "silk-beacon",
            Self::Rondo => "rondo-beacon",
            Self::Spurt => "spurt-beacon",
        }
    }
}

impl std::fmt::Display for BeaconImplementation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for BeaconImplementation {
    type Err = ParseBeaconImplementationError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|implementation| implementation.as_str() == value)
            .ok_or_else(|| ParseBeaconImplementationError(value.to_owned()))
    }
}

#[derive(Debug, Error)]
#[error(
    "unsupported beacon implementation {0:?}; supported values are silk-beacon, rondo-beacon, and spurt-beacon"
)]
pub struct ParseBeaconImplementationError(String);

#[derive(Clone, Debug)]
pub struct NodeConfig {
    pub node_id: u32,
    pub n: usize,
    pub t: usize,
    pub slots: usize,
    pub seed: u64,
    pub listen: String,
    pub peers: BTreeMap<u32, String>,
    pub store_root: PathBuf,
}

#[derive(Clone, Debug)]
pub struct AutonomousConfig {
    pub observation_labels: BTreeMap<String, String>,
    pub build_git_commit: String,
    pub build_source_fingerprint: String,
    pub node: NodeConfig,
    pub run_id: String,
    pub experiment_id: String,
    pub implementation: BeaconImplementation,
    pub samples: u32,
    pub output_root: PathBuf,
}

type SharedNode = Arc<(Mutex<WorkerState>, Condvar)>;

#[derive(Clone, Debug, Serialize, Deserialize)]
enum NodeResponse {
    Ack,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
enum DistributedMessage {
    SampleReady {
        sample: u32,
        experiment: String,
        barrier: String,
    },
    BeaconPublicTranscript {
        sample: u32,
        transcript: DealerPublicTranscript,
    },
    BeaconPrivateRow {
        sample: u32,
        row: PrivateRow,
    },
    BeaconValidationStatement {
        sample: u32,
        statement: ValidationStatement,
    },
    BeaconCertifiedDealer {
        sample: u32,
        dealer: u32,
        statements: Vec<ValidationStatement>,
    },
    BeaconEpochProposal {
        sample: u32,
        command: EpochCommand,
    },
    BeaconBftEcho {
        sample: u32,
        digest: [u8; 32],
    },
    BeaconBftReady {
        sample: u32,
        digest: [u8; 32],
    },
    BeaconBftCommit {
        sample: u32,
        digest: [u8; 32],
    },
    BeaconDecisionSignature {
        sample: u32,
        signature: DecisionSignature,
    },
    BeaconRelease {
        sample: u32,
        announcement: ReleaseAnnouncement,
    },
    BeaconReconstruction {
        sample: u32,
        message: ReconstructionMessage,
    },
    RondoShare {
        sample: u32,
        public: ::rondo_beacon::protocol::BreezePublicData,
        row: ::rondo_beacon::protocol::BreezeRowData,
        proof: Box<::rondo_beacon::protocol::BatchEvaluationProof>,
    },
    RondoValidation {
        sample: u32,
        certificate: ::rondo_beacon::protocol::BreezeValidationCertificate,
    },
    RondoValidated {
        sample: u32,
        public: ::rondo_beacon::protocol::BreezePublicData,
        qc: ::rondo_beacon::protocol::BreezeQc,
    },
    RondoProposal {
        sample: u32,
        proposal: ::rondo_beacon::bft::normal::Proposal,
        publics: Vec<::rondo_beacon::protocol::BreezePublicData>,
    },
    RondoVote {
        sample: u32,
        vote: ::rondo_beacon::bft::normal::Vote,
    },
    RondoQc {
        sample: u32,
        qc: ::rondo_beacon::bft::normal::QuorumCertificate,
    },
    RondoAggregate {
        sample: u32,
        share: ::rondo_beacon::AggregateShare,
    },
    RondoFallbackRequest {
        sample: u32,
        slot: u32,
        proof: Box<::rondo_beacon::bft::normal::DecisionProof>,
    },
    RondoFallbackShare {
        sample: u32,
        share: Box<::rondo_beacon::FallbackShare>,
    },
    SpurtContribution {
        sample: u32,
        contribution: ::spurt_beacon::DealerContribution,
    },
    SpurtProposal {
        sample: u32,
        proposal: ::spurt_beacon::ReceiverProposal,
    },
    SpurtAgreement {
        sample: u32,
        message: ::spurt_beacon::SignedAgreementMessage,
    },
    SpurtReconstruction {
        sample: u32,
        share: ::spurt_beacon::ReconstructionShare,
    },
    SpurtBeacon {
        sample: u32,
        message: Box<::spurt_beacon::BeaconMessage>,
    },
    BeaconSimpleIt {
        sample: u32,
        message: ::silk_beacon::simple_it::Message,
    },
    BeaconSimpleItSignature {
        sample: u32,
        digest: [u8; 32],
        signature: ::silk_beacon::bft::DecisionSignature,
    },
    BeaconCertificateRequest {
        sample: u32,
        ids: Vec<[u8; 32]>,
    },
    BeaconCertificateResponse {
        sample: u32,
        id: [u8; 32],
        statements: Vec<ValidationStatement>,
    },
}

#[derive(Clone, Debug)]
struct Outgoing {
    protocol: String,
    receiver: u32,
    message: DistributedMessage,
}

struct InboxEnvelope {
    envelope: WireEnvelope,
    network_wire_bytes: u64,
    receive_deserialize_cpu_ns: u64,
}

fn nanos(duration: Duration) -> u64 {
    duration.as_nanos().min(u64::MAX as u128) as u64
}

#[derive(Debug, Error)]
pub enum DistributedError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Wire(#[from] protocol_support::wire::WireError),
    #[error(transparent)]
    Store(#[from] protocol_support::store::StoreError),
    #[error("distributed protocol error: {0}")]
    Protocol(String),
}
