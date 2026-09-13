//! Distributed node execution for Silk, Rondo and Spurt.
//! Owns protocol driving, peer transport and persistence. No AWS or CLI control.
#![recursion_limit = "256"]
mod beacon;
pub mod observer;
pub use beacon::{
    AutonomousConfig, BeaconImplementation, DistributedError, NodeConfig, run_beacon_performance,
};
