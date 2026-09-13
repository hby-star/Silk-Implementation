//! Event-driven Simple-IT S (Figure 2) with dispersed Bracha RBC (§2.4).
//!
//! This is a single application-height instance. All proposal rounds and RN
//! states remain live after a chain commits; the first non-empty value in that
//! chain is the height's decision. The caller supplies authenticated sender IDs
//! and checks the application value before `accept_candidate`. A local decision
//! alone is not a service-retirement condition: peers may still need old RBC/RN
//! messages or a committed descendant. The adapter must provide decision
//! dissemination before retiring an instance.

pub mod dispersal;
mod rbc;
mod state;

use serde::{Deserialize, Serialize};
pub use state::SimpleIt;

#[derive(Clone, Copy, Debug)]
pub struct Params {
    pub n: usize,
    pub t: usize,
}
impl Params {
    pub fn new(n: usize, t: usize) -> Result<Self, Error> {
        if n == 0 || n > 65_536 || t > (n - 1) / 3 {
            return Err(Error::InvalidParams);
        }
        Ok(Self { n, t })
    }
    pub fn quorum(self) -> usize {
        self.n - self.t
    }
    pub fn data_shards(self) -> usize {
        (self.n - self.t + 1).div_ceil(2)
    }
    pub fn leader(self, round: u64) -> u32 {
        ((round - 1) % self.n as u64) as u32
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Message {
    pub context: [u8; 32],
    pub round: u64,
    pub body: Body,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum Body {
    Disperse(dispersal::Fragment),
    Echo(dispersal::Fragment),
    Ready([u8; 32]),
    Commit,
    TimeoutVote,
    TimeoutAccept,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Block {
    pub parent: u64,
    pub value: Option<Vec<u8>>,
}

#[derive(Debug)]
pub enum Action {
    Send {
        receiver: Option<u32>,
        message: Message,
    },
    Validate {
        round: u64,
        root: [u8; 32],
        value: Vec<u8>,
    },
    EnterRound(u64),
    RbDelivered(u64),
    Decide {
        proposal_round: u64,
        commit_round: u64,
        value: Vec<u8>,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid Simple-IT parameters")]
    InvalidParams,
    #[error("invalid Simple-IT payload or erasure codeword")]
    InvalidPayload,
    #[error("Reed-Solomon operation failed")]
    Coding,
    #[error("Simple-IT round overflow")]
    RoundOverflow,
}
