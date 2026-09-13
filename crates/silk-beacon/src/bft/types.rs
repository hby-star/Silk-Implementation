use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BftParams {
    pub n: usize,
    pub t: usize,
}

impl BftParams {
    pub fn new(n: usize, t: usize) -> Result<Self, super::BftError> {
        if n == 0 || 3 * t >= n {
            return Err(super::BftError::InvalidParameters);
        }
        Ok(Self { n, t })
    }

    pub fn quorum(self) -> usize {
        self.n - self.t
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Proposal {
    pub instance: u64,
    pub payload: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DecisionSignature {
    pub signer: u32,
    pub signature: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DecisionCertificate {
    pub epoch: u64,
    pub instance: u64,
    pub proposal_digest: [u8; 32],
    pub signatures: Vec<DecisionSignature>,
}
