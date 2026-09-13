use super::BftError;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BftParams {
    pub n: usize,
    pub t: usize,
}

impl BftParams {
    pub fn new(n: usize, t: usize) -> Result<Self, BftError> {
        if n == 0 || 3 * t >= n {
            return Err(BftError::InvalidParameters);
        }
        Ok(Self { n, t })
    }

    pub fn quorum(self) -> usize {
        self.n - self.t
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Request {
    pub client_id: u64,
    pub sequence: u64,
    pub payload: Vec<u8>,
}
