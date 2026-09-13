use crate::SilkError;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProtocolParams {
    pub n: usize,
    pub t: usize,
    pub d: usize,
    pub l: usize,
    pub r: usize,
    pub kappa: u16,
}

impl ProtocolParams {
    pub fn new(n: usize, t: usize, l: usize, r: usize) -> Result<Self, SilkError> {
        let params = Self {
            n,
            t,
            d: t + 1,
            l,
            r,
            // The paper defines kappa as the bit length of hash outputs and
            // leaf salts.  The canonical profile uses SHA-256 and 32-byte
            // salts, so the encoded parameter is 256 (not the target security
            // level after quantum collision search).
            kappa: 256,
        };
        params.validate()?;
        Ok(params)
    }

    pub fn validate(&self) -> Result<(), SilkError> {
        if self.n == 0 || self.l == 0 || self.r == 0 {
            return Err(SilkError::InvalidParameters);
        }
        if self.d != self.t + 1 || self.d == 0 || self.d > self.n {
            return Err(SilkError::InvalidThreshold);
        }
        if 3 * self.t >= self.n {
            return Err(SilkError::InvalidParameters);
        }
        if self.kappa != 256 {
            return Err(SilkError::InvalidParameters);
        }
        Ok(())
    }

    pub fn qc_threshold(&self) -> usize {
        self.n - self.t
    }
}
