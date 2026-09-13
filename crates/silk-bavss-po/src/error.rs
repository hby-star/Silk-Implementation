use std::error::Error;
use std::fmt::{Display, Formatter};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SilkError {
    InvalidParameters,
    InvalidThreshold,
    InvalidDealer,
    InvalidReceiver,
    InvalidIndex,
    InvalidShareCount { got: usize, expected: usize },
    InvalidResponseCount { got: usize, expected: usize },
    EmptyMerkleTree,
    InvalidMerkleProof,
    InvalidRowCheck,
    DuplicateEvaluationPoint,
    InsufficientShares { have: usize, need: usize },
    InsufficientCertificates { have: usize, need: usize },
    CertificateMismatch,
}

impl Display for SilkError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidParameters => write!(f, "invalid protocol parameters"),
            Self::InvalidThreshold => write!(f, "invalid threshold"),
            Self::InvalidDealer => write!(f, "invalid dealer"),
            Self::InvalidReceiver => write!(f, "invalid receiver"),
            Self::InvalidIndex => write!(f, "invalid index"),
            Self::InvalidShareCount { got, expected } => {
                write!(f, "invalid share count {got}, expected {expected}")
            }
            Self::InvalidResponseCount { got, expected } => {
                write!(f, "invalid response count {got}, expected {expected}")
            }
            Self::EmptyMerkleTree => write!(f, "empty Merkle tree"),
            Self::InvalidMerkleProof => write!(f, "invalid Merkle proof"),
            Self::InvalidRowCheck => write!(f, "invalid SS24 row check"),
            Self::DuplicateEvaluationPoint => write!(f, "duplicate evaluation point"),
            Self::InsufficientShares { have, need } => {
                write!(f, "insufficient shares: have {have}, need {need}")
            }
            Self::InsufficientCertificates { have, need } => {
                write!(f, "insufficient certificates: have {have}, need {need}")
            }
            Self::CertificateMismatch => write!(f, "certificate mismatch"),
        }
    }
}

impl Error for SilkError {}

impl From<crypto_primitives::polynomial::PolynomialError> for SilkError {
    fn from(error: crypto_primitives::polynomial::PolynomialError) -> Self {
        use crypto_primitives::polynomial::PolynomialError;
        match error {
            PolynomialError::InvalidCoefficientCount => Self::InvalidThreshold,
            PolynomialError::WrongShareCount { have, need } => {
                Self::InsufficientShares { have, need }
            }
            PolynomialError::DuplicatePoint | PolynomialError::ZeroEvaluationPoint => {
                Self::DuplicateEvaluationPoint
            }
        }
    }
}
