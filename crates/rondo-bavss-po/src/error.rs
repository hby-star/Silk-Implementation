use thiserror::Error;

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum BreezeError {
    #[error("invalid protocol parameters")]
    InvalidParameters,
    #[error("invalid reconstruction threshold")]
    InvalidThreshold,
    #[error("invalid polynomial length {got}, max {max}")]
    InvalidPolynomialLength { got: usize, max: usize },
    #[error("invalid share count {got}, expected {expected}")]
    InvalidShareCount { got: usize, expected: usize },
    #[error("invalid commitment count {got}, expected {expected}")]
    InvalidCommitmentCount { got: usize, expected: usize },
    #[error("invalid dealer")]
    InvalidDealer,
    #[error("invalid receiver")]
    InvalidReceiver,
    #[error("invalid beacon index")]
    InvalidBeaconIndex,
    #[error("missing dealer state")]
    MissingDealerState,
    #[error("claimed evaluation does not match polynomial")]
    InvalidClaimedEvaluation,
    #[error("invalid BatchEval proof")]
    InvalidBatchEvalProof,
    #[error("reconstructed polynomial does not match the aggregate commitment")]
    AggregateCommitmentMismatch,
    #[error("malformed proof")]
    MalformedProof,
    #[error("empty commitment vector")]
    EmptyCommitmentVector,
    #[error("invalid commitment Merkle proof")]
    InvalidMerkleProof,
    #[error("invalid batch evaluation proof")]
    InvalidBatchProof,
    #[error("duplicate evaluation point")]
    DuplicateEvaluationPoint,
    #[error("insufficient shares: have {have}, need {need}")]
    InsufficientShares { have: usize, need: usize },
    #[error("insufficient certificates: have {have}, need {need}")]
    InsufficientCertificates { have: usize, need: usize },
    #[error("validation certificate mismatch")]
    CertificateMismatch,
    #[error("invalid validation signature")]
    InvalidSignature,
}

impl From<crypto_primitives::polynomial::PolynomialError> for BreezeError {
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
