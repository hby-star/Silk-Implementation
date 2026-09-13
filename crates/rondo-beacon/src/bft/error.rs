use thiserror::Error;

#[derive(Debug, Error)]
pub enum BftError {
    #[error("invalid BFT parameters")]
    InvalidParameters,
    #[error("invalid block")]
    InvalidBlock,
    #[error("unsafe proposal")]
    UnsafeProposal,
    #[error("invalid vote")]
    InvalidVote,
    #[error("invalid quorum certificate")]
    InvalidQc,
    #[error("invalid protocol message")]
    InvalidMessage,
    #[error("cryptographic operation failed: {0}")]
    Crypto(String),
    #[error("persistent store failed: {0}")]
    Store(String),
    #[error(transparent)]
    Wire(#[from] protocol_support::wire::WireError),
    #[error(transparent)]
    Transport(#[from] protocol_support::transport::TransportError),
}
