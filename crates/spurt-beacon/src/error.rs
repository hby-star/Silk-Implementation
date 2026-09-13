use thiserror::Error;

#[derive(Debug, Error)]
pub enum SpurtError {
    #[error(transparent)]
    Wire(#[from] protocol_support::wire::WireError),
    #[error(transparent)]
    Store(#[from] protocol_support::store::StoreError),
    #[error("invalid Spurt parameter: {0}")]
    Parameter(&'static str),
    #[error("invalid Spurt transcript: {0}")]
    Transcript(&'static str),
    #[error("Spurt cryptographic verification failed: {0}")]
    Verification(&'static str),
    #[error("invalid Spurt agreement transition: {0}")]
    Agreement(&'static str),
}
