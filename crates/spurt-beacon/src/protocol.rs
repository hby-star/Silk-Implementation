//! Per-replica Spurt protocol state and pure protocol transitions.

mod prepare;
mod reconstruct;
mod transcript;

use std::collections::BTreeMap;
use std::sync::Arc;

use blstrs::Scalar;
use ed25519_dalek::{Signature, SigningKey, Verifier, VerifyingKey};
use protocol_support::derive_seed;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

use crate::SpurtError;
use crate::agreement::AgreementReplica;
use crate::pvss::{degree_check_weights, sample_nonzero_scalar, setup};
use crate::types::{BeaconMessage, DealerContribution, PublicParameters, ReconstructionShare};

/// Long-lived committee parameters and local keys shared by all Spurt epochs.
///
/// The paper's transparent setup, PVSS keys, signing keys, and evaluation
/// domain are deployment state. Keeping them here prevents per-output setup
/// work while preserving epoch-specific randomness and transcript binding in
/// [`SpurtProtocol`].
pub struct SpurtSetup {
    n: usize,
    t: usize,
    seed: u64,
    node_id: u32,
    parameters: Arc<PublicParameters>,
    secret_key: Scalar,
    public_keys: Arc<Vec<blstrs::G1Projective>>,
    degree_check_weights: Arc<Vec<Scalar>>,
    signing_key: Arc<SigningKey>,
    verifying_keys: Arc<BTreeMap<u32, VerifyingKey>>,
}

pub struct SpurtProtocol {
    n: usize,
    t: usize,
    epoch: u64,
    height: u64,
    seed: u64,
    node_id: u32,
    parameters: Arc<PublicParameters>,
    secret_key: Scalar,
    public_keys: Arc<Vec<blstrs::G1Projective>>,
    degree_check_weights: Arc<Vec<Scalar>>,
    signing_key: Arc<SigningKey>,
    verifying_keys: Arc<BTreeMap<u32, VerifyingKey>>,
    verification_context: [u8; 32],
}

/// A contribution validated against one concrete Spurt committee and epoch.
/// The inner message is private so callers cannot manufacture a cached-verify
/// result without passing the full signature, degree, and DLEQ checks.
#[derive(Debug)]
pub struct VerifiedDealerContribution {
    verification_context: [u8; 32],
    contribution: DealerContribution,
}

/// A reconstruction share whose signature and pairing equation were checked.
#[derive(Debug)]
pub struct VerifiedReconstructionShare {
    verification_context: [u8; 32],
    message: ReconstructionShare,
}

/// A signed BEACON relay checked against one expected reconstructed value.
#[derive(Debug)]
pub struct VerifiedBeaconMessage {
    verification_context: [u8; 32],
    message: BeaconMessage,
}

impl SpurtSetup {
    pub fn new(n: usize, t: usize, seed: u64, node_id: u32) -> Result<Self, SpurtError> {
        if n < 4 || n < 3 * t + 1 || node_id as usize >= n {
            return Err(SpurtError::Parameter(
                "Spurt setup requires n >= 4, n >= 3t+1, and a valid node id",
            ));
        }
        let mut setup_rng = ChaCha20Rng::from_seed(derive_seed(seed, b"spurt-dbdh-setup-v1"));
        let parameters = setup(&mut setup_rng);
        let degree_check_weights = degree_check_weights(n)?;

        let mut public_keys = Vec::with_capacity(n);
        let mut local_secret = None;
        let mut verifying_keys = BTreeMap::new();
        let mut local_signing_key = None;
        for participant in 0..n {
            let mut pvss_rng = ChaCha20Rng::from_seed(derive_seed(
                seed,
                format!("spurt-pvss-key-v1-{participant}").as_bytes(),
            ));
            let secret = sample_nonzero_scalar(&mut pvss_rng);
            public_keys.push(parameters.h0 * secret);
            if participant == node_id as usize {
                local_secret = Some(secret);
            }

            let signing_seed = derive_seed(
                seed,
                format!("spurt-ed25519-key-v1-{participant}").as_bytes(),
            );
            let signing_key = SigningKey::from_bytes(&signing_seed);
            verifying_keys.insert(participant as u32, signing_key.verifying_key());
            if participant == node_id as usize {
                local_signing_key = Some(signing_key);
            }
        }
        Ok(Self {
            n,
            t,
            seed,
            node_id,
            parameters: Arc::new(parameters),
            secret_key: local_secret.ok_or(SpurtError::Parameter("missing local PVSS key"))?,
            public_keys: Arc::new(public_keys),
            degree_check_weights: Arc::new(degree_check_weights),
            signing_key: Arc::new(
                local_signing_key.ok_or(SpurtError::Parameter("missing local signing key"))?,
            ),
            verifying_keys: Arc::new(verifying_keys),
        })
    }

    pub fn protocol(&self, epoch: u64, height: u64) -> Result<SpurtProtocol, SpurtError> {
        if epoch == 0 || height == 0 {
            return Err(SpurtError::Parameter(
                "Spurt protocol requires positive epoch and height",
            ));
        }
        Ok(SpurtProtocol {
            n: self.n,
            t: self.t,
            epoch,
            height,
            seed: self.seed,
            node_id: self.node_id,
            parameters: Arc::clone(&self.parameters),
            secret_key: self.secret_key,
            public_keys: Arc::clone(&self.public_keys),
            degree_check_weights: Arc::clone(&self.degree_check_weights),
            signing_key: Arc::clone(&self.signing_key),
            verifying_keys: Arc::clone(&self.verifying_keys),
            verification_context: derive_seed(
                self.seed,
                format!(
                    "spurt-verified-context-v1-{}-{}-{epoch}-{height}",
                    self.n, self.t
                )
                .as_bytes(),
            ),
        })
    }
}

impl SpurtProtocol {
    pub fn leader(&self) -> u32 {
        (self.epoch % self.n as u64) as u32
    }

    pub fn agreement(&self, digest: [u8; 32]) -> Result<AgreementReplica, SpurtError> {
        AgreementReplica::new(
            self.n,
            self.t,
            self.epoch,
            self.height,
            digest,
            self.node_id,
            Arc::clone(&self.signing_key),
            Arc::clone(&self.verifying_keys),
        )
    }

    fn verify_signature(
        &self,
        signer: u32,
        payload: &[u8],
        signature: &[u8],
    ) -> Result<(), SpurtError> {
        let key = self
            .verifying_keys
            .get(&signer)
            .ok_or(SpurtError::Verification("unknown Ed25519 signer"))?;
        let signature = Signature::from_slice(signature)
            .map_err(|_| SpurtError::Verification("invalid Ed25519 signature encoding"))?;
        key.verify(payload, &signature)
            .map_err(|_| SpurtError::Verification("invalid Ed25519 signature"))
    }

    fn rng(&self, label: &str) -> ChaCha20Rng {
        ChaCha20Rng::from_seed(derive_seed(self.seed, label.as_bytes()))
    }
}

pub const CONTRIBUTION_PROTOCOL: &str = "spurt/beacon/contribution/v1";
pub const PROPOSAL_PROTOCOL: &str = "spurt/beacon/private-proposal/v1";
pub const AGREEMENT_PROTOCOL: &str = "spurt/beacon/agreement/v1";
pub const RECONSTRUCTION_PROTOCOL: &str = "spurt/beacon/reconstruction/v1";
pub const BEACON_PROTOCOL: &str = "spurt/beacon/output-certificate/v1";
