use crate::BreezeError;
use crate::primitives::merkle::MerkleProof;
use crate::primitives::poly_commit::BatchEvalProofMember;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProtocolParams {
    pub n: usize,
    pub t: usize,
    pub d: usize,
    pub l: usize,
}

impl ProtocolParams {
    pub fn new(n: usize, t: usize, l: usize) -> Result<Self, BreezeError> {
        let params = Self { n, t, d: t + 1, l };
        params.validate()?;
        Ok(params)
    }

    pub fn validate(&self) -> Result<(), BreezeError> {
        if self.n == 0 || self.l == 0 || 3 * self.t >= self.n {
            return Err(BreezeError::InvalidParameters);
        }
        if self.d != self.t + 1 || self.d == 0 || self.d > self.n {
            return Err(BreezeError::InvalidThreshold);
        }
        Ok(())
    }

    pub fn qc_threshold(&self) -> usize {
        self.n - self.t
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BreezePublicData {
    pub sid: Vec<u8>,
    pub dealer_id: usize,
    pub params: ProtocolParams,
    pub commitments: Vec<RistrettoPoint>,
    pub commitment_root: [u8; 32],
    /// Binds every receiver row and mask evaluation before Fiat--Shamir
    /// challenges are derived.
    pub evaluation_root: [u8; 32],
    pub mask_commitment: RistrettoPoint,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BreezeRowData {
    pub dealer_id: usize,
    pub receiver_id: usize,
    pub shares: Vec<Scalar>,
    pub eval_point: Scalar,
}

/// One BatchEval proof authenticating all B evaluations in a receiver row.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BatchEvaluationProof {
    pub dealer_id: usize,
    pub receiver_id: usize,
    pub commitment_root: [u8; 32],
    pub evaluation_root: [u8; 32],
    pub gamma_digest: [u8; 32],
    pub mask_commitment: RistrettoPoint,
    pub mask_evaluation: Scalar,
    pub evaluation_proof: MerkleProof,
    pub proof_member: BatchEvalProofMember,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BreezeValidationCertificate {
    pub dealer_id: usize,
    pub receiver_id: usize,
    pub transcript_hash: [u8; 32],
    pub signature: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BreezeQc {
    pub dealer_id: usize,
    pub transcript_hash: [u8; 32],
    /// Independent BLS public-key identities participating in the aggregate.
    /// This is not a threshold-signature share set and uses no shared key/DKG.
    pub signer_ids: Vec<usize>,
    pub aggregate_signature: Vec<u8>,
}
