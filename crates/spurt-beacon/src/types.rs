use blstrs::{G1Projective, G2Projective, Gt, Scalar};
use serde::{Deserialize, Serialize};

use crate::agreement::AgreementPhase;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PublicParameters {
    pub g0: G1Projective,
    pub h0: G1Projective,
    pub g1: G2Projective,
    pub h1: G2Projective,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DleqProof {
    pub commitment_g1: G1Projective,
    pub commitment_g2: G2Projective,
    pub response: Scalar,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DealerContribution {
    pub epoch: u64,
    pub height: u64,
    pub dealer: u32,
    pub commitments: Vec<G2Projective>,
    pub ciphertexts: Vec<G1Projective>,
    pub proofs: Vec<DleqProof>,
    pub signature: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AggregateTranscript {
    pub epoch: u64,
    pub height: u64,
    pub dealer_ids: Vec<u32>,
    pub commitments: Vec<G2Projective>,
    pub ciphertexts: Vec<G1Projective>,
    pub digest: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ReceiverColumnEntry {
    pub dealer: u32,
    pub commitment: G2Projective,
    pub ciphertext: G1Projective,
    pub proof: DleqProof,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ReceiverProposal {
    pub leader: u32,
    pub receiver: u32,
    pub aggregate: AggregateTranscript,
    pub column: Vec<ReceiverColumnEntry>,
    pub signature: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SignedAgreementMessage {
    pub epoch: u64,
    pub height: u64,
    pub digest: [u8; 32],
    pub phase: AgreementPhase,
    pub signer: u32,
    pub signature: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ReconstructionShare {
    pub epoch: u64,
    pub height: u64,
    pub digest: [u8; 32],
    pub holder: u32,
    pub share: G1Projective,
    pub signature: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BeaconValue {
    pub epoch: u64,
    pub height: u64,
    pub digest: [u8; 32],
    pub value: Gt,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BeaconMessage {
    pub value: BeaconValue,
    pub signer: u32,
    pub signature: Vec<u8>,
}
