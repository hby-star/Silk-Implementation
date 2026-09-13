use crate::BreezeError;
use crate::primitives::poly_commit::PolyCommitment;
use crate::protocol::breeze_share::{commitment_tree, evaluation_leaf};
use crate::protocol::types::{
    BatchEvaluationProof, BreezePublicData, BreezeQc, BreezeRowData, BreezeValidationCertificate,
    ProtocolParams,
};
use crypto_primitives::bls::{self, PublicKey, SecretKey};
use crypto_primitives::hash::HashTranscript;
use curve25519_dalek::scalar::Scalar;
use std::collections::{BTreeMap, BTreeSet};

const DST: &[u8] = b"RONDO-BREEZE-BLS12381G2-XMD:SHA-256_SSWU_RO_V1";
// Frozen input of the aggregate-only v2 transcript. Keeping the byte preserves
// the verified Fiat--Shamir statement while the obsolete profile enum is gone.
const AGGREGATE_PROOF_TRANSCRIPT_TAG: u8 = 1;

#[derive(Debug)]
pub struct BreezeReceiver {
    receiver_id: usize,
    signing_key: SecretKey,
    evaluation_verifier: BreezeEvaluationVerifier,
}

/// Reusable non-signing verifier for an authenticated Breeze receiver row.
///
/// Validation uses this verifier before signing its own row. Reconstruction
/// fallback uses the same statement to verify rows supplied by arbitrary QC
/// signers, without possessing or invoking the signer's secret key.
#[derive(Clone, Debug)]
pub struct BreezeEvaluationVerifier {
    params: ProtocolParams,
    poly_commit: PolyCommitment,
}

impl BreezeEvaluationVerifier {
    pub fn new(params: ProtocolParams) -> Result<Self, BreezeError> {
        params.validate()?;
        Ok(Self {
            params,
            poly_commit: PolyCommitment::new(params.d)?,
        })
    }

    pub fn verify_batch_eval(
        &self,
        row: &BreezeRowData,
        public: &BreezePublicData,
        proof: &BatchEvaluationProof,
    ) -> Result<(), BreezeError> {
        validate_shapes(row.receiver_id, self.params, row, public)?;
        if proof.dealer_id != public.dealer_id
            || proof.receiver_id != row.receiver_id
            || proof.commitment_root != public.commitment_root
            || proof.evaluation_root != public.evaluation_root
            || proof.mask_commitment != public.mask_commitment
        {
            return Err(BreezeError::InvalidBatchProof);
        }
        let tree = commitment_tree(&public.commitments)?;
        if tree.root() != public.commitment_root {
            return Err(BreezeError::InvalidMerkleProof);
        }
        if proof.evaluation_proof.index() != row.receiver_id
            || proof.evaluation_proof.leaf_count() != self.params.n
            || !proof.evaluation_proof.verify(
                &public.evaluation_root,
                &evaluation_leaf(row, proof.mask_evaluation),
            )
        {
            return Err(BreezeError::InvalidBatchProof);
        }
        let gammas = batch_challenges(public)?;
        if gamma_digest(&gammas) != proof.gamma_digest {
            return Err(BreezeError::InvalidBatchProof);
        }
        let (aggregate_commitment, aggregate_share) = public
            .commitments
            .iter()
            .zip(row.shares.iter())
            .zip(gammas.iter())
            .fold(
                (public.mask_commitment, proof.mask_evaluation),
                |(point, share), ((commitment, value), gamma)| {
                    (point + gamma * commitment, share + gamma * value)
                },
            );
        self.poly_commit
            .batch_verify_eval(
                aggregate_commitment,
                row.eval_point,
                aggregate_share,
                row.receiver_id,
                self.params.n,
                &proof.proof_member,
            )
            .map_err(|_| BreezeError::InvalidBatchProof)
    }
}

impl BreezeReceiver {
    pub fn from_seed(
        receiver_id: usize,
        params: ProtocolParams,
        seed: [u8; 32],
    ) -> Result<Self, BreezeError> {
        params.validate()?;
        if receiver_id >= params.n {
            return Err(BreezeError::InvalidReceiver);
        }
        let receiver_bytes = (receiver_id as u64).to_le_bytes();
        let signing_key =
            bls::derive_secret_key(&seed, b"Rondo-Breeze-validation-key-v1", &[&receiver_bytes])
                .map_err(|_| BreezeError::InvalidSignature)?;
        Ok(Self {
            receiver_id,
            signing_key,
            evaluation_verifier: BreezeEvaluationVerifier::new(params)?,
        })
    }

    pub fn public_key(&self) -> Vec<u8> {
        bls::public_key(&self.signing_key).to_bytes().to_vec()
    }

    /// Breeze BatchVerifyEval over all B evaluations, followed by a real
    /// validation signature over the canonical transcript.
    pub fn batch_verify_eval(
        &self,
        row: &BreezeRowData,
        public: &BreezePublicData,
        proof: &BatchEvaluationProof,
    ) -> Result<BreezeValidationCertificate, BreezeError> {
        if row.receiver_id != self.receiver_id {
            return Err(BreezeError::InvalidReceiver);
        }
        self.evaluation_verifier
            .verify_batch_eval(row, public, proof)?;
        let transcript_hash = transcript_hash(public);
        let message = validation_message(public.dealer_id, &transcript_hash);
        Ok(BreezeValidationCertificate {
            dealer_id: public.dealer_id,
            receiver_id: self.receiver_id,
            transcript_hash,
            signature: bls::sign(&self.signing_key, &message, DST, &[]),
        })
    }
}

pub fn collect_qc(
    dealer_id: usize,
    public: &BreezePublicData,
    certs: &[BreezeValidationCertificate],
    committee: &BTreeMap<usize, Vec<u8>>,
) -> Result<BreezeQc, BreezeError> {
    collect_qc_inner(dealer_id, public, certs, committee, true)
}

pub fn collect_qc_preverified(
    dealer_id: usize,
    public: &BreezePublicData,
    certs: &[BreezeValidationCertificate],
    committee: &BTreeMap<usize, Vec<u8>>,
) -> Result<BreezeQc, BreezeError> {
    collect_qc_inner(dealer_id, public, certs, committee, false)
}

fn collect_qc_inner(
    dealer_id: usize,
    public: &BreezePublicData,
    certs: &[BreezeValidationCertificate],
    committee: &BTreeMap<usize, Vec<u8>>,
    verify_signatures: bool,
) -> Result<BreezeQc, BreezeError> {
    let expected_hash = transcript_hash(public);
    let mut signer_ids = BTreeSet::new();
    let mut accepted = Vec::new();
    let mut ordered = certs.iter().collect::<Vec<_>>();
    ordered.sort_by_key(|cert| cert.receiver_id);
    let need = public.params.qc_threshold();
    for cert in ordered.into_iter().take(need) {
        if cert.dealer_id != dealer_id
            || cert.transcript_hash != expected_hash
            || cert.receiver_id >= public.params.n
            || !signer_ids.insert(cert.receiver_id)
        {
            return Err(BreezeError::CertificateMismatch);
        }
        if verify_signatures {
            let registered = committee
                .get(&cert.receiver_id)
                .ok_or(BreezeError::CertificateMismatch)?;
            verify_validation_certificate(cert, registered)?;
        } else if !committee.contains_key(&cert.receiver_id) {
            return Err(BreezeError::CertificateMismatch);
        }
        accepted.push(cert.clone());
    }
    if accepted.len() < need {
        return Err(BreezeError::InsufficientCertificates {
            have: accepted.len(),
            need,
        });
    }
    let aggregate_signature = bls::aggregate(
        &accepted
            .iter()
            .map(|cert| cert.signature.clone())
            .collect::<Vec<_>>(),
    )
    .map_err(|_| BreezeError::InvalidSignature)?;
    Ok(BreezeQc {
        dealer_id,
        transcript_hash: expected_hash,
        signer_ids: accepted.iter().map(|cert| cert.receiver_id).collect(),
        aggregate_signature,
    })
}

/// Check the public commitment vector as well as its signed transcript binding.
pub fn verify_public_qc(
    public: &BreezePublicData,
    qc: &BreezeQc,
    committee: &BTreeMap<usize, Vec<u8>>,
) -> Result<(), BreezeError> {
    public.params.validate()?;
    if public.commitments.len() != public.params.l
        || commitment_tree(&public.commitments)?.root() != public.commitment_root
    {
        return Err(BreezeError::InvalidMerkleProof);
    }
    verify_qc(public, qc, committee)
}

pub fn verify_qc(
    public: &BreezePublicData,
    qc: &BreezeQc,
    committee: &BTreeMap<usize, Vec<u8>>,
) -> Result<(), BreezeError> {
    if qc.dealer_id != public.dealer_id
        || qc.transcript_hash != transcript_hash(public)
        || qc.signer_ids.len() != public.params.qc_threshold()
    {
        return Err(BreezeError::CertificateMismatch);
    }
    let unique = qc.signer_ids.iter().copied().collect::<BTreeSet<_>>();
    if unique.len() != qc.signer_ids.len() {
        return Err(BreezeError::CertificateMismatch);
    }
    let keys = qc
        .signer_ids
        .iter()
        .map(|signer| {
            let bytes = committee
                .get(signer)
                .ok_or(BreezeError::CertificateMismatch)?;
            PublicKey::from_bytes(bytes).map_err(|_| BreezeError::InvalidSignature)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let message = validation_message(qc.dealer_id, &qc.transcript_hash);
    bls::fast_aggregate_verify(
        &keys.iter().collect::<Vec<_>>(),
        &qc.aggregate_signature,
        &message,
        DST,
    )
    .map_err(|_| BreezeError::InvalidSignature)
}

fn transcript_hash(public: &BreezePublicData) -> [u8; 32] {
    let mut hasher = HashTranscript::new(b"Rondo-Breeze-validation-transcript-v2");
    hasher.update(&(public.sid.len() as u64).to_le_bytes());
    hasher.update(&public.sid);
    hasher.update(&(public.dealer_id as u64).to_le_bytes());
    hasher.update(&(public.params.n as u64).to_le_bytes());
    hasher.update(&(public.params.t as u64).to_le_bytes());
    hasher.update(&(public.params.d as u64).to_le_bytes());
    hasher.update(&(public.params.l as u64).to_le_bytes());
    hasher.update(&[AGGREGATE_PROOF_TRANSCRIPT_TAG]);
    hasher.update(&public.commitment_root);
    hasher.update(&public.evaluation_root);
    hasher.update(&public.mask_commitment.compress().to_bytes());
    hasher.finalize()
}

pub(crate) fn batch_challenges(public: &BreezePublicData) -> Result<Vec<Scalar>, BreezeError> {
    if public.commitments.len() != public.params.l {
        return Err(BreezeError::InvalidCommitmentCount {
            got: public.commitments.len(),
            expected: public.params.l,
        });
    }
    Ok(public
        .commitments
        .iter()
        .enumerate()
        .map(|(index, commitment)| {
            let mut wide = [0u8; 64];
            let mut hasher = HashTranscript::new(b"Rondo-Breeze-BatchEval-gamma-v2");
            hasher.update(&(public.sid.len() as u64).to_le_bytes());
            hasher.update(&public.sid);
            hasher.update(&(public.dealer_id as u64).to_le_bytes());
            hasher.update(&(public.params.n as u64).to_le_bytes());
            hasher.update(&(public.params.t as u64).to_le_bytes());
            hasher.update(&(public.params.d as u64).to_le_bytes());
            hasher.update(&(public.params.l as u64).to_le_bytes());
            hasher.update(&[AGGREGATE_PROOF_TRANSCRIPT_TAG]);
            hasher.update(&public.commitment_root);
            // The evaluation root and mask commitment are fixed before this
            // challenge. This prevents a dealer from choosing row errors that
            // cancel in the random linear combination after seeing gamma.
            hasher.update(&public.evaluation_root);
            hasher.update(&public.mask_commitment.compress().to_bytes());
            hasher.update(&(index as u64).to_le_bytes());
            hasher.update(&commitment.compress().to_bytes());
            hasher.fill_xof(&mut wide);
            Scalar::from_bytes_mod_order_wide(&wide)
        })
        .collect())
}

pub(crate) fn gamma_digest(gammas: &[Scalar]) -> [u8; 32] {
    let mut hasher = HashTranscript::new(b"Rondo-Breeze-gamma-vector-v1");
    for gamma in gammas {
        hasher.update(&gamma.to_bytes());
    }
    hasher.finalize()
}

fn validate_shapes(
    receiver_id: usize,
    params: ProtocolParams,
    row: &BreezeRowData,
    public: &BreezePublicData,
) -> Result<(), BreezeError> {
    if row.receiver_id != receiver_id || receiver_id >= params.n {
        return Err(BreezeError::InvalidReceiver);
    }
    if row.dealer_id != public.dealer_id {
        return Err(BreezeError::InvalidDealer);
    }
    if public.params != params {
        return Err(BreezeError::InvalidParameters);
    }
    if row.shares.len() != params.l {
        return Err(BreezeError::InvalidShareCount {
            got: row.shares.len(),
            expected: params.l,
        });
    }
    if public.commitments.len() != params.l {
        return Err(BreezeError::InvalidCommitmentCount {
            got: public.commitments.len(),
            expected: params.l,
        });
    }
    if row.eval_point != Scalar::from(receiver_id as u64 + 1) {
        return Err(BreezeError::InvalidReceiver);
    }
    Ok(())
}

pub fn verify_validation_certificate(
    cert: &BreezeValidationCertificate,
    public_key: &[u8],
) -> Result<(), BreezeError> {
    let key = PublicKey::from_bytes(public_key).map_err(|_| BreezeError::InvalidSignature)?;
    let message = validation_message(cert.dealer_id, &cert.transcript_hash);
    bls::verify(&key, &cert.signature, &message, DST, &[])
        .map_err(|_| BreezeError::InvalidSignature)
}

fn validation_message(dealer_id: usize, digest: &[u8; 32]) -> Vec<u8> {
    let mut message = Vec::with_capacity(80);
    message.extend_from_slice(b"Rondo-Breeze-validation-signature-v2");
    message.extend_from_slice(&(dealer_id as u64).to_le_bytes());
    message.extend_from_slice(digest);
    message
}
