//! Breeze sharing, aggregate evaluation verification, and validation quorum.

use curve25519_dalek::scalar::Scalar;
use protocol_support::derive_seed;
use protocol_support::store::ProtocolStore;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use rondo_bavss_po::protocol::breeze_share::BreezeDealer;
use rondo_bavss_po::protocol::breeze_verify::{
    collect_qc_preverified, verify_qc, verify_validation_certificate,
};

use super::*;
use crate::subset_digest;

impl RetainedDealer {
    pub fn dealer_id(&self) -> usize {
        self.public.dealer_id
    }

    pub fn persist(&self, store: &mut ProtocolStore) -> Result<u64, RondoError> {
        // The normal path only needs the compact row. Fault recovery must be
        // able to retransmit and independently verify that row, so the
        // original BatchEvaluationProof is durable protocol state.
        Ok(store.persist(&(&self.public, &self.row, &self.proof))?)
    }
}

impl RondoSetup {
    pub fn bootstrap(
        n: usize,
        t: usize,
        slots: usize,
        epoch: u64,
        seed: u64,
        node_id: u32,
    ) -> Result<RondoSetupBootstrap, RondoError> {
        let params = ProtocolParams::new(n, t, slots)?;
        if node_id as usize >= n {
            return Err(RondoError::Invalid("node id out of range"));
        }
        let committee = committee(seed, params)?;
        let receiver = receiver(seed, node_id as usize, params)?;
        Ok(RondoSetupBootstrap {
            params,
            epoch,
            seed,
            node_id,
            committee,
            receiver,
        })
    }

    pub fn local_commitment_root(&self) -> [u8; 32] {
        self.local_public.commitment_root
    }

    pub fn local_share(&self, receiver: u32) -> Result<RondoShare, RondoError> {
        let receiver = receiver as usize;
        Ok(RondoShare {
            public: self.local_public.clone(),
            row: self
                .local_rows
                .get(receiver)
                .cloned()
                .ok_or(RondoError::Invalid("share receiver out of range"))?,
            proof: self
                .local_proofs
                .get(receiver)
                .cloned()
                .ok_or(RondoError::Invalid("proof receiver out of range"))?,
        })
    }

    pub fn accept_share(
        &self,
        sender: u32,
        share: RondoShare,
    ) -> Result<(RetainedDealer, BreezeValidationCertificate), RondoError> {
        if sender as usize != share.public.dealer_id
            || share.row.receiver_id != self.node_id as usize
        {
            return Err(RondoError::Invalid("share context mismatch"));
        }
        let certificate =
            self.receiver
                .batch_verify_eval(&share.row, &share.public, &share.proof)?;
        Ok((
            RetainedDealer {
                public: share.public,
                row: share.row,
                proof: share.proof,
            },
            certificate,
        ))
    }

    pub fn collect_validation_qc(
        &self,
        certificates: Vec<VerifiedLocalValidationCertificate>,
    ) -> Result<BreezeQc, RondoError> {
        let certificates = certificates
            .into_iter()
            .map(|verified| {
                if verified.verification_context != self.verification_context {
                    return Err(RondoError::Invalid(
                        "preverified validation certificate context mismatch",
                    ));
                }
                Ok(verified.certificate)
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(collect_qc_preverified(
            self.node_id as usize,
            &self.local_public,
            &certificates,
            &self.committee,
        )?)
    }

    fn verify_local_validation_certificate(
        &self,
        sender: u32,
        certificate: &BreezeValidationCertificate,
    ) -> Result<(), RondoError> {
        if certificate.dealer_id != self.node_id as usize
            || certificate.receiver_id != sender as usize
        {
            return Err(RondoError::Invalid(
                "validation certificate context mismatch",
            ));
        }
        let public_key = self
            .committee
            .get(&(sender as usize))
            .ok_or(RondoError::Invalid(
                "validation signer is not in the committee",
            ))?;
        Ok(verify_validation_certificate(certificate, public_key)?)
    }

    pub fn accept_local_validation_certificate(
        &self,
        sender: u32,
        certificate: BreezeValidationCertificate,
    ) -> Result<VerifiedLocalValidationCertificate, RondoError> {
        protocol_support::compute::run(|| {
            self.verify_local_validation_certificate(sender, &certificate)?;
            Ok(VerifiedLocalValidationCertificate {
                verification_context: self.verification_context,
                certificate,
            })
        })
    }

    pub fn local_public(&self) -> &BreezePublicData {
        &self.local_public
    }

    pub fn verify_dealer_material(
        &self,
        public: BreezePublicData,
        qc: BreezeQc,
    ) -> Result<VerifiedDealerMaterial, RondoError> {
        protocol_support::compute::run(|| {
            if public.params != self.params
                || public.dealer_id >= self.params.n
                || public.commitments.len() != self.params.l
            {
                return Err(RondoError::Invalid("certified public shape mismatch"));
            }
            rondo_bavss_po::protocol::breeze_verify::verify_public_qc(
                &public,
                &qc,
                &self.committee,
            )?;
            Ok(VerifiedDealerMaterial {
                context: self.verification_context,
                public,
                qc,
            })
        })
    }

    pub fn finish_preverified_epoch(
        &self,
        retained: &BTreeMap<usize, RetainedDealer>,
        materials: Vec<VerifiedDealerMaterial>,
    ) -> Result<RondoEpoch, RondoError> {
        if materials.len() != self.params.d {
            return Err(RondoError::Invalid(
                "common subset must contain t+1 dealers",
            ));
        }
        let mut selected = BTreeMap::new();
        for material in materials {
            if material.context != self.verification_context {
                return Err(RondoError::Invalid("material context mismatch"));
            }
            let row = retained
                .get(&material.public.dealer_id)
                .filter(|row| {
                    protocol_support::wire::canonical_serialize(&row.public).ok()
                        == protocol_support::wire::canonical_serialize(&material.public).ok()
                })
                .cloned();
            if selected
                .insert(
                    material.public.dealer_id,
                    StoredDealer {
                        public: material.public,
                        qc: material.qc,
                        retained: row,
                    },
                )
                .is_some()
            {
                return Err(RondoError::Invalid("duplicate certified dealer"));
            }
        }
        let subset = subset_digest(
            self.epoch,
            &selected
                .values()
                .map(|dealer| dealer.qc.transcript_hash)
                .collect::<Vec<_>>(),
        );
        Ok(RondoEpoch {
            params: self.params,
            epoch: self.epoch,
            selected,
            subset,
            aggregate_reconstructors: Default::default(),
            fallback_verifier: BreezeEvaluationVerifier::new(self.params)?,
        })
    }

    pub fn finish_epoch(
        &self,
        retained: BTreeMap<usize, RetainedDealer>,
        announcements: Vec<ValidatedDealer>,
    ) -> Result<RondoEpoch, RondoError> {
        let mut validated = BTreeMap::new();
        for announcement in announcements {
            let dealer = retained
                .get(&announcement.dealer_id)
                .ok_or(RondoError::Invalid("validated dealer has no retained row"))?;
            if announcement.sender as usize != announcement.dealer_id
                || dealer.public.commitment_root != announcement.commitment_root
            {
                return Err(RondoError::Invalid("validated dealer context mismatch"));
            }
            verify_qc(&dealer.public, &announcement.qc, &self.committee)?;
            if validated
                .insert(
                    announcement.dealer_id,
                    StoredDealer {
                        public: dealer.public.clone(),
                        retained: Some(dealer.clone()),
                        qc: announcement.qc,
                    },
                )
                .is_some()
            {
                return Err(RondoError::Invalid("duplicate validated dealer"));
            }
        }
        let selected = validated
            .into_iter()
            .take(self.params.d)
            .collect::<BTreeMap<_, _>>();
        if selected.len() != self.params.d {
            return Err(RondoError::Invalid("common subset below threshold"));
        }
        let transcripts = selected
            .values()
            .map(|dealer| dealer.qc.transcript_hash)
            .collect::<Vec<_>>();
        let subset = subset_digest(self.epoch, &transcripts);
        let holder_points = (0..self.params.d)
            .map(|holder| Scalar::from(holder as u64 + 1))
            .collect::<Vec<_>>();
        Ok(RondoEpoch {
            params: self.params,
            epoch: self.epoch,
            selected,
            subset,
            aggregate_reconstructors: std::sync::Mutex::new(BTreeMap::from([(
                (0..self.params.d as u32).collect(),
                CompactAggregateReconstructor::new(self.params, &holder_points)?,
            )])),
            fallback_verifier: BreezeEvaluationVerifier::new(self.params)?,
        })
    }
}

impl RondoSetupBootstrap {
    pub fn prepare_sharing(self) -> Result<RondoSetup, RondoError> {
        protocol_support::compute::run(|| {
            let dealer_id = self.node_id as usize;
            let mut rng = ChaCha20Rng::from_seed(derive_seed(
                self.seed,
                format!("rondo-dealer-{dealer_id}").as_bytes(),
            ));
            let mut dealer = BreezeDealer::random(dealer_id, self.params, &mut rng)?;
            let (local_public, local_rows) = dealer.share(&mut rng)?;
            let local_proofs = dealer.batch_eval(&local_public, &local_rows)?;
            Ok(RondoSetup {
                params: self.params,
                epoch: self.epoch,
                node_id: self.node_id,
                committee: self.committee,
                receiver: self.receiver,
                local_public,
                local_rows,
                local_proofs,
                verification_context: derive_seed(
                    self.seed,
                    format!(
                        "rondo-verified-validation-v1-{}-{}-{}-{}-{}",
                        self.params.n, self.params.t, self.params.l, self.epoch, self.node_id
                    )
                    .as_bytes(),
                ),
            })
        })
    }
}

fn receiver(
    seed: u64,
    receiver: usize,
    params: ProtocolParams,
) -> Result<BreezeReceiver, RondoError> {
    Ok(BreezeReceiver::from_seed(
        receiver,
        params,
        derive_seed(seed, format!("rondo-validator-{receiver}").as_bytes()),
    )?)
}

fn committee(seed: u64, params: ProtocolParams) -> Result<BTreeMap<usize, Vec<u8>>, RondoError> {
    (0..params.n)
        .map(|node| Ok((node, receiver(seed, node, params)?.public_key())))
        .collect()
}
