//! Distributed Silk beacon workload in the paper's phase order.

mod agree;
mod certificate_service;
mod materials;
mod prepare;
mod reconstruct;

use super::message_flow::scoped_protocol;
use super::{AutonomousConfig, DistributedError, NodeObserver, SharedNode};
use ::silk_beacon::protocol::{
    CERTIFIED_DEALER_PROTOCOL, DECISION_SIGNATURE_PROTOCOL, SilkProtocol, VALIDATION_PROTOCOL,
};
use ::silk_beacon::{EpochCompletion, QrSupport};
use materials::CertifiedMaterialCache;
use std::sync::Arc;
use std::time::Instant;

pub(super) struct BeaconSampleResult {
    pub(super) completion: EpochCompletion,
    pub(super) outputs: Vec<[u8; 32]>,
    pub(super) qr_support: Vec<QrSupport>,
    pub(super) agreement_trace: Vec<serde_json::Value>,
}

struct SilkSampleContext<'a> {
    shared: &'a SharedNode,
    config: &'a AutonomousConfig,
    logger: &'a mut dyn NodeObserver,
    process_start: &'a Instant,
    sample: u32,
}

impl<'a> SilkSampleContext<'a> {
    fn network(&self) -> SilkNetworkContext<'a> {
        SilkNetworkContext {
            shared: self.shared,
            config: self.config,
            sample: self.sample,
        }
    }
}

#[derive(Clone, Copy)]
struct SilkNetworkContext<'a> {
    shared: &'a SharedNode,
    config: &'a AutonomousConfig,
    sample: u32,
}

struct EpochProtocols {
    validation: String,
    certified_dealer: String,
    decision_signature: String,
}

impl EpochProtocols {
    fn new(sample: u32) -> Self {
        Self {
            validation: scoped_protocol(VALIDATION_PROTOCOL, sample, 0),
            certified_dealer: scoped_protocol(CERTIFIED_DEALER_PROTOCOL, sample, 0),
            decision_signature: scoped_protocol(DECISION_SIGNATURE_PROTOCOL, sample, 0),
        }
    }
}

struct PreparedEpoch {
    state: prepare::SharedPreparation,
    certified_materials: CertifiedMaterialCache,
    service: prepare::PreparationService,
}

pub(super) fn run_silk_sample(
    shared: &SharedNode,
    config: &AutonomousConfig,
    logger: &mut dyn NodeObserver,
    process_start: &Instant,
    sample: u32,
    predecessor: Option<&EpochCompletion>,
) -> Result<BeaconSampleResult, DistributedError> {
    let epoch = sample as u64 + 1;
    let seed = config.node.seed;
    let silk = Arc::new(
        SilkProtocol::new(
            config.node.n,
            config.node.t,
            config.node.slots,
            epoch,
            seed,
            config.node.node_id,
        )
        .map_err(super::message_flow::protocol_error)?,
    );
    let slots = silk.slots();
    let protocols = EpochProtocols::new(sample);
    let mut context = SilkSampleContext {
        shared,
        config,
        logger,
        process_start,
        sample,
    };

    let service = certificate_service::CertificateService::start(shared, config, sample)?;
    let mut prepared = prepare::prepare(&mut context, &silk, &service.store)?;
    let (certified, mut agreement_trace) = agree::agree(
        &mut context,
        &silk,
        &protocols,
        &mut prepared,
        &service.store,
    )?;
    let mut result = reconstruct::reconstruct(
        &mut context,
        &silk,
        protocols,
        &prepared.state,
        certified,
        epoch,
        slots,
        predecessor,
    )?;
    agreement_trace.extend(service.finish()?);
    agreement_trace.extend(prepared.service.finish()?);
    result.agreement_trace = agreement_trace;
    Ok(result)
}
