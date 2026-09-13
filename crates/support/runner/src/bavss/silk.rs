use super::*;
use crypto_primitives::hash::hash;
use crypto_primitives::mldsa::{key_from_seed, public_key_bytes, verifying_key_from_bytes};
use protocol_support::{
    derive_seed, measurement::PhaseTimer, store::ProtocolStore, wire::canonical_serialize,
};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use serde::Serialize;
use silk_bavss_po::{
    CompactReconstructionItem, CompactReconstructionPlan, Dealer, ProtocolContext,
    build_dealer_certificate, compact_item_from_row, par_verify, sign_validation_statement,
    verify_dealer_certificate, verify_validation_statement_preparsed,
};

#[derive(Clone, Serialize)]
struct ReconstructionEnvelope {
    sender: u32,
    index: u32,
    item: CompactReconstructionItem,
}

pub(super) fn run(
    recorder: &mut RunRecorder,
    sample_context: SampleContext<'_>,
) -> Result<(), Box<dyn Error>> {
    let SampleContext {
        n, t, slots, seed, ..
    } = sample_context;
    let silk_params = silk_bavss_po::ProtocolParams::new(n, t, slots, 1)?;
    let sid = b"silk-bavss-phase-cost-v1".to_vec();
    let validation_keys = (0..n)
        .map(|node| {
            key_from_seed(derive_seed(
                seed,
                format!("silk-bavss-validation-{node}").as_bytes(),
            ))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let validation_public_keys = validation_keys
        .iter()
        .map(public_key_bytes)
        .collect::<Vec<_>>();
    let validation_verifying_keys = validation_public_keys
        .iter()
        .map(|key| verifying_key_from_bytes(key))
        .collect::<Result<Vec<_>, _>>()?;
    let protocol_context = ProtocolContext::derive(
        &sid,
        1,
        hash(&canonical_serialize(&(
            "silk/bavss-validation-registry/v1",
            &validation_public_keys,
        ))?),
        silk_params,
        slots as u64,
    )?;
    let mut store = ProtocolStore::open(sample_context.store_path("silk-bavss-po"))?;
    let mut wire = FramedWireCounter::default();

    let timer = PhaseTimer::start();
    let mut rng = ChaCha20Rng::from_seed(derive_seed(seed, b"silk-bavss-phase-cost-dealer-0"));
    let dealer = Dealer::random(sid.clone(), protocol_context, 0, silk_params, &mut rng)?;
    let (silk_public, silk_rows) = dealer.share(&mut rng)?;
    let mut share_wire = wire.broadcast("silk/bavss/public-transcript/v1", 0, n, &silk_public)?;
    for (receiver, row) in silk_rows.iter().enumerate().skip(1) {
        share_wire += wire.send("silk/bavss/private-row/v1", 0, receiver as u32, row)?;
    }
    record_measurement(
        recorder,
        sample_context.event("silk-bavss-po", silk_bavss_po::IMPLEMENTATION_PROFILE),
        "share",
        timer.finish(),
        share_wire,
        store.bytes(),
    )?;

    let timer = PhaseTimer::start();
    for row in &silk_rows {
        par_verify(&sid, protocol_context, silk_params, row, &silk_public)?;
        store.persist(&("retained-row-v1", silk_public.transcript_id(), row))?;
    }
    let transcript_id = silk_public.transcript_id();
    let validation_statements = (0..n)
        .map(|signer| {
            sign_validation_statement(
                &sid,
                protocol_context,
                signer as u32,
                0,
                silk_public.dealer,
                transcript_id,
                &validation_keys[signer],
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let selected_statements = validation_statements
        .iter()
        .take(silk_params.qc_threshold())
        .cloned()
        .collect::<Vec<_>>();
    for statement in &selected_statements {
        verify_validation_statement_preparsed(
            silk_params,
            &sid,
            protocol_context,
            &validation_verifying_keys,
            statement,
        )?;
    }
    let validation_certificate = build_dealer_certificate(
        silk_params,
        silk_public.dealer,
        silk_public.transcript_id(),
        &selected_statements,
    )?;
    verify_dealer_certificate(silk_params, &validation_certificate, &selected_statements)?;
    let mut verify_wire = WireMeasurement::default();
    for (signer, statement) in validation_statements.iter().enumerate().skip(1) {
        verify_wire += wire.send(
            "silk/bavss/validation-statement/v2",
            signer as u32,
            0,
            statement,
        )?;
    }
    verify_wire += wire.broadcast(
        "silk/bavss/validation-certificate/v1",
        0,
        n,
        &(&selected_statements, &validation_certificate),
    )?;
    store.persist(&(
        "validation-certificate-v1",
        &selected_statements,
        &validation_certificate,
    ))?;
    record_measurement(
        recorder,
        sample_context.event("silk-bavss-po", silk_bavss_po::IMPLEMENTATION_PROFILE),
        "verify",
        timer.finish(),
        verify_wire,
        store.bytes(),
    )?;

    let reconstruction_senders = silk_rows
        .iter()
        .take(silk_params.d)
        .map(|row| row.receiver)
        .collect::<Vec<_>>();
    let reconstruction_plan = CompactReconstructionPlan::new(silk_params, &reconstruction_senders)?;
    for index in 0..slots {
        let timer = PhaseTimer::start();
        let reconstruction_items = silk_rows
            .iter()
            .take(silk_params.d)
            .map(|row| {
                Ok(ReconstructionEnvelope {
                    sender: row.receiver,
                    index: index as u32,
                    item: compact_item_from_row(&silk_public, row, index)?,
                })
            })
            .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
        let fast_input = reconstruction_items
            .iter()
            .map(|message| (message.sender, message.item.clone()))
            .collect::<Vec<_>>();
        let core_timer = PhaseTimer::start();
        let fast_points =
            reconstruction_plan.verify_prevalidated(&silk_public, index, &fast_input)?;
        let fast_secret = reconstruction_plan.interpolate_shares(
            &fast_points
                .iter()
                .map(|(_, share)| *share)
                .collect::<Vec<_>>(),
        )?;
        let output = crypto_primitives::hash::hash(&fast_secret.to_bytes());
        let core_measurement = core_timer.finish();
        store.persist(&("reconstructed-output-v1", index as u32, output))?;
        let mut reconstruct_wire = WireMeasurement::default();
        for message in &reconstruction_items {
            reconstruct_wire += wire.broadcast(
                "silk/bavss/reconstruction-item/v1",
                message.sender,
                n,
                message,
            )?;
        }
        let full_measurement = timer.finish();
        record_measurement(
            recorder,
            sample_context.event_at(
                "silk-bavss-po",
                silk_bavss_po::IMPLEMENTATION_PROFILE,
                index as u32,
            ),
            "reconstruct",
            full_measurement,
            reconstruct_wire,
            store.bytes(),
        )?;
        record_measurement(
            recorder,
            sample_context.event_at(
                "silk-bavss-po",
                silk_bavss_po::IMPLEMENTATION_PROFILE,
                index as u32,
            ),
            "reconstruct-core",
            core_measurement,
            WireMeasurement::default(),
            store.bytes(),
        )?;
    }
    Ok(())
}
