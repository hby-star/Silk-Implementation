use super::*;
use protocol_support::{derive_seed, measurement::PhaseTimer, store::ProtocolStore};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use rondo_bavss_po::protocol::breeze_reconstruct::{
    CompactAggregateReconstructor, aggregate_dealer_secrets as rondo_aggregate,
    beacon_output as rondo_hash,
};
use rondo_bavss_po::protocol::breeze_share::BreezeDealer;
use rondo_bavss_po::protocol::breeze_verify::{BreezeReceiver, collect_qc as rondo_collect_qc};

pub(super) fn run(
    recorder: &mut RunRecorder,
    sample_context: SampleContext<'_>,
) -> Result<(), Box<dyn Error>> {
    let SampleContext {
        n, t, slots, seed, ..
    } = sample_context;
    let rondo_params = rondo_bavss_po::ProtocolParams::new(n, t, slots)?;
    let mut rondo_rng = ChaCha20Rng::seed_from_u64(seed.wrapping_add(1));
    let receivers = (0..n)
        .map(|receiver| {
            BreezeReceiver::from_seed(
                receiver,
                rondo_params,
                derive_seed(seed, format!("rondo-validator-{receiver}").as_bytes()),
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let committee = receivers
        .iter()
        .enumerate()
        .map(|(id, receiver)| (id, receiver.public_key()))
        .collect::<BTreeMap<_, _>>();
    let mut store = ProtocolStore::open(sample_context.store_path("rondo-bavss-po"))?;
    let mut wire = FramedWireCounter::default();

    let timer = PhaseTimer::start();
    let mut rondo = BreezeDealer::random(0, rondo_params, &mut rondo_rng)?;
    let (rondo_public, rondo_rows) = rondo.share(&mut rondo_rng)?;
    let proofs = rondo.batch_eval(&rondo_public, &rondo_rows)?;
    let mut share_wire = WireMeasurement::default();
    for (receiver, row) in rondo_rows.iter().enumerate().skip(1) {
        share_wire += wire.send(
            "rondo/bavss/share/v1",
            0,
            receiver as u32,
            &(&rondo_public, row, &proofs[receiver]),
        )?;
    }
    record_measurement(
        recorder,
        sample_context.event("rondo-bavss-po", rondo_bavss_po::IMPLEMENTATION_PROFILE),
        "share",
        timer.finish(),
        share_wire,
        store.bytes(),
    )?;

    let timer = PhaseTimer::start();
    let certs = rondo_rows
        .iter()
        .zip(proofs.iter())
        .enumerate()
        .map(|(receiver, (row, proof))| {
            let certificate = receivers[receiver].batch_verify_eval(row, &rondo_public, proof)?;
            store.persist(&("retained-row-v2", rondo_public.commitment_root, row))?;
            Ok(certificate)
        })
        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
    let rondo_qc = rondo_collect_qc(0, &rondo_public, &certs, &committee)?;
    let mut verify_wire = WireMeasurement::default();
    for (receiver, certificate) in certs.iter().enumerate().take(n).skip(1) {
        verify_wire += wire.send("rondo/bavss/validation/v1", receiver as u32, 0, certificate)?;
    }
    verify_wire += wire.broadcast("rondo/bavss/validation-certificate/v1", 0, n, &rondo_qc)?;
    store.persist(&("validation-certificate-v1", &rondo_qc))?;
    record_measurement(
        recorder,
        sample_context.event("rondo-bavss-po", rondo_bavss_po::IMPLEMENTATION_PROFILE),
        "verify",
        timer.finish(),
        verify_wire,
        store.bytes(),
    )?;

    let holder_points = (0..rondo_params.d)
        .map(|holder| curve25519_dalek::scalar::Scalar::from(holder as u64 + 1))
        .collect::<Vec<_>>();
    let rondo_reconstructor = CompactAggregateReconstructor::new(rondo_params, &holder_points)?;
    for index in 0..slots {
        let timer = PhaseTimer::start();
        let shares = rondo_rows
            .iter()
            .take(rondo_params.d)
            .map(|row| (row.eval_point, row.shares[index]))
            .collect::<Vec<_>>();
        let core_timer = PhaseTimer::start();
        let rondo_secret =
            rondo_reconstructor.reconstruct(&shares, rondo_public.commitments[index])?;
        let output = rondo_hash(
            b"bavss-phase-cost-rondo",
            index,
            b"single-dealer",
            rondo_aggregate(&[rondo_secret]),
        );
        let core_measurement = core_timer.finish();
        store.persist(&("reconstructed-output-v1", index as u32, output))?;
        let mut reconstruct_wire = WireMeasurement::default();
        for (holder, row) in rondo_rows.iter().take(rondo_params.d).enumerate() {
            let compact_share = (
                "rondo-compact-reconstruction-share-v1",
                0u32,
                holder as u32,
                index as u32,
                row.eval_point,
                row.shares[index],
            );
            reconstruct_wire += wire.broadcast(
                "rondo/bavss/compact-reconstruction-share/v1",
                holder as u32,
                n,
                &compact_share,
            )?;
        }
        let full_measurement = timer.finish();
        record_measurement(
            recorder,
            sample_context.event_at(
                "rondo-bavss-po",
                rondo_bavss_po::IMPLEMENTATION_PROFILE,
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
                "rondo-bavss-po",
                rondo_bavss_po::IMPLEMENTATION_PROFILE,
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
