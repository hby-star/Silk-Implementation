//! Same-message ML-DSA-65 interoperability and remote CPU comparison.
use crypto_primitives::mldsa;
use libcrux_ml_dsa::{MLDSASignature, ml_dsa_65 as fast};
use ml_dsa::{Keypair, MlDsa65, Seed, SignatureEncoding, Signer, SigningKey};
use std::{hint::black_box, time::Instant};

fn main() {
    let iterations = 256;
    let reference = SigningKey::<MlDsa65>::from_seed(&Seed::from([71; 32]));
    let public = reference.verifying_key().encode().as_slice().to_vec();
    let parsed = mldsa::verifying_key_from_bytes(&public).unwrap();
    let fast_key = fast::generate_key_pair([71; 32]);
    assert_eq!(public, fast_key.verification_key.as_slice());
    let message = b"silk-validation-backend-comparison/epoch/1/dealer/7";
    let reference_signature = reference.sign(message).to_bytes().as_slice().to_vec();
    let fast_signature = fast::sign(&fast_key.signing_key, message, b"", [0; 32]).unwrap();
    assert_eq!(reference_signature, fast_signature.as_slice());
    let encoded = MLDSASignature::new(reference_signature.as_slice().try_into().unwrap());
    fast::verify(&fast_key.verification_key, message, b"", &encoded).unwrap();
    mldsa::verify_with_key(&parsed, fast_signature.as_slice(), message).unwrap();
    assert!(fast::verify(&fast_key.verification_key, b"wrong", b"", &encoded).is_err());
    println!("backend,operation,iterations,ns_per_operation");
    let start = Instant::now();
    for _ in 0..iterations {
        black_box(reference.sign(black_box(message)));
    }
    println!(
        "rustcrypto,sign,{iterations},{}",
        start.elapsed().as_nanos() / iterations
    );
    let start = Instant::now();
    for _ in 0..iterations {
        black_box(fast::sign(&fast_key.signing_key, black_box(message), b"", [0; 32]).unwrap());
    }
    println!(
        "libcrux-dispatch,sign,{iterations},{}",
        start.elapsed().as_nanos() / iterations
    );
    let start = Instant::now();
    for _ in 0..iterations {
        mldsa::verify_with_key(&parsed, black_box(&reference_signature), message).unwrap();
    }
    println!(
        "{},verify,{iterations},{}",
        mldsa::backend_name(),
        start.elapsed().as_nanos() / iterations
    );
    let start = Instant::now();
    for _ in 0..iterations {
        fast::verify(
            &fast_key.verification_key,
            message,
            b"",
            black_box(&encoded),
        )
        .unwrap();
    }
    println!(
        "libcrux-dispatch,verify,{iterations},{}",
        start.elapsed().as_nanos() / iterations
    );
}
