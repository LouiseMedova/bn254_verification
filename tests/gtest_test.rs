use ark_bn254::{Bn254, G1Affine, G1Projective as G1, G2Affine, G2Projective as G2};
use ark_ec::{
    pairing::{Pairing, PairingOutput},
    CurveGroup, Group,
};
use ark_ff::fields::{Fp256, MontBackend, MontConfig};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{ops::Mul, One, UniformRand};
use gstd::{prelude::*, ActorId};
use gtest::{Program, System};
use test_bn254::*;

#[test]
fn bn_verify_gtest() {
    let system = System::new();
    let program = Program::current(&system);

    type ScalarField = <G2 as Group>::ScalarField;
    let mut rng = ark_std::test_rng();

    let generator: G2 = G2::generator();
    let message: G1Affine = G1::rand(&mut rng).into();
    let mut pub_keys = Vec::new();
    let mut signatures = Vec::new();
    for _ in 0..10 {
        let priv_key: ScalarField = UniformRand::rand(&mut rng);
        let pub_key: G2Affine = generator.mul(priv_key).into();
        let mut pub_key_bytes = Vec::new();
        pub_key.serialize_compressed(&mut pub_key_bytes).unwrap();
        pub_keys.push(pub_key_bytes);

         // sign
        let signature: G1Affine = message.mul(priv_key).into();
        let mut sig_bytes = Vec::new();
        signature.serialize_compressed(&mut sig_bytes).unwrap();
        signatures.push(sig_bytes);   
    }
    
    let mut gen_bytes = Vec::new();
    generator.serialize_compressed(&mut gen_bytes).unwrap();

    let mut gen_bytes = Vec::new();
    generator.serialize_compressed(&mut gen_bytes).unwrap();

    let result = program.send(10, InitMessage {
        g2_gen: gen_bytes,
        pub_keys,
    });

    assert!(!result.main_failed());

    let mut message_bytes = Vec::new();
    message.serialize_compressed(&mut message_bytes).unwrap();


    let payload = HandleMessage::MillerLoop {
        message: message_bytes,
        signatures,
    };

    let result = program.send(10, payload);

    assert!(!result.main_failed());

    let result = program.send(10, HandleMessage::Exp);

    assert!(!result.main_failed());

}
