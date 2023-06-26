use ark_bn254::{Bn254, G1Affine, G1Projective as G1, G2Affine, G2Projective as G2};
use ark_ec::{
    pairing::{Pairing, PairingOutput},
    CurveGroup, Group,
};
use ark_serialize::{CanonicalSerialize};
use ark_std::{ops::Mul, UniformRand};
use gclient::{EventListener, EventProcessor, GearApi, Result};
use gstd::{prelude::*};
use test_bn254::*;
const PATH: &str = "./target/wasm32-unknown-unknown/release/test_bn254.opt.wasm";


async fn common_upload_program(
    client: &GearApi,
    code: Vec<u8>,
    payload: impl Encode,
) -> Result<([u8; 32], [u8; 32])> {
    let encoded_payload = payload.encode();
    let gas_limit = client
        .calculate_upload_gas(None, code.clone(), encoded_payload, 0, true)
        .await?
        .min_limit;
    println!(" init gas {:?}", gas_limit);
    let (message_id, program_id, _) = client
        .upload_program(
            code,
            gclient::now_micros().to_le_bytes(),
            payload,
            gas_limit,
            0,
        )
        .await?;

    Ok((message_id.into(), program_id.into()))
}

async fn upload_program(
    client: &GearApi,
    listener: &mut EventListener,
    path: &str,
    payload: impl Encode,
) -> Result<[u8; 32]> {
    let (message_id, program_id) =
        common_upload_program(client, gclient::code_from_os(path)?, payload).await?;

    assert!(listener
        .message_processed(message_id.into())
        .await?
        .succeed());

    Ok(program_id)
}

#[ignore]
#[tokio::test]
async fn bn_verify_node() -> Result<()> {
    let client = GearApi::dev().await?.with("//Alice")?;
    let mut listener = client.subscribe().await?;

    type ScalarField = <G2 as Group>::ScalarField;
    let mut rng = ark_std::test_rng();

    let generator: G2 = G2::generator();
    let message: G1Affine = G1::rand(&mut rng).into();
    let mut pub_keys = Vec::new();
    let mut signatures = Vec::new();
    for _ in 0..2 {
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

    let program_id = upload_program(
        &client,
        &mut listener,
        PATH,
        InitMessage {
            g2_gen: gen_bytes,
            pub_keys,
        },
    )
    .await?;

    let mut message_bytes = Vec::new();
    message.serialize_compressed(&mut message_bytes).unwrap();

    let payload = HandleMessage::MillerLoop {
        message: message_bytes,
        signatures,
    };
    let gas_limit = client
        .calculate_handle_gas(None, program_id.into(), payload.encode(), 0, true)
        .await?
        .min_limit;
    println!("gas_limit {:?}", gas_limit);

    let (message_id, _) = client
        .send_message(program_id.into(), payload, gas_limit, 0)
        .await?;

    assert!(listener
        .message_processed(message_id.into())
        .await?
        .succeed());

    let gas_limit = client
        .calculate_handle_gas(
            None,
            program_id.into(),
            HandleMessage::Exp.encode(),
            0,
            true,
        )
        .await?
        .min_limit;
    println!("gas_limit {:?}", gas_limit);

    let (message_id, _) = client
        .send_message(program_id.into(), HandleMessage::Exp, gas_limit, 0)
        .await?;

    assert!(listener
        .message_processed(message_id.into())
        .await?
        .succeed());

    Ok(())
}

