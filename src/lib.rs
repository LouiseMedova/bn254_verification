#![no_std]

use ark_bls12_381::{Bls12_381, G1Affine, G2Affine};
use ark_ec::pairing::Pairing;
use gstd::{msg::{self, builtin::bls12_381::*}, prelude::*, ActorId};
use hex_literal::hex;

type ArkScale<T> = ark_scale::ArkScale<T, { ark_scale::HOST_CALL }>;

const BUILTIN_BLS381: ActorId = ActorId::new(hex!(
    "821333d9551994022480dc6eb9d5cb323142d0073275564ff6f4dc6f0f2be545"
));

#[derive(Default)]
pub struct Contract {
    g2_gen: G2Affine,
    pub_keys: Vec<G2Affine>,
    aggregate_pub_key: G2Affine,
    miller_out: (
        // encoded ArkScale::<MillerLoopOutput<Bls12_381>>
        Option<Vec<u8>>,
        Option<Vec<u8>>,
    ),
}
static mut CONTRACT: Option<Contract> = None;

#[derive(Encode, Decode)]
pub enum HandleMessage {
    MillerLoop {
        message: Vec<u8>,
        signatures: Vec<Vec<u8>>,
    },
    Exp,
    Verify {
        message: Vec<u8>,
        signatures: Vec<Vec<u8>>,
    }
}

#[derive(Encode, Decode)]
pub struct InitMessage {
    pub g2_gen: Vec<u8>,
    pub pub_keys: Vec<Vec<u8>>,
}

#[gstd::async_main]
async fn main() {
    let msg: HandleMessage = msg::load().expect("Unable to decode `HandleMessage`");
    let contract = unsafe {
        CONTRACT
            .as_mut()
            .expect("The contract is not initialized")
    };

    match msg {
        HandleMessage::MillerLoop { message, signatures } => {
            let mut aggregate_signature: G1Affine = Default::default();
            for signature in signatures.iter() {
                let signature = <ArkScale<<Bls12_381 as Pairing>::G1Affine> as Decode>::decode(&mut signature.as_slice())
                    .unwrap();
                aggregate_signature = (aggregate_signature + signature.0).into();
            }

            let aggregate_pub_key: ArkScale<Vec<G2Affine>> = vec![contract.aggregate_pub_key.clone()].into();

            let request = Request::MultiMillerLoop { a: message, b: aggregate_pub_key.encode() }.encode();
            let reply = msg::send_bytes_for_reply(BUILTIN_BLS381, &request, 0, 0)
                .expect("Failed to send message")
                .await
                .expect("Received error reply");

            let response = Response::decode(&mut reply.as_slice()).unwrap();
            let miller_out1 = match response {
                Response::MultiMillerLoop(MultiMillerLoopResult::Ok(v)) => v,
                _ => unreachable!(),
            };

            let aggregate_signature: ArkScale<Vec<G1Affine>> = vec![aggregate_signature].into();
            let g2_gen: ArkScale<Vec<G2Affine>> = vec![contract.g2_gen.clone()].into();
            let request = Request::MultiMillerLoop { a: aggregate_signature.encode(), b: g2_gen.encode() }.encode();
            let reply = msg::send_bytes_for_reply(BUILTIN_BLS381, &request, 0, 0)
                .expect("Failed to send message")
                .await
                .expect("Received error reply");
            let response = Response::decode(&mut reply.as_slice()).unwrap();
            let miller_out2 = match response {
                Response::MultiMillerLoop(MultiMillerLoopResult::Ok(v)) => v,
                _ => unreachable!(),
            };

            contract.miller_out = (Some(miller_out1), Some(miller_out2));
        }

        HandleMessage::Exp => {
            if let (Some(miller_out1), Some(miller_out2)) = &contract.miller_out {
                let request = Request::FinalExponentiation { f: miller_out1.clone() }.encode();
                let reply = msg::send_bytes_for_reply(BUILTIN_BLS381, &request, 0, 0)
                    .expect("Failed to send message")
                    .await
                    .expect("Received error reply");
                let response = Response::decode(&mut reply.as_slice()).unwrap();
                let exp1 = match response {
                    Response::FinalExponentiation(Ok(v)) => ArkScale::<<Bls12_381 as Pairing>::TargetField>::decode(&mut v.as_slice()).unwrap(),
                    _ => unreachable!(),
                };

                let request = Request::FinalExponentiation { f: miller_out2.clone() }.encode();
                let reply = msg::send_bytes_for_reply(BUILTIN_BLS381, &request, 0, 0)
                    .expect("Failed to send message")
                    .await
                    .expect("Received error reply");
                let response = Response::decode(&mut reply.as_slice()).unwrap();
                let exp2 = match response {
                    Response::FinalExponentiation(Ok(v)) => ArkScale::<<Bls12_381 as Pairing>::TargetField>::decode(&mut v.as_slice()).unwrap(),
                    _ => unreachable!(),
                };

                assert_eq!(exp1.0, exp2.0);

                contract.miller_out = (None, None);
            }
        }

        _ => todo!(),
    }
}

#[no_mangle]
extern "C" fn init() {
    let init_msg: InitMessage = msg::load().expect("Unable to decode `InitMessage`");

    let g2_gen = <ArkScale<<Bls12_381 as Pairing>::G2Affine> as Decode>::decode(&mut init_msg.g2_gen.as_slice())
        .unwrap();

    let mut pub_keys = Vec::new();
    let mut aggregate_pub_key: G2Affine = Default::default();

    for pub_key_bytes in init_msg.pub_keys.iter() {
        let pub_key = <ArkScale<<Bls12_381 as Pairing>::G2Affine> as Decode>::decode(&mut pub_key_bytes.as_slice())
            .unwrap();
       aggregate_pub_key = (aggregate_pub_key + pub_key.0).into();
       pub_keys.push(pub_key.0);
    }

    let contract = Contract {
        g2_gen: g2_gen.0,
        pub_keys,
        aggregate_pub_key,
        miller_out: (None, None),
    };

    unsafe { CONTRACT = Some(contract) }
}
