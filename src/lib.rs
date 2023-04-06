#![no_std]
use ark_bn254::{Bn254, G1Affine, G1Projective as G1, G2Affine, G2Projective as G2};
use ark_ec::pairing::{MillerLoopOutput, Pairing};
use ark_ec::Group;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use gstd::{debug, msg, prelude::*};

#[derive(Default)]
pub struct BnContract {
    g2_gen: G2Affine,
    pub_keys: Vec<G2Affine>,
    aggregate_pub_key: G2Affine,
    miller_out: (
        Option<MillerLoopOutput<Bn254>>,
        Option<MillerLoopOutput<Bn254>>,
    ),
}
static mut BN_CONTRACT: Option<BnContract> = None;

#[derive(Encode, Decode)]
pub enum HandleMessage {
    MillerLoop {
        message: Vec<u8>,
        signatures: Vec<Vec<u8>>,
    },
    Exp,
}

#[derive(Encode, Decode)]
pub struct InitMessage {
    pub g2_gen: Vec<u8>,
    pub pub_keys: Vec<Vec<u8>>,
}

impl BnContract {
    fn miller_loop(&mut self, message: Vec<u8>, signatures: Vec<Vec<u8>>) {
        let mut aggregate_signature: G1Affine = Default::default();
        for signature in signatures.iter() {
            let signature = G1Affine::deserialize_compressed(&**signature).unwrap();
            aggregate_signature = (aggregate_signature + signature).into();
        }
        let message = G1Affine::deserialize_compressed(&*message).unwrap();
        let miller_out1 = Bn254::miller_loop(message, self.aggregate_pub_key);
        let miller_out2 = Bn254::miller_loop(aggregate_signature, self.g2_gen);
        self.miller_out = (Some(miller_out1), Some(miller_out2));
    }

    fn exp(&mut self) {
        if let (Some(miller_out1), Some(miller_out2)) = self.miller_out {
            let exp1 = Bn254::final_exponentiation(miller_out1).unwrap();
            let exp2 = Bn254::final_exponentiation(miller_out2).unwrap();
            assert_eq!(exp1, exp2);
            self.miller_out = (None, None);
        }
    }
}

#[no_mangle]
extern "C" fn handle() {
    let msg: HandleMessage = msg::load().expect("Unable to decode `HandleMessage`");
    let bn_contract = unsafe {
        BN_CONTRACT
            .as_mut()
            .expect("The contract is not initialized")
    };

    match msg {
        HandleMessage::MillerLoop { message, signatures } => {
            bn_contract.miller_loop(message, signatures)
        }
        HandleMessage::Exp => bn_contract.exp(),
    }
}

#[no_mangle]
extern "C" fn init() {
    let init_msg: InitMessage = msg::load().expect("Unable to decode `InitMessage`");

    let g2_gen = G2Affine::deserialize_compressed(&*init_msg.g2_gen).unwrap();

    let mut pub_keys = Vec::new();
    let mut aggregate_pub_key: G2Affine = Default::default();

    for pub_key_bytes in init_msg.pub_keys.iter() {
       let pub_key = G2Affine::deserialize_compressed(&**pub_key_bytes).unwrap();
       aggregate_pub_key =  (aggregate_pub_key + pub_key).into();
       pub_keys.push(pub_key);
    }

    let bn_contract = BnContract {
        g2_gen,
        pub_keys,
        aggregate_pub_key,
        miller_out: (None, None),
    };

    unsafe { BN_CONTRACT = Some(bn_contract) }
}
