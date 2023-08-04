#![no_std]

use ark_ec::pairing::{MillerLoopOutput, Pairing};
use ark_ec::Group;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use gstd::{debug, msg, prelude::*};
use sp_ark_bls12_381::{
    fq::Fq, fq2::Fq2, fr::Fr, Bls12_381 as Bls12_381Host, G1Affine as G1AffineHost,
    G1Projective as G1ProjectiveHost, G2Affine as G2AffineHost,
    G2Projective as G2ProjectiveHost, HostFunctions, ArkScale,
};

#[derive(PartialEq, Eq)]
struct Host<const PREALLOCATE: u32 = 1_000>;

mod sys {
    extern "C" {
        pub fn bls12_381_multi_miller_loop(
            a_len: u32,
            a_ptr: *const u8,
            b_len: u32,
            b_ptr: *const u8,
            len_ptr: *mut u32,
            ptr: *mut u8,
        ) -> u32;

        pub fn bls12_381_final_exponentiation(
            a_len: u32,
            a_ptr: *const u8,
            len_ptr: *mut u32,
            ptr: *mut u8,
        ) -> u32;
    }
}

impl<const PREALLOCATE: u32> HostFunctions for Host<PREALLOCATE> {
    fn bls12_381_multi_miller_loop(a: Vec<u8>, b: Vec<u8>) -> Result<Vec<u8>, ()> {
        // crate::elliptic_curves::bls12_381_multi_miller_loop(a, b)

        let mut result = vec![0u8; PREALLOCATE as usize];
        let mut len = result.len() as u32;
        if unsafe { sys::bls12_381_multi_miller_loop(
            a.len() as u32,
            a.as_ptr(),
            b.len() as u32,
            b.as_ptr(),
            &mut len,
            result.as_mut_ptr(),
        ) } != 0 {
            return Err(());
        }

        result.truncate(len as usize);

        Ok(result)
        // todo!()
    }

    fn bls12_381_final_exponentiation(f12: Vec<u8>) -> Result<Vec<u8>, ()> {
        // crate::elliptic_curves::bls12_381_final_exponentiation(f12)

        let mut result = vec![0u8; PREALLOCATE as usize];
        let mut len = result.len() as u32;
        if unsafe { sys::bls12_381_final_exponentiation(
            f12.len() as u32,
            f12.as_ptr(),
            &mut len,
            result.as_mut_ptr(),
        ) } != 0 {
            return Err(());
        }

        result.truncate(len as usize);

        Ok(result)
        //todo!()
    }

    fn bls12_381_msm_g1(bases: Vec<u8>, bigints: Vec<u8>) -> Result<Vec<u8>, ()> {
        // crate::elliptic_curves::bls12_381_msm_g1(bases, bigints)
        todo!()
    }

    fn bls12_381_msm_g2(bases: Vec<u8>, bigints: Vec<u8>) -> Result<Vec<u8>, ()> {
        // crate::elliptic_curves::bls12_381_msm_g2(bases, bigints)
        todo!()
    }

    fn bls12_381_mul_projective_g1(base: Vec<u8>, scalar: Vec<u8>) -> Result<Vec<u8>, ()> {
        // crate::elliptic_curves::bls12_381_mul_projective_g1(base, scalar)
        todo!()
    }

    fn bls12_381_mul_projective_g2(base: Vec<u8>, scalar: Vec<u8>) -> Result<Vec<u8>, ()> {
        // crate::elliptic_curves::bls12_381_mul_projective_g2(base, scalar)
        todo!()
    }
}

type Bls12_381 = Bls12_381Host<Host>;
type G1Projective = G1ProjectiveHost<Host>;
type G2Projective = G2ProjectiveHost<Host>;
type G1Affine = G1AffineHost<Host>;
type G2Affine = G2AffineHost<Host>;

#[derive(Default)]
pub struct BnContract {
    g2_gen: G2Affine,
    pub_keys: Vec<G2Affine>,
    aggregate_pub_key: G2Affine,
    miller_out: (
        Option<MillerLoopOutput<Bls12_381>>,
        Option<MillerLoopOutput<Bls12_381>>,
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

impl BnContract {
    fn miller_loop(&mut self, message: Vec<u8>, signatures: Vec<Vec<u8>>) {
        let mut aggregate_signature: G1Affine = Default::default();
        for signature in signatures.iter() {
            // let signature = G1Affine::deserialize_compressed(&**signature).unwrap();
            let signature = <ArkScale<<Bls12_381 as Pairing>::G1Affine> as Decode>::decode(&mut signature.as_slice())
                .unwrap();
            aggregate_signature = (aggregate_signature + signature.0).into();
        }

        // let message = G1Affine::deserialize_compressed(&*message).unwrap();
        let message = <ArkScale<<Bls12_381 as Pairing>::G1Affine> as Decode>::decode(&mut message.as_slice())
            .unwrap();
        let miller_out1 = Bls12_381::miller_loop(message.0, self.aggregate_pub_key);
        let miller_out2 = Bls12_381::miller_loop(aggregate_signature, self.g2_gen);
        self.miller_out = (Some(miller_out1), Some(miller_out2));
    }

    fn exp(&mut self) {
        if let (Some(miller_out1), Some(miller_out2)) = self.miller_out {
            let exp1 = Bls12_381::final_exponentiation(miller_out1).unwrap();
            let exp2 = Bls12_381::final_exponentiation(miller_out2).unwrap();
            assert_eq!(exp1, exp2);
            self.miller_out = (None, None);
        }
    }

    fn verify(&mut self, message: Vec<u8>, signatures: Vec<Vec<u8>>) {
        let mut aggregate_signature: G1Affine = Default::default();
        for signature in signatures.iter() {
            let signature = G1Affine::deserialize_compressed(&**signature).unwrap();
            aggregate_signature = (aggregate_signature + signature).into();
        }

        let message = G1Affine::deserialize_compressed(&*message).unwrap();

        let e1 = Bls12_381::pairing(message, self.aggregate_pub_key);
        let e2 = Bls12_381::pairing(aggregate_signature, self.g2_gen);

        assert_eq!(e1, e2);
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
        HandleMessage::Verify { message, signatures } => bn_contract.verify(message, signatures),
    }
}

#[no_mangle]
extern "C" fn init() {
    let init_msg: InitMessage = msg::load().expect("Unable to decode `InitMessage`");

    let g2_gen = <ArkScale<<Bls12_381 as Pairing>::G2Affine> as Decode>::decode(&mut init_msg.g2_gen.as_slice())
        .unwrap();
    // let g2_gen = <ArkScale<<ark_bn254::Bn254 as Pairing>::G2Affine> as Decode>::decode(&mut init_msg.g2_gen.as_slice())
    //     .unwrap();

    // let g2_gen = G2Affine::deserialize_compressed(&*init_msg.g2_gen).unwrap();

    let mut pub_keys = Vec::new();
    let mut aggregate_pub_key: G2Affine = Default::default();

    for pub_key_bytes in init_msg.pub_keys.iter() {
    //    let pub_key = G2Affine::deserialize_compressed(&**pub_key_bytes).unwrap();
    //    let pub_key = <ArkScale<<ark_bn254::Bn254 as Pairing>::G2Affine> as Decode>::decode(&mut pub_key_bytes.as_slice())
    //         .unwrap();
    let pub_key = <ArkScale<<Bls12_381 as Pairing>::G2Affine> as Decode>::decode(&mut pub_key_bytes.as_slice())
            .unwrap();
       aggregate_pub_key = (aggregate_pub_key + pub_key.0).into();
       pub_keys.push(pub_key.0);
    }

    let bn_contract = BnContract {
        g2_gen: g2_gen.0,
        pub_keys,
        aggregate_pub_key,
        miller_out: (None, None),
    };

    unsafe { BN_CONTRACT = Some(bn_contract) }
}
