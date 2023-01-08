#[warn(non_snake_case)]
use zcash_proofs::circuit::ecc::*;
use bellman::gadgets::test::*;
mod circuit;
use circuit::*;
use zcash_proofs::constants::*;
use bellman::gadgets::boolean::Boolean;
use rand_xorshift::XorShiftRng;
use jubjub;
use ff::{Field};
use rand_core::SeedableRng;
use bellman::groth16::{
    create_random_proof, generate_random_parameters, prepare_verifying_key, verify_proof
};
use bls12_381::{Bls12};
use std::time::{Duration, Instant};
use std::fs::File;
fn main() {
    println!("Hello, world!");

    let mut rng = XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06,
        0xbc, 0xe5,
    ]);
    let mut total_para = Duration::new(0, 0);
    let mut total_proof = Duration::new(0, 0);
    let start = Instant::now();
    let params = {

        let c = Mint {
            token_id: None,
            sk: None,
            hash: None
        };

        // let c = Transfer {
        //     token_id: None,
        //     sk: None,
        //     hash1: None,
        //     pk_x : None,
        //     pk_y : None,
        //     hash2: None

        // };

        generate_random_parameters::<Bls12, _, _>(c, &mut rng).unwrap()
    };
    let buffer = File::create("foo").unwrap();
    params.write(buffer).unwrap();

    let pvk = prepare_verifying_key(&params.vk);

    total_para += start.elapsed();
    let start = Instant::now();
    {
        // Create an instance of our circuit (with the
        // witness)
        let token_id = jubjub::Fr::random(&mut rng);
        let sk = jubjub::Fr::random(&mut rng);
        let hash1 = jubjub::Fr::random(&mut rng);
        let pk_x = bls12_381::Scalar::random(&mut rng);
        let pk_y = bls12_381::Scalar::random(&mut rng);
        let hash2 = jubjub::Fr::random(&mut rng);

        let c = Mint {
            token_id: Some(token_id),
            sk : Some(sk),
            hash : Some(hash1)
        };

        // let c = Transfer {

        //     token_id: Some(token_id),
        //     sk : Some(sk),
        //     hash1 : Some(hash1),
        //     pk_x : Some(pk_x),
        //     pk_y : Some(pk_y),
        //     hash2: Some(hash2)

        // };

        // Create a groth16 proof with our parameters.
        let proof = create_random_proof(c, &params, &mut rng).unwrap();

    }
    total_proof += start.elapsed();
    println!("{:?} {:?}",total_para.as_millis(),total_proof.as_millis());

}
