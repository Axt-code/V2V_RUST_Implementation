extern crate blake2;
extern crate byteorder;
extern crate pairing;
extern crate rand;

use pairing::bls12_381::*;
use pairing::*;
use rand::XorShiftRng;

mod util;

// Key generation
pub fn bls_key_gen(rng: &mut XorShiftRng) -> (G2, Fr) {
    let g2 = G2::one();

    //let mut rng = OsRng::new().unwrap();

    let sk = util::gen_random_fr(rng);

    let vk = util::mul_g2_fr(g2, &sk);

    (vk, sk)
}

pub fn bls_sign(sk: &Fr, message: u128) -> G1 {
    let h = util::hash_int_to_g1(message);
    let sig = util::mul_g1_fr(h, &sk);
    sig
}

pub fn bls_verify(pk: &G2, message: u128, sign: G1) -> bool {
    let g2 = G2::one();
    let h = util::hash_int_to_g1(message);
    let left_pair = util::do_pairing(&sign.into_affine(), &g2.into_affine());
    let right_pait = util::do_pairing(&h.into_affine(), &pk.into_affine());

    left_pair == right_pait
}
