extern crate blake2;
extern crate byteorder;
extern crate pairing;
extern crate rand;

use blake2::{Blake2b, Blake2s, Digest};
use byteorder::{BigEndian, ByteOrder, NativeEndian, ReadBytesExt};
use pairing::bls12_381::*;
use pairing::*;
use rand::chacha::ChaChaRng;
use rand::{Rand, Rng, SeedableRng, XorShiftRng};
use std::fmt;
use std::time::{Duration, Instant};

mod util;

// Key generation
pub fn pke_key_gen(rng: &mut XorShiftRng) -> (G2, Fr) {
    let g2 = G2::one();

    //let mut rng = OsRng::new().unwrap();

    let sk = util::gen_random_fr(rng);
    let vk = util::mul_g2_fr(g2, &sk);
    (vk, sk)
}

pub fn pke_encrypt(rng: &mut XorShiftRng, pk: G2, plaintext: G2) -> (G2, G2){
    let g = G2::one();
    let k = util::gen_random_fr(rng); 
    let c_1 = util::mul_g2_fr(g, &k);
    let c_2 = util::add_g2_g2(util::mul_g2_fr(pk, &k), plaintext);
    (c_1, c_2)
}

pub fn pke_decrypt(sk: &Fr, ciphertext: (G2, G2)) -> G2 {
    let (c_1, c_2) = ciphertext;
    let c_1_sk = util::mul_g2_fr(c_1, &sk);
    let plaintext = util::add_g2_g2(c_2, util::g2_neg(c_1_sk));
    plaintext
}
