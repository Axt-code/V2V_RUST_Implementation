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

pub fn do_pairing(g_1: &G1Affine, g_2: &G2Affine) -> Fq12 {
    Bls12::final_exponentiation(&Bls12::miller_loop([&(
        &(*g_1).prepare(),
        &(*g_2).prepare(),
    )]))
    .unwrap()
}

pub fn gen_random_fr(rng: &mut XorShiftRng) -> Fr {
    let sk = Fr::rand(rng);
    sk
}

pub fn gen_random_g1(rng: &mut XorShiftRng) -> G1 {
    let sk = G1::rand(rng);
    sk
}

pub fn gen_random_g2(rng: &mut XorShiftRng) -> G2 {
    let sk = G2::rand(rng);
    sk
}

pub fn gen_random_gt(rng: &mut XorShiftRng) -> Fq12 {
    let sk = Fq12::rand(rng);
    sk
}

pub fn mul_fr_fr(a: Fr, b: &Fr) -> Fr {
    let mut r = &mut a.clone();
    r.mul_assign(b);
    return *r;
}

pub fn mul_g1_fr(a: G1, b: &Fr) -> G1 {
    let mut r = &mut a.clone();
    r.mul_assign(*b);
    return *r;
}
pub fn mul_g2_fr(a: G2, b: &Fr) -> G2 {
    let mut r = &mut a.clone();
    r.mul_assign(*b);
    return *r;
}

pub fn add_fr_fr(a: Fr, b: &Fr) -> Fr {
    let mut r = &mut a.clone();
    r.add_assign(b);
    return *r;
}

pub fn add_g1_g1(a: G1, b: G1) -> G1 {
    let mut r = &mut a.clone();
    r.add_assign(&b);
    return *r;
}

pub fn add_g2_g2(a: G2, b: G2) -> G2 {
    let mut r = &mut a.clone();
    r.add_assign(&b);
    return *r;
}

pub fn add_fq12_fq12(a: Fq12, b: Fq12) -> Fq12 {
    let mut r = &mut a.clone();
    r.add_assign(&b);
    return *r;
}

pub fn mul_fq12_fq12(a: Fq12, b: Fq12) -> Fq12 {
    let mut r = &mut a.clone();
    r.mul_assign(&b);
    return *r;
}

pub fn fr_inv(a: Fr) -> Fr {
    let mut r = &mut a.clone();
    let k = r.inverse().unwrap();
    k
}

pub fn g1_neg(a: G1) -> G1 {
    let mut r = &mut a.clone();
    r.negate();
    *r
}

pub fn g2_neg(a: G2) -> G2 {
    let mut r = &mut a.clone();
    r.negate();
    *r
}
pub fn gt_inv(a: Fq12) -> Fq12 {
    let mut r = &mut a.clone();
    let k = r.inverse().unwrap();
    k
}

pub fn print_fr(a: &Fr) -> () {
    println!("element fr:{:?}", *a);
    println!();
}

pub fn print_g1(a: &G1) -> () {
    println!("element g1:{:?}", *a);
    println!();
}

pub fn print_g2(a: &G2) -> () {
    println!("element g2:{:?}", *a);
    println!();
}
pub fn print_gt(a: &Fq12) -> () {
    println!("element gt:{:?}", *a);
    println!();
}

pub fn int_to_fr(i: &u128) -> Fr {
    Fr::from_str(&i.to_string()).unwrap()
}
