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

pub fn keygen(rng: &mut XorShiftRng, k: usize) -> (G2, Fr, Vec<Fr>, Fr, G2, Vec<G2>, G2) {
    let g2 = G2::one();

    let x2 = util::gen_random_fr(rng);
    let k = 10;
    let mut yk = Vec::with_capacity(k);

    for _ in 0..k {
        let y = util::gen_random_fr(rng);
        yk.push(y);
    }

    let yk1 = util::gen_random_fr(rng);

    let X2 = util::mul_g2_fr(g2, &x2);

    let mut YK = Vec::with_capacity(k);
    for i in 0..k {
        let Y = util::mul_g2_fr(g2, &yk[i]);
        YK.push(Y);
    }

    let YK1 = util::mul_g2_fr(g2, &yk1);

    println!("{}", { "\nKEY GENERATION......\n" });
    util::print_g2(&g2);
    util::print_fr(&x2);
    println!("yk: {:?}", yk);
    println!();
    util::print_fr(&yk1);
    util::print_g2(&X2);
    println!("YK: {:?}", YK);
    println!();
    util::print_g2(&YK1);

    (g2, x2, yk, yk1, X2, YK, YK1)
}

pub fn sign(
    rng: &mut XorShiftRng,
    g2: &G2,
    x2: &Fr,
    yk: &Vec<Fr>,
    yk1: &Fr,
    k: usize,
) -> (Fr, G1, Vec<Fr>, G1) {
    let h = G1::one();
    let m_dash = util::gen_random_fr(rng);

    let mut yjmj = x2.clone();

    let mut messages = Vec::with_capacity(k);

    for _ in 0..k {
        let m = util::gen_random_fr(rng);
        messages.push(m);
    }

    for i in 0..k {
        yjmj = util::add_fr_fr(yjmj, &util::mul_fr_fr(yk[i], &messages[i]));
    }

    let pw = util::add_fr_fr(yjmj, &util::mul_fr_fr(m_dash, yk1));

    let sigma_2 = util::mul_g1_fr(h, &pw);

    println!("{}", { "\nSIGNING......\n" });
    println!("m_dash {:?}", m_dash);
    println!();
    println!("h {:?}", h);
    println!();
    println!("sigma_2 {:?}", sigma_2);

    (m_dash, h, messages, sigma_2)
}

pub fn verify(
    h: &G1,
    m_dash: &Fr,
    messages: &Vec<Fr>,
    sigma_2: &G1,
    X2: &G2,
    YK: &Vec<G2>,
    YK1: &G2,
    g2: &G2,
    k: usize,
) -> bool {
    let mut XYY = X2.clone();

    for i in 0..k {
        XYY = util::add_g2_g2(XYY, util::mul_g2_fr(YK[i], &messages[i]));
    }

    XYY = util::add_g2_g2(XYY, util::mul_g2_fr(*YK1, m_dash));

    let pair1 = util::do_pairing(&h.into_affine(), &XYY.into_affine());
    let pair2 = util::do_pairing(&sigma_2.into_affine(), &g2.into_affine());

    println!("{}", { "\nVERIFYING......\n" });

    println!();
    println!("XYY {:?}", XYY);
    println!("pair1 {:?}", pair1);
    println!();
    println!("pair2 {:?}", pair2);
    println!();

    pair1 == pair2
}
