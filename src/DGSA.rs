extern crate bit_vec;
extern crate blake2;
extern crate byteorder;
extern crate pairing;
extern crate rand;

use pairing::bls12_381::*;
use pairing::*;
use rand::{SeedableRng, XorShiftRng};
use std::collections::HashMap;
use std::time::{Duration, Instant};

mod util;

pub fn keygen(rng: &mut XorShiftRng, k: usize) -> (G2, Fr, Fr, Fr, Fr, G2, G2, G2, G2) {
    let g2 = G2::one();

    // sk
    let x2 = util::gen_random_fr(rng);
    let y_id = util::gen_random_fr(rng);
    let y_epoch = util::gen_random_fr(rng);
    let y_k1 = util::gen_random_fr(rng);

    // pk
    let X2 = util::mul_g2_fr(g2, &x2);
    let Y_id = util::mul_g2_fr(g2, &y_id);
    let Y_epoch = util::mul_g2_fr(g2, &y_epoch);
    let Y_K1 = util::mul_g2_fr(g2, &y_k1);

    // SET
    println!("{}", { "\nKEY GENERATION......\n" });
    // util::print_g2("g2", &g2);
    // util::print_fr("x2", &x2);
    // util::print_fr("y_id", &y_id);
    // util::print_fr("y_epoch", &y_epoch);
    // util::print_fr("y_k1", &y_k1);
    // util::print_g2("X2", &X2);
    // util::print_g2("Y_id", &Y_id);
    // util::print_g2("Y_epoch", &Y_epoch);
    // util::print_g2("Y_k1", &Y_K1);
    (g2, x2, y_id, y_epoch, y_k1, X2, Y_id, Y_epoch, Y_K1)
}
pub fn issue_i<'a>(
    rng: &mut XorShiftRng,
    g2: &G2,
    x2: &Fr,
    y_id: &Fr,
    y_epoch: &Fr,
    y_k1: &Fr,
    id: &u128,
    epoch: &u128,
    set: &mut HashMap<(u128, u128), Fr>,
) -> Option<((Fr, G1, G1), HashMap<(u128, u128), Fr>)> {
    let a_dash = util::gen_random_fr(rng);

    if set.contains_key(&(*id, *epoch)) {
        println!("The key (id, epoch) is present in the map.");
        return None; // Exit the function early if the key is present
    } else {
        // println!("The key (id, epoch) is not present in the map.");
        set.insert((*id, *epoch), a_dash.clone());
    }

    let h = G1::one();

    // converting id and epoch to field element
    let id_fr = util::int_to_fr(id);
    let epoch_fr = util::int_to_fr(epoch);

    let mut pw = x2.clone();
    pw = util::add_fr_fr(pw, &util::mul_fr_fr(id_fr, &y_id));
    pw = util::add_fr_fr(pw, &util::mul_fr_fr(epoch_fr, &y_epoch));
    pw = util::add_fr_fr(pw, &util::mul_fr_fr(a_dash, y_k1));

    let sigma_2 = util::mul_g1_fr(h, &pw);

    let sigma = (a_dash, h, sigma_2);

    println!("{}", { "\nISSUE_I......\n" });
    // util::print_fr("a_dash", &a_dash);
    // util::print_g1("h", &h);
    // util::print_fr("pw", &pw);
    // util::print_g1("sigma_2", &sigma_2);

    Some((sigma, set.clone()))
}
pub fn issue_u(
    sigma: &(Fr, G1, G1),
    id: &u128,
    epoch: &u128,
    X2: &G2,
    Y_id: &G2,
    Y_epoch: &G2,
    Y_K1: &G2,
    g2: &G2,
) -> bool {
    // converting id and epoch to field element
    let (a_dash, h, sigma_2) = sigma;
    let id_fr = util::int_to_fr(id);
    let epoch_fr = util::int_to_fr(epoch);

    let mut XYY = X2.clone();

    XYY = util::add_g2_g2(XYY, util::mul_g2_fr(*Y_id, &id_fr));
    XYY = util::add_g2_g2(XYY, util::mul_g2_fr(*Y_epoch, &epoch_fr));
    XYY = util::add_g2_g2(XYY, util::mul_g2_fr(*Y_K1, a_dash));

    let pair1 = util::do_pairing(&h.into_affine(), &XYY.into_affine());
    let pair2 = util::do_pairing(&sigma_2.into_affine(), &g2.into_affine());

    println!("{}", { "\nISSUE_U......\n" });
    // util::print_g2("XYY", &XYY);
    // util::print_gt("pair1", &pair1);
    // util::print_gt("pair2", &pair2);
    pair1 == pair2
}

pub fn auth(
    rng: &mut XorShiftRng,
    m: &u128,
    sigma: &(Fr, G1, G1),
    id: &u128,
    epoch: &u128,
    X2: &G2,
    Y_id: &G2,
    Y_epoch: &G2,
    Y_K1: &G2,
    g2: &G2,
) -> (G1, G1, (Fr, (Fr, Fr))) {
    let (a_dash, sigma_1, sigma_2) = sigma;
    let id_fr = util::int_to_fr(id);
    let epoch_fr = util::int_to_fr(epoch);

    let r = util::gen_random_fr(rng);

    let sigma_1_dash = util::mul_g1_fr(*sigma_1, &r);
    let sigma_2_dash = util::mul_g1_fr(*sigma_2, &r);

    let s_id = util::gen_random_fr(rng);
    let s_a_dash = util::gen_random_fr(rng);

    let p1 = util::do_pairing(
        &util::mul_g1_fr(sigma_1_dash, &s_id).into_affine(),
        &Y_id.into_affine(),
    );
    let p2 = util::do_pairing(
        &util::mul_g1_fr(sigma_1_dash, &s_a_dash).into_affine(),
        &Y_K1.into_affine(),
    );

    let u = util::mul_fq12_fq12(p1, p2);

    let c = util::combine_to_fr(
        &u,
        &epoch_fr,
        &m,
        &sigma_1_dash,
        &sigma_2_dash,
        &X2,
        &Y_epoch,
        &Y_id,
        &Y_K1,
    );

    let vid = util::minus_fr_fr(s_id, &util::mul_fr_fr(c, &id_fr));
    let va_dash = util::minus_fr_fr(s_a_dash, &util::mul_fr_fr(c, &a_dash));

    let v = (vid, va_dash);

    let pie = (c, v);

    let token = (sigma_1_dash, sigma_2_dash, pie);

    // Output the results
    println!("{}", { "\nAUTH......\n" });
    // util::print_g1("sigma_1_dash", &sigma_1_dash);
    // util::print_g1("sigma_2_dash", &sigma_2_dash);
    // println!("pie: {:?}\n", pie);
    token
}

pub fn Vf(
    sigma_1_dash: &G1,
    sigma_2_dash: &G1,
    pie: &(Fr, (Fr, Fr)),
    X2: &G2,
    Y_epoch: &G2,
    Y_id: &G2,
    Y_K1: &G2,
    m: u128,
    g2: &G2,
    epoch: &u128,
) -> bool {
    let (c, v) = pie; // Destructure the tuple into its components

    let (vid, va_dash) = v;

    let epoch_fr = util::int_to_fr(epoch);

    let p1 = util::do_pairing(
        &util::mul_g1_fr(*sigma_1_dash, &vid).into_affine(),
        &Y_id.into_affine(),
    );

    let p2 = util::do_pairing(
        &util::mul_g1_fr(*sigma_1_dash, &va_dash).into_affine(),
        &Y_K1.into_affine(),
    );

    let p3 = util::do_pairing(
        &util::mul_g1_fr(*sigma_2_dash, &c).into_affine(),
        &g2.into_affine(),
    );

    // let inv: u128 = -1;
    let mut XY_inverse = util::mul_g2_fr(*X2, &util::int_to_fr_negate(&1));

    let mut epoch_neg = epoch_fr.clone();
    epoch_neg.negate();
    XY_inverse = util::add_g2_g2(XY_inverse, util::mul_g2_fr(*Y_epoch, &epoch_neg));

    let p4 = util::do_pairing(
        &util::mul_g1_fr(*sigma_1_dash, &c).into_affine(),
        &XY_inverse.into_affine(),
    );

    let u1 = util::mul_fq12_fq12(p1, util::mul_fq12_fq12(p2, util::mul_fq12_fq12(p3, p4)));

    // println!("u1: {:?}\n", u1);

    let c1 = util::combine_to_fr(
        &u1,
        &epoch_fr,
        &m,
        &sigma_1_dash,
        &sigma_2_dash,
        &X2,
        &Y_epoch,
        &Y_id,
        &Y_K1,
    );

    println!("{}", { "\nVF......\n" });

    util::print_fr("c", c);
    util::print_fr("c1", &c1);
    // util::print_fr("c2", &c2);

    c == &c1
}
