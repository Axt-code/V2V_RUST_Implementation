extern crate blake2;
extern crate byteorder;
extern crate pairing;
extern crate rand;

use pairing::bls12_381::*;
use pairing::*;
use rand::XorShiftRng;
use std::collections::VecDeque;

pub fn keygen(rng: &mut XorShiftRng)->{

    let g=G1::One();

}