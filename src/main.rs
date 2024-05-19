extern crate aes_gcm_siv;
extern crate pairing;
extern crate rand;
extern crate sha2;

use aes_gcm_siv::aead::{generic_array::GenericArray, Aead, NewAead};

use aes_gcm_siv::{Aes128GcmSiv, AesGcmSiv};
use bit_vec::BitVec;
use pairing::bls12_381::{G2Affine, G2};
use pairing::{CurveAffine, CurveProjective};
use rand::{SeedableRng, XorShiftRng};
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant}; // AES-256-GCM-SIV

mod BLS;
mod DAE;
mod PKE;
mod SE;
mod util;

fn main() {
    let mut rng = XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
}
