extern crate aes_gcm_siv;
extern crate pairing;
extern crate rand;
extern crate sha2;

use aes_gcm_siv::aead::{generic_array::GenericArray, Aead, NewAead};

use aes_gcm_siv::{Aes128GcmSiv, AesGcmSiv};
use rand::{SeedableRng, XorShiftRng};
use sha2::digest::consts::U12;
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant}; // AES-256-GCM-SIV

mod DAE;
mod DGSA;
mod SE;
mod util;

fn main() {
    //Generate Kp
    let Kp = DAE::generate_key();
    println!("kp: {:?}", Kp);

    let payload = "Hello Ashish";
    let key1 = Aes128GcmSiv::new(&Kp);
    let nonce = GenericArray::from_slice(&[0u8; 12]);
    let cipher_text = DAE::encrypt(&key1, &nonce, &payload);
    println!("cipher: {:?}", cipher_text);

    // let decrypted_text = SE::decrypt(&key1, &nonce, &cipher_text);

    // let decrypted_string = String::from_utf8(decrypted_text).expect("Found invalid UTF-8");
    // println!("Decrypted text: {}", decrypted_string);

    let Kzt = DAE::generate_key();
    println!("kp: {:?}", Kzt);
}
