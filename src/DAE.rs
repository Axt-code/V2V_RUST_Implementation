extern crate aes_gcm_siv;
extern crate rand;
extern crate sha2;

use aes_gcm_siv::aead::Payload;
use aes_gcm_siv::aead::{generic_array::GenericArray, Aead, NewAead};
use aes_gcm_siv::Aes128GcmSiv; // AES-256-GCM-SIV
use generic_array::typenum::U12;
use rand::Rng;
use sha2::digest::generic_array;
use sha2::{Digest, Sha256};

pub fn generate_key() -> GenericArray<u8, <Aes128GcmSiv as NewAead>::KeySize> {
    let mut rng = rand::thread_rng();
    let key: [u8; 16] = rng.gen();
    GenericArray::clone_from_slice(&key)
}

// Function to encrypt a message
pub fn encrypt(
    cipher: &Aes128GcmSiv,
    nonce: &GenericArray<u8, <Aes128GcmSiv as Aead>::NonceSize>,
    Payload: &str,
) -> Vec<u8> {
    let Payload_bytes = Payload.as_bytes();
    cipher
        .encrypt(nonce, Payload_bytes.as_ref())
        .expect("encryption failure!")
}

// Function to generate an IV from a key and a cipher
pub fn generate_iv(
    kp: GenericArray<u8, <Aes128GcmSiv as Aead>::NonceSize>,
    cipher: Vec<u8>,
) -> GenericArray<u8, generic_array::typenum::U12> {
    let mut hasher = Sha256::new();
    hasher.update(&kp);
    hasher.update(&cipher);

    let result = hasher.finalize();
    GenericArray::clone_from_slice(&result[0..12])
}
