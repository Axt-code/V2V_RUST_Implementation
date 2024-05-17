extern crate aes_gcm_siv;
extern crate rand;

use aes_gcm_siv::aead::{generic_array::GenericArray, Aead, NewAead};
use aes_gcm_siv::Aes128GcmSiv; // AES-256-GCM-SIV
use rand::Rng;

pub fn generate_key() -> GenericArray<u8, <Aes128GcmSiv as NewAead>::KeySize> {
    let mut rng = rand::thread_rng();
    let key: [u8; 16] = rng.gen();
    GenericArray::clone_from_slice(&key)
}

// Function to encrypt a message
pub fn encrypt(
    cipher: &Aes128GcmSiv,
    nonce: &GenericArray<u8, <Aes128GcmSiv as Aead>::NonceSize>,
    plaintext: &[u8],
) -> Vec<u8> {
    cipher
        .encrypt(nonce, plaintext.as_ref())
        .expect("encryption failure!")
}

// Function to decrypt a message
pub fn decrypt(
    cipher: &Aes128GcmSiv,
    nonce: &GenericArray<u8, <Aes128GcmSiv as Aead>::NonceSize>,
    ciphertext: &[u8],
) -> Vec<u8> {
    cipher
        .decrypt(nonce, ciphertext.as_ref())
        .expect("decryption failure!")
}

pub fn key_to_int(key: &GenericArray<u8, <Aes128GcmSiv as NewAead>::KeySize>) -> u128 {
    let mut int_key = 0u128;
    for (i, byte) in key.iter().enumerate() {
        int_key |= (*byte as u128) << (i * 8);
    }
    int_key
}

pub fn int_to_key(int_key: u128) -> GenericArray<u8, <Aes128GcmSiv as NewAead>::KeySize> {
    let mut key = [0u8; 16];
    for i in 0..16 {
        key[i] = (int_key >> (i * 8)) as u8;
    }
    GenericArray::clone_from_slice(&key)
}
