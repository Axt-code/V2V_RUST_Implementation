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
    Kp: &GenericArray<u8, <Aes128GcmSiv as Aead>::NonceSize>,
    payload: &str,
) -> Vec<u8> {
    let payload_bytes = payload.as_bytes();
    cipher
        .encrypt(Kp, payload_bytes.as_ref())
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
