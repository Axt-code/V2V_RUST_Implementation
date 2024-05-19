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

mod BLS;
mod util;
mod SE;
mod PKE;


fn main() {
    let mut rng = XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

    // PS signatures
    /* 
    // PS.KG
    let attribute = 10;
    let (g2, x, yk, yk1, X2, YK, YK1) = PS::keygen(&mut rng, attribute);

    //PS.Sign

    let (m_dash, h, messages, sigma_2) = PS::sign(&mut rng, &g2, &x, &yk, &yk1, attribute);

    //PS.Verify
    let result = PS::verify(
        &h, &m_dash, &messages, &sigma_2, &X2, &YK, &YK1, &g2, attribute,
    );
    println!("Verification result: {:?}", result);
    

    let (vk, sk) = BLS::bls_key_gen(&mut rng);
    println!("vk = {} and sk = {}",vk, sk);
    
    
    let value = 12345;
    let sign = BLS::bls_sign(&sk, value);
    println!("Sign in G1: {:?}", sign);

    let ver = BLS::bls_verify(&vk, value, sign);
    println!("Verified {:?}", ver);



    let key = SE::generate_key(); // Generate a new key
    let cipher = Aes128GcmSiv::new(&key);

    let nonce = GenericArray::from_slice(&[0u8; 12]); // 96-bit nonce
    let plaintext = b"plaintext message";

    // Encrypt
    let ciphertext = SE::encrypt(&cipher, &nonce, plaintext);

    let int_key = SE::key_to_int(&key);
    let key_again = SE::int_to_key(int_key);
    let cipher_again = Aes128GcmSiv::new(&key_again);

    // Decrypt
    let decrypted_text = SE::decrypt(&cipher_again, &nonce, &ciphertext);

    let decrypted_string = String::from_utf8(decrypted_text).expect("Found invalid UTF-8");
    println!("Decrypted text: {}", decrypted_string);

    assert_eq!(key, key_again);
    */

    let (p1, p2) = PKE::pke_key_gen(&mut rng);
    println!("plaintext{}", p1);

    let (pk, sk) = PKE::pke_key_gen(&mut rng);
    println!("Key{}", pk);

    let cipher = PKE::pke_encrypt(&mut rng, pk, p1);
    let plain = PKE::pke_decrypt(&sk, cipher);

    println!("plaintext {}", plain);


        
}
