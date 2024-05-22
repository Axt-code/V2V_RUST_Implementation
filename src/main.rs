extern crate aes_gcm_siv;
extern crate pairing;
extern crate rand;
extern crate sha2;

use std::collections::HashSet;

use rand::{SeedableRng, XorShiftRng};

use crate::BLS::bls_verify;

mod BLS;
mod DAE;
mod PKE;
mod SE;
mod util;

// V->Vehicle
// vid1->10
// E->Enrollment Authority

fn main() {
    // Enroll.V <=> Enroll.E
    let (E_pk, E_sk) = BLS::bls_key_gen();

    //1. Enroll.V(pk ℰ , 𝒱):
    let vid1 = 10;
    let (V_vk, V_sk) = BLS::bls_key_gen();

    //2. Enroll.E(sk ℰ , st ℰ , 𝒱) upon receiving (𝒱, vk 𝒱 ):
    let mut sete: HashSet<u128> = HashSet::new();

    // sete.insert(10);  to test
    let signature_e = BLS::bls_sign(&E_sk, vid1, V_vk, &mut sete);
    if let Some(signature) = &signature_e {
        println!("Signing Successful");
    } else {
        println!("Signing Fails");
    }

    // 3. Enroll.V upon receiving 𝜎ℰ from ℰ:
    let verify;
    if let Some(signature) = &signature_e {
        verify = bls_verify(&E_pk, vid1, V_vk, signature.clone());
        println!("Verification Successful: {:?}", verify);
    } else {
        println!("Verification Skipped: Signature is None");
    }
}
