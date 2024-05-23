extern crate aes_gcm_siv;
extern crate pairing;
extern crate rand;
extern crate sha2;

use std::collections::HashSet;

use BLS::bls_verify_for_e;

use crate::BLS::bls_verify;

mod BLS;
mod DAE;
mod PKE;
mod SE;
mod util;

// V->Vehicle
// vid1->10
// E->Enrollment Authority
// e->100

fn main() {
    // Enroll.V <=> Enroll.E
    let (e_pk, e_sk) = BLS::bls_key_gen();

    //1. Enroll.V(pk ℰ , 𝒱):
    let vid1 = 10;
    let (v_pk, v_sk) = BLS::bls_key_gen();

    //2. Enroll.E(sk ℰ , st ℰ , 𝒱) upon receiving (𝒱, vk 𝒱 ):
    let mut sete: HashSet<u128> = HashSet::new();

    // sete.insert(10);  to test
    let signature_e = BLS::bls_sign(&e_sk, vid1, &v_pk, &mut sete);
    if let Some(sig) = &signature_e {
        println!("Signing Successful");
    } else {
        println!("Signing Fails");
    }

    // 3. Enroll.V upon receiving 𝜎ℰ from ℰ:
    let cred;
    if let Some(signature) = &signature_e {
        let verify = bls_verify(&e_pk, vid1, v_pk, signature);
        if verify {
            cred = (v_sk, v_pk, signature_e);
            println!("Verification Successful:");
            // println!("Cred = {:?}", cred);
        } else {
            {
                println!("Verification Failed");
            }
        }
    } else {
        println!("Verification Skipped: Signature is None");
    }

    //Authorize.V <=> Authorize.I
    // 1. Authorize.V(cert 𝒱 , e, pk ℐ )
    let e = 100;
    let signature_v = BLS::bls_sign_for_e(&v_sk, e);

    // 2. Authorize.I(sk 𝐼 , st ℐ , 𝒱, e, pk ℰ )
    let check_e = bls_verify_for_e(&v_pk, e, signature_v.clone());
    if check_e {
        println!("verified");
    }
}
