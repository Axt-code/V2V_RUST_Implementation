extern crate aes_gcm_siv;
extern crate pairing;
extern crate rand;
extern crate sha2;

use pairing::{bls12_381::*, CurveProjective};
use rand::{SeedableRng, XorShiftRng};
use std::collections::{HashMap, HashSet};

use crate::{
    util::{combine_vec_u128, g2_to_vec_u128, gen_random_fr, mul_g1_fr},
    DAE::decrypt,
};

mod BLS;
mod DAE;
mod DGSA;
mod PKE;
mod SE;
mod util;

// V->Vehicle
// vid1->10
// E->Enrollment Authority
// epoch->100

// v_pk

fn get_signature_e(e_sk: &Fr, vid1: u128, v_pk: &G2, sete: &mut HashSet<u128>) -> Option<G1> {
    let signature_e = BLS::bls_sign(&e_sk, vid1, &v_pk, sete);
    if let Some(sig) = &signature_e {
        println!("Signing Successful for vehicle {}\n", vid1);
    } else {
        println!("Signing Failed for vehicle {}\n", vid1);
    }
    signature_e
}

fn verify_signature_e(
    e_pk: &G2,
    vid: u128,
    v_pk: &G2,
    signature_e: &G1,
    v_sk: &Fr,
) -> Option<(Fr, G2, G1)> {
    if BLS::bls_verify(e_pk, vid, *v_pk, signature_e) {
        let cred = (v_sk.clone(), v_pk.clone(), signature_e.clone());
        Some(cred)
    } else {
        None
    }
}

fn verify_authorization(
    e_pk: &G2,
    vid: u128,
    v_pk: &G2,
    signature_e: &G1,
    epoch: u128,
    signature_v: &G1,
) -> bool {
    let check_vid_vpk = BLS::bls_verify(e_pk, vid, *v_pk, signature_e);
    let check_e = BLS::bls_verify_for_e(v_pk, epoch, signature_v);

    check_e && check_vid_vpk
}

fn perform_dgsa_issuance_and_verification(
    rng: &mut XorShiftRng,
    g2: &G2,
    i_sk_x2: &Fr,
    i_sk_yid: &Fr,
    i_sk_epoch: &Fr,
    i_sk_k1: &Fr,
    vid: &u128,
    epoch: &u128,
    v_pk: &G2,
    set: &mut HashMap<(u128, u128), Fr>,
    i_pk_X2: &G2,
    i_pk_id: &G2,
    i_pk_epoch: &G2,
    i_pk_k1: &G2,
) -> Option<(u128, u128, (Fr, G1, G1))> {
    if let Some(((a_dash_v, h_v, sigma_2_v), updated_set)) = DGSA::issue_i(
        rng, g2, i_sk_x2, i_sk_yid, i_sk_epoch, i_sk_k1, vid, epoch, v_pk, set,
    ) {
        *set = updated_set;
        let sigma_v = (a_dash_v.clone(), h_v.clone(), sigma_2_v.clone());
        // println!("DGSA Issuance Successful");

        // Perform DGSA verification
        let result = DGSA::issue_v(
            &sigma_v, vid, epoch, *v_pk, i_pk_X2, i_pk_id, i_pk_epoch, i_pk_k1, g2,
        );
        // println!("Verification result: {:?}", result);

        if result {
            Some((vid.clone(), epoch.clone(), sigma_v))
        } else {
            println!("Verification Failed\n");
            None
        }
    } else {
        println!("DGSA Issuance Failed: Key (id, epoch) is present in the map");
        None
    }
}

fn process_encryption(zpk_encryption_c1: G2, zpk_encryption_c2: G2) -> u128 {
    let zpk_encrypt_1_vec_u128 = g2_to_vec_u128(zpk_encryption_c1);
    let zpk_encrypt_2_vec_u128 = g2_to_vec_u128(zpk_encryption_c2);

    let mut concatenated_vec = zpk_encrypt_1_vec_u128.clone();
    concatenated_vec.extend(zpk_encrypt_2_vec_u128);

    // Combine the concatenated vector into a single u128
    let zpk_encrypt_u128 = combine_vec_u128(concatenated_vec);

    zpk_encrypt_u128
}

fn main() {
    let mut rng = XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

    // Enroll.V <=> Enroll.E
    let (e_pk, e_sk) = BLS::bls_key_gen(&mut rng);
    let mut set_e: HashSet<u128> = HashSet::new();

    //1. Enroll.V(pk ℰ , 𝒱):
    let vid = 10;
    let (v_pk, v_sk) = BLS::bls_key_gen(&mut rng);

    let wid = 20;
    let (w_pk, w_sk) = BLS::bls_key_gen(&mut rng);

    //2. Enroll.E(sk ℰ , st ℰ , 𝒱) upon receiving (𝒱, vk 𝒱 ):

    let signature_e_1 = get_signature_e(&e_sk, vid, &v_pk, &mut set_e);
    let signature_e_2 = get_signature_e(&e_sk, wid, &w_pk, &mut set_e);

    // 3. Enroll.V upon receiving 𝜎ℰ from ℰ:
    let mut cred_l_v: Option<(Fr, G2, G1)> = None;
    let mut cred_l_w: Option<(Fr, G2, G1)> = None;

    match signature_e_1 {
        Some(sig) => {
            // Call verify_signature_e to verify the generated signature
            cred_l_v = match verify_signature_e(&e_pk, vid, &v_pk, &sig, &v_sk) {
                Some(cred) => {
                    println!("Verification Successful for vehicle v\n");
                    Some(cred)
                }
                None => {
                    println!("Verification Failed for vehicle v\n");
                    None
                }
            }
        }
        None => println!("Signing Failed for vehicle v\n"),
    }

    // if let Some(cred) = cred1 {
    //     println!("Credential: {:?}", cred);
    // }

    match signature_e_2 {
        Some(sig) => {
            // Call verify_signature_e to verify the generated signature
            cred_l_w = match verify_signature_e(&e_pk, wid, &w_pk, &sig, &w_sk) {
                Some(cred) => {
                    println!("Verification Successful for vehicle w\n");
                    Some(cred)
                }
                None => {
                    println!("Verification Failed for vehicle w\n");
                    None
                }
            }
        }
        None => println!("Signing Failed for vehicle w\n"),
    }

    // Authorize.V <=> Authorize.I
    // 1. Authorize.V(cert 𝒱 , e, pk ℐ )
    let epoch = 100;
    let signature_v = BLS::bls_sign_for_e(&v_sk, epoch);
    let signature_w = BLS::bls_sign_for_e(&w_sk, epoch);

    // // 2. Authorize.I(sk 𝐼 , st ℐ , 𝒱, e, pk ℰ )
    if verify_authorization(
        &e_pk,
        vid,
        &v_pk,
        &signature_e_1.unwrap(),
        epoch,
        &signature_v,
    ) {
        println!("Authorization verified for vehicle v\n");
    } else {
        println!("Authorization failed for vehicle v\n");
    }

    if verify_authorization(
        &e_pk,
        wid,
        &w_pk,
        &signature_e_2.unwrap(),
        epoch,
        &signature_w,
    ) {
        println!("Authorization verified for vehicle w\n");
    } else {
        println!("Authorization failed for vehicle w\n");
    }

    // DGSA Key generation.
    let attribute = 1;
    let (g2, i_sk_x2, i_sk_yid, i_sk_epoch, i_sk_k1, i_pk_X2, i_pk_id, i_pk_epoch, i_pk_k1) =
        DGSA::keygen(&mut rng, attribute);
    let mut set_i: HashMap<(u128, u128), Fr> = HashMap::new();

    // // DGSA ℐ and 𝒱 run the issuance protocol of DGSA
    let cred_s_v = perform_dgsa_issuance_and_verification(
        &mut rng,
        &g2,
        &i_sk_x2,
        &i_sk_yid,
        &i_sk_epoch,
        &i_sk_k1,
        &vid,
        &epoch,
        &v_pk,
        &mut set_i,
        &i_pk_X2,
        &i_pk_id,
        &i_pk_epoch,
        &i_pk_k1,
    );

    if let Some(cred) = cred_s_v {
        println!("\nVerification Success Cred is created for vehicle v\n",);
    }

    let cred_s_w = perform_dgsa_issuance_and_verification(
        &mut rng,
        &g2,
        &i_sk_x2,
        &i_sk_yid,
        &i_sk_epoch,
        &i_sk_k1,
        &wid,
        &epoch,
        &w_pk,
        &mut set_i,
        &i_pk_X2,
        &i_pk_id,
        &i_pk_epoch,
        &i_pk_k1,
    );

    if let Some(cred) = cred_s_w {
        println!("\nVerification Success Cred is created for vehicle w\n",);
    }

    //ENTER
    //1. 𝒱 running Enter.V(cred 𝒱 , 𝐿𝐾 , pk ℐ , 𝑧, 𝑡, requester )
    let (v_pke_pk, v_pke_sk) = PKE::pke_key_gen(&mut rng);

    let (cred_vid, cred_vepoch, sigma_v) = cred_s_v.unwrap();
    let v_pke_pk_u128_vec = util::g2_to_vec_u128(v_pke_pk);
    let v_pke_pk_u128 = util::combine_vec_u128(v_pke_pk_u128_vec);

    let m_v = cred_vid + cred_vepoch + v_pke_pk_u128;

    let token_v = DGSA::auth(
        &mut rng,
        &m_v,
        &sigma_v,
        &cred_vid,
        &cred_vepoch,
        &i_pk_X2,
        &i_pk_id,
        &i_pk_epoch,
        &i_pk_k1,
        &g2,
    );

    // println!("Token: is generated for vehicle v\n",);

    //FOR vehicle w

    //2. 𝒲𝑖 running Enter.W(cred 𝒲𝑖 , 𝐿𝐾𝑖 , pk ℐ , 𝑧, 𝑡, responder 𝑖 ) upon receiving (𝑧,𝑡, ek , tok 𝒱 ) from a vehicle 𝒱:

    let (sigma_v1_dash, sigma_v2_dash, pie_v) = token_v;
    let is_valid_w = DGSA::Vf(
        &sigma_v1_dash,
        &sigma_v2_dash,
        &pie_v,
        &i_pk_X2,
        &i_pk_epoch,
        &i_pk_id,
        &i_pk_k1,
        m_v,
        &g2,
        &cred_vepoch,
    );

    println!("For vehicke v token is valid: {}\n", is_valid_w);

    let z1 = 1000;

    // generating secret key for Zone.
    let z1_sk = gen_random_fr(&mut rng);
    let g = G2::one();
    let z1_sk_g2_w = util::mul_g2_fr(g, &z1_sk);

    let Zpk_w = DAE::generate_key(z1_sk_g2_w);
    // println!("zpk_w {:?}\n", Zpk_w);
    let (zpk_encrypted_c1, zpk_encrypted_c2) = PKE::pke_encrypt(&mut rng, v_pke_pk, z1_sk_g2_w);

    let zpk_encrypt_ct = process_encryption(zpk_encrypted_c1, zpk_encrypted_c2);

    let (cred_wid, cred_wepoch, sigma_w) = cred_s_w.unwrap();
    let m_w = cred_wid + cred_wepoch + zpk_encrypt_ct;

    let token_w = DGSA::auth(
        &mut rng,
        &m_w,
        &sigma_w,
        &cred_wid,
        &cred_wepoch,
        &i_pk_X2,
        &i_pk_id,
        &i_pk_epoch,
        &i_pk_k1,
        &g2,
    );

    // 3.Vehicle 𝒱 upon receiving (𝑧, 𝑡, ct, tok 𝒲 ) from a vehicle 𝒲𝑖 :

    let (sigma_w1_dash, sigma_w2_dash, pie_w) = token_w;
    let is_valid_w = DGSA::Vf(
        &sigma_w1_dash,
        &sigma_w2_dash,
        &pie_w,
        &i_pk_X2,
        &i_pk_epoch,
        &i_pk_id,
        &i_pk_k1,
        m_w,
        &g2,
        &cred_wepoch,
    );

    println!("For vehicke w token is valid: {}\n", is_valid_w);

    let z1_sk_g2_v = PKE::pke_decrypt(&v_pke_sk, (zpk_encrypted_c1, zpk_encrypted_c2));
    let Zpk_v = DAE::generate_key(z1_sk_g2_v);
    // println!("zpk_v {:?}\n", Zpk_v);

    ////Sending and Receiving Payloads.

    // Send(𝐿𝐾 , P , 𝑌 ⊆ 𝑍, 𝑡) :
    let kp = SE::generate_key();
    // println!("before encryption kp {:?}\n", kp);
    let payload_v = "12345678";
    println!("payload_v: {}\n", payload_v);
    let (cipher_payload_v, nonce_payload_v) = SE::encrypt(kp, payload_v);

    // let bytes: Vec<u8> = kp.as_slice().to_vec();
    // println!("bytes {:?}", bytes);

    let (cipher_kp_v, iv_kp_v) = DAE::encrypt(Zpk_v, kp);

    let message_v_to_w = (cipher_payload_v, nonce_payload_v, cipher_kp_v, iv_kp_v);

    println!("size of payload {}\n", payload_v.len());
    let size_cipher_payload_v = message_v_to_w.0.len();
    let size_nonce_payload_v = message_v_to_w.1.len();
    let size_cipher_kp_v = message_v_to_w.2.len();
    let size_iv_kp_v = message_v_to_w.3.len();

    // Calculate and print the total size
    let total_size = size_cipher_payload_v + size_nonce_payload_v + size_cipher_kp_v + size_iv_kp_v;
    println!("total size of message_v_to_w {}\n", total_size);

    let (cipher_payload_w, nonce_payload_w, cipher_kp_w, iv_kp_w) = message_v_to_w;
    let decrypted_kp = DAE::decrypt(Zpk_v, (iv_kp_w, cipher_kp_w));

    // println!("decrypted_kp {:?}\n", decrypted_kp);

    let payload_w = SE::decrypt(decrypted_kp, &nonce_payload_w, &cipher_payload_w);
    println!("payload_w: {}", payload_w);
}
