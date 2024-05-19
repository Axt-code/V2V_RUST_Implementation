extern crate blake2;
extern crate byteorder;
extern crate pairing;
extern crate rand;

use pairing::bls12_381::{Fr, G2};
use pairing::CurveProjective;
use rand::XorShiftRng;

mod util;

// Key generation
pub fn pke_key_gen(rng: &mut XorShiftRng) -> (G2, Fr) {
    let g2 = G2::one();

    //let mut rng = OsRng::new().unwrap();

    let sk = util::gen_random_fr(rng);
    let vk = util::mul_g2_fr(g2, &sk);
    (vk, sk)
}

pub fn pke_encrypt(rng: &mut XorShiftRng, pk: G2, plaintext: G2) -> (G2, G2) {
    let g = G2::one();
    let k = util::gen_random_fr(rng);
    let c_1 = util::mul_g2_fr(g, &k);
    let c_2 = util::add_g2_g2(util::mul_g2_fr(pk, &k), plaintext);
    (c_1, c_2)
}

pub fn pke_decrypt(sk: &Fr, ciphertext: (G2, G2)) -> G2 {
    let (c_1, c_2) = ciphertext;
    let c_1_sk = util::mul_g2_fr(c_1, &sk);
    let plaintext = util::add_g2_g2(c_2, util::g2_neg(c_1_sk));
    plaintext
}

// pub fn g2_to_generic_array(g2_element: G2) -> GenericArray<u8, <Aes128GcmSiv as NewAead>::KeySize> {
//     // Serialize the G2 element to bytes
//     let serialized = g2_element.to_compressed(); // Assuming `to_compressed()` gives us a 48-byte array

//     // Ensure the serialized data fits into the key size
//     // For AES128GcmSiv, the key size is 16 bytes
//     // We will use the first 16 bytes of the serialized output
//     let key_size = <Aes128GcmSiv as NewAead>::KeySize::to_usize();

//     // Create a generic array from the first 16 bytes
//     let key_bytes: [u8; 16] = serialized[..16]
//         .try_into()
//         .expect("Slice with incorrect length");

//     GenericArray::from_slice(&key_bytes).clone()
// }
