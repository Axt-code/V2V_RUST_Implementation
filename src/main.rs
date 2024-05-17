extern crate pairing;
extern crate rand;

use pairing::bls12_381::*;
use pairing::*;
use rand::{SeedableRng, XorShiftRng};
use std::collections::HashMap;
use std::time::{Duration, Instant};

mod DGSA;
mod util;

fn main() {
    let mut rng = XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

    // PS signatures

    // DGSA.KG

    let attribute = 1;
    let (g2, x2, y_id, y_epoch, y_k1, X2, Y_id, Y_epoch, Y_K1) = DGSA::keygen(&mut rng, attribute);
    let mut set: HashMap<(u128, u128), Fr> = HashMap::new();

    //DGSA.issue_i
    let id: u128 = 10;
    let epoch: u128 = 1234;
    let mut sigma: Option<(Fr, G1, G1)> = None;

    match DGSA::issue_i(
        &mut rng, &g2, &x2, &y_id, &y_epoch, &y_k1, &id, &epoch, &mut set,
    ) {
        Some((sigma_i, updated_set)) => {
            sigma = Some(sigma_i);
            println!("Issue successful.\n");
            // println!("sigma: {:?}\n", sigma);
            println!("Updated set: {:?}\n", updated_set);
        }
        None => {
            println!("The key (id, epoch) was already present in the map. Exiting function early.");
        }
    }

    //DGSA.issue_i
    let cred: Option<(u128, u128, (Fr, G1, G1))>;

    if let Some(s) = sigma {
        let result = DGSA::issue_u(&s, &id, &epoch, &X2, &Y_id, &Y_epoch, &Y_K1, &g2);
        println!("Verification result: {:?}", result);
        if result {
            cred = Some((id.clone(), epoch.clone(), s));
            println!("\nVerification Successfull Cred generated");
        } else {
            println!("Verification Failed\n");
        }
    } else {
        println!("Error: sigma was not successfully generated.");
    }

    //Auth
    let m = 123;
    let mut sigma_1_dash: Option<G1> = None;
    let mut sigma_2_dash: Option<G1> = None;
    let mut pie = (Fr::zero(), (Fr::zero(), Fr::zero())); // Assuming Fr::zero() gives a default zero value for Fr

    if let Some(s) = sigma {
        let (s1_dash, s2_dash, p) = DGSA::auth(
            &mut rng, &m, &s, // Unwrap the Fr component from sigma tuple
            &id, &epoch, &X2, &Y_id, &Y_epoch, &Y_K1, &g2,
        );
        sigma_1_dash = Some(s1_dash);
        sigma_2_dash = Some(s2_dash);
        pie = p;
        println!("Token Generated");
    } else {
        println!("Error: sigma was not successfully generated.");
    }

    //Vf
    let result = if let (Some(sigma_1_dash), Some(sigma_2_dash)) = (sigma_1_dash, sigma_2_dash) {
        DGSA::Vf(
            &sigma_1_dash,
            &sigma_2_dash,
            &pie,
            &X2,
            &Y_epoch,
            &Y_id,
            &Y_K1,
            m,
            &g2,
            &epoch,
        )
    } else {
        false
    };

    if result {
        println!("Verification Success");
    } else {
        println!("Verification Failed");
    }
}
