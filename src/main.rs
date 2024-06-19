use std::collections::VecDeque;

use pairing::{bls12_381::Fr, CurveProjective};
use rand::{SeedableRng, XorShiftRng};
use util::{gen_random_fr, int_to_fr};
use PS::{keygen, sign, verify, GenCommitment, Unblind};

mod PS;
mod util;

extern crate aes_gcm_siv;
extern crate pairing;
extern crate rand;
extern crate sha2;

fn main() {
    let k = 3;
    let mut rng = XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

    let (PS_sk, PS_pk) = keygen(&mut rng, k);

    let mut message_q: VecDeque<Fr> = VecDeque::new();
    message_q.push_back(gen_random_fr(&mut rng));
    message_q.push_back(gen_random_fr(&mut rng));
    message_q.push_back(gen_random_fr(&mut rng));

    let (commit, (c, sr, s_tr), r) = GenCommitment(&mut rng, &PS_pk, &mut message_q, 3);

    // Output the result
    let epoch = int_to_fr(&10);
    let sigma = sign(
        &mut rng,
        (c, sr, s_tr),
        commit,
        epoch,
        PS_sk,
        &PS_pk,
        k.into(),
    );

    // println!("sigma: {:?}", sigma);

    let sigma_22 = Unblind(&mut sigma.unwrap(), r);

    let (_, sigma_2) = sigma_22;

    println!("sigma_2 in main: {:?}\n", { sigma_2.into_affine() });

    let verified = verify(sigma_22, &mut message_q, epoch, &PS_pk, 3);
    println!("verified: {:?}", verified);
}
