use std::simd::{LaneCount, SupportedLaneCount};
use std::slice;
use rand::distributions::{Distribution, Uniform};
use tiny_keccak::{Hasher, Xof};
use crate::{f4, tree, seed_len, hash_len, dim, n, m, tau, Level};
use crate::shake::{get_shake, get_commit, Domain, Salt, ShakeRng};

type Seed<const L: Level> = [u8; seed_len(L)];
type Hash<const L: Level> = [u8; hash_len(L)];
type Vector<const L: Level> = f4::Vector<{2*dim(L)}>;
type Mq<const L: Level> = f4::Mq<{dim(L)}>;
type PartyTree<const L: Level> = tree::SeedTree<{n(L)}, {seed_len(L)}>;
type SetupTree<const L: Level> = tree::SeedTree<{m(L)}, {seed_len(L)}>;
type CommitTree<const L: Level> = tree::MerkleTree<{m(L)}, {hash_len(L)}>;

#[derive(Debug)]
pub struct VerifyError;

pub struct PublicKey<const L: Level>(Vector<L>, Seed<L>) where
    LaneCount<{f4::lanes(dim(L))}>: SupportedLaneCount,
    LaneCount<{f4::lanes(2*dim(L))}>: SupportedLaneCount,
    [(); seed_len(L)]:;

pub struct SecretKey<const L: Level>(Vector<L>, Seed<L>, PublicKey<L>) where
    LaneCount<{f4::lanes(dim(L))}>: SupportedLaneCount,
    LaneCount<{f4::lanes(2*dim(L))}>: SupportedLaneCount,
    [(); seed_len(L)]:;

impl<const L: Level> PublicKey<L> where
    LaneCount<{f4::lanes(dim(L))}>: SupportedLaneCount,
    LaneCount<{f4::lanes(2*dim(L))}>: SupportedLaneCount,
    [(); hash_len(L)]:,
    [(); seed_len(L)]:,
    [(); 2*n(L)]:,
    [(); 2*m(L)]:,
{
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), VerifyError> {
        let mq = Mq::<L>::expand::<L>(&self.1);
        let mut shake = get_shake::<L>();
        shake.update(self.0.buf());
        shake.update(message);
        let salt = Salt::new(&shake);
        let (commit, witness) = signature.split_at(hash_len(L));
        let challenge = self.challenge(commit, salt);
        let (seeds, witness) = SetupTree::<L>::restore(
            &challenge.0,
            witness,
            salt.with_domain::<{Domain::SetupTree}>());
        let mut transcript = salt.with_domain::<{Domain::Transcript}>().shake();
        let mut coms = CommitTree::<L>::new();
        let mut witness = witness;
        for i in 0..m(L) {
            let salt = salt.with_setup(i);
            let hidden = challenge.1[i];
            let aux = if hidden < n(L) {
                let seeds;
                let aux_hidden;
                let masked_buf;
                (seeds, witness) = PartyTree::<L>::restore(
                    &challenge.1[i..i+1],
                    witness,
                    salt.with_domain::<{Domain::PartyTree}>());
                (aux_hidden, witness) = witness.split_at(hash_len(L));
                (masked_buf, witness) = witness.split_at(Vector::<L>::BYTES);
                let masked = Vector::<L>::from(masked_buf);
                let (mut shares, mut aux) = self.expand_seeds(&seeds, hidden, salt);
                if hidden != n(L) - 1 {
                    let correction_buf;
                    (correction_buf, witness) = witness.split_at(Vector::<L>::BYTES);
                    shares[n(L) - 1][1] = Vector::<L>::from(correction_buf);
                    aux[n(L) - 1] = self.commit_final(
                        &seeds[n(L) - 1], &shares[n(L) - 1][1], salt);
                }
                let com = self.verify_execute(&mq, &masked, shares, hidden, salt);
                coms[i].copy_from_slice(&com);
                aux[hidden].copy_from_slice(aux_hidden);
                aux
            } else {
                self.verify_setup(&mq, &seeds[i], salt)
            };
            transcript.update(unsafe {
                std::slice::from_raw_parts(
                    aux.as_ptr() as *const u8,
                    n(L)*hash_len(L))
            });
        }
        let (root, witness) = coms.restore(
            &challenge.0,
            witness,
            salt.with_domain::<{Domain::CommitTree}>());
        transcript.update(root);
        let new_commit = get_commit::<{hash_len(L)}>(transcript);
        if commit == new_commit && witness.is_empty() {
            Ok(())
        } else {
            Err(VerifyError)
        }
    }

    fn challenge(&self, commit: &[u8], salt: Salt) -> (Vec<usize>, [usize; m(L)]) {
        let mut shake = salt.with_domain::<{Domain::Challenge}>().shake();
        shake.update(commit);
        let mut rng = ShakeRng(shake);
        let party = Uniform::from(0..n(L));
        let setups = rand::seq::index::sample(&mut rng, m(L), tau(L));
        let mut parties = [usize::MAX; m(L)];
        for i in setups.iter() {
            parties[i] = party.sample(&mut rng);
        }
        (setups.into_vec(), parties)
    }

    fn verify_setup(&self, mq: &Mq<L>, seed: &[u8], salt: Salt) -> [Hash<L>; n(L)] {
        let (seeds, shares, mask, mut aux) = self.setup(seed, salt);
        let mut correction = mq.apply(&mask);
        for share in shares.iter().take(n(L) - 1) {
            correction ^= share[1];
        }
        aux[n(L) - 1] = self.commit_final(&seeds[n(L) - 1], &correction, salt);
        aux
    }

    fn verify_execute(
        &self, mq: &Mq<L>,
        masked: &Vector<L>,
        shares: [[Vector<L>; 2]; n(L)],
        hidden: usize,
        salt: Salt,
    ) -> Hash<L> {
        let (out, polar) = mq.apply_and_polar(masked);
        let mut msgs = [Vector::<L>::zero(); n(L)];
        msgs[hidden] = self.0 ^ out;
        for i in (0..n(L)).filter(|&i| i != hidden) {
            msgs[i] = polar.apply(&shares[i][0]) ^ shares[i][1];
            msgs[hidden] ^= msgs[i];
        }
        let mut shake = salt.with_domain::<{Domain::SimulateCommit}>().shake();
        for msg in msgs.iter() {
            shake.update(msg.buf());
        }
        get_commit(shake)
    }

    fn setup(
        &self, seed: &[u8], salt: Salt,
    ) -> (PartyTree<L>, [[Vector<L>; 2]; n(L)], Vector<L>, [Hash<L>; n(L)]) {
        let seeds = PartyTree::<L>::new(seed, salt.with_domain::<{Domain::PartyTree}>());
        let (shares, aux) = self.expand_seeds(&seeds, usize::MAX, salt);
        let mut mask = Vector::<L>::zero();
        for share in shares.iter() {
            mask ^= share[0];
        }
        (seeds, shares, mask, aux)
    }

    fn expand_seeds(
        &self, seeds: &PartyTree<L>, hidden: usize, salt: Salt,
    ) -> ([[Vector<L>; 2]; n(L)], [Hash<L>; n(L)]) {
        let mut shares = [[Vector::<L>::zero(); 2]; n(L)];
        let mut aux = [[0u8; hash_len(L)]; n(L)];
        for i in (0..n(L)).filter(|&i| i != hidden) {
            let salt = salt.with_party(i);
            if i != n(L) - 1 {
                (shares[i], aux[i]) = self.expand_and_commit(&seeds[i], salt);
            } else {
                shares[n(L) - 1][0] = self.expand_final(&seeds[n(L) - 1], salt);
            }
        }
        (shares, aux)
    }

    fn expand_and_commit(&self, seed: &[u8], salt: Salt) -> ([Vector<L>; 2], Hash<L>) {
        let mut share = [Vector::<L>::zero(); 2];
        let mut shake = salt.with_domain::<{Domain::SetupTape}>().shake();
        shake.update(seed);
        shake.squeeze(share[0].mut_buf());
        shake.squeeze(share[1].mut_buf());
        let mut shake = salt.with_domain::<{Domain::SetupCommit}>().shake();
        shake.update(seed);
        (share, get_commit(shake))
    }

    fn expand_final(&self, seed: &[u8], salt: Salt) -> Vector<L> {
        let mut share = Vector::<L>::zero();
        let mut shake = salt.with_domain::<{Domain::SetupTape}>().shake();
        shake.update(seed);
        shake.squeeze(share.mut_buf());
        share
    }

    fn commit_final(&self, seed: &[u8], correction: &Vector<L>, salt: Salt) -> Hash<L> {
        let mut shake = salt.with_party(n(L) - 1).with_domain::<{Domain::SetupCommit}>().shake();
        shake.update(seed);
        shake.update(correction.buf());
        get_commit(shake)
    }
}

impl<const L: Level> SecretKey<L> where
    LaneCount<{f4::lanes(dim(L))}>: SupportedLaneCount,
    LaneCount<{f4::lanes(2*dim(L))}>: SupportedLaneCount,
    [(); hash_len(L)]:,
    [(); seed_len(L)]:,
    [(); 2*n(L)]:,
    [(); 2*m(L)]:,
{
    pub fn generate(coins: &[u8]) -> Self {
        let mut shake = get_shake::<L>();
        let mut pk_seed = [0u8; seed_len(L)];
        let mut sk_seed = [0u8; seed_len(L)];
        let mut s = Vector::<L>::zero();
        shake.update(coins);
        shake.squeeze(&mut pk_seed);
        shake.squeeze(&mut sk_seed);
        shake.squeeze(s.mut_buf());
        let mq = Mq::<L>::expand::<L>(&pk_seed);
        let v = mq.apply(&s);
        Self(s, sk_seed, PublicKey(v, pk_seed))
    }

    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        let mq = Mq::<L>::expand::<L>(&self.2.1);
        let mut shake = get_shake::<L>();
        shake.update(self.2.0.buf());
        shake.update(message);
        let salt = Salt::new(&shake);
        let seed = {
            let mut seed = [0u8; seed_len(L)];
            let mut shake = salt.with_domain::<{Domain::Seed}>().shake();
            shake.update(&self.1);
            shake.squeeze(&mut seed);
            seed
        };
        let seeds = SetupTree::<L>::new(&seed, salt.with_domain::<{Domain::SetupTree}>());
        let mut transcript = salt.with_domain::<{Domain::Transcript}>().shake();
        let mut coms = CommitTree::<L>::new();
        let mut setups = Vec::with_capacity(m(L));
        for i in 0..m(L) {
            let salt = salt.with_setup(i);
            let (com, setup) = self.prove_round(&mq, &seeds[i], salt);
            transcript.update(unsafe {
                std::slice::from_raw_parts(
                    setup.1.as_ptr() as *const u8,
                    n(L)*hash_len(L))
            });
            coms[i].copy_from_slice(&com);
            setups.push(setup);
        }
        transcript.update(coms.derive_root(salt.with_domain::<{Domain::CommitTree}>()));
        let commit = get_commit::<{hash_len(L)}>(transcript);
        let challenge = self.2.challenge(&commit, salt);
        let mut signature: Vec<u8> = Vec::new();
        signature.extend_from_slice(&commit);
        signature.extend_from_slice(&seeds.conceal(&challenge.0));
        for (i, &hidden) in challenge.1.iter().enumerate().filter(|(_, &h)| h < n(L)) {
            let (seeds, aux, masked, correction) = &setups[i];
            signature.extend_from_slice(&seeds.conceal(slice::from_ref(&hidden)));
            signature.extend_from_slice(&aux[hidden]);
            signature.extend_from_slice(masked.buf());
            if hidden != n(L) - 1 {
                signature.extend_from_slice(correction.buf());
            }
        }
        signature.extend_from_slice(&coms.reveal(&challenge.0));
        signature
    }

    fn prove_round(
        &self, mq: &Mq<L>, seed: &[u8], salt: Salt
    ) -> (Hash<L>, (PartyTree<L>, [Hash<L>; n(L)], Vector<L>, Vector<L>)) {
        let (seeds, shares, mask, mut aux) = self.2.setup(seed, salt);
        let masked = self.0 ^ mask;
        let (com, correction) = self.execute(mq, &masked, shares, salt);
        aux[n(L) - 1] = self.2.commit_final(&seeds[n(L) - 1], &correction, salt);
        (com, (seeds, aux, masked, correction))
    }

    fn execute(
        &self, mq: &Mq<L>, masked: &Vector<L>, shares: [[Vector<L>; 2]; n(L)], salt: Salt
    ) -> (Hash<L>, Vector<L>) {
        let (out, polar) = mq.apply_and_polar(masked);
        let mut correction = self.2.0 ^ out;
        let mut shake = salt.with_domain::<{Domain::SimulateCommit}>().shake();
        for share in shares.iter().take(n(L) - 1) {
            let msg = polar.apply(&share[0]) ^ share[1];
            shake.update(msg.buf());
            correction ^= msg;
        }
        shake.update(correction.buf());
        correction ^= polar.apply(&shares[n(L) - 1][0]);
        (get_commit(shake), correction)
    }
}

#[cfg(test)]
mod tests {
    extern crate test;
    use test::{black_box, Bencher};

    use average::Variance;
    use tiny_keccak::{Hasher, Shake, Xof};
    use crate::Level;
    use super::SecretKey;

    #[test]
    fn test_l1() {
        let sk: SecretKey<{Level::L1Fast}> = SecretKey::generate(b"test_l1.sk");
        let message = b"test_l1.message";
        let proof = sk.sign(message);
        sk.2.verify(message, &proof).unwrap();
    }

    #[test]
    fn test_l3() {
        let sk: SecretKey<{Level::L3Fast}> = SecretKey::generate(b"test_l3.sk");
        let message = b"test_l3.message";
        let proof = sk.sign(message);
        sk.2.verify(message, &proof).unwrap();
    }

    #[test]
    fn test_l5() {
        let sk: SecretKey<{Level::L5Fast}> = SecretKey::generate(b"test_l5.sk");
        let message = b"test_l5.message";
        let proof = sk.sign(message);
        sk.2.verify(message, &proof).unwrap();
    }

    #[bench]
    fn bench_l1_fast_sign(b: &mut Bencher) {
        let sk: SecretKey<{Level::L1Fast}> = SecretKey::generate(b"bench_l1_fast_sign.sk");
        let message = b"bench_l1_fast_sign.message";
        b.iter(|| black_box(sk.sign(message)));
    }

    #[bench]
    fn bench_l1_compact_sign(b: &mut Bencher) {
        let sk: SecretKey<{Level::L1Compact}> = SecretKey::generate(b"bench_l1_compact_sign.sk");
        let message = b"bench_l1_compact_sign.message";
        b.iter(|| black_box(sk.sign(message)));
    }

    #[bench]
    fn bench_l3_fast_sign(b: &mut Bencher) {
        let sk: SecretKey<{Level::L3Fast}> = SecretKey::generate(b"bench_l3_fast_sign.sk");
        let message = b"bench_l1_fast_sign.message";
        b.iter(|| black_box(sk.sign(message)));
    }

    #[bench]
    fn bench_l3_compact_sign(b: &mut Bencher) {
        let sk: SecretKey<{Level::L3Compact}> = SecretKey::generate(b"bench_l3_compact_sign.sk");
        let message = b"bench_l1_compact_sign.message";
        b.iter(|| black_box(sk.sign(message)));
    }

    #[bench]
    fn bench_l5_fast_sign(b: &mut Bencher) {
        let sk: SecretKey<{Level::L5Fast}> = SecretKey::generate(b"bench_l5_fast_sign.sk");
        let message = b"bench_l1_fast_sign.message";
        b.iter(|| black_box(sk.sign(message)));
    }

    #[bench]
    fn bench_l5_compact_sign(b: &mut Bencher) {
        let sk: SecretKey<{Level::L5Compact}> = SecretKey::generate(b"bench_l5_compact_sign.sk");
        let message = b"bench_l1_compact_sign.message";
        b.iter(|| black_box(sk.sign(message)));
    }

    #[bench]
    fn bench_l1_fast_verify(b: &mut Bencher) {
        let sk: SecretKey<{Level::L1Fast}> = SecretKey::generate(b"bench_l1_fast_verify.sk");
        let message = b"bench_l1_fast_verify.message";
        let proof = sk.sign(message);
        b.iter(|| black_box(sk.2.verify(message, &proof).unwrap()));
    }

    #[bench]
    fn bench_l1_compact_verify(b: &mut Bencher) {
        let sk: SecretKey<{Level::L1Compact}> = SecretKey::generate(b"bench_l1_compact_verify.sk");
        let message = b"bench_l1_compact_verify.message";
        let proof = sk.sign(message);
        b.iter(|| black_box(sk.2.verify(message, &proof).unwrap()));
    }

    #[bench]
    fn bench_l3_fast_verify(b: &mut Bencher) {
        let sk: SecretKey<{Level::L3Fast}> = SecretKey::generate(b"bench_l3_fast_verify.sk");
        let message = b"bench_l3_fast_verify.message";
        let proof = sk.sign(message);
        b.iter(|| black_box(sk.2.verify(message, &proof).unwrap()));
    }

    #[bench]
    fn bench_l3_compact_verify(b: &mut Bencher) {
        let sk: SecretKey<{Level::L3Compact}> = SecretKey::generate(b"bench_l3_compact_verify.sk");
        let message = b"bench_l3_compact_verify.message";
        let proof = sk.sign(message);
        b.iter(|| black_box(sk.2.verify(message, &proof).unwrap()));
    }

    #[bench]
    fn bench_l5_fast_verify(b: &mut Bencher) {
        let sk: SecretKey<{Level::L5Fast}> = SecretKey::generate(b"bench_l5_fast_verify.sk");
        let message = b"bench_l5_fast_verify.message";
        let proof = sk.sign(message);
        b.iter(|| black_box(sk.2.verify(message, &proof).unwrap()));
    }

    #[bench]
    fn bench_l5_compact_verify(b: &mut Bencher) {
        let sk: SecretKey<{Level::L5Compact}> = SecretKey::generate(b"bench_l5_compact_verify.sk");
        let message = b"bench_l5_compact_verify.message";
        let proof = sk.sign(message);
        b.iter(|| black_box(sk.2.verify(message, &proof).unwrap()));
    }

    #[test]
    #[ignore]
    fn estimate_l1_fast_size() {
        let sk: SecretKey<{Level::L1Fast}> = SecretKey::generate(b"estimate_l1_fast_size.sk");
        let mut message = [0u8; 16];
        let mut xof = Shake::v128();
        xof.update(b"estimate_l1_fast_size.message");
        let stats: Variance = (0..1000).map(|_| {
            xof.squeeze(&mut message);
            sk.sign(&message).len() as f64
        }).map(f64::from).collect();
        println!("L1 Fast signature size: {:.0} ± {:.0}", stats.mean(), stats.sample_variance().sqrt());
    }

    #[test]
    #[ignore]
    fn estimate_l1_compact_size() {
        let sk: SecretKey<{Level::L1Compact}> = SecretKey::generate(b"estimate_l1_compact_size.sk");
        let mut message = [0u8; 16];
        let mut xof = Shake::v128();
        xof.update(b"estimate_l1_compact_size.message");
        let stats: Variance = (0..1000).map(|_| {
            xof.squeeze(&mut message);
            sk.sign(&message).len() as f64
        }).map(f64::from).collect();
        println!("L1 Compact signature size: {:.0} ± {:.0}", stats.mean(), stats.sample_variance().sqrt());
    }

    #[test]
    #[ignore]
    fn estimate_l3_fast_size() {
        let sk: SecretKey<{Level::L3Fast}> = SecretKey::generate(b"estimate_l3_fast_size.sk");
        let mut message = [0u8; 16];
        let mut xof = Shake::v128();
        xof.update(b"estimate_l3_fast_size.message");
        let stats: Variance = (0..1000).map(|_| {
            xof.squeeze(&mut message);
            sk.sign(&message).len() as f64
        }).map(f64::from).collect();
        println!("L3 Fast signature size: {:.0} ± {:.0}", stats.mean(), stats.sample_variance().sqrt());
    }

    #[test]
    #[ignore]
    fn estimate_l3_compact_size() {
        let sk: SecretKey<{Level::L3Compact}> = SecretKey::generate(b"estimate_l3_compact_size.sk");
        let mut message = [0u8; 16];
        let mut xof = Shake::v128();
        xof.update(b"estimate_l3_compact_size.message");
        let stats: Variance = (0..1000).map(|_| {
            xof.squeeze(&mut message);
            sk.sign(&message).len() as f64
        }).map(f64::from).collect();
        println!("L3 Compact signature size: {:.0} ± {:.0}", stats.mean(), stats.sample_variance().sqrt());
    }

    #[test]
    #[ignore]
    fn estimate_l5_fast_size() {
        let sk: SecretKey<{Level::L5Fast}> = SecretKey::generate(b"estimate_l5_fast_size.sk");
        let mut message = [0u8; 16];
        let mut xof = Shake::v128();
        xof.update(b"estimate_l5_fast_size.message");
        let stats: Variance = (0..1000).map(|_| {
            xof.squeeze(&mut message);
            sk.sign(&message).len() as f64
        }).map(f64::from).collect();
        println!("L5 Fast signature size: {:.0} ± {:.0}", stats.mean(), stats.sample_variance().sqrt());
    }

    #[test]
    #[ignore]
    fn estimate_l5_compact_size() {
        let sk: SecretKey<{Level::L5Compact}> = SecretKey::generate(b"estimate_l5_compact_size.sk");
        let mut message = [0u8; 16];
        let mut xof = Shake::v128();
        xof.update(b"estimate_l5_compact_size.message");
        let stats: Variance = (0..1000).map(|_| {
            xof.squeeze(&mut message);
            sk.sign(&message).len() as f64
        }).map(f64::from).collect();
        println!("L5 Compact signature size: {:.0} ± {:.0}", stats.mean(), stats.sample_variance().sqrt());
    }
}
