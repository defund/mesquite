use std::ops::Index;
use tiny_keccak::{Hasher, Xof};
use crate::shake::Salt;
use super::derive_mask;

#[derive(Debug)]
pub struct SeedTree<const N: usize, const M: usize> where
    [(); 2*N]:,
{
    nodes: [[u8; M]; 2*N],
}

impl<const N: usize, const M: usize> SeedTree<N, M> where
    [(); 2*N]:
{
    pub fn new(root: &[u8], salt: Salt) -> Self {
        let mut tree = Self {
            nodes: [[0; _]; _],
        };
        tree.nodes[1].copy_from_slice(root);
        for i in 1..N {
            tree.expand(i, salt);
        }
        tree
    }

    fn expand(&mut self, idx: usize, salt: Salt) {
        let mut shake = salt.with_node(idx).shake();
        shake.update(&self.nodes[idx]);
        shake.squeeze(&mut self.nodes[2*idx]);
        shake.squeeze(&mut self.nodes[2*idx + 1]);
    }

    pub fn conceal(&self, idxs: &[usize]) -> Vec<u8> {
        let mut hint: Vec<u8> = Vec::new();
        let mask = derive_mask::<N>(idxs);
        for i in 1..2*N {
            if mask[i] && !mask[i >> 1] {
                hint.extend_from_slice(&self.nodes[i]);
            }
        }
        hint
    }

    pub fn restore<'a>(idxs: &[usize], hint: &'a [u8], salt: Salt) -> (Self, &'a [u8]) {
        let mask = derive_mask::<N>(idxs);
        let mut tree = Self {
            nodes: [[0; _]; _],
        };
        let mut j = 0;
        for i in (1..2*N).filter(|&i| mask[i] && !mask[i >> 1]) {
            tree.nodes[i].copy_from_slice(&hint[j*M..(j+1)*M]);
            j += 1;
        }
        for i in (1..N).filter(|&i| mask[i]) {
            tree.expand(i, salt);
        }
        (tree, &hint[j*M..])
    }
}

impl<const N: usize, const M: usize> Index<usize> for SeedTree<N, M> where
    [(); 2*N]:,
{
    type Output = [u8];

    fn index(&self, idx: usize) -> &Self::Output {
        &self.nodes[N + idx]
    }
}

#[cfg(test)]
mod tests {
    use tiny_keccak::Shake;
    use super::*;

    #[test]
    fn test_seed_tree() {
        const NUM_SEEDS: usize = 7;
        const SEED_BYTES: usize = 16;

        let shake = Shake::v128();
        let salt = Salt::new(&shake);
        let seeds = SeedTree::<NUM_SEEDS, SEED_BYTES>::new(b"test_seed_tree!!", salt);

        {
            let idxs = [5];
            let hint = seeds.conceal(&idxs);
            for (i, &x) in [2, 7, 13].iter().enumerate() {
                assert_eq!(hint[i*SEED_BYTES..(i+1)*SEED_BYTES], seeds.nodes[x]);
            }
            let (new_seeds, slice) = SeedTree::<NUM_SEEDS, SEED_BYTES>::restore(&idxs, &hint, salt);
            for i in (0..NUM_SEEDS).filter(|x| idxs.iter().all(|y| x != y)) {
                assert_eq!(seeds[i], new_seeds[i]);
            }
            assert_eq!(slice.len(), 0);
        }

        {
            let idxs = [1, 5];
            let hint = seeds.conceal(&idxs);
            for (i, &x) in [5, 7, 9, 13].iter().enumerate() {
                assert_eq!(hint[i*SEED_BYTES..(i+1)*SEED_BYTES], seeds.nodes[x]);
            }
            let (new_seeds, slice) = SeedTree::<NUM_SEEDS, SEED_BYTES>::restore(&idxs, &hint, salt);
            for i in (0..NUM_SEEDS).filter(|x| idxs.iter().all(|y| x != y)) {
                assert_eq!(seeds[i], new_seeds[i]);
            }
            assert_eq!(slice.len(), 0);
        }
    }
}
