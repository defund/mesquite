use std::ops::{Index, IndexMut};
use tiny_keccak::{Hasher, Xof};
use crate::shake::Salt;
use super::derive_mask;

#[derive(Debug)]
pub struct MerkleTree<const N: usize, const M: usize> where
    [(); 2*N]:
{
    nodes: [[u8; M]; 2*N],
}

impl<const N: usize, const M: usize> MerkleTree<N, M> where
    [(); 2*N]:
{
    pub fn new() -> Self {
        Self {
            nodes: [[0; _]; _],
        }
    }

    fn commit(&mut self, idx: usize, salt: Salt) {
        let mut shake = salt.with_node(idx).shake();
        shake.update(&self.nodes[2*idx]);
        shake.update(&self.nodes[2*idx + 1]);
        shake.squeeze(&mut self.nodes[idx]);
    }

    pub fn derive_root(&mut self, salt: Salt) -> &[u8] {
        for i in (0..N).rev() {
            self.commit(i, salt);
        }
        &self.nodes[1]
    }

    pub fn reveal(&self, idxs: &[usize]) -> Vec<u8> {
        let mut hint: Vec<u8> = Vec::new();
        let mask = derive_mask::<N>(idxs);
        for i in (1..2*N).rev() {
            if mask[i] && !mask[i >> 1] {
                hint.extend_from_slice(&self.nodes[i]);
            }
        }
        hint
    }

    pub fn restore<'a>(
        &mut self, idxs: &[usize], hint: &'a [u8], salt: Salt
    ) -> (&[u8], &'a [u8]) {
        let mask = derive_mask::<N>(idxs);
        let mut j = 0;
        for i in (1..2*N).rev().filter(|&i| mask[i] && !mask[i >> 1]) {
            self.nodes[i].copy_from_slice(&hint[j*M..(j+1)*M]);
            j += 1;
        }
        for i in (1..N).rev().filter(|&i| !mask[i]) {
            self.commit(i, salt);
        }
        (&self.nodes[1], &hint[j*M..])
    }
}

impl<const N: usize, const M: usize> Index<usize> for MerkleTree<N, M> where
    [(); 2*N]:,
{
    type Output = [u8];

    fn index(&self, idx: usize) -> &Self::Output {
        return &self.nodes[N + idx];
    }
}

impl<const N: usize, const M: usize> IndexMut<usize> for MerkleTree<N, M> where
    [(); 2*N]:,
{
    fn index_mut(&mut self, idx: usize) -> &mut Self::Output {
        return &mut self.nodes[N + idx];
    }
}

#[cfg(test)]
mod tests {
    use tiny_keccak::{Hasher, Shake, Xof};
    use super::*;

    #[test]
    fn test_merkle_tree() {
        const NUM_LEAVES: usize = 7;
        const HASH_BYTES: usize = 32;

        let shake = Shake::v128();
        let salt = Salt::new(&shake);
        let mut tree: MerkleTree<NUM_LEAVES, HASH_BYTES> = MerkleTree::new();

        let bufs = [b"0", b"1", b"2", b"3", b"4", b"5", b"6"];
        for i in 0..bufs.len() {
            let mut shake = Shake::v128();
            shake.update(bufs[i]);
            shake.squeeze(&mut tree[i]);
        }
        let mut root = [0u8; HASH_BYTES];
        root.copy_from_slice(tree.derive_root(salt));

        {
            let idxs = [5];
            let hint = tree.reveal(&idxs);
            for (i, &x) in [13, 7, 2].iter().enumerate() {
                assert_eq!(hint[i*HASH_BYTES..(i+1)*HASH_BYTES], tree.nodes[x]);
            }
            let mut new_tree: MerkleTree<NUM_LEAVES, HASH_BYTES> = MerkleTree::new();
            for i in idxs {
                let mut shake = Shake::v128();
                shake.update(bufs[i]);
                shake.squeeze(&mut new_tree[i]);
            }
            let (new_root, slice) = new_tree.restore(&idxs, &hint, salt);
            assert_eq!(new_root, root);
            assert_eq!(slice.len(), 0);
        }

        {
            let idxs = [1, 5];
            let hint = tree.reveal(&idxs);
            for (i, &x) in [13, 9, 7, 5].iter().enumerate() {
                assert_eq!(hint[i*HASH_BYTES..(i+1)*HASH_BYTES], tree.nodes[x]);
            }
            let mut new_tree: MerkleTree<NUM_LEAVES, HASH_BYTES> = MerkleTree::new();
            for i in idxs {
                let mut shake = Shake::v128();
                shake.update(bufs[i]);
                shake.squeeze(&mut new_tree[i]);
            }
            let (new_root, slice) = new_tree.restore(&idxs, &hint, salt);
            assert_eq!(new_root, root);
            assert_eq!(slice.len(), 0);
        }
    }
}
