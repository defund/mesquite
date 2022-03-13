mod merkle;
mod seed;

pub use merkle::MerkleTree;
pub use seed::SeedTree;

fn derive_mask<const N: usize>(idxs: &[usize]) -> [bool; 2*N] where
    [(); 2*N]:,
{
    let mut mask = [true; 2*N];
    mask[0] = false;
    for idx in idxs {
        let mut i = N + idx;
        while mask[i] {
            mask[i] = false;
            i >>= 1;
        }
    }
    mask
}
