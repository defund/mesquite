use std::simd::{LaneCount, Simd, SupportedLaneCount};
use tiny_keccak::{Hasher, Xof};
use crate::Level;
use crate::shake::get_shake;
use super::vector::{bytes, lanes, Vector};

const fn quad(n: usize) -> usize {
    n * (n + 1) / 2
}

pub struct Mq<const N: usize> where
    LaneCount<{lanes(N)}>: SupportedLaneCount,
{
    mat: Vec<[Simd<u64, {lanes(N)}>; 2]>,
    vec: Vec<[Simd<u64, {lanes(N)}>; 2]>,
}

pub struct Polar<const N: usize> where
    LaneCount<{lanes(N)}>: SupportedLaneCount,
{
    basis: [[Simd<u64, {lanes(N)}>; 2]; N],
}

impl<const N: usize> Mq<N> where
    LaneCount<{lanes(N)}>: SupportedLaneCount,
    LaneCount<{lanes(2*N)}>: SupportedLaneCount,
{
    pub fn expand<const L: Level>(seed: &[u8]) -> Self {
        let mut mat = Vec::with_capacity(quad(N));
        let mut vec = Vec::with_capacity(N);
        let mut shake = get_shake::<L>();
        shake.update(seed);
        unsafe {
            shake.squeeze(core::slice::from_raw_parts_mut(
                mat.as_mut_ptr() as *mut u8,
                mat.capacity() * std::mem::size_of::<[Simd<u64, {lanes(N)}>; 2]>()));
            shake.squeeze(core::slice::from_raw_parts_mut(
                vec.as_mut_ptr() as *mut u8,
                vec.capacity() * std::mem::size_of::<[Simd<u64, {lanes(N)}>; 2]>()));
            mat.set_len(mat.capacity());
            vec.set_len(vec.capacity());
        };
        Self { mat, vec }
    }

    pub fn apply(&self, x: &Vector<{2*N}>) -> Vector<{2*N}> {
        let mask = x.mask();
        let mut out0 = Simd::default();
        let mut out1 = Simd::default();
        let mut k = 0;
        for i in 0..N {
            let i0 = Simd::splat(mask[i]);
            let i1 = Simd::splat(mask[i + N]);
            let mut tmp0 = Simd::default();
            let mut tmp1 = Simd::default();
            for j in 0..i+1 {
                let j0 = Simd::splat(mask[j]);
                let j1 = Simd::splat(mask[j + N]);
                tmp0 ^= (j1 & self.mat[k][1]) ^ (j0 & self.mat[k][0]);
                tmp1 ^= (j1 & self.mat[k][1]) ^ (j0 & self.mat[k][1]) ^ (j1 & self.mat[k][0]);
                k += 1;
            }
            out0 ^= (i1 & tmp1) ^ (i0 & tmp0);
            out1 ^= (i1 & tmp1) ^ (i0 & tmp1) ^ (i1 & tmp0);
        }
        for i in 0..N {
            let i0 = Simd::splat(mask[i]);
            let i1 = Simd::splat(mask[i + N]);
            out0 ^= (i1 & self.vec[i][1]) ^ (i0 & self.vec[i][0]);
            out1 ^= (i1 & self.vec[i][1]) ^ (i0 & self.vec[i][1]) ^ (i1 & self.vec[i][0]);
        }
        let mut out = Vector::zero();
        out.mut_buf()[..bytes(N)].copy_from_slice(unsafe {
            core::slice::from_raw_parts(
                out0.as_array().as_ptr() as *const u8,
                N / u8::BITS as usize,
            )
        });
        out.mut_buf()[bytes(N)..].copy_from_slice(unsafe {
            core::slice::from_raw_parts(
                out1.as_array().as_ptr() as *const u8,
                N / u8::BITS as usize,
            )
        });
        out
    }

    pub fn apply_and_polar(&self, x: &Vector<{2*N}>) -> (Vector<{2*N}>, Polar<N>) {
        let mask = x.mask();
        let mut out0 = Simd::default();
        let mut out1 = Simd::default();
        let mut basis = [[Simd::default(); _]; _];
        let mut k = 0;
        for i in 0..N {
            let i0 = Simd::splat(mask[i]);
            let i1 = Simd::splat(mask[i + N]);
            let mut tmp0 = Simd::default();
            let mut tmp1 = Simd::default();
            for j in 0..i+1 {
                let j0 = Simd::splat(mask[j]);
                let j1 = Simd::splat(mask[j + N]);
                tmp0 ^= (j1 & self.mat[k][1]) ^ (j0 & self.mat[k][0]);
                tmp1 ^= (j1 & self.mat[k][1]) ^ (j0 & self.mat[k][1]) ^ (j1 & self.mat[k][0]);
                basis[j][0] ^= (i1 & self.mat[k][1]) ^ (i0 & self.mat[k][0]);
                basis[j][1] ^= (i1 & self.mat[k][1]) ^ (i0 & self.mat[k][1]) ^ (i1 & self.mat[k][0]);
                k += 1;
            }
            out0 ^= (i1 & tmp1) ^ (i0 & tmp0);
            out1 ^= (i1 & tmp1) ^ (i0 & tmp1) ^ (i1 & tmp0);
            basis[i][0] ^= tmp0;
            basis[i][1] ^= tmp1;
        }
        for i in 0..N {
            let i0 = Simd::splat(mask[i]);
            let i1 = Simd::splat(mask[i + N]);
            out0 ^= (i1 & self.vec[i][1]) ^ (i0 & self.vec[i][0]);
            out1 ^= (i1 & self.vec[i][1]) ^ (i0 & self.vec[i][1]) ^ (i1 & self.vec[i][0]);
        }
        let mut out = Vector::zero();
        out.mut_buf()[..bytes(N)].copy_from_slice(unsafe {
            core::slice::from_raw_parts(
                out0.as_array().as_ptr() as *const u8,
                N / u8::BITS as usize,
            )
        });
        out.mut_buf()[bytes(N)..].copy_from_slice(unsafe {
            core::slice::from_raw_parts(
                out1.as_array().as_ptr() as *const u8,
                N / u8::BITS as usize,
            )
        });
        (out, Polar { basis })
    }
}

impl<const N: usize> Polar<N> where
    LaneCount<{lanes(N)}>: SupportedLaneCount,
    LaneCount<{lanes(2*N)}>: SupportedLaneCount,
{
    pub fn apply(&self, x: &Vector<{2*N}>) -> Vector<{2*N}> {
        let mask = x.mask();
        let mut out0 = Simd::default();
        let mut out1 = Simd::default();
        for i in 0..N {
            let i0 = Simd::splat(mask[i]);
            let i1 = Simd::splat(mask[i + N]);
            out0 ^= (i1 & self.basis[i][1]) ^ (i0 & self.basis[i][0]);
            out1 ^= (i1 & self.basis[i][1]) ^ (i0 & self.basis[i][1]) ^ (i1 & self.basis[i][0]);
        }
        let mut out = Vector::zero();
        out.mut_buf()[..bytes(N)].copy_from_slice(unsafe {
            core::slice::from_raw_parts(
                out0.as_array().as_ptr() as *const u8,
                N / u8::BITS as usize,
            )
        });
        out.mut_buf()[bytes(N)..].copy_from_slice(unsafe {
            core::slice::from_raw_parts(
                out1.as_array().as_ptr() as *const u8,
                N / u8::BITS as usize,
            )
        });
        out
    }
}

#[cfg(test)]
mod tests {
    extern crate test;
    use test::{black_box, Bencher};

    use tiny_keccak::{Hasher, Shake, Xof};
    use crate::dim;
    use super::*;

    fn generate_vec<const N: usize>(seed: &[u8]) -> Vector<N> where
        LaneCount<{lanes(N)}>: SupportedLaneCount,
    {
        let mut x = Vector::<N>::zero();
        let mut xof = Shake::v128();
        xof.update(seed);
        xof.squeeze(x.mut_buf());
        black_box(x)
    }

    #[test]
    fn test_apply() {
        let mq: Mq<{dim(Level::L1Compact)}> = Mq::expand::<{Level::L1Compact}>(b"test_apply.mq");
        let x = generate_vec(b"test_apply.x");
        let y = generate_vec(b"test_apply.y");
        let z = generate_vec(b"test_apply.z");
        let v1 = mq.apply(&(x ^ z)) ^ mq.apply(&x) ^ mq.apply(&z);
        let v2 = mq.apply(&(y ^ z)) ^ mq.apply(&y) ^ mq.apply(&z);
        let v3 = mq.apply(&(x ^ y ^ z)) ^ mq.apply(&(x ^ y)) ^ mq.apply(&z);
        assert_eq!(v1 ^ v2, v3);
    }

    #[test]
    fn test_polar() {
        let mq: Mq<{dim(Level::L1Compact)}> = Mq::expand::<{Level::L1Compact}>(b"test_polar.mq");
        let x = generate_vec(b"test_polar.x");
        let y = generate_vec(b"test_polar.y");
        let z = generate_vec(b"test_apply.z");
        let (out, polar) = mq.apply_and_polar(&x);
        assert_eq!(mq.apply(&x), out);
        assert_eq!(polar.apply(&(y ^ z)), polar.apply(&y) ^ polar.apply(&z));
        assert_eq!(polar.apply(&z), mq.apply(&(x ^ z)) ^ mq.apply(&x) ^ mq.apply(&z));
    }

    #[bench]
    fn bench_expand_l1(b: &mut Bencher) {
        b.iter(|| Mq::<{dim(Level::L1Compact)}>::expand::<{Level::L1Compact}>(b"bench_new_l1.mq"));
    }

    #[bench]
    fn bench_expand_l3(b: &mut Bencher) {
        b.iter(|| Mq::<{dim(Level::L3Compact)}>::expand::<{Level::L3Compact}>(b"bench_new_l3.mq"));
    }

    #[bench]
    fn bench_expand_l5(b: &mut Bencher) {
        b.iter(|| Mq::<{dim(Level::L5Compact)}>::expand::<{Level::L5Compact}>(b"bench_new_l5.mq"));
    }

    #[bench]
    fn bench_apply_l1(b: &mut Bencher) {
        let mq: Mq<{dim(Level::L1Compact)}> = Mq::expand::<{Level::L1Compact}>(b"bench_apply_l1.mq");
        let x = generate_vec(b"bench_apply_l1.x");
        b.iter(|| mq.apply(&x));
    }

    #[bench]
    fn bench_apply_l3(b: &mut Bencher) {
        let mq: Mq<{dim(Level::L3Compact)}> = Mq::expand::<{Level::L3Compact}>(b"bench_apply_l3.mq");
        let x = generate_vec(b"bench_apply_l3.x");
        b.iter(|| mq.apply(&x));
    }

    #[bench]
    fn bench_apply_l5(b: &mut Bencher) {
        let mq: Mq<{dim(Level::L5Compact)}> = Mq::expand::<{Level::L5Compact}>(b"bench_apply_l5.mq");
        let x = generate_vec(b"bench_apply_l5.x");
        b.iter(|| mq.apply(&x));
    }

    #[bench]
    fn bench_apply_and_polar_l1(b: &mut Bencher) {
        let mq: Mq<{dim(Level::L1Compact)}> = Mq::expand::<{Level::L1Compact}>(b"bench_apply_and_polar_l1.mq");
        let x = generate_vec(b"bench_apply_and_polar_l1.x");
        b.iter(|| mq.apply_and_polar(&x));
    }

    #[bench]
    fn bench_apply_and_polar_l3(b: &mut Bencher) {
        let mq: Mq<{dim(Level::L3Compact)}> = Mq::expand::<{Level::L3Compact}>(b"bench_apply_and_polar_l3.mq");
        let x = generate_vec(b"bench_apply_and_polar_l3.x");
        b.iter(|| mq.apply_and_polar(&x));
    }

    #[bench]
    fn bench_apply_and_polar_l5(b: &mut Bencher) {
        let mq: Mq<{dim(Level::L5Compact)}> = Mq::expand::<{Level::L5Compact}>(b"bench_apply_and_polar_l5.mq");
        let x = generate_vec(b"bench_apply_and_polar_l5.x");
        b.iter(|| mq.apply_and_polar(&x));
    }

    #[bench]
    fn bench_polar_l1(b: &mut Bencher) {
        let mq: Mq<{dim(Level::L1Compact)}> = Mq::expand::<{Level::L1Compact}>(b"bench_polar_l1.mq");
        let x = generate_vec(b"bench_polar_l1.x");
        let y = generate_vec(b"bench_polar_l1.y");
        let (_, polar) = mq.apply_and_polar(&x);
        b.iter(|| polar.apply(&y));
    }

    #[bench]
    fn bench_polar_l3(b: &mut Bencher) {
        let mq: Mq<{dim(Level::L3Compact)}> = Mq::expand::<{Level::L3Compact}>(b"bench_polar_l3.mq");
        let x = generate_vec(b"bench_polar_l3.x");
        let y = generate_vec(b"bench_polar_l3.y");
        let (_, polar) = mq.apply_and_polar(&x);
        b.iter(|| polar.apply(&y));
    }

    #[bench]
    fn bench_polar_l5(b: &mut Bencher) {
        let mq: Mq<{dim(Level::L5Compact)}> = Mq::expand::<{Level::L5Compact}>(b"bench_polar_l5.mq");
        let x = generate_vec(b"bench_polar_l5.x");
        let y = generate_vec(b"bench_polar_l5.y");
        let (_, polar) = mq.apply_and_polar(&x);
        b.iter(|| polar.apply(&y));
    }
}
