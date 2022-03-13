use std::ops::{BitXor, BitXorAssign};
use std::simd::{LaneCount, Simd, SupportedLaneCount};

pub const fn bytes(n: usize) -> usize {
    n / u8::BITS as usize
}

pub const fn words(n: usize) -> usize {
    (n - 1) / u64::BITS as usize + 1
}

pub const fn lanes(n: usize) -> usize {
    words(n).next_power_of_two()
}

#[derive(Clone, Copy, Default)]
pub struct Vector<const N: usize>(pub Simd<u64, {lanes(N)}>) where
    LaneCount<{lanes(N)}>: SupportedLaneCount;

impl<const N: usize> Vector<N> where
    LaneCount<{lanes(N)}>: SupportedLaneCount,
{
    pub const BYTES: usize = bytes(N);

    pub fn zero() -> Self {
        Self::default()
    }

    pub fn buf(&self) -> &[u8] {
        unsafe {
            core::slice::from_raw_parts(
                self.0.as_array().as_ptr() as *const u8,
                N / u8::BITS as usize,
            )
        }
    }

    pub fn mut_buf(&mut self) -> &mut [u8] {
        unsafe {
            core::slice::from_raw_parts_mut(
                self.0.as_mut_array().as_mut_ptr() as *mut u8,
                Self::BYTES,
            )
        }
    }

    pub fn mask(&self) -> [u64; N] {
        let mut mask = [0u64; N];
        let mut k = 0;
        for i in 0..words(N) {
            let mut word = self.0[i];
            for _ in 0..(u64::BITS as usize) {
                mask[k] = (word & 1).wrapping_neg();
                word >>= 1;
                k += 1;
                if k == N {
                    break
                }
            }
        }
        mask
    }
}

impl<const N: usize> BitXor for Vector<N> where
    LaneCount<{lanes(N)}>: SupportedLaneCount,
{
    type Output = Self;

    fn bitxor(self, rhs: Self) -> Self::Output {
        Self(self.0 ^ rhs.0)
    }
}

impl<const N: usize> BitXorAssign for Vector<N> where
    LaneCount<{lanes(N)}>: SupportedLaneCount,
{
    fn bitxor_assign(&mut self, rhs: Self) {
        self.0 ^= rhs.0;
    }
}

impl<const N: usize> From<&[u8]> for Vector<N> where
    LaneCount<{lanes(N)}>: SupportedLaneCount,
{
    fn from(buf: &[u8]) -> Self {
        let mut vector = Self::zero();
        vector.mut_buf().copy_from_slice(buf);
        vector
    }
}

#[cfg(test)]
use std::fmt;

#[cfg(test)]
impl<const N: usize> PartialEq for Vector<N> where
    LaneCount<{lanes(N)}>: SupportedLaneCount,
{
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

#[cfg(test)]
impl<const N: usize> fmt::Debug for Vector<N> where
    LaneCount<{lanes(N)}>: SupportedLaneCount,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Vector").field("buf", &self.buf()).finish()
    }
}
