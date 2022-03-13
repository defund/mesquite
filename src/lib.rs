#![allow(incomplete_features)]
#![feature(adt_const_params)]
#![feature(generic_arg_infer, generic_const_exprs)]
#![feature(portable_simd)]
#![feature(test)]

mod f4;
mod scheme;
mod shake;
mod tree;

pub use scheme::{PublicKey, SecretKey};

#[derive(PartialEq, Eq)]
pub enum Level {
    L1Fast,
    L1Compact,
    L3Fast,
    L3Compact,
    L5Fast,
    L5Compact,
}

pub const fn seed_len(level: Level) -> usize {
    match level {
        Level::L1Fast => 16,
        Level::L1Compact => 16,
        Level::L3Fast => 24,
        Level::L3Compact => 24,
        Level::L5Fast => 32,
        Level::L5Compact => 32,
    }
}

pub const fn hash_len(level: Level) -> usize {
    match level {
        Level::L1Fast => 32,
        Level::L1Compact => 32,
        Level::L3Fast => 48,
        Level::L3Compact => 48,
        Level::L5Fast => 64,
        Level::L5Compact => 64,
    }
}

pub const fn dim(level: Level) -> usize {
    match level {
        Level::L1Fast => 88,
        Level::L1Compact => 88,
        Level::L3Fast => 128,
        Level::L3Compact => 128,
        Level::L5Fast => 160,
        Level::L5Compact => 160,
    }
}

pub const fn n(level: Level) -> usize {
    match level {
        Level::L1Fast => 8,
        Level::L1Compact => 16,
        Level::L3Fast => 8,
        Level::L3Compact => 16,
        Level::L5Fast => 8,
        Level::L5Compact => 16,
    }
}

pub const fn m(level: Level) -> usize {
    match level {
        Level::L1Fast => 176,
        Level::L1Compact => 232,
        Level::L3Fast => 276,
        Level::L3Compact => 354,
        Level::L5Fast => 372,
        Level::L5Compact => 460,
    }
}

pub const fn tau(level: Level) -> usize {
    match level {
        Level::L1Fast => 51,
        Level::L1Compact => 37,
        Level::L3Fast => 74,
        Level::L3Compact => 55,
        Level::L5Fast => 98,
        Level::L5Compact => 74,
    }
}
