use rand_core::{RngCore, impls};
use tiny_keccak::{Hasher, Shake, Xof};
use crate::Level;

#[derive(PartialEq, Eq)]
pub enum Domain {
	Seed = 0,
	Transcript = 1,
    Challenge = 2,
    SetupTape = 3,
    SetupCommit = 4,
    SimulateCommit = 5,
    SetupTree = 6,
    PartyTree = 7,
    CommitTree = 8,
}

pub fn get_shake<const L: Level>() -> Shake {
    match L {
        Level::L1Fast => Shake::v128(),
        Level::L1Compact => Shake::v128(),
        _ => Shake::v256(),
    }
}

pub fn get_commit<const N: usize>(mut shake: Shake) -> [u8; N] {
	let mut commit = [0u8; N];
	shake.squeeze(&mut commit);
	commit
}

#[derive(Copy, Clone)]
pub struct Salt<'a>(u64, &'a Shake);

impl<'a> Salt<'a> {
	pub fn new(shake: &'a Shake) -> Self {
		Self(0, shake)
	}

	pub fn shake(self) -> Shake {
		let mut shake = self.1.clone();
		shake.update(&self.0.to_le_bytes());
		shake
	}

	pub fn with_domain<const D: Domain>(self) -> Self {
		Self(self.0 | D as u64, self.1)
	}

	pub fn with_node(self, x: usize) -> Self {
		Self(self.0 | (x as u64) << 16, self.1)
	}

	pub fn with_setup(self, x: usize) -> Self {
		Self(self.0 | (x as u64) << 32, self.1)
	}

	pub fn with_party(self, x: usize) -> Self {
		Self(self.0 | (x as u64) << 48, self.1)
	}
}

pub struct ShakeRng(pub Shake);

impl RngCore for ShakeRng {
	fn next_u32(&mut self) -> u32 {
		impls::next_u32_via_fill(self)
	}

	fn next_u64(&mut self) -> u64 {
		impls::next_u64_via_fill(self)
	}

	fn fill_bytes(&mut self, dest: &mut [u8]) {
		self.0.squeeze(dest);
	}
	
	fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
		self.fill_bytes(dest);
		Ok(())
	}
}
