mod ffi;

use ffi::{MKEM_GROUPBYTES, MKEM_PUBLICKEYBYTES, mkem_group, MKEM_SECRETKEYBYTES, mkem_keypair, MKEM_CTIBYTES, MKEM_CTDBYTES, MKEM_SSBYTES, mkem_enc, mkem_dec};

pub type Seed = [u8; MKEM_GROUPBYTES];

pub fn gen_seed() -> Seed {
	let mut seed = [0; MKEM_GROUPBYTES];

	unsafe { mkem_group(seed.as_mut_ptr()); }

	seed
}

pub type PublicKey = [u8; MKEM_PUBLICKEYBYTES];
pub type SecretKey = [u8; MKEM_SECRETKEYBYTES];
pub struct KeyPair {
	pub pk: PublicKey,
	pub sk: SecretKey
}

pub fn gen_keypair(seed: &Seed) -> KeyPair {
	let mut pk = [0; MKEM_PUBLICKEYBYTES];
	let mut sk = [0; MKEM_SECRETKEYBYTES];

	unsafe { mkem_keypair(pk.as_mut_ptr(), sk.as_mut_ptr(), seed.as_ptr()) };

	KeyPair { pk, sk }
}

pub type Cti = [u8; MKEM_CTIBYTES];
pub type Ctd = [u8; MKEM_CTDBYTES];
pub type SharedSecret = [u8; MKEM_SSBYTES];

pub struct Encapsulation {
	// key-independent (shared) ciphertext
	pub cti: Cti,
	// key-dependent ciphertext
	pub ctds: Vec<Ctd>,
	// shared secret
	pub ss: SharedSecret
}

// does not check whether the supplied keys are of the same seed
pub fn enc(seed: &Seed, keys: &[PublicKey]) -> Encapsulation {
	let pks: Vec<*const u8> = keys.iter().map(|k| k.as_ptr()).collect();
	let ctds = vec![[0u8; MKEM_CTDBYTES]; keys.len()];
	let mut cti = [0u8; MKEM_CTIBYTES];
	let mut ss = [0u8; MKEM_SSBYTES];
	let mut ctds_ptrs: Vec<*mut u8> = ctds.iter().map(|c| c.as_ptr() as *mut u8).collect();
	
	unsafe { mkem_enc(ctds_ptrs.as_mut_ptr(), cti.as_mut_ptr(), ss.as_mut_ptr(), seed.as_ptr(), pks.as_ptr(), pks.len()) };

	Encapsulation {
		cti,
		ctds,
		ss
	}
}

// returns Some(SharedKey), if decapsulates or None otherwise
pub fn dec(cti: &Cti, ctd: &Ctd, seed: &Seed, pk: &PublicKey, sk: &SecretKey) -> Option<SharedSecret> {
	let empty_ss = [0u8; MKEM_SSBYTES];
	let mut ss = empty_ss.clone();

	unsafe { mkem_dec(ss.as_mut_ptr(), cti.as_ptr(), ctd.as_ptr(), seed.as_ptr(), pk.as_ptr(), sk.as_ptr()) };

	if ss == empty_ss {
		// if for any reason decapsulation fails, ss is not filled with data from mkem_dec
		None
	} else {
		Some(ss)
	}
}


#[cfg(test)]
mod tests {
	use crate::{gen_seed, gen_keypair, enc, PublicKey, dec};

	#[test]
	fn test_gen_seed() {
		let seed = gen_seed();

		assert_ne!(seed.to_vec(), vec![0u8; seed.len()]);
	}

	#[test]
	fn test_enc_dec() {
		let seed = gen_seed();
		let ref_keys = vec![gen_keypair(&seed), gen_keypair(&seed)];
		let pks: Vec<PublicKey> = ref_keys.iter().map(|kp| kp.pk).collect();
		let encapsulated = enc(&seed, &pks);

		// it decapsulates with the right keys
		ref_keys.iter().enumerate().for_each(|(idx, kp)| {
			let ss = dec(&encapsulated.cti, &encapsulated.ctds[idx], &seed, &kp.pk, &kp.sk);

			assert_eq!(ss.unwrap(), encapsulated.ss);
		});

		let wrong_keys = vec![gen_keypair(&seed), gen_keypair(&seed)];

		// and fails with the wrong ones
		wrong_keys.iter().enumerate().for_each(|(idx, kp)| {
			let ss = dec(&encapsulated.cti, &encapsulated.ctds[idx], &seed, &kp.pk, &kp.sk);

			assert!(ss.is_none());
		});
	}
}