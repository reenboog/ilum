// copied from mkem.h
// DO NOT MODIFY
pub const MKEM_GROUPBYTES: usize = 16;
pub const MKEM_SECRETKEYBYTES: usize = (2 * 384) + 16;
pub const MKEM_PUBLICKEYBYTES: usize = 2 * 384;
pub const MKEM_SSBYTES: usize = 16;
pub const MKEM_CTIBYTES: usize = 2 * 352;
pub const MKEM_CTDBYTES: usize = 48;

extern {
	pub fn mkem_group(seed: *mut u8);
	pub fn mkem_keypair(pk: *mut u8, sk: *mut u8, seed: *const u8);
	
	pub fn mkem_enc(ctds: *mut *mut u8, cti: *mut u8, ss: *mut u8, seed: *const u8, pks: *const *const u8, nkps: usize);
	pub fn mkem_dec(ss: *mut u8, cti: *const u8, ctd: *const u8, seed: *const u8, pk: *const u8, sk: *const u8);
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_gen_non_zeroes_and_unique() {
		(0..10).for_each(|_| {
			let mut s0 = vec![0; MKEM_GROUPBYTES];

			unsafe { mkem_group(s0.as_mut_ptr()); }

			assert_ne!(s0, vec![0; MKEM_GROUPBYTES]);

			let mut s1 = vec![0; MKEM_GROUPBYTES];

			unsafe { mkem_group(s1.as_mut_ptr()); }

			assert_ne!(s1, vec![0; MKEM_GROUPBYTES]);
			assert_ne!(s0, s1);

			let mut pk0 = vec![0; MKEM_PUBLICKEYBYTES];
			let mut sk0 = vec![0; MKEM_SECRETKEYBYTES];

			unsafe { mkem_keypair(pk0.as_mut_ptr(), sk0.as_mut_ptr(), s0.as_ptr()) };

			assert_ne!(pk0, vec![0; MKEM_PUBLICKEYBYTES]);
			assert_ne!(sk0, vec![0; MKEM_SECRETKEYBYTES]);

			let mut pk1 = vec![0; MKEM_PUBLICKEYBYTES];
			let mut sk1 = vec![0; MKEM_SECRETKEYBYTES];

			unsafe { mkem_keypair(pk1.as_mut_ptr(), sk1.as_mut_ptr(), s1.as_ptr()) };

			assert_ne!(pk1, vec![0; MKEM_PUBLICKEYBYTES]);
			assert_ne!(pk0, pk1);
			assert_ne!(sk1, vec![0; MKEM_SECRETKEYBYTES]);
			assert_ne!(sk0, sk1);
		});
	}

	#[test]
	fn test_enc_dec() {
		let mut seed = vec![0; MKEM_GROUPBYTES];

		unsafe { mkem_group(seed.as_mut_ptr()); }

		let keys: Vec<(Vec<u8>, Vec<u8>)> = (0..10).map(|_| {
			let mut pk = vec![0; MKEM_PUBLICKEYBYTES];
			let mut sk = vec![0; MKEM_SECRETKEYBYTES];

			unsafe { mkem_keypair(pk.as_mut_ptr(), sk.as_mut_ptr(), seed.as_ptr()) };

			(pk, sk)
		}).collect();

		let pks: Vec<*const u8> = keys.iter().map(|kp| kp.0.as_ptr()).collect();
		let ctds = vec![vec![0u8; MKEM_CTDBYTES]; keys.len()];
		let mut cti = vec![0u8; MKEM_CTIBYTES];
		let mut ref_ss = vec![0u8; MKEM_SSBYTES];
		let mut ctds_ptrs: Vec<*mut u8> = ctds.iter().map(|c| c.as_ptr() as *mut u8).collect();
		
		unsafe { mkem_enc(ctds_ptrs.as_mut_ptr(), cti.as_mut_ptr(), ref_ss.as_mut_ptr(), seed.as_ptr(), pks.as_ptr(), pks.len()) };

		keys.iter().enumerate().for_each(|(idx, kp)| {
			let mut ss = vec![0u8; MKEM_SSBYTES];

			unsafe { mkem_dec(ss.as_mut_ptr(), cti.as_ptr(), ctds[idx].as_ptr(), seed.as_ptr(), kp.0.as_ptr(), kp.1.as_ptr()) };
			assert_eq!(ss, ref_ss);
		})
	}

	#[test]
	fn test_dec_fails_with_seed_mismatch() {
		let mut ref_seed = vec![0; MKEM_GROUPBYTES];

		unsafe { mkem_group(ref_seed.as_mut_ptr()); }

		let keys: Vec<(Vec<u8>, Vec<u8>, Vec<u8>)> = (0..10).map(|_| {
			// each of these keys has its unique seed, so there's no way to bind them
			let mut seed = vec![0; MKEM_GROUPBYTES];

			unsafe { mkem_group(seed.as_mut_ptr()); }

			assert_ne!(seed, ref_seed);

			let mut pk = vec![0; MKEM_PUBLICKEYBYTES];
			let mut sk = vec![0; MKEM_SECRETKEYBYTES];

			unsafe { mkem_keypair(pk.as_mut_ptr(), sk.as_mut_ptr(), seed.as_ptr()) };

			(pk, sk, seed)
		}).collect();

		let pks: Vec<*const u8> = keys.iter().map(|kp| kp.0.as_ptr()).collect();
		let ctds = vec![vec![0u8; MKEM_CTDBYTES]; keys.len()];
		let mut cti = vec![0u8; MKEM_CTIBYTES];
		let mut ref_ss = vec![0u8; MKEM_SSBYTES];
		let mut ctds_ptrs: Vec<*mut u8> = ctds.iter().map(|c| c.as_ptr() as *mut u8).collect();
		
		// mkem_enc does return a "shared" secret
		unsafe { mkem_enc(ctds_ptrs.as_mut_ptr(), cti.as_mut_ptr(), ref_ss.as_mut_ptr(), ref_seed.as_ptr(), pks.as_ptr(), pks.len()) };

		keys.iter().enumerate().for_each(|(idx, kp)| {
			let mut ss = vec![0u8; MKEM_SSBYTES];

			// but it does not decapsulates the shared secret because of seed mismatch
			unsafe { mkem_dec(ss.as_mut_ptr(), cti.as_ptr(), ctds[idx].as_ptr(), kp.2.as_ptr(), kp.0.as_ptr(), kp.1.as_ptr()) };
			assert_ne!(ss, ref_ss);

			// even if the same ref seed from mkem_enc is used (each key has its own seed, hence no bond)
			unsafe { mkem_dec(ss.as_mut_ptr(), cti.as_ptr(), ctds[idx].as_ptr(), ref_seed.as_ptr(), kp.0.as_ptr(), kp.1.as_ptr()) };
			assert_ne!(ss, ref_ss);
		})
	}

	#[test]
	fn test_dec_fails_with_keys_mismatch() {
		let mut seed = vec![0; MKEM_GROUPBYTES];

		unsafe { mkem_group(seed.as_mut_ptr()); }

		let n_keys = 10;

		let ref_keys: Vec<(Vec<u8>, Vec<u8>)> = (0..n_keys).map(|_| {
			let mut pk = vec![0; MKEM_PUBLICKEYBYTES];
			let mut sk = vec![0; MKEM_SECRETKEYBYTES];

			unsafe { mkem_keypair(pk.as_mut_ptr(), sk.as_mut_ptr(), seed.as_ptr()) };

			(pk, sk)
		}).collect();

		let pks: Vec<*const u8> = ref_keys.iter().map(|kp| kp.0.as_ptr()).collect();
		let ctds = vec![vec![0u8; MKEM_CTDBYTES]; ref_keys.len()];
		let mut cti = vec![0u8; MKEM_CTIBYTES];
		let mut ref_ss = vec![0u8; MKEM_SSBYTES];
		let mut ctds_ptrs: Vec<*mut u8> = ctds.iter().map(|c| c.as_ptr() as *mut u8).collect();
		
		unsafe { mkem_enc(ctds_ptrs.as_mut_ptr(), cti.as_mut_ptr(), ref_ss.as_mut_ptr(), seed.as_ptr(), pks.as_ptr(), pks.len()) };

		// decapsulation suceeds with the right keys
		ref_keys.iter().enumerate().for_each(|(idx, kp)| {
			let mut ss = vec![0u8; MKEM_SSBYTES];

			unsafe { mkem_dec(ss.as_mut_ptr(), cti.as_ptr(), ctds[idx].as_ptr(), seed.as_ptr(), kp.0.as_ptr(), kp.1.as_ptr()) };
			assert_eq!(ss, ref_ss);
		});

		let wrong_keys: Vec<(Vec<u8>, Vec<u8>)> = (0..n_keys).map(|_| {
			let mut pk = vec![0; MKEM_PUBLICKEYBYTES];
			let mut sk = vec![0; MKEM_SECRETKEYBYTES];

			unsafe { mkem_keypair(pk.as_mut_ptr(), sk.as_mut_ptr(), seed.as_ptr()) };

			(pk, sk)
		}).collect();
		
		// but fails with the wrong keys
		wrong_keys.iter().enumerate().for_each(|(idx, kp)| {
			let mut ss = vec![0u8; MKEM_SSBYTES];

			unsafe { mkem_dec(ss.as_mut_ptr(), cti.as_ptr(), ctds[idx].as_ptr(), seed.as_ptr(), kp.0.as_ptr(), kp.1.as_ptr()) };
			assert_ne!(ss, ref_ss);
		});

		// as well as with mismatched pk-sk pairs
		wrong_keys.iter().enumerate().for_each(|(idx, kp)| {
			let mut ss = vec![0u8; MKEM_SSBYTES];

			unsafe { mkem_dec(ss.as_mut_ptr(), cti.as_ptr(), ctds[idx].as_ptr(), seed.as_ptr(), ref_keys[idx].0.as_ptr(), kp.1.as_ptr()) };
			assert_ne!(ss, ref_ss);

			ss = vec![0u8; MKEM_SSBYTES];

			unsafe { mkem_dec(ss.as_mut_ptr(), cti.as_ptr(), ctds[idx].as_ptr(), seed.as_ptr(), kp.0.as_ptr(), ref_keys[idx].1.as_ptr()) };
			assert_ne!(ss, ref_ss);
		});
	}
}