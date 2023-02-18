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
	pub fn mkem_dec(ss: *mut u8, cti: *const u8, ctd: *const u8, group: *const u8, pk: *const u8, sk: *const u8);
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
	fn test_encrypt_decrypt() {
		let mut seed = vec![0; MKEM_GROUPBYTES];

		unsafe { mkem_group(seed.as_mut_ptr()); }

		let keys: Vec<(Vec<u8>, Vec<u8>)> = (0..5).map(|_| {
			let mut pk = vec![0; MKEM_PUBLICKEYBYTES];
			let mut sk = vec![0; MKEM_SECRETKEYBYTES];

			unsafe { mkem_keypair(pk.as_mut_ptr(), sk.as_mut_ptr(), seed.as_ptr()) };

			(pk, sk)
		}).collect();

		let pks: Vec<*const u8> = keys.iter().map(|kp| kp.0.as_ptr()).collect();
		let ctds = vec![vec![0u8; MKEM_CTDBYTES]; keys.len()];
		let mut cti = vec![0u8; MKEM_CTIBYTES];
		let mut ss_ref = vec![0u8; MKEM_SSBYTES];

		let mut ctds_ptrs: Vec<*mut u8> = ctds.iter().map(|c| c.as_ptr() as *mut u8).collect();
		
		unsafe { mkem_enc(ctds_ptrs.as_mut_ptr(), cti.as_mut_ptr(), ss_ref.as_mut_ptr(), seed.as_mut_ptr(), pks.as_ptr(), pks.len()) };

		keys.iter().enumerate().for_each(|(idx, kp)| {
			let mut ss = vec![0u8; MKEM_SSBYTES];

			unsafe { mkem_dec(ss.as_mut_ptr(), cti.as_ptr(), ctds[idx].as_ptr(), seed.as_ptr(), kp.0.as_ptr(), kp.1.as_ptr()) };

			assert_eq!(ss, ss_ref);
		})
	}
}
