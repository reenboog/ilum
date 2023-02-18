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
}
