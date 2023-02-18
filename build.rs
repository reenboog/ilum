use std::env;
use std::path::PathBuf;

extern crate cc;

fn main() {
	let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

	cc::Build::new()
		.flag("-Wall")
		.flag("-Wextra")
		.flag("-Wpedantic")
		.flag("-Wmissing-prototypes")
		.flag("-Wredundant-decls")
		.flag("-Wshadow")
		.flag("-Wpointer-arith")
		.flag("-fomit-frame-pointer")
		.flag("-fPIC")
		.flag("-DKYBER_K=2 ")
		.file("c/cbd.c")
		.file("c/indcpa.c")
		.file("c/kem.c")
		.file("c/kex.c")
		.file("c/mkem.c")
		.file("c/ntt.c")
		.file("c/poly.c")
		.file("c/polyvec.c")
		.file("c/reduce.c")
		.file("c/symmetric-shake.c")
		.file("c/randombytes.c")

		.file("c/fips202.c")
		.file("c/verify.c")
		.compile("ilum");

	println!("cargo:rustc-link-search=native={}", out_dir.display());
	println!("cargo:rustc-link-lib=static=ilum");
}