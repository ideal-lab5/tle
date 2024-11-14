/*
 * Copyright 2024 by Ideal Labs, LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use alloc::borrow::ToOwned;
use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;
use ark_std::vec::Vec;
use sha2::Digest;
use w3f_bls::EngineBLS;

/// sha256 hasher
pub fn sha256(b: &[u8]) -> Vec<u8> {
	let mut hasher = sha2::Sha256::new();
	hasher.update(b);
	hasher.finalize().to_vec()
}

// TODO: can do this in place instead
pub fn cross_product_32(a: &[u8], b: &[u8]) -> Vec<u8> {
	let mut o = a.to_owned();
	for (i, ri) in o.iter_mut().enumerate().take(32) {
		*ri ^= b[i];
	}
	o.to_vec()
}

/// a map from G -> {0, 1}^{32}
pub fn h2<G: CanonicalSerialize>(g: G) -> Vec<u8> {
	// let mut out = Vec::with_capacity(g.compressed_size());
	let mut out = Vec::new();
	g.serialize_compressed(&mut out)
		.expect("Enough space has been allocated in the buffer");
	sha256(&out)
}

// Should add a const to the signature so I can enforce sized inputs?
// right now this works with any size slices
/// H_3: {0,1}^n x {0, 1}^m -> Z_p
pub fn h3<E: EngineBLS>(a: &[u8], b: &[u8]) -> E::Scalar {
	let mut input = Vec::new();
	input.extend_from_slice(a);
	input.extend_from_slice(b);
	let hash = sha256(&input);
	E::Scalar::from_be_bytes_mod_order(&hash)
}

/// H_4: {0, 1}^n -> {0, 1}^n
pub fn h4(a: &[u8]) -> Vec<u8> {
	let o = sha256(a);
	o[..a.len()].to_vec()
}

#[cfg(test)]
mod test {

	use alloc::vec;

	#[test]
	fn utils_can_calc_sha256() {
		let actual = crate::ibe::utils::sha256(b"test");
		let expected = vec![
			159, 134, 208, 129, 136, 76, 125, 101, 154, 47, 234, 160, 197, 90,
			208, 21, 163, 191, 79, 27, 43, 11, 130, 44, 209, 93, 108, 21, 176,
			240, 10, 8,
		];
		assert_eq!(actual, expected);
	}
}
