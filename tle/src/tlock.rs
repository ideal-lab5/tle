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
use crate::{
	ibe::fullident::{Ciphertext as IBECiphertext, IBESecret, Identity},
	stream_ciphers::StreamCipherProvider,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use ark_std::{
	rand::{CryptoRng, Rng},
	vec::Vec,
};

use w3f_bls::EngineBLS;

/// a secret key used for encryption/decryption
pub type OpaqueSecretKey = [u8; 32];

#[derive(CanonicalDeserialize, CanonicalSerialize, Debug)]
pub struct TLECiphertext<E: EngineBLS> {
	/// The header holds the IBE encrypted key
	pub header: IBECiphertext<E>,
	/// The body holds the message encrypted with a stream cipher
	pub body: Vec<u8>,
	/// The cipher suite used
	pub cipher_suite: Vec<u8>,
}

/// Errors that may occur while execute timelock encryption/decryption
#[derive(Debug, PartialEq)]
pub enum Error {
	/// The message could not be encrypted with the provided cipher
	MessageEncryptionError,
	/// The type could not be deserialized
	DeserializationError,
	/// The type could not be deserialized to an element of G1
	DeserializationErrorG1,
	/// The type could not be deserialized to an element of G2
	DeserializationErrorG2,
	/// The type could not be deserialized to a field element
	DeserializationErrorFr,
	/// The ciphertext could not be decrypted
	DecryptionError,
	/// The signature is invalid
	InvalidSignature,
	/// The secret key is not well-formed (must be 32 bytes)
	InvalidSecretKey,
}

/// encrypt a message for an identity
///
///
/// * `p_pub`: the public key commitment for the IBE system (i.e. the setup
///   phase)
/// * `message`: The message to encrypt
/// * `id`: the identity to encrypt for
/// * `rng`: a CSPRNG
///
pub fn tle<E, S, R>(
	p_pub: E::PublicKeyGroup,
	secret_key: OpaqueSecretKey,
	message: &[u8],
	id: Identity,
	mut rng: R,
) -> Result<TLECiphertext<E>, Error>
where
	E: EngineBLS,
	S: StreamCipherProvider<32>,
	R: Rng + CryptoRng,
{
	// IBE encryption 'to the future'
	let header: IBECiphertext<E> = id.encrypt(&secret_key, p_pub, &mut rng);
	// encrypt arbitrary-length messages with a stream cipher
	let body = S::encrypt(message, secret_key, &mut rng)
		.map_err(|_| Error::MessageEncryptionError)?; // not sure how to test this line...
	let mut message_bytes = Vec::new();
	body.serialize_compressed(&mut message_bytes).unwrap(); // TODO

	Ok(TLECiphertext {
		header,
		body: message_bytes,
		cipher_suite: S::CIPHER_SUITE.to_vec(),
	})
}

/// decrypt a ciphertext created as a result of timelock encryption
/// the signature should be equivalent to the output of IBE.Extract(ID)
/// where ID is the identity for which the message was created
///
/// * `ciphertext`: A TLECiphertext encrypted under some supported protocol
/// * `signature`: A BLS signature that allows decryption of the ciphertext
///
pub fn tld<E, S>(
	ciphertext: TLECiphertext<E>,
	signature: E::SignatureGroup,
) -> Result<Vec<u8>, Error>
where
	E: EngineBLS,
	S: StreamCipherProvider<32>,
{
	// IBE decrypt the secret key
	let secret_bytes = IBESecret(signature)
		.decrypt(&ciphertext.header)
		.map_err(|_| Error::InvalidSignature)?;
	// ensure we recovered a valid sized secret
	let secret_array: [u8; 32] =
		secret_bytes.clone().try_into().map_err(|_| Error::InvalidSecretKey)?;

	let ct = S::Ciphertext::deserialize_compressed(
		&mut &ciphertext.body.clone()[..],
	)
	.map_err(|_| Error::DeserializationError)?;

	return S::decrypt(ct, secret_array).map_err(|_| Error::DecryptionError);
}

#[cfg(test)]
mod test {

	use super::*;
	use crate::{
		curves::drand::TinyBLS381, 
		stream_ciphers::{AESGCMStreamCipherProvider, AESOutput},
	};
	use alloc::vec;
	use ark_ec::Group;
	use ark_ff::UniformRand;
	use rand_chacha::ChaCha20Rng;
	use rand_core::{OsRng, SeedableRng};
	use sha2::Digest;
	use w3f_bls::TinyBLS377;

	// specific conditions that we want to test/verify
	enum TestStatusReport {
		DecryptSuccess { actual: Vec<u8>, expected: Vec<u8> },
		DecryptionFailed { error: Error },
	}

	// tlock test aes_gcm 256
	fn tlock_test<E: EngineBLS, R: Rng + Sized + CryptoRng>(
		inject_bad_ct: bool,
		inject_bad_nonce: bool,
		handler: &dyn Fn(TestStatusReport) -> (),
	) {
		let message = b"this is a test message".to_vec();
		let id = Identity::new(b"", vec![b"id".to_vec()]);
		let sk = E::Scalar::rand(&mut OsRng);
		let p_pub = E::PublicKeyGroup::generator() * sk;

		// key used for aes encryption
		let msk = [1; 32];

		let sig: E::SignatureGroup = id.extract::<E>(sk).0;

		match tle::<E, AESGCMStreamCipherProvider, OsRng>(
			p_pub, msk, &message, id, OsRng,
		) {
			Ok(mut ct) => {
				// create error scenarios here
				if inject_bad_ct {
					let mut output =
						AESOutput::deserialize_compressed(&mut &ct.body[..])
							.unwrap();
					output.ciphertext = vec![];
					let mut corrupted = Vec::new();
					output.serialize_compressed(&mut corrupted).unwrap();
					ct.body = corrupted;
				}

				if inject_bad_nonce {
					let mut output =
						AESOutput::deserialize_compressed(&mut &ct.body[..])
							.unwrap();
					output.nonce = vec![];
					let mut corrupted = Vec::new();
					output.serialize_compressed(&mut corrupted).unwrap();
					ct.body = corrupted;
				}

				match tld::<E, AESGCMStreamCipherProvider>(ct, sig) {
					Ok(output) => {
						handler(TestStatusReport::DecryptSuccess {
							actual: output,
							expected: message,
						});
					},
					Err(e) => {
						handler(TestStatusReport::DecryptionFailed {
							error: e,
						});
					},
				}
			},
			Err(_) => {
				panic!("The test should pass but failed to run tlock encrypt");
			},
		}
	}

	#[test]
	pub fn tlock_can_encrypt_decrypt_with_single_sig() {
		tlock_test::<TinyBLS377, OsRng>(
			false,
			false,
			&|status: TestStatusReport| match status {
				TestStatusReport::DecryptSuccess { actual, expected } => {
					assert_eq!(actual, expected);
				},
				_ => panic!("all other conditions invalid"),
			},
		);
	}

	#[test]
	pub fn tlock_can_encrypt_decrypt_with_full_sigs_present() {
		tlock_test::<TinyBLS377, OsRng>(
			false,
			false,
			&|status: TestStatusReport| match status {
				TestStatusReport::DecryptSuccess { actual, expected } => {
					assert_eq!(actual, expected);
				},
				_ => panic!("all other conditions invalid"),
			},
		);
	}

	#[test]
	pub fn tlock_can_encrypt_decrypt_with_many_identities_at_threshold() {
		tlock_test::<TinyBLS377, OsRng>(
			false,
			false,
			&|status: TestStatusReport| match status {
				TestStatusReport::DecryptSuccess { actual, expected } => {
					assert_eq!(actual, expected);
				},
				_ => panic!("all other conditions invalid"),
			},
		);
	}

	#[test]
	pub fn tlock_decryption_fails_with_bad_ciphertext() {
		tlock_test::<TinyBLS377, OsRng>(
			true,
			false,
			&|status: TestStatusReport| match status {
				TestStatusReport::DecryptionFailed { error } => {
					assert_eq!(error, Error::DecryptionError);
				},
				_ => panic!("all other conditions invalid"),
			},
		);
	}

	#[test]
	pub fn tlock_decryption_fails_with_bad_nonce() {
		tlock_test::<TinyBLS377, OsRng>(
			false,
			true,
			&|status: TestStatusReport| match status {
				TestStatusReport::DecryptionFailed { error } => {
					assert_eq!(error, Error::DecryptionError);
				},
				_ => panic!("all other conditions invalid"),
			},
		);
	}

	#[test]
	pub fn tlock_encrypt_decrypt_drand_quicknet_works() {
		// using a pulse from drand's QuickNet
		// https://api.drand.sh/52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971/public/1000
		// the beacon public key
		let pk_bytes =
	b"83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a"
	; // a round number that we know a signature for
		let round: u64 = 1000;
		// the signature produced in that round
		let signature =
	b"b44679b9a59af2ec876b1a6b1ad52ea9b1615fc3982b19576350f93447cb1125e342b73a8dd2bacbe47e4b6b63ed5e39"
	;

		// Convert hex string to bytes
		let pub_key_bytes = hex::decode(pk_bytes).expect("Decoding failed");
		// Deserialize to G1Affine
		let pub_key =
			<TinyBLS381 as EngineBLS>::PublicKeyGroup::deserialize_compressed(
				&*pub_key_bytes,
			)
			.unwrap();

		// then we tlock a message for the pubkey
		let plaintext = b"this is a test".as_slice();
		let esk = [2; 32];

		let sig_bytes = hex::decode(signature)
			.expect("The signature should be well formatted");
		let sig =
			<TinyBLS381 as EngineBLS>::SignatureGroup::deserialize_compressed(
				&*sig_bytes,
			)
			.unwrap();

		let message = {
			let mut hasher = sha2::Sha256::new();
			hasher.update(round.to_be_bytes());
			hasher.finalize().to_vec()
		};

		let identity = Identity::new(b"", vec![message]);

		let rng = ChaCha20Rng::seed_from_u64(0);
		let ct = tle::<TinyBLS381, AESGCMStreamCipherProvider, ChaCha20Rng>(
			pub_key, esk, plaintext, identity, rng,
		)
		.unwrap();

		// then we can decrypt the ciphertext using the signature
		let result =
			tld::<TinyBLS381, AESGCMStreamCipherProvider>(ct, sig).unwrap();
		assert!(result == plaintext);
	}
}
