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

use aes_gcm::{
    aead::{Aead, AeadCore, AeadInPlace, KeyInit},
    Aes256Gcm, Nonce,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::Rng;

use serde::{Deserialize, Serialize};

use ark_std::rand::CryptoRng;
use ark_std::vec::Vec;

/// The output of AES Encryption plus the ephemeral secret key
#[derive(Serialize, Deserialize, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct AESOutput {
    /// the AES ciphertext
    pub ciphertext: Vec<u8>,
    /// the AES nonce
    pub nonce: Vec<u8>,
    pub key: Vec<u8>,
}

#[derive(Debug, PartialEq)]
pub enum Error {
    CiphertextTooLarge,
    EncryptionError,
    DecryptionError,
    InvalidKey,
    BadNonce,
}

/// AES-GCM encryption of the message using an ephemeral keypair
/// basically a wrapper around the AEADs library to handle serialization
///
/// * `message`: The message to encrypt
///
pub fn encrypt<R: Rng + CryptoRng + Sized>(
    message: &[u8], 
    key: [u8;32], 
    mut rng: R,
) -> Result<AESOutput, Error> {
    let cipher = Aes256Gcm::new(generic_array::GenericArray::from_slice(&key));
    let nonce = Aes256Gcm::generate_nonce(&mut rng); // 96-bits; unique per message

    let mut buffer: Vec<u8> = Vec::new(); // Note: buffer needs 16-bytes overhead for auth tag
    buffer.extend_from_slice(message);
    // Encrypt `buffer` in-place, replacing the plaintext contents with ciphertext
    // will this error ever be thrown here? nonces should always be valid as well as buffer
    cipher.encrypt_in_place(&nonce, b"", &mut buffer)
        .map_err(|_| Error::CiphertextTooLarge)?;
    Ok(AESOutput{
        ciphertext: buffer,
        nonce: nonce.to_vec(),
        key: key.to_vec(), // TODO: remove key from AESOutput struct
    })
}

/// AES-GCM decryption
///
/// * `ciphertext`: the ciphertext to decrypt
/// * `nonce`: the nonce used on encryption
/// * `key`: the key used for encryption
///
pub fn decrypt(
    ct: AESOutput,
) -> Result<Vec<u8>, Error> {
    let cipher = Aes256Gcm::new_from_slice(&ct.key)
        .map_err(|_| Error::InvalidKey)?;
    // lets check the nonce... not great way to do it but ok for now
    // TODO:get a valid nonce size as a constant
    if ct.nonce.len() != 12 {
        return Err(Error::BadNonce);
    }
    let nonce = Nonce::from_slice(&ct.nonce);
    let plaintext = cipher.decrypt(nonce, ct.ciphertext.as_ref())
        .map_err(|_| Error::DecryptionError)?;
    Ok(plaintext)
}

#[cfg(test)]
mod test {
    use super::*;
    use alloc::vec;
    use ark_std::rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    #[test]
    pub fn aes_encrypt_decrypt_works() {
        let msg = b"test";
        let rng = ChaCha20Rng::from_seed([2;32]);
        match encrypt(msg, [2;32], rng) {
            Ok(aes_out) => {
                match decrypt(aes_out) {
                    Ok(plaintext) => {
                        assert_eq!(msg.to_vec(), plaintext);
                    }, 
                    Err(_) => {
                        panic!("test should pass");
                    }
                }
            },
            Err(_) => {
                panic!("test should pass");
            }
        }
    }

    #[test]
    pub fn aes_encrypt_decrypt_fails_with_bad_key() {
        let msg = b"test";
        let rng = ChaCha20Rng::from_seed([1;32]);
        match encrypt(msg, [2;32], rng) {
            Ok(aes_out) => {
                let bad = AESOutput {
                    ciphertext: aes_out.ciphertext,
                    nonce: aes_out.nonce, 
                    key: b"hi".to_vec(),
                };
                match decrypt(bad) {
                    Ok(_) => {
                        panic!("should be an error");
                    }, 
                    Err(e) => {
                        assert_eq!(e, Error::InvalidKey);
                    }
                }
            },
            Err(_) => {
                panic!("test should pass");
            }
        }
    }
     
    #[test]
    pub fn aes_encrypt_decrypt_fails_with_invalid_nonce() {
        let msg = b"test";
        let rng = ChaCha20Rng::from_seed([3;32]);
        match encrypt(msg, [2;32], rng) {
            Ok(aes_out) => {
                let bad = AESOutput {
                    ciphertext: aes_out.ciphertext,
                    nonce: vec![0,0,0,0,0,0,0,0,0,0,0,0], 
                    key: aes_out.key,
                };
                match decrypt(bad) {
                    Ok(_) => {
                        panic!("should be an error");
                    }, 
                    Err(e) => {
                        assert_eq!(e, Error::DecryptionError);
                    }
                }
            },
            Err(_) => {
                panic!("test should pass");
            }
        }
    }

    #[test]
    pub fn aes_encrypt_decrypt_fails_with_bad_length_nonce() {
        let msg = b"test";
        let rng = ChaCha20Rng::from_seed([3;32]);
        match encrypt(msg, [2;32], rng) {
            Ok(aes_out) => {
                let bad = AESOutput {
                    ciphertext: aes_out.ciphertext,
                    nonce: vec![0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0], 
                    key: aes_out.key,
                };
                match decrypt(bad) {
                    Ok(_) => {
                        panic!("should be an error");
                    }, 
                    Err(e) => {
                        assert_eq!(e, Error::BadNonce);
                    }
                }
            },
            Err(_) => {
                panic!("test should pass");
            }
        }
    }
}