
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

use ark_ff::{UniformRand, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_ec::Group;
use ark_std::{
    ops::Mul,
    rand::Rng,
};
use ark_std::vec::Vec;
use serde::{Deserialize, Serialize};
use super::utils::{h2, h3, h4, cross_product_32};

use w3f_bls::{EngineBLS, Message};

/// represents a ciphertext in the BF-IBE FullIdent scheme
#[derive(Debug, Clone, PartialEq, CanonicalDeserialize, CanonicalSerialize, Serialize, Deserialize)]
pub struct IBECiphertext<E: EngineBLS> {
    /// U = rP
    pub u: E::PublicKeyGroup,
    /// V = sigma (+) H_2(g_id^r)
    pub v: Vec<u8>,
    /// W = message (+) H_4(sigma)
    pub w: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum IbeError {
    DecryptionFailed,
}

/// A type to represent an IBE identity (for which we will encrypt message)
#[derive(Debug, Clone)]
pub struct Identity(pub Vec<Message>);

impl Identity {

    /// construct a new identity from a string
    pub fn new(ctx: &[u8], identities: Vec<Vec<u8>>) -> Self {
        Self (
            identities.iter()
                .map(|identity| Message::new(ctx, &identity))
                .collect::<Vec<_>>()
            )
    }

    /// the IBE extract function on a given secret key 
    pub fn extract<E: EngineBLS>(&self, sk: E::Scalar) -> IBESecret<E> {
        IBESecret(self.public::<E>() * sk)
    }

    /// derive the public key for this identity (hash to G1)
    pub fn public<E: EngineBLS>(&self) -> E::SignatureGroup {
        self.0.iter()
            .map(|message| message.hash_to_signature_curve::<E>())
            .fold(E::SignatureGroup::zero(), |acc, val| acc + val)

    }

    /// BF-IBE encryption 
    /// For a message with 32-bytes and a public key (in G2), calculates the BF-IBE ciphertext
    ///
    /// C = <U, V, W> = <rP, sigma (+) H_2(g_{ID}^r, message (+) H_4(sigma))>
    /// where r is randomly selected from the finite field (Z_p) and g_{ID} = e(Q_ID, P_pub)
    ///
    pub fn encrypt<E, R>(
        &self,
        message: &[u8;32],
        p_pub: E::PublicKeyGroup,
        mut rng: R
    ) -> IBECiphertext<E> 
    where E: EngineBLS, R: Rng + Sized {
        let t = E::Scalar::rand(&mut rng);
        let mut t_bytes = Vec::new();
        t.serialize_compressed(&mut t_bytes)
            .expect("compressed size has been allocated");
        let sigma = h4(&t_bytes);
        // r= H3(sigma, message)
        let r: E::Scalar = h3::<E>(&sigma, message);
        let p = <<E as EngineBLS>::PublicKeyGroup as Group>::generator();
        // U = rP \in \mathbb{G}_1
        let u = p * r; 
        // e(P_pub, Q_id)
        let g_id = E::pairing(p_pub.mul(r), self.public::<E>());
        // sigma (+) H2(e(P_pub, Q_id))
        let v_rhs = h2(g_id);
        let v_out = cross_product_32(&sigma, &v_rhs);
        // message (+) H4(sigma)
        let w_rhs = h4(&sigma);
        let w_out = cross_product_32(message, &w_rhs);
        // (rP, sigma (+) H2(e(Q_id, P_pub)), message (+) H4(sigma))
        IBECiphertext::<E> {
            u,
            v: v_out.to_vec(), 
            w: w_out.to_vec(),
        }
    }
}

/// The output of the IBE extract algorithm is a BLS signature
#[derive(Debug, Clone, CanonicalDeserialize, CanonicalSerialize, Serialize, Deserialize)]
pub struct IBESecret<E: EngineBLS>(pub E::SignatureGroup);

impl<E: EngineBLS> IBESecret<E> {
    /// BF-IBE decryption of a ciphertext C = <U, V, W>  
    /// Attempts to decrypt under the given IBESecret (in G1)
    pub fn decrypt(
        &self, 
        ciphertext: &IBECiphertext<E>,
    ) -> Result<Vec<u8>, IbeError> {
        // sigma = V (+) H2(e(d_id, U))
        let sigma_rhs = h2(E::pairing(ciphertext.u, self.0));
        let sigma = cross_product_32(&ciphertext.v, &sigma_rhs);
        // m = W (+) H4(sigma)
        let m_rhs = h4(&sigma);
        let m = cross_product_32(&ciphertext.w, &m_rhs);
        // check: U == rP
        let p = <<E as EngineBLS>::PublicKeyGroup as Group>::generator();
        let r = h3::<E>(&sigma, &m);
        let u_check = p * r;
        
        if !u_check.eq(&ciphertext.u) {
            return Err(IbeError::DecryptionFailed);
        }

        Ok(m)
    }
}

#[cfg(test)]
mod test {

    use super::*;
    use alloc::vec;
    use ark_std::{test_rng, UniformRand};
    use w3f_bls::TinyBLS377;
    
    // this enum represents the conditions or branches that I want to test
    enum TestStatusReport {
        DecryptionResult { data: Vec<u8>, verify: Vec<u8> },
        DecryptionFailure{ error: IbeError }
    }

    fn run_test<EB: EngineBLS>(
        identity: Identity,
        message: [u8;32],
        derive_bad_sk: bool,
        insert_bad_ciphertext: bool,
        handler: &dyn Fn(TestStatusReport) -> ()
    ) {
        let (msk, sk) = extract::<EB>(identity.clone(), derive_bad_sk);

        let p_pub = <<EB as EngineBLS>::PublicKeyGroup as Group>::generator() * msk;

        let mut ct = IBECiphertext {
            u: EB::PublicKeyGroup::generator(),
            v: vec![],
            w: vec![],
        };

        if !insert_bad_ciphertext {
            ct = identity.encrypt(&message, p_pub, &mut test_rng());
        }

        match sk.decrypt(&ct) {
            Ok(data) => {
                handler(TestStatusReport::DecryptionResult{ data, verify: message.to_vec() });
            },
            Err(e) => {
                handler(TestStatusReport::DecryptionFailure{ error: e });
            }
        }
    }

    fn extract<E: EngineBLS>(
        identity: Identity,
        derive_bad_sk: bool,
    ) -> (E::Scalar, IBESecret<E>) {
        let msk = <E as EngineBLS>::Scalar::rand(&mut test_rng());
        if derive_bad_sk {
            return (msk, IBESecret(E::SignatureGroup::generator()))
        }

        let sk = identity.extract::<E>(msk);
        (msk, sk)
    }

    #[test]
    pub fn fullident_identity_construction_works() {
        let id_string = b"example@test.com";
        let identity = Identity::new(b"", vec![id_string.to_vec()]);
        
        let expected_message = Message::new(b"", id_string);
        assert_eq!(identity.0[0], expected_message);
    }

    #[test]
    pub fn fullident_encrypt_and_decrypt() {
        let id_string = b"example@test.com";
        let identity = Identity::new(b"", vec![id_string.to_vec()]);
        let message: [u8;32] = [2;32];

        run_test::<TinyBLS377>(
            identity, message, false, false,
            &|status: TestStatusReport| {
            match status {
                TestStatusReport::DecryptionResult{ data, verify } => {
                    assert_eq!(data, verify);
                },
                _ => 
                    panic!("Decryption should work"),
            }
        });
    }

    #[test]
    pub fn fullident_decryption_fails_with_bad_ciphertext() {
        let id_string = b"example@test.com";
        let identity = Identity::new(b"", vec![id_string.to_vec()]);
        let message: [u8;32] = [2;32];

        run_test::<TinyBLS377>(
            identity,
            message, 
            false,
            true,
            &|status: TestStatusReport| {
            match status {
                TestStatusReport::DecryptionFailure{ error } => {
                    assert_eq!(error, IbeError::DecryptionFailed);
                },
                _ => panic!("all other conditions invalid"),
            }
        });
    }

    #[test]
    pub fn fullident_decryption_fails_with_bad_key() {
        let id_string = b"example@test.com";
        let identity = Identity::new(b"", vec![id_string.to_vec()]);
        let message: [u8;32] = [2;32];

        run_test::<TinyBLS377>(
            identity, message, true, false,
            &|status: TestStatusReport| {
            match status {
                TestStatusReport::DecryptionFailure{ error } => {
                    assert_eq!(error, IbeError::DecryptionFailed);
                },
                _ => panic!("all other conditions invalid"),
            }
        });
    }
}