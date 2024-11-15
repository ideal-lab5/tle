# Identity Based Encryption

This module contains an impementation of the [Boneh-Franklin Identity Based Encryption](https://crypto.stanford.edu/~dabo/papers/bfibe.pdf) "FullIdent" scheme. The protocol enables secure message encryption and decryption based on identities. It uses elliptic-curve cryptography (BLS signatures) and is implemented with the [arkworks library](https://github.com/arkworks-rs) and [w3f/bls](https://github.com/w3f/bls).

## Usage

Below is an example of encrypting a message for an identity and subsequently decrypting a message using a secret key 'extracted' from the identity. 

``` rust
use bf_ibe::{Identity, Ciphertext, IBESecret};
use w3f_bls::TinyBLS377;
use ark_std::test_rng;

// Create an identity
let id_string = b"example@test.com";
let identity = Identity::new(b"", vec![id_string.to_vec()]);

// Generate a message
let message: [u8; 32] = [1; 32];

// Create master secret and public key
let msk = <TinyBLS377 as EngineBLS>::Scalar::rand(&mut test_rng());
let p_pub = <<TinyBLS377 as EngineBLS>::PublicKeyGroup as Group>::generator() * msk;

// Encrypt the message
let ciphertext = identity.encrypt(&message, p_pub, &mut test_rng());

// "Extract" a secret key
let sk = identity.extract::<TinyBLS377>(msk);
// Decrypt the message
let decrypted_message = sk.decrypt(&ciphertext).expect("Decryption failed");

// Verify
assert_eq!(message.to_vec(), decrypted_message);
```

## License 
Apache-2.0