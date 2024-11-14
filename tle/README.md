# Timelock Encryption

This library enables timelock encryption using the Boneh-Franklin IBE scheme. Specifically, it allows timelock encryption to be instantiated on top of a verifiable randomness beacon, such as the [Ideal Network](https://docs.idealabs.network) or [drand](https://drand.love). The library is implemented with [arkworks](https://github.com/arkworks-rs)

Currently the scheme supports several flavors of beacons, including the Drand 'quicknet', which uses BLS381 keys, and the Ideal Network beacon, which uses BLS377 keys. Both beacons use a BLS variant with tiny 48 byte signatures and 96 byte public keys, with signatures being elements of $\mathbb{G}_1$ and public keys in $\mathbb{G}_2$. 

This flavor of timelock encryption is a hybrid encryption scheme, using `AES_GCM` to efficiently encrypt and decrypt and size ciphertexts, while secret keys are encrypted for identities of future beacon pulses.

## Usage

The library is flexible and can support various flavors of encryption schemes. Officially, only AES_GCM is supported at the moment, but we will support AGE encryption within the library in the near future. You can implement your own by implementing the `StreamCipherProvider` trait.

### Encrypt a Message

This is an example of using the Ideal Network beacon to encrypt message. This same can be accomplished against Drand's quicknet. See the tlock tests [here](./src/tlock.rs) for more examples.

``` rust
// gather public parameters for the randomenss beacon
let pk = hex::decode("471ba929a4e2ef2790fb5f2a65ebe86598a28cbb8a58e49c6cc7292cf40cecbdf10152394ba938367ded5355ae373e01a99567467bc816864774e84b984fc16e2ae2232be6481cd4db0e378e1d6b0c2265d2aa8e0fa4e2c76958ce9f12df8e0134c431c181308a68b94b9cfba5176c3a8dd22ead9a68a077ecce7facfe4adb9e0e0a71c94a0c436d8049b03fa5352301").expect("decoding failure");
let p_pub = <TinyBLS377 as EngineBLS>::deserialize_compressed(&*pk).unwrap();
// construct an identity
// choose a future round number of the randomness beacon
let round_number: u64 = 10;
let identity = Identity::new(b"", vec![round_number.to_be_bytes()]);
// generate an ephemeral secret key 32-byte secret key
let esk = [2;32];
// encrypt using the identity
let ct = tle::<TinyBLS377, AESGCMStreamCipherProvider, OsRng>::(p_pub, msk, &message, id, OsRng).unwrap();
```

### Decrypt a Message

#### Early decryption
Message can be encrypted at any time using the ephemeral secret key used to encrypt it:
``` rust
// use the same esk as in `encrypt`
let early_result = ct.aes_decrypt(esk).unwrap();
```

#### Timelock Decryption
Messages can also be decrypted with a signature produced by a beacon on top of the 'identity' used to construct it:
``` rust
// first get a valid siganture from the beacon
let signature =	hex::decode(b"f8178b1c3c9477f7b0e37cd3e63ff3a184e1d05df3117438cd05e109b5731a52a96ae344e461bc6cb8e04f5efed34701").expect("decoding failure");
let result: DecryptionResult = ct.tld(sig).unwrap();
```

## Build

From the root, run `cargo build`

## Test


### Unit tests
From the root, run `cargo test`

### Coverage
We use [tarpaulin](https://github.com/xd009642/tarpaulin) for test coverage. From the root, run:

```
cargo tarpaulin --rustflags="-C opt-level=0"
```

### Benchmarks

``` shell
cargo benchmark
```
