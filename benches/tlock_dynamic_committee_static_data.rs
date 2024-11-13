use criterion::{
    black_box, criterion_group, criterion_main,
    Criterion, BenchmarkId, Throughput
};
use ark_ff::UniformRand;
use w3f_bls::{EngineBLS, TinyBLS377};
use etf_crypto_primitives::encryption::tlock::*;
use etf_crypto_primitives::ibe::fullident::*;
use rand_core::OsRng;
use ark_ec::Group;

/// encrypts a message for the identity and then performs decryption on threshold sigs
/// represents the worst case scenario where the threshold equals the size of the committee
fn tlock_tinybls377<E: EngineBLS>(
    msk: SecretKey<E>,
    p_pub: E::PublicKeyGroup,
    message: Vec<u8>,
    id: Identity,
    sigs: Vec<IBESecret<E>>,
) {
    let ct = msk.encrypt(p_pub, &message, id.clone(), &mut OsRng).unwrap();
    let _m = ct.decrypt(sigs).unwrap();
}

fn tlock_dynamic_commitee_static_data(c: &mut Criterion) {
    static KB: usize = 1024;
    let id = Identity::new(b"", vec![b"test".to_vec()]);

    let mut group = c.benchmark_group("tlock_dynamic_commitee_static_data");
    for size in [3, 5, 10, 20, 50, 100].iter() {

        let (round_secret, shares) = generate_secrets::<TinyBLS377, OsRng>(*size as u8, *size as u8, &mut OsRng);
        let p_pub = <TinyBLS377 as EngineBLS>::PublicKeyGroup::generator() * round_secret;
        let msk = <TinyBLS377 as EngineBLS>::Scalar::rand(&mut OsRng);

        let mut dummy_data = Vec::with_capacity(KB);
        (0..KB).for_each(|i| dummy_data.push(i as u8));

        group.throughput(Throughput::Bytes(KB as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
            b.iter(|| {
                tlock_tinybls377(
                    black_box(SecretKey::<TinyBLS377>::new(msk)), 
                    black_box(p_pub),
                    black_box(dummy_data.clone()),
                    black_box(id.clone()),
                    black_box(shares.iter().map(|share| id.extract(share.1)).collect()),
                );
            });
        });
    }
    group.finish();
}

criterion_group!(benches, tlock_dynamic_commitee_static_data);
criterion_main!(benches);
