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

/// encrypts a message for the identity and then decrypts it after preparing a bls sig
/// this expects on a single signature but tests many different input data sizes
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

fn tlock_single_commitee_dynamic_data(c: &mut Criterion) {
    static KB: usize = 1024;   

    let s = <TinyBLS377 as EngineBLS>::Scalar::rand(&mut OsRng);
    let p_pub = <TinyBLS377 as EngineBLS>::PublicKeyGroup::generator() * s;
    let id = Identity::new(b"", vec![b"test".to_vec()]);
    let msk = <TinyBLS377 as EngineBLS>::Scalar::rand(&mut OsRng);

    let mut group = c.benchmark_group("tlock_single_commitee_dynamic_data");
    for size in [KB, 2*KB, 4*KB, 8*KB, 16*KB, 128*KB].iter() {

        let mut dummy_data = Vec::with_capacity(*size);
        (0..*size).for_each(|i| dummy_data.push(i as u8));

        group.throughput(Throughput::Bytes(KB as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
            b.iter(|| {
                tlock_tinybls377(
                    black_box(SecretKey::<TinyBLS377>::new(msk)), 
                    black_box(p_pub),
                    black_box(dummy_data.clone()),
                    black_box(id.clone()),
                    black_box(vec![id.extract(s)])
                );
            });
        });
    }
    group.finish();
}

criterion_group!(benches, tlock_single_commitee_dynamic_data);
criterion_main!(benches);
