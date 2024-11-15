use ark_ec::Group;
use ark_ff::UniformRand;
use criterion::{
	black_box, criterion_group, criterion_main, BenchmarkId, Criterion,
	Throughput,
};
use rand_core::OsRng;
use tle::{ibe::fullident::*, stream_ciphers::AESGCMStreamCipherProvider, tlock::*};
use w3f_bls::{EngineBLS, SecretKey, TinyBLS377};

/// encrypts a message for the identity and then decrypts it after preparing a
/// bls sig this expects on a single signature but tests many different input
/// data sizes
fn tlock_tinybls377<E: EngineBLS>(
	msk: [u8;32],
	p_pub: E::PublicKeyGroup,
	message: Vec<u8>,
	id: Identity,
	sig: IBESecret<E>,
) {
	let ct = tle::<TinyBLS377, AESGCMStreamCipherProvider, OsRng>(
		p_pub, msk, &message, id, OsRng,
	)
	.uwnrap();
	let _m = tld::<TinyBLS377, AESGCMStreamCipherProvider>(ct, sig).unwrap();
}

fn tlock(c: &mut Criterion) {
	static KB: usize = 1024;

	let s = <TinyBLS377 as EngineBLS>::Scalar::rand(&mut OsRng);
	let p_pub = <TinyBLS377 as EngineBLS>::PublicKeyGroup::generator() * s;
	let id = Identity::new(b"", vec![b"test".to_vec()]);
	let msk = <TinyBLS377 as EngineBLS>::Scalar::rand(&mut OsRng);

	let mut group = c.benchmark_group("tlock");
	for size in [KB, 2 * KB, 4 * KB, 8 * KB, 16 * KB, 128 * KB, 256 * KB].iter() {
		let mut dummy_data = Vec::with_capacity(*size);
		(0..*size).for_each(|i| dummy_data.push(i as u8));

		group.throughput(Throughput::Bytes(KB as u64));
		group.bench_with_input(
			BenchmarkId::from_parameter(size),
			size,
			|b, &size| {
				b.iter(|| {
					tlock_tinybls377::<TinyBLS377>(
						black_box([2;32]),
						black_box(p_pub),
						black_box(dummy_data.clone()),
						black_box(id.clone()),
						black_box(id.extract(s)),
					);
				});
			},
		);
	}
	group.finish();
}

criterion_group!(benches, tlock);
criterion_main!(benches);
