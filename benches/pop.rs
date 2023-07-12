use blst::{min_pk::*, BLST_ERROR};

use criterion::{criterion_group, criterion_main, Criterion};
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha12Rng;

// Benchmarks for proof-of-possession design:
// - common message among all signers
// - each signer includes a PoP that must be verified
// - aggregated verification is as usual

const MSG_LEN: usize = 256;
const DST_SIGN: &[u8] = b"TEST_SIGN";
const DST_POP: &[u8] = b"TEST_POP";
const SIGNERS: usize = 32;

// Data used internally for signing
struct SigningData {
	pk: PublicKey,
	sig: Signature,
	pop: Signature,
}

// Data for public verification
struct PublicData {
	pks: Vec<Vec<u8>>, // compressed public keys
	pops: Vec<Vec<u8>>, // compressed proofs
	msg: Vec<u8>, // common message
	agg: Vec<u8>, // compressed aggregated signature
}

fn gen_msg(rng: &mut ChaCha12Rng) -> Vec<u8> {
	let mut msg = vec![0u8; MSG_LEN];
	rng.fill_bytes(&mut msg);

	msg
}

fn gen_data(msg: &Vec<u8>, dst: &[u8], rng: &mut ChaCha12Rng) -> SigningData {
	let mut ikm = [0u8; 32];
	rng.fill_bytes(&mut ikm);

	let sk = SecretKey::key_gen(&ikm, &[]).unwrap();
	let pk = sk.sk_to_pk();
	let sig = sk.sign(&msg, dst, &[]);
	let pop = sk.sign(&pk.compress(), DST_POP, &[]);

	SigningData {
		pk,
		sig,
		pop,
	}
}

fn bench_pop(c: &mut Criterion) {
	let seed = [0u8; 32];
	let mut rng = ChaCha12Rng::from_seed(seed);

	let mut group = c.benchmark_group("bench_pop");
	group.bench_function("pop", |b| {
		// Generate signing data for a common message
		let msg = gen_msg(&mut rng);
		let secret_data: Vec<SigningData> = (0..SIGNERS).into_iter().map(
			|_| gen_data(&msg, DST_SIGN, &mut rng)
		).collect();

		// Aggregate the signatures
		let sigs = secret_data.iter().map(|d| &d.sig).collect::<Vec<&Signature>>();
		let aggregate = AggregateSignature::aggregate(&sigs, true).unwrap().to_signature();

		// Prepare the public data
		let public_data = PublicData {
			pks: secret_data.iter().map(|d| d.pk.compress().to_vec()).collect(),
			pops: secret_data.iter().map(|d| d.pop.compress().to_vec()).collect(),
			msg,
			agg: aggregate.compress().to_vec(),
		};

		b.iter(|| {
			// Decompress the public keys
			let pks: Vec<PublicKey> = public_data.pks.iter().map(|p| PublicKey::uncompress(p).unwrap()).collect();

			// Verify the proofs of possession
			for ((pk, pk_bytes), pop_bytes) in pks.clone().into_iter().zip(public_data.pks.iter()).zip(public_data.pops.iter()) {
				// Decompress the proof
				let pop = Signature::uncompress(pop_bytes).unwrap();

				// Verify the proof
				let result = pop.verify(
					true,
					pk_bytes,
					DST_POP,
					&[],
					&pk,
					true,
				);
				assert_eq!(result, BLST_ERROR::BLST_SUCCESS);
			}
		})
	});
}

fn bench_verify(c: &mut Criterion) {
	let seed = [0u8; 32];
	let mut rng = ChaCha12Rng::from_seed(seed);

	let mut group = c.benchmark_group("bench_pop");
	group.bench_function("verify", |b| {
		// Generate signing data for a common message
		let msg = gen_msg(&mut rng);
		let secret_data: Vec<SigningData> = (0..SIGNERS).into_iter().map(
			|_| gen_data(&msg, DST_SIGN, &mut rng)
		).collect();

		// Aggregate the signatures
		let sigs = secret_data.iter().map(|d| &d.sig).collect::<Vec<&Signature>>();
		let aggregate = AggregateSignature::aggregate(&sigs, true).unwrap().to_signature();

		// Prepare the public data
		let public_data = PublicData {
			pks: secret_data.iter().map(|d| d.pk.compress().to_vec()).collect(),
			pops: secret_data.iter().map(|d| d.pop.compress().to_vec()).collect(),
			msg,
			agg: aggregate.compress().to_vec(),
		};

		// Decompress the public keys
		let pks: Vec<PublicKey> = public_data.pks.iter().map(|p| PublicKey::uncompress(p).unwrap()).collect();
		let pks_ref: Vec<&PublicKey> = pks.iter().collect();

		b.iter(|| {
			// Verify the aggregated signature
			let agg = Signature::uncompress(&public_data.agg).unwrap();
			let result = agg.fast_aggregate_verify(true, &public_data.msg, DST_SIGN, &pks_ref);
			assert_eq!(result, BLST_ERROR::BLST_SUCCESS);
		})
	});
}

criterion_group!(benches, bench_pop, bench_verify);
criterion_main!(benches);
