use blst::{min_sig::*, BLST_ERROR, blst_scalar, blst_scalar_from_uint32};

use std::mem::MaybeUninit;

use criterion::{criterion_group, criterion_main, Criterion, BenchmarkId};
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha12Rng;

// Benchmarks for proof-of-possession design:
// - common message among all signers
// - each signer includes a PoP that must be verified
// - aggregated verification is as usual

const MSG_LEN: usize = 32; // length of common message in bytes
const DST_SIGN: &[u8] = b"TEST_SIGN";
const DST_POP: &[u8] = b"TEST_POP";
const SIGNERS: &[usize] = &[1, 2, 32, 64]; // number of signers for an aggregate signature

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
	let pop = sk.sign(&[], DST_POP, &[]);

	SigningData {
		pk,
		sig,
		pop,
	}
}

fn bench_pop(c: &mut Criterion) {
	let seed = [0u8; 32];
	let mut rng = ChaCha12Rng::from_seed(seed);

	let mut group = c.benchmark_group("PoP verify (minimal signature)");
	for signers in SIGNERS {
		group.bench_with_input(BenchmarkId::from_parameter(signers), signers, |b, &signers| {
			// Generate signing data for a common message
			let msg = gen_msg(&mut rng);
			let secret_data: Vec<SigningData> = (0..signers).into_iter().map(
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
				// Decompress the public keys and proofs
				let pks: Vec<PublicKey> = public_data.pks.iter().map(|p| PublicKey::uncompress(p).unwrap()).collect();
				let pops: Vec<Signature> = public_data.pops.iter().map(|s| Signature::uncompress(s).unwrap()).collect();

				// Verify the proofs of possession
				for (pk,  pop) in pks.clone().into_iter().zip(pops) {
					// Verify the proof
					// Note that the public key is validated here
					let result = pop.verify(
						true,
						&[],
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
}

fn bench_pop_batch(c: &mut Criterion) {
	let seed = [0u8; 32];
	let mut rng = ChaCha12Rng::from_seed(seed);

	let mut group = c.benchmark_group("PoP batch verify (minimal signature)");
	for signers in SIGNERS {
		group.bench_with_input(BenchmarkId::from_parameter(signers), signers, |b, &signers| {
			// Generate signing data for a common message
			let msg = gen_msg(&mut rng);
			let secret_data: Vec<SigningData> = (0..signers).into_iter().map(
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
				// Decompress the public keys and proofs
				let pks: Vec<PublicKey> = public_data.pks.iter().map(|p| PublicKey::uncompress(p).unwrap()).collect();
				let pks_ref: Vec<&PublicKey> = pks.iter().collect();
				let pops: Vec<Signature> = public_data.pops.iter().map(|s| Signature::uncompress(s).unwrap()).collect();
				let pops_ref: Vec<&Signature> = pops.iter().collect();

				// Set up the (empty) message slice
				let msgs_ref: Vec<&[u8]> = vec![&[]; signers];

				// Generate random weighting scalars (it's fine to use low-weight scalars here)
				let mut weights = Vec::<blst_scalar>::with_capacity(signers);
				for _ in 0..signers {
					let weight_u32 = rng.next_u32();
					let mut weight = MaybeUninit::<blst_scalar>::uninit();
					unsafe {
						blst_scalar_from_uint32(weight.as_mut_ptr(), &weight_u32);
						weights.push(weight.assume_init());
					}
				}

				// Verify the proofs of possession in a batch
				let result = Signature::verify_multiple_aggregate_signatures(
					&msgs_ref,
					DST_POP,
					&pks_ref,
					true,
					&pops_ref,
					true,
					&weights,
					32,
				);
				assert_eq!(result, BLST_ERROR::BLST_SUCCESS);
			})
		});
	}
}

fn bench_verify(c: &mut Criterion) {
	let seed = [0u8; 32];
	let mut rng = ChaCha12Rng::from_seed(seed);

	let mut group = c.benchmark_group("Signature verify (minimal signature)");
	for signers in SIGNERS {
		group.bench_with_input(BenchmarkId::from_parameter(signers), signers, |b, &signers| {
			// Generate signing data for a common message
			let msg = gen_msg(&mut rng);
			let secret_data: Vec<SigningData> = (0..signers).into_iter().map(
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
				// Because the earlier proof verifications validated the public keys, we don't need to do that here
				let agg = Signature::uncompress(&public_data.agg).unwrap();
				let result = agg.fast_aggregate_verify(true, &public_data.msg, DST_SIGN, &pks_ref);
				assert_eq!(result, BLST_ERROR::BLST_SUCCESS);
			})
		});
	}
}

criterion_group!(benches, bench_pop, bench_pop_batch, bench_verify);
criterion_main!(benches);
