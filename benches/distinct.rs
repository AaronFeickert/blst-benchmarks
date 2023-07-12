use blst::{min_pk::*, BLST_ERROR};

use criterion::{criterion_group, criterion_main, Criterion};
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha12Rng;

// Benchmarks for distinct-message design:
// - distinct message for each signer
// - aggregated verification is on all messages

const MSG_LEN: usize = 256;
const DST_SIGN: &[u8] = b"TEST_SIGN";
const SIGNERS: usize = 32;

// Data used internally for signing
struct SigningData {
	pk: PublicKey,
	sig: Signature,
}

// Data for public verification
struct PublicData {
	pks: Vec<Vec<u8>>, // compressed public keys
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
	let mut extended_msg = pk.compress().to_vec();
	extended_msg.extend(msg);
	let sig = sk.sign(&extended_msg, dst, &[]);

	SigningData {
		pk,
		sig,
	}
}

fn bench_distinct(c: &mut Criterion) {
	let seed = [0u8; 32];
	let mut rng = ChaCha12Rng::from_seed(seed);

	let mut group = c.benchmark_group("bench_distinct");
	group.bench_function("distinct", |b| {
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
			msg,
			agg: aggregate.compress().to_vec(),
		};

		b.iter(|| {
			// Decompress the public keys
			let pks: Vec<PublicKey> = public_data.pks.iter().map(|p| PublicKey::uncompress(p).unwrap()).collect();
			let pks_ref: Vec<&PublicKey> = pks.iter().collect();

			// Prepare the extended messages
			let extended_msgs: Vec<Vec<u8>> = public_data.pks.iter().map(
				|p| {
					let mut extended_msg = p.clone();
					extended_msg.extend(public_data.msg.clone());

					extended_msg
				}
			).collect();
			let extended_msgs_ref: Vec<&[u8]> = extended_msgs.iter().map(|m| m.as_slice()).collect();

			// Verify the aggregated signature
			let agg = Signature::uncompress(&public_data.agg).unwrap();
			let result = agg.aggregate_verify(true, &extended_msgs_ref, DST_SIGN, &pks_ref, true);
			assert_eq!(result, BLST_ERROR::BLST_SUCCESS);
		})
	});
}

criterion_group!(benches, bench_distinct);
criterion_main!(benches);
