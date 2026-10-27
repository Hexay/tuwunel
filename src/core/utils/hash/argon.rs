use std::fmt::Display;

use argon2::{
	Algorithm, Argon2, Error as Argon2Error, Params, PasswordHash, PasswordHasher,
	PasswordVerifier, Version, password_hash::phc::Salt,
};
use rand::random;
use smallstr::SmallString;

use crate::{Error, Result, err, format_small_string, implement};

/// A PHC-formatted Argon2id password hash.
///
/// The inline budget fits the 97 bytes a hash takes at any OWASP recommended
/// cost, so a hash spills to the heap only past an unusually large `m_cost`.
pub type PhcString = SmallString<[u8; 112]>;

const KEYID: &str = "keyid";

/// At most 8 bytes, Argon2's `keyid` limit.
const IMPORTED_KEYID: &[u8] = b"imported";

/// Argon2id cost parameters for hashing a new password.
///
/// Every hash records the values it was produced with, so a change takes
/// effect on new hashes only. Each hashing operation holds `m_cost` KiB for
/// its duration, which dominates the server's cost when several run at once.
#[derive(Clone, Copy, Debug)]
pub struct Cost {
	/// Size of the working buffer, in 1 KiB blocks.
	pub m_cost: u32,

	/// Number of passes made over the working buffer.
	pub t_cost: u32,

	/// Number of lanes the working buffer is divided into.
	pub p_cost: u32,
}

/// Hashes a plaintext password with Argon2id at the given cost.
///
/// A fresh random salt is generated for every call. The result is a
/// PHC-formatted string containing the salt and parameters needed for
/// verification.
pub fn password(password: &str, cost: Cost) -> Result<PhcString> {
	let salt: [u8; Salt::RECOMMENDED_LENGTH] = random();

	hasher(cost)
		.map_err(map_err)?
		.hash_password_with_salt(password.as_bytes(), &salt)
		.map(|hash| format_small_string!("{hash}"))
		.map_err(map_err)
}

/// Verifies a plaintext password against an encoded Argon2 password hash.
///
/// Cost parameters come from the encoded hash, so a hash written under any
/// cost still verifies. Malformed hashes and password mismatches return an
/// error.
pub fn verify_password(password: &str, password_hash: &str) -> Result {
	Argon2::default()
		.verify_password(password.as_bytes(), password_hash)
		.map_err(map_err)
}

/// Like [`verify_password`], for a hash keyed with a secret (MAS's
/// `passwords.schemes[].secret`). Parameters still come from the hash.
pub fn verify_password_with_secret(password: &str, password_hash: &str, secret: &[u8]) -> Result {
	Argon2::new_with_secret(secret, Algorithm::default(), Version::default(), Params::default())
		.map_err(map_err)?
		.verify_password(password.as_bytes(), password_hash)
		.map_err(map_err)
}

/// Adds the PHC `keyid` parameter to an Argon2 hash keyed with a secret.
///
/// A keyed hash is otherwise indistinguishable from an unkeyed one. Argon2
/// parses `keyid` but leaves it out of the digest, so the marked hash still
/// verifies with [`verify_password_with_secret`]. A marked hash is returned
/// unchanged.
pub fn mark_keyed_argon2_hash(hash: &str) -> Result<PhcString> {
	let Some(mut parsed) = parse_argon2_hash(hash) else {
		return Err(err!("Not an Argon2 password hash."));
	};

	if parsed.params.get(KEYID).is_none() {
		parsed
			.params
			.add_b64_bytes(KEYID, IMPORTED_KEYID)
			.map_err(map_err)?;
	}

	Ok(format_small_string!("{parsed}"))
}

/// Whether a stored password hash was marked by [`mark_keyed_argon2_hash`].
#[must_use]
pub fn is_keyed_argon2_hash(hash: &str) -> bool {
	parse_argon2_hash(hash).is_some_and(|hash| hash.params.get(KEYID).is_some())
}

/// Whether a stored password hash is a complete Argon2 PHC string.
#[must_use]
pub fn is_argon2_hash(hash: &str) -> bool { parse_argon2_hash(hash).is_some() }

fn parse_argon2_hash(hash: &str) -> Option<PasswordHash> {
	PasswordHash::new(hash)
		.ok()
		.filter(|hash| hash.hash.is_some())
		.filter(|hash| Algorithm::try_from(hash.algorithm.as_str()).is_ok())
}

/// Rejects a cost Argon2id cannot accept.
///
/// The parameters are interdependent: `m_cost` has a floor of eight blocks and
/// must be at least eight times `p_cost`, and `t_cost` has a floor of one. The
/// crate's error names the parameter at fault.
#[implement(Cost)]
pub fn check(self) -> Result<(), Argon2Error> { hasher(self).map(|_| ()) }

/// Whether the cost is at least as strong as the weakest OWASP Argon2id
/// recommendation.
///
/// The recommended pairs of memory and passes run from (47104, 1) down to
/// (7168, 5) at a roughly constant product, so a cost qualifies when its
/// memory is at least 7168 blocks and its memory times its passes at least
/// matches that last pair. Lanes are left out, since `p_cost` divides that
/// work rather than adding to it.
#[implement(Cost)]
#[must_use]
pub fn is_recommended(self) -> bool {
	const MIN_M_COST: u64 = 7168;
	const MIN_PRODUCT: u64 = MIN_M_COST * 5;

	let m_cost = u64::from(self.m_cost);
	let product = m_cost.saturating_mul(u64::from(self.t_cost));

	m_cost >= MIN_M_COST && product >= MIN_PRODUCT
}

fn hasher(Cost { m_cost, t_cost, p_cost }: Cost) -> Result<Argon2<'static>, Argon2Error> {
	let out_len: Option<usize> = None;

	Params::new(m_cost, t_cost, p_cost, out_len)
		.map(|params| Argon2::new(Algorithm::Argon2id, Version::default(), params))
}

fn map_err<E: Display>(e: E) -> Error { err!("{e}") }

#[cfg(test)]
mod tests {
	use argon2::{Algorithm, Argon2, Params, PasswordHasher, Version};

	use super::{
		Cost, is_argon2_hash, is_keyed_argon2_hash, mark_keyed_argon2_hash, password,
		verify_password, verify_password_with_secret,
	};

	// The OWASP cost the shipped configuration also defaults to.
	const COST: Cost = Cost {
		m_cost: Params::DEFAULT_M_COST,
		t_cost: Params::DEFAULT_T_COST,
		p_cost: Params::DEFAULT_P_COST,
	};

	#[test]
	fn password_hash_and_verify() {
		let preimage = "temp123";
		let digest = password(preimage, COST).expect("digest");

		verify_password(preimage, &digest).expect("verified");
	}

	// "temp123" keyed with secret "mas secret", from the reference libargon2.
	const KEYED: &str = concat!(
		"$argon2id$v=19$m=64,t=1,p=1$c2FsdHNhbHRzYWx0c2FsdA$",
		"q4tnt7PK6IVEaGRuhzFf3PQkgfW3qMlwjHzr1DerNSg",
	);

	#[test]
	fn a_keyed_hash_verifies_only_with_its_secret() {
		let params = Params::new(64, 1, 1, None).expect("params");
		let keyed =
			Argon2::new_with_secret(b"mas secret", Algorithm::Argon2id, Version::V0x13, params)
				.expect("hasher")
				.hash_password_with_salt(b"temp123", b"saltsaltsaltsalt")
				.expect("digest")
				.to_string();

		assert_eq!(keyed, KEYED);
		assert!(is_argon2_hash(KEYED));
		verify_password_with_secret("temp123", KEYED, b"mas secret").expect("verified");
		assert!(verify_password("temp123", KEYED).is_err());
		assert!(verify_password_with_secret("temp123", KEYED, b"other").is_err());
		assert!(verify_password_with_secret("temp321", KEYED, b"mas secret").is_err());
	}

	#[test]
	fn a_marked_keyed_hash_still_verifies_with_its_secret() {
		assert!(!is_keyed_argon2_hash(KEYED));
		let marked = mark_keyed_argon2_hash(KEYED).expect("marked");

		assert!(marked.contains(",keyid="), "{marked}");
		assert!(is_argon2_hash(&marked));
		assert!(is_keyed_argon2_hash(&marked));
		assert_eq!(mark_keyed_argon2_hash(&marked).expect("idempotent"), marked);
		verify_password_with_secret("temp123", &marked, b"mas secret").expect("verified");
		assert!(verify_password("temp123", &marked).is_err());

		let unkeyed = password("temp123", COST).expect("digest");
		assert!(!is_keyed_argon2_hash(&unkeyed));
		mark_keyed_argon2_hash("temp123").unwrap_err();
	}

	#[test]
	fn recognizes_only_complete_argon2_hashes() {
		let digest = password("temp123", COST).expect("digest");

		assert!(is_argon2_hash(&digest));
		assert!(!is_argon2_hash(digest.rsplit_once('$').expect("has output").0));
		assert!(!is_argon2_hash("$scrypt$ln=16,r=8,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNo"));
		assert!(!is_argon2_hash("temp123"));
		assert!(!is_argon2_hash(""));
	}

	#[test]
	fn the_owasp_pairs_are_recommended_and_weaker_costs_are_not() {
		let recommended = [(47104, 1), (19456, 2), (12288, 3), (9216, 4), (7168, 5)];
		let weaker = [(19456, 1), (7168, 4), (4096, 9), (64, 1)];
		let cost = |(m_cost, t_cost)| Cost { m_cost, t_cost, p_cost: 1 };

		for pair in recommended {
			assert!(cost(pair).is_recommended(), "{pair:?}");
		}

		for pair in weaker {
			assert!(!cost(pair).is_recommended(), "{pair:?}");
		}
	}

	#[test]
	#[should_panic(expected = "unverified")]
	fn password_hash_and_verify_fail() {
		let preimage = "temp123";
		let fakeimage = "temp321";
		let digest = password(preimage, COST).expect("digest");

		verify_password(fakeimage, &digest).expect("unverified");
	}
}
