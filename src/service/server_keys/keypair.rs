//! Local Ed25519 keypair persistence and initialization.
//!
//! A missing database entry is imported from `signing_key_path` when that is
//! configured, and generated otherwise. An invalid stored entry is deleted and
//! reported as an error so a later service start can regenerate it.

use std::{path::Path, sync::Arc};

use base64::{
	Engine as _,
	alphabet::STANDARD,
	engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig},
};
use ruma::{api::federation::discovery::VerifyKey, serde::Base64, signatures::Ed25519KeyPair};
use tuwunel_core::{
	Err, Result, debug, debug_info, err, error, info, utils, utils::string_from_bytes, warn,
};
use tuwunel_database::Database;

use super::VerifyKeys;

/// PKCS#8 v1 header for a bare Ed25519 private key (RFC 8410); the 32-byte
/// seed follows it. ruma loads keys only from DER, so the seed is wrapped.
const ED25519_PKCS8_V1_PREFIX: [u8; 16] = [
	0x30, 0x2E, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x04, 0x22, 0x04,
	0x20,
];

/// Initializes the local keypair and its active verify-key map.
///
/// A configured `signing_key_path` is imported first, and refused if the
/// database already holds a different or undecodable key. A missing keypair
/// is otherwise generated immediately. If a stored keypair cannot be decoded,
/// its row is removed but the current call still returns that error.
pub(super) fn init(
	db: &Arc<Database>,
	signing_key_path: Option<&Path>,
) -> Result<(Box<Ed25519KeyPair>, VerifyKeys)> {
	if let Some(path) = signing_key_path {
		import(db, path)?;
	}

	let keypair = load(db).inspect_err(|_e| {
		error!("Keypair invalid. Deleting...");
		remove(db);
	})?;

	let verify_key = VerifyKey {
		key: Base64::new(keypair.public_key().to_vec()),
	};

	let id = format!("ed25519:{}", keypair.version());
	let verify_keys: VerifyKeys = [(id.try_into()?, verify_key)].into();

	Ok((keypair, verify_keys))
}

/// Reads a Synapse-format signing key file into its keypair, key version and
/// PKCS#8 DER.
///
/// Only the file's first key is read; any further keys are reported with a
/// warning and otherwise ignored.
pub fn read_synapse_key_file(path: &Path) -> Result<(Ed25519KeyPair, String, Vec<u8>)> {
	let contents = std::fs::read_to_string(path)
		.map_err(|e| err!(Config("signing_key_path", "Cannot read {path:?}: {e}")))?;

	let (version, der) = parse_synapse_key(&contents)
		.map_err(|e| err!(Config("signing_key_path", "Invalid key in {path:?}: {e}")))?;

	let ignored = key_lines(&contents).skip(1).count();
	if ignored > 0 {
		warn!(
			"{path:?} holds {ignored} more key(s) after ed25519:{version}; only the first key \
			 is used as this server's signing key."
		);
	}

	let keypair = Ed25519KeyPair::from_der(&der, version.clone())
		.map_err(|e| err!(Config("signing_key_path", "Invalid key in {path:?}: {e:?}")))?;

	Ok((keypair, version, der))
}

fn import(db: &Arc<Database>, path: &Path) -> Result {
	let (imported, version, der) = read_synapse_key_file(path)?;

	let stored = match db["global"].get_blocking(b"keypair") {
		| Ok(val) => split_entry(&val),
		| Err(e) if e.is_not_found() => {
			db["global"].raw_put(b"keypair", &(version.clone(), der));
			info!("Imported signing key ed25519:{version} from {path:?}");

			return Ok(());
		},
		| Err(e) => return Err(e),
	};

	let stored_key = Ed25519KeyPair::from_der(&stored.1, stored.0.clone()).map_err(|e| {
		err!(Config(
			"signing_key_path",
			"The database's signing key ed25519:{} cannot be decoded: {e:?}. Refusing to \
			 replace it with {path:?}.",
			stored.0
		))
	})?;

	let matches = stored_key.version() == imported.version()
		&& stored_key.public_key() == imported.public_key();

	if !matches {
		return Err!(Config(
			"signing_key_path",
			"{path:?} holds ed25519:{version}, but the database already has signing key \
			 ed25519:{}. Refusing to replace this server's signing key.",
			stored.0
		));
	}

	Ok(())
}

/// Parses Synapse's signing key file format into a key version and PKCS#8 DER.
fn parse_synapse_key(contents: &str) -> Result<(String, Vec<u8>)> {
	const SEED_BASE64: GeneralPurpose = GeneralPurpose::new(
		&STANDARD,
		GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent),
	);

	let line = key_lines(contents)
		.next()
		.ok_or_else(|| err!("the file is empty"))?;

	let [algorithm, version, seed] = line.split_whitespace().collect::<Vec<_>>()[..] else {
		return Err!("expected `ed25519 <version> <base64 seed>`");
	};

	if algorithm != "ed25519" {
		return Err!("unsupported key algorithm {algorithm:?}");
	}

	// tuwunel's ruma compat features skip ruma's version check; apply the spec's.
	if !version
		.chars()
		.all(|c| c.is_ascii_alphanumeric() || c == '_')
	{
		return Err!("invalid key version {version:?}: expected only [a-zA-Z0-9_]");
	}

	let seed: [u8; 32] = SEED_BASE64
		.decode(seed)
		.map_err(|_| err!("seed is not valid base64"))?
		.try_into()
		.map_err(|seed: Vec<u8>| err!("seed is {} bytes, not 32", seed.len()))?;

	Ok((version.to_owned(), [&ED25519_PKCS8_V1_PREFIX[..], &seed].concat()))
}

fn key_lines(contents: &str) -> impl Iterator<Item = &str> {
	contents
		.lines()
		.map(str::trim)
		.filter(|line| !line.is_empty())
}

fn load(db: &Arc<Database>) -> Result<Box<Ed25519KeyPair>> {
	let (version, key) = db["global"]
		.get_blocking(b"keypair")
		.map(|ref val| {
			let (ver, der) = split_entry(val);
			debug!("Found existing Ed25519 keypair: {ver:?}");
			(ver, der)
		})
		.or_else(|e| {
			assert!(e.is_not_found(), "unexpected error fetching keypair");
			create(db)
		})?;

	let key = Ed25519KeyPair::from_der(&key, version)
		.map_err(|e| err!("Failed to load ed25519 keypair from der: {e:?}"))?;

	Ok(Box::new(key))
}

// database deserializer is having trouble with this so it's manual for now
fn split_entry(val: &[u8]) -> (String, Vec<u8>) {
	let mut elems = val.split(|&b| b == b'\xFF');
	let vlen = elems.next().expect("invalid keypair entry").len();
	let ver = string_from_bytes(&val[..vlen]).expect("invalid keypair version");
	let der = val[vlen.saturating_add(1)..].to_vec();

	(ver, der)
}

fn create(db: &Arc<Database>) -> Result<(String, Vec<u8>)> {
	let keypair = Ed25519KeyPair::generate();

	let id = utils::rand::string(8);
	debug_info!("Generated new Ed25519 keypair: {id:?}");

	let value: (String, Vec<u8>) = (id, keypair.to_vec());
	db["global"].raw_put(b"keypair", &value);

	Ok(value)
}

#[inline]
fn remove(db: &Arc<Database>) {
	let global = &db["global"];
	global.remove(b"keypair");
}

#[cfg(test)]
mod tests;
