use std::{env::temp_dir, fs, path::PathBuf};

use base64::{Engine as _, engine::general_purpose::STANDARD_NO_PAD};
use ruma::signatures::Ed25519KeyPair;
use tuwunel_core::{Error, Result, config::Figment, utils::random_string};

use super::{init, parse_synapse_key, read_synapse_key_file};
use crate::test_utils::{Warnings, fixture};

// RFC 8032 section 7.1, tests 1 and 2.
const SEED: &str = "nWGxne/9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A";
const PUBLIC: &str = "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo";
const OTHER_SEED: &str = "TM0Imyj/ltqdtsNG7BFOD1uKMZ81q6Yk2oz27U+4pvs";

/// A key file in the temp directory, removed when dropped.
struct KeyFile(PathBuf);

impl KeyFile {
	fn new(contents: &str) -> Self {
		let path = temp_dir().join(format!("tuwunel-signing-{}.key", random_string(16)));
		fs::write(&path, contents).expect("key file written");

		Self(path)
	}
}

impl Drop for KeyFile {
	fn drop(&mut self) { fs::remove_file(&self.0).ok(); }
}

fn key_line(version: &str, seed: &str) -> String { format!("ed25519 {version} {seed}\n") }

#[test]
fn parses_a_synapse_key_into_the_same_keypair() {
	let (version, der) = parse_synapse_key(&key_line("a_Rfc1", SEED)).expect("parsed");
	let keypair = Ed25519KeyPair::from_der(&der, version).expect("valid DER");

	assert_eq!(keypair.version(), "a_Rfc1");
	assert_eq!(STANDARD_NO_PAD.encode(keypair.public_key()), PUBLIC);
}

#[test]
fn accepts_padded_seeds_and_surrounding_blank_lines() {
	let padded = format!("\n  ed25519 a_Rfc1 {SEED}=  \n\n");

	assert_eq!(
		parse_synapse_key(&padded).expect("parsed"),
		parse_synapse_key(&key_line("a_Rfc1", SEED)).expect("parsed")
	);
}

#[test]
fn rejects_malformed_key_files() {
	for contents in [
		String::new(),
		"ed25519 a_Rfc1".to_owned(),
		format!("ed25519 a_Rfc1 {SEED} extra"),
		format!("curve25519 a_Rfc1 {SEED}"),
		format!("ed25519 a-1 {SEED}"),
		"ed25519 a_Rfc1 not*base64".to_owned(),
		"ed25519 a_Rfc1 nWGxne/9WmC6hEr0kuwsxERJxWl7MmkZ".to_owned(),
	] {
		parse_synapse_key(&contents).expect_err(&contents);
	}
}

#[test]
fn uses_the_first_of_several_keys_and_warns() {
	let contents = [key_line("a_Rfc1", SEED), key_line("b_Other", OTHER_SEED)].concat();
	let file = KeyFile::new(&contents);
	let warnings = Warnings::capture();

	let (keypair, version, _) = read_synapse_key_file(&file.0).expect("read");

	assert_eq!(version, "a_Rfc1");
	assert_eq!(STANDARD_NO_PAD.encode(keypair.public_key()), PUBLIC);
	assert_eq!(warnings.count(), 1);
}

#[test]
fn a_missing_key_file_is_a_config_error() {
	let path = temp_dir().join(format!("tuwunel-missing-{}.key", random_string(16)));
	let error = read_synapse_key_file(&path).expect_err("missing file");

	assert!(matches!(error, Error::Config("signing_key_path", _)), "{error}");
}

#[tokio::test]
async fn configured_key_becomes_the_server_identity() -> Result {
	let file = KeyFile::new(&key_line("a_Rfc1", SEED));
	let config = Figment::new().merge(("signing_key_path", &file.0));
	let Some(fixture) = fixture(config).await? else {
		return Ok(());
	};

	let db = &fixture.services.db;
	let server_keys = &fixture.services.server_keys;
	assert_eq!(server_keys.active_key_id().as_str(), "ed25519:a_Rfc1");
	assert_eq!(STANDARD_NO_PAD.encode(server_keys.keypair().public_key()), PUBLIC);

	init(db, Some(&file.0)).expect("the same key is accepted again");

	let other_seed = KeyFile::new(&key_line("a_Rfc1", OTHER_SEED));
	init(db, Some(&other_seed.0)).expect_err("a different seed is refused");

	let other_version = KeyFile::new(&key_line("b_Rfc1", SEED));
	init(db, Some(&other_version.0)).expect_err("a different version is refused");

	init(db, Some(&file.0)).expect("the refused keys changed nothing");

	Ok(())
}

#[tokio::test]
async fn generated_key_is_not_replaced_by_a_configured_one() -> Result {
	let Some(fixture) = fixture(Figment::new()).await? else {
		return Ok(());
	};

	let file = KeyFile::new(&key_line("a_Rfc1", SEED));
	init(&fixture.services.db, Some(&file.0)).expect_err("the generated key is kept");

	let (keypair, _) = init(&fixture.services.db, None)?;
	assert_eq!(keypair.version(), fixture.services.server_keys.keypair().version());

	Ok(())
}
