//! The parts of MAS's config.yaml the import reads. Everything else it needs
//! (upstream providers, clients) MAS mirrors into its database.

use std::{
	fmt,
	path::{Path, PathBuf},
};

use ruma::OwnedServerName;
use serde::Deserialize;
use tuwunel_core::{Result, err};

#[derive(Debug, Deserialize)]
pub(in super::super) struct MasConfig {
	pub(super) matrix: Matrix,
	#[serde(default)]
	pub(super) passwords: Passwords,
}

#[derive(Debug, Deserialize)]
pub(super) struct Matrix {
	pub(super) homeserver: OwnedServerName,
}

#[derive(Debug, Default, Deserialize)]
pub(super) struct Passwords {
	#[serde(default)]
	pub(super) schemes: Vec<Scheme>,
}

#[derive(Deserialize)]
pub(super) struct Scheme {
	pub(super) version: i32,
	pub(super) algorithm: String,
	secret: Option<String>,
	secret_file: Option<PathBuf>,
}

impl MasConfig {
	pub(super) fn read(path: &Path) -> Result<Self> {
		let yaml = std::fs::read_to_string(path)
			.map_err(|e| err!("Cannot read MAS's config {}: {e}", path.display()))?;

		serde_yaml::from_str(&yaml)
			.map_err(|e| err!("Cannot parse MAS's config {}: {e}", path.display()))
	}

	pub(super) fn scheme(&self, version: i32) -> Option<&Scheme> {
		self.passwords
			.schemes
			.iter()
			.find(|scheme| scheme.version == version)
	}
}

impl Scheme {
	/// The secret as MAS reads it: a relative `secret_file` resolves against
	/// the working directory, and the file's bytes, a trailing newline
	/// included, are the secret.
	pub(super) fn secret(&self) -> Result<Option<String>> {
		match (&self.secret, &self.secret_file) {
			| (Some(secret), _) => Ok(Some(secret.clone())),
			| (None, Some(path)) => std::fs::read_to_string(path)
				.map(Some)
				.map_err(|e| err!("Cannot read MAS password secret {}: {e}", path.display())),
			| (None, None) => Ok(None),
		}
	}
}

impl fmt::Debug for Scheme {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("Scheme")
			.field("version", &self.version)
			.field("algorithm", &self.algorithm)
			.field("secret", &self.secret.as_ref().map(|_| "<redacted>"))
			.field("secret_file", &self.secret_file)
			.finish()
	}
}

#[cfg(test)]
mod tests {
	use super::MasConfig;

	fn config(scheme: &str) -> MasConfig {
		let yaml = format!(
			"matrix:\n  homeserver: example.com\npasswords:\n  schemes:\n    - version: 1\n      \
			 algorithm: bcrypt\n{scheme}"
		);

		serde_yaml::from_str(&yaml).expect("a valid MAS config")
	}

	fn secret(config: &MasConfig) -> Option<String> {
		config
			.scheme(1)
			.expect("scheme 1")
			.secret()
			.expect("a readable secret")
	}

	#[test]
	fn inline_secret_wins_over_file() {
		let config = config("      secret: pepper\n      secret_file: /nonexistent\n");
		assert_eq!(secret(&config).as_deref(), Some("pepper"));
	}

	#[test]
	fn secret_file_is_kept_byte_for_byte() {
		let path =
			std::env::temp_dir().join(format!("tuwunel-mas-secret-{}", std::process::id()));
		std::fs::write(&path, "pepper\n").expect("writable temp dir");

		let config = config(&format!("      secret_file: '{}'\n", path.display()));
		let read = secret(&config);
		std::fs::remove_file(&path).ok();

		assert_eq!(read.as_deref(), Some("pepper\n"));
	}

	#[test]
	fn missing_secret_file_is_an_error() {
		let config = config("      secret_file: /nonexistent/tuwunel-mas-secret\n");
		let scheme = config.scheme(1).expect("scheme 1");
		scheme.secret().unwrap_err();
	}

	#[test]
	fn schemes_without_a_secret_and_unknown_versions() {
		let config = config("");
		assert_eq!(secret(&config), None);
		assert!(config.scheme(2).is_none());
	}

	#[test]
	fn debug_hides_the_secret() {
		let config = config("      secret: pepper\n");
		assert!(!format!("{config:?}").contains("pepper"));
	}

	#[test]
	fn passwords_default_to_no_schemes() {
		let config: MasConfig =
			serde_yaml::from_str("matrix:\n  homeserver: example.com\n").expect("a valid config");
		assert!(config.scheme(1).is_none());
	}
}
