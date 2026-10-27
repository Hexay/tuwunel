//! The parts of Synapse's homeserver.yaml the import reads.

use std::{
	collections::BTreeMap,
	fmt,
	path::{Path, PathBuf},
};

use ruma::OwnedServerName;
use serde::Deserialize;
use tuwunel_core::{Result, err};

#[derive(Debug, Deserialize)]
pub(super) struct SynapseConfig {
	pub(super) server_name: OwnedServerName,
	pub(super) signing_key_path: PathBuf,
	#[serde(default = "default_media_store_path")]
	pub(super) media_store_path: PathBuf,
	#[serde(default)]
	pub(super) app_service_config_files: Vec<PathBuf>,
	#[serde(default)]
	pub(super) old_signing_keys: BTreeMap<String, OldSigningKey>,
	#[serde(default)]
	pub(super) password_config: PasswordConfig,
	#[serde(default)]
	pub(super) registration_requires_token: bool,
	#[serde(default)]
	pub(super) experimental_features: ExperimentalFeatures,
	pub(super) matrix_authentication_service: Option<serde_yaml::Value>,
	#[serde(default)]
	oidc_providers: Vec<OidcProvider>,
	oidc_config: Option<OidcProvider>,
}

#[derive(Debug, Deserialize)]
pub(super) struct OidcProvider {
	idp_id: Option<String>,
	enabled: Option<bool>,
	pub(super) issuer: String,
	pub(super) user_mapping_provider: Option<serde_yaml::Value>,
}

fn default_media_store_path() -> PathBuf { "media_store".into() }

#[derive(Debug, Deserialize)]
pub(super) struct OldSigningKey {
	pub(super) key: String,
	pub(super) expired_ts: u64,
}

#[derive(Default, Deserialize)]
pub(super) struct PasswordConfig {
	pub(super) pepper: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
pub(super) struct ExperimentalFeatures {
	pub(super) msc3861: Option<serde_yaml::Value>,
}

impl SynapseConfig {
	/// Reads homeserver.yaml. Relative paths in it are kept as they are, so they
	/// resolve against the importer's working directory, as Synapse resolved
	/// them against its own.
	pub(super) fn read(path: &Path) -> Result<Self> {
		let contents = std::fs::read_to_string(path)
			.map_err(|e| err!("Cannot read Synapse config {path:?}: {e}"))?;

		Self::parse(&contents, path)
	}

	/// homeserver.yaml's contents, as read from `path`.
	pub(super) fn parse(contents: &str, path: &Path) -> Result<Self> {
		serde_yaml::from_str(contents)
			.map_err(|e| err!("Cannot parse Synapse config {path:?}: {e}"))
	}

	/// The OIDC provider Synapse records as `auth_provider` in
	/// user_external_ids: "oidc" for the legacy `oidc_config`, otherwise
	/// "oidc-" and its idp_id.
	pub(super) fn oidc_provider(&self, auth_provider: &str) -> Option<&OidcProvider> {
		// The legacy block is off unless enabled; list entries are on unless disabled.
		let legacy = self
			.oidc_config
			.iter()
			.filter(|provider| provider.enabled == Some(true));

		let listed = self
			.oidc_providers
			.iter()
			.filter(|provider| provider.enabled != Some(false));

		legacy
			.chain(listed)
			.find(|provider| match provider.idp_id.as_deref().unwrap_or("oidc") {
				| "oidc" => auth_provider == "oidc",
				| idp_id => auth_provider.strip_prefix("oidc-") == Some(idp_id),
			})
	}

	/// Whether logins are delegated to the Matrix Authentication Service,
	/// whose tokens tuwunel cannot accept.
	pub(super) fn delegates_auth(&self) -> bool {
		let enabled = |value: &serde_yaml::Value| {
			value
				.get("enabled")
				.and_then(serde_yaml::Value::as_bool)
				.unwrap_or(false)
		};

		self.matrix_authentication_service
			.as_ref()
			.is_some_and(enabled)
			|| self
				.experimental_features
				.msc3861
				.as_ref()
				.is_some_and(enabled)
	}
}

impl fmt::Debug for PasswordConfig {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("PasswordConfig")
			.field("pepper", &self.pepper.as_ref().map(|_| "<redacted>"))
			.finish()
	}
}

#[cfg(test)]
mod tests {
	use std::path::Path;

	use super::SynapseConfig;

	fn config(extra: &str) -> SynapseConfig {
		let yaml =
			format!("server_name: example.com\nsigning_key_path: keys/signing.key\n{extra}");

		SynapseConfig::parse(&yaml, Path::new("/etc/synapse/homeserver.yaml"))
			.expect("a valid config")
	}

	#[test]
	fn relative_paths_are_kept_as_written() {
		let config = config("app_service_config_files: [bridge.yaml, /abs/other.yaml]\n");
		assert_eq!(config.signing_key_path, Path::new("keys/signing.key"));
		assert_eq!(config.media_store_path, Path::new("media_store"));
		assert_eq!(config.app_service_config_files, [
			Path::new("bridge.yaml"),
			Path::new("/abs/other.yaml")
		]);
	}

	#[test]
	fn legacy_oidc_config_is_off_unless_enabled() {
		let provider = "oidc_config:\n  issuer: https://idp.example/\n";
		assert!(config(provider).oidc_provider("oidc").is_none());

		let enabled = config(&format!("{provider}  enabled: true\n"));
		let found = enabled
			.oidc_provider("oidc")
			.expect("the legacy provider");
		assert_eq!(found.issuer, "https://idp.example/");
	}

	#[test]
	fn listed_providers_match_by_idp_id() {
		let config = config(
			"oidc_providers:\n  - idp_id: google\n    issuer: https://accounts.google.com/\n  - \
			 idp_id: retired\n    issuer: https://retired.example/\n    enabled: false\n  - issuer: \
			 https://default.example/\n",
		);

		let google = config
			.oidc_provider("oidc-google")
			.expect("google");
		assert_eq!(google.issuer, "https://accounts.google.com/");
		assert!(config.oidc_provider("google").is_none());
		assert!(config.oidc_provider("oidc-retired").is_none());

		let default = config
			.oidc_provider("oidc")
			.expect("the provider without idp_id");
		assert_eq!(default.issuer, "https://default.example/");
	}

	#[test]
	fn delegation_to_mas_in_either_form() {
		assert!(!config("").delegates_auth());
		assert!(config("matrix_authentication_service:\n  enabled: true\n").delegates_auth());
		assert!(!config("matrix_authentication_service:\n  enabled: false\n").delegates_auth());
		assert!(
			config("experimental_features:\n  msc3861:\n    enabled: true\n").delegates_auth()
		);
		assert!(!config("experimental_features:\n  msc3861: {}\n").delegates_auth());
	}

	#[test]
	fn debug_hides_the_pepper() {
		let config = config("password_config:\n  pepper: secret-pepper\n");
		assert_eq!(config.password_config.pepper.as_deref(), Some("secret-pepper"));
		assert!(!format!("{config:?}").contains("secret-pepper"));
	}
}
