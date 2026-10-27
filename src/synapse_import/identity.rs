//! Synapse's retired signing keys, so events they signed keep verifying.
//!
//! The current key is not imported here: preflight requires this server to
//! already run on it, through `signing_key_path`.

use ruma::{
	MilliSecondsSinceUnixEpoch, OwnedServerSigningKeyId, UInt,
	api::federation::discovery::{OldVerifyKey, ServerSigningKeys},
	serde::Base64,
};
use tuwunel_core::{Result, err};
use tuwunel_service::Services;

use super::{Report, config::SynapseConfig};

pub(super) async fn import(
	services: &Services,
	config: &SynapseConfig,
	report: &mut Report,
) -> Result {
	let server_name = services.globals.server_name().to_owned();
	let mut keys = ServerSigningKeys::new(server_name, MilliSecondsSinceUnixEpoch::now());

	for (key_id, old) in &config.old_signing_keys {
		let key_id: OwnedServerSigningKeyId = key_id
			.as_str()
			.try_into()
			.map_err(|e| err!("Synapse old signing key {key_id:?}: {e}"))?;

		let key =
			Base64::parse(&old.key).map_err(|e| err!("Synapse old signing key {key_id}: {e}"))?;

		let expired_ts = UInt::new(old.expired_ts)
			.map(MilliSecondsSinceUnixEpoch)
			.ok_or_else(|| err!("Synapse old signing key {key_id}: expired_ts out of range"))?;

		keys.old_verify_keys
			.insert(key_id, OldVerifyKey::new(expired_ts, key));
	}

	report.old_keys = keys.old_verify_keys.len();
	if report.old_keys > 0 {
		services.server_keys.add_signing_keys(keys).await;
	}

	Ok(())
}
