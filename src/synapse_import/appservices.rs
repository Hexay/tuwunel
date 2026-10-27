//! Appservice registrations (bridges), from the files homeserver.yaml lists, so
//! their tokens keep working. Their ghost users came across with the accounts.

use std::path::Path;

use ruma::api::appservice::Registration;
use tuwunel_core::{Result, err};
use tuwunel_service::Services;

use super::{Report, config::SynapseConfig};

pub(super) async fn import(
	services: &Services,
	config: &SynapseConfig,
	report: &mut Report,
) -> Result {
	for file in &config.app_service_config_files {
		match register(services, file).await {
			| Ok(()) => Report::count(&mut report.appservices),
			| Err(e) => report.skip(format!("appservice {}: {e}", file.display())),
		}
	}

	Ok(())
}

async fn register(services: &Services, file: &Path) -> Result {
	let contents = std::fs::read_to_string(file).map_err(|e| err!("cannot read it: {e}"))?;
	let registration: Registration =
		serde_yaml::from_str(&contents).map_err(|e| err!("cannot parse it: {e}"))?;

	// Already registered by a run that stopped partway through this phase.
	if services
		.appservice
		.get_db_registration(&registration.id)
		.await
		.is_ok()
	{
		return Ok(());
	}

	services
		.appservice
		.register_appservice(registration)
		.await
}
