//! Refuses an import that cannot be lossless, before anything is written.

use std::ops::RangeInclusive;

use tuwunel_core::{Err, Result, info};
use tuwunel_service::{Services, server_keys::read_synapse_key_file};

use super::{config::SynapseConfig, mas::Mas, source::Source};

/// Synapse 1.100 through 1.163, the releases this import is tested against.
/// Columns added in between are checked by name (`Source::column_or`), not by
/// this number.
const SUPPORTED_SCHEMA: RangeInclusive<i32> = 84..=94;

/// Tables that must be empty: work Synapse accepted but hadn't finished.
const MUST_BE_EMPTY: [(&str, &str); 3] = [
	(
		"federation_inbound_events_staging",
		"incoming federation events are still queued",
	),
	("partial_state_rooms", "some rooms were joined with partial state"),
	("background_updates", "Synapse's own database updates haven't finished"),
];

/// Lists every problem at once rather than stopping at the first.
pub(super) async fn check(
	services: &Services,
	config: &SynapseConfig,
	source: &Source,
	mas: Option<&Mas>,
	resuming: bool,
) -> Result {
	let mut problems = Vec::new();
	let mut problem = |p: String| problems.push(p);

	check_identity(services, config, &mut problem);
	check_auth(services, config, mas, &mut problem).await?;
	let schema = check_source(source, &mut problem).await?;
	check_target(services, source, resuming, &mut problem).await?;

	if !problems.is_empty() {
		return Err!("Cannot import from Synapse:\n- {}", problems.join("\n- "));
	}

	let server_name = services.globals.server_name();
	info!("Preflight passed: Synapse schema {schema}, server {server_name}");
	Ok(())
}

/// The same server name and signing key, so other servers see the same server.
fn check_identity(services: &Services, config: &SynapseConfig, problem: &mut impl FnMut(String)) {
	let server_name = services.globals.server_name();
	if config.server_name != server_name {
		problem(format!(
			"Synapse's server_name is {}, but this server's is {server_name}; they must be the \
			 same",
			config.server_name
		));
	}

	check_signing_key(services, config, problem);
}

/// What users log in with: Synapse's password hashes, or MAS's whole database.
async fn check_auth(
	services: &Services,
	config: &SynapseConfig,
	mas: Option<&Mas>,
	problem: &mut impl FnMut(String),
) -> Result {
	match (config.delegates_auth(), mas) {
		| (true, None) => problem(
			"Synapse delegates logins to the Matrix Authentication Service; pass its database \
			 and config with --mas-db and --mas-config"
				.into(),
		),
		| (false, Some(_)) => problem(
			"--mas-db was given, but Synapse doesn't delegate logins to the Matrix \
			 Authentication Service"
				.into(),
		),
		| (_, Some(mas)) => {
			mas.check(services, problem).await?;
			if let Some(clients) = other_clients(&mas.source).await? {
				problem(format!(
					"other clients are connected to MAS's database ({clients}); stop MAS first"
				));
			}
		},
		// With MAS, Synapse's own password hashes are stale and its pepper unused.
		| (false, None) => {
			let pepper = config.password_config.pepper.as_deref();
			if services.config.imported_bcrypt_pepper.as_deref() != pepper {
				problem(
					"imported_bcrypt_pepper must be set to Synapse's password_config.pepper (or \
					 both unset)"
						.into(),
				);
			}
		},
	}

	Ok(())
}

/// A supported, idle Synapse database; returns its schema version.
async fn check_source(source: &Source, problem: &mut impl FnMut(String)) -> Result<i32> {
	if !source.has_table("schema_version").await? {
		return Err!("--synapse-db is not a Synapse database: it has no schema_version table");
	}

	let schema: i32 = source
		.rows("SELECT version FROM schema_version", &[])
		.await?
		.first()
		.map_or(0, |row| row.get(0));

	if !SUPPORTED_SCHEMA.contains(&schema) {
		problem(format!(
			"Synapse database schema {schema} is not supported (supported: {}-{})",
			SUPPORTED_SCHEMA.start(),
			SUPPORTED_SCHEMA.end()
		));
	}

	if let Some(clients) = other_clients(source).await? {
		problem(format!(
			"other clients are connected to Synapse's database ({clients}); stop Synapse and \
			 its workers first, or both servers will accept messages the other never sees"
		));
	}

	for (table, why) in MUST_BE_EMPTY {
		if source.count(table).await? > 0 {
			problem(format!("{table} isn't empty: {why}. Let Synapse finish, then stop it"));
		}
	}

	Ok(schema)
}

/// A new tuwunel database, whose server user no Synapse user would merge into.
async fn check_target(
	services: &Services,
	source: &Source,
	resuming: bool,
	problem: &mut impl FnMut(String),
) -> Result {
	let server_user = services.globals.server_user.as_str();
	let taken = source
		.rows("SELECT 1 FROM users WHERE name = $1", &[&server_user])
		.await?;

	if !taken.is_empty() {
		problem(format!(
			"Synapse has a user {server_user}, which is this server's own server user; set \
			 server_user_localpart to a name Synapse doesn't use, in a new database"
		));
	}

	// Beyond the server user that a fresh database creates.
	if !resuming && services.users.count().await > 1 {
		problem("this tuwunel database already has users; import into a new one".into());
	}

	Ok(())
}

/// Who else is connected to the database, as "N from <client>" entries.
async fn other_clients(source: &Source) -> Result<Option<String>> {
	let rows = source
		.rows(
			"SELECT count(*), coalesce(nullif(application_name, ''), host(client_addr), \
			 'local') FROM pg_stat_activity WHERE datname = current_database() AND pid <> \
			 ALL($1) AND backend_type = 'client backend' GROUP BY 2 ORDER BY 2",
			&[source.pids()],
		)
		.await?;

	Ok((!rows.is_empty()).then(|| {
		rows.iter()
			.map(|row| format!("{} from {}", row.get::<_, i64>(0), row.get::<_, String>(1)))
			.collect::<Vec<_>>()
			.join(", ")
	}))
}

fn check_signing_key(
	services: &Services,
	config: &SynapseConfig,
	problem: &mut impl FnMut(String),
) {
	let synapse = match read_synapse_key_file(&config.signing_key_path) {
		| Ok((keypair, ..)) => keypair,
		| Err(e) => return problem(format!("Synapse's signing key: {e}")),
	};

	let ours = services.server_keys.keypair();
	if ours.version() != synapse.version() || ours.public_key() != synapse.public_key() {
		problem(format!(
			"this server's signing key is ed25519:{}, not Synapse's ed25519:{}; set \
			 signing_key_path = \"{}\" and use a new database",
			ours.version(),
			synapse.version(),
			config.signing_key_path.display()
		));
	}
}
