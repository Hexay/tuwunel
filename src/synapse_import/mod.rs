//! One-shot import of a stopped Synapse server into a new tuwunel database,
//! behind `tuwunel --import-synapse`. The operator's guide is
//! docs/deploying/migrating-from-synapse.md.
//!
//! [`import`] runs the preflight checks, which refuse before anything is
//! written, then these phases in order, each relying only on earlier ones:
//!
//! 1. identity: Synapse's old signing keys
//! 2. accounts: users, password hashes, admin rights, moderation, profiles
//! 3. threepids: email bindings
//! 4. sso: single sign-on links
//! 5. oauth_clients: MAS's OAuth clients (MAS only)
//! 6. appservices: registrations
//! 7. sessions: devices, their access and refresh tokens, dehydrated devices
//! 8. crypto: cross-signing, device, one-time and fallback keys
//! 9. backups: server-side key backups
//! 10. inbox: undelivered to-device messages
//! 11. rooms: events, state, aliases, the public room directory
//! 12. receipts
//! 13. media: the local media store
//! 14. userdata: account data, tags, filters
//! 15. push_rules
//! 16. admin: blocked rooms, registration tokens
//! 17. leftovers: counts what tuwunel has no place for
//! 18. pushers: last, so nothing imported earlier triggers a push
//!
//! The import is resumable at phase granularity: each phase is stamped done in
//! the `global` column family once it completes. A rerun with
//! `--import-resume` skips stamped phases and reruns the first unfinished one
//! from its start, so every phase must be idempotent, re-applying whatever an
//! interrupted run already wrote rather than skipping it.
//!
//! A malformed row is skipped and named in the [`Report`]; only a failing
//! database or service stops the import.

mod accounts;
mod admin;
mod appservices;
mod backups;
mod config;
mod crypto;
#[cfg(any(feature = "fuzzing", test))]
#[doc(hidden)]
pub mod fuzz;
mod identity;
mod inbox;
mod leftovers;
mod mas;
mod media;
mod preflight;
mod push_rules;
mod pushers;
mod receipts;
mod rooms;
mod sessions;
mod source;
mod sso;
mod threepids;
mod userdata;

use std::{
	fmt::{self, Display},
	path::{Path, PathBuf},
};

use serde::Serialize;
use tuwunel_core::{Err, Result, err, info, warn};
use tuwunel_service::Services;

use self::{config::SynapseConfig, mas::Mas, source::Source};

/// What to import from.
#[derive(Clone)]
pub struct Import {
	/// Synapse's homeserver.yaml.
	pub synapse_config: PathBuf,

	/// Synapse's PostgreSQL database, as a libpq connection string or URL.
	pub synapse_db: String,

	/// For a Synapse that delegated logins to MAS: MAS's database, like
	/// `synapse_db`, and its config.yaml. Both or neither.
	pub mas_db: Option<String>,
	pub mas_config: Option<PathBuf>,

	/// Continue an import that stopped partway.
	pub resume: bool,

	/// Imports into a throwaway database that is deleted afterwards; media is
	/// checked, not copied.
	pub dry_run: bool,
}

/// Leaves out the connection strings, which may hold passwords.
impl fmt::Debug for Import {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("Import")
			.field("synapse_config", &self.synapse_config)
			.field("mas_config", &self.mas_config)
			.field("resume", &self.resume)
			.field("dry_run", &self.dry_run)
			.finish_non_exhaustive()
	}
}

/// What an import carried over, and what it had to leave behind. A resumed
/// import counts only what it did itself.
#[derive(Debug, Default, Serialize)]
pub struct Report {
	pub dry_run: bool,
	pub resumed: bool,
	pub old_keys: usize,
	pub users: usize,
	pub deactivated: usize,
	pub admins: usize,
	pub locked: usize,
	pub suspended: usize,
	pub profiles: usize,
	pub threepids: usize,
	pub sso: usize,
	pub oauth_clients: usize,
	pub devices: usize,
	pub tokens: usize,
	pub dehydrated_devices: usize,
	pub cross_signing: usize,
	pub device_keys: usize,
	pub one_time_keys: usize,
	pub fallback_keys: usize,
	pub signatures: usize,
	pub backups: usize,
	pub room_keys: usize,
	pub to_device: usize,
	pub account_data: usize,
	pub tags: usize,
	pub filters: usize,
	pub push_rules: usize,
	pub pushers: usize,
	pub rooms: usize,
	pub events: usize,
	pub outliers: usize,
	pub soft_failed: usize,
	pub public_rooms: usize,
	pub aliases: usize,
	pub receipts: usize,
	pub media: usize,
	pub appservices: usize,
	pub blocked_rooms: usize,
	pub registration_tokens: usize,
	pub skipped: Vec<String>,
}

const STARTED_MARKER: &str = "synapse_import";
const FINISHED_MARKER: &str = "synapse_import_finished";

/// Runs a phase unless an earlier run already stamped it done.
macro_rules! phase {
	($services:expr, $marker:literal, $run:expr) => {
		if !marker_present($services, $marker) {
			info!("Importing {}", $marker.trim_start_matches("synapse_import_"));
			$run.await?;
			stamp($services, $marker);
		}
	};
}

/// Imports a stopped Synapse server into this server's new database.
pub async fn import(services: &Services, import: &Import) -> Result<Report> {
	let config = SynapseConfig::read(&import.synapse_config)?;
	let source = Source::connect(&import.synapse_db).await?;
	let mas = Mas::connect(import).await?;
	let mas = mas.as_ref();
	if marker_present(services, FINISHED_MARKER) {
		return Err!("This database already holds a finished Synapse import");
	}

	let resuming = marker_present(services, STARTED_MARKER);
	if resuming && !import.resume {
		return Err!(
			"An import into this database stopped partway; run again with --import-resume to \
			 continue it"
		);
	}

	preflight::check(services, &config, &source, mas, resuming).await?;
	stamp(services, STARTED_MARKER);

	let mut report = Report {
		dry_run: import.dry_run,
		resumed: resuming,
		..Report::default()
	};
	let r = &mut report;

	phase!(services, "synapse_import_identity", identity::import(services, &config, r));
	phase!(services, "synapse_import_accounts", accounts::import(services, &source, mas, r));
	phase!(
		services,
		"synapse_import_threepids",
		threepids::import(services, &source, mas, r)
	);
	phase!(services, "synapse_import_sso", sso::import(services, &config, &source, mas, r));
	if let Some(mas) = mas {
		phase!(services, "synapse_import_oauth_clients", mas::clients::import(services, mas, r));
	}
	phase!(
		services,
		"synapse_import_appservices",
		appservices::import(services, &config, r)
	);
	phase!(services, "synapse_import_sessions", sessions::import(services, &source, mas, r));
	phase!(services, "synapse_import_crypto", crypto::import(services, &source, r));
	phase!(services, "synapse_import_backups", backups::import(services, &source, r));
	phase!(services, "synapse_import_inbox", inbox::import(services, &source, r));
	phase!(services, "synapse_import_rooms", rooms::import(services, &source, r));
	phase!(services, "synapse_import_receipts", receipts::import(services, &source, r));
	phase!(
		services,
		"synapse_import_media",
		media::import(services, &source, &config.media_store_path, import.dry_run, r)
	);
	phase!(services, "synapse_import_userdata", userdata::import(services, &source, r));
	phase!(services, "synapse_import_push_rules", push_rules::import(services, &source, r));
	phase!(services, "synapse_import_admin", admin::import(services, &config, &source, r));
	phase!(services, "synapse_import_leftovers", leftovers::report(&source, mas, r));
	phase!(services, "synapse_import_pushers", pushers::import(services, &source, r));

	stamp(services, FINISHED_MARKER);
	report.log();
	Ok(report)
}

impl Report {
	pub fn write_json(&self, path: &Path) -> Result {
		let json = serde_json::to_vec_pretty(self).expect("the report serializes");

		std::fs::write(path, json)
			.map_err(|e| err!("Cannot write the import report to {}: {e}", path.display()))
	}

	fn skip(&mut self, why: String) { self.skipped.push(why); }

	/// A row's value, or `None` with the row reported as skipped, so one
	/// malformed row doesn't stop the import.
	fn keep<T>(&mut self, what: impl Display, value: Result<T>) -> Option<T> {
		value
			.map_err(|e| self.skip(format!("{what}: {e}")))
			.ok()
	}

	fn count(counter: &mut usize) { *counter = counter.saturating_add(1); }

	fn log(&self) {
		let mut counts = serde_json::to_value(self).expect("the report serializes");
		counts
			.as_object_mut()
			.expect("the report is an object")
			.remove("skipped");

		info!(skipped = self.skipped.len(), "Synapse import finished: {counts}");

		for why in &self.skipped {
			warn!("Not imported: {why}");
		}
	}
}

fn marker_present(services: &Services, marker: &str) -> bool {
	services.db["global"]
		.get_blocking(marker.as_bytes())
		.is_ok()
}

fn stamp(services: &Services, marker: &str) {
	services.db["global"].insert(marker.as_bytes(), []);
}
