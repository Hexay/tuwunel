//! `--import-synapse`: start the services without listening, import, then stop.
#![cfg(feature = "synapse_import")]

use std::{io::ErrorKind, path::Path, sync::Arc, time::Duration};

use tuwunel_core::{Err, Result};
use tuwunel_synapse_import::{self as synapse_import, Import};

use crate::{Args, Runtime, Server, async_run, async_start, async_stop};

/// Runs the import the arguments ask for, if any. Returns whether one ran.
pub fn exec_if_requested(server: &Arc<Server>, runtime: &Runtime, args: &Args) -> Result<bool> {
	let Some(synapse_config) = &args.import_synapse else {
		return Ok(false);
	};

	let Some(synapse_db) = &args.synapse_db else {
		return Err!("--import-synapse needs --synapse-db");
	};

	let import = Import {
		synapse_config: synapse_config.clone(),
		synapse_db: synapse_db.clone(),
		mas_db: args.mas_db.clone(),
		mas_config: args.mas_config.clone(),
		resume: args.import_resume,
		dry_run: args.import_dry_run,
	};

	// args.rs points a dry run at its own database; a leftover one is stale.
	let database_path = &server.server.config.database_path;
	if args.import_dry_run {
		remove_dry_run_database(database_path)?;
	}

	let report = runtime.block_on(async {
		let services = async_start(server).await?;
		let imported = synapse_import::import(&services, &import).await;

		// RocksDB isn't closed cleanly at shutdown (leaked Database references), so
		// unflushed memtables would make the first start replay the whole import.
		if imported.is_ok() && !args.import_dry_run {
			services.db.engine.sort()?;
		}

		server.server.shutdown()?;
		drop(services);

		async_run(server).await?;
		async_stop(server).await?;

		imported
	});

	if args.import_dry_run {
		remove_dry_run_database(database_path)?;
	}

	if let (Ok(report), Some(path)) = (&report, &args.import_report) {
		report.write_json(path)?;
	}

	report.map(|_| true)
}

fn remove_dry_run_database(path: &Path) -> Result {
	if path.extension() != Some("dry-run".as_ref()) {
		return Err!("Refusing to delete {}: not a dry-run database", path.display());
	}

	// RocksDB outlives shutdown (leaked Database references), and a background
	// flush can write files mid-delete; once its files are gone, it stops.
	let mut attempts = 0_u32;
	loop {
		match std::fs::remove_dir_all(path) {
			| Err(e) if e.kind() == ErrorKind::DirectoryNotEmpty && attempts < 20 => {
				attempts = attempts.saturating_add(1);
				std::thread::sleep(Duration::from_millis(100));
			},
			| Err(e) if e.kind() != ErrorKind::NotFound =>
				return Err!("Cannot delete the dry-run database {}: {e}", path.display()),
			| _ => return Ok(()),
		}
	}
}
