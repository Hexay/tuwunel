use ruma::{api::client::backup::BackupAlgorithm, serde::Raw, user_id};
use serde_json::json;
use tuwunel_core::{Result, config::Figment};

use super::MAX_VERSION_LEAD;
use crate::test_utils::fixture;

fn algorithm() -> Raw<BackupAlgorithm> {
	let json = json!({
		"algorithm": "m.megolm_backup.v1.curve25519-aes-sha2",
		"auth_data": {
			"public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
			"signatures": {}
		}
	})
	.to_string();

	Raw::from_json_string(json).expect("valid backup algorithm JSON")
}

#[tokio::test]
async fn chosen_version_is_never_allocated_again() -> Result {
	let Some(fixture) = fixture(Figment::new()).await? else {
		return Ok(());
	};

	let key_backups = &fixture.services.key_backups;
	let user_id = user_id!("@chosen:localhost");

	// Ahead of the global sequence, as on a young database.
	let chosen = fixture
		.services
		.globals
		.pending_count()
		.end
		.saturating_add(7);

	key_backups
		.create_backup_with_version(user_id, chosen, &algorithm())
		.await?;

	assert_eq!(
		key_backups
			.get_latest_backup_version(user_id)
			.await?,
		chosen.to_string()
	);

	key_backups
		.create_backup_with_version(user_id, chosen, &algorithm())
		.await
		.expect_err("an existing version is refused");

	let created = key_backups
		.create_backup(user_id, &algorithm())
		.await?;

	assert!(created.parse::<u64>()? > chosen, "{created}");

	key_backups.delete_backup(user_id, &created).await;
	let recreated = key_backups
		.create_backup(user_id, &algorithm())
		.await?;

	assert!(recreated.parse::<u64>()? > created.parse::<u64>()?, "{recreated}");
	assert_eq!(
		key_backups
			.get_latest_backup_version(user_id)
			.await?,
		recreated
	);

	Ok(())
}

#[tokio::test]
async fn version_far_ahead_of_the_sequence_is_refused() -> Result {
	let Some(fixture) = fixture(Figment::new()).await? else {
		return Ok(());
	};

	let globals = &fixture.services.globals;
	let user_id = user_id!("@ahead:localhost");
	let ahead = globals
		.pending_count()
		.end
		.saturating_add(MAX_VERSION_LEAD)
		.saturating_add(1);

	fixture
		.services
		.key_backups
		.create_backup_with_version(user_id, ahead, &algorithm())
		.await
		.expect_err("a version far ahead is refused");

	assert!(globals.pending_count().end < ahead);

	Ok(())
}
