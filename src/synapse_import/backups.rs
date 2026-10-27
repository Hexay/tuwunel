//! Server-side room key backups, under the version numbers clients already
//! hold.

use std::pin::pin;

use futures::TryStreamExt;
use ruma::{OwnedRoomId, UserId, api::client::backup::KeyBackupData, serde::Raw};
use serde::Serialize;
use serde_json::value::{RawValue, to_raw_value};
use tokio_postgres::Row;
use tuwunel_core::{Result, err, utils::IterStream};
use tuwunel_service::Services;

use super::{
	Report,
	source::{Source, json_column, user_id},
};

/// Keys handed to tuwunel at once, which bounds what a user's backup holds in
/// memory.
const BATCH: usize = 1024;

type BackedUpKey = (OwnedRoomId, String, Raw<KeyBackupData>);

#[derive(Serialize)]
struct Metadata<'a> {
	algorithm: &'a str,
	auth_data: &'a RawValue,
}

#[derive(Serialize)]
struct SessionKey<'a> {
	first_message_index: i32,
	forwarded_count: i32,
	is_verified: bool,
	session_data: &'a RawValue,
}

pub(super) async fn import(services: &Services, source: &Source, report: &mut Report) -> Result {
	// Ascending, so each version is the latest when its keys are added; tuwunel
	// only writes keys into the latest version.
	let rows = source
		.rows(
			"SELECT user_id, version, algorithm, auth_data FROM e2e_room_keys_versions WHERE \
			 deleted = 0 ORDER BY user_id, version",
			&[],
		)
		.await?;

	for row in rows {
		let Some(user_id) = report.keep("key backup", user_id(&row, 0)) else {
			continue;
		};

		if !services.users.is_active(&user_id).await {
			continue;
		}

		let version: i64 = row.get(1);
		let version_string = version.to_string();

		// Found on a rerun; once a later version exists, this one already has all its keys.
		if services
			.key_backups
			.get_backup(&user_id, &version_string)
			.await
			.is_ok()
		{
			let latest = services
				.key_backups
				.get_latest_backup_version(&user_id)
				.await?;

			if latest != version_string {
				continue;
			}
		} else {
			let created = create_version(services, &user_id, &row).await;
			if report
				.keep(format_args!("{user_id} key backup {version}"), created)
				.is_none()
			{
				continue;
			}

			Report::count(&mut report.backups);
		}

		import_room_keys(services, source, &user_id, version, report).await?;
	}

	Ok(())
}

async fn create_version(services: &Services, user_id: &UserId, row: &Row) -> Result {
	let version: i64 = row.get(1);
	let auth_data = json_column(row.get(3))?;
	let metadata = to_raw_value(&Metadata {
		algorithm: row.get(2),
		auth_data: &auth_data,
	})?;

	let version = version
		.try_into()
		.map_err(|e| err!("invalid version: {e}"))?;

	services
		.key_backups
		.create_backup_with_version(user_id, version, &Raw::from_json(metadata))
		.await
}

async fn import_room_keys(
	services: &Services,
	source: &Source,
	user_id: &UserId,
	version: i64,
	report: &mut Report,
) -> Result {
	// The counters and flag are nullable in Synapse's schema.
	let mut rows = pin!(
		source
			.stream(
				"SELECT room_id, session_id, coalesce(first_message_index, 0), \
				 coalesce(forwarded_count, 0), coalesce(is_verified, false), session_data FROM \
				 e2e_room_keys WHERE user_id = $1 AND version = $2",
				&[&user_id.as_str(), &version],
			)
			.await?
	);

	let version = version.to_string();
	let mut batch = Vec::with_capacity(BATCH);
	while let Some(row) = rows.try_next().await? {
		let key = session_key(&row);
		if let Some(key) = report.keep(format_args!("{user_id} backed-up key"), key) {
			batch.push(key);
		}

		if batch.len() >= BATCH {
			add_batch(services, user_id, &version, &mut batch, report).await;
		}
	}

	add_batch(services, user_id, &version, &mut batch, report).await;

	Ok(())
}

fn session_key(row: &Row) -> Result<BackedUpKey> {
	let room_id: OwnedRoomId = row
		.get::<_, &str>(0)
		.try_into()
		.map_err(|e| err!("invalid room ID: {e}"))?;

	let session_data = json_column(row.get(5))?;
	let key = to_raw_value(&SessionKey {
		first_message_index: row.get(2),
		forwarded_count: row.get(3),
		is_verified: row.get(4),
		session_data: &session_data,
	})?;

	Ok((room_id, row.get(1), Raw::from_json(key)))
}

/// Adds the batch's keys to the backup, and empties it.
async fn add_batch(
	services: &Services,
	user_id: &UserId,
	version: &str,
	batch: &mut Vec<BackedUpKey>,
	report: &mut Report,
) {
	if batch.is_empty() {
		return;
	}

	let keys = batch
		.iter()
		.map(|(room_id, session_id, key)| (room_id.as_ref(), session_id.as_str(), key))
		.stream();

	let added = services
		.key_backups
		.add_keys(user_id, version, keys)
		.await;

	if report
		.keep(format_args!("{user_id} key backup {version}"), added)
		.is_some()
	{
		report.room_keys = report.room_keys.saturating_add(batch.len());
	}

	batch.clear();
}
