//! End-to-end encryption keys: cross-signing keys, device keys, one-time and
//! fallback keys, and the cross-signing signatures between them.

use std::{collections::BTreeMap, iter, pin::pin};

use futures::TryStreamExt;
use ruma::{
	DeviceId, OneTimeKeyId, OwnedDeviceId, OwnedOneTimeKeyId, OwnedUserId, UserId,
	encryption::{CrossSigningKey, OneTimeKey},
	serde::Raw,
};
use tokio_postgres::Row;
use tuwunel_core::{Err, Result, err};
use tuwunel_service::Services;

use super::{
	Report,
	source::{Source, raw_json, user_id},
};

pub(super) async fn import(services: &Services, source: &Source, report: &mut Report) -> Result {
	import_cross_signing_keys(services, source, report).await?;
	import_device_keys(services, source, report).await?;
	import_one_time_keys(services, source, report).await?;
	import_fallback_keys(services, source, report).await?;

	// Last: a signature is only accepted once both keys it links are stored.
	import_signatures(services, source, report).await
}

/// The user and device a row's first two columns name, if that device was
/// imported. A user ID that doesn't parse is reported.
pub(super) async fn existing_device(
	services: &Services,
	row: &Row,
	report: &mut Report,
) -> Option<(OwnedUserId, OwnedDeviceId)> {
	let user_id = report.keep("device owner", user_id(row, 0))?;
	let device_id: OwnedDeviceId = row.get::<_, String>(1).into();

	services
		.users
		.device_exists(&user_id, &device_id)
		.await
		.then_some((user_id, device_id))
}

async fn import_cross_signing_keys(
	services: &Services,
	source: &Source,
	report: &mut Report,
) -> Result {
	// Synapse keeps every key a user ever uploaded; only the newest of each kind is current.
	let rows = source
		.rows(
			"SELECT DISTINCT ON (user_id, keytype) user_id, keytype, keydata FROM \
			 e2e_cross_signing_keys ORDER BY user_id, keytype, stream_id DESC",
			&[],
		)
		.await?;

	let mut keys: BTreeMap<OwnedUserId, [Option<Raw<CrossSigningKey>>; 3]> = BTreeMap::new();
	for row in rows {
		let Some(user_id) = report.keep("cross-signing key", user_id(&row, 0)) else {
			continue;
		};

		let kind: &str = row.get(1);
		let slot = match kind {
			| "master" => Ok(0),
			| "self_signing" => Ok(1),
			| "user_signing" => Ok(2),
			| other => Err!("unknown type {other:?}"),
		};
		let key = slot.and_then(|slot| Ok((slot, raw_json(row.get(2))?)));
		if let Some((slot, key)) =
			report.keep(format_args!("{user_id} cross-signing key {kind}"), key)
		{
			keys.entry(user_id).or_default()[slot] = Some(key);
		}
	}

	for (user_id, [master, self_signing, user_signing]) in keys {
		if !services.users.is_active(&user_id).await {
			continue;
		}

		match services
			.users
			.add_cross_signing_keys(&user_id, &master, &self_signing, &user_signing, false)
			.await
		{
			| Ok(()) => Report::count(&mut report.cross_signing),
			| Err(e) => report.skip(format!("{user_id}: cross-signing keys: {e}")),
		}
	}

	Ok(())
}

async fn import_device_keys(services: &Services, source: &Source, report: &mut Report) -> Result {
	let rows = source
		.rows(
			"SELECT user_id, device_id, key_json FROM e2e_device_keys_json ORDER BY user_id, \
			 device_id",
			&[],
		)
		.await?;

	for row in rows {
		let Some((user_id, device_id)) = existing_device(services, &row, report).await else {
			continue;
		};

		let Some(keys) =
			report.keep(format_args!("{user_id} {device_id} device keys"), raw_json(row.get(2)))
		else {
			continue;
		};

		let added = services
			.users
			.add_device_keys(&user_id, &device_id, &keys)
			.await;

		if report
			.keep(format_args!("{user_id} {device_id} device keys"), added)
			.is_some()
		{
			Report::count(&mut report.device_keys);
		}
	}

	Ok(())
}

async fn import_one_time_keys(
	services: &Services,
	source: &Source,
	report: &mut Report,
) -> Result {
	// Upload order, so /keys/claim hands out the oldest first as Synapse did (MSC4225).
	let mut rows = pin!(
		source
			.stream(
				"SELECT user_id, device_id, algorithm, key_id, key_json FROM \
				 e2e_one_time_keys_json ORDER BY user_id, device_id, ts_added_ms, key_id",
				&[],
			)
			.await?
	);

	while let Some(row) = rows.try_next().await? {
		let Some((user_id, device_id)) = existing_device(services, &row, report).await else {
			continue;
		};

		// One key per call: a batch is stored in key ID order, not upload order.
		let key = one_time_key_id(row.get(2), row.get(3))
			.and_then(|id| Ok((id, raw_json(row.get(4))?)));
		let Some(key) = report.keep(format_args!("{user_id} {device_id} one-time key"), key)
		else {
			continue;
		};

		let keys = BTreeMap::from([key]);
		let added = services
			.users
			.add_one_time_keys(&user_id, &device_id, &keys, 1)
			.await;

		if report
			.keep(format_args!("{user_id} {device_id} one-time key"), added)
			.is_some()
		{
			Report::count(&mut report.one_time_keys);
		}
	}

	Ok(())
}

async fn import_fallback_keys(
	services: &Services,
	source: &Source,
	report: &mut Report,
) -> Result {
	let rows = source
		.rows(
			"SELECT user_id, device_id, algorithm, key_id, key_json, used FROM \
			 e2e_fallback_keys_json ORDER BY user_id, device_id, algorithm",
			&[],
		)
		.await?;

	for row in rows {
		let Some((user_id, device_id)) = existing_device(services, &row, report).await else {
			continue;
		};

		let key = one_time_key_id(row.get(2), row.get(3))
			.and_then(|id| Ok((id, raw_json(row.get(4))?)));
		let Some((key_id, key)) =
			report.keep(format_args!("{user_id} {device_id} fallback key"), key)
		else {
			continue;
		};

		let used = row.get(5);
		let added = add_fallback_key(services, &user_id, &device_id, &key_id, &key, used).await;
		if report
			.keep(format_args!("{user_id} {device_id} fallback key"), added)
			.is_some()
		{
			Report::count(&mut report.fallback_keys);
		}
	}

	Ok(())
}

async fn add_fallback_key(
	services: &Services,
	user_id: &UserId,
	device_id: &DeviceId,
	key_id: &OneTimeKeyId,
	key: &Raw<OneTimeKey>,
	used: bool,
) -> Result {
	services
		.users
		.add_fallback_keys(user_id, device_id, iter::once((key_id, key)))
		.await?;

	// Claiming is the only way tuwunel marks a fallback key used; the key itself stays.
	if used {
		services
			.users
			.take_fallback_key(user_id, device_id, &key_id.algorithm())
			.await?;
	}

	Ok(())
}

/// Signatures uploaded through /keys/signatures/upload. Synapse keeps them
/// apart from the keys they sign; tuwunel stores them inside the signed key,
/// after checking them.
async fn import_signatures(services: &Services, source: &Source, report: &mut Report) -> Result {
	let rows = source
		.rows(
			"SELECT user_id, key_id, target_user_id, target_device_id, signature FROM \
			 e2e_cross_signing_signatures ORDER BY user_id, target_user_id, target_device_id",
			&[],
		)
		.await?;

	for row in rows {
		let users = user_id(&row, 0).and_then(|signer| Ok((signer, user_id(&row, 2)?)));
		let Some((signer, target)) = report.keep("cross-signing signature", users) else {
			continue;
		};

		if !services.users.is_active(&signer).await {
			continue;
		}

		let target_key: String = row.get(3);
		let signature = [(row.get::<_, String>(1), row.get::<_, String>(4))];

		match services
			.users
			.sign_key(&target, &target_key, signature.into(), &signer)
			.await
		{
			| Ok(()) => Report::count(&mut report.signatures),
			| Err(e) =>
				report.skip(format!("{signer}'s signature on {target} {target_key}: {e}")),
		}
	}

	Ok(())
}

fn one_time_key_id(algorithm: &str, key_id: &str) -> Result<OwnedOneTimeKeyId> {
	let id = format!("{algorithm}:{key_id}");

	id.as_str()
		.try_into()
		.map_err(|e| err!("Synapse one-time key ID {id:?}: {e}"))
}

#[cfg(test)]
mod tests;
