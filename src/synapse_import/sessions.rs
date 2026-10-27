//! Devices and their access and refresh tokens, so clients stay logged in.

use std::{collections::HashMap, net::IpAddr, time::Duration};

use ruma::{
	DeviceId, MilliSecondsSinceUnixEpoch, OwnedDeviceId, OwnedUserId, UserId,
	serde::Raw as RawJson,
};
use tokio_postgres::Row;
use tuwunel_core::{Result, err};
use tuwunel_service::{Services, users::device::TOKEN_LENGTH};

use super::{
	Report,
	mas::{self, Mas},
	source::{Source, user_id},
};

pub(super) struct Token {
	pub(super) token: String,
	pub(super) valid_until_ms: Option<i64>,

	/// The refresh token the client holds alongside this access token.
	pub(super) refresh: Option<String>,

	/// From an OAuth 2.0 login, which tuwunel's OAuth endpoints serve.
	pub(super) oidc: bool,
}

/// Each device's current token.
pub(super) type Tokens = HashMap<(OwnedUserId, OwnedDeviceId), Token>;

pub(super) async fn import(
	services: &Services,
	source: &Source,
	mas: Option<&Mas>,
	report: &mut Report,
) -> Result {
	let mut tokens = match mas {
		| Some(mas) => mas::sessions::tokens(mas, services, report).await?,
		| None => latest_tokens(source, report).await?,
	};

	// Hidden devices are Synapse's records of cross-signing keys, not sessions.
	let rows = source
		.rows(
			"SELECT user_id, device_id, display_name, ip FROM devices WHERE NOT \
			 coalesce(hidden, false) ORDER BY user_id, device_id",
			&[],
		)
		.await?;

	for row in rows {
		let Some(user_id) = report.keep("devices", user_id(&row, 0)) else {
			continue;
		};

		if !services.users.is_active(&user_id).await {
			continue;
		}

		let device_id: OwnedDeviceId = row.get::<_, String>(1).into();
		let token = tokens.remove(&(user_id.clone(), device_id.clone()));
		import_device(services, &row, &user_id, &device_id, token, report).await;
	}

	report_orphans(services, tokens, mas.is_some(), report).await;
	import_dehydrated(services, source, report).await
}

/// Creates the device with its tokens unless an interrupted run already did,
/// and marks an OAuth 2.0 session's device either way.
async fn import_device(
	services: &Services,
	row: &Row,
	user_id: &UserId,
	device_id: &DeviceId,
	token: Option<Token>,
	report: &mut Report,
) {
	// Shorter access tokens are refused when issued; Synapse's `syt_` tokens are longer.
	let token = match token {
		| Some(token) if token.token.len() < TOKEN_LENGTH => {
			report.skip(format!(
				"{user_id} {device_id}: access token too short to keep; sign in again"
			));
			None
		},
		| token => token,
	};

	if !services
		.users
		.device_exists(user_id, device_id)
		.await
		&& let Err(e) = create_device(services, row, user_id, device_id, token.as_ref()).await
	{
		report.skip(format!("{user_id} {device_id}: {e}"));
		return;
	}

	if token.as_ref().is_some_and(|token| token.oidc) {
		// An empty identity provider ID records it as unknown.
		services
			.users
			.mark_oidc_device(user_id, device_id, "");
	}

	Report::count(&mut report.devices);
	if token.is_some() {
		Report::count(&mut report.tokens);
	}
}

async fn create_device(
	services: &Services,
	row: &Row,
	user_id: &UserId,
	device_id: &DeviceId,
	token: Option<&Token>,
) -> Result {
	let display_name: Option<String> = row.get(2);
	let ip: Option<IpAddr> = row
		.get::<_, Option<String>>(3)
		.and_then(|ip| ip.parse().ok());

	let access = token.map_or((None, None), |token| {
		(Some(token.token.as_str()), token.valid_until_ms.map(expires_in))
	});

	let refresh = token.and_then(|token| token.refresh.as_deref());
	services
		.users
		.create_device(user_id, Some(device_id), access, refresh, display_name.as_deref(), ip)
		.await?;

	Ok(())
}

/// Tokens no imported device took: Synapse (or MAS) has a session whose device
/// row is missing, hidden, or was skipped.
async fn report_orphans(services: &Services, tokens: Tokens, mas: bool, report: &mut Report) {
	let mut orphans: Vec<_> = tokens.into_keys().collect();
	orphans.sort();

	let holder = if mas {
		"MAS has this session"
	} else {
		"Synapse has an access token"
	};
	for (user_id, device_id) in orphans {
		if services.users.is_active(&user_id).await {
			report.skip(format!(
				"{user_id} {device_id}: {holder}, but no such device was imported; sign in again"
			));
		}
	}
}

/// Synapse keeps a dehydrated device as a normal device, imported above, plus
/// its encrypted data.
async fn import_dehydrated(services: &Services, source: &Source, report: &mut Report) -> Result {
	let rows = source
		.rows(
			"SELECT user_id, device_id, device_data FROM dehydrated_devices ORDER BY user_id",
			&[],
		)
		.await?;

	for row in rows {
		let Some(user_id) = report.keep("dehydrated_devices", user_id(&row, 0)) else {
			continue;
		};

		if !services.users.is_active(&user_id).await {
			continue;
		}

		let device_id: OwnedDeviceId = row.get::<_, String>(1).into();
		let device_data =
			RawJson::from_json_string(row.get(2)).map_err(|e| err!("invalid device data: {e}"));
		let Some(device_data) =
			report.keep(format_args!("{user_id} dehydrated device {device_id}"), device_data)
		else {
			continue;
		};

		// Its device row may have been skipped, which is reported already.
		if let Err(e) = services
			.users
			.set_dehydrated_device_data(&user_id, &device_id, device_data)
			.await
		{
			report.skip(format!("{user_id} dehydrated device {device_id}: {e}"));
			continue;
		}

		Report::count(&mut report.dehydrated_devices);
	}

	Ok(())
}

/// The newest access token of each device. Tokens a server admin uses to act as
/// someone else (`puppets_user_id`) are not sessions of that user.
async fn latest_tokens(source: &Source, report: &mut Report) -> Result<Tokens> {
	let rows = source
		.rows(
			"SELECT DISTINCT ON (a.user_id, a.device_id) a.user_id, a.device_id, a.token, \
			 a.valid_until_ms, r.token FROM access_tokens a LEFT JOIN refresh_tokens r ON r.id \
			 = a.refresh_token_id WHERE a.device_id IS NOT NULL AND a.puppets_user_id IS NULL \
			 ORDER BY a.user_id, a.device_id, a.id DESC",
			&[],
		)
		.await?;

	let mut tokens = Tokens::with_capacity(rows.len());
	for row in rows {
		let Some(user_id) = report.keep("access_tokens", user_id(&row, 0)) else {
			continue;
		};

		let device_id: OwnedDeviceId = row.get::<_, String>(1).into();
		tokens.insert((user_id, device_id), Token {
			token: row.get(2),
			valid_until_ms: row.get(3),
			refresh: row.get(4),
			oidc: false,
		});
	}

	Ok(tokens)
}

/// An expired token still imports; it just fails as it would have on Synapse.
fn expires_in(valid_until_ms: i64) -> Duration {
	let now: i64 = MilliSecondsSinceUnixEpoch::now().get().into();

	Duration::from_millis(
		valid_until_ms
			.saturating_sub(now)
			.max(0)
			.unsigned_abs(),
	)
}

#[cfg(test)]
mod tests {
	use std::time::Duration;

	use ruma::MilliSecondsSinceUnixEpoch;

	use super::expires_in;

	#[test]
	fn expired_tokens_expire_at_once() {
		assert_eq!(expires_in(0), Duration::ZERO);
		assert_eq!(expires_in(i64::MIN), Duration::ZERO);
	}

	#[test]
	fn live_tokens_keep_their_remaining_lifetime() {
		let now: i64 = MilliSecondsSinceUnixEpoch::now().get().into();
		let left = expires_in(now.saturating_add(60_000));
		assert!(left <= Duration::from_mins(1));
		assert!(left > Duration::from_secs(50));
		assert!(expires_in(i64::MAX) > Duration::from_mins(1));
	}
}
