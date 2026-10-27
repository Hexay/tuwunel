//! Server-wide admin state: rooms an admin blocked, and registration tokens.

use std::time::{Duration, UNIX_EPOCH};

use ruma::{MilliSecondsSinceUnixEpoch, OwnedRoomId};
use tuwunel_core::{Result, err};
use tuwunel_service::{Services, registration_tokens::TokenExpires};

use super::{
	Report,
	config::SynapseConfig,
	source::{Source, user_id},
};

pub(super) async fn import(
	services: &Services,
	config: &SynapseConfig,
	source: &Source,
	report: &mut Report,
) -> Result {
	import_blocked_rooms(services, source, report).await?;
	import_registration_tokens(services, config, source, report).await
}

/// Blocked rooms need not exist locally; neither do tuwunel's bans.
async fn import_blocked_rooms(
	services: &Services,
	source: &Source,
	report: &mut Report,
) -> Result {
	let rows = source
		.rows("SELECT room_id, user_id FROM blocked_rooms ORDER BY room_id", &[])
		.await?;

	for row in rows {
		let room_id: Result<OwnedRoomId> = row
			.get::<_, &str>(0)
			.try_into()
			.map_err(|e| err!("invalid room ID: {e}"));
		let Some(room_id) = report.keep("blocked_rooms", room_id) else {
			continue;
		};

		match user_id(&row, 1) {
			| Ok(blocker) => services.metadata.block_room(&room_id, &blocker),
			| Err(_) => services.metadata.ban_room(&room_id),
		}

		Report::count(&mut report.blocked_rooms);
	}

	Ok(())
}

/// Only the tokens still usable. tuwunel demands a token from new users
/// whenever one exists, so they're imported only if Synapse demanded one too.
async fn import_registration_tokens(
	services: &Services,
	config: &SynapseConfig,
	source: &Source,
	report: &mut Report,
) -> Result {
	let now: i64 = MilliSecondsSinceUnixEpoch::now().get().into();
	let rows = source
		.rows(
			"SELECT token, uses_allowed, completed, expiry_time FROM registration_tokens WHERE \
			 (uses_allowed IS NULL OR completed < uses_allowed) AND (expiry_time IS NULL OR \
			 expiry_time > $1) ORDER BY token",
			&[&now],
		)
		.await?;

	if !config.registration_requires_token {
		if !rows.is_empty() {
			report.skip(format!(
				"{} registration tokens: Synapse didn't require one to register, and tuwunel \
				 would start to",
				rows.len()
			));
		}

		return Ok(());
	}

	for row in rows {
		let token: &str = row.get(0);
		if services
			.registration_tokens
			.get_token_info(token)
			.await
			.is_ok()
		{
			continue;
		}

		// The token itself stays out of the report.
		let limits = token_limits(row.get(2), row.get(1), row.get(3));
		let Some((uses, expires)) = report.keep("a registration token", limits) else {
			continue;
		};

		if let Err(e) = services
			.registration_tokens
			.create_token_with_uses(token, uses, expires)
			.await
		{
			report.skip(format!("a registration token: {e}"));
			continue;
		}

		Report::count(&mut report.registration_tokens);
	}

	Ok(())
}

/// Synapse's `completed`, `uses_allowed` and `expiry_time` as the uses so far
/// and tuwunel's limits. Registrations still pending on Synapse never finish
/// here, so only completed uses count.
fn token_limits(
	completed: i32,
	uses_allowed: Option<i32>,
	expiry_ms: Option<i64>,
) -> Result<(u64, TokenExpires)> {
	let count = |n: i32| u64::try_from(n).map_err(|_| err!("negative use count {n}"));
	let time = |ms: i64| {
		u64::try_from(ms)
			.ok()
			.and_then(|ms| UNIX_EPOCH.checked_add(Duration::from_millis(ms)))
			.ok_or_else(|| err!("invalid expiry time {ms}"))
	};

	let expires = TokenExpires {
		max_uses: uses_allowed.map(count).transpose()?,
		max_age: expiry_ms.map(time).transpose()?,
	};

	Ok((count(completed)?, expires))
}

#[cfg(test)]
mod tests {
	use std::time::{Duration, UNIX_EPOCH};

	use super::token_limits;

	#[test]
	fn token_limits_carry_over() {
		let (uses, expires) = token_limits(2, Some(5), Some(1_500)).expect("valid limits");
		assert_eq!(uses, 2);
		assert_eq!(expires.max_uses, Some(5));
		assert_eq!(expires.max_age, Some(UNIX_EPOCH + Duration::from_millis(1_500)));
	}

	#[test]
	fn absent_limits_stay_absent() {
		let (uses, expires) = token_limits(0, None, None).expect("valid limits");
		assert_eq!(uses, 0);
		assert_eq!(expires.max_uses, None);
		assert_eq!(expires.max_age, None);
	}

	#[test]
	fn negative_values_are_refused() {
		token_limits(-1, None, None).unwrap_err();
		token_limits(0, Some(-1), None).unwrap_err();
		token_limits(0, None, Some(-1)).unwrap_err();
	}
}
