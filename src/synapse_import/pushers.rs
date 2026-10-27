//! Pushers: where each session's notifications go (a phone's push gateway, or
//! email).

use ruma::{
	OwnedDeviceId,
	api::client::push::set_pusher::v3::{PusherAction, PusherPostData},
};
use serde_json::{Value, json};
use tuwunel_core::Result;
use tuwunel_service::Services;

use super::{
	Report,
	source::{Source, json, user_id},
};

pub(super) async fn import(services: &Services, source: &Source, report: &mut Report) -> Result {
	// Older pushers name their session through the access token, not a device.
	let rows = source
		.rows(
			"SELECT p.user_name, coalesce(p.device_id, t.device_id), p.pushkey, \
			 coalesce(p.enabled, true), p.kind, p.app_id, p.app_display_name, \
			 p.device_display_name, p.lang, p.profile_tag, p.data FROM pushers p LEFT JOIN \
			 access_tokens t ON t.id = p.access_token ORDER BY p.user_name, p.id",
			&[],
		)
		.await?;

	for row in rows {
		let Some(user_id) = report.keep("pusher", user_id(&row, 0)) else {
			continue;
		};

		if !services.users.is_active(&user_id).await {
			continue;
		}

		let pushkey: &str = row.get(2);
		let device_id = row
			.get::<_, Option<String>>(1)
			.map(OwnedDeviceId::from);
		let Some(device_id) = device_id else {
			report.skip(format!("{user_id} pusher {pushkey}: no session to attach it to"));
			continue;
		};

		if !services
			.users
			.device_exists(&user_id, &device_id)
			.await
		{
			continue;
		}

		if !row.get::<_, bool>(3) {
			report.skip(format!("{user_id} pusher {pushkey}: disabled pushers aren't imported"));
			continue;
		}

		let data = row
			.get::<_, Option<&str>>(10)
			.map(json)
			.transpose()
			.map(|data| data.unwrap_or_else(|| Value::Object(Default::default())));

		// A NULL lang fails to parse below, so the pusher is reported.
		let pusher = data.and_then(|data| {
			Ok(serde_json::from_value::<PusherPostData>(json!({
				"pushkey": pushkey,
				"kind": row.get::<_, &str>(4),
				"app_id": row.get::<_, &str>(5),
				"app_display_name": row.get::<_, &str>(6),
				"device_display_name": row.get::<_, &str>(7),
				"lang": row.get::<_, Option<&str>>(8),
				"profile_tag": row.get::<_, Option<&str>>(9),
				"data": data,
			}))?)
		});

		let result = match pusher {
			| Ok(pusher) =>
				services
					.pusher
					.set_pusher(&user_id, &device_id, &PusherAction::Post(pusher))
					.await,
			| Err(e) => Err(e),
		};

		match result {
			| Ok(()) => Report::count(&mut report.pushers),
			| Err(e) => report.skip(format!("{user_id} pusher {pushkey}: {e}")),
		}
	}

	Ok(())
}
