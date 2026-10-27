//! To-device messages still waiting for their device, such as room keys sent
//! while it was offline.

use std::{collections::HashSet, pin::pin};

use futures::TryStreamExt;
use ruma::{OwnedDeviceId, OwnedUserId};
use serde::Deserialize;
use serde_json::Value;
use tuwunel_core::{Result, err};
use tuwunel_service::Services;

use super::{Report, crypto::existing_device, source::Source};

#[derive(Deserialize)]
pub(super) struct Message {
	sender: OwnedUserId,
	#[serde(rename = "type")]
	event_type: String,
	content: Value,
}

pub(super) async fn import(services: &Services, source: &Source, report: &mut Report) -> Result {
	let mut rows = pin!(
		source
			.stream(
				"SELECT user_id, device_id, message_json FROM device_inbox ORDER BY stream_id",
				&[],
			)
			.await?
	);

	let mut cleared: HashSet<(OwnedUserId, OwnedDeviceId)> = HashSet::new();
	while let Some(row) = rows.try_next().await? {
		let Some((user_id, device_id)) = existing_device(services, &row, report).await else {
			continue;
		};

		// Only this phase fills these queues; emptied first so a rerun doesn't deliver twice.
		if cleared.insert((user_id.clone(), device_id.clone())) {
			services
				.users
				.remove_to_device_events(&user_id, &device_id, None::<u64>)
				.await;
		}

		let message = serde_json::from_str::<Message>(row.get(2))
			.map_err(|e| err!("invalid to-device message: {e}"));
		let Some(message) = report.keep(format_args!("{user_id} {device_id}"), message) else {
			continue;
		};

		services.users.add_to_device_event(
			&message.sender,
			&user_id,
			&device_id,
			&message.event_type,
			&message.content,
		);

		Report::count(&mut report.to_device);
	}

	let unsent = source.count("device_federation_outbox").await?;
	if unsent > 0 {
		report.skip(format!(
			"{unsent} to-device messages for users on other servers were never sent"
		));
	}

	Ok(())
}
