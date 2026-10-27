//! Account data (global and per room, including the DM list and ignored
//! users), room tags and sync filters.

use std::{collections::BTreeMap, pin::pin};

use futures::TryStreamExt;
use ruma::{OwnedRoomId, OwnedUserId, RoomId, UserId, api::client::filter::FilterDefinition};
use serde_json::{Map, Value, json};
use tuwunel_core::{Result, err};
use tuwunel_service::Services;

use super::{
	Report,
	source::{Source, json, user_id},
};

pub(super) async fn import(services: &Services, source: &Source, report: &mut Report) -> Result {
	import_account_data(services, source, report).await?;
	import_room_account_data(services, source, report).await?;
	import_tags(services, source, report).await?;
	import_filters(services, source, report).await
}

/// Synapse marks deleted account data with `{}` content (MSC3391) and serves
/// none of it. Its m.push_rules is built from its own tables; see push_rules.rs.
async fn import_account_data(
	services: &Services,
	source: &Source,
	report: &mut Report,
) -> Result {
	let mut rows = pin!(
		source
			.stream(
				"SELECT user_id, account_data_type, content FROM account_data WHERE \
				 account_data_type <> 'm.push_rules' AND content <> '{}' ORDER BY user_id, \
				 stream_id",
				&[],
			)
			.await?
	);

	while let Some(row) = rows.try_next().await? {
		let Some(user_id) = report.keep("account data", user_id(&row, 0)) else {
			continue;
		};

		let kind: &str = row.get(1);
		if !services.users.is_active(&user_id).await {
			continue;
		}

		let Some(content) = report.keep(format_args!("{user_id} {kind}"), json(row.get(2)))
		else {
			continue;
		};

		let added = put(services, None, &user_id, kind, content).await;
		if report
			.keep(format_args!("{user_id} {kind}"), added)
			.is_some()
		{
			Report::count(&mut report.account_data);
		}
	}

	Ok(())
}

async fn import_room_account_data(
	services: &Services,
	source: &Source,
	report: &mut Report,
) -> Result {
	let mut rows = pin!(
		source
			.stream(
				"SELECT user_id, room_id, account_data_type, content FROM room_account_data \
				 WHERE content <> '{}' ORDER BY user_id, stream_id",
				&[],
			)
			.await?
	);

	while let Some(row) = rows.try_next().await? {
		let Some(user_id) = report.keep("room account data", user_id(&row, 0)) else {
			continue;
		};

		let (room, kind): (&str, &str) = (row.get(1), row.get(2));
		if !services.users.is_active(&user_id).await {
			continue;
		}

		let parsed = room_id(room).and_then(|room_id| Ok((room_id, json(row.get(3))?)));
		let Some((room_id, content)) =
			report.keep(format_args!("{user_id} {room} {kind}"), parsed)
		else {
			continue;
		};

		let added = put(services, Some(&room_id), &user_id, kind, content).await;
		if report
			.keep(format_args!("{user_id} {room} {kind}"), added)
			.is_some()
		{
			Report::count(&mut report.account_data);
		}
	}

	Ok(())
}

/// Synapse keeps tags in their own table; clients see them as each room's
/// `m.tag` account data.
async fn import_tags(services: &Services, source: &Source, report: &mut Report) -> Result {
	let rows = source
		.rows("SELECT user_id, room_id, tag, content FROM room_tags", &[])
		.await?;

	let mut tags: BTreeMap<(OwnedUserId, OwnedRoomId), Map<String, Value>> = BTreeMap::new();
	for row in rows {
		let (user, room, tag): (&str, &str, String) = (row.get(0), row.get(1), row.get(2));
		let parsed =
			user_id(&row, 0).and_then(|user_id| Ok((user_id, room_id(room)?, json(row.get(3))?)));

		if let Some((user_id, room_id, content)) =
			report.keep(format_args!("{user} {room} tag {tag}"), parsed)
		{
			tags.entry((user_id, room_id))
				.or_default()
				.insert(tag, content);
		}
	}

	for ((user_id, room_id), tags) in tags {
		if !services.users.is_active(&user_id).await {
			continue;
		}

		let count = tags.len();
		let content = json!({ "tags": tags });
		let added = put(services, Some(&room_id), &user_id, "m.tag", content).await;
		if report
			.keep(format_args!("{user_id} {room_id} tags"), added)
			.is_some()
		{
			report.tags = report.tags.saturating_add(count);
		}
	}

	Ok(())
}

async fn import_filters(services: &Services, source: &Source, report: &mut Report) -> Result {
	let server_name = services.globals.server_name();

	// Older rows name the user by localpart only.
	let mut rows = pin!(
		source
			.stream(
				"SELECT user_id, full_user_id, filter_id, filter_json FROM user_filters ORDER \
				 BY user_id, filter_id",
				&[],
			)
			.await?
	);

	while let Some(row) = rows.try_next().await? {
		let user_id = match row.get::<_, Option<&str>>(1) {
			| Some(full) => UserId::parse(full),
			| None => UserId::parse_with_server_name(row.get::<_, &str>(0), server_name),
		};

		let user_id = user_id.map_err(|e| err!("invalid user ID: {e}"));
		let Some(user_id) = report.keep("filter", user_id) else {
			continue;
		};

		if !services.users.is_active(&user_id).await {
			continue;
		}

		let filter_id = row.get::<_, i64>(2).to_string();
		match serde_json::from_slice::<FilterDefinition>(row.get(3)) {
			| Ok(filter) => {
				services
					.users
					.set_filter(&user_id, &filter_id, &filter);
				Report::count(&mut report.filters);
			},
			| Err(e) => report.skip(format!("{user_id} filter {filter_id}: {e}")),
		}
	}

	Ok(())
}

async fn put(
	services: &Services,
	room_id: Option<&RoomId>,
	user_id: &UserId,
	event_type: &str,
	content: Value,
) -> Result {
	let event = json!({ "type": event_type, "content": content });
	services
		.account_data
		.update(room_id, user_id, event_type.into(), &event)
		.await
}

fn room_id(room_id: &str) -> Result<OwnedRoomId> {
	room_id
		.try_into()
		.map_err(|e| err!("Synapse room ID {room_id:?}: {e}"))
}
