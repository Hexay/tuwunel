#![cfg(test)]

use std::{iter::once, time::Duration};

use futures::StreamExt;
use serde_json::json;
use tuwunel_core::{
	Result,
	ruma::{
		OwnedEventId, RoomId, UserId,
		events::room::{
			member::{MembershipState, RoomMemberEventContent},
			message::RoomMessageEventContent,
		},
	},
};
use tuwunel_matrix::{event::Event, pdu::PduBuilder};
use tuwunel_service::Services;

use self::{
	client::{Client, poll_until, register},
	fixture::boot,
	timeline::{append_message, append_pdu},
};

mod client;
mod fixture;
mod timeline;

const ADMIN_TOKEN: &str = "import-effects-admin-access-token";
const READER_TOKEN: &str = "import-effects-reader-access-token";

const DEADLINE: Duration = Duration::from_secs(10);

/// Imported history is stored and searchable but replays none of its effects.
///
/// Each imported event has a live twin that does take effect. The workers run
/// in arrival order and the imported events go first, so once the live twin's
/// effect shows, the imported one would already have shown had it been queued.
/// Imports also leave the forward extremities and the sender's read marker.
#[test]
fn imported_events_notify_no_one_and_run_nothing() -> Result {
	let options = [
		"create_admin_room=true",
		"grant_admin_to_first_user=false",
		"auto_accept_invites=true",
	];

	boot("import-effects", options, exercise)
}

async fn exercise(services: &Services, base: &str) -> Result {
	let admin_id = register(services, "importadmin", ADMIN_TOKEN).await?;
	let reader_id = register(services, "importreader", READER_TOKEN).await?;
	let user = async |name: &str| {
		let token = format!("import-effects-{name}-access-token");

		register(services, name, &token).await
	};

	let imported_target = user("importedtarget").await?;
	let live_target = user("livetarget").await?;
	let imported_invitee = user("importedinvitee").await?;
	let live_invitee = user("liveinvitee").await?;

	services.admin.make_user_admin(&admin_id).await?;

	let admin = Client { services, base, token: ADMIN_TOKEN };
	let reader = Client { services, base, token: READER_TOKEN };
	let room = admin
		.create_room(&json!({ "preset": "public_chat" }))
		.await?;

	reader
		.post(&format!("rooms/{room}/join"), &json!({}))
		.await?;

	let admin_room = services.admin.get_admin_room().await?;
	let deactivate = |user_id: &UserId| {
		RoomMessageEventContent::text_plain(format!("!admin users deactivate {user_id}"))
	};

	let hello = RoomMessageEventContent::text_plain("hello");
	let invite = |user_id: &UserId| {
		let content = RoomMemberEventContent::new(MembershipState::Invite);

		PduBuilder::state(user_id.as_str(), &content)
	};

	let read_marker = async || {
		services
			.read_receipt
			.private_read_get_count(&room, &admin_id)
			.await
			.ok()
	};

	let marker_before = read_marker().await;
	let imported_hello =
		import_pdu(services, &admin_id, &room, PduBuilder::timeline(&hello)).await?;
	import_pdu(
		services,
		&admin_id,
		&admin_room,
		PduBuilder::timeline(&deactivate(&imported_target)),
	)
	.await?;
	import_pdu(services, &admin_id, &room, invite(&imported_invitee)).await?;

	services
		.timeline
		.get_pdu_id(&imported_hello)
		.await?;

	assert_eq!(read_marker().await, marker_before, "an import moved the sender's marker");
	assert_eq!(
		services
			.pusher
			.notification_count(&reader_id, &room)
			.await,
		0
	);

	append_message(services, &admin_id, &room, &hello).await?;
	assert_ne!(read_marker().await, marker_before, "the live event left its sender's marker");

	let search = json!({"search_categories": {"room_events": {
		"search_term": "hello", "filter": {"rooms": [room]}
	}}});
	let found = admin.post("search", &search).await?;
	assert_eq!(found["search_categories"]["room_events"]["count"], json!(2));

	append_message(services, &admin_id, &admin_room, &deactivate(&live_target)).await?;
	append_pdu(services, &admin_id, &room, invite(&live_invitee)).await?;

	let membership = async |user_id: &UserId| {
		services
			.state_cache
			.user_membership(user_id, &room)
			.await
	};

	let notified = async || {
		services
			.pusher
			.notification_count(&reader_id, &room)
			.await
			== 1
	};
	let commanded = async || {
		services
			.users
			.is_deactivated(&live_target)
			.await
			.unwrap_or(false)
	};

	let accepted = async || membership(&live_invitee).await == Some(MembershipState::Join);

	assert!(poll_until(DEADLINE, notified).await, "the live message never notified");
	assert!(poll_until(DEADLINE, commanded).await, "the live command never ran");
	assert!(poll_until(DEADLINE, accepted).await, "the live invite was never accepted");

	assert!(
		!services
			.users
			.is_deactivated(&imported_target)
			.await?,
		"an imported command ran"
	);
	assert_eq!(membership(&imported_invitee).await, Some(MembershipState::Invite));

	Ok(())
}

/// Append an event as history imported from another server, then make it the
/// room's forward extremity as an importer does once the room's history is in.
///
/// Fails if the append itself moved the extremities.
async fn import_pdu(
	services: &Services,
	sender: &UserId,
	room_id: &RoomId,
	builder: PduBuilder,
) -> Result<OwnedEventId> {
	let state_lock = services.state.mutex.lock(room_id).await;
	let (pdu, pdu_json) = services
		.timeline
		.create_hash_and_sign_event(builder, sender, room_id, &state_lock)
		.await?;

	let statehashid = services.state.append_to_state(&pdu).await?;
	let extremities = forward_extremities(services, room_id).await;

	services
		.timeline
		.append_imported_pdu(&pdu, pdu_json, &state_lock)
		.await?;

	assert_eq!(
		forward_extremities(services, room_id).await,
		extremities,
		"an imported append moved the forward extremities"
	);

	services
		.state
		.set_room_state(room_id, statehashid, &state_lock);

	services
		.state
		.set_forward_extremities(room_id, once(pdu.event_id()), &state_lock)
		.await;

	Ok(pdu.event_id().to_owned())
}

async fn forward_extremities(services: &Services, room_id: &RoomId) -> Vec<OwnedEventId> {
	services
		.state
		.get_forward_extremities(room_id)
		.map(ToOwned::to_owned)
		.collect()
		.await
}
