//! One room: its events, the state at each, its current state and forward
//! extremities. Modelled on how tuwunel accepts a federated event: stored as
//! an outlier first, then given its state and appended.

use std::{collections::HashSet, pin::pin, sync::Arc};

use futures::TryStreamExt;
use ruma::{EventId, OwnedUserId, RoomId, RoomVersionId, events::StateEventType};
use tuwunel_core::{Result, err};
use tuwunel_matrix::Event as _;
use tuwunel_service::{
	Services,
	rooms::{state::RoomMutexGuard, state_compressor::CompressedState},
};

use super::{
	super::{Report, source::Source},
	events::{self, Placement, imported},
	redactions,
	state::StateGroups,
};

pub(super) async fn import(
	services: &Services,
	source: &Source,
	room_id: &RoomId,
	version: &RoomVersionId,
	erased: &HashSet<OwnedUserId>,
	report: &mut Report,
) -> Result {
	let shortroomid = services
		.short
		.get_or_create_shortroomid(room_id)
		.await;

	let skipped =
		events::store_outliers(services, source, room_id, version, erased, report).await?;

	let mut groups = StateGroups::load(services, source, room_id).await?;
	let state_lock = services.state.mutex.lock(room_id).await;

	append_timeline(services, source, room_id, &mut groups, &state_lock, report).await?;

	let state = set_current_state(services, source, room_id, &state_lock).await?;
	let extremities =
		set_forward_extremities(services, source, room_id, &skipped, &state_lock).await?;

	let dropped = groups
		.dropped
		.saturating_add(state)
		.saturating_add(extremities);

	if dropped > 0 {
		report.skip(format!(
			"{room_id}: left out {dropped} state entries with an invalid event ID and forward \
			 extremities naming an event that wasn't imported"
		));
	}

	// After current state, so the room's power levels decide who could redact.
	redactions::apply_late(services, source, room_id, shortroomid, &state_lock, report).await
}

/// Gives each timeline event the state before it, then appends it, or only
/// marks it soft-failed.
async fn append_timeline(
	services: &Services,
	source: &Source,
	room_id: &RoomId,
	groups: &mut StateGroups,
	state_lock: &RoomMutexGuard,
	report: &mut Report,
) -> Result {
	let mut timeline = pin!(events::timeline(source, room_id).await?);
	while let Some(placement) = timeline.try_next().await? {
		let Placement { event_id, state_group, soft_failed } = placement;
		let event_id = &event_id;

		// Appended by an earlier run that stopped partway through this room.
		if services
			.timeline
			.get_pdu_id(event_id)
			.await
			.is_ok()
		{
			continue;
		}

		// Not stored when it couldn't be converted, which is already reported.
		let Ok(json) = services
			.timeline
			.get_outlier_pdu_json(event_id)
			.await
		else {
			continue;
		};

		let pdu = services
			.timeline
			.get_outlier_pdu(event_id)
			.await?;

		let before = groups
			.before(services, source, &pdu, state_group)
			.await
			.and_then(|before| {
				before.ok_or_else(|| err!("Synapse doesn't record the state before it"))
			});

		let Some(before) = report.keep(format_args!("{room_id} event {event_id}"), before) else {
			continue;
		};

		let shortstatehash = services
			.state
			.set_event_state(event_id, room_id, Arc::new(before))
			.await?;

		// The next event's state is stored as a diff against the room's current one.
		services
			.state
			.set_room_state(room_id, shortstatehash, state_lock);

		if soft_failed {
			services
				.pdu_metadata
				.mark_as_referenced(room_id, pdu.prev_events());
			services
				.pdu_metadata
				.mark_event_soft_failed(event_id);
			Report::count(&mut report.soft_failed);
			continue;
		}

		services
			.timeline
			.append_imported_pdu(&pdu, json, state_lock)
			.await?;

		Report::count(&mut report.events);
	}

	Ok(())
}

/// Synapse's current state, installed as the room's, with membership caches
/// brought in line. Events that couldn't be imported stay in it, as they do in
/// the state other servers hold. Returns how many entries had an invalid ID.
async fn set_current_state(
	services: &Services,
	source: &Source,
	room_id: &RoomId,
	state_lock: &RoomMutexGuard,
) -> Result<usize> {
	let rows = source
		.rows(
			"SELECT type, state_key, event_id FROM current_state_events WHERE room_id = $1",
			&[&room_id.as_str()],
		)
		.await?;

	if rows.is_empty() {
		return Ok(0);
	}

	let mut dropped: usize = 0;
	let mut state = CompressedState::new();
	for row in &rows {
		let Ok(event_id) = <&EventId>::try_from(row.get::<_, &str>(2)) else {
			dropped = dropped.saturating_add(1);
			continue;
		};

		let event_type = StateEventType::from(row.get::<_, &str>(0));
		let key = services
			.short
			.get_or_create_shortstatekey(&event_type, row.get(1))
			.await;

		state.insert(
			services
				.state_compressor
				.compress_state_event(key, event_id)
				.await,
		);
	}

	let saved = services
		.state_compressor
		.save_state(room_id, Arc::new(state))
		.await?;

	services
		.state
		.force_state(room_id, saved.shortstatehash, saved.added, saved.removed, state_lock)
		.await?;

	Ok(dropped)
}

/// Returns how many extremities named an event not imported: new events can't
/// build on one Tuwunel doesn't have.
async fn set_forward_extremities(
	services: &Services,
	source: &Source,
	room_id: &RoomId,
	skipped: &HashSet<String>,
	state_lock: &RoomMutexGuard,
) -> Result<usize> {
	let rows = source
		.rows("SELECT event_id FROM event_forward_extremities WHERE room_id = $1", &[
			&room_id.as_str()
		])
		.await?;

	let extremities: Vec<&EventId> = rows
		.iter()
		.filter_map(|row| imported(row.get(0), skipped))
		.collect();

	services
		.state
		.set_forward_extremities(room_id, extremities.iter().copied(), state_lock)
		.await;

	Ok(rows.len().saturating_sub(extremities.len()))
}
