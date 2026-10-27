//! Redactions appended before the event they redact.
//!
//! Appending a redaction only redacts an event already in the timeline, and
//! the timeline is ordered by depth, so a redaction can come first: from
//! another fork, or when backfill filled in its target later. Synapse applies
//! a redaction whenever it serves the target, so these are applied once the
//! room's events are all appended.

use std::pin::pin;

use futures::TryStreamExt;
use ruma::{EventId, RoomId};
use tuwunel_core::Result;
use tuwunel_matrix::Event as _;
use tuwunel_service::{
	Services,
	rooms::{short::ShortRoomId, state::RoomMutexGuard},
};

use super::super::{Report, source::Source};

pub(super) async fn apply_late(
	services: &Services,
	source: &Source,
	room_id: &RoomId,
	shortroomid: ShortRoomId,
	state_lock: &RoomMutexGuard,
	report: &mut Report,
) -> Result {
	let mut rows = pin!(
		source
			.stream(
				"SELECT r.event_id, r.redacts FROM redactions r JOIN events e USING (event_id) \
				 WHERE e.room_id = $1",
				&[&room_id.as_str()],
			)
			.await?
	);

	while let Some(row) = rows.try_next().await? {
		let (Ok(redaction), Ok(target)) = (
			<&EventId>::try_from(row.get::<_, &str>(0)),
			<&EventId>::try_from(row.get::<_, &str>(1)),
		) else {
			continue;
		};

		if let Err(e) =
			redact_if_late(services, room_id, redaction, target, shortroomid, state_lock).await
		{
			report.skip(format!("{room_id} redaction {redaction} of {target}: {e}"));
		}
	}

	Ok(())
}

/// Redacts `target` when both are in the timeline and `redaction` comes first.
/// Idempotent, so a resumed room applies it again harmlessly.
async fn redact_if_late(
	services: &Services,
	room_id: &RoomId,
	redaction: &EventId,
	target: &EventId,
	shortroomid: ShortRoomId,
	state_lock: &RoomMutexGuard,
) -> Result {
	let (Ok(redaction_count), Ok(target_count)) = (
		services.timeline.get_pdu_count(redaction).await,
		services.timeline.get_pdu_count(target).await,
	) else {
		return Ok(());
	};

	if redaction_count > target_count {
		return Ok(());
	}

	let reason = services.timeline.get_pdu(redaction).await?;

	// As Synapse judges it: the redacter's power, or a redaction from the target's server.
	if !services
		.state_accessor
		.user_can_redact(target, reason.sender(), room_id, true)
		.await?
	{
		return Ok(());
	}

	services
		.timeline
		.redact_pdu(target, &reason, shortroomid, state_lock)
		.await
}
