//! Rooms: their events and state, aliases and the public room directory.

mod events;
mod redactions;
mod room;
mod state;
#[cfg(test)]
mod tests;

use std::collections::HashSet;

use ruma::{OwnedRoomAliasId, OwnedRoomId, OwnedUserId, RoomVersionId};
use tokio_postgres::Row;
use tuwunel_core::{Result, err, info};
use tuwunel_matrix::room_version;
use tuwunel_service::Services;

use super::{
	Report, marker_present,
	source::{Source, user_id},
	stamp,
};

pub(super) async fn import(services: &Services, source: &Source, report: &mut Report) -> Result {
	let erased: HashSet<OwnedUserId> = source
		.rows("SELECT user_id FROM erased_users", &[])
		.await?
		.iter()
		.filter_map(|row| user_id(row, 0).ok())
		.collect();

	let rows = source
		.rows(
			"SELECT room_id, room_version, coalesce(is_public, false) FROM rooms ORDER BY \
			 room_id",
			&[],
		)
		.await?;

	let total = rows.len();
	for (i, row) in rows.into_iter().enumerate() {
		let room_id = OwnedRoomId::try_from(row.get::<_, &str>(0))
			.map_err(|e| err!("Synapse room ID {:?}: {e}", row.get::<_, &str>(0)));

		let Some(room_id) = report.keep("room", room_id) else {
			continue;
		};

		// Per room as well as per phase, so a rerun doesn't redo finished rooms.
		let marker = format!("synapse_import_room:{room_id}");
		if marker_present(services, &marker) {
			continue;
		}

		let version = match room_version(row.get(1)) {
			| Ok(version) => version,
			| Err(e) => {
				report.skip(format!("room {room_id}: {e}"));
				continue;
			},
		};

		info!("Importing room {room_id} ({} of {total})", i.saturating_add(1));
		room::import(services, source, &room_id, &version, &erased, report).await?;

		if row.get::<_, bool>(2) {
			services.directory.set_public(&room_id, None);
			Report::count(&mut report.public_rooms);
		}

		stamp(services, &marker);
		Report::count(&mut report.rooms);
	}

	import_aliases(services, source, report).await
}

/// Synapse leaves the column empty for some rooms it only heard of, and has
/// served experimental versions tuwunel doesn't know.
fn room_version(version: Option<&str>) -> Result<RoomVersionId> {
	let version: RoomVersionId = version
		.ok_or_else(|| err!("Synapse doesn't record its room version"))?
		.try_into()
		.map_err(|e| err!("room version: {e}"))?;

	room_version::rules(&version)?;
	Ok(version)
}

async fn import_aliases(services: &Services, source: &Source, report: &mut Report) -> Result {
	let rows = source
		.rows("SELECT room_alias, room_id, creator FROM room_aliases ORDER BY room_alias", &[])
		.await?;

	for row in rows {
		match import_alias(services, &row) {
			| Ok(()) => Report::count(&mut report.aliases),
			| Err(e) => report.skip(format!("alias {}: {e}", row.get::<_, &str>(0))),
		}
	}

	Ok(())
}

/// An alias without a recorded creator is the server's. A Synapse room
/// holding tuwunel's own admin alias is refused here.
fn import_alias(services: &Services, row: &Row) -> Result {
	let alias = OwnedRoomAliasId::try_from(row.get::<_, &str>(0)).map_err(|e| err!("{e}"))?;
	let room_id = OwnedRoomId::try_from(row.get::<_, &str>(1)).map_err(|e| err!("{e}"))?;
	let creator = match row.get::<_, Option<&str>>(2) {
		| Some(_) => user_id(row, 2)?,
		| None => services.globals.server_user.clone(),
	};

	if alias == services.admin.admin_alias {
		return Err(err!("it is tuwunel's admin room alias"));
	}

	services
		.alias
		.set_alias_by(&alias, &room_id, &creator)
}
