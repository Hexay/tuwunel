//! Synapse's state groups, turned into the state before each event.
//!
//! A group is its parent group's state plus a delta, and Synapse records the
//! state after each event. A room's groups stay in memory while it's imported:
//! an entry per group and 16 bytes per `state_groups_state` row.

#[cfg(test)]
mod tests;

use std::{
	collections::{HashMap, hash_map::Entry},
	pin::pin,
};

use futures::TryStreamExt;
use ruma::{EventId, RoomId, events::StateEventType};
use tuwunel_core::{Err, Result};
use tuwunel_matrix::{Event as _, PduEvent};
use tuwunel_service::{
	Services,
	rooms::{
		short::{ShortEventId, ShortStateKey},
		state_compressor::{CompressedState, compress_state_event},
	},
};

use super::super::source::Source;

type State = HashMap<ShortStateKey, ShortEventId>;

/// Fully built states kept for reuse; consecutive events mostly share a group.
const CACHE_LIMIT: usize = 64;

pub(super) struct StateGroups {
	groups: HashMap<i64, Group>,
	cache: HashMap<i64, State>,

	/// State entries left out because their event ID is invalid.
	pub(super) dropped: usize,
}

#[derive(Default)]
struct Group {
	parent: Option<i64>,
	delta: Vec<(ShortStateKey, ShortEventId)>,
}

impl StateGroups {
	/// Events that couldn't be imported stay in the groups: they are still the
	/// room's state, as other servers see it.
	pub(super) async fn load(
		services: &Services,
		source: &Source,
		room_id: &RoomId,
	) -> Result<Self> {
		let mut groups = Self {
			groups: load_edges(source, room_id).await?,
			cache: HashMap::new(),
			dropped: 0,
		};

		groups
			.load_deltas(services, source, room_id)
			.await?;

		Ok(groups)
	}

	async fn load_deltas(
		&mut self,
		services: &Services,
		source: &Source,
		room_id: &RoomId,
	) -> Result {
		// Through state_groups: Synapse indexes state_groups_state by group, not by room.
		let mut rows = pin!(
			source
				.stream(
					"SELECT s.state_group, s.type, s.state_key, s.event_id FROM state_groups g \
					 JOIN state_groups_state s ON s.state_group = g.id WHERE g.room_id = $1",
					&[&room_id.as_str()],
				)
				.await?
		);

		let mut keys: HashMap<(String, String), ShortStateKey> = HashMap::new();
		while let Some(row) = rows.try_next().await? {
			let Ok(event_id) = <&EventId>::try_from(row.get::<_, &str>(3)) else {
				self.dropped = self.dropped.saturating_add(1);
				continue;
			};

			let key = match keys.entry((row.get(1), row.get(2))) {
				| Entry::Occupied(entry) => *entry.get(),
				| Entry::Vacant(entry) => {
					let (event_type, state_key) = entry.key();
					let short = services
						.short
						.get_or_create_shortstatekey(
							&StateEventType::from(event_type.as_str()),
							state_key,
						)
						.await;

					*entry.insert(short)
				},
			};

			let event = services
				.short
				.get_or_create_shorteventid(event_id)
				.await;

			self.groups
				.entry(row.get(0))
				.or_default()
				.delta
				.push((key, event));
		}

		Ok(())
	}

	/// The state before `pdu`, from `group`, the state after it. None when
	/// Synapse's groups don't determine it, which would need state resolution.
	///
	/// Synapse stores a state event's group as the state before it plus the
	/// event, so that parent group is the answer. Failing that, as across a
	/// backfill gap, the event's key is set back to what its predecessors'
	/// groups agree on.
	pub(super) async fn before(
		&mut self,
		services: &Services,
		source: &Source,
		pdu: &PduEvent,
		group: Option<i64>,
	) -> Result<Option<CompressedState>> {
		let Some(after) = group else {
			return Ok(None);
		};

		let Some(state_key) = pdu.state_key() else {
			return self.state(after).map(compress).map(Some);
		};

		let kind = StateEventType::from(pdu.kind().to_string());
		let key = services
			.short
			.get_or_create_shortstatekey(&kind, state_key)
			.await;

		let event = services
			.short
			.get_or_create_shorteventid(pdu.event_id())
			.await;

		if let Some(parent) = self.parent_before(after, key, event) {
			return self.state(parent).map(compress).map(Some);
		}

		let prevs = prev_groups(source, pdu).await?;
		self.predecessors_before(after, key, &prevs)
	}

	/// The parent of group `after` when its delta is just `key` set to `event`.
	fn parent_before(&self, after: i64, key: ShortStateKey, event: ShortEventId) -> Option<i64> {
		self.groups
			.get(&after)
			.filter(|group| group.delta == [(key, event)])
			.and_then(|group| group.parent)
	}

	/// Group `after` with `key` set back to what every predecessor's group has
	/// for it; nothing, for the create event. None when a predecessor has no
	/// group or they disagree.
	fn predecessors_before(
		&mut self,
		after: i64,
		key: ShortStateKey,
		prevs: &[Option<i64>],
	) -> Result<Option<CompressedState>> {
		let mut prior: Option<Option<ShortEventId>> = None;
		for &prev in prevs {
			let Some(group) = prev else {
				return Ok(None);
			};

			let value = self.state(group)?.get(&key).copied();
			if prior.is_some_and(|prior| prior != value) {
				return Ok(None);
			}

			prior = Some(value);
		}

		let mut state = self.state(after)?.clone();
		match prior.flatten() {
			| Some(value) => state.insert(key, value),
			| None => state.remove(&key),
		};

		Ok(Some(compress(&state)))
	}

	fn state(&mut self, group: i64) -> Result<&State> {
		if !self.cache.contains_key(&group) {
			let state = self.build(group)?;
			if self.cache.len() >= CACHE_LIMIT {
				self.cache.clear();
			}

			self.cache.insert(group, state);
		}

		Ok(&self.cache[&group])
	}

	/// Walks up to the nearest cached ancestor or the root, then applies each
	/// delta on the way back down.
	fn build(&self, group: i64) -> Result<State> {
		let mut chain = Vec::new();
		let mut state = State::new();
		let mut next = Some(group);

		while let Some(id) = next {
			if let Some(cached) = self.cache.get(&id) {
				state.clone_from(cached);
				break;
			}

			let Some(found) = self.groups.get(&id) else {
				return Err!("Synapse state group {id} is referenced but missing");
			};

			chain.push(found);
			next = found.parent;
		}

		for found in chain.iter().rev() {
			state.extend(found.delta.iter().copied());
		}

		Ok(state)
	}
}

async fn load_edges(source: &Source, room_id: &RoomId) -> Result<HashMap<i64, Group>> {
	let mut rows = pin!(
		source
			.stream(
				"SELECT g.id, e.prev_state_group FROM state_groups g LEFT JOIN \
				 state_group_edges e ON e.state_group = g.id WHERE g.room_id = $1",
				&[&room_id.as_str()],
			)
			.await?
	);

	let mut groups: HashMap<i64, Group> = HashMap::new();
	while let Some(row) = rows.try_next().await? {
		groups.entry(row.get(0)).or_default().parent = row.get(1);
	}

	Ok(groups)
}

/// The group of each of `pdu`'s predecessors, where Synapse recorded one.
async fn prev_groups(source: &Source, pdu: &PduEvent) -> Result<Vec<Option<i64>>> {
	let prevs: Vec<&str> = pdu.prev_events().map(EventId::as_str).collect();
	let groups: HashMap<String, i64> = source
		.rows(
			"SELECT event_id, state_group FROM event_to_state_groups WHERE event_id = ANY($1)",
			&[&prevs],
		)
		.await?
		.iter()
		.map(|row| (row.get(0), row.get(1)))
		.collect();

	Ok(prevs
		.iter()
		.map(|prev| groups.get(*prev).copied())
		.collect())
}

fn compress(state: &State) -> CompressedState {
	state
		.iter()
		.map(|(&key, &event)| compress_state_event(key, event))
		.collect()
}
