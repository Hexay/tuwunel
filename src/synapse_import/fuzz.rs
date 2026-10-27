//! Entry points for the fuzz targets in fuzz/: the importer's parsing of what
//! Synapse stored, run without a database. A broken invariant panics, which
//! the fuzzer reports as a crash.

use std::{collections::HashSet, iter::once, path::Path, str};

use ruma::{
	CanonicalJsonObject, CanonicalJsonValue, EventId, OwnedRoomId, OwnedUserId, RoomId,
	RoomVersionId,
	api::{appservice::Registration, client::filter::FilterDefinition},
	canonical_json::redact_in_place,
	push::Ruleset,
	room_version_rules::RoomVersionRules,
	user_id,
};
use tuwunel_matrix::{Event as _, PduEvent, event::gen_event_id, room_version};

use crate::{config::SynapseConfig, inbox::Message, push_rules, receipts, rooms, source, sso};

/// An event_json row as `room_version\nroom_id\nevent_id\njson`.
pub fn event_row(data: &[u8]) {
	if let Some([version, room_id, event_id, json]) = fields(data) {
		event(version, room_id, event_id, json);
	}
}

/// Converts the event as Synapse stored it, and again under the ID its content
/// hashes to, each with and without its sender erased.
pub fn event(version: &str, room_id: &str, event_id: &str, json: &str) {
	let (Ok(version), Ok(room_id)) =
		(RoomVersionId::try_from(version), <&RoomId>::try_from(room_id))
	else {
		return;
	};

	let Ok(rules) = room_version::rules(&version) else {
		return;
	};

	let parsed = serde_json::from_str::<CanonicalJsonObject>(json).ok();
	let sender: HashSet<OwnedUserId> = parsed
		.as_ref()
		.and_then(|json| json.get("sender"))
		.and_then(CanonicalJsonValue::as_str)
		.and_then(|sender| OwnedUserId::try_from(sender).ok())
		.into_iter()
		.collect();

	let derived = parsed.and_then(|mut json| {
		json.remove("unsigned");
		gen_event_id(&json, &version).ok()
	});

	for event_id in once(event_id).chain(derived.as_deref().map(EventId::as_str)) {
		// Under room version 12 a create event's ID names its room.
		let own_room = rules
			.authorization
			.room_create_event_id_as_room_id
			.then(|| event_id.strip_prefix('$'))
			.flatten()
			.and_then(|hash| OwnedRoomId::try_from(format!("!{hash}")).ok());

		for room_id in once(room_id).chain(own_room.as_deref()) {
			for erased in [&HashSet::new(), &sender] {
				convert(room_id, event_id, json, &version, &rules, erased);
			}
		}
	}
}

fn convert(
	room_id: &RoomId,
	event_id: &str,
	json: &str,
	version: &RoomVersionId,
	rules: &RoomVersionRules,
	erased: &HashSet<OwnedUserId>,
) {
	let Ok((pdu, stored)) = rooms::convert(room_id, event_id, json, version, rules, erased)
	else {
		return;
	};

	let (again, stored_again) = rooms::convert(room_id, event_id, json, version, rules, erased)
		.expect("conversion is deterministic");

	assert_eq!(stored, stored_again, "conversion is deterministic");
	assert_eq!(
		serde_json::to_value(&pdu).ok(),
		serde_json::to_value(&again).ok(),
		"conversion is deterministic"
	);
	assert_eq!(pdu.event_id().as_str(), event_id, "the PDU keeps its ID");

	// tuwunel reads the outlier back from these bytes before appending it.
	let bytes = serde_json::to_vec(&stored).expect("the stored JSON serializes");
	let read: CanonicalJsonObject =
		serde_json::from_slice(&bytes).expect("the stored JSON reads back");
	assert_eq!(read, stored, "the stored JSON reads back unchanged");
	serde_json::from_slice::<PduEvent>(&bytes).expect("the stored JSON reads back as a PDU");

	// tuwunel sets event_id, and room_id on a version 12 create event, unhashed;
	// an event_id already there in versions 3 to 10 was hashed, and is lost.
	let original: CanonicalJsonObject = serde_json::from_str(json).expect("it converted");
	let mut hashed = stored;
	for set in ["event_id", "room_id"] {
		match original.get(set) {
			| Some(value) => hashed.insert(set.into(), value.clone()),
			| None => hashed.remove(set),
		};
	}

	assert_eq!(
		gen_event_id(&hashed, version)
			.ok()
			.as_deref()
			.map(EventId::as_str),
		Some(event_id),
		"the stored event still hashes to its ID"
	);
}

/// `room_version\njson`: redacting is idempotent and keeps the event's ID,
/// which is what lets Synapse censor an event in place.
pub fn redaction(data: &[u8]) {
	let Some([version, json]) = fields(data) else {
		return;
	};

	let (Ok(version), Ok(json)) = (
		RoomVersionId::try_from(version),
		serde_json::from_str::<CanonicalJsonObject>(json),
	) else {
		return;
	};

	let Ok(rules) = room_version::rules(&version) else {
		return;
	};

	let mut once = json.clone();
	if redact_in_place(&mut once, &rules.redaction, None).is_err() {
		return;
	}

	let mut twice = once.clone();
	redact_in_place(&mut twice, &rules.redaction, None).expect("a redacted event redacts");
	assert_eq!(once, twice, "redaction is idempotent");

	if let Ok(event_id) = gen_event_id(&json, &version) {
		assert_eq!(
			gen_event_id(&once, &version).ok(),
			Some(event_id),
			"redaction keeps the event ID"
		);
	}
}

/// A push_rules row as `rule_id\nconditions\nactions`. An imported ruleset
/// must read back, since it's stored as the user's account data.
pub fn push_rule(data: &[u8]) {
	let Some([namespaced, conditions, actions]) = fields(data) else {
		return;
	};

	_ = push_rules::split_rule_id(namespaced);
	let (Ok(conditions), Ok(actions)) = (source::json(conditions), source::json(actions)) else {
		return;
	};

	let mut ruleset = Ruleset::server_default(user_id!("@fuzz:example.org"));
	if push_rules::apply_rule(&mut ruleset, namespaced, &conditions, actions).is_ok() {
		let json = serde_json::to_value(&ruleset).expect("a ruleset serializes");
		serde_json::from_value::<Ruleset>(json).expect("an imported ruleset reads back");
	}
}

/// homeserver.yaml, or an appservice registration it lists.
pub fn synapse_config(data: &[u8]) {
	let Ok(contents) = str::from_utf8(data) else {
		return;
	};

	if let Ok(config) = SynapseConfig::parse(contents, Path::new("/etc/synapse/homeserver.yaml"))
	{
		_ = config.delegates_auth();
		for auth_provider in ["oidc", "oidc-github", "saml"] {
			if let Some(provider) = config.oidc_provider(auth_provider) {
				_ = sso::uses_sub_claim(provider);
			}
		}
	}

	_ = serde_yaml::from_str::<Registration>(contents);
}

/// One text, read as each of the other JSON columns the importer parses.
pub fn json_columns(data: &[u8]) {
	let Ok(text) = str::from_utf8(data) else {
		return;
	};

	_ = rooms::soft_failed(text);
	_ = receipts::receipt_ts(text);
	_ = serde_json::from_str::<Message>(text);
	_ = serde_json::from_slice::<FilterDefinition>(data);
	_ = source::raw_json::<CanonicalJsonObject>(text.to_owned());
}

/// `N` newline-separated fields, the last taking the rest.
fn fields<const N: usize>(data: &[u8]) -> Option<[&str; N]> {
	str::from_utf8(data)
		.ok()?
		.splitn(N, '\n')
		.collect::<Vec<_>>()
		.try_into()
		.ok()
}

#[cfg(test)]
mod tests {
	use std::{fs, path::Path};

	type Target = (&'static str, fn(&[u8]));

	/// Each target's committed seeds, through its entry point.
	#[test]
	fn seeds_pass() {
		let seeds = Path::new(env!("CARGO_MANIFEST_DIR")).join("fuzz/seeds");
		let targets: [Target; 5] = [
			("event_row", super::event_row),
			("redaction", super::redaction),
			("push_rule", super::push_rule),
			("synapse_config", super::synapse_config),
			("json_columns", super::json_columns),
		];

		for (target, run) in targets {
			let dir = fs::read_dir(seeds.join(target)).expect("the target has seeds");
			for seed in dir {
				let path = seed.expect("a listable seed").path();
				run(&fs::read(&path).expect("a readable seed"));
			}
		}
	}
}
