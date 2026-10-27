//! Events built field by field, so most get past parsing and hash to their own
//! ID: wrong types, odd numbers and deep nesting land in every field.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use serde_json::{Map, Number, Value, json};
use tuwunel_synapse_import::fuzz;

const VERSIONS: &[&str] = &[
	"1",
	"2",
	"3",
	"4",
	"5",
	"6",
	"7",
	"8",
	"9",
	"10",
	"11",
	"12",
	"org.matrix.hydra.11",
];

const TYPES: &[&str] = &[
	"m.room.create",
	"m.room.member",
	"m.room.power_levels",
	"m.room.join_rules",
	"m.room.history_visibility",
	"m.room.redaction",
	"m.room.message",
	"m.room.encrypted",
	"m.room.third_party_invite",
	"m.room.server_acl",
	"m.room.name",
];

const KEYS: &[&str] = &[
	"membership",
	"join_authorised_via_users_server",
	"third_party_invite",
	"signed",
	"users",
	"users_default",
	"events",
	"ban",
	"kick",
	"redact",
	"invite",
	"notifications",
	"creator",
	"additional_creators",
	"room_version",
	"predecessor",
	"type",
	"join_rule",
	"allow",
	"history_visibility",
	"redacts",
	"body",
	"msgtype",
	"m.relates_to",
	"rel_type",
	"event_id",
	"m.federate",
];

const IDS: &[&str] = &[
	"@alice:example.org",
	"@bob:remote.test",
	"!room:example.org",
	"$event:example.org",
	"$Rqnc-F-dvnEYJTyHq_iKxU2bZ1CI92-kuZq3a5lr5Zg",
	"example.org",
	"",
];

#[derive(Arbitrary, Debug)]
enum Text {
	Known(u8),
	Any(String),
}

#[derive(Arbitrary, Debug)]
enum Json {
	Null,
	Bool(bool),
	Int(i64),
	Big(u64),
	Float(f64),
	Text(Text),
	Array(Vec<Json>),
	Object(Vec<(Text, Json)>),
}

#[derive(Arbitrary, Debug)]
struct Event {
	version: u8,
	kind: Text,
	state_key: Option<Text>,
	sender: Text,
	room_id: Text,
	content: Vec<(Text, Json)>,
	prev_events: Vec<Text>,
	auth_events: Vec<Text>,
	depth: Json,
	origin_server_ts: Json,
	redacts: Option<Text>,
	extra: Vec<(Text, Json)>,

	/// `[[id, hashes]]` reference pairs, as room versions 1 and 2 have them.
	v1_references: bool,

	/// Top-level fields to leave out, by bit.
	omit: u16,
}

impl Text {
	fn pick<'a>(&'a self, known: &[&'a str]) -> &'a str {
		match self {
			| Self::Known(i) => known[usize::from(*i) % known.len()],
			| Self::Any(text) => text,
		}
	}
}

impl Json {
	fn value(&self) -> Value {
		match self {
			| Self::Null => Value::Null,
			| Self::Bool(b) => Value::Bool(*b),
			| Self::Int(i) => (*i).into(),
			| Self::Big(u) => (*u).into(),
			| Self::Float(f) => Number::from_f64(*f).map_or(Value::Null, Value::Number),
			| Self::Text(text) => text.pick(IDS).into(),
			| Self::Array(items) => items.iter().map(Self::value).collect(),
			| Self::Object(fields) => object(fields),
		}
	}
}

fn object(fields: &[(Text, Json)]) -> Value {
	fields
		.iter()
		.map(|(key, value)| (key.pick(KEYS).to_owned(), value.value()))
		.collect::<Map<_, _>>()
		.into()
}

fn references(ids: &[Text], v1: bool) -> Value {
	ids.iter()
		.map(|id| match v1 {
			| true => json!([id.pick(IDS), { "sha256": "aGFzaA" }]),
			| false => id.pick(IDS).into(),
		})
		.collect()
}

impl Event {
	fn json(&self) -> Value {
		let mut fields = vec![
			("type", self.kind.pick(TYPES).into()),
			("sender", self.sender.pick(IDS).into()),
			("room_id", self.room_id.pick(IDS).into()),
			("content", object(&self.content)),
			("prev_events", references(&self.prev_events, self.v1_references)),
			("auth_events", references(&self.auth_events, self.v1_references)),
			("depth", self.depth.value()),
			("origin_server_ts", self.origin_server_ts.value()),
			("origin", "example.org".into()),
			("hashes", json!({ "sha256": "aGFzaA" })),
			("signatures", json!({ "example.org": { "ed25519:a": "c2ln" } })),
			("unsigned", json!({ "age_ts": 1 })),
		];

		if let Some(state_key) = &self.state_key {
			fields.push(("state_key", state_key.pick(IDS).into()));
		}

		if let Some(redacts) = &self.redacts {
			fields.push(("redacts", redacts.pick(IDS).into()));
		}

		let mut json: Map<String, Value> = fields
			.into_iter()
			.enumerate()
			.filter(|(i, _)| self.omit & (1 << i) == 0)
			.map(|(_, (key, value))| (key.to_owned(), value))
			.collect();

		if let Value::Object(extra) = object(&self.extra) {
			json.extend(extra);
		}

		json.into()
	}
}

fuzz_target!(|event: Event| {
	let version = VERSIONS[usize::from(event.version) % VERSIONS.len()];
	let room_id = event.room_id.pick(IDS);
	let json = event.json().to_string();

	fuzz::event(version, room_id, "$unknown", &json);
	fuzz::redaction(format!("{version}\n{json}").as_bytes());
});
