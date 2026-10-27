use std::collections::HashSet;

use ruma::{EventId, RoomVersionId};

use super::{
	events::{imported, soft_failed},
	room_version,
};

#[test]
fn room_version_known() {
	assert_eq!(room_version(Some("10")).ok(), Some(RoomVersionId::V10));
}

#[test]
fn room_version_missing_is_an_error() { room_version(None).unwrap_err(); }

#[test]
fn room_version_unsupported_is_an_error() {
	room_version(Some("org.matrix.msc1767.10")).unwrap_err();
	room_version(Some("")).unwrap_err();
}

#[test]
fn soft_failed_reads_the_flag() {
	assert!(soft_failed(r#"{"soft_failed":true,"policy_server_spammy":true}"#));
	assert!(!soft_failed(r#"{"soft_failed":false}"#));
	assert!(!soft_failed("{}"));
}

#[test]
fn soft_failed_tolerates_malformed_metadata() {
	assert!(!soft_failed(r#"{"soft_failed":"yes"}"#));
	assert!(!soft_failed("not json"));
	assert!(!soft_failed("[]"));
}

#[test]
fn imported_leaves_out_skipped_and_invalid_events() {
	let skipped = HashSet::from(["$skipped".to_owned()]);

	assert_eq!(imported("$kept", &skipped).map(EventId::as_str), Some("$kept"));
	assert!(imported("$skipped", &skipped).is_none());
	assert!(imported("not an event ID", &skipped).is_none());
}
