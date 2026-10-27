//! Keys: 1 is m.room.create, 2 and 3 are members. Events are numbered after
//! their key: 10 the create event, 20 and 21 two memberships of key 2.

use std::collections::HashMap;

use super::{Group, State, StateGroups, compress};

type Delta = Vec<(u64, u64)>;

fn state_groups<const N: usize>(groups: [(i64, Option<i64>, Delta); N]) -> StateGroups {
	StateGroups {
		groups: groups
			.into_iter()
			.map(|(id, parent, delta)| (id, Group { parent, delta }))
			.collect(),
		cache: HashMap::new(),
		dropped: 0,
	}
}

fn state(entries: &[(u64, u64)]) -> State { entries.iter().copied().collect() }

#[test]
fn state_applies_deltas_from_the_root() {
	let mut groups = state_groups([
		(1, None, vec![(1, 10)]),
		(2, Some(1), vec![(2, 20)]),
		(3, Some(2), vec![(2, 21)]),
	]);

	let built = groups.state(3).expect("every group is present");
	assert_eq!(built, &state(&[(1, 10), (2, 21)]));
}

#[test]
fn state_of_a_missing_ancestor_is_an_error() {
	let mut groups = state_groups([(2, Some(1), vec![(2, 20)])]);

	groups.state(2).unwrap_err();
}

#[test]
fn build_starts_from_a_cached_ancestor() {
	let mut groups = state_groups([(2, Some(1), vec![]), (3, Some(2), vec![(2, 21)])]);
	groups.cache.insert(2, state(&[(3, 30)]));

	let built = groups.build(3).expect("the ancestor is cached");
	assert_eq!(built, state(&[(3, 30), (2, 21)]));
}

#[test]
fn parent_before_takes_a_delta_of_just_the_event() {
	let groups = state_groups([(1, None, vec![(1, 10)]), (2, Some(1), vec![(2, 20)])]);

	assert_eq!(groups.parent_before(2, 2, 20), Some(1));
	assert_eq!(groups.parent_before(2, 2, 21), None);
	assert_eq!(groups.parent_before(1, 1, 10), None);
}

#[test]
fn parent_before_refuses_a_wider_delta() {
	let groups = state_groups([(1, None, vec![]), (2, Some(1), vec![(1, 10), (2, 20)])]);

	assert_eq!(groups.parent_before(2, 2, 20), None);
}

#[test]
fn predecessors_before_restores_what_they_agree_on() {
	let mut groups = state_groups([
		(1, None, vec![(1, 10), (2, 20)]),
		(2, Some(1), vec![(2, 21)]),
		(3, Some(1), vec![(3, 30)]),
	]);

	let before = groups
		.predecessors_before(2, 2, &[Some(1), Some(3)])
		.expect("every group is present");

	assert_eq!(before, Some(compress(&state(&[(1, 10), (2, 20)]))));
}

#[test]
fn predecessors_before_the_create_event_is_empty() {
	let mut groups = state_groups([(1, None, vec![(1, 10)])]);

	let before = groups
		.predecessors_before(1, 1, &[])
		.expect("every group is present");

	assert_eq!(before, Some(compress(&state(&[]))));
}

#[test]
fn predecessors_before_gives_up_on_disagreement_or_a_gap() {
	let mut groups = state_groups([
		(1, None, vec![(2, 20)]),
		(2, None, vec![(2, 21)]),
		(3, None, vec![(2, 22)]),
	]);

	let disagree = groups.predecessors_before(3, 2, &[Some(1), Some(2)]);
	let gap = groups.predecessors_before(3, 2, &[Some(1), None]);

	assert_eq!(disagree.expect("every group is present"), None);
	assert_eq!(gap.expect("every group is present"), None);
}
