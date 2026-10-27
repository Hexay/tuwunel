use ruma::{
	push::{Action, RuleKind, Ruleset},
	user_id,
};
use serde_json::json;

use super::{apply_rule, split_rule_id};

fn ruleset() -> Ruleset { Ruleset::server_default(user_id!("@alice:example.org")) }

#[test]
fn split_rule_id_takes_the_kind_and_the_rest() {
	let (kind, rule_id) = split_rule_id("global/content/cats/dogs").expect("a global rule");

	assert_eq!(kind, RuleKind::Content);
	assert_eq!(rule_id, "cats/dogs");
}

#[test]
fn split_rule_id_refuses_other_scopes_and_short_ids() {
	split_rule_id("device/abc/override/x").unwrap_err();
	split_rule_id("global/override").unwrap_err();
	split_rule_id("").unwrap_err();
}

#[test]
fn apply_rule_reads_a_content_rule_pattern_from_its_condition() {
	let mut rules = ruleset();
	let conditions = json!([{ "kind": "event_match", "key": "content.body", "pattern": "cats" }]);

	apply_rule(&mut rules, "global/content/cats", &conditions, json!(["notify"]))
		.expect("a valid content rule");

	let rule = rules
		.get(RuleKind::Content, "cats")
		.expect("the rule was added");

	assert!(matches!(rule.actions(), [Action::Notify]));
}

#[test]
fn apply_rule_refuses_a_content_rule_without_a_pattern() {
	let applied = apply_rule(&mut ruleset(), "global/content/cats", &json!([]), json!([]));

	assert!(applied.is_err());
}

#[test]
fn apply_rule_gives_a_default_rule_new_actions() {
	let mut rules = ruleset();
	let actions = json!(["notify"]);

	apply_rule(&mut rules, "global/override/.m.rule.suppress_notices", &json!([]), actions)
		.expect("a default rule");

	let rule = rules
		.get(RuleKind::Override, ".m.rule.suppress_notices")
		.expect("a default rule");

	assert!(matches!(rule.actions(), [Action::Notify]));
}

#[test]
fn apply_rule_refuses_an_unknown_kind() {
	let applied = apply_rule(&mut ruleset(), "global/postcontent/x", &json!([]), json!([]));

	assert!(applied.is_err());
}
