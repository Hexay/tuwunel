//! Synapse data tuwunel has no place for, counted in the report so nothing is
//! dropped silently.

use tuwunel_core::Result;

use super::{Report, mas::Mas, source::Source};

/// Table, row filter, and what its rows are. Tables older Synapse releases
/// don't have yet are skipped.
const LEFTOVERS: [(&str, &str, &str); 7] = [
	("event_reports", "", "event reports: tuwunel keeps none"),
	("room_reports", "", "room reports: tuwunel keeps none"),
	("user_reports", "", "user reports: tuwunel keeps none"),
	(
		"delayed_events",
		"WHERE NOT is_processed",
		"delayed events: tuwunel has none, so they won't be sent",
	),
	(
		"device_federation_outbox",
		"",
		"to-device messages Synapse hadn't delivered to other servers yet",
	),
	("ratelimit_override", "", "per-user rate limit overrides"),
	(
		"users_pending_deactivation",
		"",
		"deactivations Synapse hadn't finished: those users may still be in rooms",
	),
];

pub(super) async fn report(source: &Source, mas: Option<&Mas>, report: &mut Report) -> Result {
	if let Some(mas) = mas {
		mas.leftovers(report).await?;
	}

	for (table, filter, what) in LEFTOVERS {
		if !source.has_table(table).await? {
			continue;
		}

		let count = source.count_where(table, filter).await?;
		if count > 0 {
			report.skip(format!("{count} {what}"));
		}
	}

	Ok(())
}
