//! Read receipts, public and private. After rooms, since a receipt points at
//! an event.

use std::{collections::BTreeMap, pin::pin};

use futures::TryStreamExt;
use ruma::{
	EventId, MilliSecondsSinceUnixEpoch, OwnedEventId, OwnedRoomId, UInt,
	events::receipt::{Receipt, ReceiptEvent, ReceiptEventContent, ReceiptThread, ReceiptType},
};
use tokio_postgres::Row;
use tuwunel_core::{Err, Result, err};
use tuwunel_matrix::{PduCount, PduId};
use tuwunel_service::{Services, rooms::read_receipt::PrivateRead};

use super::{
	Report,
	source::{Source, json, user_id},
};

pub(super) async fn import(services: &Services, source: &Source, report: &mut Report) -> Result {
	let mut rows = pin!(
		source
			.stream(
				"SELECT room_id, receipt_type, user_id, event_id, data, thread_id FROM \
				 receipts_linearized ORDER BY stream_id",
				&[],
			)
			.await?
	);

	while let Some(row) = rows.try_next().await? {
		match import_receipt(services, &row).await {
			| Ok(()) => Report::count(&mut report.receipts),
			| Err(e) => report.skip(format!(
				"{} receipt of {} in {}: {e}",
				row.get::<_, &str>(1),
				row.get::<_, &str>(2),
				row.get::<_, &str>(0)
			)),
		}
	}

	Ok(())
}

async fn import_receipt(services: &Services, row: &Row) -> Result {
	let room_id = OwnedRoomId::try_from(row.get::<_, &str>(0)).map_err(|e| err!("{e}"))?;
	let user_id = user_id(row, 2)?;
	let event_id = OwnedEventId::try_from(row.get::<_, &str>(3)).map_err(|e| err!("{e}"))?;
	let thread = match row.get::<_, Option<&str>>(5) {
		| None => ReceiptThread::Unthreaded,
		| Some("main") => ReceiptThread::Main,
		| Some(root) => ReceiptThread::Thread(root.try_into().map_err(|e| err!("{e}"))?),
	};

	let ts = receipt_ts(row.get(4))?;

	match row.get::<_, &str>(1) {
		| "m.read" => {
			let receipt = Receipt { ts, thread };
			let content = BTreeMap::from([(
				event_id,
				BTreeMap::from([(
					ReceiptType::Read,
					BTreeMap::from([(user_id.clone(), receipt)]),
				)]),
			)]);

			services
				.read_receipt
				.readreceipt_store(&user_id, &room_id, &ReceiptEvent {
					content: ReceiptEventContent(content),
					room_id: room_id.clone(),
				})
				.await;
		},
		| "m.read.private" => {
			let count = event_count(services, &event_id).await?;
			services
				.read_receipt
				.private_read_set(PrivateRead {
					room_id: &room_id,
					user_id: &user_id,
					count,
					ts: ts.unwrap_or_else(MilliSecondsSinceUnixEpoch::now),
					thread: &thread,
					announce: false,
				})
				.await;
		},
		| other => return Err!("receipt type {other} isn't supported"),
	}

	Ok(())
}

/// When the receipt was sent, from its `data` column.
pub(super) fn receipt_ts(data: &str) -> Result<Option<MilliSecondsSinceUnixEpoch>> {
	Ok(json(data)?
		.get("ts")
		.and_then(serde_json::Value::as_u64)
		.and_then(UInt::new)
		.map(MilliSecondsSinceUnixEpoch))
}

async fn event_count(services: &Services, event_id: &EventId) -> Result<u64> {
	let pdu_id = services
		.timeline
		.get_pdu_id(event_id)
		.await
		.map_err(|_| err!("the event wasn't imported"))?;

	match PduId::from(pdu_id).count {
		| PduCount::Normal(count) => Ok(count),
		| PduCount::Backfilled(_) => Err!("the event is backfilled"),
	}
}
