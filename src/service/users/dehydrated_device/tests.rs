use ruma::{
	api::client::dehydrated_device::DehydratedDeviceData, device_id, serde::Raw, user_id,
};
use tuwunel_core::{Result, config::Figment, utils::random_string};

use crate::{
	test_utils::{create_devices, fixture},
	users::device::TOKEN_LENGTH,
};

fn device_data() -> Raw<DehydratedDeviceData> {
	Raw::from_json_string(r#"{"algorithm":"m.dehydration.v1.olm","device_pickle":"x"}"#.into())
		.expect("valid dehydrated device JSON")
}

#[tokio::test]
async fn tokenless_device_becomes_dehydrated() -> Result {
	let Some(fixture) = fixture(Figment::new()).await? else {
		return Ok(());
	};

	let users = &fixture.services.users;
	let user_id = user_id!("@dehydrated:localhost");
	let device_id = device_id!("DEHYDRATED");

	create_devices(users, user_id, &[device_id]).await?;
	users
		.set_dehydrated_device_data(user_id, device_id, device_data())
		.await?;

	assert_eq!(
		users
			.get_dehydrated_device_id(user_id)
			.await?
			.as_str(),
		device_id.as_str()
	);

	// Repeating it for the same device is harmless.
	users
		.set_dehydrated_device_data(user_id, device_id, device_data())
		.await?;

	Ok(())
}

#[tokio::test]
async fn missing_or_live_device_is_refused() -> Result {
	let Some(fixture) = fixture(Figment::new()).await? else {
		return Ok(());
	};

	let users = &fixture.services.users;
	let user_id = user_id!("@live:localhost");
	let live = device_id!("LIVE");

	users.create(user_id, None, None).await?;
	users
		.set_dehydrated_device_data(user_id, live, device_data())
		.await
		.expect_err("a missing device is refused");

	let access_token = random_string(TOKEN_LENGTH);
	users
		.create_device(user_id, Some(live), (Some(access_token.as_str()), None), None, None, None)
		.await?;

	users
		.set_dehydrated_device_data(user_id, live, device_data())
		.await
		.expect_err("a device holding an access token is refused");

	users
		.get_dehydrated_device_id(user_id)
		.await
		.unwrap_err();

	Ok(())
}

#[tokio::test]
async fn second_dehydrated_device_is_refused() -> Result {
	let Some(fixture) = fixture(Figment::new()).await? else {
		return Ok(());
	};

	let users = &fixture.services.users;
	let user_id = user_id!("@second:localhost");
	let (first, second) = (device_id!("FIRST"), device_id!("SECOND"));

	create_devices(users, user_id, &[first, second]).await?;
	users
		.set_dehydrated_device_data(user_id, first, device_data())
		.await?;

	users
		.set_dehydrated_device_data(user_id, second, device_data())
		.await
		.expect_err("the first dehydrated device would leak");

	assert_eq!(
		users
			.get_dehydrated_device_id(user_id)
			.await?
			.as_str(),
		first.as_str()
	);

	Ok(())
}
