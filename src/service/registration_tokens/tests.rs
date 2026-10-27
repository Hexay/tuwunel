use tuwunel_core::{Result, config::Figment};

use super::TokenExpires;
use crate::test_utils::fixture;

const THREE_USES: TokenExpires = TokenExpires { max_uses: Some(3), max_age: None };

#[tokio::test]
async fn token_with_prior_uses_runs_out_at_max_uses() -> Result {
	let Some(fixture) = fixture(Figment::new()).await? else {
		return Ok(());
	};

	let tokens = &fixture.services.registration_tokens;

	let info = tokens
		.create_token_with_uses("carried", 2, THREE_USES)
		.await?;

	assert_eq!(info.uses, 2);
	tokens
		.create_token_with_uses("carried", 0, THREE_USES)
		.await
		.expect_err("an existing token is refused");

	tokens.try_consume("carried").await?;
	tokens
		.is_token_valid("carried")
		.await
		.expect_err("the third use exhausts it");

	Ok(())
}

#[tokio::test]
async fn token_stored_exhausted_is_invalid() -> Result {
	let Some(fixture) = fixture(Figment::new()).await? else {
		return Ok(());
	};

	let tokens = &fixture.services.registration_tokens;

	tokens
		.create_token_with_uses("spent", 3, THREE_USES)
		.await?;

	tokens
		.is_token_valid("spent")
		.await
		.expect_err("a token stored at max_uses is invalid");

	assert!(tokens.get_token_info("spent").await.is_err(), "and is removed by the check");

	Ok(())
}
