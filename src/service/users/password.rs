use ruma::UserId;
use tuwunel_core::{
	Err, Result, implement,
	utils::hash::{
		is_argon2_hash, is_bcrypt_hash, is_keyed_argon2_hash, password as hash_password,
		verify_bcrypt_password, verify_password, verify_password_with_secret,
	},
	warn,
};

#[cfg(test)]
mod tests;

/// Verifies a plaintext password against the user's stored hash.
///
/// Argon2id hashes are checked as they are. Hashes imported from Synapse
/// (bcrypt) or MAS (Argon2id keyed with a secret, marked as such on import) are
/// checked the way they were made, then replaced with an Argon2id hash at the
/// configured cost.
#[implement(super::Service)]
pub async fn verify_and_upgrade_password(
	&self,
	user_id: &UserId,
	password: &str,
	hash: &str,
) -> Result {
	let config = &self.services.config;
	if is_bcrypt_hash(hash) {
		let pepper = config
			.imported_bcrypt_pepper
			.as_deref()
			.unwrap_or_default();

		verify_bcrypt_password(password, pepper, hash)?;
	} else if is_keyed_argon2_hash(hash) {
		let Some(secret) = config.imported_argon2_secret.as_deref() else {
			return Err!("A keyed password hash needs imported_argon2_secret, which is unset.");
		};

		verify_password_with_secret(password, hash, secret.as_bytes())?;
	} else {
		return verify_password(password, hash);
	}

	self.upgrade_imported_hash(user_id, password, hash)
		.await;

	Ok(())
}

/// Stores an existing Argon2 or bcrypt password hash verbatim and marks the
/// account as password-origin.
///
/// This carries hashes over from another server. Anything that is not a
/// complete hash in one of those formats is refused rather than stored.
#[implement(super::Service)]
pub async fn set_password_hash(&self, user_id: &UserId, hash: &str) -> Result {
	if !is_argon2_hash(hash) && !is_bcrypt_hash(hash) {
		return Err!(Request(InvalidParam("Not an Argon2 or bcrypt password hash.")));
	}

	let _password_guard = self.changing_password.lock(user_id).await;

	self.db.userid_password.insert(user_id, hash);
	self.db.userid_origin.insert(user_id, "password");

	Ok(())
}

#[implement(super::Service)]
async fn upgrade_imported_hash(&self, user_id: &UserId, password: &str, verified_hash: &str) {
	let _password_guard = self.changing_password.lock(user_id).await;

	// A password changed since the check must not be overwritten with the old one.
	if !self
		.password_hash(user_id)
		.await
		.is_ok_and(|current| current == verified_hash)
	{
		return;
	}

	match hash_password(password, self.services.config.password_hash_cost()) {
		| Ok(hash) => self.db.userid_password.insert(user_id, hash),
		| Err(e) => warn!(%user_id, "Keeping the imported hash; re-hashing failed: {e}"),
	}
}
