//! Password hashing and cryptographic digest utilities.
//!
//! Password helpers use Argon2id with a fresh random salt for each new hash.
//! Bcrypt is verify-only, for hashes imported from Synapse. The SHA-256
//! submodule provides byte-oriented digest helpers.

mod argon;
mod bcrypt;

pub mod sha256;

pub use self::{
	argon::{
		Cost, PhcString, is_argon2_hash, is_keyed_argon2_hash, mark_keyed_argon2_hash, password,
		verify_password, verify_password_with_secret,
	},
	bcrypt::{is_bcrypt_hash, verify_bcrypt_password},
};
