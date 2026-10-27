//! Users, their password hashes, admin rights and profiles.

use std::collections::HashMap;

use ruma::{OwnedMxcUri, OwnedUserId, UserId, profile::ProfileFieldName};
use serde_json::Value;
use tokio_postgres::Row;
use tuwunel_core::{Result, err};
use tuwunel_service::{Services, profile::Propagation, users::PASSWORD_SENTINEL};

use super::{
	Report,
	mas::{self, Mas, users::MasUser},
	source::{Source, json, user_id},
};

/// A user's auth state, from Synapse or, with MAS, from MAS.
struct Auth {
	password_hash: Option<String>,
	admin: bool,
	deactivated: bool,
	guest: bool,
	locked: bool,
}

pub(super) async fn import(
	services: &Services,
	source: &Source,
	mas: Option<&Mas>,
	report: &mut Report,
) -> Result {
	let mas_users = match mas {
		| Some(mas) => Some(mas::users::users(mas, services, report).await?),
		| None => None,
	};

	let suspended = source
		.column_or("users", "suspended", "FALSE")
		.await?;
	let rows = source
		.rows(
			&format!(
				"SELECT name, password_hash, admin <> 0, deactivated <> 0, is_guest <> 0, \
				 locked, {suspended}, shadow_banned IS TRUE, approved IS FALSE FROM users ORDER \
				 BY name"
			),
			&[],
		)
		.await?;

	for row in rows {
		let Some(user_id) = report.keep("users", user_id(&row, 0)) else {
			continue;
		};

		let auth = auth(&row, &user_id, mas_users.as_ref());
		import_user(services, &row, &user_id, auth, report).await?;
	}

	import_profiles(services, source, report).await
}

/// With MAS, Synapse's copy went stale; users MAS doesn't know (appservice
/// users) never had a password.
fn auth(row: &Row, user_id: &UserId, mas_users: Option<&HashMap<OwnedUserId, MasUser>>) -> Auth {
	let synapse = Auth {
		password_hash: row.get(1),
		admin: row.get(2),
		deactivated: row.get(3),
		guest: row.get(4),
		locked: row.get(5),
	};

	match mas_users.map(|users| users.get(user_id)) {
		| None => synapse,
		| Some(None) => Auth { password_hash: None, ..synapse },
		| Some(Some(user)) => Auth {
			password_hash: user.password_hash.clone(),
			admin: user.admin,
			deactivated: user.deactivated,
			guest: user.guest,
			locked: user.locked,
		},
	}
}

/// Creates the user unless an interrupted run already did, then applies the
/// rest every time, so a resumed phase leaves no user half imported.
async fn import_user(
	services: &Services,
	row: &Row,
	user_id: &UserId,
	auth: Auth,
	report: &mut Report,
) -> Result {
	if auth.guest {
		report.skip(format!("{user_id}: guest accounts aren't imported"));
		return Ok(());
	}

	let exists = services.users.exists(user_id).await;
	if auth.deactivated {
		if !exists {
			services.users.create(user_id, None, None).await?;
		}

		Report::count(&mut report.deactivated);
		return Ok(());
	}

	// A user without a password (SSO, appservice) is still active; an empty
	// value would mark the account deactivated.
	if !exists {
		services
			.users
			.create(user_id, Some(PASSWORD_SENTINEL), None)
			.await?;
	}

	// Synapse stores an empty hash for users an appservice registered.
	if let Some(hash) = auth
		.password_hash
		.as_deref()
		.filter(|hash| !hash.is_empty())
		&& services
			.users
			.set_password_hash(user_id, hash)
			.await
			.is_err()
	{
		report.skip(format!("{user_id}: unrecognized password hash; reset this password"));
	}

	if auth.admin {
		services.admin.make_user_admin(user_id).await?;
		Report::count(&mut report.admins);
	}

	import_moderation(services, row, user_id, auth.locked, report);
	Report::count(&mut report.users);
	Ok(())
}

/// Synapse doesn't record who locked or suspended a user, so the server user
/// stands in.
fn import_moderation(
	services: &Services,
	row: &Row,
	user_id: &UserId,
	locked: bool,
	report: &mut Report,
) {
	let (suspended, shadow_banned, unapproved): (bool, bool, bool) =
		(row.get(6), row.get(7), row.get(8));

	let by = &services.globals.server_user;
	if locked {
		services.users.set_locked(user_id, by);
		Report::count(&mut report.locked);
	}

	if suspended {
		services.users.set_suspended(user_id, by);
		Report::count(&mut report.suspended);
	}

	if shadow_banned {
		report
			.skip(format!("{user_id}: tuwunel has no shadow ban; the user is now unrestricted"));
	}

	if unapproved {
		report.skip(format!(
			"{user_id}: tuwunel has no registration approval; the user can now log in"
		));
	}
}

async fn import_profiles(services: &Services, source: &Source, report: &mut Report) -> Result {
	let server_name = services.globals.server_name();

	// `user_id` here is the localpart.
	let fields = source
		.column_or("profiles", "fields", "NULL")
		.await?;
	let rows = source
		.rows(
			&format!("SELECT user_id, displayname, avatar_url, {fields}::text FROM profiles"),
			&[],
		)
		.await?;

	for row in rows {
		let localpart: &str = row.get(0);
		let user_id = UserId::parse_with_server_name(localpart, server_name)
			.map_err(|e| err!("profile of {localpart:?}: {e}"));
		let Some(user_id) = report.keep("profiles", user_id) else {
			continue;
		};

		if !services.users.is_active(&user_id).await {
			continue;
		}

		let displayname: Option<String> = row.get(1);
		if displayname.is_some() {
			services
				.profile
				.set_displayname(&user_id, displayname.as_deref(), None)
				.await?;
		}

		let avatar_url: Option<String> = row.get(2);
		if let Some(avatar_url) = avatar_url {
			let avatar_url = OwnedMxcUri::from(avatar_url);
			services
				.profile
				.set_avatar_url(&user_id, Some(&avatar_url), None)
				.await?;
		}

		let fields = row.get::<_, Option<&str>>(3).and_then(|fields| {
			report.keep(format_args!("{user_id} profile fields"), json(fields))
		});
		if let Some(fields) = fields {
			import_profile_fields(services, &user_id, &fields, report).await;
		}

		Report::count(&mut report.profiles);
	}

	Ok(())
}

/// Custom profile fields (MSC4133), each set on its own so tuwunel's checks
/// reject only the field that fails them.
async fn import_profile_fields(
	services: &Services,
	user_id: &UserId,
	fields: &Value,
	report: &mut Report,
) {
	for (name, value) in fields.as_object().into_iter().flatten() {
		let field = [(ProfileFieldName::from(name.as_str()), Some(value.clone()))];
		if let Err(e) = services
			.profile
			.set_profile_keys(user_id, &field, Some(Propagation::None))
			.await
		{
			report.skip(format!("{user_id}: profile field {name:?}: {e}"));
		}
	}
}
