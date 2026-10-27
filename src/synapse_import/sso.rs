//! Links users to their single sign-on identities, so they keep their accounts
//! when they next log in through the same identity provider.
//!
//! tuwunel keys an identity by the provider's issuer and the `sub` claim, so
//! a Synapse or MAS provider is matched to a tuwunel `identity_provider` by
//! issuer, and only when the external ID was taken from `sub`.

use ruma::UserId;
use tuwunel_core::{Result, config::IdentityProvider};
use tuwunel_service::{Services, oauth::sessions::Adoption};
use url::Url;

use super::{
	Report,
	config::{OidcProvider, SynapseConfig},
	mas::Mas,
	source::{Source, user_id},
};

pub(super) async fn import(
	services: &Services,
	config: &SynapseConfig,
	source: &Source,
	mas: Option<&Mas>,
	report: &mut Report,
) -> Result {
	if let Some(mas) = mas {
		return import_mas(services, mas, report).await;
	}

	let rows = source
		.rows(
			"SELECT auth_provider, external_id, user_id FROM user_external_ids ORDER BY user_id",
			&[],
		)
		.await?;

	for row in rows {
		let (auth_provider, external_id): (&str, &str) = (row.get(0), row.get(1));
		let Some(user_id) = report.keep("user_external_ids", user_id(&row, 2)) else {
			continue;
		};

		if !services.users.is_active(&user_id).await {
			continue;
		}

		let Some(synapse_provider) = config.oidc_provider(auth_provider) else {
			report.skip(format!(
				"{user_id}: identity provider {auth_provider:?} isn't an OIDC provider in \
				 Synapse's config, and tuwunel supports only OIDC"
			));
			continue;
		};

		let issuer = &synapse_provider.issuer;
		let by_sub = uses_sub_claim(synapse_provider);
		link(services, &user_id, issuer, external_id, by_sub, report).await?;
	}

	Ok(())
}

async fn import_mas(services: &Services, mas: &Mas, report: &mut Report) -> Result {
	for row in mas.links(services).await? {
		let (issuer, subject, by_sub): (&str, &str, bool) = (row.get(0), row.get(1), row.get(3));
		let Some(user_id) = report.keep("upstream_oauth_links", user_id(&row, 2)) else {
			continue;
		};

		if services.users.is_active(&user_id).await {
			link(services, &user_id, issuer, subject, by_sub, report).await?;
		}
	}

	Ok(())
}

async fn link(
	services: &Services,
	user_id: &UserId,
	issuer: &str,
	subject: &str,
	by_sub: bool,
	report: &mut Report,
) -> Result {
	if !by_sub {
		report.skip(format!(
			"{user_id}: their {issuer} identity is keyed by a claim other than `sub`, which \
			 tuwunel can't match"
		));
		return Ok(());
	}

	let Some(provider) = matching_provider(services, issuer) else {
		report.skip(format!(
			"{user_id}: no identity_provider in tuwunel's config has issuer_url {issuer:?} (a \
			 trailing slash aside); add it and import again to keep these logins"
		));
		return Ok(());
	};

	let adoption = services
		.oauth
		.sessions
		.adopt_subject(provider, subject, user_id)
		.await?;

	match adoption {
		| Adoption::Adopted | Adoption::AlreadyBound => Report::count(&mut report.sso),
		| Adoption::Absent =>
			report.skip(format!("{user_id}: no local account to link their {issuer} identity to")),
		| Adoption::Collision => report.skip(format!(
			"{user_id}: their {issuer} identity is already linked to another user"
		)),
		| Adoption::Invalid => report.skip(format!(
			"{user_id}: their {issuer} identity's subject {subject:?} is unusable"
		)),
	}

	Ok(())
}

fn matching_provider<'a>(services: &'a Services, issuer: &str) -> Option<&'a IdentityProvider> {
	let issuer = Url::parse(issuer).ok()?;

	services
		.config
		.identity_provider
		.values()
		.find(|provider| {
			provider
				.issuer_url
				.as_ref()
				.is_some_and(|url| same_issuer(url, &issuer))
		})
}

/// Issuers compared as URLs, ignoring a trailing slash, which providers and
/// their configs often disagree on.
fn same_issuer(a: &Url, b: &Url) -> bool {
	a.as_str().trim_end_matches('/') == b.as_str().trim_end_matches('/')
}

/// Whether Synapse's mapping provider took the external ID from `sub`: the
/// default, unless `subject_claim` or `subject_template` say otherwise, or a
/// custom module maps users.
pub(super) fn uses_sub_claim(provider: &OidcProvider) -> bool {
	let Some(mapping) = &provider.user_mapping_provider else {
		return true;
	};

	let custom_module = mapping
		.get("module")
		.and_then(serde_yaml::Value::as_str)
		.is_some_and(|module| !module.ends_with("JinjaOidcMappingProvider"));

	let config = mapping.get("config");
	let claim = config
		.and_then(|config| config.get("subject_claim"))
		.and_then(serde_yaml::Value::as_str);

	let template = config.and_then(|config| config.get("subject_template"));

	!custom_module && template.is_none() && claim.is_none_or(|claim| claim == "sub")
}

#[cfg(test)]
mod tests {
	use url::Url;

	use super::{OidcProvider, same_issuer, uses_sub_claim};

	fn by_sub(mapping: &str) -> bool {
		let yaml = format!("issuer: https://idp.example/\n{mapping}");
		let provider: OidcProvider = serde_yaml::from_str(&yaml).expect("a valid provider");

		uses_sub_claim(&provider)
	}

	#[test]
	fn default_mapping_uses_sub() {
		assert!(by_sub(""));
		assert!(by_sub("user_mapping_provider:\n  config:\n    localpart_template: x\n"));
		assert!(by_sub("user_mapping_provider:\n  config:\n    subject_claim: sub\n"));
	}

	#[test]
	fn other_claims_templates_and_modules_do_not() {
		assert!(!by_sub("user_mapping_provider:\n  config:\n    subject_claim: email\n"));
		assert!(!by_sub(
			"user_mapping_provider:\n  config:\n    subject_template: '{{ user.email }}'\n"
		));
		assert!(!by_sub("user_mapping_provider:\n  module: my_module.Mapper\n"));
		assert!(by_sub(
			"user_mapping_provider:\n  module: synapse.handlers.oidc.JinjaOidcMappingProvider\n"
		));
	}

	#[test]
	fn issuers_match_regardless_of_a_trailing_slash() {
		let url = |s: &str| Url::parse(s).expect("a valid URL");
		assert!(same_issuer(&url("https://idp.example"), &url("https://idp.example/")));
		assert!(same_issuer(
			&url("https://idp.example/realms/a/"),
			&url("https://idp.example/realms/a")
		));
		assert!(!same_issuer(
			&url("https://idp.example/realms/a"),
			&url("https://idp.example/realms/b")
		));
	}
}
