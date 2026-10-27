//! OAuth clients registered with MAS, kept under the client IDs they already
//! hold, so a later login from the same app needs no new registration.

use tuwunel_core::Result;
use tuwunel_service::{Services, oauth::server::DcrRequest};

use super::{super::Report, Mas, ulid};

pub(in super::super) async fn import(
	services: &Services,
	mas: &Mas,
	report: &mut Report,
) -> Result {
	let Some(server) = &services.oauth.server else {
		return Ok(());
	};

	let rows = mas
		.source
		.rows(
			"SELECT oauth2_client_id::text, redirect_uris, client_name, client_uri, logo_uri, \
			 coalesce(contacts, '{}'), coalesce(token_endpoint_auth_method, 'none'), \
			 grant_type_authorization_code, grant_type_refresh_token, application_type, \
			 policy_uri, tos_uri FROM oauth2_clients ORDER BY oauth2_client_id",
			&[],
		)
		.await?;

	for row in rows {
		let Some(client_id) = report.keep("oauth2_clients", ulid(row.get(0))) else {
			continue;
		};

		let auth_method: String = row.get(6);
		if auth_method != "none" {
			report.skip(format!(
				"OAuth client {client_id}: it authenticates with {auth_method}, and tuwunel \
				 serves only public clients; it must register again"
			));
			continue;
		}

		// A rerun after a crash finds the client already there.
		if server.get_client(&client_id).await.is_ok() {
			continue;
		}

		let grant_types = [(7, "authorization_code"), (8, "refresh_token")]
			.into_iter()
			.filter(|&(column, _)| row.get(column))
			.map(|(_, grant)| grant.to_owned())
			.collect();

		let request = DcrRequest {
			redirect_uris: row.get(1),
			client_name: row.get(2),
			client_uri: row.get(3),
			logo_uri: row.get(4),
			contacts: row.get(5),
			token_endpoint_auth_method: Some(auth_method),
			grant_types: Some(grant_types),
			response_types: Some(vec!["code".to_owned()]),
			application_type: row.get(9),
			policy_uri: row.get(10),
			tos_uri: row.get(11),
			software_id: None,
			software_version: None,
		};

		if let Err(e) = server
			.register_client_with_id(&client_id, request)
			.await
		{
			report.skip(format!("OAuth client {client_id}: {e}; it must register again"));
			continue;
		}

		Report::count(&mut report.oauth_clients);
	}

	Ok(())
}
