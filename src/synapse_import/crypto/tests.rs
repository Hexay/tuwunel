use super::one_time_key_id;

#[test]
fn one_time_key_id_joins_algorithm_and_id() {
	let id = one_time_key_id("signed_curve25519", "AAAAHQ").expect("a valid key ID");

	assert_eq!(id.as_str(), "signed_curve25519:AAAAHQ");
	assert_eq!(id.algorithm().as_str(), "signed_curve25519");
}

#[test]
fn one_time_key_id_keeps_an_unknown_algorithm() {
	let id = one_time_key_id("org.example.alg", "k1").expect("a valid key ID");

	assert_eq!(id.algorithm().as_str(), "org.example.alg");
}
