// SPDX-License-Identifier: MIT
//! What the identity provider refuses, and why each refusal has its own name.
//!
//! Every case here is a credential that is *almost* right. A test suite that
//! only feeds garbage proves the parser works; these prove the checks work.

mod support;

use openmls::prelude::{BasicCredential, CredentialWithKey, KeyPackage, MlsMessageOut};
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::types::SignatureScheme;
use peachy_mls_core::credential::{CredentialPayload, DeviceCredential};
use peachy_mls_core::issuer::{device_key_pair, TestIssuer};
use peachy_mls_core::{
    Client, ClientConfig, CredentialRejection, Error, FixedClock, PeachyIdentityProvider,
    TrustedServerKeys, PEACHY_CIPHERSUITE,
};
use support::{device_seed, issuer, other_issuer, DAY, HOUR, NOW};

fn provider(trusted: TrustedServerKeys) -> PeachyIdentityProvider {
    PeachyIdentityProvider::with_clock(trusted, Box::new(FixedClock(NOW)))
}

/// An honest `pdc1` payload, read back out of an honestly minted token.
///
/// Built this way rather than by hand so that a forgery below differs from a
/// real credential in exactly ONE respect — which key signed it — and nothing
/// else can be blamed for the refusal.
fn device_payload(
    server: &TestIssuer,
    actor_id: &str,
    device_id: &str,
    device_key: &[u8; 32],
) -> CredentialPayload {
    let token = server
        .issue(actor_id, device_id, device_key, NOW - HOUR, NOW + DAY)
        .expect("mint");
    DeviceCredential::parse(&token)
        .expect("an honestly minted token parses")
        .payload()
        .clone()
}

fn rejection(result: Result<impl std::fmt::Debug, Error>) -> CredentialRejection {
    match result {
        Err(Error::CredentialRejected(reason)) => reason,
        other => panic!("expected a credential rejection, got {other:?}"),
    }
}

#[test]
fn a_good_credential_yields_the_key_layer_and_nothing_else() {
    let server = issuer();
    let (_, public) = device_key_pair(&device_seed(11));
    let token = server
        .issue("actor-ada", "device-1", &public, NOW - HOUR, NOW + 30 * DAY)
        .expect("mint");

    let identity = provider(server.trusted_keys().expect("keys"))
        .validate_token(&token, &public)
        .expect("a fresh credential verifies");

    assert_eq!(identity.actor_id, "actor-ada");
    assert_eq!(identity.device_id, "device-1");
    assert_eq!(identity.device_key, public);
    assert_eq!(identity.kid, server.kid());
    assert_eq!(identity.expires_at, NOW + 30 * DAY);
}

#[test]
fn the_published_key_list_is_readable_as_the_server_serves_it() {
    let server = issuer();
    let trusted = TrustedServerKeys::from_published_json(&server.published_json())
        .expect("the published shape parses");
    assert_eq!(trusted.len(), 1);
    assert!(trusted.contains(server.kid()));

    let (_, public) = device_key_pair(&device_seed(12));
    let token = server
        .issue("actor-bo", "device-2", &public, NOW - HOUR, NOW + DAY)
        .expect("mint");
    assert!(provider(trusted).validate_token(&token, &public).is_ok());
}

/// A list with no `use` on its entries is a list from before the field
/// existed, and every key on it was a device key.
#[test]
fn a_published_entry_with_no_use_is_a_device_key() {
    let server = issuer();
    let json = server.published_json().replace(",\"use\":\"device\"", "");
    let trusted = TrustedServerKeys::from_published_json(&json).expect("parses");
    assert!(trusted.contains(server.kid()));
}

/// Any `use` but `device` — one this build has never heard of — is dropped rather than guessed at, so a credential under it
/// reads as `unknown_kid` instead of being accepted under whatever this build
/// would have assumed.
#[test]
fn a_published_entry_with_any_other_use_vouches_for_nothing() {
    let server = issuer();
    let (_, public) = device_key_pair(&device_seed(13));
    let token = server
        .issue("actor-bo", "device-2", &public, NOW - HOUR, NOW + DAY)
        .expect("mint");
    for key_use in ["notary", "backup"] {
        let trusted =
            TrustedServerKeys::from_published_json(&server.published_json_with_use(key_use))
                .expect("parses");
        assert!(trusted.is_empty(), "a `{key_use}` key is not trusted");
        assert_eq!(
            rejection(provider(trusted).validate_token(&token, &public)),
            CredentialRejection::UnknownKid,
            "a credential under a `{key_use}` key"
        );
    }
}

// ---- One format, and nothing beside it ---------------------------------------
//
// Each shape below is signed by the trusted key, so the refusal is about the
// format and nothing else — and each is `malformed`, never an identity.

/// A person's `v: 1` payload, exactly as `pdc1` would carry it, signed by the
/// key this verifier trusts, under any other prefix: not a credential at all.
fn a_person_payload_under_another_prefix(server: &TestIssuer, tag: u8) -> (Vec<u8>, [u8; 32]) {
    let (_, public) = device_key_pair(&device_seed(tag));
    let payload = device_payload(server, "actor-ada", "device-ada-phone", &public);
    let bytes = serde_json::to_vec(&payload).expect("encode");
    (server.issue_raw("pdc9", &bytes), public)
}

#[test]
fn a_signed_person_payload_under_another_prefix_is_malformed_and_never_a_person() {
    let server = issuer();
    let (token, public) = a_person_payload_under_another_prefix(&server, 22);

    assert_eq!(
        rejection(provider(server.trusted_keys().expect("keys")).validate_token(&token, &public)),
        CredentialRejection::Malformed
    );
    assert!(DeviceCredential::parse(&token).is_err());
}

/// A `v: 1` `pdc1` that carries a field beside its own. A verifier that
/// ignored unknown fields would read this as Ada's device and drop the field
/// on the floor; this one refuses the lot.
#[test]
fn a_person_credential_carrying_an_unknown_field_is_malformed() {
    let server = issuer();
    let (_, public) = device_key_pair(&device_seed(22));
    let payload = device_payload(&server, "actor-ada", "device-ada-phone", &public);
    let mut json = serde_json::to_value(&payload).expect("encode");
    json.as_object_mut()
        .expect("object")
        .insert("role".into(), serde_json::json!("admin"));
    let token = server.issue_raw("pdc1", &serde_json::to_vec(&json).expect("encode"));
    assert_eq!(
        rejection(provider(server.trusted_keys().expect("keys")).validate_token(&token, &public)),
        CredentialRejection::Malformed
    );
}

/// The same refusal where it matters most: at the door a leaf comes in by. A
/// key package whose leaf carries a credential in another format — built with
/// OpenMLS directly, since no Peachy client will build on one — is refused at
/// the Add as `malformed`, and the group is untouched.
#[test]
fn a_key_package_carrying_another_format_is_refused_at_the_add() {
    let server = issuer();
    let mut ada = support::client(&server, 30, "actor-ada", "device-ada");
    ada.create_group(b"peachy-other-format").expect("create");

    let seed = device_seed(31);
    let (token, public) = a_person_payload_under_another_prefix(&server, 31);
    let signer =
        SignatureKeyPair::from_raw(SignatureScheme::ED25519, seed.to_vec(), public.to_vec());
    let provider = openmls_rust_crypto::OpenMlsRustCrypto::default();
    let bundle = KeyPackage::builder()
        .build(
            PEACHY_CIPHERSUITE,
            &provider,
            &signer,
            CredentialWithKey {
                credential: BasicCredential::new(token).into(),
                signature_key: public.to_vec().into(),
            },
        )
        .expect("OpenMLS builds whatever credential it is handed");
    let key_package = MlsMessageOut::from(bundle.key_package().clone())
        .to_bytes()
        .expect("encode");

    assert_eq!(
        rejection(ada.add_member(b"peachy-other-format", &key_package)),
        CredentialRejection::Malformed
    );
    assert_eq!(ada.roster(b"peachy-other-format").expect("roster").len(), 1);
}

#[test]
fn an_expired_credential_is_expired_and_not_merely_invalid() {
    let server = issuer();
    let (_, public) = device_key_pair(&device_seed(13));
    let token = server
        .issue(
            "actor-ada",
            "device-1",
            &public,
            NOW - 40 * DAY,
            // One second ago. The boundary matters: `exp` is exclusive, the
            // same way the server reads it.
            NOW - 1,
        )
        .expect("mint");

    assert_eq!(
        rejection(provider(server.trusted_keys().expect("keys")).validate_token(&token, &public)),
        CredentialRejection::Expired
    );

    // Exactly at `exp` is already too late, on both sides.
    let at_exp = server
        .issue("actor-ada", "device-1", &public, NOW - DAY, NOW)
        .expect("mint");
    assert_eq!(
        rejection(provider(server.trusted_keys().expect("keys")).validate_token(&at_exp, &public)),
        CredentialRejection::Expired
    );
}

#[test]
fn a_credential_from_the_future_is_not_yet_valid() {
    let server = issuer();
    let (_, public) = device_key_pair(&device_seed(14));
    let token = server
        .issue(
            "actor-ada",
            "device-1",
            &public,
            NOW + 10 * HOUR,
            NOW + 30 * DAY,
        )
        .expect("mint");
    assert_eq!(
        rejection(provider(server.trusted_keys().expect("keys")).validate_token(&token, &public)),
        CredentialRejection::NotYetValid
    );

    // Inside the 60s skew allowance it still passes: clocks disagree, and a
    // credential minted 30 seconds ago by a slightly fast server is not a
    // forgery.
    let barely_ahead = server
        .issue("actor-ada", "device-1", &public, NOW + 30, NOW + 30 * DAY)
        .expect("mint");
    assert!(provider(server.trusted_keys().expect("keys"))
        .validate_token(&barely_ahead, &public)
        .is_ok());
}

#[test]
fn a_kid_we_do_not_hold_is_an_unknown_kid_and_not_a_bad_signature() {
    let server = issuer();
    let impostor = other_issuer();
    let (_, public) = device_key_pair(&device_seed(15));

    // Signed by a real key, but one this verifier has never fetched. The
    // distinction is operational: unknown kid after a rotation means "refresh
    // the key list", a bad signature means something else entirely.
    let token = impostor
        .issue("actor-ada", "device-1", &public, NOW - HOUR, NOW + DAY)
        .expect("mint");
    assert_eq!(
        rejection(provider(server.trusted_keys().expect("keys")).validate_token(&token, &public)),
        CredentialRejection::UnknownKid
    );

    // The same token verifies fine against a verifier that holds that key —
    // proof the rejection was about trust and not about the bytes.
    assert!(provider(impostor.trusted_keys().expect("keys"))
        .validate_token(&token, &public)
        .is_ok());
}

#[test]
fn a_credential_claiming_a_trusted_kid_but_signed_by_another_key_fails_the_signature() {
    let server = issuer();
    let impostor = other_issuer();
    let (_, public) = device_key_pair(&device_seed(16));

    // The sharpest forgery available: take the trusted `kid` — a public,
    // guessable 8 hex characters — and sign with your own key.
    let payload = CredentialPayload {
        v: 1,
        kid: server.kid().to_string(),
        actor_id: "actor-ada".into(),
        device_id: "device-1".into(),
        device_key: base64_standard(&public),
        account_key: String::new(),
        account_sig: String::new(),
        iat: NOW - HOUR,
        exp: NOW + DAY,
    };
    let token = impostor.issue_payload(&payload).expect("mint");

    assert_eq!(
        rejection(provider(server.trusted_keys().expect("keys")).validate_token(&token, &public)),
        CredentialRejection::BadSignature
    );
}

#[test]
fn a_tampered_payload_fails_the_signature() {
    let server = issuer();
    let (_, public) = device_key_pair(&device_seed(17));
    let token = server
        .issue("actor-ada", "device-1", &public, NOW - HOUR, NOW + DAY)
        .expect("mint");

    // Flip one character of the payload segment. base64url is dense enough
    // that almost any change decodes to different bytes, and the signature
    // covers the bytes as they arrived — which is the whole reason this crate
    // never re-serializes a parsed payload.
    let text = String::from_utf8(token).expect("ascii");
    let mut parts: Vec<String> = text.split('.').map(str::to_string).collect();
    let payload = &mut parts[1];
    let last = payload.pop().expect("a non-empty payload segment");
    payload.push(if last == 'A' { 'B' } else { 'A' });
    let tampered = parts.join(".").into_bytes();

    let reason = rejection(
        provider(server.trusted_keys().expect("keys")).validate_token(&tampered, &public),
    );
    assert!(
        matches!(
            reason,
            CredentialRejection::BadSignature | CredentialRejection::Malformed
        ),
        "a tampered payload must not verify, got {reason}"
    );
}

#[test]
fn a_tampered_signature_fails_the_signature() {
    let server = issuer();
    let (_, public) = device_key_pair(&device_seed(18));
    let token = server
        .issue("actor-ada", "device-1", &public, NOW - HOUR, NOW + DAY)
        .expect("mint");

    let text = String::from_utf8(token).expect("ascii");
    let mut parts: Vec<String> = text.split('.').map(str::to_string).collect();
    let signature = &mut parts[2];
    let first = signature.remove(0);
    signature.insert(0, if first == 'A' { 'B' } else { 'A' });
    let tampered = parts.join(".").into_bytes();

    assert_eq!(
        rejection(
            provider(server.trusted_keys().expect("keys")).validate_token(&tampered, &public)
        ),
        CredentialRejection::BadSignature
    );
}

#[test]
fn a_valid_credential_on_the_wrong_leaf_is_a_leaf_key_mismatch() {
    let server = issuer();
    let (_, ada_key) = device_key_pair(&device_seed(19));
    let (_, attacker_key) = device_key_pair(&device_seed(20));

    // Ada's credential is a public artefact — anyone who has seen one of her
    // messages has seen it. Replayed onto a leaf signing with somebody else's
    // key, it must buy nothing.
    let token = server
        .issue("actor-ada", "device-1", &ada_key, NOW - HOUR, NOW + DAY)
        .expect("mint");

    assert_eq!(
        rejection(
            provider(server.trusted_keys().expect("keys")).validate_token(&token, &attacker_key)
        ),
        CredentialRejection::LeafKeyMismatch
    );
    // Against the right leaf it is fine, so the refusal was about the binding.
    assert!(provider(server.trusted_keys().expect("keys"))
        .validate_token(&token, &ada_key)
        .is_ok());
}

#[test]
fn a_future_token_version_is_refused_rather_than_read_with_todays_rules() {
    let server = issuer();
    let (_, public) = device_key_pair(&device_seed(21));
    // Neither version has ever been issued under `pdc1`. Both are refused by
    // version, before the payload is read strictly.
    for version in [2, 3] {
        let payload = CredentialPayload {
            v: version,
            kid: server.kid().to_string(),
            actor_id: "actor-ada".into(),
            device_id: "device-1".into(),
            device_key: base64_standard(&public),
            account_key: String::new(),
            account_sig: String::new(),
            iat: NOW - HOUR,
            exp: NOW + DAY,
        };
        let token = server.issue_payload(&payload).expect("mint");
        assert_eq!(
            rejection(
                provider(server.trusted_keys().expect("keys")).validate_token(&token, &public)
            ),
            CredentialRejection::UnsupportedVersion
        );
    }
}

#[test]
fn malformed_tokens_are_malformed() {
    let server = issuer();
    let (_, public) = device_key_pair(&device_seed(22));
    let trusted = server.trusted_keys().expect("keys");

    let cases: &[(&str, &[u8])] = &[
        ("empty", b""),
        ("no dots", b"pdc1"),
        ("wrong prefix", b"pdc9.aaaa.bbbb"),
        ("four parts", b"pdc1.aaaa.bbbb.cccc"),
        ("not base64", b"pdc1.!!!!.????"),
        ("payload is not json", b"pdc1.aGVsbG8.aGVsbG8"),
    ];
    for (name, bytes) in cases {
        assert_eq!(
            rejection(provider(trusted.clone()).validate_token(bytes, &public)),
            CredentialRejection::Malformed,
            "{name} should be malformed"
        );
    }
}

#[test]
fn a_client_refuses_to_build_on_a_credential_it_cannot_prove() {
    let server = issuer();
    let seed = device_seed(23);
    let (_, public) = device_key_pair(&seed);
    let other_seed = device_seed(24);

    let token = server
        .issue("actor-ada", "device-1", &public, NOW - HOUR, NOW + DAY)
        .expect("mint");

    // The credential is valid; the private key this client holds is not the
    // one it names. Catching that here beats discovering it as a remote
    // rejection the first time somebody tries to add us.
    let mut config = ClientConfig::new(
        token.clone(),
        other_seed,
        server.trusted_keys().expect("keys"),
    );
    config.clock = Some(Box::new(FixedClock(NOW)));
    assert_eq!(
        rejection(Client::new(config).map(|_| "built")),
        CredentialRejection::LeafKeyMismatch
    );

    // And a client whose trust set is empty cannot vouch for itself either.
    let mut config = ClientConfig::new(token, seed, support::empty_trust());
    config.clock = Some(Box::new(FixedClock(NOW)));
    assert_eq!(
        rejection(Client::new(config).map(|_| "built")),
        CredentialRejection::UnknownKid
    );
}

#[test]
fn a_peer_whose_credential_expired_is_refused_at_the_add() {
    use peachy_mls_core::Incoming;

    let server = issuer();
    let mut ada = support::client(&server, 25, "actor-ada", "device-ada");

    // Bo's credential ran out yesterday. He can still build a client on a
    // clock that predates the expiry, and still mint a key package — the
    // refusal has to happen at Ada's door, not at his.
    let bo_seed = device_seed(26);
    let (_, bo_public) = device_key_pair(&bo_seed);
    let stale = server
        .issue(
            "actor-bo",
            "device-bo",
            &bo_public,
            NOW - 31 * DAY,
            NOW - DAY,
        )
        .expect("mint");
    let mut bo_config = ClientConfig::new(stale, bo_seed, server.trusted_keys().expect("keys"))
        .with_own_account_identity(Some(support::held_identity("actor-bo")));
    bo_config.clock = Some(Box::new(FixedClock(NOW - 10 * DAY)));
    let bo = Client::new(bo_config).expect("bo's own clock accepts it");

    ada.create_group(b"peachy-stale").expect("create");
    let kp = bo.generate_key_package().expect("key package");
    assert_eq!(
        rejection(ada.add_member(b"peachy-stale", &kp)),
        CredentialRejection::Expired
    );
    assert_eq!(ada.roster(b"peachy-stale").expect("roster").len(), 1);

    // Nothing was half-done: Ada can still add somebody legitimate afterwards.
    let mut cy = support::client(&server, 27, "actor-cy", "device-cy");
    let cy_kp = cy.generate_key_package().expect("key package");
    let bundle = ada.add_member(b"peachy-stale", &cy_kp).expect("add cy");
    ada.merge_pending_commit(b"peachy-stale").expect("merge");
    cy.join_from_welcome(&bundle.welcome.expect("welcome"))
        .expect("join");
    let hello = ada.encrypt(b"peachy-stale", b"hello cy").expect("encrypt");
    assert!(matches!(
        cy.process_message(b"peachy-stale", &hello).expect("read"),
        Incoming::Application { .. }
    ));
}

/// The server writes `device_key` with `Buffer.toString("base64")`.
fn base64_standard(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}
