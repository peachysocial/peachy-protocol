// SPDX-License-Identifier: MIT
//! The server keys a build carries, read against what a server publishes.
//!
//! Three comparisons (equal, a published key the build does not carry, a
//! carried key the server does not publish), and what each mode then trusts:
//! [`PinMode::Compare`] the published list exactly, [`PinMode::Enforce`] only
//! the keys both hold under the same bytes.
//!
//! The `development` set exists only with the `development-keys` feature
//! (`cargo test --all-features`); without it the set is empty, which the last
//! test pins.

mod support;

use base64::Engine as _;
use peachy_mls_core::issuer::{device_key_pair, TestIssuer};
use peachy_mls_core::server_key_pins::{
    server_key_pin_report, server_keys_pinned_json, PinComparison, PinMode, PINNED_DEVELOPMENT,
    PINNED_PRODUCTION,
};
use peachy_mls_core::{
    CredentialRejection, Error, FixedClock, PeachyIdentityProvider, TrustedServerKeys,
};
use sha2::{Digest, Sha256};
use support::{device_seed, issuer, other_issuer, DAY, HOUR, NOW};

fn b64(raw: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(raw)
}

/// A published list in the server's shape.
fn published(keys: &[(&str, [u8; 32], &str)]) -> String {
    let entries: Vec<String> = keys
        .iter()
        .enumerate()
        .map(|(i, (kid, raw, key_use))| {
            format!(
                "{{\"kid\":\"{kid}\",\"publicKey\":\"{}\",\"current\":{},\"use\":\"{key_use}\"}}",
                b64(raw),
                i == 0
            )
        })
        .collect();
    format!("{{\"enabled\":true,\"keys\":[{}]}}", entries.join(","))
}

fn pinned_of(issuers: &[&TestIssuer]) -> TrustedServerKeys {
    let mut set = TrustedServerKeys::new();
    for issuer in issuers {
        set.insert(issuer.kid(), &issuer.public_key())
            .expect("valid key");
    }
    set
}

fn kids(set: &TrustedServerKeys) -> Vec<String> {
    set.iter().map(|(kid, _)| kid.to_owned()).collect()
}

/// The published list of the carried set for `server`, as its server would
/// serve it today.
fn published_pins(server: &str) -> String {
    let pinned = TrustedServerKeys::pinned(server).expect("a carried set");
    let keys: Vec<(String, [u8; 32])> = pinned.iter().map(|(k, raw)| (k.to_owned(), raw)).collect();
    let refs: Vec<(&str, [u8; 32], &str)> = keys
        .iter()
        .map(|(k, raw)| (k.as_str(), *raw, "device"))
        .collect();
    published(&refs)
}

/// The carried sets this build holds keys for.
fn carried_sets() -> Vec<&'static str> {
    if cfg!(feature = "development-keys") {
        vec![PINNED_PRODUCTION, PINNED_DEVELOPMENT]
    } else {
        vec![PINNED_PRODUCTION]
    }
}

/// The seed every local test server signs with. Public in the repository on
/// purpose, which is why only a `development-keys` build carries its key.
fn local_test_server() -> TestIssuer {
    let seed = base64::engine::general_purpose::STANDARD
        .decode("DRQbIikwNz5FTFNaYWhvdn2Ei5KZoKeutbzDytHY3+Y=")
        .expect("base64");
    TestIssuer::from_seed(&seed.try_into().expect("32 bytes"))
}

#[test]
fn every_carried_kid_is_the_one_its_key_derives() {
    // The server names a key by the first 8 hex of SHA-256 over its raw public
    // key; a typo in the carried file would otherwise read as a rotation.
    for server in carried_sets() {
        let pinned = TrustedServerKeys::pinned(server).expect("a carried set");
        assert!(!pinned.is_empty(), "{server} carries no keys");
        for (kid, raw) in pinned.iter() {
            let derived = hex::encode(&Sha256::digest(raw)[..4]);
            assert_eq!(kid, derived, "{server}: kid {kid} is not its key's");
        }
    }
}

#[cfg(feature = "development-keys")]
#[test]
fn the_development_set_is_the_fixed_local_test_key() {
    let local = local_test_server();
    let development = TrustedServerKeys::pinned(PINNED_DEVELOPMENT).expect("carried");
    assert_eq!(
        development.public_key(local.kid()),
        Some(local.public_key())
    );
    let production = TrustedServerKeys::pinned(PINNED_PRODUCTION).expect("carried");
    assert!(!production.contains(local.kid()));
}

#[test]
fn an_unknown_set_name_is_an_error_not_an_empty_set() {
    assert!(matches!(
        TrustedServerKeys::pinned("staging"),
        Err(Error::InvalidArgument(_))
    ));
}

#[test]
fn equal_lists_compare_as_a_match() {
    let server = issuer();
    let pinned = pinned_of(&[&server]);
    let (trusted, comparison) = TrustedServerKeys::from_published_json_pinned(
        &server.published_json(),
        &pinned,
        PinMode::Compare,
    )
    .expect("parses");
    assert!(comparison.is_match());
    assert_eq!(comparison.describe(), "");
    assert_eq!(kids(&trusted), vec![server.kid().to_owned()]);

    // The carried sets against their own lists.
    for set in carried_sets() {
        assert_eq!(
            server_key_pin_report(&published_pins(set), set).expect("reads"),
            ""
        );
    }
}

#[test]
fn a_published_key_the_build_does_not_carry_is_reported_and_still_trusted() {
    let ours = issuer();
    let theirs = other_issuer();
    let pinned = pinned_of(&[&ours]);
    let json = published(&[
        (theirs.kid(), theirs.public_key(), "device"),
        (ours.kid(), ours.public_key(), "device"),
    ]);
    let (trusted, comparison) =
        TrustedServerKeys::from_published_json_pinned(&json, &pinned, PinMode::Compare)
            .expect("parses");
    assert_eq!(
        comparison,
        PinComparison {
            unpinned: vec![theirs.kid().to_owned()],
            missing: vec![],
        }
    );
    assert!(comparison.describe().contains(theirs.kid()));
    // Compare changes nothing: both keys are trusted, as today.
    let mut want = vec![ours.kid().to_owned(), theirs.kid().to_owned()];
    want.sort();
    assert_eq!(kids(&trusted), want);
}

#[test]
fn a_carried_kid_published_under_other_bytes_is_not_pinned() {
    let ours = issuer();
    let theirs = other_issuer();
    let pinned = pinned_of(&[&ours]);
    let json = published(&[(ours.kid(), theirs.public_key(), "device")]);
    let (trusted, comparison) =
        TrustedServerKeys::from_published_json_pinned(&json, &pinned, PinMode::Enforce)
            .expect("parses");
    assert_eq!(comparison.unpinned, vec![ours.kid().to_owned()]);
    assert!(trusted.is_empty());
}

#[test]
fn a_carried_key_the_server_does_not_publish_is_reported_missing() {
    let ours = issuer();
    let retired = other_issuer();
    let pinned = pinned_of(&[&ours, &retired]);
    for mode in [PinMode::Compare, PinMode::Enforce] {
        let (trusted, comparison) =
            TrustedServerKeys::from_published_json_pinned(&ours.published_json(), &pinned, mode)
                .expect("parses");
        assert_eq!(
            comparison,
            PinComparison {
                unpinned: vec![],
                missing: vec![retired.kid().to_owned()],
            }
        );
        // Not trusted in either mode: retiring a key stays the server's call.
        assert_eq!(kids(&trusted), vec![ours.kid().to_owned()], "{mode:?}");
    }
}

#[test]
fn enforce_trusts_the_intersection_and_refuses_a_credential_under_any_other_kid() {
    let ours = issuer();
    let theirs = other_issuer();
    let pinned = pinned_of(&[&ours]);
    let json = published(&[
        (theirs.kid(), theirs.public_key(), "device"),
        (ours.kid(), ours.public_key(), "device"),
    ]);
    let (_, public) = device_key_pair(&device_seed(31));
    let minted_by_theirs = theirs
        .issue("actor-ada", "device-1", &public, NOW - HOUR, NOW + DAY)
        .expect("mint");
    let minted_by_ours = ours
        .issue("actor-ada", "device-1", &public, NOW - HOUR, NOW + DAY)
        .expect("mint");
    let provider = |trusted| PeachyIdentityProvider::with_clock(trusted, Box::new(FixedClock(NOW)));

    let (compare, _) =
        TrustedServerKeys::from_published_json_pinned(&json, &pinned, PinMode::Compare)
            .expect("parses");
    assert!(provider(compare)
        .validate_token(&minted_by_theirs, &public)
        .is_ok());

    let (enforce, _) =
        TrustedServerKeys::from_published_json_pinned(&json, &pinned, PinMode::Enforce)
            .expect("parses");
    assert_eq!(kids(&enforce), vec![ours.kid().to_owned()]);
    let enforce_provider = provider(enforce);
    assert!(enforce_provider
        .validate_token(&minted_by_ours, &public)
        .is_ok());
    match enforce_provider.validate_token(&minted_by_theirs, &public) {
        Err(Error::CredentialRejected(CredentialRejection::UnknownKid)) => {}
        other => panic!("expected unknown_kid, got {other:?}"),
    }
}

#[test]
fn the_pinned_json_door_is_the_enforce_set_in_the_published_shape() {
    // The production set's own key, plus one it does not carry, plus a
    // carried key published for another use.
    let pinned = TrustedServerKeys::pinned(PINNED_PRODUCTION).expect("carried");
    let (kid, raw) = pinned.iter().next().expect("one key");
    let (kid, raw) = (kid.to_owned(), raw);
    let theirs = other_issuer();
    let json = published(&[
        (theirs.kid(), theirs.public_key(), "device"),
        (&kid, raw, "device"),
    ]);
    let narrowed = server_keys_pinned_json(&json, PINNED_PRODUCTION).expect("narrows");
    let reread = TrustedServerKeys::from_published_json(&narrowed).expect("same shape");
    let (enforce, _) =
        TrustedServerKeys::from_published_json_pinned(&json, &pinned, PinMode::Enforce)
            .expect("parses");
    assert_eq!(kids(&reread), kids(&enforce));
    assert_eq!(kids(&reread), vec![kid.clone()]);
    // Everything else in the document is carried through.
    assert!(narrowed.contains("\"enabled\":true"));
    assert!(narrowed.contains("\"current\":false"));

    let other_use = published(&[(&kid, raw, "notary")]);
    let narrowed = server_keys_pinned_json(&other_use, PINNED_PRODUCTION).expect("narrows");
    assert!(TrustedServerKeys::from_published_json(&narrowed)
        .expect("parses")
        .is_empty());

    let report = server_key_pin_report(&json, PINNED_PRODUCTION).expect("reads");
    assert_eq!(
        report,
        format!("published but not pinned: {}", theirs.kid())
    );
}

#[cfg(not(feature = "development-keys"))]
#[test]
fn without_development_keys_the_development_set_is_empty() {
    // Still a set, not an unknown name: a client on a server that is not
    // production compares, logs, and with enforcement off trusts the list.
    let development = TrustedServerKeys::pinned(PINNED_DEVELOPMENT).expect("a set");
    assert!(development.is_empty());

    // The local test server's own list: its key reads as not pinned, and the
    // enforce door narrows the list to nothing.
    let local = local_test_server();
    let json = local.published_json();
    assert_eq!(
        server_key_pin_report(&json, PINNED_DEVELOPMENT).expect("reads"),
        format!("published but not pinned: {}", local.kid())
    );
    let narrowed = server_keys_pinned_json(&json, PINNED_DEVELOPMENT).expect("narrows");
    assert!(TrustedServerKeys::from_published_json(&narrowed)
        .expect("same shape")
        .is_empty());
    let (compare, _) =
        TrustedServerKeys::from_published_json_pinned(&json, &development, PinMode::Compare)
            .expect("parses");
    assert_eq!(kids(&compare), vec![local.kid().to_owned()]);
    let (enforce, _) =
        TrustedServerKeys::from_published_json_pinned(&json, &development, PinMode::Enforce)
            .expect("parses");
    assert!(enforce.is_empty());
}

#[test]
fn a_list_that_is_not_json_is_an_error_at_both_doors() {
    for door in [server_key_pin_report, server_keys_pinned_json] {
        assert!(matches!(
            door("not json", PINNED_PRODUCTION),
            Err(Error::InvalidArgument(_))
        ));
    }
}

#[test]
fn a_kid_listed_twice_narrows_to_the_entry_the_list_is_read_by() {
    // The carried key's kid, first under the carried bytes and last under a
    // key it does not carry. The list is read by its last entry, so neither
    // the enforce set nor the narrowed list trusts the kid; and in the other
    // order, both trust it under the carried bytes.
    let pinned = TrustedServerKeys::pinned(PINNED_PRODUCTION).expect("carried");
    let (kid, raw) = pinned.iter().next().expect("one key");
    let (kid, raw) = (kid.to_owned(), raw);
    let theirs = other_issuer().public_key();
    for (keys, trusted) in [
        (
            [
                (kid.as_str(), raw, "device"),
                (kid.as_str(), theirs, "device"),
            ],
            false,
        ),
        (
            [
                (kid.as_str(), theirs, "device"),
                (kid.as_str(), raw, "device"),
            ],
            true,
        ),
    ] {
        let json = published(&keys);
        let (enforce, _) =
            TrustedServerKeys::from_published_json_pinned(&json, &pinned, PinMode::Enforce)
                .expect("parses");
        let narrowed = server_keys_pinned_json(&json, PINNED_PRODUCTION).expect("narrows");
        let reread = TrustedServerKeys::from_published_json(&narrowed).expect("same shape");
        assert_eq!(kids(&reread), kids(&enforce));
        assert_eq!(reread.public_key(&kid), enforce.public_key(&kid));
        assert_eq!(enforce.contains(&kid), trusted);
        if trusted {
            assert_eq!(reread.public_key(&kid), Some(raw));
        }
    }
}

#[test]
fn a_list_that_is_not_an_object_is_refused_at_every_door() {
    // An array holding the key list reads as the list to a struct reader,
    // and the narrowing door finds no `keys` in it to narrow: refused at
    // every door, so none passes a key it was meant to drop.
    let theirs = other_issuer();
    let entry = format!(
        "{{\"kid\":\"{}\",\"publicKey\":\"{}\",\"use\":\"device\"}}",
        theirs.kid(),
        b64(&theirs.public_key())
    );
    let pinned = TrustedServerKeys::pinned(PINNED_PRODUCTION).expect("carried");
    for json in [format!("[[{entry}]]"), "[]".to_owned(), "null".to_owned()] {
        assert!(matches!(
            TrustedServerKeys::from_published_json(&json),
            Err(Error::InvalidArgument(_))
        ));
        for mode in [PinMode::Compare, PinMode::Enforce] {
            assert!(TrustedServerKeys::from_published_json_pinned(&json, &pinned, mode).is_err());
        }
        for door in [server_key_pin_report, server_keys_pinned_json] {
            assert!(matches!(
                door(&json, PINNED_PRODUCTION),
                Err(Error::InvalidArgument(_))
            ));
        }
    }
}

#[test]
fn a_key_that_is_not_an_object_is_refused_at_every_door() {
    // The carried key as an array, which a struct reader reads as a key and
    // the narrowing door finds no kid in and drops: refused at every door,
    // so Enforce and the narrowed list cannot differ on it.
    let pinned = TrustedServerKeys::pinned(PINNED_PRODUCTION).expect("carried");
    let (kid, raw) = pinned.iter().next().expect("one key");
    let array = format!("[\"{kid}\",\"{}\",\"device\"]", b64(&raw));
    let object = format!(
        "{{\"kid\":\"{kid}\",\"publicKey\":\"{}\",\"use\":\"device\"}}",
        b64(&raw)
    );
    for keys in [array.clone(), format!("{object},{array}"), "7".to_owned()] {
        let json = format!("{{\"enabled\":true,\"keys\":[{keys}]}}");
        assert!(matches!(
            TrustedServerKeys::from_published_json(&json),
            Err(Error::InvalidArgument(_))
        ));
        for mode in [PinMode::Compare, PinMode::Enforce] {
            assert!(TrustedServerKeys::from_published_json_pinned(&json, &pinned, mode).is_err());
        }
        for door in [server_key_pin_report, server_keys_pinned_json] {
            assert!(matches!(
                door(&json, PINNED_PRODUCTION),
                Err(Error::InvalidArgument(_))
            ));
        }
    }
}
