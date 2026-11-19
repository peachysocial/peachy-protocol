// SPDX-License-Identifier: MIT
//! The server's published key list (`GET /healthz/device-credential-keys`)
//! through every door that reads it: `TrustedServerKeys::from_published_json`,
//! `from_published_json_pinned` in both modes, and the bindings' doors
//! `server_key_pin_report` and `server_keys_pinned_json`, against the
//! production and development sets. docs/mls-core.md §Fuzzing.
//!
//! The first input byte picks what the rest is:
//! - even: the list, as UTF-8 the fuzzer wrote;
//! - odd: entries of 3 bytes each, `kid ‖ key ‖ use`, built into a list in
//!   the server's shape: each byte picks from the carried production key, a
//!   key no set carries, the development key, a kid the fuzzer's bytes name,
//!   a key that is not base64, and a use of `device`, another use, `null` or
//!   none, as an object or as an array of the three. So the same kid can be
//!   listed twice, under different bytes.
//!
//! - No input panics.
//! - Every door reads the list alike: one refuses it exactly when
//!   `from_published_json` does.
//! - The comparison is exact: `unpinned` is every published kid not carried
//!   under the same bytes, `missing` every carried kid not published, and
//!   the report is `""` exactly when both are empty.
//! - Compare trusts exactly the published set; Enforce exactly the kids both
//!   hold under the same bytes.
//! - `server_keys_pinned_json` reads back as the Enforce set, kid for kid and
//!   byte for byte, and narrowing it again changes nothing.

#![no_main]

use libfuzzer_sys::fuzz_target;
use peachy_mls_core::issuer::device_key_pair;
use peachy_mls_core::server_key_pins::{
    server_key_pin_report, server_keys_pinned_json, PinMode, PINNED_DEVELOPMENT, PINNED_PRODUCTION,
};
use peachy_mls_core::TrustedServerKeys;

fn base64(raw: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in raw.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(char::from(ALPHABET[((n >> (18 - 6 * i)) & 63) as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

fn keys_of(set: &TrustedServerKeys) -> Vec<(String, [u8; 32])> {
    set.iter().map(|(kid, raw)| (kid.to_owned(), raw)).collect()
}

/// The list in the server's shape, from 3-byte entries.
fn built(rest: &[u8]) -> String {
    let carried = TrustedServerKeys::pinned(PINNED_PRODUCTION).expect("the production set");
    let (carried_kid, carried_raw) = carried.iter().next().expect("one production key");
    // The development set's own key, named here so it is listed whether or
    // not this build carries it.
    let development_kid = "f8f6eaa4";
    let development_key = "nHq6JH1Lmot5tW6rGCV05fjNlUAomh+JWgaeAFtYs8o=";
    // A valid key no carried set holds.
    let other_key = device_key_pair(&[0x99; 32]).1;
    let mut entries = Vec::new();
    for (i, entry) in rest.chunks_exact(3).enumerate() {
        let kid = match entry[0] % 4 {
            0 => carried_kid.to_owned(),
            1 => development_kid.to_owned(),
            2 => format!("k{}", entry[0] >> 2),
            _ => String::new(),
        };
        let public_key = match entry[1] % 5 {
            0 => base64(&carried_raw),
            1 => base64(&other_key),
            2 => development_key.to_owned(),
            3 => base64(&[entry[1]; 32]),
            _ => "not base64!".to_owned(),
        };
        let mut object = serde_json::json!({
            "kid": kid,
            "publicKey": public_key,
            "current": i == 0,
        });
        match entry[2] % 4 {
            0 => object["use"] = "device".into(),
            1 => object["use"] = "notary".into(),
            2 => object["use"] = serde_json::Value::Null,
            _ => {}
        }
        if entry[2] & 4 != 0 {
            // The same key as an array, which a struct reader would read
            // field by field.
            let array = vec![
                object["kid"].clone(),
                object["publicKey"].clone(),
                object.get("use").cloned().unwrap_or_default(),
            ];
            entries.push(serde_json::Value::Array(array));
            continue;
        }
        entries.push(object);
    }
    serde_json::json!({ "enabled": true, "keys": entries }).to_string()
}

fn check(json: &str, server: &str) {
    let pinned = TrustedServerKeys::pinned(server).expect("a carried set");
    let report = server_key_pin_report(json, server);
    let narrowed = server_keys_pinned_json(json, server);
    let compare = TrustedServerKeys::from_published_json_pinned(json, &pinned, PinMode::Compare);
    let enforce = TrustedServerKeys::from_published_json_pinned(json, &pinned, PinMode::Enforce);
    let Ok(published) = TrustedServerKeys::from_published_json(json) else {
        assert!(report.is_err(), "the report read a list the reader refused");
        assert!(
            narrowed.is_err(),
            "the narrowing read a list the reader refused"
        );
        assert!(compare.is_err() && enforce.is_err());
        return;
    };
    let report = report.expect("the report reads what the reader reads");
    let narrowed = narrowed.expect("the narrowing reads what the reader reads");
    let (compare, comparison) = compare.expect("Compare reads what the reader reads");
    let (enforce, enforce_comparison) = enforce.expect("Enforce reads what the reader reads");
    assert_eq!(comparison, enforce_comparison);

    let unpinned: Vec<String> = published
        .iter()
        .filter(|(kid, raw)| pinned.public_key(kid) != Some(*raw))
        .map(|(kid, _)| kid.to_owned())
        .collect();
    let missing: Vec<String> = pinned
        .iter()
        .filter(|(kid, _)| !published.contains(kid))
        .map(|(kid, _)| kid.to_owned())
        .collect();
    assert_eq!(comparison.unpinned, unpinned);
    assert_eq!(comparison.missing, missing);
    assert_eq!(report.is_empty(), comparison.is_match());
    assert_eq!(report, comparison.describe());

    assert_eq!(keys_of(&compare), keys_of(&published));
    let both: Vec<(String, [u8; 32])> = published
        .iter()
        .filter(|(kid, raw)| pinned.public_key(kid) == Some(*raw))
        .map(|(kid, raw)| (kid.to_owned(), raw))
        .collect();
    assert_eq!(keys_of(&enforce), both);

    let reread = TrustedServerKeys::from_published_json(&narrowed)
        .expect("the narrowed list reads in the published shape");
    assert_eq!(
        keys_of(&reread),
        both,
        "the narrowed list trusts other keys than Enforce does"
    );
    let again = server_keys_pinned_json(&narrowed, server).expect("the narrowed list narrows");
    let reread_again = TrustedServerKeys::from_published_json(&again).expect("reads");
    assert_eq!(keys_of(&reread_again), both);
}

fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };
    let json = if mode % 2 == 0 {
        let Ok(json) = std::str::from_utf8(rest) else {
            return;
        };
        json.to_owned()
    } else {
        built(rest)
    };
    check(&json, PINNED_PRODUCTION);
    check(&json, PINNED_DEVELOPMENT);
});
