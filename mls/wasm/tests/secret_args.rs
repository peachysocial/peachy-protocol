// SPDX-License-Identifier: MIT
//! Every key and plaintext argument the binding is handed is its own copy,
//! wiped on return (docs/mls-core.md §Security considerations).
//! wasm-bindgen hands a `&[u8]` or `&str` argument in a
//! buffer its glue frees after the call, unwiped; a `Vec<u8>` or `String` is
//! the module's own, which the function wraps in `Zeroizing`. Both are a
//! `Uint8Array` or `string` to JavaScript, so nothing a caller writes changes.
//!
//! The check reads the binding's source: what it pins is each signature and
//! the wrap that follows it, which the host build of the crate cannot observe.

const SOURCE: &str = include_str!("../src/lib.rs");

/// (function, argument): the secrets, then the plaintexts the binding seals.
const OWNED: &[(&str, &str)] = &[
    ("new", "device_signing_key_seed"),
    ("open", "device_signing_key_seed"),
    ("sign_install_revocations", "account_key"),
    ("call_sender_key", "call_root"),
    ("call_frame_key", "sender_key"),
    ("resend_author_commitment", "secret"),
    ("signing_key_public_key", "seed"),
    ("sign_device_approval", "seed"),
    ("device_link_qr", "link_secret"),
    ("device_link_qr_matches", "scanned"),
    ("device_link_qr_secret", "scanned"),
    ("sign_device_link_commitment", "seed"),
    ("device_link_kem_public_key", "seed"),
    ("sign_device_link_kem", "seed"),
    ("account_identity_public_key", "account_key"),
    ("sign_account_device", "account_key"),
    ("sign_device_revocation", "account_key"),
    ("account_key_seal", "approver_seed"),
    ("account_key_seal", "account_key"),
    ("account_key_seal_hybrid", "approver_seed"),
    ("account_key_seal_hybrid", "account_key"),
    ("account_key_accept_hybrid", "recipient_seed"),
    ("account_key_accept_hybrid", "link_key_seed"),
    ("account_key_open", "recipient_seed"),
    ("transfer_key_seal", "key"),
    ("transfer_key_open", "recipient_seed"),
    ("store_seal", "account_key"),
    ("store_open", "account_key"),
    ("note_seal_signed", "account_key"),
    ("note_seal_signed", "device_seed"),
    ("note_sender", "account_key"),
    ("note_open_signed", "account_key"),
    ("seal_envelope", "inner"),
    ("encrypt", "plaintext"),
    ("encrypt_with_hint", "plaintext"),
    ("seal_call_signal", "signal_json"),
    ("seal_call_signal_signed", "signal_json"),
    ("encode_call_signal", "signal_json"),
    ("call_signal_is_urgent", "signal_json"),
    ("store_seal", "plaintext"),
    ("note_seal_signed", "plaintext"),
];

/// Each `pub fn name(` or `pub async fn name(` in the source: its parameter
/// list and the body text up to the next `pub fn` or `pub async fn`.
fn definitions(name: &str) -> Vec<(&'static str, &'static str)> {
    let next = |text: &str| {
        [text.find("pub fn "), text.find("pub async fn ")]
            .into_iter()
            .flatten()
            .min()
    };
    let mut found = Vec::new();
    for needle in [format!("pub fn {name}("), format!("pub async fn {name}(")] {
        let mut from = 0;
        while let Some(at) = SOURCE[from..].find(&needle) {
            let start = from + at + needle.len();
            let close = start + SOURCE[start..].find(')').unwrap_or(0);
            let rest = &SOURCE[close..];
            let end = next(&rest[1..]).map_or(rest.len(), |n| n + 1);
            found.push((&SOURCE[start..close], &rest[..end]));
            from = close;
        }
    }
    found
}

/// The type a parameter list gives `arg`, if it has one by that name.
fn arg_type<'a>(params: &'a str, arg: &str) -> Option<&'a str> {
    params.split(',').find_map(|param| {
        let (name, ty) = param.split_once(':')?;
        (name.trim() == arg).then(|| ty.trim())
    })
}

#[test]
fn every_key_and_plaintext_argument_is_owned_and_wiped() {
    let mut wrong = Vec::new();
    for (name, arg) in OWNED {
        // Every definition under the name that takes the argument (`new` is
        // also the test issuer's, which takes no such argument).
        let defs: Vec<_> = definitions(name)
            .into_iter()
            .filter_map(|(params, body)| arg_type(params, arg).map(|ty| (ty, body)))
            .collect();
        if defs.is_empty() {
            wrong.push(format!("{name}({arg}): no such function"));
        }
        for (ty, body) in defs {
            if !["Vec<u8>", "String", "Option<Vec<u8>>"].contains(&ty) {
                wrong.push(format!("{name}({arg}) is not taken by value"));
                continue;
            }
            let wrap = format!("let {arg} = Zeroizing::new({arg})");
            let Some(at) = body.find(&wrap) else {
                wrong.push(format!("{name}({arg}) is not wrapped to be wiped"));
                continue;
            };
            // Wrapped before anything can return: an early `?` or `return`
            // ahead of the wrap drops the argument unwiped.
            let before = &body[body.find('{').unwrap_or(0)..at];
            let code: String = before
                .lines()
                .map(|line| line.split("//").next().unwrap_or(""))
                .collect();
            if code.contains('?') || code.contains("return") {
                wrong.push(format!("{name}({arg}) can return before it is wrapped"));
            }
        }
    }
    assert!(wrong.is_empty(), "{wrong:#?}");
}

/// (type, field): what the binding returns inside an object that holds a
/// message's words or an envelope's inner bytes, wiped by the type's own
/// `Drop` once serde has copied it out to JavaScript.
const RETURNED: &[(&str, &str)] = &[("IncomingDto", "plaintext"), ("OpenedEnvelopeDto", "inner")];

#[test]
fn every_plaintext_returned_in_an_object_is_wiped() {
    let mut wrong = Vec::new();
    for (ty, field) in RETURNED {
        let needle = format!("impl Drop for {ty} {{");
        let Some(at) = SOURCE.find(&needle) else {
            wrong.push(format!("{ty} has no Drop"));
            continue;
        };
        let body = &SOURCE[at..];
        let body = &body[..body.find("\n}\n").unwrap_or(body.len())];
        if !body.contains(&format!("{field}.zeroize()")) {
            wrong.push(format!("{ty}'s Drop does not wipe {field}"));
        }
    }
    assert!(wrong.is_empty(), "{wrong:#?}");
}

/// The text secrets, taken as UTF-8 bytes and never as a `String`: the glue
/// copies a JS string into the module by growing its block at the first
/// non-ASCII character, a reallocation that can leave the string's start in
/// the block it frees, where a `Uint8Array` is copied once at its length.
const TEXT_AS_BYTES: &[(&str, &str)] = &[
    ("device_link_qr_matches", "scanned"),
    ("device_link_qr_secret", "scanned"),
    ("seal_call_signal", "signal_json"),
    ("seal_call_signal_signed", "signal_json"),
    ("encode_call_signal", "signal_json"),
    ("call_signal_is_urgent", "signal_json"),
];

#[test]
fn every_text_secret_is_taken_as_bytes() {
    let mut wrong = Vec::new();
    for (name, arg) in TEXT_AS_BYTES {
        let types: Vec<_> = definitions(name)
            .into_iter()
            .filter_map(|(params, _)| arg_type(params, arg))
            .collect();
        if types.is_empty() {
            wrong.push(format!("{name}({arg}): no such function"));
        }
        for ty in types {
            if ty != "Vec<u8>" {
                wrong.push(format!("{name}({arg}) is taken as {ty}"));
            }
        }
    }
    assert!(wrong.is_empty(), "{wrong:#?}");
}
