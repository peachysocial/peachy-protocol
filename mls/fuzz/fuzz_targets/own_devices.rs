// SPDX-License-Identifier: MIT
//! What a device makes of its own account's devices as the server lists
//! them: `Client::check_own_device_approval` (a key package and the
//! approval the list gives it), `Client::check_own_device_key` and
//! `Client::own_device_standing` (a row's id and key), and the device-list
//! JSON doors `Client::note_own_install_links`,
//! `Client::note_restore_signed_out` and `Client::sign_install_revocations`.
//! docs/mls-core.md §Fuzzing.
//!
//! Each input runs on a fresh phone of Ada's, `device-ada`, whose chain is
//! itself alone. Her tablet, `device-ada-tablet`, published a key package
//! and holds the phone's real approval. The first input byte picks the door
//! (`mode % 6`), and its higher bits which of the inputs below are the real
//! ones; the rest is fields, each `len (1) ‖ bytes`, the last the remainder:
//! - 0: `key package ‖ approver ‖ signature`, through the seat check; a real
//!   field is the tablet's package or the phone's approval with the field's
//!   bytes as a `common::mutate` spec, or the approver `device-ada`;
//! - 1: `id ‖ key ‖ approver ‖ signature`, through the row check, and the
//!   seat check on the tablet's package when the row is the tablet's;
//! - 2: `actor ‖ id ‖ key`, through the standing, with the tablet approved
//!   first when a bit says so;
//! - 3, 4: a device list or a restore's answer, as JSON;
//! - 5: a revocation request, as JSON, signed with Ada's account key, with
//!   the tablet approved first when a bit says so.
//!
//! - No input panics.
//! - The seat check seats nothing but the tablet, and only on the real
//!   approval by a device on the chain; seating puts it on the chain.
//! - The row check reads only, agrees with the seat check on the tablet,
//!   and answers approved only for an approval that verifies.
//! - The standing is `ThisDevice` exactly for the phone itself, `NotOwn`
//!   exactly for another actor, and `OnChain` only for the approved tablet.
//! - Every JSON door reads only objects a JSON value holds, as every other
//!   reader of them does: never an array read field by field, nor a number
//!   no value holds (`1e400`), so each check below reads what the core read.
//! - A device list pins at most one link per row, and the same list again
//!   pins nothing; a restore's answer is kept once.
//! - A revocation is signed only for a row listed once, under the one key
//!   this phone can vouch for (the tablet's), never the phone's own, and
//!   never for a restore, since a fresh phone kept no restore's answer; each
//!   verifies under Ada's account identity key, and the key is never
//!   approved here again.

#![no_main]

mod common;

use std::cell::RefCell;

use common::{device, issuer};
use libfuzzer_sys::fuzz_target;
use peachy_mls_core::issuer::{device_key_pair, TestIssuer};
use peachy_mls_core::{
    account_identity_public_key, sign_device_approval, verify_device_approval,
    verify_device_revocation, Client, OwnDeviceStanding, OwnDeviceVerdict,
};

const ACTOR: &str = "actor-ada";
const PHONE: &str = "device-ada";
const TABLET: &str = "device-ada-tablet";

fn seed(n: u8) -> [u8; 32] {
    let mut seed = [0u8; 32];
    seed[0] = n;
    seed
}

struct Tablet {
    key_package: Vec<u8>,
    key: [u8; 32],
    approval: Vec<u8>,
}

fn tablet() -> Tablet {
    let tablet = device(&issuer(), 5, ACTOR, TABLET);
    let key = device_key_pair(&seed(5)).1;
    Tablet {
        key_package: tablet.generate_key_package().expect("a key package"),
        key,
        approval: sign_device_approval(&seed(1), TABLET, &key)
            .expect("the phone approves")
            .to_vec(),
    }
}

thread_local! {
    static TABLET_OF: RefCell<Tablet> = RefCell::new(tablet());
}

fn phone() -> Client {
    device(&issuer(), 1, ACTOR, PHONE)
}

/// `len (1) ‖ bytes`, or the remainder when it is the last.
fn fields(mut rest: &[u8], n: usize) -> Vec<&[u8]> {
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        if i + 1 == n {
            out.push(rest);
            break;
        }
        let Some((&len, tail)) = rest.split_first() else {
            out.push(&[]);
            continue;
        };
        let len = usize::from(len).min(tail.len());
        out.push(&tail[..len]);
        rest = &tail[len..];
    }
    out
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len() / 2)
        .filter_map(|i| u8::from_str_radix(text.get(i * 2..i * 2 + 2)?, 16).ok())
        .collect()
}

fn seat(phone: &mut Client, tablet: &Tablet, package: &[u8], approver: &str, signature: &[u8]) {
    let before = phone.own_device_anchors().expect("anchors");
    let verdict = phone.check_own_device_approval(package, approver, signature);
    if matches!(
        verdict,
        OwnDeviceVerdict::Known | OwnDeviceVerdict::Approved
    ) {
        let identity = phone
            .key_package_identity(package)
            .expect("a package that seats parses")
            .expect("and is certified");
        assert_eq!(
            (identity.device_id.as_str(), identity.device_key),
            (TABLET, tablet.key),
            "the seat check seated a device nobody approved"
        );
        if verdict == OwnDeviceVerdict::Approved {
            assert!(before.iter().any(|(id, key)| id == approver
                && verify_device_approval(key, TABLET, &tablet.key, signature)));
        } else {
            assert!(before
                .iter()
                .any(|(id, key)| id == TABLET && key.as_slice() == tablet.key));
        }
        assert_eq!(
            phone.check_own_device_key(TABLET, &tablet.key, "", &[]),
            OwnDeviceVerdict::Known,
            "a seated device is not on the chain"
        );
    }
    if package == tablet.key_package && approver == PHONE && signature == tablet.approval {
        assert_eq!(verdict, OwnDeviceVerdict::Approved);
    }
}

fn approve(phone: &mut Client, tablet: &Tablet) {
    assert_eq!(
        phone.check_own_device_approval(&tablet.key_package, PHONE, &tablet.approval),
        OwnDeviceVerdict::Approved
    );
}

fn signed_out(phone: &mut Client, json: &str, tablet: &Tablet) {
    let account = TestIssuer::test_account_key(ACTOR);
    let Ok(out) = phone.sign_install_revocations(&account, json) else {
        return;
    };
    // The core reads the request as a JSON value first and only from
    // objects, so what it signed for reads here alike.
    let request: serde_json::Value =
        serde_json::from_str(json).expect("the core signed for a request no JSON value holds");
    assert!(
        request.is_object(),
        "the core read a request that is not an object"
    );
    let rows = request["rows"].as_array().cloned().unwrap_or_default();
    assert!(
        rows.iter().all(serde_json::Value::is_object),
        "the core read a row that is not an object"
    );
    let identity = account_identity_public_key(&account).expect("an identity key");
    let phone_key = device_key_pair(&seed(1)).1;
    let out: Vec<serde_json::Value> = serde_json::from_str(&out).expect("an array");
    if !out.is_empty() {
        // A fresh phone kept no restore's answer, so a restore signs nothing.
        assert!(
            request["restoredSince"].as_i64().unwrap_or(0) <= 0,
            "a restore signed with no answer kept"
        );
    }
    for entry in out {
        let id = entry["deviceId"].as_str().expect("an id");
        let signature = unhex(entry["signature"].as_str().expect("a signature"));
        let under: Vec<&serde_json::Value> = rows.iter().filter(|row| row["id"] == id).collect();
        assert_eq!(under.len(), 1, "a revocation for an id listed twice");
        let key = unhex(under[0]["signingKey"].as_str().unwrap_or_default());
        assert_eq!(key.len(), 32);
        assert_ne!(key, phone_key, "the phone signed its own key out");
        assert!(verify_device_revocation(&identity, &key, &signature));
        // The tablet is the one device the phone can vouch for: approved
        // first, or by the phone's real approval on its row.
        assert!(
            id == TABLET && key == tablet.key,
            "a removal signed a key the phone does not vouch for"
        );
        assert!(
            phone.sign_own_device_approval(id, &key, 0).is_err(),
            "a key signed out is approved again"
        );
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };
    let real = mode / 6;
    TABLET_OF.with(|cell| {
        let tablet = &*cell.borrow();
        let mut phone = phone();
        match mode % 6 {
            0 => {
                let f = fields(rest, 3);
                let package = if real & 1 == 1 {
                    common::mutate(&tablet.key_package, f[0])
                } else {
                    f[0].to_vec()
                };
                let approver = if real & 2 == 2 {
                    PHONE.to_owned()
                } else {
                    text(f[1])
                };
                let signature = if real & 4 == 4 {
                    common::mutate(&tablet.approval, f[2])
                } else {
                    f[2].to_vec()
                };
                seat(&mut phone, tablet, &package, &approver, &signature);
            }
            1 => {
                let f = fields(rest, 4);
                let id = if real & 1 == 1 {
                    TABLET.to_owned()
                } else {
                    text(f[0])
                };
                let key = if real & 2 == 2 {
                    common::mutate(&tablet.key, f[1])
                } else {
                    f[1].to_vec()
                };
                let approver = if real & 4 == 4 {
                    PHONE.to_owned()
                } else {
                    text(f[2])
                };
                let signature = if real & 8 == 8 {
                    common::mutate(&tablet.approval, f[3])
                } else {
                    f[3].to_vec()
                };
                let before = phone.own_device_anchors().expect("anchors");
                let verdict = phone.check_own_device_key(&id, &key, &approver, &signature);
                assert_eq!(phone.own_device_anchors().expect("anchors"), before);
                assert_ne!(
                    verdict,
                    OwnDeviceVerdict::Known,
                    "a fresh phone knows nobody"
                );
                if verdict == OwnDeviceVerdict::Approved {
                    assert_eq!(approver, PHONE);
                    assert!(verify_device_approval(
                        &device_key_pair(&seed(1)).1,
                        &id,
                        &key,
                        &signature
                    ));
                }
                if id == TABLET && key == tablet.key {
                    assert_eq!(
                        phone.check_own_device_approval(&tablet.key_package, &approver, &signature),
                        verdict,
                        "the row check and the seat check disagree on the tablet"
                    );
                }
            }
            2 => {
                let f = fields(rest, 3);
                let approved = real & 1 == 1;
                if approved {
                    approve(&mut phone, tablet);
                }
                let actor = if real & 2 == 2 {
                    ACTOR.to_owned()
                } else {
                    text(f[0])
                };
                let id = if real & 4 == 4 {
                    TABLET.to_owned()
                } else {
                    text(f[1])
                };
                let key = if real & 8 == 8 {
                    common::mutate(&tablet.key, f[2])
                } else {
                    f[2].to_vec()
                };
                let phone_key = device_key_pair(&seed(1)).1;
                let standing = phone.own_device_standing(&actor, &id, &key);
                assert_eq!(standing == OwnDeviceStanding::NotOwn, actor != ACTOR);
                assert_eq!(
                    standing == OwnDeviceStanding::ThisDevice,
                    actor == ACTOR && id == PHONE && key == phone_key
                );
                assert_eq!(
                    standing == OwnDeviceStanding::OnChain,
                    approved && actor == ACTOR && id == TABLET && key == tablet.key
                );
                assert_ne!(standing, OwnDeviceStanding::Forgotten);
            }
            3 => {
                let json = text(rest);
                if let Ok(pinned) = phone.note_own_install_links(&json) {
                    // As for a request (`signed_out`): read alike here.
                    let rows: Vec<serde_json::Value> = serde_json::from_str(&json)
                        .expect("the core read a list no JSON value holds");
                    assert!(rows.iter().all(serde_json::Value::is_object));
                    assert!(pinned as usize <= rows.len());
                    assert_eq!(phone.note_own_install_links(&json).expect("again"), 0);
                }
            }
            4 => {
                let json = text(rest);
                if let Ok(kept) = phone.note_restore_signed_out(&json) {
                    // As for a request (`signed_out`): read alike here.
                    let answer: serde_json::Value = serde_json::from_str(&json)
                        .expect("the core read an answer no JSON value holds");
                    assert!(answer.is_object());
                    let keys = answer["keys"].as_array().map_or(0, Vec::len);
                    assert!(kept as usize <= keys);
                    assert_eq!(phone.note_restore_signed_out(&json).expect("again"), 0);
                }
            }
            _ => {
                if real & 1 == 1 {
                    approve(&mut phone, tablet);
                }
                signed_out(&mut phone, &text(rest), tablet);
            }
        }
    });
});
