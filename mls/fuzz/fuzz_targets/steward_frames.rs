// SPDX-License-Identifier: MIT
//! What a steward-enrolled group reads that the server or a member chooses:
//! the sealed stamp beside a commit (`open_stamp`), the head log's copy of a
//! commit (`open_log_copy`), a REPAIR NOTICE lane frame
//! (`RepairNotice::parse`), and the steward key and admins a group's meta
//! names (`steward_key_of_meta`, `meta_names_admin`,
//! `may_change_steward_key`). docs/mls-core.md §Fuzzing.
//!
//! The first input byte picks the reader (`mode % 4`), since no fuzzer forges
//! an AEAD tag:
//! - 0: `epoch (8, BE) ‖ sealed`, opened as a stamp and as a log copy under
//!   the fixed send key `mls/fixtures/steward.json` seals with;
//! - 1: `epoch (8, BE) ‖ kind (1) ‖ spec_len (1) ‖ spec ‖ body`: the target
//!   seals `body` (a log copy, or for `kind` bit 0 a stamp of its first 96
//!   bytes) under that key, then `common::mutate`s it by `spec`;
//! - 2: the rest is a repair notice's wire;
//! - 3: `actor_len (1) ‖ actor ‖ meta`: a group meta, and a prior one for the
//!   steward-key change rule.
//!
//! Asserted:
//! - No input panics.
//! - A sealed stamp or log copy opens only under its own epoch and key
//!   (never the other's key); unchanged, it opens to what was sealed; with
//!   any byte changed, it does not open.
//! - A repair notice parses canonically: written back with `to_wire`, it
//!   reads the same.

#![no_main]

mod common;

use libfuzzer_sys::fuzz_target;
use peachy_mls_core::steward::{
    may_change_steward_key, meta_names_admin, open_log_copy, open_stamp, seal_log_copy_with_nonce,
    seal_stamp_with_nonce, steward_key_of_meta, RepairNotice, Stamp,
};

/// `stamp-seal`'s send key in `mls/fixtures/steward.json`.
const SEND_KEY: [u8; 32] = [0x99; 32];
const NONCE: [u8; 12] = [7; 12];

fn epoch_of(bytes: &[u8]) -> Option<(u64, &[u8])> {
    let (epoch, rest) = bytes.split_first_chunk::<8>()?;
    Some((u64::from_be_bytes(*epoch), rest))
}

fn nonzero(bytes: &[u8]) -> Option<[u8; 32]> {
    let arr = <[u8; 32]>::try_from(bytes).ok()?;
    (arr != [0u8; 32]).then_some(arr)
}

fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };
    match mode % 4 {
        0 => {
            let Some((epoch, sealed)) = epoch_of(rest) else {
                return;
            };
            let _ = open_stamp(&SEND_KEY, epoch, sealed);
            let _ = open_log_copy(&SEND_KEY, epoch, sealed);
        }
        1 => {
            let Some((epoch, rest)) = epoch_of(rest) else {
                return;
            };
            let [kind, spec_len, rest @ ..] = rest else {
                return;
            };
            let Some((spec, body)) = rest.split_at_checked(usize::from(*spec_len)) else {
                return;
            };
            if kind & 1 == 1 {
                let Some(plain) = body.get(..96) else {
                    return;
                };
                let stamp = Stamp {
                    next_verifier: plain[..32].try_into().expect("32 bytes"),
                    steward_pub: nonzero(&plain[32..64]),
                    mac: nonzero(&plain[64..96]),
                };
                let sealed =
                    seal_stamp_with_nonce(&SEND_KEY, epoch, &stamp, &NONCE).expect("a stamp seals");
                assert!(open_stamp(&SEND_KEY, epoch.wrapping_add(1), &sealed).is_err());
                assert!(open_log_copy(&SEND_KEY, epoch, &sealed).is_err());
                let changed = common::mutate(&sealed, spec);
                let opened = open_stamp(&SEND_KEY, epoch, &changed);
                if changed == sealed {
                    assert_eq!(opened.expect("a stamp opens under its key"), stamp);
                } else {
                    assert!(opened.is_err(), "a changed stamp opened");
                }
            } else {
                let Ok(sealed) = seal_log_copy_with_nonce(&SEND_KEY, epoch, body, &NONCE) else {
                    return;
                };
                assert!(open_log_copy(&SEND_KEY, epoch.wrapping_add(1), &sealed).is_err());
                assert!(open_stamp(&SEND_KEY, epoch, &sealed).is_err());
                let changed = common::mutate(&sealed, spec);
                let opened = open_log_copy(&SEND_KEY, epoch, &changed);
                if changed == sealed {
                    assert_eq!(opened.expect("a log copy opens under its key"), body);
                } else {
                    assert!(opened.is_err(), "a changed log copy opened");
                }
            }
        }
        2 => {
            if let Some(notice) = RepairNotice::parse(rest) {
                assert_eq!(
                    RepairNotice::parse(notice.to_wire().as_bytes()).as_ref(),
                    Some(&notice),
                    "a repair notice did not read back the same"
                );
                let _ = notice.judge(Some(&notice.w));
                let _ = notice.judge(None);
            }
        }
        _ => {
            let Some((&len, rest)) = rest.split_first() else {
                return;
            };
            let Some((actor, meta)) = rest.split_at_checked(usize::from(len)) else {
                return;
            };
            let actor = String::from_utf8_lossy(actor);
            let _ = steward_key_of_meta(meta);
            let _ = meta_names_admin(meta, &actor);
            let _ = may_change_steward_key(Some(meta), &actor);
            let _ = may_change_steward_key(None, &actor);
        }
    }
});
