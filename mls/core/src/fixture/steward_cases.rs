// SPDX-License-Identifier: MIT
//! The `"steward"` kind: `mls/fixtures/steward.json`, the steward key's
//! statements, the veto frame, the commit MAC, the sealed stamp, the head
//! log copy and the repair notice ([`crate::steward`],
//! not part of this specification).

use serde_json::{json, Value};

use super::{hex_bytes, to_hex};
use crate::error::{Error, Result};
use crate::steward;

/// Evaluate one case of `mls/fixtures/steward.json`.
///
/// | `call` | needs | returns |
/// | --- | --- | --- |
/// | `constants` | — | the magic, labels, sizes, caps and `stewardWrites` |
/// | `public_key` | `seedHex` | `{"publicKeyHex"}` |
/// | `statement` | `statement` (`repair`, `veto`, `change`), `seedHex`, its fields | `{"statementHex","signatureHex"}` |
/// | `wrap_veto` | `seedHex`, `handleHex`, `epoch`, `vetoedNextHex`, `replacementNextHex`, `innerHex` | `{"accepted":true,"bytesHex"}` or `{"accepted":false}` |
/// | `split` | `bytesHex` | `{"accepted":true,"vetoHex","vetoedHex","proposalsHex","commitHex"}` or `{"accepted":false}` |
/// | `verify_veto` | `bytesHex`, `publicKeyHex` | `{"verified"}` |
/// | `mac` | `macKeyHex`, `nextVerifierHex`, `epoch`, `entryHex` | `{"macHex"}` |
/// | `seal_stamp` | `sendKeyHex`, `epoch`, `nextVerifierHex`, `stewardPubHex`, `macHex`, `nonceHex` | `{"stampHex"}` |
/// | `open_stamp` | `sendKeyHex`, `epoch`, `stampHex` | `{"accepted":true,"nextVerifierHex","stewardPubHex","macHex"}` or `{"accepted":false}` |
/// | `seal_log_copy` | `sendKeyHex`, `epoch`, `envelopeHex`, `nonceHex` | `{"copyHex"}` |
/// | `open_log_copy` | `sendKeyHex`, `epoch`, `copyHex` | `{"accepted":true,"envelopeHex"}` or `{"accepted":false}` |
/// | `repair_notice` | `wire`, `ownHex` (or null) | `{"parsed":true,"epoch","verdict"}` or `{"parsed":false}` |
/// | `meta_key` | `meta` | `{"keyHex"}` (null for none) |
pub(super) fn evaluate_steward_case(case_json: &str) -> Result<String> {
    let case: Value = serde_json::from_str(case_json)
        .map_err(|err| Error::invalid(format!("could not read the steward case: {err}")))?;
    let call = case
        .get("call")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::invalid("a steward case needs a `call`"))?;
    let bytes = |key: &str| -> Result<Vec<u8>> {
        let text = case
            .get(key)
            .and_then(Value::as_str)
            .ok_or_else(|| Error::invalid(format!("a `{call}` case needs a `{key}`")))?;
        hex_bytes(text, key)
    };
    let b32 = |key: &str| -> Result<[u8; 32]> {
        <[u8; 32]>::try_from(bytes(key)?.as_slice())
            .map_err(|_| Error::invalid(format!("`{key}` is 32 bytes")))
    };
    let opt32 = |key: &str| -> Result<Option<[u8; 32]>> {
        let raw = bytes(key)?;
        if raw.is_empty() {
            return Ok(None);
        }
        <[u8; 32]>::try_from(raw.as_slice())
            .map(Some)
            .map_err(|_| Error::invalid(format!("`{key}` is 32 bytes or empty")))
    };
    let nonce = || -> Result<[u8; 12]> {
        <[u8; 12]>::try_from(bytes("nonceHex")?.as_slice())
            .map_err(|_| Error::invalid("`nonceHex` is 12 bytes"))
    };
    let epoch = || -> Result<u64> {
        case.get("epoch")
            .and_then(Value::as_u64)
            .ok_or_else(|| Error::invalid(format!("a `{call}` case needs an `epoch`")))
    };
    let verdict = match call {
        "constants" => json!({
            "vetoMagicHex": to_hex(&steward::VETO_FRAME_MAGIC),
            "signedVetoBytes": steward::SIGNED_VETO_BYTES,
            "stampBytes": steward::STAMP_BYTES,
            "commitMacLabel": steward::COMMIT_MAC_LABEL,
            "stampInfo": steward::COMMIT_STAMP_INFO,
            "logInfo": steward::COMMIT_LOG_INFO,
            "repairDomain": steward::STEWARD_REPAIR_DOMAIN,
            "vetoDomain": steward::STEWARD_VETO_DOMAIN,
            "changeDomain": steward::STEWARD_CHANGE_DOMAIN,
            "holdCapSeconds": steward::HOLD_CAP_SECONDS,
            "stewardKeyKeptSeconds": steward::STEWARD_KEY_KEPT_SECONDS,
            "stewardWrites": steward::STEWARD_WRITES,
        }),
        "public_key" => json!({
            "publicKeyHex": to_hex(&steward::steward_public_key(&b32("seedHex")?)),
        }),
        "statement" => {
            let handle = b32("handleHex")?;
            let statement = match case.get("statement").and_then(Value::as_str) {
                Some("repair") => {
                    steward::repair_statement(&handle, epoch()?, &b32("sHex")?, &b32("vHex")?)
                }
                Some("veto") => steward::veto_statement(
                    &handle,
                    epoch()?,
                    &b32("vetoedNextHex")?,
                    &b32("digestHex")?,
                    &b32("replacementNextHex")?,
                ),
                Some("change") => {
                    steward::change_statement(&handle, epoch()?, &b32("oldHex")?, &b32("newHex")?)
                }
                other => {
                    return Err(Error::invalid(format!(
                        "unknown statement {other:?}; known: repair, veto, change"
                    )))
                }
            };
            let signature = steward::sign_statement(&b32("seedHex")?, &statement);
            json!({ "statementHex": to_hex(&statement), "signatureHex": to_hex(&signature) })
        }
        "wrap_veto" => {
            let inner = bytes("innerHex")?;
            let mut veto = steward::SignedVeto {
                handle: b32("handleHex")?,
                epoch: epoch()?,
                vetoed_next: b32("vetoedNextHex")?,
                replacement_next: b32("replacementNextHex")?,
                signature: [0u8; 64],
            };
            veto.signature = steward::sign_statement(&b32("seedHex")?, &veto.statement(&inner));
            match steward::wrap_veto(&veto, &inner) {
                Ok(framed) => json!({ "accepted": true, "bytesHex": to_hex(&framed) }),
                Err(_) => json!({ "accepted": false }),
            }
        }
        "split" => {
            let input = bytes("bytesHex")?;
            match crate::carried_commit::split_carried(&input) {
                Ok(split) => json!({
                    "accepted": true,
                    "vetoHex": split.veto.map(to_hex),
                    "vetoedHex": to_hex(split.vetoed),
                    "proposalsHex": split.proposals.iter().map(|p| to_hex(p)).collect::<Vec<_>>(),
                    "commitHex": to_hex(split.commit),
                }),
                Err(_) => json!({ "accepted": false }),
            }
        }
        "verify_veto" => {
            let input = bytes("bytesHex")?;
            let key = b32("publicKeyHex")?;
            let verified = crate::carried_commit::split_carried(&input)
                .ok()
                .and_then(|split| {
                    let veto = steward::SignedVeto::from_bytes(split.veto?).ok()?;
                    Some(veto.verify(&key, split.vetoed))
                })
                .unwrap_or(false);
            json!({ "verified": verified })
        }
        "mac" => json!({
            "macHex": to_hex(&steward::commit_mac(
                &bytes("macKeyHex")?,
                &b32("nextVerifierHex")?,
                epoch()?,
                &bytes("entryHex")?,
            )),
        }),
        "seal_stamp" => {
            let stamp = steward::Stamp {
                next_verifier: b32("nextVerifierHex")?,
                steward_pub: opt32("stewardPubHex")?,
                mac: opt32("macHex")?,
            };
            let sealed =
                steward::seal_stamp_with_nonce(&bytes("sendKeyHex")?, epoch()?, &stamp, &nonce()?)?;
            json!({ "stampHex": to_hex(&sealed) })
        }
        "open_stamp" => {
            match steward::open_stamp(&bytes("sendKeyHex")?, epoch()?, &bytes("stampHex")?) {
                Ok(stamp) => json!({
                    "accepted": true,
                    "nextVerifierHex": to_hex(&stamp.next_verifier),
                    "stewardPubHex": stamp.steward_pub.map(|k| to_hex(&k)),
                    "macHex": stamp.mac.map(|m| to_hex(&m)),
                }),
                Err(_) => json!({ "accepted": false }),
            }
        }
        "seal_log_copy" => {
            let sealed = steward::seal_log_copy_with_nonce(
                &bytes("sendKeyHex")?,
                epoch()?,
                &bytes("envelopeHex")?,
                &nonce()?,
            )?;
            json!({ "copyHex": to_hex(&sealed) })
        }
        "open_log_copy" => {
            match steward::open_log_copy(&bytes("sendKeyHex")?, epoch()?, &bytes("copyHex")?) {
                Ok(envelope) => json!({ "accepted": true, "envelopeHex": to_hex(&envelope) }),
                Err(_) => json!({ "accepted": false }),
            }
        }
        "repair_notice" => {
            let wire = case
                .get("wire")
                .and_then(Value::as_str)
                .ok_or_else(|| Error::invalid("a `repair_notice` case needs a `wire`"))?;
            let own = match case.get("ownHex") {
                Some(Value::String(_)) => Some(b32("ownHex")?),
                _ => None,
            };
            match steward::RepairNotice::parse(wire.as_bytes()) {
                Some(notice) => json!({
                    "parsed": true,
                    "epoch": notice.epoch,
                    "verdict": notice.judge(own.as_ref()) as u32,
                }),
                None => json!({ "parsed": false }),
            }
        }
        "meta_key" => {
            let meta = case
                .get("meta")
                .and_then(Value::as_str)
                .ok_or_else(|| Error::invalid("a `meta_key` case needs a `meta`"))?;
            json!({ "keyHex": steward::steward_key_of_meta(meta.as_bytes()).map(|k| to_hex(&k)) })
        }
        other => {
            return Err(Error::invalid(format!(
                "unknown steward call {other:?}; known: constants, public_key, statement, \
                 wrap_veto, split, verify_veto, mac, seal_stamp, open_stamp, seal_log_copy, \
                 open_log_copy, repair_notice, meta_key"
            )))
        }
    };
    Ok(verdict.to_string())
}
