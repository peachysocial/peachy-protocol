// SPDX-License-Identifier: MIT
//! The `"device_seal"` kind: `mls/fixtures/device-seal.json`, the device seal
//! ([`crate::device_seal`]; not part of this specification).

use serde_json::{json, Value};

use super::{hex_bytes, to_hex};
use crate::device_seal;
use crate::error::{Error, Result};

/// Evaluate one case of `mls/fixtures/device-seal.json`.
///
/// | `call` | needs | returns |
/// | --- | --- | --- |
/// | `constants` | — | `{"version","bytes","bodyBytes","maxGroupIdBytes","senderDomain","bodyDomain","sends"}` |
/// | `seal` | `senderSeedHex`, `recipientKeyHex`, `groupIdHex`, `epochSecretHex`, `envelopeHex`, `ephemeralHex` | `{"sealHex"}` or `{"refused":true}` |
/// | `open` | `recipientSeedHex`, `sealHex`, `envelopeHex` | `{"opened":true,"senderKeyHex","groupIdHex","epochSecretHex"}` or `{"opened":false}` |
///
/// A refusal is an answer rather than an error, so every replay compares one
/// object; `sends` pins what every build SENDS, and changes in the release
/// that turns the writer on.
pub(super) fn evaluate_device_seal_case(case_json: &str) -> Result<String> {
    let case: Value = serde_json::from_str(case_json)
        .map_err(|err| Error::invalid(format!("could not read the device-seal case: {err}")))?;
    let call = case
        .get("call")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::invalid("a device-seal case needs a `call`"))?;
    let bytes = |key: &str| -> Result<Vec<u8>> {
        let text = case
            .get(key)
            .and_then(Value::as_str)
            .ok_or_else(|| Error::invalid(format!("a `{call}` case needs a `{key}`")))?;
        hex_bytes(text, key)
    };
    let verdict = match call {
        "constants" => json!({
            "version": device_seal::DEVICE_SEAL_VERSION,
            "bytes": device_seal::DEVICE_SEAL_BYTES,
            "bodyBytes": device_seal::DEVICE_SEAL_BODY_BYTES,
            "maxGroupIdBytes": device_seal::DEVICE_SEAL_MAX_GROUP_ID_BYTES,
            "senderDomain": device_seal::DEVICE_SEAL_SENDER_DOMAIN,
            "bodyDomain": device_seal::DEVICE_SEAL_BODY_DOMAIN,
            "sends": device_seal::DEVICE_SEAL_SENDS,
        }),
        "seal" => {
            match device_seal::device_seal_with_ephemeral(
                &bytes("senderSeedHex")?,
                &bytes("recipientKeyHex")?,
                &bytes("groupIdHex")?,
                &bytes("epochSecretHex")?,
                &bytes("envelopeHex")?,
                &bytes("ephemeralHex")?,
            ) {
                Ok(seal) => json!({ "sealHex": to_hex(&seal) }),
                Err(_) => json!({ "refused": true }),
            }
        }
        "open" => match device_seal::device_seal_open(
            &bytes("recipientSeedHex")?,
            &bytes("sealHex")?,
            &bytes("envelopeHex")?,
        ) {
            Ok(opened) => json!({
                "opened": true,
                "senderKeyHex": to_hex(&opened.sender_key),
                "groupIdHex": to_hex(&opened.group_id),
                "epochSecretHex": to_hex(&opened.epoch_secret[..]),
            }),
            Err(_) => json!({ "opened": false }),
        },
        other => {
            return Err(Error::invalid(format!(
                "unknown device-seal call {other:?}; known: constants, seal, open"
            )));
        }
    };
    Ok(verdict.to_string())
}
