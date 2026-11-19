// SPDX-License-Identifier: MIT
//! The `"welcome_frame"` kind: `mls/fixtures/welcome-frame.json`, the padded
//! Welcome frame ([`crate::welcome_frame`], docs/delivery.md
//! §The padded Welcome frame).

use serde_json::{json, Value};

use super::{hex_bytes, to_hex};
use crate::error::{Error, Result};
use crate::welcome_frame;

/// Evaluate one case of `mls/fixtures/welcome-frame.json`.
///
/// | `call` | needs | returns |
/// | --- | --- | --- |
/// | `constants` | — | `{"magicHex","headerBytes","block","gapMagicHex","gapEpochs","gapBlockBytes"}` |
/// | `frame` | `welcomeHex`, `paddedLen`, optional `gapHex` | `{"framedHex"}`: version 2 with a gap block |
/// | `paddedLen` | `largestWelcome`, optional `withGap` | `{"paddedLen"}`: the frame for the largest candidate |
/// | `unframe` | `bytesHex` | `{"accepted":true,"welcomeHex"}` (and `"gapHex"` for version 2) or `{"accepted":false}` |
/// | `sealGap` | `keyHex`, `nonceHex`, `gap` (`[{"epoch","secretHex"}]`) | `{"blockHex"}` |
/// | `openGap` | `keyHex`, `blockHex` | `{"opened":true,"gap"}` or `{"opened":false}` |
///
/// `unframe` answers a refusal as `accepted: false` rather than an error, so
/// every replay compares one object.
pub(super) fn evaluate_welcome_frame_case(case_json: &str) -> Result<String> {
    let case: Value = serde_json::from_str(case_json)
        .map_err(|err| Error::invalid(format!("could not read the welcome-frame case: {err}")))?;
    let call = case
        .get("call")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::invalid("a welcome-frame case needs a `call`"))?;
    let text = |key: &str| -> Result<&str> {
        case.get(key)
            .and_then(Value::as_str)
            .ok_or_else(|| Error::invalid(format!("a `{call}` case needs a `{key}`")))
    };
    let number = |key: &str| -> Result<usize> {
        case.get(key)
            .and_then(Value::as_u64)
            .and_then(|n| usize::try_from(n).ok())
            .ok_or_else(|| Error::invalid(format!("a `{call}` case needs a `{key}`")))
    };
    let verdict = match call {
        "constants" => json!({
            "magicHex": to_hex(&welcome_frame::WELCOME_FRAME_MAGIC),
            "headerBytes": welcome_frame::WELCOME_FRAME_HEADER_BYTES,
            "block": welcome_frame::WELCOME_FRAME_BLOCK,
            "gapMagicHex": to_hex(&welcome_frame::WELCOME_FRAME_GAP_MAGIC),
            "gapEpochs": welcome_frame::WELCOME_GAP_EPOCHS,
            "gapBlockBytes": welcome_frame::WELCOME_GAP_BLOCK_BYTES,
        }),
        "frame" => {
            let welcome = hex_bytes(text("welcomeHex")?, "`welcomeHex`")?;
            let padded = number("paddedLen")?;
            let framed = match case.get("gapHex").and_then(Value::as_str) {
                Some(gap) => welcome_frame::frame_welcome_with_gap(
                    &welcome,
                    &hex_bytes(gap, "`gapHex`")?,
                    padded,
                )?,
                None => welcome_frame::frame_welcome(&welcome, padded)?,
            };
            json!({ "framedHex": to_hex(&framed) })
        }
        "paddedLen" => {
            let largest = number("largestWelcome")?;
            let with_gap = case
                .get("withGap")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            json!({
                "paddedLen": if with_gap {
                    welcome_frame::framed_len_with_gap(largest)
                } else {
                    welcome_frame::framed_len(largest)
                },
            })
        }
        "unframe" => {
            let bytes = hex_bytes(text("bytesHex")?, "`bytesHex`")?;
            match welcome_frame::unframe_welcome_parts(&bytes) {
                Ok(parts) => match parts.gap_block {
                    Some(gap) => json!({
                        "accepted": true,
                        "welcomeHex": to_hex(parts.welcome),
                        "gapHex": to_hex(gap),
                    }),
                    None => json!({ "accepted": true, "welcomeHex": to_hex(parts.welcome) }),
                },
                Err(_) => json!({ "accepted": false }),
            }
        }
        "sealGap" => {
            let key = hex_bytes(text("keyHex")?, "`keyHex`")?;
            let nonce = hex_bytes(text("nonceHex")?, "`nonceHex`")?;
            let entries = case
                .get("gap")
                .and_then(Value::as_array)
                .ok_or_else(|| Error::invalid("a `sealGap` case needs a `gap`"))?;
            let mut gap = Vec::with_capacity(entries.len());
            for entry in entries {
                let epoch = entry
                    .get("epoch")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| Error::invalid("a gap entry needs an `epoch`"))?;
                let secret = entry
                    .get("secretHex")
                    .and_then(Value::as_str)
                    .ok_or_else(|| Error::invalid("a gap entry needs a `secretHex`"))?;
                let secret = <[u8; 32]>::try_from(hex_bytes(secret, "`secretHex`")?.as_slice())
                    .map_err(|_| Error::invalid("a gap entry's secret is 32 bytes"))?;
                gap.push((epoch, secret));
            }
            let block = welcome_frame::seal_gap_block_with_nonce(&key, &gap, &nonce)?;
            json!({ "blockHex": to_hex(&block) })
        }
        "openGap" => {
            let key = hex_bytes(text("keyHex")?, "`keyHex`")?;
            let block = hex_bytes(text("blockHex")?, "`blockHex`")?;
            match welcome_frame::open_gap_block(&key, &block) {
                Ok(gap) => json!({
                    "opened": true,
                    "gap": gap
                        .iter()
                        .map(|(epoch, secret)| json!({ "epoch": epoch, "secretHex": to_hex(secret) }))
                        .collect::<Vec<_>>(),
                }),
                Err(_) => json!({ "opened": false }),
            }
        }
        other => {
            let known = "constants, frame, paddedLen, unframe, sealGap, openGap";
            return Err(Error::invalid(format!(
                "unknown welcome-frame call {other:?}; known: {known}"
            )));
        }
    };
    Ok(verdict.to_string())
}
