// SPDX-License-Identifier: MIT
//! The `"carried_commit"` kind: `mls/fixtures/carried-commit.json`, the
//! commit that carries the leave proposals it names
//! ([`crate::carried_commit`], docs/delivery.md §The carried commit).

use serde_json::{json, Value};

use super::{hex_bytes, to_hex};
use crate::carried_commit;
use crate::error::{Error, Result};

/// Evaluate one case of `mls/fixtures/carried-commit.json`.
///
/// | `call` | needs | returns |
/// | --- | --- | --- |
/// | `constants` | — | `{"magicHex","maxProposals"}` |
/// | `carry` | `proposalsHex` (array), `commitHex` | `{"accepted":true,"bytesHex"}` or `{"accepted":false}` |
/// | `split` | `bytesHex` | `{"accepted":true,"proposalsHex","commitHex"}` or `{"accepted":false}` |
///
/// A refusal is `accepted: false` rather than an error, so every replay
/// compares one object.
pub(super) fn evaluate_carried_commit_case(case_json: &str) -> Result<String> {
    let case: Value = serde_json::from_str(case_json)
        .map_err(|err| Error::invalid(format!("could not read the carried-commit case: {err}")))?;
    let call = case
        .get("call")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::invalid("a carried-commit case needs a `call`"))?;
    let bytes = |key: &str| -> Result<Vec<u8>> {
        let text = case
            .get(key)
            .and_then(Value::as_str)
            .ok_or_else(|| Error::invalid(format!("a `{call}` case needs a `{key}`")))?;
        hex_bytes(text, key)
    };
    let verdict = match call {
        "constants" => json!({
            "magicHex": to_hex(&carried_commit::CARRIED_COMMIT_MAGIC),
            "maxProposals": carried_commit::MAX_CARRIED_PROPOSALS,
        }),
        "carry" => {
            let proposals = case
                .get("proposalsHex")
                .and_then(Value::as_array)
                .ok_or_else(|| Error::invalid("a `carry` case needs a `proposalsHex` array"))?
                .iter()
                .map(|p| {
                    p.as_str()
                        .ok_or_else(|| Error::invalid("each of `proposalsHex` is hex"))
                        .and_then(|text| hex_bytes(text, "`proposalsHex`"))
                })
                .collect::<Result<Vec<_>>>()?;
            match carried_commit::carry_proposals(&proposals, &bytes("commitHex")?) {
                Ok(carried) => json!({ "accepted": true, "bytesHex": to_hex(&carried) }),
                Err(_) => json!({ "accepted": false }),
            }
        }
        "split" => {
            let input = bytes("bytesHex")?;
            match carried_commit::split_carried(&input) {
                Ok(split) => json!({
                    "accepted": true,
                    "proposalsHex": split.proposals.iter().map(|p| to_hex(p)).collect::<Vec<_>>(),
                    "commitHex": to_hex(split.commit),
                }),
                Err(_) => json!({ "accepted": false }),
            }
        }
        other => {
            return Err(Error::invalid(format!(
                "unknown carried-commit call {other:?}; known: constants, carry, split"
            )))
        }
    };
    Ok(verdict.to_string())
}
