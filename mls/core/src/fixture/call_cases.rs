// SPDX-License-Identifier: MIT
//! The `"call"` kind: `mls/fixtures/calls.json` (docs/calls.md §Keys,
//! §Signaling, §Ringing).

use serde_json::{json, Value};

use super::{hex_bytes, to_hex};
use crate::call;
use crate::error::{Error, Result};

/// Evaluate one case of `mls/fixtures/calls.json`.
///
/// | `call` | needs | returns |
/// | --- | --- | --- |
/// | `constants` | — | every constant four clients must agree on |
/// | `senderKey` | `callRootHex`, `leafIndex`, `epoch` | `{"senderKeyHex","keyIndex","frameKeyHex"}` |
/// | `encode` | `signal` (JSON form) | `{"bytesHex"}` |
/// | `decode` | `bytesHex` | `{"signal"}` |
/// | `sealLive` | `liveKeyHex`, `nonceHex`, `senderLeaf`, `sentAtMs`, `signal` | `{"innerHex"}` |
/// | `openLive` | `liveKeyHex`, `innerHex` | `{"senderLeaf","sentAtMs","signal"}` |
/// | `liveReplay` | `steps` (`{"callId"?,"epoch","leaf","sentAtMs","nowMs"}`…) | `{"verdicts"}` — one fresh window |
/// | `envelope` | `groupId`, `innerHex`, `nonceHex` | `{"envelopeHex","kind","innerHex"}` — sealed, then opened again |
/// | `ring` | `state` (or `null`), `event` | `{"state","effects"}` |
/// | `selfUpdateOffset` | `rank`, `participants` | `{"offsetMs"}` |
/// | `senderKeyV2` | `callRootHex`, `mediaSecretHex`, `leafIndex`, `epoch`, `generation` | `{"senderKeyHex","keyIndex","frameKeyHex"}` |
/// | `mediaAdvance` | `secretHex`, `steps` | `{"secretHex"}` — advanced `steps` times |
/// | `mediaKeyPair` | `ikmHex` | `{"publicKeyHex"}` |
/// | `openMediaGrant` | `ikmHex` (the recipient's key pair), `callIdHex`, `senderLeaf`, `toLeaf`, `encHex`, `ciphertextHex` | `{"generation","secretHex","sessionId","trackNames"}` |
///
/// A refusal is an `Err`, which each replay compares with the case's
/// `expectError`.
pub(super) fn evaluate_call_case(case_json: &str) -> Result<String> {
    let case: Value = serde_json::from_str(case_json)
        .map_err(|err| Error::invalid(format!("could not read the call case: {err}")))?;
    let name = case
        .get("call")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::invalid("a call case needs a `call`"))?
        .to_string();
    let field = |key: &str| -> Result<&Value> {
        case.get(key)
            .ok_or_else(|| Error::invalid(format!("a `{name}` case needs a `{key}`")))
    };
    let text = |key: &str| -> Result<String> {
        field(key)?
            .as_str()
            .map(str::to_string)
            .ok_or_else(|| Error::invalid(format!("`{key}` is a string")))
    };
    let bytes = |key: &str| -> Result<Vec<u8>> { hex_bytes(&text(key)?, key) };
    let signal = |key: &str| -> Result<call::CallSignal> {
        let parsed: call::CallSignalJson = serde_json::from_value(field(key)?.clone())
            .map_err(|err| Error::invalid(format!("could not read the call signal: {err}")))?;
        call::CallSignal::try_from(&parsed)
    };
    let u32_field = |key: &str| -> Result<u32> {
        field(key)?
            .as_u64()
            .and_then(|v| u32::try_from(v).ok())
            .ok_or_else(|| Error::invalid(format!("`{key}` is a u32")))
    };
    let signal_json = |signal: &call::CallSignal| -> Result<Value> {
        serde_json::to_value(call::CallSignalJson::from(signal))
            .map_err(|err| Error::invalid(format!("could not write the call signal: {err}")))
    };

    let verdict = match name.as_str() {
        "constants" => json!({
            "exporterLabel": call::CALL_EXPORTER_LABEL,
            "callRootBytes": call::CALL_ROOT_BYTES,
            "callIdBytes": call::CALL_ID_BYTES,
            "senderInfo": String::from_utf8_lossy(call::CALL_SENDER_INFO),
            "senderKeyBytes": call::CALL_SENDER_KEY_BYTES,
            "frameRatchetSalt": call::CALL_FRAME_RATCHET_SALT,
            "frameKeyInfoBytes": call::CALL_FRAME_KEY_INFO_BYTES,
            "frameKeyBytes": call::CALL_FRAME_KEY_BYTES,
            "keyRingSize": call::CALL_KEY_RING_SIZE,
            "keyGraceMs": call::CALL_KEY_GRACE_MS,
            "liveExporterLabel": call::CALL_LIVE_EXPORTER_LABEL,
            "liveKeyBytes": call::CALL_LIVE_KEY_BYTES,
            "livePaddingBlock": call::CALL_LIVE_PADDING_BLOCK,
            "liveMaxSkewMs": call::CALL_LIVE_MAX_SKEW_MS,
            "liveMaxSenders": call::CALL_LIVE_MAX_SENDERS,
            "laneMls": call::CALL_LANE_MLS,
            "laneLive": call::CALL_LANE_LIVE,
            "envelopeKind": crate::envelope::ENVELOPE_KIND_CALL,
            "signalVersion": call::CALL_SIGNAL_VERSION,
            "maxSignalBytes": call::MAX_CALL_SIGNAL_BYTES,
            "maxSdpBytes": call::MAX_CALL_SDP_BYTES,
            "ringCap": call::CALL_RING_CAP,
            "ringTimeoutMs": call::CALL_RING_TIMEOUT_MS,
            "offerMaxAgeMs": call::CALL_OFFER_MAX_AGE_MS,
            "offerMaxSkewMs": call::CALL_OFFER_MAX_SKEW_MS,
            "selfUpdateIntervalMs": call::CALL_SELF_UPDATE_INTERVAL_MS,
            "exporterLabelV2": call::CALL_EXPORTER_LABEL_V2,
            "senderInfoV2": String::from_utf8_lossy(call::CALL_SENDER_INFO_V2),
            "mediaSecretBytes": call::CALL_MEDIA_SEED_BYTES,
            "mediaAdvanceInfo": String::from_utf8_lossy(call::CALL_MEDIA_ADVANCE_INFO),
            "mediaKeyInfo": String::from_utf8_lossy(call::CALL_MEDIA_KEY_INFO),
            "mediaPublicKeyBytes": call::CALL_MEDIA_PUBLIC_KEY_BYTES,
            "mediaMaxGrants": call::MAX_CALL_MEDIA_GRANTS,
            "mediaMaxAdvance": call::CALL_MEDIA_MAX_ADVANCE,
            "mediaRotateDelayMs": call::CALL_MEDIA_ROTATE_DELAY_MS,
        }),
        "senderKeyV2" => {
            let leaf = u32_field("leafIndex")?;
            let generation = u32_field("generation")?;
            let epoch = field("epoch")?
                .as_u64()
                .ok_or_else(|| Error::invalid("`epoch` is a u64"))?;
            let sender =
                call::call_sender_key_v2(&bytes("callRootHex")?, &bytes("mediaSecretHex")?, leaf)?;
            json!({
                "senderKeyHex": to_hex(&sender),
                "keyIndex": call::call_key_index_v2(epoch, generation),
                "frameKeyHex": to_hex(&call::call_frame_key(&sender)?),
            })
        }
        "mediaAdvance" => {
            let mut secret = bytes("secretHex")?;
            for _ in 0..u32_field("steps")? {
                secret = call::call_media_advance(&secret)?.to_vec();
            }
            json!({ "secretHex": to_hex(&secret) })
        }
        "mediaKeyPair" => {
            let (_, public) = call::call_media_key_pair(&bytes("ikmHex")?)?;
            json!({ "publicKeyHex": to_hex(&public) })
        }
        "openMediaGrant" => {
            let (private, _) = call::call_media_key_pair(&bytes("ikmHex")?)?;
            let payload = call::open_call_media_grant(
                &private,
                &bytes("callIdHex")?,
                u32_field("senderLeaf")?,
                u32_field("toLeaf")?,
                &bytes("encHex")?,
                &bytes("ciphertextHex")?,
            )?;
            json!({
                "generation": payload.generation,
                "secretHex": to_hex(&payload.secret[..]),
                "sessionId": payload.session_id,
                "trackNames": payload.track_names,
            })
        }
        "selfUpdateOffset" => {
            let number = |key: &str| -> Result<u32> {
                field(key)?
                    .as_u64()
                    .and_then(|v| u32::try_from(v).ok())
                    .ok_or_else(|| Error::invalid(format!("`{key}` is a u32")))
            };
            json!({ "offsetMs": call::call_self_update_offset_ms(number("rank")?, number("participants")?) })
        }
        "senderKey" => {
            let root = bytes("callRootHex")?;
            let leaf = field("leafIndex")?
                .as_u64()
                .and_then(|v| u32::try_from(v).ok())
                .ok_or_else(|| Error::invalid("`leafIndex` is a u32"))?;
            let epoch = field("epoch")?
                .as_u64()
                .ok_or_else(|| Error::invalid("`epoch` is a u64"))?;
            let sender = call::call_sender_key(&root, leaf)?;
            json!({
                "senderKeyHex": to_hex(&sender),
                "keyIndex": call::call_key_index(epoch),
                "frameKeyHex": to_hex(&call::call_frame_key(&sender)?),
            })
        }
        "encode" => json!({ "bytesHex": to_hex(&call::encode_call_signal(&signal("signal")?)?) }),
        "decode" => {
            json!({ "signal": signal_json(&call::decode_call_signal(&bytes("bytesHex")?)?)? })
        }
        "sealLive" => {
            let encoded = call::encode_call_signal(&signal("signal")?)?;
            let stamp = call::LiveStamp {
                sender_leaf: field("senderLeaf")?
                    .as_u64()
                    .and_then(|v| u32::try_from(v).ok())
                    .ok_or_else(|| Error::invalid("`senderLeaf` is a u32"))?,
                sent_at_ms: field("sentAtMs")?
                    .as_u64()
                    .ok_or_else(|| Error::invalid("`sentAtMs` is a u64"))?,
            };
            let inner = call::seal_live_frame_with_nonce(
                &bytes("liveKeyHex")?,
                stamp,
                &encoded,
                &bytes("nonceHex")?,
            )?;
            json!({ "innerHex": to_hex(&inner) })
        }
        "liveReplay" => call::live_replay_steps_json(field("steps")?)?,
        "openLive" => {
            let (stamp, plaintext) =
                call::open_live_frame(&bytes("liveKeyHex")?, &bytes("innerHex")?)?;
            let decoded = call::decode_call_signal(&plaintext)?;
            if decoded.body.is_mls_lane() {
                return Err(Error::invalid(
                    "that call signal must come on the MLS lane, signed by its sender",
                ));
            }
            json!({
                "senderLeaf": stamp.sender_leaf,
                "sentAtMs": stamp.sent_at_ms,
                "signal": signal_json(&decoded)?,
            })
        }
        "envelope" => {
            let group_id = text("groupId")?;
            let sealed = crate::envelope::seal_envelope_with_nonce(
                group_id.as_bytes(),
                crate::envelope::ENVELOPE_KIND_CALL,
                &bytes("innerHex")?,
                &bytes("nonceHex")?,
            )?;
            let opened = crate::envelope::open_envelope_for(group_id.as_bytes(), &sealed)?;
            json!({
                "envelopeHex": to_hex(&sealed),
                "kind": opened.kind,
                "innerHex": to_hex(&opened.inner),
            })
        }
        "ring" => {
            let state = field("state")?.to_string();
            let event = field("event")?.to_string();
            serde_json::from_str(&call::ring_step_json(&state, &event)?)
                .map_err(|err| Error::invalid(format!("could not read the ring step: {err}")))?
        }
        other => {
            return Err(Error::invalid(format!(
                "unknown call {other:?}; known: constants, senderKey, encode, decode, sealLive, \
                 openLive, liveReplay, envelope, ring, selfUpdateOffset, senderKeyV2, \
                 mediaAdvance, mediaKeyPair, openMediaGrant"
            )))
        }
    };
    serde_json::to_string(&verdict)
        .map_err(|err| Error::invalid(format!("could not write the verdict: {err}")))
}
