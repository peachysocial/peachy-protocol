// SPDX-License-Identifier: MIT
//! Sealed typing frames (docs/sealed-messages.md §Typing inside the
//! group): sealed, signed and stamped here, so the web, Apple and Android
//! clients share one rule.
//!
//! ## The frame
//!
//! ```text
//! plaintext = {"g":"<signature>","peachy":"typing","s":<ms>,"t":<bool>,"u":"<actor id>","v":1}
//! padded    = plaintext ‖ 0x00 …   (to a multiple of 128 bytes, at least 128)
//! key       = MLS-Exporter("peachy typing v1", context = group_id, length = 32)
//! frame     = nonce (12) ‖ AES-256-GCM(key, nonce, padded)   (no AAD)
//! ```
//!
//! The key is the epoch's exporter secret, not the application ratchet, for
//! the reasons the spec gives: a heartbeat must not spend a generation on
//! every receiver. A key every member derives authenticates the group and
//! nobody in it, so the frame carries two more things inside the AEAD:
//!
//! - **`g`, a signature by the sender's leaf key** (the Ed25519 key its
//!   credential binds and its MLS messages are signed with), standard base64
//!   of 64 bytes, over [`typing_statement`]: a domain, the group id, the
//!   epoch, and the frame as it reads without `g`. A receiver checks it
//!   against the leaves the group holds for the actor `u` names, and drops the
//!   frame unless one of them signed it. So a member can no longer show
//!   another member typing, and a frame cannot be carried into another group
//!   or epoch.
//! - **`s`, a stamp**: the sender's agreed clock in milliseconds, strictly
//!   increasing per device (`max(now, last + 1)`). A receiver keeps the
//!   stamps it took per (group, signing leaf) in the live call lane's replay
//!   window ([`crate::call::LiveReplayWindow`], `call/replay.rs`, its own
//!   record), and drops a frame more than two minutes from its agreed clock
//!   or with a stamp it already took. The server can record a frame but not
//!   write one, and a recording is refused while its stamp is remembered;
//!   the server sets the agreed clock, so once a stamp is forgotten it can
//!   move a device's clock back and have that frame opened again within its
//!   epoch (docs/calls.md §The live lane's replay window). There is
//!   no high-water mark, for the window's reason. The window is keyed by the
//!   leaf that signed, never the name a frame claims.
//!
//! A signed frame is 284 bytes (the plaintext pads to two blocks). Keys stay
//! alphabetical. A frame without `g` or without `s` is dropped.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine as _;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::de::{Deserializer, Error as _, MapAccess, SeqAccess, Visitor};
use serde::Deserialize;
use serde_json::{json, Map, Value};

use crate::call::{LiveReplayVerdict, CALL_ID_BYTES};
use crate::error::{Error, Result};
use crate::group::Client;

/// The frame's `peachy` tag.
pub const TYPING_KIND: &str = "typing";
/// The only `v` this build reads.
pub const TYPING_VERSION: u64 = 1;
/// The exporter label of the per-epoch typing key (context: the group id).
pub const TYPING_EXPORTER_LABEL: &str = "peachy typing v1";
/// The typing key's length.
pub const TYPING_KEY_BYTES: usize = 32;
/// The plaintext is NUL-padded to a multiple of this.
pub const TYPING_BLOCK: usize = 128;
/// The AEAD nonce, fresh per frame, carried in front.
pub const TYPING_NONCE_BYTES: usize = 12;
/// The domain of the statement a typing signature covers.
pub const TYPING_SIGNATURE_DOMAIN: &str = "peachy typing signature v1";
/// An Ed25519 signature.
pub const TYPING_SIGNATURE_BYTES: usize = 64;
/// The call id the typing window keeps every sender under: the window is its
/// own record, so this never meets a real call's id.
const TYPING_WINDOW_CALL_ID: [u8; CALL_ID_BYTES] = [0u8; CALL_ID_BYTES];

const AEAD_TAG_BYTES: usize = 16;

/// One typing frame's words.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypingFrame {
    /// `u`, the composer's actor id.
    pub actor_id: String,
    /// `t`: a heartbeat (true) or an explicit stop (false).
    pub typing: bool,
    /// `s`, the sender's stamp in milliseconds.
    pub stamp_ms: Option<u64>,
    /// `g`, the sender's leaf signature.
    pub signature: Option<[u8; TYPING_SIGNATURE_BYTES]>,
}

/// What a receiver takes from a frame it opened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenedTyping {
    /// The composer's actor id: the one its signing leaf holds.
    pub actor_id: String,
    pub typing: bool,
}

/// The frame's JSON, keys in alphabetical order, no whitespace: `g` only
/// with a signature, `s` only with a stamp.
pub fn encode_typing(frame: &TypingFrame) -> String {
    let mut out = String::from("{");
    if let Some(signature) = &frame.signature {
        out.push_str("\"g\":\"");
        out.push_str(&base64::engine::general_purpose::STANDARD.encode(signature));
        out.push_str("\",");
    }
    out.push_str("\"peachy\":\"typing\",");
    if let Some(stamp) = frame.stamp_ms {
        out.push_str(&format!("\"s\":{stamp},"));
    }
    out.push_str(if frame.typing {
        "\"t\":true,"
    } else {
        "\"t\":false,"
    });
    out.push_str("\"u\":");
    // A JSON string as serde writes it: an actor id is a UUID, but the rule
    // is the encoder's, so a signer and a verifier rebuild the same bytes.
    out.push_str(&Value::String(frame.actor_id.clone()).to_string());
    out.push_str(&format!(",\"v\":{TYPING_VERSION}}}"));
    out
}

/// Read a frame's JSON strictly, or `None`: not JSON, a duplicate key at any
/// depth, another `peachy` or `v`, an empty or non-string `u`, a non-boolean
/// `t`, an `s` that is not a whole number of milliseconds, a `g` that is not
/// base64 of 64 bytes, or one of `g` and `s` without the other. An unknown
/// key is ignored.
pub fn parse_typing(wire: &str) -> Option<TypingFrame> {
    serde_json::from_str::<NoDuplicateKeys>(wire).ok()?;
    let value: Value = serde_json::from_str(wire).ok()?;
    let map: &Map<String, Value> = value.as_object()?;
    if map.get("peachy")?.as_str()? != TYPING_KIND {
        return None;
    }
    let version = map.get("v")?;
    if version.as_u64() != Some(TYPING_VERSION) && version.as_f64() != Some(TYPING_VERSION as f64) {
        return None;
    }
    let actor_id = map.get("u")?.as_str()?;
    if actor_id.is_empty() {
        return None;
    }
    let typing = map.get("t")?.as_bool()?;
    let stamp_ms = match map.get("s") {
        None => None,
        Some(stamp) => Some(stamp.as_u64()?),
    };
    let signature = match map.get("g") {
        None => None,
        Some(g) => {
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(g.as_str()?)
                .ok()?;
            Some(<[u8; TYPING_SIGNATURE_BYTES]>::try_from(bytes.as_slice()).ok()?)
        }
    };
    if stamp_ms.is_some() != signature.is_some() {
        return None;
    }
    Some(TypingFrame {
        actor_id: actor_id.to_owned(),
        typing,
        stamp_ms,
        signature,
    })
}

/// What a typing signature covers: the domain, `0x00`, the group id (4-byte
/// big-endian length first), the epoch (8 bytes, big-endian), and the frame's
/// JSON as [`encode_typing`] writes it without `g`.
pub fn typing_statement(group_id: &[u8], epoch: u64, frame: &TypingFrame) -> Vec<u8> {
    let unsigned = encode_typing(&TypingFrame {
        signature: None,
        ..frame.clone()
    });
    let mut out =
        Vec::with_capacity(TYPING_SIGNATURE_DOMAIN.len() + 13 + group_id.len() + unsigned.len());
    out.extend_from_slice(TYPING_SIGNATURE_DOMAIN.as_bytes());
    out.push(0);
    out.extend_from_slice(&(group_id.len() as u32).to_be_bytes());
    out.extend_from_slice(group_id);
    out.extend_from_slice(&epoch.to_be_bytes());
    out.extend_from_slice(unsigned.as_bytes());
    out
}

/// Whether `public_key` (a leaf's 32-byte Ed25519 key) signed `frame` in
/// `group_id` at `epoch`. `verify_strict`, as every signature this crate
/// checks outside MLS.
pub fn typing_signature_holds(
    public_key: &[u8],
    group_id: &[u8],
    epoch: u64,
    frame: &TypingFrame,
) -> bool {
    let Some(signature) = frame.signature else {
        return false;
    };
    let Ok(key_bytes) = <[u8; 32]>::try_from(public_key) else {
        return false;
    };
    let Ok(key) = VerifyingKey::from_bytes(&key_bytes) else {
        return false;
    };
    key.verify_strict(
        &typing_statement(group_id, epoch, frame),
        &Signature::from_bytes(&signature),
    )
    .is_ok()
}

fn cipher(key: &[u8]) -> Result<Aes256Gcm> {
    if key.len() != TYPING_KEY_BYTES {
        return Err(Error::invalid("a typing key is 32 bytes"));
    }
    Aes256Gcm::new_from_slice(key).map_err(|_| Error::invalid("a typing key is 32 bytes"))
}

/// Seal a frame's JSON under `key` with `nonce`: NUL-padded to whole blocks,
/// nonce in front, no AAD. A text that ends in NUL is refused: the opener
/// strips trailing NULs as padding, so it would open as other bytes than
/// were sealed (no frame `encode_typing` writes ends in one).
pub fn seal_typing_wire(key: &[u8], nonce: &[u8], wire: &str) -> Result<Vec<u8>> {
    if nonce.len() != TYPING_NONCE_BYTES {
        return Err(Error::invalid("a typing nonce is 12 bytes"));
    }
    if wire.ends_with('\0') {
        return Err(Error::invalid(
            "a typing frame's text must not end in NUL, which pads it",
        ));
    }
    let blocks = wire.len().div_ceil(TYPING_BLOCK).max(1);
    // Not wiped: a typing frame carries no secret.
    let mut padded = wire.as_bytes().to_vec();
    padded.resize(blocks * TYPING_BLOCK, 0);
    let sealed = cipher(key)?
        .encrypt(Nonce::from_slice(nonce), padded.as_slice())
        .map_err(|_| Error::invalid("could not seal a typing frame"))?;
    let mut frame = Vec::with_capacity(TYPING_NONCE_BYTES + sealed.len());
    frame.extend_from_slice(nonce);
    frame.extend_from_slice(&sealed);
    Ok(frame)
}

/// Open a frame under `key` to its JSON, padding stripped, or `None` for one
/// that does not authenticate or is not UTF-8.
pub fn open_typing_wire(key: &[u8], frame: &[u8]) -> Option<String> {
    if frame.len() <= TYPING_NONCE_BYTES + AEAD_TAG_BYTES {
        return None;
    }
    let (nonce, body) = frame.split_at(TYPING_NONCE_BYTES);
    let padded = cipher(key)
        .ok()?
        .decrypt(Nonce::from_slice(nonce), body)
        .ok()?;
    let end = padded.iter().rposition(|b| *b != 0).map_or(0, |at| at + 1);
    String::from_utf8(padded[..end].to_vec()).ok()
}

impl Client {
    fn typing_key(&self, group_id: &[u8]) -> Result<zeroize::Zeroizing<Vec<u8>>> {
        self.export_secret(group_id, TYPING_EXPORTER_LABEL, group_id, TYPING_KEY_BYTES)
            .map(zeroize::Zeroizing::new)
    }

    /// Seal this device's typing frame for `group_id` at the current epoch:
    /// signed by its leaf, stamped, sealed under the epoch's typing key. The
    /// inner bytes of a kind-4 envelope ([`crate::envelope::ENVELOPE_KIND_TYPING`]).
    pub fn seal_typing(&mut self, group_id: &[u8], typing: bool) -> Result<Vec<u8>> {
        let key = self.typing_key(group_id)?;
        let epoch = self.epoch(group_id)?;
        let stamp_ms = self
            .now_unix_ms()
            .max(self.typing_last_sent_ms.saturating_add(1));
        let mut frame = TypingFrame {
            actor_id: self.identity().actor_id.clone(),
            typing,
            stamp_ms: Some(stamp_ms),
            signature: None,
        };
        let signature = self.sign_with_own_leaf(&typing_statement(group_id, epoch, &frame))?;
        frame.signature = Some(
            <[u8; TYPING_SIGNATURE_BYTES]>::try_from(signature.as_slice()).map_err(|_| {
                Error::Mls(format!(
                    "a typing signature came back {} bytes long",
                    signature.len()
                ))
            })?,
        );
        let mut nonce = [0u8; TYPING_NONCE_BYTES];
        getrandom::fill(&mut nonce)
            .map_err(|err| Error::invalid(format!("no randomness for a typing frame: {err}")))?;
        let sealed = seal_typing_wire(&key, &nonce, &encode_typing(&frame))?;
        self.typing_last_sent_ms = stamp_ms;
        Ok(sealed)
    }

    /// Open a typing frame for `group_id` under the current epoch's key, or
    /// `Ok(None)` for one to drop: it does not open (another epoch, not a
    /// member's), does not parse, is signed by no leaf of the actor it names,
    /// is refused by the replay window, or carries no signature or no stamp. `Err` only when the group cannot
    /// be read at all (not held, not a member).
    ///
    /// A device's own frames come back too, and open; the caller drops the
    /// ones naming its own person.
    pub fn open_typing(&mut self, group_id: &[u8], frame: &[u8]) -> Result<Option<OpenedTyping>> {
        let key = self.typing_key(group_id)?;
        let Some(wire) = open_typing_wire(&key, frame) else {
            return Ok(None);
        };
        let Some(parsed) = parse_typing(&wire) else {
            return Ok(None);
        };
        let (Some(stamp_ms), Some(_)) = (parsed.stamp_ms, parsed.signature) else {
            return Ok(None);
        };
        let epoch = self.epoch(group_id)?;
        let signer = self
            .leaf_keys_of_actor(group_id, &parsed.actor_id)?
            .into_iter()
            .find(|(_, key)| typing_signature_holds(key, group_id, epoch, &parsed))
            .map(|(leaf, _)| leaf);
        let Some(leaf) = signer else {
            return Ok(None);
        };
        // Last, so only a frame that is otherwise good is remembered.
        let now_ms = self.now_unix_ms();
        let mono_ms = self.now_monotonic_ms();
        let verdict = self.typing_replay.check(
            group_id,
            TYPING_WINDOW_CALL_ID,
            epoch,
            leaf,
            stamp_ms,
            now_ms,
            mono_ms,
        );
        if verdict != LiveReplayVerdict::Accepted {
            return Ok(None);
        }
        Ok(Some(OpenedTyping {
            actor_id: parsed.actor_id,
            typing: parsed.typing,
        }))
    }

    /// [`Self::open_typing`] as JSON: `{"actorId","typing"}`, or
    /// `null` for a frame to drop. The bindings' door.
    pub fn open_typing_json(&mut self, group_id: &[u8], frame: &[u8]) -> Result<String> {
        Ok(match self.open_typing(group_id, frame)? {
            Some(opened) => json!({
                "actorId": opened.actor_id,
                "typing": opened.typing,
            })
            .to_string(),
            None => "null".to_owned(),
        })
    }
}

/// A frame as the fixture spells it, `{"actorId","typing","stampMs"?,"signature"?}`
/// (signature in hex).
fn frame_from_json(value: &Value) -> Result<TypingFrame> {
    let field = |name: &str| {
        value
            .get(name)
            .ok_or_else(|| Error::invalid(format!("a typing frame needs `{name}`")))
    };
    let signature = match value.get("signature") {
        None | Some(Value::Null) => None,
        Some(hex) => {
            let bytes = crate::call::from_hex(
                hex.as_str()
                    .ok_or_else(|| Error::invalid("`signature` is hex"))?,
                "signature",
            )?;
            Some(
                <[u8; TYPING_SIGNATURE_BYTES]>::try_from(bytes.as_slice())
                    .map_err(|_| Error::invalid("a signature is 64 bytes"))?,
            )
        }
    };
    Ok(TypingFrame {
        actor_id: field("actorId")?
            .as_str()
            .ok_or_else(|| Error::invalid("`actorId` is a string"))?
            .to_owned(),
        typing: field("typing")?
            .as_bool()
            .ok_or_else(|| Error::invalid("`typing` is a boolean"))?,
        stamp_ms: match value.get("stampMs") {
            None | Some(Value::Null) => None,
            Some(stamp) => Some(
                stamp
                    .as_u64()
                    .ok_or_else(|| Error::invalid("`stampMs` is a whole number"))?,
            ),
        },
        signature,
    })
}

fn frame_to_json(frame: &TypingFrame) -> Value {
    let mut out = json!({ "actorId": frame.actor_id, "typing": frame.typing });
    if let Some(stamp) = frame.stamp_ms {
        out["stampMs"] = json!(stamp);
    }
    if let Some(signature) = &frame.signature {
        out["signature"] = json!(hex(signature));
    }
    out
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The fixture door for `kind: "typing"` (`mls/fixtures/formats/typing.json`):
///
/// - `encode` `{frame}` → `{"wire"}`
/// - `parse` `{wire}` → `{"frame": {…}|null}`
/// - `seal` `{key, nonce, wire}` (hex, hex, text) → `{"frame": hex}`
/// - `open` `{key, frame}` → `{"wire": text|null}`
/// - `sign` `{seed, groupId, epoch, frame}` (the leaf key's 32-byte seed in
///   hex, the group id as text) → `{"publicKey": hex, "statement": hex, "wire"}`:
///   the frame signed by that key
/// - `verify` `{publicKey, groupId, epoch, wire}` → `{"holds": bool}`
/// - `window` `{steps}` → `{"verdicts"}`, the live lane's window
///   (`crate::call::live_replay_steps_json`), which typing keeps its own
///   record of
/// - `constants` → the frame's constants
pub fn typing_case_json(call: &str, case: &Value) -> Result<Value> {
    let field = |name: &str| {
        case.get(name)
            .ok_or_else(|| Error::invalid(format!("a typing case needs `{name}`")))
    };
    let text = |name: &str| -> Result<String> {
        Ok(field(name)?
            .as_str()
            .ok_or_else(|| Error::invalid(format!("`{name}` is a string")))?
            .to_owned())
    };
    let bytes = |name: &str| -> Result<Vec<u8>> { crate::call::from_hex(&text(name)?, name) };
    Ok(match call {
        "encode" => json!({ "wire": encode_typing(&frame_from_json(field("frame")?)?) }),
        "parse" => json!({ "frame": parse_typing(&text("wire")?).map(|f| frame_to_json(&f)) }),
        "seal" => json!({ "frame": hex(&seal_typing_wire(&bytes("key")?, &bytes("nonce")?, &text("wire")?)?) }),
        "open" => json!({ "wire": open_typing_wire(&bytes("key")?, &bytes("frame")?) }),
        "sign" => {
            use ed25519_dalek::{Signer as _, SigningKey};
            let seed = <[u8; 32]>::try_from(bytes("seed")?.as_slice())
                .map_err(|_| Error::invalid("a seed is 32 bytes"))?;
            let key = SigningKey::from_bytes(&seed);
            let group_id = text("groupId")?;
            let epoch = field("epoch")?
                .as_u64()
                .ok_or_else(|| Error::invalid("`epoch` is a whole number"))?;
            let mut frame = frame_from_json(field("frame")?)?;
            frame.signature = None;
            let statement = typing_statement(group_id.as_bytes(), epoch, &frame);
            frame.signature = Some(key.sign(&statement).to_bytes());
            json!({
                "publicKey": hex(key.verifying_key().as_bytes()),
                "statement": hex(&statement),
                "wire": encode_typing(&frame),
            })
        }
        "verify" => {
            let group_id = text("groupId")?;
            let epoch = field("epoch")?
                .as_u64()
                .ok_or_else(|| Error::invalid("`epoch` is a whole number"))?;
            let holds = parse_typing(&text("wire")?).is_some_and(|frame| {
                bytes("publicKey").is_ok_and(|key| {
                    typing_signature_holds(&key, group_id.as_bytes(), epoch, &frame)
                })
            });
            json!({ "holds": holds })
        }
        "window" => crate::call::live_replay_steps_json(field("steps")?)?,
        "constants" => json!({
            "label": TYPING_EXPORTER_LABEL,
            "block": TYPING_BLOCK,
            "nonceBytes": TYPING_NONCE_BYTES,
            "signatureDomain": TYPING_SIGNATURE_DOMAIN,
            "maxSkewMs": crate::call::CALL_LIVE_MAX_SKEW_MS,
        }),
        other => {
            return Err(Error::invalid(format!(
                "unknown typing call {other:?}; known: encode, parse, seal, open, sign, verify, window, constants"
            )))
        }
    })
}

/// A JSON value walked only to refuse a duplicate key in any object (strict
/// JSON, as every client reads a typing frame).
struct NoDuplicateKeys;

impl<'de> Deserialize<'de> for NoDuplicateKeys {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        deserializer.deserialize_any(NoDuplicateKeysVisitor)
    }
}

struct NoDuplicateKeysVisitor;

impl<'de> Visitor<'de> for NoDuplicateKeysVisitor {
    type Value = NoDuplicateKeys;

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("a JSON value with no duplicate key")
    }

    fn visit_bool<E>(self, _: bool) -> std::result::Result<Self::Value, E> {
        Ok(NoDuplicateKeys)
    }

    fn visit_i64<E>(self, _: i64) -> std::result::Result<Self::Value, E> {
        Ok(NoDuplicateKeys)
    }

    fn visit_u64<E>(self, _: u64) -> std::result::Result<Self::Value, E> {
        Ok(NoDuplicateKeys)
    }

    fn visit_f64<E>(self, _: f64) -> std::result::Result<Self::Value, E> {
        Ok(NoDuplicateKeys)
    }

    fn visit_str<E>(self, _: &str) -> std::result::Result<Self::Value, E> {
        Ok(NoDuplicateKeys)
    }

    fn visit_unit<E>(self) -> std::result::Result<Self::Value, E> {
        Ok(NoDuplicateKeys)
    }

    fn visit_seq<A: SeqAccess<'de>>(
        self,
        mut seq: A,
    ) -> std::result::Result<Self::Value, A::Error> {
        while seq.next_element::<NoDuplicateKeys>()?.is_some() {}
        Ok(NoDuplicateKeys)
    }

    fn visit_map<A: MapAccess<'de>>(
        self,
        mut map: A,
    ) -> std::result::Result<Self::Value, A::Error> {
        let mut seen = std::collections::BTreeSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !seen.insert(key) {
                return Err(A::Error::custom("a duplicate key"));
            }
            map.next_value::<NoDuplicateKeys>()?;
        }
        Ok(NoDuplicateKeys)
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    fn frame(signed: bool) -> TypingFrame {
        TypingFrame {
            actor_id: "11111111-1111-1111-1111-111111111111".into(),
            typing: true,
            stamp_ms: signed.then_some(1_789_516_800_000),
            signature: signed.then_some([7u8; 64]),
        }
    }

    #[test]
    fn the_keys_are_alphabetical_and_the_frame_round_trips() {
        let wire = encode_typing(&frame(true));
        assert!(wire.starts_with("{\"g\":\""));
        assert!(wire.ends_with(
            "\"peachy\":\"typing\",\"s\":1789516800000,\"t\":true,\"u\":\"11111111-1111-1111-1111-111111111111\",\"v\":1}"
        ));
        assert_eq!(parse_typing(&wire), Some(frame(true)));
        assert_eq!(
            encode_typing(&frame(false)),
            "{\"peachy\":\"typing\",\"t\":true,\"u\":\"11111111-1111-1111-1111-111111111111\",\"v\":1}"
        );
    }

    #[test]
    fn a_signed_frame_is_two_blocks_whatever_it_says() {
        let key = [1u8; 32];
        let nonce = [2u8; 12];
        let start = seal_typing_wire(&key, &nonce, &encode_typing(&frame(true))).expect("seals");
        let mut stop = frame(true);
        stop.typing = false;
        let stop = seal_typing_wire(&key, &nonce, &encode_typing(&stop)).expect("seals");
        assert_eq!(start.len(), 12 + 2 * TYPING_BLOCK + 16);
        assert_eq!(start.len(), stop.len());
        assert_eq!(
            open_typing_wire(&key, &start).as_deref(),
            Some(encode_typing(&frame(true)).as_str())
        );
        assert_eq!(open_typing_wire(&[3u8; 32], &start), None);
    }

    #[test]
    fn a_stamp_and_a_signature_come_together_or_not_at_all() {
        let mut half = frame(true);
        half.signature = None;
        assert_eq!(parse_typing(&encode_typing(&half)), None);
        let mut other = frame(true);
        other.stamp_ms = None;
        assert_eq!(parse_typing(&encode_typing(&other)), None);
    }
}
