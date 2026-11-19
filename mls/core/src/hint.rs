// SPDX-License-Identifier: MIT
//! WHAT A RECEIVER SHOULD DO WITH A MESSAGE IT CANNOT OPEN
//! (docs/sealed-messages.md §Content hints).
//!
//! Every application message a Peachy device seals, except a call signal,
//! says, in its MLS `authenticated_data`, how its loss should be handled — the
//! CONTENT HINT. A call signal on the MLS lane carries
//! `crate::call::CALL_LANE_AAD` instead, bytes that read as no hint and are
//! there only so that its length matches a hinted message's:
//!
//! - [`CONTENT_HINT_DEFAULT`]: show the loss at once ("a message couldn't be
//!   delivered"), and ask for nothing. A call record: a resend would arrive
//!   too late to ring.
//! - [`CONTENT_HINT_RESENDABLE`]: hold a hidden placeholder, ask the sender's
//!   device for it again, and show the loss only if no answer comes in time.
//!   Transcript messages.
//! - [`CONTENT_HINT_RESENDABLE_LANE`]: the same, for a lane frame a person
//!   sent: a reaction, a delete or an edit. Only an answer that is a lane
//!   frame fills its place, and only a transcript answer fills a transcript
//!   message's, so no member can answer one kind with the other.
//! - [`CONTENT_HINT_IMPLICIT`]: count it and show nothing. Read marks, resend
//!   asks and answers, history shares: their loss is invisible or repaired by
//!   the next one.
//!
//! WHY THE AAD. The hint has to be readable when nothing else is — the whole
//! point is a message whose ratchet will not open — and `authenticated_data` is
//! the one part of a `PrivateMessage` that is not under the ratchet's key. It
//! is not hidden from whoever holds the bytes, which is why it is not on the
//! delivery service's wire either: every mailbox envelope is wrapped first
//! (`crate::envelope`), a message under its epoch's envelope key, so the
//! server sees neither the hint nor the AAD it rides in. It IS authenticated: once the message opens,
//! a member who forged the hint is caught by the message's own signature.
//!
//! THE FORMAT: three bytes, `0x70 0x01 hint`. The first two are a tag and a
//! version so a later format, or AAD some other feature adds, cannot be read
//! as a hint by accident; anything that does not start with them is "no
//! hint", and the receiver drops the loss uncounted as a person's.
//!
//! THE AUTHOR'S COMMITMENT. Since the format's second release the three
//! bytes are followed by sixteen more, [`RESEND_COMMITMENT_BYTES`]: on a
//! resendable message, a commitment to the person who wrote it, and zeros on
//! everything else ([`hint_aad_with_commitment`]). A device that cannot open
//! a message cannot read its sender either: MLS encrypts the sender with the
//! content. So without this, the answer to its resend ask was filed under
//! whoever answered first, and any member could fill the seat of a message it
//! did not write. The commitment is
//!
//! ```text
//! SHA-256("peachy resend author v1" ‖ len ‖ group_id ‖ len ‖ actor_id ‖ len ‖ secret)[..16]
//! ```
//!
//! (each `len` a 4-byte big-endian length), where the secret is something
//! only the message's readers know and its answer carries: a transcript
//! frame's own id `i` (a random UUID, lowercased), or a lane frame's whole
//! text when it carries a 16-byte salt `z` ([`resend_secret_of`]). A
//! receiver keeps the commitment of a message it could not open, and takes an
//! answer only from the MLS sender it commits to
//! ([`resend_author_commitment`]). A member cannot make an answer that
//! matches: MLS authenticates the answer's sender, and the commitment names
//! the author. Whoever holds the bytes but not the secret (the server, which
//! never sees them unwrapped; a removed member who kept the group id) learns
//! nothing from sixteen bytes over a random value. A message with no secret
//! carries zeros, which commit to nobody.
//!
//! A reader takes an answer for a message it could not open only from the
//! MLS sender the message's commitment names; a message that carried none is
//! never answered. Zeros go on every other message too (and the call lane's AAD is as long,
//! [`crate::call::CALL_LANE_AAD`]), so the AAD's length still says nothing
//! about what a message is.
//!
//! THE ONE PUBLIC BIT. A send is `urgent` (the push bit, the one thing the
//! server is told about what an envelope carries) exactly when its hint is
//! [`CONTENT_HINT_RESENDABLE`] or [`CONTENT_HINT_RESENDABLE_LANE`]: see
//! [`hint_is_urgent`].

use openmls::prelude::{MlsMessageIn, ProtocolMessage};
use sha2::{Digest, Sha256};
use tls_codec::Deserialize as _;

/// Show the loss at once; ask for nothing.
pub const CONTENT_HINT_DEFAULT: u8 = 0;
/// Hide the loss, ask for the message again, show it only if no answer comes.
pub const CONTENT_HINT_RESENDABLE: u8 = 1;
/// Count the loss and show nothing.
pub const CONTENT_HINT_IMPLICIT: u8 = 2;
/// [`CONTENT_HINT_RESENDABLE`], for a lane frame: a reaction, a delete or an
/// edit.
pub const CONTENT_HINT_RESENDABLE_LANE: u8 = 3;

/// Whether a send carrying `hint` is `urgent` on the wire: a message, a
/// reaction, an edit or a delete, which may change what a person sees; and not
/// a read or delivery mark, a resend ask or answer, a history share, a
/// group-link event or a call record, which a device sends on its own. The
/// push needs this one bit. It is derived from the hint so that no client can
/// split it any finer than this.
pub fn hint_is_urgent(hint: u8) -> bool {
    matches!(hint, CONTENT_HINT_RESENDABLE | CONTENT_HINT_RESENDABLE_LANE)
}

const HINT_TAG: u8 = 0x70;
const HINT_VERSION: u8 = 0x01;

/// The length of the author's commitment that follows the hint
/// (§The author's commitment).
pub const RESEND_COMMITMENT_BYTES: usize = 16;

/// The domain of [`resend_author_commitment`].
pub const RESEND_COMMITMENT_DOMAIN: &str = "peachy resend author v1";

/// The `authenticated_data` that carries `hint`, as builds before the
/// author's commitment wrote it: three bytes.
pub fn hint_aad(hint: u8) -> Vec<u8> {
    vec![HINT_TAG, HINT_VERSION, hint]
}

/// The `authenticated_data` a current build writes: the hint, then the
/// author's commitment, zeros for none (§The author's commitment).
pub fn hint_aad_with_commitment(
    hint: u8,
    commitment: Option<[u8; RESEND_COMMITMENT_BYTES]>,
) -> Vec<u8> {
    let mut aad = hint_aad(hint);
    aad.extend_from_slice(&commitment.unwrap_or([0u8; RESEND_COMMITMENT_BYTES]));
    aad
}

/// The commitment to `actor_id` as the author of a message whose secret is
/// `secret`, in `group_id` (§The author's commitment).
pub fn resend_author_commitment(
    group_id: &[u8],
    actor_id: &str,
    secret: &[u8],
) -> [u8; RESEND_COMMITMENT_BYTES] {
    let mut hasher = Sha256::new();
    hasher.update(RESEND_COMMITMENT_DOMAIN.as_bytes());
    for part in [group_id, actor_id.as_bytes(), secret] {
        hasher.update((part.len() as u32).to_be_bytes());
        hasher.update(part);
    }
    let digest = hasher.finalize();
    let mut out = [0u8; RESEND_COMMITMENT_BYTES];
    out.copy_from_slice(&digest[..RESEND_COMMITMENT_BYTES]);
    out
}

/// The secret an answer to a resend ask will carry for this plaintext, or
/// `None` when it has none and the message commits to nobody:
///
/// - hint [`CONTENT_HINT_RESENDABLE`]: a transcript frame (`0xFF`, a version
///   byte, a JSON object) whose `i` is a UUID. The secret is `i`, lowercased,
///   which the answer carries as its own `i`.
/// - hint [`CONTENT_HINT_RESENDABLE_LANE`]: a lane frame, a JSON object,
///   carrying `z`, standard base64 of exactly 16 bytes. The secret is the
///   whole plaintext, which the answer carries as `f`. Without the salt a
///   lane frame is guessable (a delete names only its target), so it commits
///   to nobody.
/// - any other hint: none.
pub fn resend_secret_of(hint: u8, plaintext: &[u8]) -> Option<Vec<u8>> {
    match hint {
        CONTENT_HINT_RESENDABLE => {
            let [0xFF, _version, json @ ..] = plaintext else {
                return None;
            };
            let value: serde_json::Value = serde_json::from_slice(json).ok()?;
            let id = value.as_object()?.get("i")?.as_str()?;
            is_uuid(id).then(|| id.to_ascii_lowercase().into_bytes())
        }
        CONTENT_HINT_RESENDABLE_LANE => {
            use base64::Engine as _;
            let value: serde_json::Value = serde_json::from_slice(plaintext).ok()?;
            let salt = value.as_object()?.get("z")?.as_str()?;
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(salt)
                .ok()?;
            (bytes.len() == 16).then(|| plaintext.to_vec())
        }
        _ => None,
    }
}

/// `8-4-4-4-12` hex digits, either case: the frame's own rule for `i`.
fn is_uuid(id: &str) -> bool {
    let bytes = id.as_bytes();
    bytes.len() == 36
        && bytes.iter().enumerate().all(|(at, b)| match at {
            8 | 13 | 18 | 23 => *b == b'-',
            _ => b.is_ascii_hexdigit(),
        })
}

/// The author's commitment in an `authenticated_data`: `None` when the AAD
/// carries no hint this build knows, no commitment (a build before it), or
/// zeros (a message that commits to nobody).
pub fn commitment_from_aad(aad: &[u8]) -> Option<[u8; RESEND_COMMITMENT_BYTES]> {
    hint_from_aad(aad)?;
    let tail = aad.get(3..3 + RESEND_COMMITMENT_BYTES)?;
    if tail.iter().all(|b| *b == 0) {
        return None;
    }
    let mut out = [0u8; RESEND_COMMITMENT_BYTES];
    out.copy_from_slice(tail);
    Some(out)
}

/// The hint in an `authenticated_data`, or `None` for AAD that carries none
/// or a hint this build does not know.
pub fn hint_from_aad(aad: &[u8]) -> Option<u8> {
    match aad {
        [HINT_TAG, HINT_VERSION, hint, ..]
            if matches!(
                *hint,
                CONTENT_HINT_DEFAULT
                    | CONTENT_HINT_RESENDABLE
                    | CONTENT_HINT_IMPLICIT
                    | CONTENT_HINT_RESENDABLE_LANE
            ) =>
        {
            Some(*hint)
        }
        _ => None,
    }
}

/// What can be read off a group message without opening it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MessagePeek {
    /// The epoch the message was sealed in.
    pub epoch: u64,
    /// The content hint, when it is an application message that carries one.
    pub hint: Option<u8>,
    /// The author's commitment, when it carries one (§The author's
    /// commitment).
    pub commitment: Option<[u8; RESEND_COMMITMENT_BYTES]>,
}

/// Read a group message's epoch and content hint without any key. `None` for
/// bytes that are not a group message at all. A carried commit
/// ([`crate::carried_commit`]), and a steward's veto frame around either
/// ([`crate::steward`]), is read by its commit.
pub fn peek_message(message: &[u8]) -> Option<MessagePeek> {
    let message = crate::carried_commit::split_carried(message).ok()?.commit;
    let incoming = MlsMessageIn::tls_deserialize_exact(message).ok()?;
    let protocol = incoming.try_into_protocol_message().ok()?;
    let epoch = protocol.epoch().as_u64();
    let (hint, commitment) = match &protocol {
        ProtocolMessage::PrivateMessage(private) => (
            hint_from_aad(private.aad()),
            commitment_from_aad(private.aad()),
        ),
        ProtocolMessage::PublicMessage(_) => (None, None),
    };
    Some(MessagePeek {
        epoch,
        hint,
        commitment,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_aad_round_trips_every_hint() {
        for hint in [
            CONTENT_HINT_DEFAULT,
            CONTENT_HINT_RESENDABLE,
            CONTENT_HINT_IMPLICIT,
            CONTENT_HINT_RESENDABLE_LANE,
        ] {
            assert_eq!(hint_from_aad(&hint_aad(hint)), Some(hint));
        }
    }

    #[test]
    fn foreign_or_unknown_aad_is_no_hint() {
        assert_eq!(hint_from_aad(&[]), None);
        assert_eq!(hint_from_aad(&[0x70, 0x02, 1]), None);
        assert_eq!(hint_from_aad(&[0x71, 0x01, 1]), None);
        assert_eq!(hint_from_aad(&[0x70, 0x01, 9]), None);
    }

    #[test]
    fn only_what_a_person_sent_is_urgent() {
        assert!(hint_is_urgent(CONTENT_HINT_RESENDABLE));
        assert!(hint_is_urgent(CONTENT_HINT_RESENDABLE_LANE));
        assert!(!hint_is_urgent(CONTENT_HINT_IMPLICIT));
        assert!(!hint_is_urgent(CONTENT_HINT_DEFAULT));
    }

    #[test]
    fn the_commitment_rides_after_the_hint_and_zeros_are_none() {
        let c = resend_author_commitment(b"g", "actor-ada", b"secret");
        let aad = hint_aad_with_commitment(CONTENT_HINT_RESENDABLE, Some(c));
        assert_eq!(aad.len(), 3 + RESEND_COMMITMENT_BYTES);
        // An older reader still reads the hint off the front.
        assert_eq!(hint_from_aad(&aad), Some(CONTENT_HINT_RESENDABLE));
        assert_eq!(commitment_from_aad(&aad), Some(c));
        let none = hint_aad_with_commitment(CONTENT_HINT_IMPLICIT, None);
        assert_eq!(none.len(), aad.len());
        assert_eq!(commitment_from_aad(&none), None);
        assert_eq!(
            commitment_from_aad(&hint_aad(CONTENT_HINT_RESENDABLE)),
            None
        );
    }

    #[test]
    fn the_commitment_names_one_author_in_one_group() {
        let c = resend_author_commitment(b"g", "actor-ada", b"i");
        assert_ne!(c, resend_author_commitment(b"g", "actor-bo", b"i"));
        assert_ne!(c, resend_author_commitment(b"h", "actor-ada", b"i"));
        assert_ne!(c, resend_author_commitment(b"g", "actor-ada", b"j"));
        // The lengths keep the fields apart.
        assert_ne!(
            resend_author_commitment(b"g", "ab", b"c"),
            resend_author_commitment(b"g", "a", b"bc")
        );
    }

    #[test]
    fn the_secret_is_the_frame_id_or_a_salted_lane_frame() {
        let mut frame = vec![0xFF, 0x05];
        frame.extend_from_slice(br#"{"i":"0A1B2C3D-4E5F-4A6B-8C7D-9E0F1A2B3C4D","t":"hi","a":[]}"#);
        assert_eq!(
            resend_secret_of(CONTENT_HINT_RESENDABLE, &frame),
            Some(b"0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d".to_vec())
        );
        let mut bad = vec![0xFF, 0x05];
        bad.extend_from_slice(br#"{"i":"x"}"#);
        assert_eq!(resend_secret_of(CONTENT_HINT_RESENDABLE, &bad), None);
        assert_eq!(
            resend_secret_of(CONTENT_HINT_RESENDABLE, br#"{"i":"x"}"#),
            None
        );
        let lane = br#"{"peachy":"del","v":1,"m":"0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d","z":"AAECAwQFBgcICQoLDA0ODw=="}"#;
        assert_eq!(
            resend_secret_of(CONTENT_HINT_RESENDABLE_LANE, lane),
            Some(lane.to_vec())
        );
        let unsalted = br#"{"peachy":"del","v":1,"m":"0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d"}"#;
        assert_eq!(
            resend_secret_of(CONTENT_HINT_RESENDABLE_LANE, unsalted),
            None
        );
        let short = br#"{"peachy":"del","v":1,"m":"x","z":"AAEC"}"#;
        assert_eq!(resend_secret_of(CONTENT_HINT_RESENDABLE_LANE, short), None);
        assert_eq!(resend_secret_of(CONTENT_HINT_IMPLICIT, lane), None);
    }

    #[test]
    fn garbage_is_not_a_message() {
        assert_eq!(peek_message(b"not a group message"), None);
    }
}
