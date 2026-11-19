// SPDX-License-Identifier: MIT
//! A request to be seated in a group, signed by the device that asks.
//!
//! ## Why a request needs a signature at all
//!
//! Two paths ask a group's members to seat somebody:
//!
//! - **An open community room's join inbox.** A newcomer leaves a seat ask in
//!   the room's inbox, and the first room member's device to read it adds every
//!   device of the person it names.
//! - **A rejoin.** A device that fell off a group's tree addresses a seat ask
//!   to the leaves it last saw, and a current member hands its slot back.
//!
//! Both asks travel inside an envelope sealed under a key derived from the
//! group id alone (`crate::envelope`). That seal hides the ask from the
//! delivery service. It says nothing about WHO wrote it. Every member of a
//! community can read an open room's group id out of the community group's
//! directory, so before this module existed any one of them could write
//! `{"a": "somebody else"}` and have that person pulled into a room they never
//! asked for. Anybody who knew a group id could likewise make its members
//! re-seat a current member's device.
//!
//! The fix is that the ask is signed by the
//! asking device's own key. That key is the device's Ed25519 key, the key its
//! Peachy credential binds and the key its MLS leaf signs with. The admitting
//! device already fetches a key package to seat the asker, so the check costs
//! nothing new. It reads the asker's identity out of that key package
//! (`crate::group::Client::key_package_identity`, so the credential is checked
//! against the trusted issuer keys) and verifies the signature against the key
//! that credential binds. A member can then only ask to seat THEMSELF.
//!
//! ## What the signature binds, and why each part
//!
//! ```text
//! "peachy-join-request-v1" || 0x00
//!   || u32be(len) || group_id
//!   || u32be(len) || actor_id
//!   || u32be(len) || device_id
//!   || i64be(issued_at)
//!   || nonce (16 bytes)
//! ```
//!
//! - **The group id**, so a request for one room cannot be replayed into
//!   another room's inbox.
//! - **The actor and the device**, so the signature is a statement about one
//!   person's one device, and it can be compared with the credential it is
//!   checked against.
//! - **`issued_at`**, so a request copied out of an inbox cannot be re-sent
//!   days later, after its author has left, and seat them again. A verifier
//!   accepts it for [`JOIN_REQUEST_MAX_AGE_SECONDS`] and refuses one more than
//!   [`JOIN_REQUEST_FUTURE_SKEW_SECONDS`] ahead of its own clock.
//! - **A random nonce**, so two honest requests from one device in the same
//!   second are different requests, and a verifier that remembers nonces can
//!   refuse a replay inside the window.
//!
//! Every variable-length field is length-prefixed rather than NUL-separated
//! (`crate::device_link` uses separators). A group id is arbitrary bytes, and a
//! length prefix is the one framing arbitrary bytes cannot break.
//!
//! ## The proof on the wire
//!
//! What a client carries next to its `{actor, device}` claim is 89 bytes:
//!
//! ```text
//! 0x01 (version) || i64be(issued_at) || nonce (16) || Ed25519 signature (64)
//! ```
//!
//! The group, actor and device are not repeated inside it. The verifier already
//! has all three: the group is the one whose inbox or envelope the ask came
//! through, and the actor and device are the claim the proof is checked
//! against.
//!
//! ## The verdict, and its order
//!
//! [`check_join_request`] answers with a [`JoinRequestVerdict`] and never
//! fails. The checks run in this order, and the first to refuse is the one
//! reported:
//!
//! 1. `malformed`: the proof is not 89 bytes of version 1.
//! 2. `identity_mismatch`: the credential the key package carries names another
//!    actor or another device than the claim.
//! 3. `bad_signature`: the signature does not verify under that credential's
//!    key, over this group, this actor, this device, this time and this nonce.
//! 4. `stale` / `from_the_future`: the clock. It is checked after the signature,
//!    as `crate::identity` does, so a forger is never told that their request
//!    is merely old.
//!
//! [`JoinRequestVerdict::CredentialRejected`] comes before all four, from the
//! [`crate::group::Client::verify_join_request`] door: a key package whose
//! credential does not verify identifies nobody.
//!
//! [`JoinRequestVerdict::NotAMember`] comes after all of them, from the same
//! door: a request that holds in every other way, from a person who holds no
//! leaf in the verifier's own copy of the group and is not one the verifier
//! said it is still trying to add. A signed ask proves who is asking, never
//! that they belong; a removed member can sign one as well as anybody. Nor
//! can the verifier's own list re-seat them: a person whose last leaf the
//! verifier saw leave is `NotAMember` even when the caller names them. A
//! person the caller admits by its own rule (a link, an open group's join
//! inbox) goes through [`crate::group::Client::verify_admitted_join_request`],
//! which judges everything here but membership.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

use crate::credential::ED25519_PUBLIC_KEY_BYTES;
use crate::error::{Error, Result};
use crate::identity::{PeachyIdentity, ED25519_SEED_BYTES};

/// The domain separator for the bytes a requesting device signs.
pub const JOIN_REQUEST_DOMAIN: &str = "peachy-join-request-v1";

/// The version byte a proof starts with.
pub const JOIN_REQUEST_PROOF_VERSION: u8 = 1;

/// How many random bytes a request's nonce carries.
pub const JOIN_REQUEST_NONCE_BYTES: usize = 16;

/// An Ed25519 signature: 64 bytes, always.
pub const JOIN_REQUEST_SIGNATURE_BYTES: usize = 64;

/// The whole proof: version, `issued_at`, nonce, signature.
pub const JOIN_REQUEST_PROOF_BYTES: usize =
    1 + 8 + JOIN_REQUEST_NONCE_BYTES + JOIN_REQUEST_SIGNATURE_BYTES;

/// How long after it was signed a request is still honoured: one day.
///
/// Long enough for a request left in a room's inbox while no member is online
/// to be answered when one comes back. Short enough that a request copied out
/// of an inbox stops working a day later. A requester still waiting after that
/// signs and sends a fresh one.
pub const JOIN_REQUEST_MAX_AGE_SECONDS: i64 = 86_400;

/// How far ahead of the verifier's clock a request may claim to have been
/// signed. The same 60 seconds the credential check allows
/// (`crate::identity::CLOCK_SKEW_SECONDS`).
pub const JOIN_REQUEST_FUTURE_SKEW_SECONDS: i64 = 60;

/// What a verifier decided about a signed join request.
///
/// `#[repr(u32)]` with spelled-out names for the same reason as
/// [`crate::rules::DenyReason`]: a decision four clients have to agree on is
/// pinned in a golden fixture by name AND number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum JoinRequestVerdict {
    /// The request holds: seat the device.
    Accepted = 0,
    /// The proof is not a version-1 proof of the right length.
    Malformed = 1,
    /// The key package it was checked against is not one this build accepts,
    /// or its credential does not verify.
    CredentialRejected = 2,
    /// The credential names another actor or another device than the request.
    IdentityMismatch = 3,
    /// The signature does not verify under the credential's key over this
    /// group, actor, device, time and nonce.
    BadSignature = 4,
    /// Signed more than [`JOIN_REQUEST_MAX_AGE_SECONDS`] ago.
    Stale = 5,
    /// Signed more than [`JOIN_REQUEST_FUTURE_SKEW_SECONDS`] in the future.
    FromTheFuture = 6,
    /// Every other check holds, but the asker's person holds no leaf in the
    /// verifier's copy of the group, is not the verifier's own person, and is
    /// not among the people the verifier is still trying to add (a person the
    /// verifier saw leave never is). An ex-member asking back in is this.
    NotAMember = 7,
}

impl JoinRequestVerdict {
    /// Every verdict, in code order.
    pub const ALL: [JoinRequestVerdict; 8] = [
        JoinRequestVerdict::Accepted,
        JoinRequestVerdict::Malformed,
        JoinRequestVerdict::CredentialRejected,
        JoinRequestVerdict::IdentityMismatch,
        JoinRequestVerdict::BadSignature,
        JoinRequestVerdict::Stale,
        JoinRequestVerdict::FromTheFuture,
        JoinRequestVerdict::NotAMember,
    ];

    /// The number every binding carries.
    pub fn code(self) -> u32 {
        self as u32
    }

    /// The name the fixture writes.
    pub fn name(self) -> &'static str {
        match self {
            JoinRequestVerdict::Accepted => "accepted",
            JoinRequestVerdict::Malformed => "malformed",
            JoinRequestVerdict::CredentialRejected => "credential_rejected",
            JoinRequestVerdict::IdentityMismatch => "identity_mismatch",
            JoinRequestVerdict::BadSignature => "bad_signature",
            JoinRequestVerdict::Stale => "stale",
            JoinRequestVerdict::FromTheFuture => "from_the_future",
            JoinRequestVerdict::NotAMember => "not_a_member",
        }
    }

    /// The verdict with this number, if there is one.
    pub fn from_code(code: u32) -> Option<Self> {
        Self::ALL.iter().copied().find(|v| v.code() == code)
    }

    /// Whether this is [`JoinRequestVerdict::Accepted`].
    pub fn is_accepted(self) -> bool {
        self == JoinRequestVerdict::Accepted
    }
}

fn push_field(out: &mut Vec<u8>, field: &[u8]) -> Result<()> {
    let len = u32::try_from(field.len())
        .map_err(|_| Error::invalid("a join request field is longer than 4 GiB"))?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(field);
    Ok(())
}

/// The exact bytes a requesting device signs. See the module header.
///
/// Refuses an empty group id, actor id or device id, and a nonce that is not
/// exactly [`JOIN_REQUEST_NONCE_BYTES`]. None of those is a verdict. Each is a
/// caller handing over something that is not a request.
pub fn join_request_statement(
    group_id: &[u8],
    actor_id: &str,
    device_id: &str,
    issued_at: i64,
    nonce: &[u8],
) -> Result<Vec<u8>> {
    if group_id.is_empty() {
        return Err(Error::invalid("a group_id must not be empty"));
    }
    if actor_id.is_empty() {
        return Err(Error::invalid("an actor_id must not be empty"));
    }
    if device_id.is_empty() {
        return Err(Error::invalid("a device_id must not be empty"));
    }
    if nonce.len() != JOIN_REQUEST_NONCE_BYTES {
        return Err(Error::invalid(format!(
            "a nonce must be exactly {JOIN_REQUEST_NONCE_BYTES} bytes, got {}",
            nonce.len()
        )));
    }
    let domain = JOIN_REQUEST_DOMAIN.as_bytes();
    let mut statement = Vec::with_capacity(
        domain.len() + 1 + 12 + group_id.len() + actor_id.len() + device_id.len() + 8 + nonce.len(),
    );
    statement.extend_from_slice(domain);
    statement.push(0);
    push_field(&mut statement, group_id)?;
    push_field(&mut statement, actor_id.as_bytes())?;
    push_field(&mut statement, device_id.as_bytes())?;
    statement.extend_from_slice(&issued_at.to_be_bytes());
    statement.extend_from_slice(nonce);
    Ok(statement)
}

/// Sign a join request with the requesting device's own key and return the
/// 89-byte proof.
///
/// `seed` is the device's 32-byte Ed25519 seed, the one its credential binds.
/// Deterministic for a given nonce (RFC 8032), which is what lets a golden
/// fixture pin a proof. A client calls [`crate::group::Client::sign_join_request`]
/// instead, which takes the time off its own clock and draws a fresh nonce.
pub fn sign_join_request(
    seed: &[u8],
    group_id: &[u8],
    actor_id: &str,
    device_id: &str,
    issued_at: i64,
    nonce: &[u8],
) -> Result<Vec<u8>> {
    let seed: [u8; ED25519_SEED_BYTES] = seed.try_into().map_err(|_| {
        Error::invalid(format!(
            "a device signing key seed must be exactly {ED25519_SEED_BYTES} bytes, got {}",
            seed.len()
        ))
    })?;
    let statement = join_request_statement(group_id, actor_id, device_id, issued_at, nonce)?;
    let signature = SigningKey::from_bytes(&seed).sign(&statement).to_bytes();
    Ok(assemble_proof(issued_at, nonce, &signature))
}

/// The proof's bytes around a signature somebody already made over
/// [`join_request_statement`].
pub(crate) fn assemble_proof(issued_at: i64, nonce: &[u8], signature: &[u8]) -> Vec<u8> {
    let mut proof = Vec::with_capacity(JOIN_REQUEST_PROOF_BYTES);
    proof.push(JOIN_REQUEST_PROOF_VERSION);
    proof.extend_from_slice(&issued_at.to_be_bytes());
    proof.extend_from_slice(nonce);
    proof.extend_from_slice(signature);
    proof
}

/// A proof, read. `None` for anything that is not 89 bytes of version 1.
struct Proof {
    issued_at: i64,
    nonce: [u8; JOIN_REQUEST_NONCE_BYTES],
    signature: [u8; JOIN_REQUEST_SIGNATURE_BYTES],
}

fn read_proof(proof: &[u8]) -> Option<Proof> {
    if proof.len() != JOIN_REQUEST_PROOF_BYTES {
        return None;
    }
    let (version, rest) = proof.split_first()?;
    if *version != JOIN_REQUEST_PROOF_VERSION {
        return None;
    }
    let (issued_at, rest) = rest.split_at_checked(8)?;
    let (nonce, signature) = rest.split_at_checked(JOIN_REQUEST_NONCE_BYTES)?;
    Some(Proof {
        issued_at: i64::from_be_bytes(issued_at.try_into().ok()?),
        nonce: nonce.try_into().ok()?,
        signature: signature.try_into().ok()?,
    })
}

/// The nonce a proof carries, for a verifier that remembers which requests it
/// has already answered. `None` for a malformed proof.
pub fn join_request_nonce(proof: &[u8]) -> Option<[u8; JOIN_REQUEST_NONCE_BYTES]> {
    read_proof(proof).map(|p| p.nonce)
}

/// The `issued_at`, nonce and signature a proof carries, unverified. `None`
/// for a malformed proof.
pub(crate) fn join_request_parts(
    proof: &[u8],
) -> Option<(
    i64,
    [u8; JOIN_REQUEST_NONCE_BYTES],
    [u8; JOIN_REQUEST_SIGNATURE_BYTES],
)> {
    read_proof(proof).map(|p| (p.issued_at, p.nonce, p.signature))
}

/// Whether a signed request from `(actor_id, device_id)` to be seated in
/// `group_id` holds, checked against `signer`, the identity read out of the
/// asker's key package, at `now` (unix seconds).
///
/// Never fails. The order the checks run in is in the module header.
pub fn check_join_request(
    signer: &PeachyIdentity,
    group_id: &[u8],
    actor_id: &str,
    device_id: &str,
    proof: &[u8],
    now: i64,
) -> JoinRequestVerdict {
    let Some(proof) = read_proof(proof) else {
        return JoinRequestVerdict::Malformed;
    };
    if signer.actor_id != actor_id || signer.device_id != device_id {
        return JoinRequestVerdict::IdentityMismatch;
    }
    if !verify_join_request_signature(
        &signer.device_key,
        group_id,
        actor_id,
        device_id,
        proof.issued_at,
        &proof.nonce,
        &proof.signature,
    ) {
        return JoinRequestVerdict::BadSignature;
    }
    if proof.issued_at < now.saturating_sub(JOIN_REQUEST_MAX_AGE_SECONDS) {
        return JoinRequestVerdict::Stale;
    }
    if proof.issued_at > now.saturating_add(JOIN_REQUEST_FUTURE_SKEW_SECONDS) {
        return JoinRequestVerdict::FromTheFuture;
    }
    JoinRequestVerdict::Accepted
}

/// The signature half of [`check_join_request`] alone: `true` only if
/// `signature` is `signer_key`'s signature over the statement. A plain `bool`,
/// for the reason `crate::device_link::verify_device_approval` gives. Uses
/// `verify_strict`.
pub fn verify_join_request_signature(
    signer_key: &[u8],
    group_id: &[u8],
    actor_id: &str,
    device_id: &str,
    issued_at: i64,
    nonce: &[u8],
    signature: &[u8],
) -> bool {
    let Ok(key_bytes) = <[u8; ED25519_PUBLIC_KEY_BYTES]>::try_from(signer_key) else {
        return false;
    };
    let Ok(verifying_key) = VerifyingKey::from_bytes(&key_bytes) else {
        return false;
    };
    let Ok(signature_bytes) = <[u8; JOIN_REQUEST_SIGNATURE_BYTES]>::try_from(signature) else {
        return false;
    };
    let Ok(statement) = join_request_statement(group_id, actor_id, device_id, issued_at, nonce)
    else {
        return false;
    };
    verifying_key
        .verify_strict(&statement, &Signature::from_bytes(&signature_bytes))
        .is_ok()
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    const ADA_SEED: [u8; 32] = [0x11; 32];
    const NONCE: [u8; 16] = [0x5a; 16];
    const NOW: i64 = 1_789_516_800;

    fn ada() -> PeachyIdentity {
        PeachyIdentity {
            actor_id: "actor-ada".into(),
            device_id: "device-ada-phone".into(),
            device_key: crate::identity::signing_key_public_key(&ADA_SEED).expect("a key"),
            kid: "k".into(),
            expires_at: NOW + 3600,
            issued_at: NOW - 3600,
            account_key: Some([7u8; 32]),
        }
    }

    fn proof_at(at: i64) -> Vec<u8> {
        sign_join_request(
            &ADA_SEED,
            b"room-1",
            "actor-ada",
            "device-ada-phone",
            at,
            &NONCE,
        )
        .expect("signs")
    }

    fn check(proof: &[u8], group: &[u8], actor: &str, device: &str) -> JoinRequestVerdict {
        check_join_request(&ada(), group, actor, device, proof, NOW)
    }

    #[test]
    fn a_proof_is_89_bytes_and_version_1() {
        let proof = proof_at(NOW);
        assert_eq!(proof.len(), JOIN_REQUEST_PROOF_BYTES);
        assert_eq!(proof.first(), Some(&1));
        assert_eq!(join_request_nonce(&proof), Some(NONCE));
    }

    #[test]
    fn an_honest_request_is_accepted() {
        let proof = proof_at(NOW - 30);
        assert_eq!(
            check(&proof, b"room-1", "actor-ada", "device-ada-phone"),
            JoinRequestVerdict::Accepted
        );
    }

    #[test]
    fn it_is_bound_to_the_group() {
        let proof = proof_at(NOW);
        assert_eq!(
            check(&proof, b"room-2", "actor-ada", "device-ada-phone"),
            JoinRequestVerdict::BadSignature
        );
    }

    #[test]
    fn a_claim_for_somebody_else_is_an_identity_mismatch() {
        let proof = proof_at(NOW);
        assert_eq!(
            check(&proof, b"room-1", "actor-bob", "device-ada-phone"),
            JoinRequestVerdict::IdentityMismatch
        );
        assert_eq!(
            check(&proof, b"room-1", "actor-ada", "device-ada-laptop"),
            JoinRequestVerdict::IdentityMismatch
        );
    }

    #[test]
    fn a_forger_signing_with_their_own_key_is_refused() {
        let forged = sign_join_request(
            &[0x22; 32],
            b"room-1",
            "actor-ada",
            "device-ada-phone",
            NOW,
            &NONCE,
        )
        .expect("signs");
        assert_eq!(
            check(&forged, b"room-1", "actor-ada", "device-ada-phone"),
            JoinRequestVerdict::BadSignature
        );
    }

    #[test]
    fn the_clock_is_checked_both_ways_and_after_the_signature() {
        let old = proof_at(NOW - JOIN_REQUEST_MAX_AGE_SECONDS - 1);
        assert_eq!(
            check(&old, b"room-1", "actor-ada", "device-ada-phone"),
            JoinRequestVerdict::Stale
        );
        let edge = proof_at(NOW - JOIN_REQUEST_MAX_AGE_SECONDS);
        assert!(check(&edge, b"room-1", "actor-ada", "device-ada-phone").is_accepted());
        let ahead = proof_at(NOW + JOIN_REQUEST_FUTURE_SKEW_SECONDS + 1);
        assert_eq!(
            check(&ahead, b"room-1", "actor-ada", "device-ada-phone"),
            JoinRequestVerdict::FromTheFuture
        );
        // A tampered time is a bad signature, not a stale request.
        let mut tampered = proof_at(NOW);
        if let Some(byte) = tampered.get_mut(1) {
            *byte ^= 0x01;
        }
        assert_eq!(
            check(&tampered, b"room-1", "actor-ada", "device-ada-phone"),
            JoinRequestVerdict::BadSignature
        );
    }

    #[test]
    fn a_short_or_unversioned_proof_is_malformed() {
        let proof = proof_at(NOW);
        assert_eq!(
            check(&proof[..88], b"room-1", "actor-ada", "device-ada-phone"),
            JoinRequestVerdict::Malformed
        );
        let mut v2 = proof.clone();
        if let Some(byte) = v2.first_mut() {
            *byte = 2;
        }
        assert_eq!(
            check(&v2, b"room-1", "actor-ada", "device-ada-phone"),
            JoinRequestVerdict::Malformed
        );
        assert_eq!(
            check(&[], b"room-1", "actor-ada", "device-ada-phone"),
            JoinRequestVerdict::Malformed
        );
    }

    #[test]
    fn the_statement_refuses_what_is_not_a_request() {
        assert!(join_request_statement(b"", "a", "d", NOW, &NONCE).is_err());
        assert!(join_request_statement(b"g", "", "d", NOW, &NONCE).is_err());
        assert!(join_request_statement(b"g", "a", "", NOW, &NONCE).is_err());
        assert!(join_request_statement(b"g", "a", "d", NOW, &NONCE[..15]).is_err());
    }

    #[test]
    fn length_prefixes_keep_fields_apart() {
        let one = join_request_statement(b"ab", "c", "d", NOW, &NONCE).expect("one");
        let two = join_request_statement(b"a", "bc", "d", NOW, &NONCE).expect("two");
        assert_ne!(one, two);
    }

    #[test]
    fn codes_and_names_round_trip() {
        for (index, verdict) in JoinRequestVerdict::ALL.iter().enumerate() {
            assert_eq!(verdict.code() as usize, index);
            assert_eq!(
                JoinRequestVerdict::from_code(verdict.code()),
                Some(*verdict)
            );
        }
    }
}
