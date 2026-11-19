// SPDX-License-Identifier: MIT
//! Signed revocations, and when a leaf leaves a group on the server's word.
//!
//! The model is docs/identity.md §Revocation reaches a seated leaf
//! through the roster.
//!
//! ## The gap this closes
//!
//! The delivery service tells a sender which of the devices it named are
//! revoked (`stale_device_ids`), and the sender's device removes their leaves.
//! A credential carries no revocation, so that list was the whole of the
//! evidence: a server that named a live device could have it removed, and by
//! naming every device of a person, have the PERSON removed, in a tree that
//! shows the removal as a member's own commit.
//!
//! ## What is signed
//!
//! The device that revokes holds the account key, so it signs the revoked
//! device's key with the account identity key
//! ([`crate::account_identity`]):
//!
//! `"peachy-device-revocation-v1" || 0x00 || device_key`
//!
//! Only the key, for the reason an account certificate covers only the key:
//! the ids are the server's to assign, and the key is what a leaf holds. A
//! revocation is permanent; the device comes back only as a new key, so the
//! statement carries no time. The server checks it at `RevokeDevice`, keeps
//! it on the revoked row, and hands it out beside every `stale_device_ids`
//! answer and on the row in `ListDevices`.
//!
//! ## When a stale leaf may go ([`stale_leaf_removable`])
//!
//! A leaf the server names stale is removed when ANY of these holds, judged
//! on this device's own clock and the group's tree clock, never the
//! server-corrected one (the server can move that by a day; §Which clock a
//! lapse is read on):
//!
//! 1. **The account revoked it.** A revocation verifies under the leaf's own
//!    account identity key, over the leaf's own device key.
//! 2. **Its credential has lapsed, and the person keeps a leaf that has
//!    not.** The server is the issuer: it can
//!    stop renewing a live device, stall a group's commits through the
//!    refresh window, or mint a short credential, so a lapse is the server's
//!    word too. It removes one of a person's devices only while another of
//!    their leaves there is unlapsed, and only for a credential that lived
//!    the issuer's full lifetime ([`crate::identity::has_issuer_lifetime`])
//!    and, for a leaf still seated from its key package, had at least
//!    [`crate::identity::CREDENTIAL_REFRESH_WINDOW_SECONDS`] left when its
//!    device minted the package (the package's window start, which the device
//!    signs): an issuer that backdates `iat` meets the first, never the
//!    second, and a leaf renewed since cannot have its `exp` moved earlier.
//!    A person's LAST leaf goes by this rule only past `exp` plus
//!    [`crate::identity::EXPIRED_LEAF_GRACE_SECONDS`], when its credential no
//!    longer identifies anybody and every client would evict it anyway: no
//!    earlier than without this rule, so the server gains nothing by it.
//! 3. **The person keeps another unlapsed leaf there**, while
//!    [`SIGNED_REVOCATIONS_ENFORCED`] is off: removing one of several devices
//!    is the device-level drop a sender makes on the server's word, and the
//!    person stays a member. A lapsed leaf does not count as another: a
//!    dormant tablet must not let a live phone go by this rule.
//!
//! In rules 2 and 3, another leaf of the person carries the same actor id
//! and the same account key: the issuer can mint a credential for any actor
//! id, never one under the account's key.
//!
//! A person's last leaf is otherwise removed only in the commit that seats
//! the same person's new device ([`Client::reseat_person`]), which needs a
//! key package carrying an account's signature: the account's own key, which
//! could sign a revocation anyway, or a new one, which every member sees as
//! the person's security code changing.
//!
//! Rule 3 holds while [`SIGNED_REVOCATIONS_ENFORCED`] is false: some
//! revocations are made by the server (an idle device unlinked, an unsigned
//! RevokeDevice) and cannot be signed, and they must keep working. With the
//! switch on, only rules 1 and 2 remove.
//!
//! ## Which clock a lapse is read on
//!
//! The judged leaf counts as lapsed only when it has lapsed on BOTH this
//! device's own clock and the group's tree clock (the newest `iat` its leaves
//! carry, which in an honest group only lags real time); another leaf of the
//! person counts as live only while it is live on both. So a committer whose
//! clock runs fast moves no removal earlier than the group's own leaves
//! allow, and a slow one keeps no lapsed sibling counting as live. What it
//! costs: in a group nobody has renewed in since the leaf's `exp`, a lapse
//! waits for the next renewal, at most a credential's lifetime, since every
//! live leaf renews before its own `exp`.
//!
//! These are the committer's rules; receivers do not re-judge a removal.
//!
//! ## A revoked key's messages
//!
//! A revoked leaf stays seated until a member removes it. So
//! [`Client::stale_leaf_removable`] keeps every revocation that verifies
//! (rule 1), by device key, with the second the delivery service says it
//! took effect (`revoked_at`, `0` when it did not say), and from then on
//! this device judges every application message from that key, in every
//! group, whether or not the leaf is gone yet
//! (docs/identity.md §A revoked leaf's messages):
//!
//! - **Refused:** a message the delivery service received at or after the
//!   revocation took effect, and one whose receipt this device cannot place
//!   before it (the caller did not pass a receive time, or the revocation
//!   came without one). Unknown counts as after.
//! - **Still read:** a message received before the revocation took effect,
//!   however late this device reads it: what the device sent while it was
//!   still the account's.
//!
//! Both times are the delivery service's word, read on its one clock; the
//! signed statement carries none. Of two times for one key the earlier is
//! kept, so a later answer can only refuse more. The key is re-verified
//! under the sender's own account key on every refusal, so nothing the store
//! holds can silence a device its account did not sign out.
//!
//! ## Which keys a device signs ([`install_revocation_targets`])
//!
//! A revocation is permanent and binds only a key, so a client that signed
//! whatever key the server's device list put in front of it would hand the
//! server the account's word against any device. The rule, shared by every
//! client:
//!
//! - **Never this install's own keys.** No row of the removal may be one of
//!   the revoking install's own rows; if one is, nothing is signed.
//! - **Nothing for a denial.** A pending device has no leaf; denying it signs
//!   nothing, whatever the list says it is linked to.
//! - **Only a key this device vouches for**: a row whose id and key are on
//!   this device's approval chain
//!   ([`Client::check_own_device_key`] answering known or approved). A key
//!   the server invented, or put under another id, is on no chain.
//! - **A linked row only when the person saw it named, on a link this device
//!   saw first.** The server links an install's two rows (`twin_of`) and
//!   nothing signs that link, and a Device keys screen draws one entry per
//!   install, hiding the row linked to the one it draws. So a removal signs
//!   the row the person named, and a row linked to it only when the
//!   confirmation named that row too (`namedWith`), and only when this device
//!   pinned the same link earlier ([`Client::note_own_install_links`], first
//!   sight wins). Removals with no confirmation of their own (the
//!   new-device notice, a denial) sign the named row alone.
//! - **Never an id the list names twice**, for a removal or a restore. The
//!   rule picks rows by id, and the key signed is the one the list gives the
//!   id; a second row under the id could carry a live device's key past a
//!   first row that qualified. A device list holds each id once.
//!
//! ## A PIN restore signs the others
//!
//! A device that took the account key back from its PIN made itself the
//! account's only device: the server signs every other install out in the
//! registration that restores (docs/identity.md §Who may certify,
//! PIN restore). Its intent is "every other device", not one the
//! list names, and it holds the account key, so it signs the installs the
//! restore signed out whatever its approval chain says. Which ones is fixed
//! by that registration's own answer, which names the keys it signed out,
//! never by a later read of the device list: the server chooses when a read
//! succeeds and writes the revocation times on the rows, so neither a band
//! around the restore nor "the first read" bounds anything against it.
//!
//! - **The restoring registration keeps a snapshot.** The client hands its
//!   answer to [`Client::note_restore_signed_out`], which keeps those keys
//!   for the restore's `restored_since`, first write wins. Nothing can be
//!   linked before that registration finishes: a new device needs an
//!   approval, and this device is not let back in until it registers.
//! - **An approval closes the restore.** [`Client::sign_own_device_approval`]
//!   writes an empty snapshot when none is kept yet, so an answer that never
//!   came (the answer was lost) cannot be stood in for by a list read
//!   after the person links a device.
//! - **Only keys in the snapshot are signed, and none without one.**
//!   [`Client::sign_install_revocations`] signs a row the list shows revoked
//!   within [`RESTORE_SIGN_OUT_SECONDS`] of the restore only when its key is
//!   in the snapshot, and nothing while no snapshot is kept.
//! - **Never a key on this device's chain**, under any id, never this
//!   install's own ids or keys, nor a key a live row of the list still
//!   carries, which would be a device the restore did not sign out.
//! - **A key once signed out is never approved again here.** This device
//!   refuses to approve a key the restore's answer named
//!   ([`Client::sign_own_device_approval`]), as it refuses a key it forgot
//!   or signed a revocation of. The clients hand this core only the named
//!   keys whose account certificate verifies, so a device that was waiting
//!   at the restore, never certified, is not among them, and one this
//!   device approved since is not either, since that approval closed the
//!   restore. The clients carry the keys to the account's other devices in
//!   the sealed account record and refuse them there too, removing the
//!   device instead, so it starts over under a new key
//!   (docs/identity.md §RevokeDevice).
//!
//! What the answer names is the server's word, at the moment of the
//! restore. A restore whose answer never arrived signs nothing, and its rows stay
//! unsigned, as before; so does a clock off by more than an hour, and a
//! device on this one's chain, such as the one that let it in before.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

use crate::account_store::{hkdf32, ACCOUNT_KEY_BYTES};
use crate::credential::{ED25519_PUBLIC_KEY_BYTES, ED25519_SIGNATURE_BYTES};
use crate::error::{Error, Result};
use crate::group::{Client, RosterEntry};
use crate::identity::{
    has_issuer_lifetime, CLOCK_SKEW_SECONDS, CREDENTIAL_REFRESH_WINDOW_SECONDS,
    EXPIRED_LEAF_GRACE_SECONDS,
};

/// The domain of an account's signature revoking one of its device keys.
pub const DEVICE_REVOCATION_DOMAIN: &str = "peachy-device-revocation-v1";

/// A revocation is one Ed25519 signature.
pub const DEVICE_REVOCATION_BYTES: usize = ED25519_SIGNATURE_BYTES;

/// Whether only a signed revocation or a lapsed credential removes a stale
/// leaf. Off (module docs, rule 3): a person's last leaf needs one of the
/// two, any other leaf does not.
pub const SIGNED_REVOCATIONS_ENFORCED: bool = false;

/// The bytes an account signs to revoke one device key.
pub fn device_revocation_statement(device_key: &[u8]) -> Result<Vec<u8>> {
    if device_key.len() != ED25519_PUBLIC_KEY_BYTES {
        return Err(Error::invalid(format!(
            "a device_key must be exactly {ED25519_PUBLIC_KEY_BYTES} bytes, got {}",
            device_key.len()
        )));
    }
    let domain = DEVICE_REVOCATION_DOMAIN.as_bytes();
    let mut statement = Vec::with_capacity(domain.len() + 1 + device_key.len());
    statement.extend_from_slice(domain);
    statement.push(0);
    statement.extend_from_slice(device_key);
    Ok(statement)
}

/// Sign [`device_revocation_statement`] for `device_key` with the identity key
/// derived from `account_key`. Deterministic (RFC 8032), so a golden fixture
/// pins the bytes.
pub fn sign_device_revocation(
    account_key: &[u8],
    device_key: &[u8],
) -> Result<[u8; DEVICE_REVOCATION_BYTES]> {
    if account_key.len() != ACCOUNT_KEY_BYTES {
        return Err(Error::invalid(format!(
            "an account_key must be exactly {ACCOUNT_KEY_BYTES} bytes, got {}",
            account_key.len()
        )));
    }
    let statement = device_revocation_statement(device_key)?;
    let seed = hkdf32(
        account_key,
        crate::account_identity::ACCOUNT_IDENTITY_DOMAIN.as_bytes(),
    )?;
    Ok(SigningKey::from_bytes(&seed).sign(&statement).to_bytes())
}

/// Whether `signature` is the account identity key `account_public_key`
/// revoking `device_key`. A plain `bool`, as
/// [`crate::account_identity::verify_account_device`] is; `verify_strict`.
pub fn verify_device_revocation(
    account_public_key: &[u8],
    device_key: &[u8],
    signature: &[u8],
) -> bool {
    let Ok(key_bytes) = <[u8; ED25519_PUBLIC_KEY_BYTES]>::try_from(account_public_key) else {
        return false;
    };
    let Ok(verifying) = VerifyingKey::from_bytes(&key_bytes) else {
        return false;
    };
    let Ok(signature_bytes) = <[u8; DEVICE_REVOCATION_BYTES]>::try_from(signature) else {
        return false;
    };
    let Ok(statement) = device_revocation_statement(device_key) else {
        return false;
    };
    verifying
        .verify_strict(&statement, &Signature::from_bytes(&signature_bytes))
        .is_ok()
}

/// The two readings of "now" [`stale_leaf_removable`] judges on (module
/// docs, §Which clock a lapse is read on).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StaleLeafClock {
    /// Unix seconds on this device's own clock, with no server offset.
    pub device: i64,
    /// The group's tree clock: the newest `iat` any of its leaves carries,
    /// `i64::MIN` for a tree with none.
    pub tree: i64,
}

impl StaleLeafClock {
    /// When the judged leaf counts as lapsed: the EARLIER reading, so that
    /// neither a clock running fast nor the tree alone moves a removal
    /// earlier than the other allows.
    fn lapse(self) -> i64 {
        self.device.min(self.tree)
    }

    /// When another leaf of the person counts as live: the LATER reading, so
    /// that neither a clock running slow nor a stale tree keeps a lapsed
    /// sibling counting as the leaf that keeps the person a member.
    fn live(self) -> i64 {
        self.device.max(self.tree)
    }
}

/// Which rule of the module docs (§When a stale leaf may go) lets a stale
/// leaf go.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StaleLeafRule {
    /// Rule 1: its own account signed a revocation of its key.
    Signed,
    /// Rule 2: it lapsed, and the person keeps an unlapsed leaf there.
    Lapsed,
    /// Rule 2, a last leaf: past `exp` plus the grace.
    PastGrace,
    /// Rule 3: the person keeps an unlapsed leaf there (only while
    /// [`SIGNED_REVOCATIONS_ENFORCED`] is false).
    Sibling,
}

/// The first rule that lets the leaf at `leaf_index` go, before
/// [`SIGNED_REVOCATIONS_ENFORCED`] is applied to rule 3.
fn stale_leaf_rule(
    roster: &[RosterEntry],
    leaf_index: u32,
    revocation: &[u8],
    minted_at: Option<i64>,
    clock: StaleLeafClock,
) -> Option<StaleLeafRule> {
    let entry = roster.iter().find(|e| e.leaf_index == leaf_index)?;
    let Ok(identity) = &entry.identity else {
        return None;
    };
    if let Some(account_key) = identity.account_key {
        if verify_device_revocation(&account_key, &identity.device_key, revocation) {
            return Some(StaleLeafRule::Signed);
        }
    }
    let lapsed_at =
        |expires_at: i64, now: i64| expires_at.saturating_add(CLOCK_SKEW_SECONDS) <= now;
    let keeps_an_unlapsed_leaf = roster.iter().any(|other| {
        other.leaf_index != leaf_index
            && matches!(&other.identity, Ok(o) if o.actor_id == identity.actor_id
                && o.account_key == identity.account_key
                && !lapsed_at(o.expires_at, clock.live()))
    });
    let now = clock.lapse();
    if lapsed_at(identity.expires_at, now) {
        // A lapse is evidence only for a credential the issuer gave its full
        // lifetime, and, for a leaf still seated from its key package, one
        // that had a refresh window left when its device minted the package:
        // a backdated credential lapsing within the hour of its seat is the
        // server's word, not a revocation.
        let lived_at_seat = minted_at.is_none_or(|minted| {
            identity.expires_at.saturating_sub(minted) >= CREDENTIAL_REFRESH_WINDOW_SECONDS
        });
        if keeps_an_unlapsed_leaf
            && lived_at_seat
            && has_issuer_lifetime(identity.issued_at, identity.expires_at)
        {
            return Some(StaleLeafRule::Lapsed);
        }
        if identity
            .expires_at
            .saturating_add(EXPIRED_LEAF_GRACE_SECONDS)
            <= now
        {
            return Some(StaleLeafRule::PastGrace);
        }
    }
    keeps_an_unlapsed_leaf.then_some(StaleLeafRule::Sibling)
}

/// Whether the leaf at `leaf_index` of `roster`, which the server named
/// stale, may be removed (module docs, §When a stale leaf may go).
/// `revocation` is the signature the server handed out for that device, or
/// empty. `minted_at` is when the leaf's own device minted the key package
/// it is still seated from, `None` for a leaf renewed since. `clock` is this
/// device's own clock and the group's tree clock.
///
/// Never true for a leaf whose credential does not verify: the ordinary
/// eviction of an unidentifiable leaf takes those, on its own terms.
///
/// Judges rule 3 on this build's [`SIGNED_REVOCATIONS_ENFORCED`]; a client
/// asks [`Client::stale_leaf_removable`], which also honors the refusal the
/// delivery service switched on ([`crate::client_refusals::SIGNED_REVOCATIONS`]).
pub fn stale_leaf_removable(
    roster: &[RosterEntry],
    leaf_index: u32,
    revocation: &[u8],
    minted_at: Option<i64>,
    clock: StaleLeafClock,
) -> bool {
    stale_leaf_removable_when(
        roster,
        leaf_index,
        revocation,
        minted_at,
        clock,
        SIGNED_REVOCATIONS_ENFORCED,
    )
}

/// [`stale_leaf_removable`], with rule 3 refused when `signed_enforced`.
pub fn stale_leaf_removable_when(
    roster: &[RosterEntry],
    leaf_index: u32,
    revocation: &[u8],
    minted_at: Option<i64>,
    clock: StaleLeafClock,
    signed_enforced: bool,
) -> bool {
    match stale_leaf_rule(roster, leaf_index, revocation, minted_at, clock) {
        Some(StaleLeafRule::Sibling) => !signed_enforced,
        Some(_) => true,
        None => false,
    }
}

impl Client {
    /// [`stale_leaf_removable`] against `group_id`'s tree as this device holds
    /// it, on this device's own clock and the group's tree clock: a
    /// credential check, which the server's clock offset must not move. What
    /// a client asks before it removes a leaf the delivery service or its own
    /// device list named as revoked.
    ///
    /// A `revocation` that verifies for the leaf is kept by device key, with
    /// `revoked_at`, the second the delivery service says the revocation
    /// took effect (Unix seconds, `0` when it did not say), so that this
    /// device refuses that key's messages received from then on, in every
    /// group, whether or not the leaf is removed yet (module docs, §A
    /// revoked key's messages). Failing to keep it is logged, not returned:
    /// the answer stands either way.
    pub fn stale_leaf_removable(
        &mut self,
        group_id: &[u8],
        leaf_index: u32,
        revocation: &[u8],
        revoked_at: i64,
    ) -> Result<bool> {
        let roster = self.roster(group_id)?;
        let (tree, minted_at) = self.stale_leaf_group_clock(group_id, leaf_index)?;
        let clock = StaleLeafClock {
            device: self.device_now_unix(),
            tree,
        };
        if let Some(device_key) = revoked_device_key(&roster, leaf_index, revocation) {
            if let Err(err) = self.note_peer_revocation(&device_key, revocation, revoked_at) {
                log::warn!("mls: a verified revocation for leaf {leaf_index} was not kept: {err}");
            }
        }
        Ok(stale_leaf_removable_when(
            &roster,
            leaf_index,
            revocation,
            minted_at,
            clock,
            self.client_refusals
                .is_on(crate::client_refusals::SIGNED_REVOCATIONS),
        ))
    }

    /// THE DOOR FOR A LEAF THE SERVER NAMED (`stale_device_ids`,
    /// `retired_device_ids`): judge it and, only where the judge allows,
    /// stage its removal, in one call. [`Self::stale_leaf_removable`]
    /// decides; then [`Self::remove_member`] stages the commit, with the
    /// same leaf-key check. `None`, with nothing staged, when the leaf stays:
    /// a person's last leaf, a leaf whose credential does not verify, or this
    /// device's own leaf (the server never gets to remove the device that is
    /// asking).
    ///
    /// [`Self::remove_member`] does not ask the judge: it is the door for a
    /// removal a person decided on, which group policy alone governs, and
    /// receivers do not re-judge either. So a client that acts on a list the
    /// server handed it removes through this door, never the plain one.
    ///
    /// The judge and the staging are one step against the store (§A store
    /// two processes share): the judge reads the tree the removal is staged
    /// on, so a commit another process merged in between (one taking the
    /// person's other leaf) is judged, not raced.
    pub fn remove_stale_leaf(
        &mut self,
        group_id: &[u8],
        leaf_index: u32,
        expected_leaf_key: &[u8],
        revocation: &[u8],
        revoked_at: i64,
    ) -> Result<Option<crate::group::CommitBundle>> {
        self.synced(|client| {
            if client.own_leaf(group_id)? == leaf_index {
                return Ok(None);
            }
            if !client.stale_leaf_removable(group_id, leaf_index, revocation, revoked_at)? {
                return Ok(None);
            }
            client
                .remove_member(group_id, leaf_index, expected_leaf_key)
                .map(Some)
        })
    }

    /// Keep `signature`, already verified over `device_key`, for
    /// [`crate::identity::judge_message_sender`]'s caller to read, with the
    /// earlier of `revoked_at` and any time already kept for the key
    /// ([`earliest_revoked_at`]).
    fn note_peer_revocation(
        &mut self,
        device_key: &[u8],
        signature: &[u8],
        revoked_at: i64,
    ) -> Result<()> {
        let held = self.peachy_storage().peer_revocation(device_key)?;
        let at = held.as_ref().map_or(revoked_at, |(_, held_at)| {
            earliest_revoked_at(*held_at, revoked_at)
        });
        if held
            .as_ref()
            .is_some_and(|(held_signature, held_at)| held_signature == signature && *held_at == at)
        {
            return Ok(());
        }
        self.synced(|client| {
            client
                .peachy_storage()
                .note_peer_revocation(device_key, signature, at)?;
            Ok(())
        })
    }
}

/// Of two times the delivery service gave for one revocation (`0` for none),
/// the one kept: the earlier of two known times, else whichever is known.
/// A revocation's time only ever moves earlier, so an answer that came later
/// can refuse more of the key's messages and never fewer (module docs, §A
/// revoked key's messages).
pub(crate) fn earliest_revoked_at(held: i64, offered: i64) -> i64 {
    match (held > 0, offered > 0) {
        (true, true) => held.min(offered),
        (true, false) => held,
        _ => offered,
    }
}

/// The device key of the leaf at `leaf_index` when `revocation` verifies as
/// its own account's signed revocation of that key (rule 1), else `None`.
fn revoked_device_key(
    roster: &[RosterEntry],
    leaf_index: u32,
    revocation: &[u8],
) -> Option<Vec<u8>> {
    if revocation.is_empty() {
        return None;
    }
    let entry = roster.iter().find(|e| e.leaf_index == leaf_index)?;
    let identity = entry.identity.as_ref().ok()?;
    let account_key = identity.account_key?;
    verify_device_revocation(&account_key, &identity.device_key, revocation)
        .then(|| identity.device_key.to_vec())
}

/// One row of the account's device list, as [`install_revocation_targets`]
/// judges it: its id, the row it names as `twin_of` (empty for none), whether
/// this device vouches for its id and key on its approval chain, and the row
/// this device pinned as its `twin_of` when it first saw one.
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InstallRevocationRow {
    pub id: String,
    #[serde(default)]
    pub twin_of: String,
    #[serde(default)]
    pub vouched: bool,
    #[serde(default)]
    pub pinned_twin_of: Option<String>,
    /// When the server revoked the row, Unix seconds; 0 while it is live.
    /// Read only after a PIN restore (`restored_since`).
    #[serde(default)]
    pub revoked_at: i64,
    /// The row's signing key, as any stable token (the client's hex); empty
    /// for none. Read only after a PIN restore.
    #[serde(default)]
    pub key: String,
}

/// What [`install_revocation_targets`] is asked: the row the person removes
/// or denies (`named`), whether it is a denial of a pending device, the
/// revoking install's own row ids, and the device list. Or, with
/// `restored_since` set, the rows a PIN restore signed out (module docs,
/// §A PIN restore signs the others), `named` and `denying` unread.
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InstallRevocationRequest {
    pub named: String,
    #[serde(default)]
    pub denying: bool,
    /// The rows linked to `named` that the removal's confirmation named too:
    /// only these are followed (module docs, §Which keys a device signs).
    #[serde(default)]
    pub named_with: Vec<String>,
    #[serde(default)]
    pub own_device_ids: Vec<String>,
    #[serde(default)]
    pub rows: Vec<InstallRevocationRow>,
    /// When this device took the account key back from its PIN, Unix
    /// seconds less an hour for the server's clock; 0 when it did not.
    #[serde(default)]
    pub restored_since: i64,
    /// This install's own keys, and every key on its approval chain, in the
    /// rows' `key` form: never signed.
    #[serde(default)]
    pub own_keys: Vec<String>,
    /// The keys the registration that restored answered as signed out
    /// (module docs, §A PIN restore signs the others): only these are signed,
    /// and nothing while it is `None`.
    #[serde(default)]
    pub restore_snapshot: Option<Vec<String>>,
}

/// How long after `restored_since` (an hour before the restore on the
/// restoring device's clock) a row the restore signed out may have been
/// revoked: the restore's hour, and an hour of clock skew either way.
pub const RESTORE_SIGN_OUT_SECONDS: i64 = 3 * 60 * 60;

/// The rows a PIN restore signs (module docs, §A PIN restore signs the
/// others): every row the server revoked in the restore's band, with a key
/// that is none of this install's own or its chain's, on no live row of the
/// list, and in the snapshot the restoring registration's answer kept.
fn restore_revocation_targets(request: &InstallRevocationRequest) -> Vec<String> {
    let own_id = |id: &str| request.own_device_ids.iter().any(|own| own == id);
    let own_key = |key: &str| request.own_keys.iter().any(|own| own == key);
    let live_key = |key: &str| {
        request
            .rows
            .iter()
            .any(|row| row.revoked_at == 0 && row.key == key)
    };
    let restored = |key: &str| {
        request
            .restore_snapshot
            .as_ref()
            .is_some_and(|keys| keys.iter().any(|kept| kept == key))
    };
    request
        .rows
        .iter()
        .filter(|row| {
            row.revoked_at > 0
                && row.revoked_at >= request.restored_since
                && row.revoked_at
                    <= request
                        .restored_since
                        .saturating_add(RESTORE_SIGN_OUT_SECONDS)
                && !row.key.is_empty()
                && !own_id(&row.id)
                && !own_key(&row.key)
                && !live_key(&row.key)
                && restored(&row.key)
        })
        .map(|row| row.id.clone())
        .collect()
}

/// The rows whose keys a removal signs (module docs, §Which keys a device
/// signs), or a PIN restore's (§A PIN restore signs the others), in list
/// order. For a removal: the named row and the one row linked to it, each
/// only when this device vouches for it, the linked one only when the
/// confirmation named it (`named_with`) and on the link this device pinned,
/// and none at all for a denial, a removal that touches this install's own
/// rows, or a named row more than one row is pinned to. Never an id the
/// list names twice.
pub fn install_revocation_targets(request: &InstallRevocationRequest) -> Vec<String> {
    // The targets are ids, and the key a client signs is the one the list
    // gives the id, so a row that qualified must be the only row under its
    // id: a second one could carry a live device's key into the revocation.
    revocation_targets(request)
        .into_iter()
        .filter(|id| request.rows.iter().filter(|row| row.id == *id).count() == 1)
        .collect()
}

fn revocation_targets(request: &InstallRevocationRequest) -> Vec<String> {
    if request.restored_since > 0 {
        return restore_revocation_targets(request);
    }
    if request.denying || request.named.is_empty() {
        return Vec::new();
    }
    let Some(named) = request.rows.iter().find(|row| row.id == request.named) else {
        return Vec::new();
    };
    // Only the named row and the rows linked TO it. Never the row the named
    // one links to: an honest install links its MLS row to its plain row,
    // which holds no leaf and is never vouched, so following that direction
    // signs nothing an honest list needs, and a server that gave the named
    // row a link to a live device's row on first sight would have that
    // device revoked.
    let family: Vec<&InstallRevocationRow> = request
        .rows
        .iter()
        .filter(|row| row.id == named.id || (!row.twin_of.is_empty() && row.twin_of == named.id))
        .collect();
    let own = |id: &str| request.own_device_ids.iter().any(|own| own == id);
    if family.iter().any(|row| own(&row.id)) {
        return Vec::new();
    }
    // A link counts only as this device pinned it, and only for a row the
    // person saw named: the linked row must carry the same pin, and the
    // confirmation must have named it.
    let link_pinned = |child: &InstallRevocationRow| {
        child.twin_of == named.id
            && child.pinned_twin_of.as_deref() == Some(named.id.as_str())
            && request.named_with.iter().any(|id| id == &child.id)
    };
    // An install has one MLS row. Two rows pinned to one plain row means one
    // of the pins was the server's invention, and nothing says which: sign
    // nothing rather than guess.
    let pinned_children = request
        .rows
        .iter()
        .filter(|row| {
            row.id != named.id && row.pinned_twin_of.as_deref() == Some(named.id.as_str())
        })
        .count();
    if pinned_children > 1 {
        return Vec::new();
    }
    family
        .into_iter()
        .filter(|row| row.vouched)
        .filter(|row| row.id == named.id || link_pinned(row))
        .map(|row| row.id.clone())
        .collect()
}

/// One device-list row as a client hands it to
/// [`Client::sign_install_revocations`] and
/// [`Client::note_own_install_links`]: keys and signatures as lowercase hex.
#[derive(Debug, Clone, Default, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct ListedRow {
    id: String,
    #[serde(default)]
    twin_of: String,
    #[serde(default)]
    signing_key: String,
    #[serde(default)]
    approved_by_device_id: String,
    #[serde(default)]
    approval_signature: String,
    #[serde(default)]
    revoked: bool,
    #[serde(default)]
    revoked_at: i64,
}

#[derive(Debug, Clone, Default, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct SignRequest {
    #[serde(default)]
    named: String,
    #[serde(default)]
    denying: bool,
    #[serde(default)]
    named_with: Vec<String>,
    #[serde(default)]
    own_device_ids: Vec<String>,
    #[serde(default)]
    rows: Vec<ListedRow>,
    #[serde(default)]
    restored_since: i64,
}

/// Where [`read_document`] finds the rows, each of which must be an object.
#[derive(Clone, Copy)]
enum Shape {
    /// The document is the rows.
    Rows,
    /// An object, its rows (if any) under this field.
    Object(Option<&'static str>),
}

/// Read a document the way every other reader of it does: as JSON first, so
/// a field named twice counts once (its last time) and a number no JSON
/// value holds (`1e400`) refuses the document even in a field the core does
/// not read, and then only from objects. A struct reader would also read a
/// struct out of an array, field by field, which a client never writes and
/// no other reader would read alike.
fn read_document<T: serde::de::DeserializeOwned>(
    json: &str,
    what: &str,
    shape: Shape,
) -> Result<T> {
    let doc: serde_json::Value = serde_json::from_str(json)
        .map_err(|e| Error::invalid(format!("{what} is not JSON: {e}")))?;
    let rows_are_objects = |rows: &serde_json::Value| {
        rows.as_array()
            .is_none_or(|rows| rows.iter().all(serde_json::Value::is_object))
    };
    let shaped = match shape {
        Shape::Rows => doc.is_array() && rows_are_objects(&doc),
        Shape::Object(rows) => {
            doc.is_object() && rows.is_none_or(|field| doc.get(field).is_none_or(rows_are_objects))
        }
    };
    if !shaped {
        return Err(Error::invalid(format!("{what} is not in its shape")));
    }
    serde_json::from_value(doc).map_err(|e| Error::invalid(format!("{what} is not JSON: {e}")))
}

fn hex_bytes(hex: &str) -> Option<Vec<u8>> {
    if hex.is_empty() || !hex.len().is_multiple_of(2) {
        return None;
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(hex.get(i..i + 2)?, 16).ok())
        .collect()
}

impl Client {
    /// Pin the links the account's device list states (`twin_of`), first
    /// sight wins (module docs, §Which keys a device signs). `rows_json` is
    /// a JSON array of `{"id", "twinOf"}` objects, any other field ignored.
    /// Called on every read of the device list; answers how many links it
    /// pinned now. A row that is revoked, or whose ids are not well formed,
    /// pins nothing.
    pub fn note_own_install_links(&mut self, rows_json: &str) -> Result<u32> {
        let rows: Vec<ListedRow> = read_document(rows_json, "the device list", Shape::Rows)?;
        self.synced(|client| {
            let store = client.peachy_storage();
            let mut pinned = 0u32;
            for row in rows.iter().filter(|row| !row.revoked) {
                if row.twin_of.is_empty()
                    || row.twin_of == row.id
                    || !crate::credential::is_valid_id(&row.id)
                    || !crate::credential::is_valid_id(&row.twin_of)
                {
                    continue;
                }
                if store.note_own_install_link(&row.id, &row.twin_of)? {
                    pinned += 1;
                }
            }
            Ok(pinned)
        })
    }

    /// The account's revocations of the rows a removal signs, made with
    /// `account_key` (module docs, §Which keys a device signs). `request_json`
    /// is `{"named", "denying", "namedWith", "ownDeviceIds", "rows"}`, each row
    /// `{"id", "twinOf", "signingKey", "approvedByDeviceId",
    /// "approvalSignature", "revoked", "revokedAt"}` with the key and
    /// signature as hex and `revokedAt` in Unix seconds. With
    /// `"restoredSince"` (Unix seconds) it is a PIN restore's instead
    /// (§A PIN restore signs the others): `named` and `denying` are unread. Whether this
    /// device vouches for a row is [`Self::check_own_device_key`]'s verdict,
    /// and its pinned link the one [`Self::note_own_install_links`] wrote;
    /// neither is taken from the request. Answers a JSON array of
    /// `{"deviceId", "signature"}`, the signature as hex, empty when nothing
    /// may be signed. A restore signs only keys the restoring registration's
    /// answer kept ([`Self::note_restore_signed_out`]), and nothing before
    /// one is kept. An id the request lists twice is never signed. Every key
    /// it signs is recorded, and this device never approves it again
    /// ([`Self::sign_own_device_approval`]).
    pub fn sign_install_revocations(
        &mut self,
        account_key: &[u8],
        request_json: &str,
    ) -> Result<String> {
        let request: SignRequest = read_document(
            request_json,
            "the revocation request",
            Shape::Object(Some("rows")),
        )?;
        self.synced(|client| client.sign_install_revocations_now(account_key, &request))
    }

    fn sign_install_revocations_now(
        &self,
        account_key: &[u8],
        request: &SignRequest,
    ) -> Result<String> {
        let store = self.peachy_storage();
        let mut keys = std::collections::BTreeMap::new();
        let mut rows = Vec::with_capacity(request.rows.len());
        for row in &request.rows {
            let key = hex_bytes(&row.signing_key).filter(|k| k.len() == ED25519_PUBLIC_KEY_BYTES);
            let approval = hex_bytes(&row.approval_signature).unwrap_or_default();
            let vouched = !row.revoked
                && key.as_ref().is_some_and(|key| {
                    matches!(
                        self.check_own_device_key(
                            &row.id,
                            key,
                            &row.approved_by_device_id,
                            &approval,
                        ),
                        crate::own_devices::OwnDeviceVerdict::Known
                            | crate::own_devices::OwnDeviceVerdict::Approved
                    )
                });
            let pinned_twin_of = if crate::credential::is_valid_id(&row.id) {
                store.own_install_link(&row.id)?
            } else {
                None
            };
            let key_token = key
                .as_deref()
                .map(crate::own_devices::trust_hex)
                .unwrap_or_default();
            if let Some(key) = key {
                keys.insert(row.id.clone(), key);
            }
            rows.push(InstallRevocationRow {
                id: row.id.clone(),
                twin_of: row.twin_of.clone(),
                vouched,
                pinned_twin_of,
                // A revoked row the list gives no time for reads as revoked
                // before any restore.
                revoked_at: if row.revoked {
                    row.revoked_at.max(1)
                } else {
                    0
                },
                key: key_token,
            });
        }
        let mut own_device_ids = request.own_device_ids.clone();
        own_device_ids.push(self.identity().device_id.clone());
        let restoring = request.restored_since > 0;
        // A restore never signs a key on this device's chain, whatever id the
        // list puts it under: a device it let in since is one of them.
        let own_keys = if restoring {
            self.own_device_anchors()?
                .into_iter()
                .map(|(_, key)| crate::own_devices::trust_hex(&key))
                .collect()
        } else {
            vec![crate::own_devices::trust_hex(&self.identity().device_key)]
        };
        let restore_snapshot = if restoring {
            store.restore_snapshot(request.restored_since)?
        } else {
            None
        };
        let targets = install_revocation_targets(&InstallRevocationRequest {
            named: request.named.clone(),
            denying: request.denying,
            named_with: request.named_with.clone(),
            own_device_ids,
            rows,
            restored_since: request.restored_since,
            own_keys,
            restore_snapshot,
        });
        let mut out = Vec::with_capacity(targets.len());
        for id in targets {
            let Some(key) = keys.get(&id) else { continue };
            let signature = sign_device_revocation(account_key, key)?;
            // Never approved here again (`sign_own_device_approval`).
            store.note_own_key_signed_out(key)?;
            out.push(serde_json::json!({
                "deviceId": id,
                "signature": crate::own_devices::trust_hex(&signature),
            }));
        }
        Ok(serde_json::Value::Array(out).to_string())
    }

    /// Keep what the registration that restored this device from its PIN
    /// signed out (module docs, §A PIN restore signs the others):
    /// `request_json` is `{"restoredSince", "keys", "certificates",
    /// "accountIdentityKey"}`, `restoredSince` the restore's (Unix seconds,
    /// as [`Self::sign_install_revocations`] takes it), `keys` the 32-byte
    /// device keys the answer named, `certificates` the account's
    /// certificate of each, in the same order, and `accountIdentityKey` the
    /// account identity key this device derives from the account key it
    /// holds, all as hex. A client that holds an account identity
    /// ([`crate::ClientConfig::own_account_identity`]) verifies under that one
    /// and refuses a request naming another; one that holds none yet (a
    /// device certified by this very registration) verifies under the
    /// request's, which its caller derives from the account key it holds,
    /// never from a key the server published. Kept only when nothing is kept
    /// for that restore yet, so a later registration, or one after an
    /// approval closed the restore, changes nothing. Each kept key is never approved here again.
    /// A key whose certificate does not verify under that identity key (one
    /// the account never certified, which a server could have made up), this
    /// device's own key, and a key that is not 32 bytes, are dropped. Answers
    /// how many keys it kept now.
    pub fn note_restore_signed_out(&mut self, request_json: &str) -> Result<u32> {
        let request: RestoreSignedOut =
            read_document(request_json, "the restore's answer", Shape::Object(None))?;
        if request.restored_since <= 0 {
            return Err(Error::invalid("a restore's answer needs its restoredSince"));
        }
        self.synced(|client| {
            let store = client.peachy_storage();
            if store.restore_snapshot(request.restored_since)?.is_some() {
                return Ok(0);
            }
            let own = client.identity().device_key;
            let named = hex_bytes(&request.account_identity_key).unwrap_or_default();
            let identity = match client.held_account_identity() {
                Some(held) if named != held => {
                    return Err(Error::invalid(
                        "a restore's answer names another account identity key than the one this \
                         device holds",
                    ));
                }
                Some(held) => held.to_vec(),
                None => named,
            };
            let keys: Vec<Vec<u8>> = request
                .keys
                .iter()
                .zip(&request.certificates)
                .filter_map(|(key, certificate)| Some((hex_bytes(key)?, hex_bytes(certificate)?)))
                .filter(|(key, certificate)| {
                    key.len() == ED25519_PUBLIC_KEY_BYTES
                        && *key != own
                        && crate::account_identity::verify_account_device(
                            &identity,
                            key,
                            certificate,
                        )
                })
                .map(|(key, _)| key)
                .collect();
            let tokens: Vec<String> = keys
                .iter()
                .map(|key| crate::own_devices::trust_hex(key))
                .collect();
            store.note_restore_snapshot(request.restored_since, &tokens)?;
            for key in &keys {
                store.note_own_key_signed_out(key)?;
            }
            Ok(u32::try_from(keys.len()).unwrap_or(u32::MAX))
        })
    }

    /// This device's approval of the device `device_id` holding
    /// `signing_key` (`crate::device_link::device_approval_statement`), signed
    /// with this device's own key: the same 64 bytes
    /// [`crate::device_link::sign_device_approval`] makes from its seed.
    ///
    /// Refuses a key this device forgot ([`Self::forget_own_device`]),
    /// signed the account's revocation of, or took from a restore's answer as
    /// signed out: that device starts over under a new key instead (module
    /// docs, §A PIN restore signs the others). With `restored_since` above
    /// zero, the restore this device made, it also closes that restore: an
    /// empty snapshot is kept when none is yet, so no later read of the list
    /// can say what it signed out.
    pub fn sign_own_device_approval(
        &mut self,
        device_id: &str,
        signing_key: &[u8],
        restored_since: i64,
    ) -> Result<Vec<u8>> {
        let statement = crate::device_link::device_approval_statement(device_id, signing_key)?;
        self.synced(|client| {
            let store = client.peachy_storage();
            if store.own_key_signed_out(signing_key)?
                || client
                    .forgotten_own_keys()?
                    .iter()
                    .any(|key| key.as_slice() == signing_key)
            {
                return Err(Error::invalid(
                    "this device's key was signed out of the account: start that device over to approve it",
                ));
            }
            if restored_since > 0 {
                store.note_restore_snapshot(restored_since, &[])?;
            }
            client.sign_with_own_leaf(&statement)
        })
    }
}

/// [`Client::note_restore_signed_out`]'s request.
#[derive(Debug, Clone, Default, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct RestoreSignedOut {
    #[serde(default)]
    restored_since: i64,
    #[serde(default)]
    keys: Vec<String>,
    /// The account's certificate of each key, in the same order.
    #[serde(default)]
    certificates: Vec<String>,
    /// The account identity key the certificates are checked under.
    #[serde(default)]
    account_identity_key: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_revocation_verifies_under_the_derived_key_and_nothing_else() {
        let account = [7u8; 32];
        let device = crate::identity::signing_key_public_key(&[9u8; 32]).unwrap_or([0; 32]);
        let public =
            crate::account_identity::account_identity_public_key(&account).unwrap_or([0; 32]);
        let signature = sign_device_revocation(&account, &device).unwrap_or([0; 64]);
        assert!(verify_device_revocation(&public, &device, &signature));

        let other =
            crate::account_identity::account_identity_public_key(&[8u8; 32]).unwrap_or([0; 32]);
        assert!(!verify_device_revocation(&other, &device, &signature));
        let mut wrong_device = device;
        wrong_device[0] ^= 1;
        assert!(!verify_device_revocation(
            &public,
            &wrong_device,
            &signature
        ));
        assert!(!verify_device_revocation(
            &public,
            &device,
            &signature[..63]
        ));
        assert!(!verify_device_revocation(&public, &device, &[]));
    }

    #[test]
    fn a_revocation_is_not_a_certificate_and_a_certificate_is_not_a_revocation() {
        let account = [7u8; 32];
        let device = crate::identity::signing_key_public_key(&[9u8; 32]).unwrap_or([0; 32]);
        let public =
            crate::account_identity::account_identity_public_key(&account).unwrap_or([0; 32]);
        let certificate =
            crate::account_identity::sign_account_device(&account, &device).unwrap_or([0; 64]);
        assert!(!verify_device_revocation(&public, &device, &certificate));
        let revocation = sign_device_revocation(&account, &device).unwrap_or([0; 64]);
        assert!(!crate::account_identity::verify_account_device(
            &public,
            &device,
            &revocation
        ));
    }

    const DAY: i64 = 24 * 60 * 60;
    const NOW: i64 = 1_789_516_800;

    fn leaf(index: u32, actor: &str, iat: i64, exp: i64) -> RosterEntry {
        RosterEntry {
            leaf_index: index,
            identity: Ok(crate::identity::PeachyIdentity {
                actor_id: actor.into(),
                device_id: format!("device-{index}"),
                device_key: [u8::try_from(index).unwrap_or(0); 32],
                kid: "kid".into(),
                expires_at: exp,
                issued_at: iat,
                account_key: None,
            }),
            leaf_key: Vec::new(),
        }
    }

    /// A thirty-day credential, as the issuer mints them, lapsing at `exp`.
    fn honest(index: u32, actor: &str, exp: i64) -> RosterEntry {
        leaf(index, actor, exp - 30 * DAY, exp)
    }

    /// Both clocks reading `now`.
    fn at(now: i64) -> StaleLeafClock {
        StaleLeafClock {
            device: now,
            tree: now,
        }
    }

    #[test]
    fn a_last_leaf_does_not_go_on_a_lapse_until_its_grace_is_over() {
        let roster = [honest(0, "bo", NOW + 20 * DAY), honest(1, "cy", NOW - DAY)];
        assert!(!stale_leaf_removable(&roster, 1, &[], None, at(NOW)));
        assert!(!stale_leaf_removable(
            &roster,
            1,
            &[],
            None,
            at(NOW - DAY + 55 * DAY)
        ));
        assert!(stale_leaf_removable(
            &roster,
            1,
            &[],
            None,
            at(NOW - DAY + EXPIRED_LEAF_GRACE_SECONDS)
        ));
    }

    #[test]
    fn a_lapsed_device_goes_while_the_person_keeps_an_unlapsed_one() {
        let roster = [
            honest(0, "ada", NOW + 20 * DAY),
            honest(1, "ada", NOW - DAY),
            honest(2, "bo", NOW + 20 * DAY),
        ];
        assert!(stale_leaf_removable(&roster, 1, &[], None, at(NOW)));
    }

    #[test]
    fn a_lapsed_sibling_does_not_count_as_another_leaf() {
        // A dormant tablet whose credential lapsed does not let a live phone
        // go on the server's word.
        let roster = [
            honest(0, "ada", NOW + 20 * DAY),
            honest(1, "ada", NOW - DAY),
            honest(2, "bo", NOW + 20 * DAY),
        ];
        assert!(!stale_leaf_removable(&roster, 0, &[], None, at(NOW)));
        // With an unlapsed sibling, rule 3's drop applies.
        let roster = [
            honest(0, "ada", NOW + 20 * DAY),
            honest(1, "ada", NOW + 10 * DAY),
        ];
        assert_eq!(
            stale_leaf_removable(&roster, 0, &[], None, at(NOW)),
            !SIGNED_REVOCATIONS_ENFORCED
        );
    }

    #[test]
    fn a_sibling_under_another_account_key_does_not_count() {
        // The server can mint a leaf for the same actor id under a key the
        // account never held; it must not let the person's real leaf go.
        let mut minted = honest(0, "ada", NOW + 20 * DAY);
        if let Ok(identity) = &mut minted.identity {
            identity.account_key = Some([9; 32]);
        }
        let roster = [
            minted,
            honest(1, "ada", NOW - DAY),
            honest(2, "bo", NOW + 20 * DAY),
        ];
        assert_eq!(stale_leaf_rule(&roster, 1, &[], None, at(NOW)), None);
        assert!(!stale_leaf_removable(&roster, 1, &[], None, at(NOW)));
    }

    #[test]
    fn a_lapse_the_issuer_cut_short_is_no_evidence() {
        // Minted to lapse within the hour: the server's word, not a revocation.
        let roster = [
            honest(0, "ada", NOW + 20 * DAY),
            leaf(1, "ada", NOW - 2 * 3_600, NOW - 3_600),
        ];
        assert_eq!(
            stale_leaf_removable(&roster, 1, &[], None, at(NOW)),
            !SIGNED_REVOCATIONS_ENFORCED
        );
        assert!(!crate::identity::has_issuer_lifetime(
            NOW - 7_200,
            NOW - 3_600
        ));
        assert!(crate::identity::has_issuer_lifetime(NOW, NOW + 30 * DAY));
        assert!(!crate::identity::has_issuer_lifetime(
            NOW,
            NOW + 30 * DAY - 1
        ));
    }

    #[test]
    fn a_fast_clock_moves_no_lapse_earlier_than_the_tree() {
        // Cy's last leaf, a day past `exp`. This device's clock reads the
        // grace over; the group's newest leaf was issued today.
        let roster = [honest(0, "bo", NOW + 20 * DAY), honest(1, "cy", NOW - DAY)];
        let fast = StaleLeafClock {
            device: NOW - DAY + EXPIRED_LEAF_GRACE_SECONDS,
            tree: NOW,
        };
        assert_eq!(stale_leaf_rule(&roster, 1, &[], None, fast), None);
        assert!(!stale_leaf_removable(&roster, 1, &[], None, fast));
        // Once the tree has come as far, the grace is over on both.
        let both = StaleLeafClock {
            device: fast.device,
            tree: fast.device,
        };
        assert_eq!(
            stale_leaf_rule(&roster, 1, &[], None, both),
            Some(StaleLeafRule::PastGrace)
        );
    }

    #[test]
    fn a_fast_clock_lapses_no_device_the_tree_calls_live() {
        // Ada's laptop lapses tomorrow; a clock two days fast reads it lapsed.
        let roster = [
            honest(0, "ada", NOW + 20 * DAY),
            honest(1, "ada", NOW + DAY),
        ];
        let fast = StaleLeafClock {
            device: NOW + 2 * DAY,
            tree: NOW,
        };
        assert_eq!(
            stale_leaf_rule(&roster, 1, &[], None, fast),
            Some(StaleLeafRule::Sibling)
        );
    }

    #[test]
    fn a_slow_clock_keeps_no_lapsed_sibling_live() {
        // The tree is two days past the phone's `exp`; this device's clock
        // is behind it. The phone does not keep Ada a member.
        let roster = [
            honest(0, "ada", NOW - DAY),
            honest(1, "ada", NOW - 10 * DAY),
        ];
        let slow = StaleLeafClock {
            device: NOW - 2 * DAY,
            tree: NOW + DAY,
        };
        assert_eq!(stale_leaf_rule(&roster, 1, &[], None, slow), None);
    }

    #[test]
    fn a_credential_backdated_at_its_seat_is_no_evidence() {
        // The issuer stamped `iat` thirty-one days back, so the credential
        // claims its full lifetime, but it lapsed an hour after the device
        // minted the package it was seated from.
        let roster = [
            honest(0, "ada", NOW + 20 * DAY),
            leaf(1, "ada", NOW - 31 * DAY, NOW - 3_600),
        ];
        let minted = Some(NOW - 2 * 3_600);
        assert_eq!(
            stale_leaf_rule(&roster, 1, &[], minted, at(NOW)),
            Some(StaleLeafRule::Sibling)
        );
        // Minted with the refresh window still ahead of it, the lapse counts;
        // and so it does for a leaf renewed since its seat.
        let minted = Some(NOW - 3_600 - crate::identity::CREDENTIAL_REFRESH_WINDOW_SECONDS);
        assert_eq!(
            stale_leaf_rule(&roster, 1, &[], minted, at(NOW)),
            Some(StaleLeafRule::Lapsed)
        );
        assert_eq!(
            stale_leaf_rule(&roster, 1, &[], None, at(NOW)),
            Some(StaleLeafRule::Lapsed)
        );
    }

    fn row(id: &str, twin_of: &str, vouched: bool, pinned: Option<&str>) -> InstallRevocationRow {
        InstallRevocationRow {
            id: id.into(),
            twin_of: twin_of.into(),
            vouched,
            pinned_twin_of: pinned.map(Into::into),
            ..InstallRevocationRow::default()
        }
    }

    /// A row as a PIN restore reads it: revoked at `revoked_at` (0 live),
    /// with `key`.
    fn listed(id: &str, revoked_at: i64, key: &str) -> InstallRevocationRow {
        InstallRevocationRow {
            id: id.into(),
            revoked_at,
            key: key.into(),
            ..InstallRevocationRow::default()
        }
    }

    /// A restore whose registration answered every key the rows carry: what
    /// is left to the other rules.
    fn restored(since: i64, rows: Vec<InstallRevocationRow>) -> Vec<String> {
        let answered = rows.iter().map(|row| row.key.clone()).collect();
        install_revocation_targets(&InstallRevocationRequest {
            own_device_ids: vec!["phone".into(), "phone-mls".into()],
            own_keys: vec!["k-phone".into()],
            restored_since: since,
            rows,
            restore_snapshot: Some(answered),
            ..InstallRevocationRequest::default()
        })
    }

    #[test]
    fn a_pin_restore_signs_every_install_it_signed_out() {
        let rows = vec![
            listed("laptop-mls", NOW + 5, "k-laptop"),
            listed("tablet-mls", NOW + 5, "k-tablet"),
            listed("laptop", NOW + 5, ""),
            listed("phone-mls", 0, "k-phone"),
        ];
        assert_eq!(restored(NOW, rows), ["laptop-mls", "tablet-mls"]);
    }

    #[test]
    fn a_pin_restore_signs_no_key_it_must_not() {
        let rows = vec![
            // Revoked long before the restore: not what the person asked.
            listed("old-mls", NOW - DAY, "k-old"),
            // Revoked hours after it: a device linked since, the server's word.
            listed("later-mls", NOW + RESTORE_SIGN_OUT_SECONDS + 1, "k-later"),
            // A revoked row whose key a live row still carries.
            listed("twin-mls", NOW + 5, "k-live"),
            listed("live-mls", 0, "k-live"),
            // This install's own row, or its key under another id.
            listed("phone-mls", NOW + 5, "k-other"),
            listed("fake", NOW + 5, "k-phone"),
        ];
        assert!(restored(NOW, rows).is_empty());
        // And without a restore, a revoked row is never signed this way.
        let rows = vec![listed("laptop-mls", NOW + 5, "k-laptop")];
        assert!(restored(0, rows).is_empty());
    }

    #[test]
    fn a_pin_restore_signs_only_the_keys_its_registration_answered() {
        // The restoring registration answered the laptop; a key the server
        // lists revoked in the band later, a device linked since, it did not.
        let request = |snapshot: Option<Vec<String>>| InstallRevocationRequest {
            own_device_ids: vec!["phone".into(), "phone-mls".into()],
            own_keys: vec!["k-phone".into()],
            restored_since: NOW,
            rows: vec![
                listed("laptop-mls", NOW + 5, "k-laptop"),
                listed("tablet-mls", NOW + 600, "k-tablet"),
            ],
            restore_snapshot: snapshot,
            ..InstallRevocationRequest::default()
        };
        assert_eq!(
            install_revocation_targets(&request(Some(vec!["k-laptop".into()]))),
            ["laptop-mls"]
        );
        // An approval closed the restore before any answer was kept.
        assert!(install_revocation_targets(&request(Some(Vec::new()))).is_empty());
        // No answer kept: whatever a read the server timed lists, nothing.
        assert!(install_revocation_targets(&request(None)).is_empty());
    }

    /// A removal whose confirmation named every row linked to `named`:
    /// what is left to the other rules.
    fn targets(
        named: &str,
        denying: bool,
        own: &[&str],
        rows: Vec<InstallRevocationRow>,
    ) -> Vec<String> {
        let named_with = rows
            .iter()
            .filter(|row| row.twin_of == named)
            .map(|row| row.id.clone())
            .collect();
        install_revocation_targets(&InstallRevocationRequest {
            named: named.into(),
            denying,
            named_with,
            own_device_ids: own.iter().map(|s| (*s).to_string()).collect(),
            rows,
            ..InstallRevocationRequest::default()
        })
    }

    #[test]
    fn a_linked_row_is_signed_only_when_the_confirmation_named_it() {
        // The server pinned the iPad's MLS row under a row it made up, and
        // the screen hides it there. A confirmation that named only the
        // invented row signs nothing; one that named the iPad too signs it.
        let request = |named_with: Vec<String>| InstallRevocationRequest {
            named: "windows-pc".into(),
            named_with,
            own_device_ids: vec!["me".into(), "me-mls".into()],
            rows: vec![
                row("windows-pc", "", false, None),
                row("ipad-mls", "windows-pc", true, Some("windows-pc")),
                row("ipad", "", false, None),
            ],
            ..InstallRevocationRequest::default()
        };
        assert!(install_revocation_targets(&request(Vec::new())).is_empty());
        assert_eq!(
            install_revocation_targets(&request(vec!["ipad-mls".into()])),
            ["ipad-mls"]
        );
    }

    #[test]
    fn a_removal_signs_the_install_this_device_vouches_for() {
        let rows = vec![
            row("ipad", "", false, None),
            row("ipad-mls", "ipad", true, Some("ipad")),
            row("me", "", false, None),
            row("me-mls", "me", true, Some("me")),
        ];
        assert_eq!(
            targets("ipad", false, &["me", "me-mls"], rows.clone()),
            ["ipad-mls"]
        );
        // Named by its MLS row, the plain row needs no signature.
        assert_eq!(
            targets("ipad-mls", false, &["me", "me-mls"], rows),
            ["ipad-mls"]
        );
    }

    #[test]
    fn a_denial_signs_nothing() {
        let rows = vec![
            row("new", "", false, None),
            row("phone-mls", "new", true, Some("phone")),
        ];
        assert!(targets("new", true, &["me"], rows).is_empty());
    }

    #[test]
    fn nothing_is_signed_that_touches_this_install() {
        let rows = vec![
            row("fake", "me", false, None),
            row("me", "", false, None),
            row("me-mls", "me", true, Some("me")),
        ];
        assert!(targets("fake", false, &["me", "me-mls"], rows.clone()).is_empty());
        assert!(targets("me", false, &["me", "me-mls"], rows).is_empty());
    }

    #[test]
    fn a_linked_row_is_signed_only_on_the_link_this_device_pinned() {
        // The server names the phone's MLS row as a new row's twin.
        let rows = vec![
            row("fake", "", false, None),
            row("phone", "", false, None),
            row("phone-mls", "fake", true, Some("phone")),
        ];
        assert!(targets("fake", false, &["me"], rows).is_empty());
        // Or names the new row as the MLS half of the phone's plain row: the
        // phone's MLS row is a sibling, never reached.
        let rows = vec![
            row("fake", "phone", false, None),
            row("phone", "", false, None),
            row("phone-mls", "phone", true, Some("phone")),
        ];
        assert!(targets("fake", false, &["me"], rows).is_empty());
        // A link never pinned is never followed.
        let rows = vec![
            row("ipad", "", false, None),
            row("ipad-mls", "ipad", true, None),
        ];
        assert!(targets("ipad", false, &["me"], rows).is_empty());
    }

    #[test]
    fn a_key_this_device_does_not_vouch_for_is_never_signed() {
        let rows = vec![
            row("ipad", "", false, None),
            row("ipad-mls", "ipad", false, Some("ipad")),
        ];
        assert!(targets("ipad", false, &["me"], rows).is_empty());
    }

    #[test]
    fn the_wrong_lengths_are_refused() {
        assert!(sign_device_revocation(&[1u8; 31], &[2u8; 32]).is_err());
        assert!(sign_device_revocation(&[1u8; 32], &[2u8; 31]).is_err());
        assert!(device_revocation_statement(&[0u8; 33]).is_err());
    }
}
