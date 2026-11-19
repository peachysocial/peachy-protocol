// SPDX-License-Identifier: MIT
//! Who a leaf belongs to, and what has to be true before we believe it.
//!
//! An MLS leaf node proves "this key signed this". Only Peachy can say "and
//! this key is Ada's phone" (the server's credential issuer, header). This
//! module is the client-side half of that sentence: given a leaf and a set of
//! trusted server public keys fetched once from
//! `GET /healthz/device-credential-keys`, it either produces a
//! [`PeachyIdentity`] or names the reason it would not.
//!
//! ## The four checks, in order
//!
//! 1. **Shape** — [`crate::credential::DeviceCredential::parse`]. A `pdc1`
//!    and nothing else: any other prefix is refused here as `Malformed`,
//!    never read as a person.
//! 2. **`kid` is trusted** — the payload names a server key we hold. Unknown
//!    kid is its own reason, not a bad signature: after a server key rotation
//!    it means "fetch the key list again", and after nothing at all it means
//!    somebody minted their own. A key the server publishes for any use but
//!    `device` is never trusted (see [`TrustedServerKeys::from_published_json`]),
//!    so a credential signed by one lands here too.
//! 3. **Ed25519 over the bytes as they arrived** — never a re-serialization.
//! 4. **Clock, then leaf binding** — `exp` in the future, `iat` not
//!    absurdly ahead, and finally the one check that gives the whole thing its
//!    meaning: the leaf's signature key IS the credential's `device_key`.
//!
//! Step 4's last line is why a stolen credential buys nothing. The token is a
//! public artefact; anyone who has seen one of Ada's messages has seen hers.
//! Replayed onto an attacker's leaf it fails `LeafKeyMismatch`, because the
//! attacker cannot make their leaf sign with Ada's device key.
//!
//! ## What this deliberately does NOT do
//!
//! - **Revocation.** A credential carries none, and the checks here stay pure
//!   functions of the credential and a clock. The account's signed
//!   revocation of a device key is checked elsewhere ([`crate::revocation`]),
//!   and refuses that key's messages received after it through
//!   [`judge_message_sender`]. There is no revocation feed.
//! - **Key transparency.** There is none. Nothing outside the server binds an
//!   actor id to its account identity key, so the first key a device sees for
//!   a person is the one the server served; a later change is pinned and
//!   noticed, and warned about rather than refused
//!   (docs/identity.md §Security code changed).
//! - **Anything with a display name.** A [`PeachyIdentity`] carries the KEY
//!   layer only. Display names belong to the app, not this crate, and are
//!   never derived here (docs/identity.md §Accounts, sessions and
//!   devices).

use ed25519_dalek::{Signature, VerifyingKey};
use openmls::prelude::{Credential, CredentialType, KeyPackage, LeafNode, Member};
use std::collections::BTreeMap;

use crate::account_identity::verify_account_device;
use crate::credential::{decode_public_key, DeviceCredential, ED25519_PUBLIC_KEY_BYTES};
use crate::error::{CredentialRejection, Error, Result};

/// A verified leaf identity. Only [`PeachyIdentityProvider`] can mint one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeachyIdentity {
    /// `users.actor_id` — never shown to a person.
    pub actor_id: String,
    /// `devices.id`.
    pub device_id: String,
    /// The device's raw Ed25519 public key, which is also the leaf's signature
    /// key. Equality is checked, not assumed.
    pub device_key: [u8; ED25519_PUBLIC_KEY_BYTES],
    /// Which server key vouched for it.
    pub kid: String,
    /// Unix seconds. After this the leaf needs a fresh credential.
    pub expires_at: i64,
    /// Unix seconds, as the issuer signed it. What a group's TREE CLOCK is
    /// made of (crate::group, `tree_clock`): the one notion of "now" every
    /// member of a group computes identically, because it is read off signed
    /// leaves rather than off anybody's wall.
    pub issued_at: i64,
    /// The account identity key that signed for this device
    /// ([`crate::account_identity`]), already checked to have signed
    /// `device_key`. `None` for a device its account has not let in: such a
    /// credential opens this device's own client, and is refused as
    /// [`CredentialRejection::NotApproved`] everywhere a PEER's leaf is
    /// believed.
    pub account_key: Option<[u8; ED25519_PUBLIC_KEY_BYTES]>,
}

/// The one key use this build trusts.
///
/// `GET /healthz/device-credential-keys` names a `use` per key. Every key the
/// server publishes today is `device`, and a list without the field is a list
/// from before the field existed — also all device keys. Any OTHER use — one a
/// newer server invents — is dropped rather than guessed at, so credentials under
/// it read as [`CredentialRejection::UnknownKid`]: a key published to say
/// something else never vouches for a person's device.
pub(crate) const DEVICE_KEY_USE: &str = "device";

/// The server public keys a verifier trusts, by `kid`.
///
/// Fetched once from `GET /healthz/device-credential-keys` and cached; the list
/// holds the current device key and every retired key the server still
/// publishes, so credentials minted before a
/// rotation keep checking out for their whole lifetime
/// (docs/identity.md §Rotating the server key).
#[derive(Debug, Clone, Default)]
pub struct TrustedServerKeys {
    keys: BTreeMap<String, VerifyingKey>,
}

impl TrustedServerKeys {
    pub fn new() -> Self {
        Self::default()
    }

    /// Trust one raw 32-byte Ed25519 public key under `kid`.
    pub fn insert(
        &mut self,
        kid: impl Into<String>,
        public_key: &[u8; ED25519_PUBLIC_KEY_BYTES],
    ) -> Result<()> {
        let verifying = VerifyingKey::from_bytes(public_key)
            .map_err(|_| Error::invalid("server public key is not a valid Ed25519 point"))?;
        self.keys.insert(kid.into(), verifying);
        Ok(())
    }

    /// Build the set straight from the JSON `GET /healthz/device-credential-keys`
    /// returns:
    /// `{"enabled":bool,"keys":[{"kid","publicKey","current","use"}]}`.
    ///
    /// Shaped to that response on purpose. The alternative — a caller picking
    /// the fields apart in Swift, Kotlin and TypeScript — is three chances to
    /// drop the previous keys and three ways to be surprised by a rotation.
    ///
    /// A key whose `use` is present and not `device` is DROPPED — see
    /// `DEVICE_KEY_USE`. That is the safe default any future use needs:
    /// never widen what a key may vouch for
    /// by guessing.
    pub fn from_published_json(json: &str) -> Result<Self> {
        #[derive(serde::Deserialize)]
        struct Published {
            #[serde(default)]
            keys: Vec<PublishedKey>,
        }
        #[derive(serde::Deserialize)]
        struct PublishedKey {
            kid: String,
            #[serde(rename = "publicKey")]
            public_key: String,
            /// Absent on every list published before the field existed, and
            /// those were all device keys — see [`DEVICE_KEY_USE`].
            #[serde(rename = "use")]
            key_use: Option<String>,
        }

        // Read as a document first, as `server_keys_pinned_json` reads it, so
        // the two agree on what the list says: a field named twice counts
        // once, its last time, and only an object is a list or a key (serde
        // would also read a struct out of an array, which the narrowing door
        // then would not narrow).
        let doc: serde_json::Value = serde_json::from_str(json)
            .map_err(|err| Error::invalid(format!("published key list is not JSON: {err}")))?;
        if !doc.is_object() {
            return Err(Error::invalid("published key list is not a JSON object"));
        }
        if let Some(keys) = doc.get("keys").and_then(|keys| keys.as_array()) {
            if keys.iter().any(|key| !key.is_object()) {
                return Err(Error::invalid(
                    "a key in the published key list is not a JSON object",
                ));
            }
        }
        let parsed: Published = serde_json::from_value(doc)
            .map_err(|err| Error::invalid(format!("published key list is not JSON: {err}")))?;
        let mut set = Self::new();
        for key in parsed.keys {
            if !key
                .key_use
                .as_deref()
                .is_none_or(|name| name == DEVICE_KEY_USE)
            {
                // Not a device key. Dropped rather than guessed at.
                continue;
            }
            let raw = decode_public_key(&key.public_key)?;
            set.insert(key.kid, &raw)?;
        }
        Ok(set)
    }

    pub fn len(&self) -> usize {
        self.keys.len()
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// Whether `kid` is trusted.
    pub fn contains(&self, kid: &str) -> bool {
        self.keys.contains_key(kid)
    }

    fn get(&self, kid: &str) -> Option<&VerifyingKey> {
        self.keys.get(kid)
    }

    /// The raw public key trusted under `kid`.
    pub fn public_key(&self, kid: &str) -> Option<[u8; ED25519_PUBLIC_KEY_BYTES]> {
        self.keys.get(kid).map(|key| key.to_bytes())
    }

    /// Every trusted `(kid, raw public key)`, by kid.
    pub fn iter(&self) -> impl Iterator<Item = (&str, [u8; ED25519_PUBLIC_KEY_BYTES])> {
        self.keys
            .iter()
            .map(|(kid, key)| (kid.as_str(), key.to_bytes()))
    }
}

/// What "now" is. A trait because a fixture must be able to pin it: an expiry
/// test written against the wall clock is a test that starts failing on a date
/// nobody chose.
pub trait Clock: Send + Sync + std::fmt::Debug {
    /// Unix seconds.
    fn now_unix(&self) -> i64;
    /// Unix milliseconds: the live call lane's stamps
    /// (`crate::call::replay`). A clock that only knows seconds answers its
    /// second's first millisecond.
    fn now_unix_ms(&self) -> i64 {
        self.now_unix().saturating_mul(1000)
    }
    /// Milliseconds on a MONOTONIC clock, from an arbitrary origin: for spans
    /// this device measures alone (a call's rotation due time and the grace
    /// it keeps a peer's old key for), which setting the wall clock must not
    /// move. Never stored, and never compared across devices or processes.
    /// The default reads a process-wide [`std::time::Instant`], which traps
    /// on `wasm32-unknown-unknown`: a clock for a browser overrides it.
    fn monotonic_ms(&self) -> u64 {
        process_monotonic_ms()
    }
}

/// The farthest the server's clock may be taken to be from this device's:
/// one day. A device whose clock is off by more (a wrong date, not a wrong
/// time zone) still has its call stamps refused; and a server, which states
/// the time, can move a device's agreed clock by no more than this.
pub const SERVER_CLOCK_OFFSET_MAX_MS: i64 = 86_400_000;

static SERVER_CLOCK_OFFSET_MS: std::sync::atomic::AtomicI64 = std::sync::atomic::AtomicI64::new(0);

/// Tell the core how far the server's clock is ahead of this device's, in
/// milliseconds (negative when behind), as the client last measured it from
/// a reply that carries the server's time (`FetchMailbox.server_time`).
/// Process-wide: every [`crate::Client`] in the process stamps and judges
/// the time-bound frames other devices check against their own clocks, the
/// live call lane's and typing's, on this device's clock plus the offset
/// (docs/calls.md §The live lane's replay window). Clamped to
/// ±[`SERVER_CLOCK_OFFSET_MAX_MS`]. Credential checks stay on the device's
/// own clock.
pub fn set_server_clock_offset_ms(offset_ms: i64) {
    let clamped = offset_ms.clamp(-SERVER_CLOCK_OFFSET_MAX_MS, SERVER_CLOCK_OFFSET_MAX_MS);
    SERVER_CLOCK_OFFSET_MS.store(clamped, std::sync::atomic::Ordering::Relaxed);
}

/// The offset [`set_server_clock_offset_ms`] last set; 0 until then.
pub fn server_clock_offset_ms() -> i64 {
    SERVER_CLOCK_OFFSET_MS.load(std::sync::atomic::Ordering::Relaxed)
}

/// Milliseconds since this process first asked, on [`std::time::Instant`].
fn process_monotonic_ms() -> u64 {
    static ORIGIN: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    let origin = *ORIGIN.get_or_init(std::time::Instant::now);
    u64::try_from(origin.elapsed().as_millis()).unwrap_or(u64::MAX)
}

/// The system clock.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_unix(&self) -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            // Before 1970 the only honest answer is "the clock is wrong", and
            // every credential is then not-yet-valid. Saturating to 0 makes
            // that the outcome instead of a panic.
            .unwrap_or(0)
    }

    fn now_unix_ms(&self) -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
            .unwrap_or(0)
    }
}

/// A clock pinned to one instant. For fixtures and for replaying a captured
/// session at the time it happened.
#[derive(Debug, Clone, Copy)]
pub struct FixedClock(pub i64);

impl Clock for FixedClock {
    fn now_unix(&self) -> i64 {
        self.0
    }
}

/// How far ahead of us an issuer's clock may be before `iat` reads as a
/// forgery. Matches the 60s the server allows itself.
pub const CLOCK_SKEW_SECONDS: i64 = 60;

/// The longest a credential may claim to live, `exp - iat`: thirty-one days.
///
/// The issuer's real number, not a guess. `issueCredential` in
/// the server's credential issuer floors `iat` to a UTC midnight and rounds
/// `exp` UP to the UTC midnight at or after issue + `CREDENTIAL_LIFETIME_MS`
/// (thirty days), so `exp - iat` is at least thirty days and at most
/// thirty-one; the rotation window there waits out the same thirty-one. No
/// clock skew is added: both ends are stamped by one issuer from one reading
/// of its clock, so there is nothing for a skew to be between.
///
/// It is what caps the tree clock from above (docs/identity.md §A
/// received commit is judged on the tree clock). The tree clock is a max over
/// signed `iat`s, and nothing else bounded how far ahead an `iat` could be
/// with an `exp` to match; one such leaf pushed every other leaf past its
/// grace on that clock, after which every commit was refused and membership
/// froze for good. A credential longer than this is refused as
/// [`CredentialRejection::ImplausibleLifetime`], and so is one whose `iat` is
/// after its `exp`.
///
/// Changing `CREDENTIAL_LIFETIME_MS` on the server means changing this in the
/// same commit, or every leaf the new server issues is refused here.
pub const MAX_CREDENTIAL_LIFETIME_SECONDS: i64 = 31 * 24 * 60 * 60;

/// The SHORTEST lifetime the issuer gives (the thirty days before `exp` is
/// rounded up to midnight), which is the half of the bound on a commit's
/// clock jump that an honest newest leaf can rely on
/// ([`MAX_TREE_CLOCK_JUMP_SECONDS`]).
pub const MIN_CREDENTIAL_LIFETIME_SECONDS: i64 = 30 * 24 * 60 * 60;

/// Whether a credential issued at `iat` and expiring at `exp` lived at least
/// the issuer's shortest lifetime ([`MIN_CREDENTIAL_LIFETIME_SECONDS`]), as
/// every credential an honest issuer signs does.
///
/// Not a refusal at every credential check: a credential too short to be
/// honest still identifies its leaf, and refusing it would only make the
/// leaf unidentifiable sooner. It is what a LAPSE must pass to count as
/// evidence (`crate::revocation`, rule 2): the server is the issuer, and a
/// credential it minted to lapse within the hour is no sign that its device
/// was revoked.
pub fn has_issuer_lifetime(iat: i64, exp: i64) -> bool {
    exp.saturating_sub(iat) >= MIN_CREDENTIAL_LIFETIME_SECONDS
}

/// How far past the tree clock taken BEFORE a commit any leaf the commit
/// brings in may claim its `iat`: the issuer's shortest lifetime plus
/// [`EXPIRED_LEAF_GRACE_SECONDS`] minus [`RENEWAL_CUTOFF_MARGIN_SECONDS`],
/// eighty-five days, exclusive.
///
/// The group's newest person leaf has `iat` equal to the tree clock and an
/// `exp` at least thirty days after it, and its own device stops renewing
/// ([`Client::leaf_credential_past_grace`](crate::group::Client::leaf_credential_past_grace))
/// a day BEFORE its grace ends. So after a jump of less than this that leaf is
/// still short of its renewal cutoff on the new clock and can RENEW — the group
/// always keeps one member who can renew, which is the whole of what the bound
/// is for. Eighty-six days (the first bound, before the margin was counted) let
/// a forged leaf at the clock plus 85.9 days put that leaf past its cutoff, and
/// every member's; nobody could renew, and membership froze for the ~55 days
/// until the forger stepped again.
///
/// Honest commits sit inside it: a committer that is not lapsed brings in
/// nothing issued later than its own `exp`, at most thirty-one days past the
/// clock. A lapsed one renewing stops a day short of its grace, which for a
/// thirty-one-day leaf in a group nobody else has touched for eighty-five days
/// is one day past this bound — its renewal is refused, it reads as past its
/// grace a day later and asks for a seat (docs/identity.md §A received
/// commit is judged on the tree clock).
pub const MAX_TREE_CLOCK_JUMP_SECONDS: i64 =
    MIN_CREDENTIAL_LIFETIME_SECONDS + EXPIRED_LEAF_GRACE_SECONDS - RENEWAL_CUTOFF_MARGIN_SECONDS;

/// How close to its `exp` a device's OWN leaf credential may get, in a group,
/// before the device hands that group a fresh one
/// ([`Client::credential_refresh_due`](crate::group::Client::credential_refresh_due),
/// docs/identity.md §Refreshing a seated leaf).
///
/// Ten days of a thirty-day credential, so a device renews each group's leaf
/// at most once every ~twenty days. Both edges matter:
///
/// - **Not later.** The refresh is a commit, and every receiver validates the
///   committer's CURRENT leaf credential before it reads anything else, so a
///   refresh that lands after `exp` depends on the grace
///   ([`EXPIRED_LEAF_GRACE_SECONDS`]) and on every receiver being a build that
///   has one. Ten days is a person opening the app once in a ten-day stretch,
///   which is the realistic floor for someone who is using a messenger at all.
/// - **Not earlier.** Every refresh spends an epoch: a commit every member
///   applies, and one more epoch between a message in flight and the
///   [`RETAINED_PAST_EPOCHS`](crate::group::RETAINED_PAST_EPOCHS) it can
///   still open from. Refreshing on every open — `RegisterDevice` moves `exp`
///   forward a day at a time — would be one commit per device per group per
///   day, for nothing the leaf rotation does not already do.
pub const CREDENTIAL_REFRESH_WINDOW_SECONDS: i64 = 10 * 24 * 60 * 60;

/// How long a credential that has EXPIRED on a leaf already seated in a group
/// is still believed, for two things only: an application message from that
/// leaf, and a commit whose sole effect is that leaf handing in a fresh
/// credential for the same actor, device and key
/// (docs/identity.md §Refreshing a seated leaf).
///
/// Eight weeks, which outlasts the delivery service's retention (a mailbox
/// entry is kept 30 days, docs/delivery.md §Retention), and that is
/// the reason for the number: a device that can still catch up on the ratchet
/// through the server — asleep for less than the retention — can also still
/// catch its credential up, so "away too long" is ONE line for a device and
/// not two. Past the retention the device needs a fresh Welcome anyway.
///
/// What it does not widen, deliberately:
///
/// - **Adds stay strict where they are made.** A stranger's first entry into
///   a group is where a credential is believed for the first time, and the
///   member BUILDING the Add refuses an expired key package exactly as before.
///   Members receiving that commit apply the grace (below), because the
///   package was checked once already, on the one clock that mattered.
/// - **A lapsed leaf may renew itself, and seal or build nothing else.**
///   Its own client refuses to seal an application message once its own
///   wall is within [`CLOCK_SKEW_SECONDS`] of the leaf's `exp`, and to build
///   an add, a remove, a replace, a key rotation or a rename from a lapsed
///   leaf; standalone proposals from one are refused by every receiver. What
///   it sent while live is still read through the grace.
/// - **The roster follows the same line.** [`crate::group::Client::roster`]
///   reads a person's lapsed leaf as identified, with its past `expires_at`
///   showing, until the grace runs out — because every client evicts a leaf
///   it cannot identify, and evicting a leaf that may still renew itself,
///   and whose history is still read, is the conversation breaking, not a
///   repair.
///
/// What it costs: an expired credential was the only OFFLINE end to a
/// device's voice in a group, short of a signed revocation the reader holds
/// ([`judge_message_sender`]). It still ends what the device can say: a
/// message received after its `exp`, or sealed where the tree clock has
/// passed it, is refused as new. What the grace keeps for eight more weeks
/// is its seat, its history and its renewal. That is a smaller loss than it reads: an expired leaf has
/// always gone on RECEIVING everything — MLS membership is the ability to
/// decrypt — so the check being relaxed was never what kept a lost device out
/// of a conversation. Removing its leaf is — and every client's reconcile
/// removes the leaf of a device the directory says is REVOKED, whatever its
/// credential says
/// (docs/identity.md §Revocation reaches a seated leaf through the
/// roster), so the grace no longer extends a revoked device's seat.
///
/// **Commits a member RECEIVES are judged with the grace throughout**, and
/// that is a fork rule rather than a leniency: a receiver checks a commit at
/// the moment IT processes it, which for a phone that was offline can be days
/// after every other member merged it. A strict clock check there refused, on
/// catch-up, a commit that was perfectly valid when it was made — and a
/// refused commit is a member stuck on the old epoch forever. So the sender,
/// the leaf an update path installs, a by-reference Update's leaf and every
/// key package a commit adds are all accepted up to the grace when the commit
/// is someone else's — the grace, and whether the committer has lapsed at
/// all, measured on the group's tree clock rather than on anybody's wall
/// (docs/identity.md §A received commit is judged on the tree clock). The strict checks stay where one
/// clock decides: the committer's own, when it builds the commit.
pub const EXPIRED_LEAF_GRACE_SECONDS: i64 = 56 * 24 * 60 * 60;

/// How long before the grace runs out a device STOPS renewing its own lapsed
/// leaf and asks for a seat instead
/// ([`Client::leaf_credential_past_grace`](crate::group::Client::leaf_credential_past_grace)).
///
/// A renewal built one second before the grace ends reaches a receiver whose
/// clock is a minute ahead — or who processes it an hour later — one second
/// after, and that receiver refuses what the others took: a fork, at exactly
/// the edge nobody tests. A day of margin makes the sender's cutoff and every
/// receiver's cutoff two different lines with a day between them.
pub const RENEWAL_CUTOFF_MARGIN_SECONDS: i64 = 24 * 60 * 60;

/// What a receiver does with an application message whose tag and signature
/// held, by its sender's credential and revocation
/// ([`judge_message_sender`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageSenderVerdict {
    /// Read it: the sender's credential is live on the reader's wall.
    Read,
    /// Read it inside the grace: the credential has lapsed on the reader's
    /// wall, by less than [`EXPIRED_LEAF_GRACE_SECONDS`], and the message is
    /// history: received before the sender's `exp`, and not sealed in an
    /// epoch whose tree clock is past it.
    ReadLapsed,
    /// Refuse it as [`CredentialRejection::Expired`]: read past the grace,
    /// or a lapsed sender's NEW message, received at or after its `exp` or
    /// sealed in an epoch whose tree clock is at or past it.
    ///
    /// [`CredentialRejection::Expired`]: crate::error::CredentialRejection::Expired
    Expired,
    /// Refuse it without a word: the sender's own account signed a
    /// revocation of its key, and nothing places the message's receipt
    /// before the revocation took effect.
    Revoked,
}

/// THE MESSAGE RULE: whether a receiver reads an application message from a
/// sender whose credential has `expires_at`
/// (docs/identity.md §A revoked leaf's messages, §A lapsed leaf's
/// new messages).
///
/// - `reader_now`: this reader's wall. Past `exp` plus
///   [`EXPIRED_LEAF_GRACE_SECONDS`] nothing from the leaf is read; inside it
///   the message is read and marked lapsed.
/// - `received_at`: the second the delivery service received the message
///   (the mailbox envelope's `received_at`), or `0` when the caller does not
///   know it.
/// - `sealed_tree_clock`: the tree clock of the epoch the message was sealed
///   in, when that is the epoch the reader's group is in now; `None` for a
///   message from an epoch the group has left.
/// - `revoked_at`: `Some` when this reader holds a revocation of the
///   sender's device key, signed by the sender's own account identity key
///   and verified by the caller, carrying the second the delivery service
///   says the revocation took effect, or `0` when it did not say. `None`
///   when the reader holds none.
///
/// A revoked sender's message is refused unless both times are known and
/// it was received strictly before the revocation. What the device sent
/// while it was still the account's is read, however late; anything the
/// reader cannot place before the revocation is refused, an unknown time
/// counting as after. Only messages: whether one member read a message forks
/// no state, so a verdict that differs between members, by who has heard of
/// the revocation, is safe here and nowhere else (commits and proposals are
/// judged on the tree clock alone).
///
/// A lapsed sender's message is NEW, and refused as
/// [`MessageSenderVerdict::Expired`], when the delivery service received it at or after `exp`, whatever epoch
/// it was sealed in, or, when the reader does not know the receive time,
/// when the reader's wall is at or past `exp`. It is new too when it was
/// sealed in the current epoch and that epoch's tree clock is at or past
/// `exp`. That rule adds what the receive time cannot: the tree clock is the
/// issuer's signed `iat`s in a tree every member holds alike, fixed before
/// the message was sealed, so a delivery service that backdates a receive
/// time still cannot have a message sealed after a member's renewal past
/// `exp` read as history. Every leaf in an epoch's tree was minted before the
/// epoch began, so an epoch's tree clock is never later than a message
/// sealed in it, and a message sealed and received while the credential was
/// live is never new.
pub fn judge_message_sender(
    expires_at: i64,
    reader_now: i64,
    received_at: i64,
    revoked_at: Option<i64>,
    sealed_tree_clock: Option<i64>,
) -> MessageSenderVerdict {
    if let Some(revoked_at) = revoked_at {
        let received_before = received_at > 0 && revoked_at > 0 && received_at < revoked_at;
        if !received_before {
            return MessageSenderVerdict::Revoked;
        }
    }
    if reader_now >= expires_at.saturating_add(EXPIRED_LEAF_GRACE_SECONDS) {
        return MessageSenderVerdict::Expired;
    }
    let received = if received_at > 0 {
        received_at
    } else {
        reader_now
    };
    if received >= expires_at || sealed_tree_clock.is_some_and(|clock| clock >= expires_at) {
        return MessageSenderVerdict::Expired;
    }
    if reader_now >= expires_at {
        return MessageSenderVerdict::ReadLapsed;
    }
    MessageSenderVerdict::Read
}

/// Validates leaf credentials against a trusted server key set.
#[derive(Debug)]
pub struct PeachyIdentityProvider {
    trusted: TrustedServerKeys,
    clock: Box<dyn Clock>,
    skew_seconds: i64,
}

impl PeachyIdentityProvider {
    /// A provider on the system clock.
    pub fn new(trusted: TrustedServerKeys) -> Self {
        Self {
            trusted,
            clock: Box::new(SystemClock),
            skew_seconds: CLOCK_SKEW_SECONDS,
        }
    }

    /// A provider on a clock of your choosing.
    pub fn with_clock(trusted: TrustedServerKeys, clock: Box<dyn Clock>) -> Self {
        Self {
            trusted,
            clock,
            skew_seconds: CLOCK_SKEW_SECONDS,
        }
    }

    pub fn trusted_keys(&self) -> &TrustedServerKeys {
        &self.trusted
    }

    /// Validate a bare token against a leaf signature key.
    ///
    /// `leaf_signature_key` is the leaf's signature key as MLS carries it. For
    /// ciphersuite 0x004F (Ed25519 signatures, like suite 1 before it) that is
    /// the raw 32-byte Ed25519 public key, which is what
    /// the credential binds — so the comparison is a byte equality and not a
    /// re-encoding. A future suite whose signature key is not the device key's
    /// own encoding would need this line rewritten, which is why it is one line
    /// and not spread through the crate.
    pub fn validate_token(
        &self,
        token: &[u8],
        leaf_signature_key: &[u8],
    ) -> Result<PeachyIdentity> {
        self.validate_token_with_grace(token, leaf_signature_key, 0)
            .map(|(identity, _lapsed)| identity)
    }

    /// [`Self::validate_token`], except that a credential which EXPIRED less
    /// than `grace_seconds` ago is accepted and reported as lapsed (`true`).
    ///
    /// Every other check is exactly as strict: an unknown kid, a bad signature, a token from the future or a leaf key the token
    /// does not bind are refused whatever the grace. Only the clock's upper
    /// edge moves, and only for the caller that asked — see
    /// [`EXPIRED_LEAF_GRACE_SECONDS`] for the one caller that does, and why
    /// it is not a door a stranger comes in by.
    pub fn validate_token_with_grace(
        &self,
        token: &[u8],
        leaf_signature_key: &[u8],
        grace_seconds: i64,
    ) -> Result<(PeachyIdentity, bool)> {
        self.validate_token_inner(token, leaf_signature_key, grace_seconds, true, None)
    }

    /// [`Self::validate_token_with_grace`] for a credential that is ALREADY
    /// SEATED, or arrives inside a commit another member built: the same
    /// checks, except that an `iat` in this reader's future is not refused.
    ///
    /// The not-before check guards the moment a credential is first believed,
    /// and there it stays (an Add, a key package's identity, this device's own
    /// credential). On a received leaf it is a fork: a renewal leaf is minted
    /// seconds before it is committed, so every member whose clock runs more
    /// than [`CLOCK_SKEW_SECONDS`] slow refused the commit everybody else
    /// merged, and stayed on the old epoch for good. Dropping it costs nothing
    /// real. `iat` is signed by the issuer, and the issuer could as easily sign
    /// `iat = now`, so a future `iat` is evidence of a skewed clock and never of
    /// a forgery; and what a renewal may claim is bounded anyway, by the rule
    /// that its `exp` is no earlier than the leaf it replaces
    /// (`check_renewed_leaf` in crate::group). Every other refusal — kid,
    /// signature, leaf binding, expiry past the grace — is unchanged.
    pub fn validate_seated_credential(
        &self,
        credential: &Credential,
        leaf_signature_key: &[u8],
        grace_seconds: i64,
    ) -> Result<(PeachyIdentity, bool)> {
        self.validate_seated_inner(credential, leaf_signature_key, grace_seconds, None)
    }

    /// [`Self::validate_seated_credential`], with the expiry judged at `at`
    /// rather than on this provider's clock.
    ///
    /// The door every verdict on a received COMMIT or PROPOSAL goes through,
    /// with `at` the group's tree clock (crate::group, `tree_clock`). A
    /// verdict that changes a group's state must come out the same for every
    /// member, and a member's wall clock is the one input that is different
    /// for each of them — a receiver catching up a week late, or running a
    /// day slow, would otherwise refuse the commit the rest merged and sit on
    /// the old epoch for good. Every other check is unchanged.
    pub fn validate_seated_credential_at(
        &self,
        credential: &Credential,
        leaf_signature_key: &[u8],
        grace_seconds: i64,
        at: i64,
    ) -> Result<(PeachyIdentity, bool)> {
        self.validate_seated_inner(credential, leaf_signature_key, grace_seconds, Some(at))
    }

    fn validate_seated_inner(
        &self,
        credential: &Credential,
        leaf_signature_key: &[u8],
        grace_seconds: i64,
        at: Option<i64>,
    ) -> Result<(PeachyIdentity, bool)> {
        if credential.credential_type() != CredentialType::Basic {
            return Err(CredentialRejection::WrongCredentialType.into());
        }
        let basic = openmls::prelude::BasicCredential::try_from(credential.clone())
            .map_err(|_| CredentialRejection::WrongCredentialType)?;
        let (identity, lapsed) = self.validate_token_inner(
            basic.identity(),
            leaf_signature_key,
            grace_seconds,
            false,
            at,
        )?;
        Ok((require_approved(identity)?, lapsed))
    }

    fn validate_token_inner(
        &self,
        token: &[u8],
        leaf_signature_key: &[u8],
        grace_seconds: i64,
        check_not_before: bool,
        at: Option<i64>,
    ) -> Result<(PeachyIdentity, bool)> {
        let credential = DeviceCredential::parse(token)?;
        let payload = credential.payload();

        let verifying = self
            .trusted
            .get(&payload.kid)
            .ok_or(CredentialRejection::UnknownKid)?;

        let signature = Signature::from_bytes(credential.signature());
        verifying
            .verify_strict(credential.signed_bytes(), &signature)
            .map_err(|_| CredentialRejection::BadSignature)?;

        let now = at.unwrap_or_else(|| self.clock.now_unix());
        let lapsed = now >= payload.exp;
        if lapsed && now >= payload.exp.saturating_add(grace_seconds.max(0)) {
            return Err(CredentialRejection::Expired.into());
        }
        if check_not_before && now + self.skew_seconds < payload.iat {
            return Err(CredentialRejection::NotYetValid.into());
        }
        // After the clock checks, so a credential that is simply old still
        // answers `expired` (mls/fixtures/credentials.json pins that order),
        // and before the leaf binding, since it is a fact about the signed
        // token alone. See MAX_CREDENTIAL_LIFETIME_SECONDS.
        if payload.iat > payload.exp
            || payload.exp.saturating_sub(payload.iat) > MAX_CREDENTIAL_LIFETIME_SECONDS
        {
            return Err(CredentialRejection::ImplausibleLifetime.into());
        }

        if leaf_signature_key != credential.device_key().as_slice() {
            return Err(CredentialRejection::LeafKeyMismatch.into());
        }

        // Last, and not the server's word: the account identity key's own
        // signature over the device key. The server wrote both fields and
        // signed the token around them, but it holds no account's identity
        // key, so it can copy a genuine certificate and cannot make one for a
        // key of its own. WHICH account key is right is the reader's pin
        // (`Client::observe_account_keys`), not this function's.
        let account_key = match credential.account() {
            None => None,
            Some((account_key, account_sig)) => {
                if !verify_account_device(account_key, credential.device_key(), account_sig) {
                    return Err(CredentialRejection::AccountSignature.into());
                }
                Some(*account_key)
            }
        };

        Ok((
            PeachyIdentity {
                actor_id: payload.actor_id.clone(),
                device_id: payload.device_id.clone(),
                device_key: *credential.device_key(),
                kid: payload.kid.clone(),
                expires_at: payload.exp,
                issued_at: payload.iat,
                account_key,
            },
            lapsed,
        ))
    }

    /// The `iat` a leaf credential claims, read without verifying it.
    ///
    /// For the tree clock only (crate::group, `tree_clock`), and safe there
    /// for a reason worth writing down: every leaf already in a tree was
    /// verified by every member when it arrived, and every leaf a commit
    /// introduces is verified before that commit is merged — so an `iat` read
    /// here either comes from a signature somebody checked or belongs to a
    /// commit that is about to be refused anyway. `None` for a credential that
    /// does not parse, which then simply adds
    /// nothing to the clock.
    pub fn claimed_issued_at(credential: &Credential) -> Option<i64> {
        let basic = openmls::prelude::BasicCredential::try_from(credential.clone()).ok()?;
        let token = DeviceCredential::parse(basic.identity()).ok()?;
        Some(token.payload().iat)
    }

    /// The `exp` a leaf credential claims, read without verifying it, for
    /// the reason [`Self::claimed_issued_at`] gives. For asking whether a
    /// renewal would move the tree clock past a seated leaf's `exp`
    /// (crate::group, `lapsed_leaf_awaits_tree_clock`). `None` for a
    /// credential that does not parse.
    pub fn claimed_expires_at(credential: &Credential) -> Option<i64> {
        let basic = openmls::prelude::BasicCredential::try_from(credential.clone()).ok()?;
        let token = DeviceCredential::parse(basic.identity()).ok()?;
        Some(token.payload().exp)
    }

    /// The device key a credential names, parsed and NOT verified.
    ///
    /// For finding a past epoch's sender in the current tree (crate::group,
    /// `process_inner`), where it is safe for the reason
    /// [`Self::claimed_issued_at`] gives: OpenMLS has already checked the
    /// message's signature against the leaf that carried this credential, and
    /// that leaf's key was checked against this very `device_key` when it was
    /// seated. `None` for a credential that does not parse.
    pub fn claimed_device_key(credential: &Credential) -> Option<[u8; ED25519_PUBLIC_KEY_BYTES]> {
        let basic = openmls::prelude::BasicCredential::try_from(credential.clone()).ok()?;
        let token = DeviceCredential::parse(basic.identity()).ok()?;
        Some(*token.device_key())
    }

    /// The `(actor, device, account key)` a seated leaf's credential names,
    /// parsed and NOT verified.
    ///
    /// For drawing the people of a copy this device holds (crate::group,
    /// `claim_of_held`), safe for the reason [`Self::claimed_issued_at`]
    /// gives: every leaf in a held tree was verified when it arrived. Read
    /// this way, a leaf whose credential no longer verifies today (it
    /// lapsed, or the server stopped publishing its kid) still counts as
    /// its person, so a Welcome that leaves it out draws that person as
    /// gone. `None` for a credential that does not parse, which no held
    /// tree carries.
    pub fn claimed_person(
        credential: &Credential,
    ) -> Option<(String, String, Option<[u8; ED25519_PUBLIC_KEY_BYTES]>)> {
        let basic = openmls::prelude::BasicCredential::try_from(credential.clone()).ok()?;
        let token = DeviceCredential::parse(basic.identity()).ok()?;
        let payload = token.payload();
        Some((
            payload.actor_id.clone(),
            payload.device_id.clone(),
            token.account().map(|(key, _)| *key),
        ))
    }

    /// Unix seconds, on this provider's clock — the same instant every expiry
    /// check above is made against, so a caller comparing an `expires_at` to
    /// "now" cannot disagree with the verdict by reading a different clock.
    pub fn now_unix(&self) -> i64 {
        self.clock.now_unix()
    }

    /// Unix milliseconds, on the same clock.
    pub fn now_unix_ms(&self) -> i64 {
        self.clock.now_unix_ms()
    }

    /// Milliseconds on the same clock's monotonic side ([`Clock::monotonic_ms`]).
    pub fn monotonic_ms(&self) -> u64 {
        self.clock.monotonic_ms()
    }

    /// Validate an MLS credential plus the signature key of the leaf carrying
    /// it.
    pub fn validate_credential(
        &self,
        credential: &Credential,
        leaf_signature_key: &[u8],
    ) -> Result<PeachyIdentity> {
        self.validate_credential_with_grace(credential, leaf_signature_key, 0)
            .map(|(identity, _lapsed)| identity)
    }

    /// [`Self::validate_credential`] with an expiry grace — see
    /// [`Self::validate_token_with_grace`]. `true` in the answer means the
    /// credential has expired and was let through by the grace alone.
    pub fn validate_credential_with_grace(
        &self,
        credential: &Credential,
        leaf_signature_key: &[u8],
        grace_seconds: i64,
    ) -> Result<(PeachyIdentity, bool)> {
        if credential.credential_type() != CredentialType::Basic {
            return Err(CredentialRejection::WrongCredentialType.into());
        }
        // Through `BasicCredential::try_from` rather than
        // `credential.serialized_content()`. They return the same bytes in
        // OpenMLS 0.9 — a basic credential's serialized content IS its identity
        // — but that is an implementation detail of one version of one library,
        // and the typed route is the one that keeps failing loudly if it stops
        // being true.
        let basic = openmls::prelude::BasicCredential::try_from(credential.clone())
            .map_err(|_| CredentialRejection::WrongCredentialType)?;
        self.validate_token_with_grace(basic.identity(), leaf_signature_key, grace_seconds)
    }

    /// Validate a leaf node: its credential against its own signature key.
    pub fn validate_leaf(&self, leaf: &LeafNode) -> Result<PeachyIdentity> {
        self.validate_credential(leaf.credential(), leaf.signature_key().as_slice())
    }

    /// Validate a key package before adding its owner to a group. This is the
    /// door an Add proposal comes through, so it is the door where a stranger's
    /// credential is first believed or refused.
    ///
    /// A key package from a device its account has not let in is refused
    /// here as [`CredentialRejection::NotApproved`]: nothing a peer does
    /// seats it, whatever the server that handed it over says.
    pub fn validate_key_package(&self, key_package: &KeyPackage) -> Result<PeachyIdentity> {
        require_approved(self.validate_leaf(key_package.leaf_node())?)
    }

    /// Validate a roster entry. A seated leaf, so an account certificate is
    /// required, as [`Self::validate_seated_credential`] requires one.
    pub fn validate_member(&self, member: &Member) -> Result<PeachyIdentity> {
        require_approved(self.validate_credential(&member.credential, &member.signature_key)?)
    }
}

/// A leaf a peer is asked to believe must carry its account's certificate.
///
/// The one rule this whole door exists for (docs/identity.md §The
/// account identity key): a device the account never let in is not a member
/// of anything. Its own client still opens — a device waiting for approval
/// has to be able to hold a credential — but no key package of it is added
/// and no leaf of it is accepted in a tree, a commit or a Welcome.
fn require_approved(identity: PeachyIdentity) -> Result<PeachyIdentity> {
    if identity.account_key.is_none() {
        return Err(CredentialRejection::NotApproved.into());
    }
    Ok(identity)
}

/// This device's OWN credential must not be certified under an account
/// identity key other than the one it derives from the account key it holds
/// (docs/identity.md §The account identity key).
///
/// `held` is that derived key, or `None` when the device holds no account
/// key. A device that holds no account key accepts only an uncertified
/// credential: a certificate is something it can make only once it holds
/// the key, so one it is handed names a key it cannot check and is refused.
/// It runs uncertified until it holds the key. A credential with no
/// certificate passes either way: it names no key. Checking `account_key` is
/// enough, because the token's validation already verified `account_sig`
/// under it.
pub fn check_own_account_key(
    identity: &PeachyIdentity,
    held: Option<&[u8; ED25519_PUBLIC_KEY_BYTES]>,
) -> Result<()> {
    match (held, identity.account_key.as_ref()) {
        (Some(held), Some(carried)) if carried != held => {
            Err(CredentialRejection::NotOwnAccountKey.into())
        }
        (None, Some(_)) => Err(CredentialRejection::NotOwnAccountKey.into()),
        _ => Ok(()),
    }
}

// ---- Enrolment ---------------------------------------------------------------
//
// The first two steps of putting a device into MLS, and they live HERE rather
// than in each binding because there must be exactly one answer to "where does
// a Peachy signing key come from". They were written three times before this —
// once in the wasm facade and, had this file not existed, once more for the C
// door that Swift and Kotlin share — and three CSPRNG choices is three chances
// to get the one that matters wrong.
//
// Both are free functions: enrolment happens BEFORE there is a client to hang
// them on, and that ordering is load-bearing. A `Client` opened with a seed
// the server minted no credential against fails `LeafKeyMismatch` on every
// call, which reads as a protocol bug and is really this sequence run out of
// order: make a seed, publish its public half, take the credential the server
// mints against it, and only then open a client.

/// The length of a device signing key seed.
///
/// Numerically the same 32 as [`ED25519_PUBLIC_KEY_BYTES`] and deliberately a
/// separate name: one is a secret this device stores and the other is a public
/// value it publishes, and a reader following `32` from one to the other
/// learns nothing about which of the two they are holding.
pub const ED25519_SEED_BYTES: usize = 32;

/// A fresh device signing key seed, from the platform CSPRNG.
///
/// The seed belongs in the platform's key store — the Keychain on Apple, the
/// no-backup directory on Android, IndexedDB in a browser — and never on the
/// wire. What goes on the wire is [`signing_key_public_key`] of it, as
/// `RegisterDevice`'s `signing_key`.
///
/// It is a RAW seed rather than a handle to a key the platform will only use
/// on the caller's behalf, and that is a real weakening with a reason: every
/// signing site inside OpenMLS is synchronous and takes key bytes, so there is
/// no seam in this crate where a signature could be delegated back out to a
/// non-extractable key. Closing that is an asynchronous signer threaded
/// through the protocol engine and honoured identically by three bindings
/// (docs/identity.md §Security considerations).
pub fn generate_signing_key_seed() -> Result<[u8; ED25519_SEED_BYTES]> {
    let mut seed = [0u8; ED25519_SEED_BYTES];
    getrandom::fill(&mut seed)
        .map_err(|err| Error::InvalidArgument(format!("no system randomness available: {err}")))?;
    Ok(seed)
}

/// The raw Ed25519 public key for a seed — which is also the leaf signature
/// key and the `device_key` the credential binds. Three names, one 32 bytes.
pub fn signing_key_public_key(seed: &[u8]) -> Result<[u8; ED25519_PUBLIC_KEY_BYTES]> {
    let seed: [u8; ED25519_SEED_BYTES] = seed.try_into().map_err(|_| {
        Error::InvalidArgument(format!(
            "a device signing key seed must be exactly {ED25519_SEED_BYTES} bytes, got {}",
            seed.len()
        ))
    })?;
    Ok(ed25519_dalek::SigningKey::from_bytes(&seed)
        .verifying_key()
        .to_bytes())
}
