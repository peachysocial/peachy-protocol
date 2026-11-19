// SPDX-License-Identifier: MIT
//! Every way this crate can say no.
//!
//! Two rules hold across the whole crate and both live here:
//!
//!  1. **No panics across the API.** Every public function returns
//!     [`Result`]. The C ABI (`peachy-mls-cabi`) still wraps each entry in
//!     `catch_unwind`, because a panic from *inside* OpenMLS or a dependency is
//!     not ours to promise away — but nothing in `peachy-mls-core` may
//!     `unwrap`, `expect`, index or slice its way into one.
//!  2. **A rejection carries its reason as data, not as a string.**
//!     [`CredentialRejection`] and [`DenyReason`](crate::rules::DenyReason) are `#[repr(u32)]` enums with
//!     stable discriminants, because every client is held to one golden
//!     fixture of these decisions (docs/mls-core.md §Rejection codes,
//!     `mls/fixtures/credentials.json`). A message can be reworded; a
//!     discriminant cannot.

/// Why a `pdc1` device credential was not accepted.
///
/// The first five mirror `VerifyFailure` in the server's credential issuer
/// one for one, deliberately:
/// the same token checked by the server and by a client should fail for the
/// same named reason, or the two halves have drifted. The other three are
/// checks only a *leaf* verifier makes, because only it has the leaf in front
/// of it, and so is [`CredentialRejection::ImplausibleLifetime`], which bounds
/// the group's tree clock and means nothing to a server that issued the token.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum CredentialRejection {
    /// Not three dot-separated parts, wrong prefix, unreadable base64, not
    /// JSON, or a field of the wrong type.
    Malformed = 1,
    /// `kid` names a server key this verifier does not trust.
    UnknownKid = 2,
    /// Ed25519 said no over the bytes exactly as they arrived.
    BadSignature = 3,
    /// `exp` is in the past.
    Expired = 4,
    /// `iat` is in the future by more than the allowed skew.
    NotYetValid = 5,
    /// The leaf's signature key is not the `device_key` the credential binds.
    /// This is the check that makes the credential mean anything at a leaf: a
    /// valid credential for somebody else's device, replayed onto your own
    /// leaf, fails here and nowhere else.
    LeafKeyMismatch = 6,
    /// A `pdc1` whose payload's `v` is not 1. A future format must fail loudly
    /// on an old client rather than be read with `pdc1` rules.
    UnsupportedVersion = 7,
    /// The MLS credential was an X.509 chain or an unknown type. Peachy leaves
    /// carry exactly one shape (see [`crate::credential`]).
    WrongCredentialType = 8,
    // 9 was `WrongKeyUse`, retired: a key published for any use but `device`
    // is never trusted at all (`TrustedServerKeys::from_published_json`), so
    // a credential under one answers `UnknownKid`. The number is not reused.
    /// The credential claims a lifetime no issuer gives: `iat` after `exp`, or
    /// `exp` more than
    /// [`MAX_CREDENTIAL_LIFETIME_SECONDS`](crate::identity::MAX_CREDENTIAL_LIFETIME_SECONDS)
    /// past `iat`.
    ///
    /// A leaf-only check, and the upper bound on the group's tree clock
    /// (docs/identity.md §A received commit is judged on the tree
    /// clock): `iat` is what the tree clock is made of, and a signed `iat`
    /// years ahead with an `exp` to match would push every other leaf past its
    /// grace on that clock and freeze the group. Bounding `exp - iat` makes an
    /// `iat` in the future cost the same future `exp`, which the not-before
    /// check and the commit-side jump bound then catch.
    ImplausibleLifetime = 10,
    /// The credential carries an account identity key, and that key's
    /// signature over the device key does not check out
    /// ([`crate::account_identity`]). A leaf-only check, like the three above
    /// it: the server that minted the token cannot make this signature, which
    /// is the point of it.
    AccountSignature = 11,
    /// The credential is sound but carries no account certificate: a device
    /// its account has not let in. Refused wherever a PEER's leaf is believed
    /// — a key package being added, a leaf in a tree, a commit or a Welcome —
    /// and accepted only as this device's own credential while it waits
    /// (docs/identity.md §The account identity key).
    NotApproved = 12,
    /// This device's OWN credential carries an account certificate under an
    /// account identity key other than the one derived from the account key
    /// the device holds ([`crate::ClientConfig::own_account_identity`]), or
    /// carries one at all while the device holds no account key. A
    /// device-only check: the server can certify a device under a key it made
    /// itself, and only the device holding the real account key can tell.
    /// Refused when a client opens on such a credential or is handed one; a
    /// credential with no certificate at all is still this device's own while
    /// it waits (docs/identity.md §The account identity key).
    NotOwnAccountKey = 13,
}

impl CredentialRejection {
    /// Every variant, in discriminant order.
    ///
    /// The same shape as [`crate::rules::DenyReason::ALL`] and for the same
    /// reason: `mls/fixtures/credentials.json` is replayed by every binding,
    /// and the Rust replay walks this array to prove that **every** code is
    /// reached by some case. A rejection no case produces is a branch the
    /// fixture cannot protect, and it could go wrong in one client with
    /// nothing anywhere going red.
    pub const ALL: [CredentialRejection; 12] = [
        Self::Malformed,
        Self::UnknownKid,
        Self::BadSignature,
        Self::Expired,
        Self::NotYetValid,
        Self::LeafKeyMismatch,
        Self::UnsupportedVersion,
        Self::WrongCredentialType,
        Self::ImplausibleLifetime,
        Self::AccountSignature,
        Self::NotApproved,
        Self::NotOwnAccountKey,
    ];

    /// The stable discriminant, for the C ABI and for fixtures.
    pub fn code(self) -> u32 {
        self as u32
    }

    /// The inverse of [`CredentialRejection::name`], as a search over
    /// [`CredentialRejection::ALL`] rather than a second `match` that a rename
    /// could leave half-updated.
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|reason| reason.name() == name)
    }

    /// A short, stable name. Fixture-facing, so it is spelled out rather than
    /// derived from the variant name by a macro that a rename would follow.
    pub fn name(self) -> &'static str {
        match self {
            Self::Malformed => "malformed",
            Self::UnknownKid => "unknown_kid",
            Self::BadSignature => "bad_signature",
            Self::Expired => "expired",
            Self::NotYetValid => "not_yet_valid",
            Self::LeafKeyMismatch => "leaf_key_mismatch",
            Self::UnsupportedVersion => "unsupported_version",
            Self::WrongCredentialType => "wrong_credential_type",
            Self::ImplausibleLifetime => "implausible_lifetime",
            Self::AccountSignature => "account_signature",
            Self::NotApproved => "not_approved",
            Self::NotOwnAccountKey => "not_own_account_key",
        }
    }
}

impl std::fmt::Display for CredentialRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// Everything `peachy-mls-core` returns as an error.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A `pdc1` credential — ours at construction, or a peer's at a leaf —
    /// did not check out.
    #[error("device credential rejected: {0}")]
    CredentialRejected(CredentialRejection),

    /// Group policy refused a proposal or a sender. See
    /// [`crate::rules::DenyReason`].
    #[error("group policy refused: {0}")]
    PolicyRefused(crate::rules::DenyReason),

    /// OpenMLS said no. The string is OpenMLS' own `Display`, kept as text
    /// rather than re-modelled: its error enums are large, versioned and not
    /// ours, and re-modelling them is how a wrapper starts lying about which
    /// case it is in.
    #[error("mls: {0}")]
    Mls(String),

    /// A TLS-presentation encode or decode failed.
    #[error("codec: {0}")]
    Codec(String),

    /// No group with that id is open on this client.
    #[error("no such group")]
    NoSuchGroup,

    /// The group exists but this client is no longer an active member of it —
    /// it was removed, or the group was left.
    #[error("not an active member of this group")]
    NotAMember,

    /// The named member is not in the roster.
    #[error("no such member")]
    NoSuchMember,

    /// A Welcome invited this client into a group it is already in.
    ///
    /// Its own variant, and not folded into [`Error::InvalidArgument`],
    /// because it is the one failure whose right answer is to do nothing and
    /// carry on: the group the caller wanted is open already. Two members
    /// racing an add produce two Welcomes and the delivery service hands over
    /// both, so this is an ordinary Tuesday rather than an anomaly — but a
    /// caller that cannot tell it from "this Welcome will not open" either logs
    /// noise on every race or swallows a real failure to avoid the noise.
    ///
    /// Also a stale Welcome: one at or below the highest epoch this device
    /// has held the group at, or one it already took through a last-resort
    /// package. The right answer is the same: acknowledge it and drop it.
    #[error("already a member of this group")]
    AlreadyAMember,

    /// A shape this build does not implement yet. Distinct from
    /// [`Error::PolicyRefused`]: refused means "we decided against it",
    /// unsupported means "nobody has written it".
    #[error("unsupported: {0}")]
    Unsupported(&'static str),

    /// The caller handed us something the API cannot accept — an empty group
    /// id, a signing key of the wrong length, a null pointer at the C edge.
    #[error("invalid argument: {0}")]
    InvalidArgument(String),

    /// The device's own MLS store would not read or would not write: a locked
    /// database, a full disk, a file written by a newer schema.
    ///
    /// Its own variant rather than folded into [`Error::Mls`] because the two
    /// mean opposite things to a caller. An `Mls` error is the protocol saying
    /// no — retrying will fail the same way. A `Storage` error is the device
    /// saying not now, and the operation may well succeed on the next try.
    #[error("storage: {0}")]
    Storage(String),

    /// A `GroupContextExtensions` commit — the group's name and photo — could
    /// not be built because a member's leaf does not advertise the
    /// `peachy_group_meta` extension (`crate::group_meta` §Capabilities).
    ///
    /// Its own variant rather than an [`Error::Mls`] string because it is the
    /// one refusal here with a remedy a PERSON can carry out: everybody in the
    /// group updates Peachy, each client's next leaf renewal publishes a leaf
    /// that advertises it, and the rename works. A client that could not tell
    /// this from "OpenMLS said no" would show a dead end where there is a
    /// sentence.
    #[error("a member's app is too old for this group change: {0}")]
    ExtensionUnsupportedByMember(String),

    /// A group message handed to the door that does not take its kind: a
    /// commit or a proposal on the message door
    /// ([`crate::Client::process_message`]), or anything but a commit on the
    /// commit door ([`crate::Client::process_commit`]). Refused before the
    /// engine reads it, so nothing moved — no epoch, no ratchet.
    ///
    /// Its own variant because the right answer to it is neither of the
    /// others': it is not a message this device failed to open (no
    /// placeholder, no decrypt alarm) and not a commit that strands the group
    /// (no rejoin). It is a member putting bytes where they do not go, and the
    /// caller drops them and says so in its log.
    #[error("wrong door: {0}")]
    WrongDoor(&'static str),

    /// A message that opened and verified, from a device that holds no leaf
    /// in this group now: sealed at an epoch the group has left, by a member
    /// who has since been removed. A removed device keeps the keys of the
    /// epochs it was in, so it can go on sealing messages at its last one for
    /// as long as members still retain that epoch, and nothing in the message
    /// says whether it was written before or after the removal.
    ///
    /// Its own variant because the right answer is silence: not a message
    /// this device lost (no placeholder, no resend ask, no decrypt alarm) and
    /// not a fault in this device's copy of the group (no head check). The
    /// caller acknowledges it and shows nothing.
    ///
    /// The same answer for a message that opened through a device seal
    /// naming another device than its author
    /// ([`crate::Client::process_message_as`]): one member passing another's
    /// message off as its own seal's.
    #[error("not from a member: {0}")]
    NotFromAMember(&'static str),

    /// A Welcome refused for who signed it: a device this account forgot
    /// ([`crate::Client::forget_own_device`]), into any group, known or new;
    /// or, into a group this device knew, a signer whose credential does not
    /// identify, so no line could say who re-added it. Nobody else is refused
    /// for who they are: a Welcome into a group this device knew is taken and
    /// reported ([`crate::Client::take_rejoin_report`]).
    ///
    /// Its own variant because the right answer is the one for a duplicate:
    /// drop the Welcome and keep what is held. Nothing changed; the key
    /// package it was sealed to is spent, as on any refusal.
    #[error("welcome from outside the group")]
    WelcomeFromOutsider,

    /// The group holds a SAVED commit: one found staged when this client
    /// opened, whose verdict this device never heard
    /// ([`crate::Client::has_saved_commit`]). Forgetting the group, or
    /// replacing it with a Welcome, would drop a commit the delivery service
    /// may have taken, so both refuse until the group's head settles it
    /// ([`crate::Client::settle_saved_commit`]).
    ///
    /// Its own variant because the right answer is to wait, not to give up:
    /// nothing changed, a contested Welcome is still kept, and the same call
    /// succeeds once the commit is settled.
    #[error("settle first: a saved commit waits on the group's head")]
    SettleFirst,

    /// An application message this device has already opened: the very bytes
    /// of a message it opened (or opened and then refused) before, handed to
    /// it again, as a delivery service can under a fresh envelope id. Its key
    /// was spent the first time, so it cannot open again, and nothing about
    /// the copy is new.
    ///
    /// Its own variant because the right answer is silence: not a message
    /// this device lost (no placeholder, no resend ask, no decrypt alarm, no
    /// notification) and not a fault in its copy of the group (no head
    /// check). The caller acknowledges it and shows nothing. The core says it
    /// only for bytes its own record says it opened
    /// ([`crate::Client::process_message`]); a message whose key was spent by
    /// anything else stays a message that would not open.
    #[error("duplicate: {0}")]
    Duplicate(&'static str),

    /// The store at the path is written in the clear, and the open was given
    /// a key. Not [`Self::Storage`], which a caller may retry: no retry opens
    /// it. Migrate it with [`crate::sqlite::store_encrypt_in_place`]; never
    /// delete it to start over, which drops the device out of every group.
    #[error("the MLS store is not encrypted: encrypt it in place before opening it with a key")]
    PlaintextStore,

    /// The store at the path, or its `-wal`, `-shm` or `-journal`, is
    /// writable by group or others, so another local user could plant a log
    /// the bundled SQLite would read as the store's own (RUSTSEC-2026-0459;
    /// `mls/core/src/sqlite.rs` §Only this process's user writes the files).
    /// Nothing was opened. Not [`Self::Storage`]: no retry opens it. Make the
    /// files writable only by their owner and open it again; never delete
    /// the store to start over.
    #[error("insecure store: {0}")]
    InsecureStore(String),

    /// A message or commit framed at an epoch past the one this copy of the
    /// group holds: the commit that would have carried the copy there came
    /// first and did not apply, so the copy is BEHIND OR FORKED and will not
    /// catch up from what was delivered. Nothing moved.
    ///
    /// Its own variant because it says what to do, where OpenMLS's own
    /// "epoch differs" said only what happened: read the group's head and
    /// hand it to the recovery driver ([`crate::Client::recovery_judge`],
    /// with [`crate::recovery::HeadReadKind::SealedAhead`]), which answers
    /// whether to forget the group and ask back in. The framing is in the
    /// clear and anyone who holds the group id can write it, so a client
    /// never rejoins on this error alone; it still shows the placeholder a
    /// message that will not open is shown. A message framed at or below the
    /// copy's epoch that will not open stays [`Self::Mls`].
    ///
    /// Sealing says it too, the other way round
    /// ([`crate::Client::seal_envelope`]): a message or commit made at an
    /// epoch this copy has moved past and no longer keeps
    /// (`message_epoch` below `copy_epoch`) is not sealed. Nothing was sent:
    /// encrypt it again at the copy's epoch, never resend the old bytes.
    #[error("{}", stale_copy_text(*message_epoch, *copy_epoch))]
    StaleCopy { message_epoch: u64, copy_epoch: u64 },
}

impl Error {
    /// The C ABI's error code. Stable; `peachy_mls.h` names these.
    pub fn code(&self) -> i32 {
        match self {
            Self::CredentialRejected(_) => 2,
            Self::PolicyRefused(_) => 3,
            Self::Mls(_) => 4,
            Self::Codec(_) => 5,
            Self::NoSuchGroup => 6,
            Self::NotAMember => 7,
            Self::NoSuchMember => 8,
            Self::Unsupported(_) => 9,
            Self::InvalidArgument(_) => 10,
            Self::Storage(_) => 11,
            // Appended, never inserted: these numbers are in a committed C
            // header, a Swift enum and a Kotlin one.
            Self::AlreadyAMember => 12,
            Self::ExtensionUnsupportedByMember(_) => 13,
            // 14 and 15 are retired. Not reused.
            Self::WrongDoor(_) => 16,
            Self::NotFromAMember(_) => 17,
            Self::WelcomeFromOutsider => 18,
            Self::SettleFirst => 19,
            Self::Duplicate(_) => 20,
            Self::PlaintextStore => 21,
            Self::InsecureStore(_) => 22,
            Self::StaleCopy { .. } => 23,
        }
    }

    pub(crate) fn invalid(message: impl Into<String>) -> Self {
        Self::InvalidArgument(message.into())
    }
}

impl From<CredentialRejection> for Error {
    fn from(rejection: CredentialRejection) -> Self {
        Self::CredentialRejected(rejection)
    }
}

impl From<tls_codec::Error> for Error {
    fn from(err: tls_codec::Error) -> Self {
        Self::Codec(err.to_string())
    }
}

impl From<crate::storage::KvError> for Error {
    fn from(err: crate::storage::KvError) -> Self {
        Self::Storage(err.message)
    }
}

/// The crate's result type.
pub type Result<T> = std::result::Result<T, Error>;

/// Turn any OpenMLS error into [`Error::Mls`] without importing its error
/// hierarchy. Used as `.map_err(mls_err)` at every call site.
pub(crate) fn mls_err<E: std::fmt::Display>(err: E) -> Error {
    Error::Mls(err.to_string())
}

/// [`Error::StaleCopy`]'s text: a copy behind what it was handed, or a
/// message made at an epoch the copy no longer keeps.
fn stale_copy_text(message_epoch: u64, copy_epoch: u64) -> String {
    if message_epoch > copy_epoch {
        format!(
            "stale copy: sealed at epoch {message_epoch}, past this copy's epoch {copy_epoch}; \
             the copy is behind or forked: read the group's head and rejoin if the recovery driver says so"
        )
    } else {
        format!(
            "stale copy: made at epoch {message_epoch}, which this copy at epoch {copy_epoch} \
             no longer keeps; encrypt it again"
        )
    }
}

#[cfg(test)]
// See the note on the same attribute in `rules.rs`: the crate denies `expect`
// for the LIBRARY, and a test that cannot proceed should stop where it failed.
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::CredentialRejection;

    /// The three things `mls/fixtures/credentials.json` rests on.
    ///
    /// The fixture is written in NAMES and carries the numbers alongside, so
    /// the contract breaks in exactly two ways — a rename that left the
    /// discriminant alone, and a renumbering that left the name alone. Both
    /// need `name`/`from_name`/`code` to agree with each other here first.
    #[test]
    fn every_rejection_has_a_unique_name_that_round_trips_to_its_own_code() {
        for (index, rejection) in CredentialRejection::ALL.iter().enumerate() {
            assert_eq!(
                CredentialRejection::from_name(rejection.name()),
                Some(*rejection),
                "{} does not round-trip through from_name",
                rejection.name()
            );
            // ALL is in discriminant order, pinned here, so a variant added in
            // the middle without renumbering fails here rather than in a
            // fixture nobody reads twice. 9 is a retired code and stays unused.
            const PINNED: [u32; 12] = [1, 2, 3, 4, 5, 6, 7, 8, 10, 11, 12, 13];
            assert_eq!(
                rejection.code(),
                PINNED[index],
                "{} is code {}, not {}",
                rejection.name(),
                rejection.code(),
                PINNED[index]
            );
            assert_eq!(
                CredentialRejection::ALL
                    .iter()
                    .filter(|other| other.name() == rejection.name())
                    .count(),
                1,
                "two rejections are called {:?}; from_name would answer with the first",
                rejection.name()
            );
        }
        assert_eq!(CredentialRejection::from_name("expired "), None);
        assert_eq!(CredentialRejection::from_name("Expired"), None);
    }
}
