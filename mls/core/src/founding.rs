// SPDX-License-Identifier: MIT
//! Founding a conversation (docs/delivery.md §Founding a conversation).
//!
//! ## Why one commit
//!
//! A founder's device makes a group of one and then seats everybody else.
//! Seated one device per commit, every founding commit was made from a tree
//! that held only her devices, so its recipient set was her; each later set
//! grew by the device the previous Welcome went to, which gave the order she
//! seated people. And her device was the one leaf no Welcome ever seated,
//! which the server could still read off every later send's set.
//!
//! ## What a founding sends instead
//!
//! - **One founding commit seats every device**
//!   ([`crate::Client::seat_founding`]), submitted with no recipients: the
//!   tree before it is the founder's alone and she holds it already.
//! - **Her device is Welcomed like everyone else's.** The founding fetches a
//!   KeyPackage of every device, hers included, and this module adds a
//!   secrets entry sealed to her own package to the commit's one Welcome:
//!   HPKE to its init key under the RFC 9420 `Welcome` label, as long as the
//!   others. The entries are sorted by KeyPackageRef, and the same Welcome
//!   bytes go to every device. The server sees a Welcome recipient for every
//!   device the commit seats and for her, each with one entry, and no device
//!   left over.
//! - **No later list puts her first.** She made the group, so her
//!   device is leaf 0; the joiners take their leaves in an order drawn at
//!   random, neither the order she passed them nor one the server could
//!   work out, and every send and commit lists its recipients by device id,
//!   not by leaf (docs/delivery.md §Sending). No list the server
//!   reads afterwards shows whom she seated in what order,
//!   and a commit's padded length depends on the tree's width and member
//!   count, not on where a removed device sat
//!   ([`crate::commit_padding`]). A removal that halves the tree takes its
//!   rightmost leaf, never hers while anybody else is seated, and shows only
//!   that.
//! - Her own copy does not open: her device erases that package's private
//!   half when it is a one-time package, and the entry seals nothing she
//!   could join with anyway. A reader treats it as any Welcome that does not
//!   open.
//! - **Nothing falls back to one add per commit.** A package the core
//!   refuses ([`crate::Client::founding_refusals`]) is left out, and its
//!   device is offered an ordinary add once the founding is merged, when the
//!   add's set is the whole tree. That door names every package the
//!   founding commit would refuse, the MLS commit's own checks included, so
//!   no invitee's package can refuse the founding of everybody else, and a
//!   package that commit refuses claims no device id or account key ahead
//!   of a later one.
//! - **A founding fails by rules that name nobody**, decided on the
//!   founder's group of one before the client opens the conversation's
//!   handle. The one fetch is never repeated. It fails when her own package
//!   did not come back, or did not read as a valid KeyPackage of her
//!   device's id and device key (`key_package_identity`), and when it means
//!   to seat another person, other people's packages came back, and none
//!   passed `founding_refusals`; a note to self and a community's own group
//!   mean to seat only her devices. A founding commit the core still refuses fails too: a
//!   package lapsing between the two reads, say.
//! - **A person with no package is waited on.** When no other person's
//!   package came back at all (their devices unused for weeks, or none), the
//!   founding seats only her own devices, and each other person is offered an
//!   ordinary add once a package of theirs appears.
//!
//! A reader finds its own entry by its KeyPackageRef and ignores every other
//! (RFC 9420 §12.4.3.1), so no reader changes.
//!
//! Every reader opens such a Welcome (`tests/founding_names_nobody.rs`
//! holds it), and acknowledges the copy it cannot open.

use openmls::prelude::{EncryptedGroupSecrets, KeyPackage};
use openmls_traits::crypto::OpenMlsCrypto;
use openmls_traits::types::HpkeCiphertext;
use tls_codec::{Deserialize as _, Serialize as _, VLBytes};

use crate::error::{mls_err, Error, Result};

/// The most devices one founding commit seats, the founder's own included.
/// Every device gets its own copy of the one Welcome, whose length grows with
/// the tree (about 4 KB a device), so the request grows with the square:
/// about 4 MB at this many. A founding with more seats the rest by ordinary
/// adds once this commit is merged.
pub const FOUNDING_MAX_SEATS: usize = 32;

/// An `MLSMessage`'s version and wire format, then a Welcome's cipher suite.
const WELCOME_HEAD_BYTES: usize = 2 + 2 + 2;
/// `wire_format` of a Welcome (RFC 9420 §6).
const WELCOME_WIRE_FORMAT: [u8; 2] = [0x00, 0x03];
/// The AEAD tag every MLS cipher suite's HPKE appends.
const AEAD_TAG_BYTES: usize = 16;
/// RFC 9420 §5.1.3 `EncryptWithLabel`, label "Welcome", prefixed.
const WELCOME_LABEL: &[u8] = b"MLS 1.0 Welcome";

/// `raw` (an `MLSMessage` carrying a Welcome) with one more secrets entry,
/// sealed to `own`, this device's own KeyPackage, and every entry sorted by
/// KeyPackageRef, so no position says which is the founder's.
pub(crate) fn with_founder_seat(
    raw: &[u8],
    own: &KeyPackage,
    crypto: &impl OpenMlsCrypto,
) -> Result<Vec<u8>> {
    if raw.len() < WELCOME_HEAD_BYTES || raw[2..4] != WELCOME_WIRE_FORMAT {
        return Err(Error::invalid("that message is not a Welcome"));
    }
    let (head, body) = raw.split_at(WELCOME_HEAD_BYTES);
    let mut reader = body;
    let mut secrets = Vec::<EncryptedGroupSecrets>::tls_deserialize(&mut reader)?;
    // What is left is `encrypted_group_info`, the HPKE context, kept as is.
    let tail = reader;
    let group_info = VLBytes::tls_deserialize_exact(tail)?;

    let first = secrets
        .first()
        .ok_or_else(|| Error::invalid("a founding's Welcome seats somebody"))?;
    let sealed_len = {
        let entry = first.tls_serialize_detached()?;
        let mut entry = entry.as_slice();
        let _reference = VLBytes::tls_deserialize(&mut entry)?;
        HpkeCiphertext::tls_deserialize_exact(entry)?
            .ciphertext
            .as_slice()
            .len()
    };
    let plaintext_len = sealed_len
        .checked_sub(AEAD_TAG_BYTES)
        .ok_or_else(|| Error::invalid("a Welcome entry is longer than its tag"))?;

    let reference = own.hash_ref(crypto).map_err(mls_err)?;
    if secrets.iter().any(|s| s.new_member() == reference) {
        return Err(Error::invalid(
            "that KeyPackage is seated by this Welcome already",
        ));
    }
    let mut info = VLBytes::new(WELCOME_LABEL.to_vec()).tls_serialize_detached()?;
    info.extend(group_info.tls_serialize_detached()?);
    let sealed = crypto
        .hpke_seal(
            own.ciphersuite().hpke_config(),
            own.hpke_init_key().as_slice(),
            &info,
            &[],
            &vec![0u8; plaintext_len],
        )
        .map_err(mls_err)?;
    secrets.push(EncryptedGroupSecrets::new(reference, sealed));
    secrets.sort_by(|a, b| a.new_member().as_slice().cmp(b.new_member().as_slice()));

    let mut out = head.to_vec();
    out.extend(secrets.tls_serialize_detached()?);
    out.extend_from_slice(tail);
    Ok(out)
}
