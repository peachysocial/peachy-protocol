// SPDX-License-Identifier: MIT
//! What a group says about itself: its name, its topic and its photo.
//!
//! docs/sealed-messages.md §The name is in the group. The one
//! sentence this module is built on:
//!
//! > **Group state is carried in the group's own state, changed by a commit
//! > every member sees.**
//!
//! So a sealed group's name and photo are a **GroupContext extension**,
//! `peachy_group_meta`, changed by a `GroupContextExtensions` proposal. That is
//! where RFC 9420 puts a group's own metadata and it is the closest thing MLS
//! has to an encrypted group title and avatar: state every
//! member holds, rather than a message somebody has to remember to re-send.
//!
//! ## Why the server cannot read it
//!
//! Not because this module encrypts anything. It does not have to:
//!
//! - A commit carrying the proposal is an MLS `PrivateMessage`
//!   (`PEACHY_WIRE_FORMAT_POLICY` in `group.rs`), so the proposal's bytes —
//!   the name included — are ciphertext under the epoch's handshake keys.
//! - A member added later learns the group context from the Welcome, whose
//!   `GroupInfo` is encrypted to the joiner's init key.
//! - Nothing in Peachy publishes a `GroupInfo` anywhere; there are no external
//!   joins.
//!
//! `mls/core/tests/group_meta.rs` holds the first two as tests over the real
//! wire bytes, which is the claim the privacy document makes.
//!
//! ## The value is opaque here
//!
//! The extension carries UTF-8 JSON — `mls/fixtures/formats/group-meta.json`
//! is its golden table, replayed by every client's codec — and this crate
//! treats it as bytes with a length cap. Deliberately: the words are a product
//! format four clients render, the crate's job is to carry them where only
//! members can read them and to let exactly this one change through the
//! policy (`crate::rules`, `sets_group_meta`). A hostile member can write any
//! bytes here, as they can write any words in a message; every READER refuses
//! a value that does not parse, and draws the roster instead.
//!
//! ## Capabilities
//!
//! RFC 9420 §12.1.6 and OpenMLS' `validate_group_context_extensions_proposal`:
//! a `GroupContextExtensions` proposal with a non-default extension type is
//! refused unless the same proposal's `required_capabilities` names that type
//! AND every existing member's leaf advertises it. So every leaf this build
//! makes advertises it, whether or not its group is ever renamed, and a leaf
//! seated without it is upgraded by the ordinary leaf renewal
//! ([`crate::group::Client::credential_refresh_due`] answers true for a leaf
//! missing a capability this build requires), which every client already runs
//! before a send and at app start or foreground. A commit refused for this
//! reason is
//! [`Error::ExtensionUnsupportedByMember`], because it is the one refusal with
//! a remedy a person can carry out: that member runs a current build, and
//! its next renewal carries the capability.
//!
//! ## Retired code points
//!
//! `0xF1A7` and `0xF1A8` belonged to a retired feature. Nothing reads,
//! writes or advertises either, and neither number is reused. A group whose
//! context still requires `0xF1A7` can seat no
//! leaf this build makes; that was accepted when the numbers went.

use openmls::prelude::{
    Extension, ExtensionType, Extensions, GroupContext, RequiredCapabilitiesExtension,
    UnknownExtension,
};

use crate::error::{Error, Result};

/// The extension type code point for `peachy_group_meta`.
///
/// `0xF1A9`, in RFC 9420's **private-use** range (0xF000–0xFFFF): Peachy's
/// format about Peachy's product, which no other MLS implementation has any
/// use for, and a number in the registered range would be a claim on a code
/// point nobody granted.
pub const PEACHY_GROUP_META_EXTENSION_TYPE: u16 = 0xF1A9;

/// The longest value the group context will carry, in bytes.
///
/// The value is a name of at most 100 Unicode scalars (at most 400 bytes of
/// UTF-8), a topic of at most 500 scalars AND 1,000 bytes of UTF-8 (about
/// 1,350 once JSON escapes it; docs/sealed-messages.md §The value) and one
/// sealed-attachment pointer (about 350 bytes), plus a member-rostered group's
/// policy, link and timer, its admins and its bans (`crate::policy`: up to
/// [`crate::policy::MAX_ADMINS`] and [`crate::policy::MAX_BANNED`] actor ids
/// of 39 bytes each in JSON). All of that at once is about 9 KiB
/// (`mls/core/tests/group_meta.rs` builds it), so 16 KiB holds it with room,
/// and is still small enough that a member cannot make every commit in the
/// group carry a megabyte forever: the group context is hashed into every
/// epoch and re-sent in every Welcome.
///
/// A community's directory of rooms is not part of that worst case: each
/// entry carries a room's name and topic, so a long directory can reach the
/// cap. The change that would pass it is refused on the device making it,
/// before anything is sent.
pub const MAX_GROUP_META_BYTES: usize = 16_384;

/// The extension type, as OpenMLS names it.
pub fn group_meta_extension_type() -> ExtensionType {
    ExtensionType::Unknown(PEACHY_GROUP_META_EXTENSION_TYPE)
}

/// The group's meta value, or `None` when nobody has ever set one.
pub fn group_meta_from_context(extensions: &Extensions<GroupContext>) -> Option<Vec<u8>> {
    extensions
        .unknown(PEACHY_GROUP_META_EXTENSION_TYPE)
        .map(|UnknownExtension(data)| data.clone())
}

/// Refuse a value the group context should not carry.
pub fn check_group_meta_value(value: &[u8]) -> Result<()> {
    if value.is_empty() {
        return Err(Error::invalid(
            "a group meta value must not be empty; an unnamed group writes its format with an empty name",
        ));
    }
    if value.len() > MAX_GROUP_META_BYTES {
        return Err(Error::invalid(format!(
            "a group meta value is at most {MAX_GROUP_META_BYTES} bytes, not {}",
            value.len()
        )));
    }
    Ok(())
}

/// The group context extension set carrying `value`, starting from what the
/// group already has.
///
/// Merges, never composes: a `GroupContextExtensions` proposal REPLACES the
/// whole set, so everything the group already carries survives, our extension
/// is added or replaced, and `required_capabilities` grows to name our type
/// without losing whatever it already required. A proposal built any other
/// way would silently drop an extension a future Peachy added.
pub fn group_context_extensions_with_meta(
    current: &Extensions<GroupContext>,
    value: &[u8],
) -> Result<Extensions<GroupContext>> {
    check_group_meta_value(value)?;
    let mut next = current.clone();
    next.add_or_replace(Extension::Unknown(
        PEACHY_GROUP_META_EXTENSION_TYPE,
        UnknownExtension(value.to_vec()),
    ))
    .map_err(|err| Error::invalid(format!("the group meta is not a group extension: {err}")))?;

    let (mut extension_types, proposal_types, credential_types) =
        match current.required_capabilities() {
            Some(required) => (
                required.extension_types().to_vec(),
                required.proposal_types().to_vec(),
                required.credential_types().to_vec(),
            ),
            None => (Vec::new(), Vec::new(), Vec::new()),
        };
    if !extension_types.contains(&group_meta_extension_type()) {
        extension_types.push(group_meta_extension_type());
    }
    next.add_or_replace(Extension::RequiredCapabilities(
        RequiredCapabilitiesExtension::new(&extension_types, &proposal_types, &credential_types),
    ))
    .map_err(|err| {
        Error::invalid(format!(
            "required capabilities are not a group extension: {err}"
        ))
    })?;
    Ok(next)
}

/// Whether `proposed` differs from `current` in the group meta and nothing
/// else — the question the policy asks of an incoming `GroupContextExtensions`
/// proposal before letting a member rename the group.
///
/// Rebuild what an honest client would have proposed from `current` and the
/// proposal's own value, and compare. A proposal that also drops an
/// extension, or smuggles a second one beside the name, is not a rename, and
/// the rules refuse it as the unexplained edit it is.
///
/// `required_capabilities` is compared as a SET rather than as a list, because
/// nothing in RFC 9420 fixes the order of the types in it and two clients
/// building the same requirement could legitimately write them differently.
pub fn group_meta_change(
    current: &Extensions<GroupContext>,
    proposed: &Extensions<GroupContext>,
) -> bool {
    let Some(value) = group_meta_from_context(proposed) else {
        return false;
    };
    match group_context_extensions_with_meta(current, &value) {
        Ok(expected) => extension_sets_agree(&expected, proposed),
        Err(_) => false,
    }
}

fn extension_sets_agree(left: &Extensions<GroupContext>, right: &Extensions<GroupContext>) -> bool {
    let left_types: Vec<ExtensionType> = sorted_types(left);
    let right_types: Vec<ExtensionType> = sorted_types(right);
    if left_types != right_types {
        return false;
    }
    for extension in left.iter() {
        let extension_type = extension.extension_type();
        if extension_type == ExtensionType::RequiredCapabilities {
            let (Some(a), Some(b)) = (left.required_capabilities(), right.required_capabilities())
            else {
                return false;
            };
            if !required_capabilities_agree(a, b) {
                return false;
            }
            continue;
        }
        if right.iter().all(|other| other != extension) {
            return false;
        }
    }
    true
}

fn sorted_types(extensions: &Extensions<GroupContext>) -> Vec<ExtensionType> {
    let mut types: Vec<ExtensionType> = extensions
        .iter()
        .map(|extension| extension.extension_type())
        .collect();
    types.sort_by_key(|extension_type| u16::from(*extension_type));
    types
}

fn required_capabilities_agree(
    left: &RequiredCapabilitiesExtension,
    right: &RequiredCapabilitiesExtension,
) -> bool {
    same_set(left.extension_types(), right.extension_types())
        && same_set(left.proposal_types(), right.proposal_types())
        && same_set(left.credential_types(), right.credential_types())
}

fn same_set<T: PartialEq>(left: &[T], right: &[T]) -> bool {
    left.len() == right.len()
        && left.iter().all(|item| right.contains(item))
        && right.iter().all(|item| left.contains(item))
}

/// The error a client shows when a member's leaf cannot carry a rename.
///
/// Built here rather than at the call site so the sentence is written once: a
/// person who sees it needs to be told what to do, and "everybody has to be on
/// a build that knows about this" is the whole of it.
pub(crate) fn unsupported_by_member(detail: &str) -> Error {
    Error::ExtensionUnsupportedByMember(detail.to_string())
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn absent_reads_as_none() {
        assert_eq!(group_meta_from_context(&Extensions::empty()), None);
    }

    #[test]
    fn a_value_round_trips_and_requires_its_own_type() {
        let next =
            group_context_extensions_with_meta(&Extensions::empty(), b"{\"v\":1,\"n\":\"x\"}")
                .expect("builds");
        assert_eq!(
            group_meta_from_context(&next).as_deref(),
            Some(&b"{\"v\":1,\"n\":\"x\"}"[..])
        );
        assert!(next
            .required_capabilities()
            .is_some_and(|r| r.extension_types().contains(&group_meta_extension_type())));
    }

    #[test]
    fn empty_and_oversized_values_are_refused() {
        assert!(check_group_meta_value(b"").is_err());
        assert!(check_group_meta_value(&vec![b'a'; MAX_GROUP_META_BYTES]).is_ok());
        assert!(check_group_meta_value(&vec![b'a'; MAX_GROUP_META_BYTES + 1]).is_err());
    }

    /// A rename carries forward what the group already had, and a second
    /// rename is recognised as one from the state the first produced.
    #[test]
    fn a_rename_keeps_what_the_group_already_carried() {
        let mut current = Extensions::<GroupContext>::empty();
        current
            .add_or_replace(Extension::Unknown(0xF1FE, UnknownExtension(vec![7])))
            .expect("an unknown extension is a group extension");
        let renamed = group_context_extensions_with_meta(&current, b"a").expect("builds");
        assert_eq!(
            renamed
                .unknown(0xF1FE)
                .map(|UnknownExtension(data)| data.clone()),
            Some(vec![7])
        );
        assert!(group_meta_change(&current, &renamed));
        let again = group_context_extensions_with_meta(&renamed, b"b").expect("builds");
        assert!(group_meta_change(&renamed, &again));
    }

    #[test]
    fn a_rename_smuggling_anything_else_is_not_a_rename() {
        let current = Extensions::<GroupContext>::empty();
        let mut proposed = group_context_extensions_with_meta(&current, b"a").expect("builds");
        proposed
            .add_or_replace(Extension::Unknown(0xF1FF, UnknownExtension(vec![1])))
            .expect("an unknown extension is a group extension");
        assert!(!group_meta_change(&current, &proposed));

        // A proposal that DROPS something the group already carried is the
        // same failure wearing the other sign.
        let mut with_extra = current.clone();
        with_extra
            .add_or_replace(Extension::Unknown(0xF1FE, UnknownExtension(vec![1])))
            .expect("an unknown extension is a group extension");
        let dropping = group_context_extensions_with_meta(&current, b"a").expect("builds");
        assert!(!group_meta_change(&with_extra, &dropping));
    }
}
