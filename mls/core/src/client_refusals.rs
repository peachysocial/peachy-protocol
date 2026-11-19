// SPDX-License-Identifier: MIT
//! THE ONE-WAY SWITCHES: client refusals the delivery service can turn on and
//! never off (docs/delivery.md §The protocol floor).
//!
//! A refusal a build ships OFF (a check that would break an honest flow until
//! some other piece lands) used to wait for a new build in every store to turn
//! on. Each one now has a NAME, and the protocol floor every client already
//! reads at launch and on resume lists the names switched on. A client keeps
//! every name it has been told, for good: a name the server later leaves out
//! stays on, so a server can tighten a client and never loosen it. Turning one
//! back off takes a new build, the same trust the store already holds.
//!
//! The rules, which every client keeps the same way and
//! `mls/fixtures/client-refusals.json` pins:
//!
//! - **Grows only.** What a client holds is what it held, plus every name the
//!   server now lists that this build knows ([`ratchet`]).
//! - **Unknown names are ignored**, so a build is unaffected by a name added
//!   after it was made, and a name can go out before the code that reads it.
//!   A held name this build does not know is kept, unread: a later build of
//!   the same install wrote it.
//! - **On means the build's own default or a held name** ([`is_on`]): a
//!   refusal compiled on stays on whatever the server says.
//! - **It applies at once.** A refusal is read where it is enforced, every
//!   time, so a name learned mid-session takes effect at the next check.
//!
//! The core enforces the names its own code reads (today
//! [`crate::revocation::SIGNED_REVOCATIONS_ENFORCED`]) from what the client
//! hands [`crate::Client::adopt_client_refusals`]; the app enforces the rest.
//! Where the names are kept is each app's own store.

use std::collections::BTreeSet;

/// One named refusal: its name on the wire, whether this build compiles it on,
/// and the constant it stands beside.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientRefusal {
    /// The name the server lists.
    pub name: &'static str,
    /// Whether this build refuses with or without the server.
    pub compiled_default: bool,
    /// The constant the name ORs into, in each place it is enforced.
    pub drives: &'static str,
}

/// The seat check on a device of one's own account.
pub const OWN_SEAT_CHECK: &str = "own_seat_check";
/// Only a signed revocation or a lapse removes a person's leaf.
pub const SIGNED_REVOCATIONS: &str = "signed_revocations";

/// Every refusal this build can be told to switch on.
pub const CLIENT_REFUSALS: &[ClientRefusal] = &[
    ClientRefusal {
        name: OWN_SEAT_CHECK,
        compiled_default: false,
        drives: "OWN_SEAT_CHECK (each app)",
    },
    ClientRefusal {
        name: SIGNED_REVOCATIONS,
        compiled_default: crate::revocation::SIGNED_REVOCATIONS_ENFORCED,
        drives: "SIGNED_REVOCATIONS_ENFORCED (mls/core)",
    },
];

/// The longest name kept. A longer one is not a name of any build.
pub const CLIENT_REFUSAL_NAME_MAX: usize = 64;

/// The refusal named `name`, when this build knows it.
pub fn known(name: &str) -> Option<&'static ClientRefusal> {
    CLIENT_REFUSALS.iter().find(|r| r.name == name)
}

/// A name of the right shape: lowercase ASCII letters, digits and `_`, 1 to
/// [`CLIENT_REFUSAL_NAME_MAX`] long.
fn well_formed(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= CLIENT_REFUSAL_NAME_MAX
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

/// What a client holds after hearing `served`: everything `held`, plus every
/// name in `served` this build knows. Sorted, without duplicates. A held name
/// of the wrong shape is dropped (it was never written by a build).
pub fn ratchet<H: AsRef<str>, S: AsRef<str>>(held: &[H], served: &[S]) -> Vec<String> {
    let mut out: BTreeSet<String> = held
        .iter()
        .map(|n| n.as_ref().trim())
        .filter(|n| well_formed(n))
        .map(str::to_owned)
        .collect();
    for name in served {
        let name = name.as_ref().trim();
        if known(name).is_some() {
            out.insert(name.to_owned());
        }
    }
    out.into_iter().collect()
}

/// Whether the refusal `name` is on: compiled on in this build, or held. A
/// name this build does not know is off; no code of this build reads it.
pub fn is_on<H: AsRef<str>>(name: &str, held: &[H]) -> bool {
    match known(name) {
        Some(refusal) => refusal.compiled_default || held.iter().any(|h| h.as_ref() == name),
        None => false,
    }
}

/// A list as it crosses a binding: names separated by commas or newlines,
/// each trimmed, empty ones skipped.
pub fn parse_names(text: &str) -> Vec<String> {
    text.split([',', '\n'])
        .map(str::trim)
        .filter(|n| !n.is_empty())
        .map(str::to_owned)
        .collect()
}

/// The names one core holds, in memory: what its app last handed it, grown
/// only ([`crate::Client::adopt_client_refusals`]).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClientRefusals {
    held: Vec<String>,
}

impl ClientRefusals {
    /// Grow by `served`; returns what is held now.
    pub fn adopt<S: AsRef<str>>(&mut self, served: &[S]) -> &[String] {
        self.held = ratchet(&self.held, served);
        &self.held
    }

    /// [`is_on`] against what is held.
    pub fn is_on(&self, name: &str) -> bool {
        is_on(name, &self.held)
    }

    /// What is held, sorted.
    pub fn held(&self) -> &[String] {
        &self.held
    }
}

impl crate::Client {
    /// Grow the refusals this core enforces by `names`, the list its app
    /// holds (module docs): handed in after every open, and again whenever
    /// the list grows. Never shrinks; a name this build does not know is
    /// ignored. Returns what the core holds now. In memory.
    pub fn adopt_client_refusals<S: AsRef<str>>(&mut self, names: &[S]) -> Vec<String> {
        self.client_refusals.adopt(names).to_vec()
    }

    /// Whether the refusal `name` is on for this core: compiled on, or
    /// adopted.
    pub fn client_refusal_on(&self, name: &str) -> bool {
        self.client_refusals.is_on(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grows_only() {
        let held = ratchet(&[OWN_SEAT_CHECK], &[] as &[&str]);
        assert_eq!(held, vec![OWN_SEAT_CHECK.to_string()]);
        let held = ratchet(&held, &[SIGNED_REVOCATIONS]);
        assert_eq!(held, vec![OWN_SEAT_CHECK, SIGNED_REVOCATIONS]);
        // The server leaves one out: it stays.
        let held = ratchet(&held, &[SIGNED_REVOCATIONS]);
        assert_eq!(held, vec![OWN_SEAT_CHECK, SIGNED_REVOCATIONS]);
    }

    #[test]
    fn unknown_names_are_ignored_and_a_held_one_is_kept() {
        assert!(ratchet(&[] as &[&str], &["no_such_refusal", ""]).is_empty());
        assert!(!is_on("no_such_refusal", &["no_such_refusal"]));
        assert_eq!(
            ratchet(&["from_a_newer_build"], &[] as &[&str]),
            vec!["from_a_newer_build"]
        );
        assert_eq!(
            ratchet(&["Not A Name"], &[] as &[&str]),
            Vec::<String>::new()
        );
    }

    #[test]
    fn the_core_holds_what_it_was_handed_and_never_less() {
        let mut refusals = ClientRefusals::default();
        assert_eq!(
            refusals.is_on(SIGNED_REVOCATIONS),
            crate::revocation::SIGNED_REVOCATIONS_ENFORCED
        );
        refusals.adopt(&parse_names(" signed_revocations ,\nx"));
        assert!(refusals.is_on(SIGNED_REVOCATIONS));
        refusals.adopt(&[] as &[&str]);
        assert!(refusals.is_on(SIGNED_REVOCATIONS));
        assert_eq!(refusals.held(), [SIGNED_REVOCATIONS]);
    }
}
