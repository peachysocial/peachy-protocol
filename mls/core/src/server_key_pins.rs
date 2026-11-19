// SPDX-License-Identifier: MIT
//! The server keys a build carries, and the one rule every client applies to
//! them.
//!
//! A client learns which server keys sign device credentials from
//! `GET /healthz/device-credential-keys`, so the server that issues
//! credentials also names the keys they are checked against. Every build
//! therefore also carries those keys itself (`mls/core/pinned-server-keys.json`,
//! compiled in here), so that a change of signing key needs a new build.
//!
//! The rule (docs/identity.md §The trusted server keys): the client
//! compares what the server published with what it carries and writes any
//! difference to its own device log ([`server_key_pin_report`],
//! [`PinMode::Compare`]); nothing goes to the server. It trusts only keys
//! that are both carried AND published ([`server_keys_pinned_json`],
//! [`PinMode::Enforce`]), so a credential under any other kid reads as
//! [`crate::CredentialRejection::UnknownKid`]. A carried key the server has
//! stopped publishing is not trusted either: retiring a key stays the
//! server's call, from each client's next open (a running client keeps the
//! set it opened with). The core trusts exactly the list a client hands
//! `Client::new`, so the client hands it the narrowed list.
//!
//! Each client picks its set by the server it talks to: `production` for the
//! production API, `development` for anything else. Never by what a server
//! says about itself, or a server could pick the set it likes.
//!
//! The `development` set is the fixed key local and test servers sign with,
//! and its seed is public. Only a build with the `development-keys` feature
//! carries it; in any other build, a shipped one included, the set is empty.
//! Such a build talking to a server that is not production reports every key
//! as not pinned and trusts none of them.

use std::collections::BTreeMap;

use crate::credential::{decode_public_key, ED25519_PUBLIC_KEY_BYTES};
use crate::error::{Error, Result};
use crate::identity::{TrustedServerKeys, DEVICE_KEY_USE};

/// The keys this build carries, by server. One file, read by every client
/// through this crate rather than copied into four languages.
const PINNED_JSON: &str = include_str!("../pinned-server-keys.json");

/// The set for the production API.
pub const PINNED_PRODUCTION: &str = "production";
/// The set for every other server: local and test servers. Empty in a
/// build without the `development-keys` feature.
pub const PINNED_DEVELOPMENT: &str = "development";

/// What a client does with the keys it carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinMode {
    /// Trust the published list as it is; report any difference.
    Compare,
    /// Trust only keys that are carried and published, under the same bytes.
    Enforce,
}

/// How a published list differs from a carried set. Both empty is a match.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PinComparison {
    /// Kids the server publishes that this build does not carry, or carries
    /// under a different public key.
    pub unpinned: Vec<String>,
    /// Kids this build carries that the server does not publish.
    pub missing: Vec<String>,
}

impl PinComparison {
    pub fn is_match(&self) -> bool {
        self.unpinned.is_empty() && self.missing.is_empty()
    }

    /// One line for a device log, or `""` for a match. Kids only.
    pub fn describe(&self) -> String {
        let mut parts = Vec::new();
        if !self.unpinned.is_empty() {
            parts.push(format!(
                "published but not pinned: {}",
                self.unpinned.join(", ")
            ));
        }
        if !self.missing.is_empty() {
            parts.push(format!(
                "pinned but not published: {}",
                self.missing.join(", ")
            ));
        }
        parts.join("; ")
    }
}

#[derive(serde::Deserialize)]
struct PinnedFile {
    servers: BTreeMap<String, Vec<PinnedKey>>,
}

#[derive(serde::Deserialize)]
struct PinnedKey {
    kid: String,
    #[serde(rename = "publicKey")]
    public_key: String,
}

fn pinned_raw(server: &str) -> Result<BTreeMap<String, [u8; ED25519_PUBLIC_KEY_BYTES]>> {
    let file: PinnedFile = serde_json::from_str(PINNED_JSON)
        .map_err(|err| Error::invalid(format!("pinned server keys are not JSON: {err}")))?;
    let keys = file
        .servers
        .get(server)
        .ok_or_else(|| Error::invalid(format!("no pinned server keys named {server:?}")))?;
    let mut out = BTreeMap::new();
    if server == PINNED_DEVELOPMENT && !cfg!(feature = "development-keys") {
        return Ok(out);
    }
    for key in keys {
        out.insert(key.kid.clone(), decode_public_key(&key.public_key)?);
    }
    Ok(out)
}

impl TrustedServerKeys {
    /// The keys this build carries for `server` ([`PINNED_PRODUCTION`] or
    /// [`PINNED_DEVELOPMENT`], which is empty without `development-keys`).
    pub fn pinned(server: &str) -> Result<Self> {
        let mut set = Self::new();
        for (kid, raw) in pinned_raw(server)? {
            set.insert(kid, &raw)?;
        }
        Ok(set)
    }

    /// How this (published) set differs from `pinned`.
    pub fn compare_pinned(&self, pinned: &Self) -> PinComparison {
        let unpinned = self
            .iter()
            .filter(|(kid, raw)| pinned.public_key(kid) != Some(*raw))
            .map(|(kid, _)| kid.to_owned())
            .collect();
        let missing = pinned
            .iter()
            .filter(|(kid, _)| !self.contains(kid))
            .map(|(kid, _)| kid.to_owned())
            .collect();
        PinComparison { unpinned, missing }
    }

    /// [`Self::from_published_json`], read against `pinned`. Under
    /// [`PinMode::Compare`] the set is exactly what `from_published_json`
    /// returns; under [`PinMode::Enforce`] it is the keys both lists hold
    /// under the same bytes. The comparison is the same either way.
    pub fn from_published_json_pinned(
        json: &str,
        pinned: &Self,
        mode: PinMode,
    ) -> Result<(Self, PinComparison)> {
        let published = Self::from_published_json(json)?;
        let comparison = published.compare_pinned(pinned);
        let trusted = match mode {
            PinMode::Compare => published,
            PinMode::Enforce => {
                let mut both = Self::new();
                for (kid, raw) in published.iter() {
                    if pinned.public_key(kid) == Some(raw) {
                        both.insert(kid, &raw)?;
                    }
                }
                both
            }
        };
        Ok((trusted, comparison))
    }
}

/// The binding door for the comparison: the published list (the body of
/// `GET /healthz/device-credential-keys`, verbatim) read against the set this
/// build carries for `server`. `""` when they match, else one line for the
/// device log ([`PinComparison::describe`]).
pub fn server_key_pin_report(published_json: &str, server: &str) -> Result<String> {
    let pinned = TrustedServerKeys::pinned(server)?;
    let (_, comparison) =
        TrustedServerKeys::from_published_json_pinned(published_json, &pinned, PinMode::Compare)?;
    Ok(comparison.describe())
}

/// The binding door for enforcement: the published list with every key
/// removed that this build does not carry for `server` under the same bytes.
/// Same shape as the input, so a client hands it to every door that takes the
/// published list; [`TrustedServerKeys::from_published_json`] of it is the
/// [`PinMode::Enforce`] set.
pub fn server_keys_pinned_json(published_json: &str, server: &str) -> Result<String> {
    let pinned = pinned_raw(server)?;
    let mut doc: serde_json::Value = serde_json::from_str(published_json)
        .map_err(|err| Error::invalid(format!("published key list is not JSON: {err}")))?;
    // Read the way from_published_json reads it, so the two cannot disagree on
    // a key that does not parse, nor on a document that is not an object.
    let published = TrustedServerKeys::from_published_json(published_json)?;
    if let Some(keys) = doc.get_mut("keys").and_then(|keys| keys.as_array_mut()) {
        keys.retain(|key| {
            let kid = key.get("kid").and_then(|v| v.as_str());
            let public_key = key.get("publicKey").and_then(|v| v.as_str());
            let device_use = key
                .get("use")
                .and_then(|v| v.as_str())
                .is_none_or(|name| name == DEVICE_KEY_USE);
            match (kid, public_key) {
                (Some(kid), Some(public_key)) if device_use => {
                    // A kid listed twice is trusted under its last entry
                    // (`from_published_json`), so an earlier entry under
                    // the carried bytes must not outlive a last one under
                    // other bytes: kept only when it is what the list says.
                    let raw = decode_public_key(public_key).ok();
                    raw.is_some()
                        && pinned.get(kid) == raw.as_ref()
                        && published.public_key(kid) == raw
                }
                _ => false,
            }
        });
    }
    serde_json::to_string(&doc)
        .map_err(|err| Error::invalid(format!("published key list did not serialize: {err}")))
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    /// The server reads more of the file than the core does: a production
    /// key may name the releases that carry it and be a standby key
    /// (the server's own check of this file). The core reads past both.
    #[test]
    fn a_carried_key_may_name_its_releases_and_be_a_standby() {
        let file: PinnedFile = serde_json::from_str(
            r#"{"about": [], "servers": {"production": [
                {"kid": "8730c349", "publicKey": "H6qyFNpHLMcUuB+Nfv1XtbPU0P01Ni7TQKPi1870a2g=",
                 "carriedFrom": {"ios": "1.0.300", "web": "20261102.1200"}, "standby": true}
            ]}}"#,
        )
        .expect("the core reads a key with carriedFrom and standby");
        let key = &file.servers["production"][0];
        assert_eq!(key.kid, "8730c349");
        decode_public_key(&key.public_key).expect("its public key");
        assert!(pinned_raw(PINNED_PRODUCTION).is_ok());
    }
}
