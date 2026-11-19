// SPDX-License-Identifier: MIT
//! The profile's parameters and the log configurations built from them.
//!
//! # What is fixed, and what is not
//!
//! Every number the draft's [`Configuration`] carries is fixed by the
//! profile: the cipher suite, the deployment mode, the clock window, the
//! auditor lag bound, the reasonable monitoring window and the (absent)
//! maximum lifetime. A client never takes one of them from the log; it
//! builds the configuration it verifies against from these constants and
//! the keys its build carries, so a log that changed a parameter would sign
//! bytes no client reconstructs.
//!
//! The keys are not fixed here. The log's signature and VRF keys are pinned
//! per build. An auditor's key depends on the auditor: an independent
//! auditor's is pinned like the log's, while the attested auditor makes a new
//! key on every boot, which a client reads live and checks against the log's
//! `k` label. Each auditor therefore comes in as an [`Auditor`] at the time
//! a configuration is built.
//!
//! # `config_version`, and where it lives
//!
//! draft-ietf-keytrans-protocol-05's `Configuration` has no version field,
//! and the profile adds none: every signed structure stays byte-identical to
//! the draft's. [`CONFIG_VERSION`] lives outside the signed bytes, in two
//! places:
//!
//! - **the configuration a client build carries**, next to the log's keys,
//!   which names the one version (or, while a change rolls out, the
//!   versions) that build verifies; and
//! - **every request and transparency proof on the wire**, so a receiver
//!   picks the configuration it verifies against from its own build, never
//!   from what a server says, and refuses a version it does not carry.
//!
//! What binds a signature to its version is the signed [`Configuration`]
//! itself. The rule that makes that hold: **a new `config_version` changes
//! the configuration's bytes.** A new draft revision, a parameter change, a
//! key rotation or a lifetime is each a new version; if nothing in the
//! configuration would otherwise differ (a revision that only changes how
//! other structures encode or hash), the new version takes a new log
//! signature key. So no tree head, auditor head or proof made under one
//! version verifies under another, without a field the draft does not have.
//! Rolling a version out is a phased change like any wire format: builds
//! learn the new configuration, then the log switches, then builds drop the
//! old one.

use crate::error::{Error, Result};
use crate::profile::labels::{KIND_ACCOUNT, KIND_AUDITOR_INSTANCE, KIND_HANDLE, KIND_PHONE};
use crate::suite::{CipherSuite, PublicKey, PUBLIC_KEY_LEN};
use crate::vrf::VrfPublicKey;
use crate::wire::{Configuration, DeploymentMode, ModeConfig};

/// The configuration version this profile defines. It is not encoded in any
/// signed structure (see the module's header for where it lives).
pub const CONFIG_VERSION: u32 = 1;

/// The draft revision version 1 implements.
pub const DRAFT_REVISION: &str = "draft-ietf-keytrans-protocol-05";

/// One hour, in milliseconds (the draft's unit for every duration).
pub const HOUR_MS: u64 = 60 * 60 * 1000;
/// One day, in milliseconds.
pub const DAY_MS: u64 = 24 * HOUR_MS;

/// `KT_128_SHA256_Ed25519` (0x0002): SHA-256, Ed25519 and
/// ECVRF-EDWARDS25519-SHA512-TAI, the primitives the MLS core already uses.
pub const CIPHER_SUITE: CipherSuite = CipherSuite::Kt128Sha256Ed25519;

/// `thirdPartyAuditing`: the only mode in which no client has to trust that
/// the operator shows everyone the same tree, because every head a client
/// accepts also carries an auditor's signature over the same root.
pub const DEPLOYMENT_MODE: DeploymentMode = DeploymentMode::ThirdPartyAuditing;

/// `max_auditor_lag`: 7 days. The longest a fully malicious operator can
/// keep a split view before every client refuses its heads; long enough
/// that an auditor relaunch or outage costs nothing visible.
pub const MAX_AUDITOR_LAG_MS: u64 = 7 * DAY_MS;

/// `max_ahead`: a head may be up to 24 hours ahead of the device's clock.
/// Device clocks drift, and a phone that has been off for a while is often
/// wrong by hours.
pub const MAX_AHEAD_MS: u64 = DAY_MS;

/// `max_behind`: a head may be up to 24 hours behind the device's clock, the
/// same allowance the other way.
pub const MAX_BEHIND_MS: u64 = DAY_MS;

/// `reasonable_monitoring_window`: 1 day. Owners self-check at least daily
/// while online, distinguished entries come about daily (draft §6.1 spaces
/// them one window apart), and a new device's transparency proof is
/// provisional for at most a day.
pub const REASONABLE_MONITORING_WINDOW_MS: u64 = DAY_MS;

/// `maximum_lifetime`: unset, so the log keeps every entry. Nothing has to be
/// pruned at this size. A later configuration version may set one, never
/// below [`MIN_LIFETIME_WINDOWS`] windows ([`check_maximum_lifetime`]).
pub const MAXIMUM_LIFETIME_MS: Option<u64> = None;

/// The fewest reasonable monitoring windows a maximum lifetime may span, if
/// a later version sets one. The draft requires only more than one window;
/// thirty leave an owner who was offline for weeks still able to see every
/// version it missed.
pub const MIN_LIFETIME_WINDOWS: u64 = 30;

/// `auditor_start_pos` for the attested auditor: 0. Every instance verifies
/// the log from its first entry (a cold start replays it, a handoff resumes
/// from a predecessor whose lineage did), so the lineage has processed every
/// entry.
pub const ATTESTED_AUDITOR_START_POS: u64 = 0;

/// The most auditors one tree head can carry: a `TreeHead`'s signature list
/// has a one-byte length.
pub const MAX_AUDITORS: usize = 0xff;

/// The label kinds of the profile, in the order the spec introduces them:
/// account `a`, handle `h`, phone `p` and auditor instance `k`. One log,
/// four spaces that cannot collide.
pub const LABEL_KINDS: [u8; 4] = [KIND_ACCOUNT, KIND_HANDLE, KIND_PHONE, KIND_AUDITOR_INSTANCE];

/// One auditor, as a configuration names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Auditor {
    /// The auditor's Ed25519 public key.
    pub public_key: [u8; PUBLIC_KEY_LEN],
    /// `auditor_start_pos`: the first log entry the auditor processed.
    pub start_pos: u64,
}

/// The keys of one deployment under this profile: what a client build
/// carries, plus the auditors known when a configuration is built.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Profile {
    signature_public_key: [u8; PUBLIC_KEY_LEN],
    vrf_public_key: [u8; PUBLIC_KEY_LEN],
    auditors: Vec<Auditor>,
}

impl Profile {
    /// A deployment with these keys. Refuses an invalid or small-order key,
    /// no auditor, more than [`MAX_AUDITORS`], one auditor key twice, or an
    /// auditor key equal to the log's signature key (an operator that is its
    /// own auditor audits nothing).
    pub fn new(
        signature_public_key: [u8; PUBLIC_KEY_LEN],
        vrf_public_key: [u8; PUBLIC_KEY_LEN],
        auditors: Vec<Auditor>,
    ) -> Result<Self> {
        PublicKey::from_bytes(&signature_public_key)?;
        VrfPublicKey::from_bytes(&vrf_public_key)?;
        if auditors.is_empty() {
            return Err(Error::InvalidArgument("a profile needs an auditor"));
        }
        if auditors.len() > MAX_AUDITORS {
            return Err(Error::InvalidArgument("too many auditors"));
        }
        for (i, a) in auditors.iter().enumerate() {
            PublicKey::from_bytes(&a.public_key)?;
            if a.public_key == signature_public_key {
                return Err(Error::InvalidArgument(
                    "an auditor key is the log's own key",
                ));
            }
            if auditors[..i].iter().any(|b| b.public_key == a.public_key) {
                return Err(Error::InvalidArgument("one auditor key twice"));
            }
        }
        Ok(Profile {
            signature_public_key,
            vrf_public_key,
            auditors,
        })
    }

    /// The log's tree head signature key.
    pub fn signature_public_key(&self) -> &[u8; PUBLIC_KEY_LEN] {
        &self.signature_public_key
    }

    /// The log's VRF key.
    pub fn vrf_public_key(&self) -> &[u8; PUBLIC_KEY_LEN] {
        &self.vrf_public_key
    }

    /// The auditors, in the order given.
    pub fn auditors(&self) -> &[Auditor] {
        &self.auditors
    }

    /// The configuration naming `auditor`: the draft's structure, with the
    /// profile's parameters and this deployment's keys.
    pub fn configuration(&self, auditor: &Auditor) -> Configuration {
        Configuration {
            ciphersuite: CIPHER_SUITE,
            signature_public_key: self.signature_public_key.to_vec(),
            vrf_public_key: self.vrf_public_key.to_vec(),
            mode: ModeConfig::ThirdPartyAuditing {
                max_auditor_lag: MAX_AUDITOR_LAG_MS,
                auditor_start_pos: auditor.start_pos,
                auditor_public_key: auditor.public_key.to_vec(),
            },
            max_ahead: MAX_AHEAD_MS,
            max_behind: MAX_BEHIND_MS,
            reasonable_monitoring_window: REASONABLE_MONITORING_WINDOW_MS,
            maximum_lifetime: MAXIMUM_LIFETIME_MS,
        }
    }

    /// One configuration per auditor, in order: what the log signs a tree
    /// head under ([`crate::head::sign_tree_head`]).
    pub fn configurations(&self) -> Vec<Configuration> {
        self.auditors
            .iter()
            .map(|a| self.configuration(a))
            .collect()
    }
}

/// Checks that `config` carries exactly this profile's parameters: the suite,
/// the mode, the lag bound, the clock window, the monitoring window and the
/// lifetime. Keys are not checked here (they are a deployment's, not the
/// profile's).
pub fn check_configuration(config: &Configuration) -> Result<()> {
    if config.ciphersuite != CIPHER_SUITE {
        return Err(Error::InvalidArgument("not the profile's cipher suite"));
    }
    match &config.mode {
        ModeConfig::ThirdPartyAuditing {
            max_auditor_lag, ..
        } if *max_auditor_lag == MAX_AUDITOR_LAG_MS => {}
        ModeConfig::ThirdPartyAuditing { .. } => {
            return Err(Error::InvalidArgument("not the profile's auditor lag"));
        }
        _ => return Err(Error::InvalidArgument("not the profile's deployment mode")),
    }
    if config.max_ahead != MAX_AHEAD_MS || config.max_behind != MAX_BEHIND_MS {
        return Err(Error::InvalidArgument("not the profile's clock window"));
    }
    if config.reasonable_monitoring_window != REASONABLE_MONITORING_WINDOW_MS {
        return Err(Error::InvalidArgument(
            "not the profile's monitoring window",
        ));
    }
    if config.maximum_lifetime != MAXIMUM_LIFETIME_MS {
        return Err(Error::InvalidArgument("not the profile's maximum lifetime"));
    }
    Ok(())
}

/// Checks a maximum lifetime a later configuration version might set: absent,
/// or at least [`MIN_LIFETIME_WINDOWS`] monitoring windows (which also meets
/// the draft's rule that it exceed one window).
pub fn check_maximum_lifetime(lifetime: Option<u64>) -> Result<()> {
    match lifetime {
        None => Ok(()),
        Some(ms) if ms >= MIN_LIFETIME_WINDOWS * REASONABLE_MONITORING_WINDOW_MS => Ok(()),
        Some(_) => Err(Error::InvalidArgument("maximum lifetime below 30 windows")),
    }
}

/// The kind byte of `label`, if it is one of [`LABEL_KINDS`].
pub fn label_kind(label: &[u8]) -> Result<u8> {
    match label.first() {
        Some(kind) if LABEL_KINDS.contains(kind) => Ok(*kind),
        Some(_) => Err(Error::Decode("unknown label kind".into())),
        None => Err(Error::Decode("empty label".into())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::{decode, encode};
    use crate::head::{sign_tree_head, verify_tree_head};
    use crate::suite::SecretKey;
    use crate::vrf::VrfSecretKey;

    fn key(seed: u8) -> [u8; 32] {
        SecretKey::from_seed(&[seed; 32]).public_key().to_bytes()
    }

    fn vrf_key(seed: u8) -> [u8; 32] {
        VrfSecretKey::from_seed(&[seed; 32])
            .unwrap()
            .public_key()
            .to_bytes()
    }

    fn auditor(seed: u8, start_pos: u64) -> Auditor {
        Auditor {
            public_key: key(seed),
            start_pos,
        }
    }

    #[test]
    fn the_values() {
        assert_eq!(CONFIG_VERSION, 1);
        assert_eq!(CIPHER_SUITE as u16, 0x0002);
        assert_eq!(DEPLOYMENT_MODE as u8, 3);
        assert_eq!(MAX_AUDITOR_LAG_MS, 604_800_000);
        assert_eq!(MAX_AHEAD_MS, 86_400_000);
        assert_eq!(MAX_BEHIND_MS, 86_400_000);
        assert_eq!(REASONABLE_MONITORING_WINDOW_MS, 86_400_000);
        assert_eq!(MAXIMUM_LIFETIME_MS, None);
        assert_eq!(LABEL_KINDS, *b"ahpk");
    }

    #[test]
    fn configurations_are_the_drafts_with_the_profiles_values() {
        let profile =
            Profile::new(key(1), vrf_key(2), vec![auditor(3, 0), auditor(4, 17)]).unwrap();
        let configs = profile.configurations();
        assert_eq!(configs.len(), 2);
        for (config, a) in configs.iter().zip(profile.auditors()) {
            check_configuration(config).unwrap();
            assert_eq!(
                decode::<Configuration>(&encode(config).unwrap()).unwrap(),
                *config
            );
            match &config.mode {
                ModeConfig::ThirdPartyAuditing {
                    auditor_start_pos,
                    auditor_public_key,
                    ..
                } => {
                    assert_eq!(*auditor_start_pos, a.start_pos);
                    assert_eq!(auditor_public_key, &a.public_key.to_vec());
                }
                _ => panic!("not third-party auditing"),
            }
        }
        // The log can sign a head under them, one signature per auditor.
        let log = SecretKey::from_seed(&[1; 32]);
        let head = sign_tree_head(&log, &configs, 5, &[7; 32]).unwrap();
        for config in &configs {
            verify_tree_head(&head, config, &[7; 32]).unwrap();
        }
    }

    #[test]
    fn a_configuration_off_the_profile_is_refused() {
        let profile = Profile::new(key(1), vrf_key(2), vec![auditor(3, 0)]).unwrap();
        let good = profile.configuration(&profile.auditors()[0]);
        let mut cases: Vec<Configuration> = Vec::new();
        let mut c = good.clone();
        c.ciphersuite = CipherSuite::Kt128Sha256P256;
        cases.push(c);
        let mut c = good.clone();
        c.mode = ModeConfig::ContactMonitoring {
            leaf_public_key: key(5).to_vec(),
        };
        cases.push(c);
        let mut c = good.clone();
        c.mode = ModeConfig::ThirdPartyAuditing {
            max_auditor_lag: MAX_AUDITOR_LAG_MS + 1,
            auditor_start_pos: 0,
            auditor_public_key: key(3).to_vec(),
        };
        cases.push(c);
        let mut c = good.clone();
        c.max_ahead += 1;
        cases.push(c);
        let mut c = good.clone();
        c.max_behind -= 1;
        cases.push(c);
        let mut c = good.clone();
        c.reasonable_monitoring_window = 14 * DAY_MS;
        cases.push(c);
        let mut c = good.clone();
        c.maximum_lifetime = Some(365 * DAY_MS);
        cases.push(c);
        for c in cases {
            assert!(check_configuration(&c).is_err(), "{c:?}");
        }
    }

    #[test]
    fn profiles_refuse_bad_auditor_lists() {
        assert!(Profile::new(key(1), vrf_key(2), vec![]).is_err());
        assert!(Profile::new(key(1), vrf_key(2), vec![auditor(3, 0), auditor(3, 9)]).is_err());
        assert!(Profile::new(key(1), vrf_key(2), vec![auditor(1, 0)]).is_err());
        // The identity point is a small-order key.
        let mut identity = [0u8; 32];
        identity[0] = 1;
        assert!(Profile::new(identity, vrf_key(2), vec![auditor(3, 0)]).is_err());
        assert!(Profile::new(key(1), identity, vec![auditor(3, 0)]).is_err());
        let small = Auditor {
            public_key: identity,
            start_pos: 0,
        };
        assert!(Profile::new(key(1), vrf_key(2), vec![small]).is_err());
        let many: Vec<Auditor> = (0..=255u16)
            .map(|i| {
                let mut seed = [0xa5; 32];
                seed[..2].copy_from_slice(&i.to_be_bytes());
                Auditor {
                    public_key: SecretKey::from_seed(&seed).public_key().to_bytes(),
                    start_pos: 0,
                }
            })
            .collect();
        assert!(Profile::new(key(1), vrf_key(2), many[..255].to_vec()).is_ok());
        assert!(Profile::new(key(1), vrf_key(2), many).is_err());
    }

    #[test]
    fn lifetimes_and_label_kinds() {
        check_maximum_lifetime(None).unwrap();
        check_maximum_lifetime(Some(30 * DAY_MS)).unwrap();
        assert!(check_maximum_lifetime(Some(30 * DAY_MS - 1)).is_err());
        assert!(check_maximum_lifetime(Some(0)).is_err());
        for kind in LABEL_KINDS {
            assert_eq!(label_kind(&[kind, 1, 2]).unwrap(), kind);
        }
        assert!(label_kind(&[]).is_err());
        assert!(label_kind(b"zebra").is_err());
    }
}
