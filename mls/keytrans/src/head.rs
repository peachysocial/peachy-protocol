// SPDX-License-Identifier: MIT
//! Tree head and auditor tree head signatures (draft-ietf-keytrans-protocol-05
//! §11.2, §11.3), with the profile's one signature per auditor
//! ([`crate::wire`] explains the extension).
//!
//! This module only makes and checks signatures. The rest of verifying a
//! [`FullTreeHead`](crate::wire::FullTreeHead) (tree sizes that grow, the
//! clock window, the auditor's lag, an auditor head for every auditor the
//! build carries) is the verifier's (`verify::head`), because it needs the
//! client's state.

use crate::codec::encode;
use crate::error::{Error, Result};
use crate::suite::{Hash, PublicKey, SecretKey};
use crate::wire::{
    AuditorTreeHead, AuditorTreeHeadTbs, Configuration, KeyedAuditorTreeHead, ModeConfig, TreeHead,
    TreeHeadSignature, TreeHeadTbs,
};

/// The auditor key a configuration names: the profile runs in third-party
/// auditing mode only.
pub fn auditor_key(config: &Configuration) -> Result<&[u8]> {
    match &config.mode {
        ModeConfig::ThirdPartyAuditing {
            auditor_public_key, ..
        } => Ok(auditor_public_key),
        _ => Err(Error::InvalidArgument(
            "configuration is not in third-party auditing mode",
        )),
    }
}

/// The bytes the log signs for `config` at `tree_size` with `root`.
pub fn tree_head_tbs(config: &Configuration, tree_size: u64, root: &Hash) -> Result<Vec<u8>> {
    encode(&TreeHeadTbs {
        config: config.clone(),
        tree_size,
        root: *root,
    })
}

/// Signs a tree head once per configuration, one per auditor. Every
/// configuration must name `log_key`'s public half as its signature key and
/// a distinct auditor key.
pub fn sign_tree_head(
    log_key: &SecretKey,
    configs: &[Configuration],
    tree_size: u64,
    root: &Hash,
) -> Result<TreeHead> {
    if configs.len() > 0xff {
        return Err(Error::InvalidArgument("too many auditors"));
    }
    let public = log_key.public_key().to_bytes();
    let mut signatures: Vec<TreeHeadSignature> = Vec::with_capacity(configs.len());
    for config in configs {
        config.ciphersuite.require_supported()?;
        if config.signature_public_key != public {
            return Err(Error::InvalidArgument(
                "configuration names another log key",
            ));
        }
        let auditor = auditor_key(config)?;
        if signatures.iter().any(|s| s.auditor_public_key == auditor) {
            return Err(Error::InvalidArgument("two configurations for one auditor"));
        }
        signatures.push(TreeHeadSignature {
            auditor_public_key: auditor.to_vec(),
            signature: log_key
                .sign(&tree_head_tbs(config, tree_size, root)?)
                .to_vec(),
        });
    }
    Ok(TreeHead {
        tree_size,
        signatures,
    })
}

/// Verifies the log's signature in `head` for `config` (the one naming
/// `config`'s auditor key) over `root`. A head with no signature for that
/// auditor, or two, fails.
pub fn verify_tree_head(head: &TreeHead, config: &Configuration, root: &Hash) -> Result<()> {
    config.ciphersuite.require_supported()?;
    let auditor = auditor_key(config)?;
    let mut matching = head
        .signatures
        .iter()
        .filter(|s| s.auditor_public_key == auditor);
    let signature = matching.next().ok_or(Error::BadSignature)?;
    if matching.next().is_some() {
        return Err(Error::MalformedProof("two signatures for one auditor"));
    }
    let key = PublicKey::from_bytes(&config.signature_public_key)?;
    key.verify(
        &tree_head_tbs(config, head.tree_size, root)?,
        &signature.signature,
    )
}

/// The bytes an auditor signs.
pub fn auditor_tree_head_tbs(
    config: &Configuration,
    timestamp: u64,
    tree_size: u64,
    root: &Hash,
) -> Result<Vec<u8>> {
    encode(&AuditorTreeHeadTbs {
        config: config.clone(),
        timestamp,
        tree_size,
        root: *root,
    })
}

/// An auditor's signed head over the log at `tree_size`, whose root is
/// `root` and whose rightmost entry's timestamp is `timestamp`. `config`
/// must name `auditor`'s public half.
pub fn sign_auditor_tree_head(
    auditor: &SecretKey,
    config: &Configuration,
    timestamp: u64,
    tree_size: u64,
    root: &Hash,
) -> Result<AuditorTreeHead> {
    config.ciphersuite.require_supported()?;
    if auditor_key(config)? != auditor.public_key().to_bytes() {
        return Err(Error::InvalidArgument(
            "configuration names another auditor key",
        ));
    }
    Ok(AuditorTreeHead {
        timestamp,
        tree_size,
        signature: auditor
            .sign(&auditor_tree_head_tbs(config, timestamp, tree_size, root)?)
            .to_vec(),
    })
}

/// Verifies an auditor head's signature under the auditor key `config`
/// names, where `root` is the log's root at the head's `tree_size`.
pub fn verify_auditor_tree_head(
    head: &AuditorTreeHead,
    config: &Configuration,
    root: &Hash,
) -> Result<()> {
    config.ciphersuite.require_supported()?;
    let key = PublicKey::from_bytes(auditor_key(config)?)?;
    key.verify(
        &auditor_tree_head_tbs(config, head.timestamp, head.tree_size, root)?,
        &head.signature,
    )
}

/// The head in `heads` from the auditor `auditor_public_key`, if exactly one.
pub fn auditor_head_for<'a>(
    heads: &'a [KeyedAuditorTreeHead],
    auditor_public_key: &[u8],
) -> Result<&'a AuditorTreeHead> {
    let mut matching = heads
        .iter()
        .filter(|h| h.auditor_public_key == auditor_public_key);
    let head = matching
        .next()
        .ok_or(Error::InvalidArgument("no head from that auditor"))?;
    if matching.next().is_some() {
        return Err(Error::MalformedProof("two heads from one auditor"));
    }
    Ok(&head.auditor_tree_head)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::suite::CipherSuite;

    fn config(log: &SecretKey, auditor: &SecretKey) -> Configuration {
        Configuration {
            ciphersuite: CipherSuite::Kt128Sha256Ed25519,
            signature_public_key: log.public_key().to_bytes().to_vec(),
            vrf_public_key: vec![0x22; 32],
            mode: ModeConfig::ThirdPartyAuditing {
                max_auditor_lag: 7 * 86_400_000,
                auditor_start_pos: 0,
                auditor_public_key: auditor.public_key().to_bytes().to_vec(),
            },
            max_ahead: 86_400_000,
            max_behind: 86_400_000,
            reasonable_monitoring_window: 86_400_000,
            maximum_lifetime: None,
        }
    }

    #[test]
    fn one_signature_per_auditor() {
        let log = SecretKey::from_seed(&[1; 32]);
        let a = SecretKey::from_seed(&[2; 32]);
        let b = SecretKey::from_seed(&[3; 32]);
        let (ca, cb) = (config(&log, &a), config(&log, &b));
        let root = [9; 32];
        let head = sign_tree_head(&log, &[ca.clone(), cb.clone()], 12, &root).unwrap();
        assert_eq!(head.signatures.len(), 2);
        verify_tree_head(&head, &ca, &root).unwrap();
        verify_tree_head(&head, &cb, &root).unwrap();
        // Each signature binds its own configuration: swapping them fails.
        let mut swapped = head.clone();
        let first = swapped.signatures[0].signature.clone();
        swapped.signatures[0].signature = swapped.signatures[1].signature.clone();
        swapped.signatures[1].signature = first;
        assert_eq!(
            verify_tree_head(&swapped, &ca, &root),
            Err(Error::BadSignature)
        );
        // Another root, size, or an auditor the head does not cover.
        assert_eq!(
            verify_tree_head(&head, &ca, &[8; 32]),
            Err(Error::BadSignature)
        );
        let mut resized = head.clone();
        resized.tree_size = 13;
        assert_eq!(
            verify_tree_head(&resized, &ca, &root),
            Err(Error::BadSignature)
        );
        let c = config(&log, &SecretKey::from_seed(&[4; 32]));
        assert_eq!(verify_tree_head(&head, &c, &root), Err(Error::BadSignature));
        // A duplicate entry for one auditor is refused.
        let mut doubled = head.clone();
        doubled.signatures.push(doubled.signatures[0].clone());
        assert!(verify_tree_head(&doubled, &ca, &root).is_err());
    }

    #[test]
    fn signing_refuses_mismatched_configurations() {
        let log = SecretKey::from_seed(&[1; 32]);
        let a = SecretKey::from_seed(&[2; 32]);
        let ca = config(&log, &a);
        let other_log = SecretKey::from_seed(&[5; 32]);
        assert!(sign_tree_head(&other_log, std::slice::from_ref(&ca), 1, &[0; 32]).is_err());
        assert!(sign_tree_head(&log, &[ca.clone(), ca.clone()], 1, &[0; 32]).is_err());
        let mut contact = ca.clone();
        contact.mode = ModeConfig::ContactMonitoring {
            leaf_public_key: vec![],
        };
        assert!(sign_tree_head(&log, &[contact], 1, &[0; 32]).is_err());
        let mut p256 = ca.clone();
        p256.ciphersuite = CipherSuite::Kt128Sha256P256;
        assert!(sign_tree_head(&log, &[p256], 1, &[0; 32]).is_err());
        assert!(sign_auditor_tree_head(&log, &ca, 1, 1, &[0; 32]).is_err());
    }

    #[test]
    fn auditor_heads() {
        let log = SecretKey::from_seed(&[1; 32]);
        let a = SecretKey::from_seed(&[2; 32]);
        let ca = config(&log, &a);
        let root = [7; 32];
        let head = sign_auditor_tree_head(&a, &ca, 1_000, 5, &root).unwrap();
        verify_auditor_tree_head(&head, &ca, &root).unwrap();
        let mut later = head.clone();
        later.timestamp += 1;
        assert_eq!(
            verify_auditor_tree_head(&later, &ca, &root),
            Err(Error::BadSignature)
        );
        assert_eq!(
            verify_auditor_tree_head(&head, &ca, &[6; 32]),
            Err(Error::BadSignature)
        );
        // The auditor's signature is not the log's: a tree head TBS with the
        // same fields does not verify as an auditor head.
        let keyed = vec![KeyedAuditorTreeHead {
            auditor_public_key: a.public_key().to_bytes().to_vec(),
            auditor_tree_head: head.clone(),
        }];
        assert_eq!(
            auditor_head_for(&keyed, &a.public_key().to_bytes()).unwrap(),
            &head
        );
        assert!(auditor_head_for(&keyed, &[0; 32]).is_err());
        let doubled = [keyed[0].clone(), keyed[0].clone()];
        assert!(auditor_head_for(&doubled, &a.public_key().to_bytes()).is_err());
    }

    #[test]
    fn tbs_bytes_are_the_drafts() {
        let log = SecretKey::from_seed(&[1; 32]);
        let a = SecretKey::from_seed(&[2; 32]);
        let ca = config(&log, &a);
        let cfg = encode(&ca).unwrap();
        let tbs = tree_head_tbs(&ca, 3, &[0xab; 32]).unwrap();
        assert_eq!(tbs.len(), cfg.len() + 8 + 32);
        assert_eq!(&tbs[..cfg.len()], &cfg[..]);
        let atbs = auditor_tree_head_tbs(&ca, 2, 3, &[0xab; 32]).unwrap();
        assert_eq!(
            &atbs[cfg.len()..cfg.len() + 16],
            &[0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 3]
        );
    }
}
