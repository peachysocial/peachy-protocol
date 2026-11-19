// SPDX-License-Identifier: MIT
//! Tree head checks (draft-ietf-keytrans-protocol-05 §11.3, §11.4) with the
//! profile's one signature and one auditor head per auditor.

use crate::head::{verify_auditor_tree_head, verify_tree_head};
use crate::suite::{Hash, PUBLIC_KEY_LEN};
use crate::verify::config::{AuditorKey, Deployment};
use crate::verify::error::{VerifyError, VerifyResult};
use crate::verify::state::{ClientState, SlotHead, View};
use crate::wire::{KeyedAuditorTreeHead, TreeHead};

/// The keys a slot accepts, with each one's start position.
pub(crate) fn slot_keys(
    deployment: &Deployment,
    state: &ClientState,
    slot: usize,
) -> Vec<([u8; PUBLIC_KEY_LEN], u64)> {
    match deployment.auditors.get(slot).map(|s| &s.key) {
        Some(AuditorKey::Pinned {
            public_key,
            start_position,
        }) => vec![(*public_key, *start_position)],
        Some(AuditorKey::Live) => state
            .accepted
            .iter()
            .filter(|a| usize::from(a.slot) == slot)
            .map(|a| (a.public_key, a.start_position))
            .collect(),
        None => Vec::new(),
    }
}

/// The slot an auditor key belongs to, if the client accepts it.
pub(crate) fn slot_of(deployment: &Deployment, state: &ClientState, key: &[u8]) -> Option<usize> {
    (0..deployment.auditors.len()).find(|&i| {
        slot_keys(deployment, state, i)
            .iter()
            .any(|(k, _)| k[..] == *key)
    })
}

/// For each slot, the accepted key that signed `head`, with its start
/// position. A slot without one fails: as [`VerifyError::UnknownAuditorKeys`]
/// when it is a live slot and the head names keys the client has not
/// accepted, else as [`VerifyError::MissingAuditor`].
pub(crate) fn signing_keys(
    deployment: &Deployment,
    state: &ClientState,
    head: &TreeHead,
) -> VerifyResult<Vec<([u8; PUBLIC_KEY_LEN], u64)>> {
    let mut out = Vec::with_capacity(deployment.auditors.len());
    for (i, slot) in deployment.auditors.iter().enumerate() {
        let keys = slot_keys(deployment, state, i);
        let chosen = head.signatures.iter().find_map(|s| {
            keys.iter()
                .find(|(k, _)| k[..] == s.auditor_public_key[..])
                .copied()
        });
        match chosen {
            Some(k) => out.push(k),
            None => {
                if slot.key == AuditorKey::Live {
                    let unknown: Vec<[u8; PUBLIC_KEY_LEN]> = head
                        .signatures
                        .iter()
                        .filter(|s| slot_of(deployment, state, &s.auditor_public_key).is_none())
                        .filter_map(|s| s.auditor_public_key.as_slice().try_into().ok())
                        .collect();
                    if !unknown.is_empty() {
                        return Err(VerifyError::UnknownAuditorKeys(unknown));
                    }
                }
                return Err(VerifyError::MissingAuditor { slot: i });
            }
        }
    }
    Ok(out)
}

/// Verifies the log's signature for every slot over `root`.
pub(crate) fn verify_signatures(
    deployment: &Deployment,
    keys: &[([u8; PUBLIC_KEY_LEN], u64)],
    head: &TreeHead,
    root: &Hash,
) -> VerifyResult<()> {
    for (i, (key, start)) in keys.iter().enumerate() {
        let config = deployment.configuration(i, key, *start)?;
        verify_tree_head(head, &config, root)
            .map_err(|_| VerifyError::BadTreeHeadSignature { slot: i })?;
    }
    Ok(())
}

/// The inputs of [`verify_updated`].
pub(crate) struct UpdatedHead<'a> {
    pub tree_head: &'a TreeHead,
    pub auditor_tree_heads: &'a [KeyedAuditorTreeHead],
    /// The log's root at `tree_head.tree_size`.
    pub root: Hash,
    /// The log's root at each auditor head's size, in the heads' order.
    pub auditor_roots: &'a [Hash],
    /// The rightmost entry's timestamp.
    pub rightmost_timestamp: u64,
}

/// §11.4 step 2 for an `updated` head, given the roots the response's
/// inclusion proof computed. Returns each slot's verified auditor head.
pub(crate) fn verify_updated(
    deployment: &Deployment,
    state: &ClientState,
    previous: Option<&View>,
    head: &UpdatedHead<'_>,
) -> VerifyResult<Vec<SlotHead>> {
    let keys = signing_keys(deployment, state, head.tree_head)?;
    verify_signatures(deployment, &keys, head.tree_head, &head.root)?;
    let n = head.tree_head.tree_size;
    let mut out = Vec::with_capacity(keys.len());
    for (i, (key, start)) in keys.iter().enumerate() {
        let mut matching = head
            .auditor_tree_heads
            .iter()
            .enumerate()
            .filter(|(_, h)| h.auditor_public_key[..] == key[..]);
        let (index, keyed) = matching
            .next()
            .ok_or(VerifyError::MissingAuditor { slot: i })?;
        if matching.next().is_some() {
            return Err(VerifyError::Proof("two heads from one auditor"));
        }
        let ah = &keyed.auditor_tree_head;
        let slot = &deployment.auditors[i];
        // Step 1: the previous head's coverage reaches this instance's start.
        if let Some(prev) = previous.and_then(|v| v.slots.get(i)) {
            if prev.tree_size < *start {
                return Err(VerifyError::AuditorStartPosition { slot: i });
            }
        }
        // Step 2: not after the log's rightmost entry, nor too far behind.
        if ah.timestamp > head.rightmost_timestamp
            || head.rightmost_timestamp - ah.timestamp > slot.max_auditor_lag
        {
            return Err(VerifyError::AuditorLag { slot: i });
        }
        // Step 3 was checked before the inclusion proof was read.
        if ah.tree_size == 0 || ah.tree_size > n {
            return Err(VerifyError::AuditorAheadOfLog { slot: i });
        }
        // Step 4.
        let root = head
            .auditor_roots
            .get(index)
            .ok_or(VerifyError::Proof("no root for an auditor head"))?;
        let config = deployment.configuration(i, key, *start)?;
        verify_auditor_tree_head(ah, &config, root)
            .map_err(|_| VerifyError::BadAuditorSignature { slot: i })?;
        out.push(SlotHead {
            auditor_public_key: *key,
            tree_size: ah.tree_size,
            timestamp: ah.timestamp,
        });
    }
    Ok(out)
}

/// The clock window of §4.2 and §11.4 step 1.
pub(crate) fn check_clock(deployment: &Deployment, rightmost: u64, now: u64) -> VerifyResult<()> {
    if rightmost > now.saturating_add(deployment.max_ahead) {
        return Err(VerifyError::TooFarAhead {
            by: rightmost - now,
        });
    }
    if now > rightmost.saturating_add(deployment.max_behind) {
        return Err(VerifyError::TooFarBehind {
            by: now - rightmost,
        });
    }
    Ok(())
}
