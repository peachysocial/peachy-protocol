// SPDX-License-Identifier: MIT
//! Transparency proofs a peer hands over (draft §14): standard and
//! provisional credentials, and the update that completes a provisional
//! one (§14.2).
//!
//! None of these changes the [`ClientState`] (§14.2). A failure is reported
//! as [`FailureKind::BadProof`](super::FailureKind::BadProof) (the peer may
//! have sent it, so it is not evidence against the log) unless the anchor
//! is unknown.

use crate::implicit::frontier;
use crate::ladder::LadderKind;
use crate::verify::error::{VerifyError, VerifyResult};
use crate::verify::head::{signing_keys, verify_signatures};
use crate::verify::reader::ProofReader;
use crate::verify::search::{commitment_to, ladder_table};
use crate::verify::state::{ClientState, PendingCredential};
use crate::verify::walk::{base_ladder, Walk};
use crate::verify::Verifier;
use crate::wire::{
    CombinedTreeProof, Credential, CredentialBody, CredentialUpdate, InclusionProof,
    MonitorMapEntry,
};

/// A verified transparency proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialResult {
    /// The label.
    pub label: Vec<u8>,
    /// Its greatest version.
    pub version: u32,
    /// That version's value.
    pub value: Vec<u8>,
    /// For a provisional proof, what to keep until its update arrives
    /// ([`Verifier::verify_credential_update`]); `None` for a standard one.
    pub pending: Option<PendingCredential>,
}

/// A failure of something a peer supplied: never evidence against the log.
fn peer(e: VerifyError) -> VerifyError {
    match e {
        VerifyError::Inconsistent(what) => VerifyError::Proof(what),
        VerifyError::TimestampOrder => VerifyError::Proof("timestamps out of order"),
        VerifyError::BadTreeHeadSignature { .. } => VerifyError::Proof("bad tree head signature"),
        VerifyError::MissingAuditor { .. } => VerifyError::Proof("an auditor's signature missing"),
        other => other,
    }
}

impl Verifier {
    /// Verifies a transparency proof (§14) against the recent distinguished
    /// entries in `state`.
    pub fn verify_credential(
        &self,
        state: &ClientState,
        credential: &Credential,
    ) -> VerifyResult<CredentialResult> {
        self.credential(state, credential).map_err(peer)
    }

    fn credential(
        &self,
        state: &ClientState,
        credential: &Credential,
    ) -> VerifyResult<CredentialResult> {
        let d = credential.position;
        // Step 1.
        let anchor = state
            .distinguished_at(d)
            .ok_or(VerifyError::UnknownDistinguished { position: d })?;
        // Steps 3 and 4.
        let label = &credential.label;
        let version = credential.version;
        let target = commitment_to(&credential.opening, label, version, &credential.value)?;
        let table = ladder_table(
            &self.vrf,
            label,
            &base_ladder(Some(version)),
            &credential.binary_ladder,
            Some((version, target)),
            Some(version),
        )?;
        let pending = match &credential.body {
            CredentialBody::Standard { distinguished } => {
                // §14.1: one search ladder in the anchor's prefix tree.
                let proof = CombinedTreeProof {
                    timestamps: Vec::new(),
                    prefix_proofs: vec![distinguished.clone()],
                    prefix_roots: Vec::new(),
                    inclusion: InclusionProof {
                        elements: Vec::new(),
                    },
                };
                let mut reader = ProofReader::new(&proof, [(d, anchor.entry)], &table);
                let end = {
                    let mut walk = Walk::new(
                        &mut reader,
                        d + 1,
                        self.deployment.reasonable_monitoring_window,
                        self.deployment.maximum_lifetime,
                    );
                    walk.ladder(d, LadderKind::Search { target: version }, false)?
                };
                reader.consumed()?;
                if end.exact_greatest() != Some(Some(version)) {
                    return Err(VerifyError::VersionMismatch(
                        "the anchor does not hold the version as greatest",
                    ));
                }
                None
            }
            CredentialBody::Provisional { tree_head, search } => {
                // §14.2 step 1.
                let n = tree_head.tree_size;
                if n <= d {
                    return Err(VerifyError::Proof("a tree head not after the anchor"));
                }
                let retained: Vec<_> = frontier(d + 1)
                    .into_iter()
                    .zip(anchor.frontier.iter().copied())
                    .collect();
                let mut reader = ProofReader::new(search, retained, &table);
                // Step 2.
                let terminal = {
                    let mut walk = Walk::new(
                        &mut reader,
                        n,
                        self.deployment.reasonable_monitoring_window,
                        self.deployment.maximum_lifetime,
                    );
                    walk.update_view(Some(d + 1))?;
                    walk.greatest_search(version)?
                };
                if terminal <= d {
                    return Err(VerifyError::ProvisionalNotAfterAnchor);
                }
                // Steps 3 and 4.
                let fin = reader.finish(n, Some(d + 1), &anchor.full_subtrees, &[])?;
                let keys = signing_keys(&self.deployment, state, tree_head)?;
                verify_signatures(&self.deployment, &keys, tree_head, &fin.roots.root)?;
                let frontier_entries = frontier(n)
                    .into_iter()
                    .map(|x| {
                        fin.entries
                            .get(&x)
                            .copied()
                            .ok_or(VerifyError::Proof("no timestamp for a frontier entry"))
                    })
                    .collect::<VerifyResult<Vec<_>>>()?;
                Some(PendingCredential {
                    label: label.clone(),
                    version,
                    versions: table,
                    position: d,
                    terminal,
                    tree_size: n,
                    full_subtrees: fin.roots.full_subtrees,
                    frontier: frontier_entries,
                })
            }
        };
        Ok(CredentialResult {
            label: label.clone(),
            version,
            value: credential.value.value.clone(),
            pending,
        })
    }

    /// Verifies the update that completes a provisional transparency proof
    /// (§14.2). On success the proof counts as a standard one and `pending`
    /// can be dropped.
    pub fn verify_credential_update(
        &self,
        state: &ClientState,
        pending: &PendingCredential,
        update: &CredentialUpdate,
    ) -> VerifyResult<()> {
        self.credential_update(state, pending, update).map_err(peer)
    }

    fn credential_update(
        &self,
        state: &ClientState,
        pending: &PendingCredential,
        update: &CredentialUpdate,
    ) -> VerifyResult<()> {
        let q = update.position;
        // Step 1.
        let dq = state
            .distinguished_at(q)
            .ok_or(VerifyError::UnknownDistinguished { position: q })?;
        // Step 2. The monitoring below ends at q, or at a distinguished
        // entry on the way there.
        let terminal = pending.terminal;
        let between = state
            .distinguished
            .iter()
            .any(|e| e.position > terminal && e.position < q);
        let n = q
            .checked_add(1)
            .ok_or(VerifyError::Proof("position past the last"))?;
        if q <= terminal || between {
            return Err(VerifyError::WrongUpdateAnchor);
        }
        // Step 3, in the tree of q + 1 entries. When that tree contains the
        // credential's, the proof builds on the credential's retained tree;
        // when an entry before the credential's end has since become
        // distinguished, q + 1 is smaller and the proof stands alone.
        let kept: Vec<_> = frontier(pending.tree_size)
            .into_iter()
            .zip(pending.frontier.iter().copied())
            .collect();
        let (retained_size, retained, retained_full) = if pending.tree_size <= n {
            (
                Some(pending.tree_size),
                kept.clone(),
                pending.full_subtrees.as_slice(),
            )
        } else {
            (None, Vec::new(), &[][..])
        };
        let mut reader = ProofReader::new(&update.monitor, retained, &pending.versions);
        let map = {
            let mut walk = Walk::new(
                &mut reader,
                n,
                self.deployment.reasonable_monitoring_window,
                self.deployment.maximum_lifetime,
            );
            // The view update comes first; entry q's timestamp is in it.
            walk.update_view(retained_size)?;
            walk.contact_monitor(
                &[MonitorMapEntry {
                    position: terminal,
                    version: pending.version,
                }],
                None,
            )?
        };
        if map.iter().any(|e| e.position != q) {
            return Err(VerifyError::Proof(
                "monitoring stopped short of the distinguished entry",
            ));
        }
        // Step 4.
        let fin = reader.finish(n, retained_size, retained_full, &[])?;
        if fin.roots.full_subtrees != dq.full_subtrees {
            return Err(VerifyError::Proof(
                "the log tree differs from the retained distinguished entry",
            ));
        }
        // Any entry both trees show must be the same entry.
        for (x, entry) in &kept {
            if fin.entries.get(x).is_some_and(|e| e != entry) {
                return Err(VerifyError::Proof(
                    "the update's tree differs from the credential's",
                ));
            }
        }
        Ok(())
    }
}
