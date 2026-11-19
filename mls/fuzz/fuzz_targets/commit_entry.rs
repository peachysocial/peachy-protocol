// SPDX-License-Identifier: MIT
//! A commit entry's framing, as the commit door reads it before the MLS
//! parser: `split_carried`, which strips a steward's veto frame
//! (`split_veto`) and then a carried commit's proposals, and
//! `SignedVeto::from_bytes` for the veto it finds. The server and any member
//! choose these bytes. docs/mls-core.md §Fuzzing.
//!
//! The first input byte's bit 0 picks the layout:
//! - clear: the rest is a commit entry (`mls/fixtures/carried-commit.json`'s
//!   and `mls/fixtures/steward.json`'s `split` cases are laid out this way);
//! - set: `veto (1) ‖ count (1) ‖ count × (len (1) ‖ proposal) ‖ commit`.
//!   The target carries the proposals with the commit and, when `veto`'s
//!   bit 0 is set, wraps that in a veto the test steward key signs.
//!
//! Asserted:
//! - No input panics.
//! - The split is canonical: a veto it finds is a signed veto's length; one
//!   that reads writes back to the same bytes; and carrying the proposals it
//!   found with its commit, then wrapping that in its veto, rebuilds the
//!   entry byte for byte.
//! - An entry the target built splits back into exactly its veto, proposals
//!   and commit, or (for no proposals, an empty one, too many, or no commit)
//!   was refused when built. Its veto verifies under the steward key over
//!   what it wraps, and under no other key.

#![no_main]

use libfuzzer_sys::fuzz_target;
use peachy_mls_core::carried_commit::{carry_proposals, split_carried, MAX_CARRIED_PROPOSALS};
use peachy_mls_core::steward::{
    sign_statement, steward_public_key, wrap_veto, SignedVeto, SIGNED_VETO_BYTES, VETO_FRAME_MAGIC,
};

const STEWARD_SEED: [u8; 32] = [0x5e; 32];
const OTHER_SEED: [u8; 32] = [0x6f; 32];

fn check_split(bytes: &[u8]) {
    let Ok(split) = split_carried(bytes) else {
        return;
    };
    assert!(!split.vetoed.starts_with(&VETO_FRAME_MAGIC));
    let rebuilt = if split.proposals.is_empty() {
        assert_eq!(split.commit, split.vetoed);
        split.vetoed.to_vec()
    } else {
        assert!(split.proposals.len() <= MAX_CARRIED_PROPOSALS);
        assert!(
            !split.commit.is_empty(),
            "a carried frame split to no commit"
        );
        let proposals: Vec<Vec<u8>> = split.proposals.iter().map(|p| p.to_vec()).collect();
        carry_proposals(&proposals, split.commit).expect("what split carries again")
    };
    assert_eq!(rebuilt, split.vetoed, "a carried frame did not rebuild");
    let Some(veto) = split.veto else {
        assert_eq!(split.vetoed, bytes);
        return;
    };
    assert_eq!(veto.len(), SIGNED_VETO_BYTES);
    if let Ok(signed) = SignedVeto::from_bytes(veto) {
        assert_eq!(signed.to_bytes(), veto, "a signed veto did not write back");
        assert_eq!(
            wrap_veto(&signed, split.vetoed).expect("what split wraps again"),
            bytes,
            "a veto frame did not rebuild"
        );
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };
    if mode & 1 == 0 {
        check_split(rest);
        return;
    }

    let [veto_flag, count, tail @ ..] = rest else {
        return;
    };
    let mut rest: &[u8] = tail;
    let mut proposals = Vec::new();
    for _ in 0..*count {
        let Some((&len, tail)) = rest.split_first() else {
            return;
        };
        let Some((proposal, tail)) = tail.split_at_checked(usize::from(len)) else {
            return;
        };
        proposals.push(proposal.to_vec());
        rest = tail;
    }
    let commit = rest;
    let Ok(carried) = carry_proposals(&proposals, commit) else {
        assert!(
            commit.is_empty()
                || proposals.len() > MAX_CARRIED_PROPOSALS
                || proposals.iter().any(Vec::is_empty),
            "a carried commit was refused"
        );
        return;
    };
    let entry = if veto_flag & 1 == 1 {
        let mut veto = SignedVeto {
            handle: [*count; 32],
            epoch: u64::from(*veto_flag),
            vetoed_next: [0x11; 32],
            replacement_next: [0x22; 32],
            signature: [0; 64],
        };
        veto.signature = sign_statement(&STEWARD_SEED, &veto.statement(&carried));
        match wrap_veto(&veto, &carried) {
            Ok(entry) => {
                assert!(veto.verify(&steward_public_key(&STEWARD_SEED), &carried));
                assert!(!veto.verify(&steward_public_key(&OTHER_SEED), &carried));
                entry
            }
            Err(_) => {
                assert!(
                    carried.starts_with(&VETO_FRAME_MAGIC),
                    "a veto wrap was refused"
                );
                return;
            }
        }
    } else {
        carried.clone()
    };
    check_split(&entry);
    // A raw commit (no proposals) that itself starts like a frame (`ff`) is
    // the one entry a split reads otherwise than it was built: the reader
    // tells the forms apart by that byte, and no MLS message starts with it.
    if proposals.is_empty() && commit.first() == Some(&0xff) {
        return;
    }
    let split = split_carried(&entry).expect("an entry the target built splits");
    assert_eq!(split.vetoed, carried);
    assert_eq!(split.veto.is_some(), veto_flag & 1 == 1);
    assert_eq!(split.proposals, proposals);
    assert_eq!(split.commit, commit);
});
