// SPDX-License-Identifier: MIT
//! The carried commit: a commit that brings the leave proposals it names
//! (docs/sealed-messages.md §Leaving, docs/delivery.md
//! §The carried commit).
//!
//! ## The gap this closes
//!
//! A leave is the one proposal Peachy takes by reference: the leaver sends
//! a Remove proposal for each of its own person's leaves as a message, and
//! another member's device commits them, naming each by its reference. A
//! member that never received a proposal cannot stage a commit that names it
//! (RFC 9420 §12.4), so a leave that reached only some devices stranded the
//! rest: one that held it committed it, and every device without it fell off
//! the group and had to rejoin.
//!
//! So the committer sends the proposal messages it is committing (the exact
//! bytes it took in through the message door) in the same envelope as the
//! commit. A receiver takes each carried proposal through the leave door
//! first (one it already holds is refused there as a replay, which is fine),
//! then the commit. This is framing, not protocol: the engine sees an
//! ordinary standalone proposal and an ordinary commit by reference, and
//! nothing about either changes.
//!
//! ## The frame
//!
//! ```text
//! raw     = MLSMessage(commit)                          starts 00 01
//! carried = ff 4c 43 01 ‖ n (1 byte) ‖ n × (BE32(len) ‖ proposal) ‖ commit
//! ```
//!
//! A raw RFC 9420 message starts with its protocol version, `00 01`; the
//! frame's magic starts `ff`, which no MLS version byte is, so a reader tells
//! the two apart by the first byte. `n` is 1 to [`MAX_CARRIED_PROPOSALS`].
//! The commit is everything after the last proposal, and is never empty. The
//! frame rides inside the envelope (kind 2) exactly where a raw commit does;
//! the server, which sees only the envelope, cannot tell them apart except by
//! length, and a leave commit's length was already its own (it names
//! proposals by reference). Every member that commits a given leave carries
//! the same proposal bytes, so the length still does not say who committed.
//!
//! Every commit of a leave carries its proposals, and every reader takes a
//! carried commit and a raw one (`Client::process_commit`,
//! `Client::commit_strands`, [`crate::hint::peek_message`]): every other
//! commit is raw.
//!
//! A steward's veto frame ([`crate::steward`]) may wrap a carried frame; it
//! is always the outer one, and [`split_carried`] strips it first.
//!
//! `mls/fixtures/carried-commit.json` pins the bytes, replayed through the
//! fixture door (`kind: "carried_commit"`) in every binding.

use crate::error::{Error, Result};

/// The four bytes a carried commit starts with. The first is `0xff`, which a
/// raw MLS message (version `00 01`) never starts with.
pub const CARRIED_COMMIT_MAGIC: [u8; 4] = [0xff, 0x4c, 0x43, 0x01];

/// The most proposals one carried commit brings: one per leaf of the
/// leaving person, and nobody has this many devices.
pub const MAX_CARRIED_PROPOSALS: usize = 64;

/// `commit` carrying `proposals`, or `commit` unchanged when there are none.
pub fn carry_proposals(proposals: &[Vec<u8>], commit: &[u8]) -> Result<Vec<u8>> {
    if commit.is_empty() {
        return Err(Error::invalid(
            "a commit to carry proposals with is not empty",
        ));
    }
    if proposals.is_empty() {
        return Ok(commit.to_vec());
    }
    if proposals.len() > MAX_CARRIED_PROPOSALS {
        return Err(Error::invalid("a commit carries at most 64 proposals"));
    }
    let count = u8::try_from(proposals.len())
        .map_err(|_| Error::invalid("a commit carries at most 64 proposals"))?;
    let total = CARRIED_COMMIT_MAGIC.len()
        + 1
        + proposals.iter().map(|p| 4 + p.len()).sum::<usize>()
        + commit.len();
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(&CARRIED_COMMIT_MAGIC);
    out.push(count);
    for proposal in proposals {
        if proposal.is_empty() {
            return Err(Error::invalid("a carried proposal is not empty"));
        }
        let len = u32::try_from(proposal.len())
            .map_err(|_| Error::invalid("a carried proposal is under 4 GiB"))?;
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(proposal);
    }
    out.extend_from_slice(commit);
    Ok(out)
}

/// What a commit entry holds: the steward's veto it is wrapped in (none for
/// most), the proposals it carries (none for a raw commit) and the commit
/// itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CarriedCommit<'a> {
    /// The signed veto's bytes, when the entry is a veto frame
    /// ([`crate::steward`] §The frames nest).
    pub veto: Option<&'a [u8]>,
    /// What the veto frame wraps: the whole entry when there is none. What a
    /// veto's signature is over.
    pub vetoed: &'a [u8],
    pub proposals: Vec<&'a [u8]>,
    pub commit: &'a [u8],
}

/// Split `bytes` into the veto it is wrapped in, the proposals it carries
/// and the commit. The frames nest in one order (veto, then carried, then
/// the raw commit), each at most once, so the veto frame is stripped first.
/// `bytes` unchanged, carrying nothing, when they are neither frame (a raw
/// commit, which the MLS parser then reads or refuses). A carried frame with
/// no proposal, too many, a length that runs past its end, an empty proposal
/// or no commit after the last proposal is refused, and so is a bad veto
/// frame ([`crate::steward::split_veto`]).
pub fn split_carried(bytes: &[u8]) -> Result<CarriedCommit<'_>> {
    let (veto, bytes) = crate::steward::split_veto(bytes)?;
    let Some(rest) = bytes.strip_prefix(&CARRIED_COMMIT_MAGIC[..]) else {
        return Ok(CarriedCommit {
            veto,
            vetoed: bytes,
            proposals: Vec::new(),
            commit: bytes,
        });
    };
    let (&count, mut rest) = rest
        .split_first()
        .ok_or_else(|| Error::invalid("a carried commit ends before its count"))?;
    let count = usize::from(count);
    if count == 0 || count > MAX_CARRIED_PROPOSALS {
        return Err(Error::invalid("a carried commit carries 1 to 64 proposals"));
    }
    let mut proposals = Vec::with_capacity(count);
    for _ in 0..count {
        let (len, tail) = rest
            .split_first_chunk::<4>()
            .ok_or_else(|| Error::invalid("a carried commit ends before a proposal's length"))?;
        let len = usize::try_from(u32::from_be_bytes(*len))
            .map_err(|_| Error::invalid("a carried proposal's length does not fit"))?;
        if len == 0 {
            return Err(Error::invalid("a carried proposal is not empty"));
        }
        if len > tail.len() {
            return Err(Error::invalid(
                "a carried proposal's length runs past the end",
            ));
        }
        let (proposal, tail) = tail.split_at(len);
        proposals.push(proposal);
        rest = tail;
    }
    if rest.is_empty() {
        return Err(Error::invalid("a carried commit holds no commit"));
    }
    Ok(CarriedCommit {
        veto,
        vetoed: bytes,
        proposals,
        commit: rest,
    })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    const COMMIT: &[u8] = &[0x00, 0x01, 0x00, 0x02, 0xaa, 0xbb];
    const P1: &[u8] = &[0x00, 0x01, 0x00, 0x02, 0x01];
    const P2: &[u8] = &[0x00, 0x01, 0x00, 0x02, 0x02, 0x03];

    #[test]
    fn the_magic_cannot_start_a_raw_commit() {
        assert_ne!(CARRIED_COMMIT_MAGIC[0], COMMIT[0]);
        let split = split_carried(COMMIT).unwrap();
        assert!(split.proposals.is_empty());
        assert_eq!(split.commit, COMMIT);
    }

    #[test]
    fn a_frame_round_trips() {
        let carried = carry_proposals(&[P1.to_vec(), P2.to_vec()], COMMIT).unwrap();
        assert_eq!(&carried[..4], &CARRIED_COMMIT_MAGIC);
        assert_eq!(carried[4], 2);
        assert_eq!(&carried[5..9], &[0, 0, 0, 5]);
        let split = split_carried(&carried).unwrap();
        assert_eq!(split.proposals, vec![P1, P2]);
        assert_eq!(split.commit, COMMIT);
    }

    #[test]
    fn a_veto_frame_is_stripped_before_the_carried_frame() {
        let carried = carry_proposals(&[P1.to_vec()], COMMIT).unwrap();
        let veto = crate::steward::SignedVeto {
            handle: [1u8; 32],
            epoch: 2,
            vetoed_next: [3u8; 32],
            replacement_next: [4u8; 32],
            signature: [5u8; 64],
        };
        let framed = crate::steward::wrap_veto(&veto, &carried).unwrap();
        let split = split_carried(&framed).unwrap();
        assert_eq!(split.veto, Some(&veto.to_bytes()[..]));
        assert_eq!(split.vetoed, &carried[..]);
        assert_eq!(split.proposals, vec![P1]);
        assert_eq!(split.commit, COMMIT);
        // Around a raw commit too.
        let framed = crate::steward::wrap_veto(&veto, COMMIT).unwrap();
        let split = split_carried(&framed).unwrap();
        assert!(split.veto.is_some());
        assert!(split.proposals.is_empty());
        assert_eq!(split.commit, COMMIT);
        // A carried frame never wraps a veto frame: the carried frame's
        // commit would be the veto frame, which no parser reads as a commit.
        let wrong = carry_proposals(&[P1.to_vec()], &framed).unwrap();
        assert!(split_carried(&wrong).unwrap().veto.is_none());
    }

    #[test]
    fn nothing_to_carry_is_the_raw_commit() {
        assert_eq!(carry_proposals(&[], COMMIT).unwrap(), COMMIT);
    }

    #[test]
    fn a_bad_frame_is_refused() {
        let carried = carry_proposals(&[P1.to_vec()], COMMIT).unwrap();
        // No commit after the proposal.
        assert!(split_carried(&carried[..4 + 1 + 4 + P1.len()]).is_err());
        // A length that runs past the end.
        let mut long = carried.clone();
        long[8] = 0xff;
        assert!(split_carried(&long).is_err());
        // No proposal, or no count.
        let mut none = carried.clone();
        none[4] = 0;
        assert!(split_carried(&none).is_err());
        assert!(split_carried(&CARRIED_COMMIT_MAGIC).is_err());
        // Too many.
        let mut many = carried;
        many[4] = 65;
        assert!(split_carried(&many).is_err());
        // An empty proposal, on either side.
        assert!(split_carried(&[0xff, 0x4c, 0x43, 0x01, 1, 0, 0, 0, 0, 0x00, 0x01]).is_err());
        assert!(carry_proposals(&[Vec::new()], COMMIT).is_err());
        assert!(carry_proposals(&[P1.to_vec()], &[]).is_err());
        assert!(carry_proposals(&vec![P1.to_vec(); 65], COMMIT).is_err());
    }
}
