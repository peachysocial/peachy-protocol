// SPDX-License-Identifier: MIT
//! Every commit a member could make is ONE length on the wire, whoever makes
//! it (docs/sealed-messages.md §Size-hiding padding).
//!
//! ## The leak this closes
//!
//! A commit's UpdatePath (RFC 9420 §7.6) holds one HPKE public key per node of
//! the committer's filtered direct path and one HPKE ciphertext per node in the
//! resolution of each copath child. With X-Wing each of those is over a
//! kilobyte, so the path's size depends on WHERE in the tree its committer
//! sits: in a 3-leaf tree leaf 2's sibling is blank and its path is a node
//! shorter than leaf 0's or leaf 1's. The server knows every leaf's position
//! (it saw each Welcome go to a device, in order, and every departure as a
//! shorter recipient list), so a length class it can tell apart is a device it
//! can name. Neither the 256-byte message block nor the envelope's bucket
//! (at most 12%) hides a step of a kilobyte.
//!
//! ## What a commit is padded to
//!
//! The target is computed from what every member holds alike: the public tree
//! as the commit's proposals leave it, and the proposals themselves. It is an
//! UpdatePath no surviving member's could exceed, set by the tree's width and
//! how many members it holds: the largest of their leaf nodes as a commit
//! would re-sign it, one public key per level of the tree, and one ciphertext
//! per member but one, this commit's joiners left out. No member's path is
//! longer: it has at most one node per level, and seals at most one
//! ciphertext per other member, since every other member sits under exactly
//! one of its copath children and a non-blank parent in that child's
//! resolution stands for at least one member below it. That, plus the
//! proposals and the fixed authentication bytes, rounded up to the 256-byte
//! message block, is the target.
//!
//! It is not the largest path any member could send from this tree, though
//! that would cost less. That figure depends on where the tree's blanks and
//! filled parents lie, so after a removal it says where the removed device
//! sat; and the founder's device sits at leaf 0
//! (docs/delivery.md §Founding a conversation), so it would say
//! whether that device was the founder's. The width and the member count say
//! nothing of where anybody sits.
//!
//! The commit's own ciphertext is padded to exactly the target, through
//! RFC 9420 §6.3.1's `padding` field (OpenMLS's `padding_size`, which pads up
//! to a multiple: a modulus equal to the target pads every candidate
//! committer's commit to the target itself).
//!
//! The proposals are counted as at least a change of the group's own state:
//! the state as every member holds it now, plus [`STATE_CHANGE_ROOM`]. So a
//! rotation, a renewal (one that grows the leaf aside, below) and a small
//! state change (the disappearing timer, Advanced Chat Privacy) are one
//! length; in a direct chat, whose name and
//! admins never change, a state commit the server could tell apart would say
//! that the timer had just been switched. The cost is the state's size on
//! every commit, about one block in a direct chat.
//!
//! So a commit's length depends on the tree's width, its member count, its
//! largest leaf and what the commit carries, never on which member made it or
//! where any member sits. Receivers need nothing: the padding is the zeros
//! every MLS receiver already checks and strips (see
//! [`crate::group::APPLICATION_PADDING_BLOCK`]), so a build without this
//! opens a padded commit unchanged.
//!
//! **The cost** is the founder's commit in a tree just founded, paid by every
//! member for as long as the group lasts: her path crosses every level and
//! seals to every other member, so its path is the target's, plus the
//! state-change room below. `mls/core/tests/commit_sizes.rs` prints a
//! rotation's size in a group-id envelope: 4,736 bytes in a 2-leaf group,
//! 7,296 in 3, 8,320 in 4, 10,880 in 5, 13,184 in 7 and 16,770 in 9.
//! Unpadded, a better-placed member would send less (leaf 2 of a 3-leaf
//! group 4,736, leaf 6 of a 7-leaf group 8,320), and less again once commits fill parents: a filled
//! parent takes one ciphertext (1,172 bytes) in place of one for each member
//! below it. Commits are rare next to messages: adds, removals, renames and
//! a leaf rotation every 250 frames or 7 days, or in a two-person group on
//! the round trip, at most every ten minutes per device.
//!
//! **The bound, not the exact figure.** The target sits above the
//! worst-placed member's real commit by whatever filled parents spare that
//! member; it is never below it, which is the only property the padding
//! needs. Each leaf is counted as a commit would re-sign it: its size in the
//! tree less its leaf-node source, plus a commit source's. The one input
//! that is not the tree's is a renewal that brings this device a larger
//! credential or capability list than its leaf now carries
//! ([`CommitPlan::own_leaf_growth`]). That growth is a fact about what the
//! commit carries, like a rename's new name, so it is added to the
//! target whoever renews: were it added only where the renewer's own leaf is
//! the largest, the length would say whose leaf that is. Counted for all, it
//! costs at most one extra block, on renewals only.

use openmls::messages::group_info::GroupInfo;
use openmls::prelude::{Extension, LeafNodeIndex, MlsGroup, RatchetTreeIn};
use tls_codec::{Serialize as _, Size as _};

use crate::error::{Error, Result};
use crate::group::APPLICATION_PADDING_BLOCK;

/// X-Wing's encapsulation (`kem_output`) for [`crate::group::PEACHY_CIPHERSUITE`]:
/// an ML-KEM-768 ciphertext (1088) and an X25519 share (32).
const KEM_OUTPUT_BYTES: usize = 1120;
/// The secret an UpdatePath node carries: `PathSecret` (`opaque<V>` of the
/// suite's hash length, 32), under the AEAD's 16-byte tag.
const SEALED_PATH_NODE_BYTES: usize = 1 + 32 + 16;
/// `FramedContentAuthData` for a commit: an Ed25519 signature (`<V>`, 64)
/// and the confirmation tag (`<V>`, the suite's 32-byte MAC).
const COMMIT_AUTH_BYTES: usize = (1 + 64) + (1 + 32);
/// The AEAD tag OpenMLS counts in before it pads (`mac_length`).
const AEAD_TAG_BYTES: usize = 16;
/// How much a change of the group's own state may grow it and still be the
/// length of a rotation: room for a disappearing timer (`,"dis":2419200`,
/// 14 bytes) or Advanced Chat Privacy (`,"acp":true`, 11), with margin. A
/// change that grows the state by more (a long new name, more admins) shows
/// its growth to the block. Growth is of the extensions' encodings, their
/// own length prefixes included; the vector's prefix is counted on top.
const STATE_CHANGE_ROOM: usize = 64;

/// What a commit about to be built changes, as far as its size goes.
#[derive(Debug, Default, Clone)]
pub(crate) struct CommitPlan {
    /// The leaves it removes.
    pub removes: Vec<u32>,
    /// How many it adds (each takes the leftmost blank leaf).
    pub adds: usize,
    /// The serialized length of its inline proposals, each counted as a
    /// `ProposalOrRef` (type byte, proposal type, body).
    pub proposals_len: usize,
    /// How much larger this device's own new leaf is than the one it holds:
    /// a renewal's credential and capabilities. Zero for every other commit.
    /// Added to the largest leaf's figure whoever renews, so the target does
    /// not depend on which leaf renews.
    pub own_leaf_growth: usize,
}

impl CommitPlan {
    /// One inline `ProposalOrRef` whose proposal body is `body_len` bytes.
    pub(crate) fn inline_proposal(body_len: usize) -> usize {
        1 + 2 + body_len
    }

    /// One `ProposalOrRef` naming a proposal by its reference: the type byte
    /// and the `ProposalRef` (`opaque<V>` of the suite's 32-byte hash).
    pub(crate) fn proposal_by_reference() -> usize {
        1 + 1 + 32
    }
}

/// The MLS variable-length integer's size for `n` (RFC 9420 §2.1.2).
fn varint_len(n: usize) -> usize {
    if n < 1 << 6 {
        1
    } else if n < 1 << 14 {
        2
    } else {
        4
    }
}

/// An `opaque<V>` / vector of `n` bytes, with its length prefix.
fn vl(n: usize) -> usize {
    varint_len(n) + n
}

#[derive(Debug, Clone)]
enum Shape {
    /// `len` is the `LeafNode`'s encoding; `source` the part of it that is
    /// its `leaf_node_source`, which a commit's path re-signs as `commit`.
    Leaf {
        len: usize,
        source: usize,
        joiner: bool,
    },
    /// `fixed` is the `ParentNode`'s encoding without its unmerged-leaf list
    /// (`encryption_key<V>`, `parent_hash<V>`).
    Parent { fixed: usize, unmerged: Vec<u32> },
}

impl Shape {
    /// The node's length in a `ratchet_tree`: `optional<Node>`'s presence
    /// byte, the node type, the node.
    fn encoded_len(&self) -> usize {
        match self {
            Self::Leaf { len, .. } => 2 + len,
            Self::Parent { fixed, unmerged } => 2 + fixed + vl(4 * unmerged.len()),
        }
    }
}

/// The public tree, by node index (RFC 9420 Appendix C's array layout), with
/// only what a path's size, and the tree's own size, depend on.
#[derive(Clone)]
struct Tree {
    nodes: Vec<Option<Shape>>,
    leaves: u32,
}

/// RFC 9420 Appendix C.
fn level(x: u32) -> u32 {
    x.trailing_ones()
}

fn root(leaves: u32) -> u32 {
    leaves - 1
}

fn parent(x: u32) -> u32 {
    let k = level(x);
    let b = (x >> (k + 1)) & 1;
    (x | (1 << k)) ^ (b << (k + 1))
}

#[cfg(test)]
fn left(x: u32) -> u32 {
    let k = level(x);
    x ^ (1 << (k - 1))
}

#[cfg(test)]
fn right(x: u32) -> u32 {
    let k = level(x);
    x ^ (3 << (k - 1))
}

#[cfg(test)]
fn sibling(x: u32) -> u32 {
    let p = parent(x);
    if x < p {
        right(p)
    } else {
        left(p)
    }
}

fn direct_path(mut x: u32, leaves: u32) -> Vec<u32> {
    let r = root(leaves);
    let mut out = Vec::new();
    while x != r {
        x = parent(x);
        out.push(x);
    }
    out
}

#[cfg(test)]
fn copath(x: u32, leaves: u32) -> Vec<u32> {
    let r = root(leaves);
    if x == r {
        return Vec::new();
    }
    let mut chain = vec![x];
    chain.extend(direct_path(x, leaves));
    chain.pop();
    chain.into_iter().map(sibling).collect()
}

struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .at
            .checked_add(n)
            .filter(|&end| end <= self.bytes.len())
            .ok_or_else(|| Error::Mls("the ratchet tree ended early".into()))?;
        let out = &self.bytes[self.at..end];
        self.at = end;
        Ok(out)
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn varint(&mut self) -> Result<usize> {
        let first = self.u8()?;
        let rest = match first >> 6 {
            0 => 0,
            1 => 1,
            2 => 3,
            _ => return Err(Error::Mls("a ratchet tree length is malformed".into())),
        };
        let mut n = usize::from(first & 0x3f);
        for byte in self.take(rest)? {
            n = (n << 8) | usize::from(*byte);
        }
        Ok(n)
    }

    fn opaque(&mut self) -> Result<&'a [u8]> {
        let n = self.varint()?;
        self.take(n)
    }
}

impl Tree {
    /// Read the group's current public tree. Leaves are measured through
    /// OpenMLS's own `LeafNode` encoding; a parent's unmerged leaves are read
    /// off its encoding (`encryption_key<V>`, `parent_hash<V>`,
    /// `uint32 unmerged_leaves<V>`).
    fn of(group: &MlsGroup) -> Result<Self> {
        let source_of = |node_index: usize| -> usize {
            u32::try_from(node_index / 2)
                .ok()
                .and_then(|leaf| group.public_group().leaf(LeafNodeIndex::new(leaf)))
                .map_or(0, |leaf| leaf.leaf_node_source().tls_serialized_len())
        };
        let exported = group.export_ratchet_tree();
        let bytes = exported
            .tls_serialize_detached()
            .map_err(|err| Error::Mls(format!("could not encode the ratchet tree: {err}")))?;
        let leaf_lens: Vec<usize> = RatchetTreeIn::from(exported)
            .leaves()
            .map(|leaf| leaf.tls_serialized_len())
            .collect();
        let mut leaf_lens = leaf_lens.into_iter();
        let mut reader = Reader {
            bytes: &bytes,
            at: 0,
        };
        let total = reader.varint()?;
        let end = reader.at + total;
        let mut nodes = Vec::new();
        while reader.at < end {
            match reader.u8()? {
                0 => nodes.push(None),
                1 => match reader.u8()? {
                    1 => {
                        let len = leaf_lens
                            .next()
                            .ok_or_else(|| Error::Mls("a leaf the tree did not list".into()))?;
                        reader.take(len)?;
                        let source = source_of(nodes.len());
                        nodes.push(Some(Shape::Leaf {
                            len,
                            source,
                            joiner: false,
                        }));
                    }
                    2 => {
                        let start = reader.at;
                        reader.opaque()?;
                        reader.opaque()?;
                        let fixed = reader.at - start;
                        let list = reader.opaque()?;
                        let unmerged = list
                            .as_chunks::<4>()
                            .0
                            .iter()
                            .map(|c| u32::from_be_bytes(*c))
                            .collect();
                        nodes.push(Some(Shape::Parent { fixed, unmerged }));
                    }
                    _ => return Err(Error::Mls("a ratchet tree node type is unknown".into())),
                },
                _ => return Err(Error::Mls("a ratchet tree option is malformed".into())),
            }
        }
        let mut leaves = 1u32;
        while ((2 * leaves - 1) as usize) < nodes.len() {
            leaves *= 2;
        }
        nodes.resize((2 * leaves - 1) as usize, None);
        Ok(Self { nodes, leaves })
    }

    fn leaf(&self, i: u32) -> Option<&Shape> {
        self.nodes.get((2 * i) as usize).and_then(Option::as_ref)
    }

    fn resize(&mut self, leaves: u32) {
        self.leaves = leaves;
        self.nodes.resize((2 * leaves - 1) as usize, None);
    }

    /// Apply a commit's removes and adds the way RFC 9420 §12.3 orders them
    /// (and OpenMLS's `apply_proposals` does): blank each removed leaf and its
    /// direct path; put each joiner in the leftmost blank leaf, growing the
    /// tree when there is none, and list it as unmerged on every non-blank
    /// parent above it; then truncate.
    fn apply(&mut self, plan: &CommitPlan) {
        for &removed in &plan.removes {
            if removed >= self.leaves {
                continue;
            }
            self.nodes[(2 * removed) as usize] = None;
            for p in direct_path(2 * removed, self.leaves) {
                self.nodes[p as usize] = None;
            }
        }
        for _ in 0..plan.adds {
            let free = (0..self.leaves)
                .find(|&i| self.leaf(i).is_none())
                .unwrap_or(self.leaves);
            while free >= self.leaves {
                self.resize(self.leaves * 2);
            }
            self.nodes[(2 * free) as usize] = Some(Shape::Leaf {
                // A joiner's leaf is the same whoever adds it: the Welcome
                // bound adds the joiners' leaves as they are.
                len: 0,
                source: 0,
                joiner: true,
            });
            for p in direct_path(2 * free, self.leaves) {
                if let Some(Shape::Parent { unmerged, .. }) = &mut self.nodes[p as usize] {
                    unmerged.push(free);
                }
            }
        }
        while self.leaves > 1 {
            let rightmost = (0..self.leaves).rev().find(|&i| self.leaf(i).is_some());
            match rightmost {
                Some(r) if r < self.leaves / 2 => self.resize(self.leaves / 2),
                _ => break,
            }
        }
    }

    /// The largest UpdatePath, as its new leaf plus its `nodes<V>`, that any
    /// member could send in this tree, from the tree's width and its members
    /// alone. `public_key` is one node's encoded HPKE public key (`<V>`,
    /// prefix included).
    ///
    /// A path has a node per non-blank copath child, at most one per level
    /// of the tree, and seals one ciphertext per member of each child's
    /// resolution that is not a joiner. Every other member sits under exactly
    /// one copath child, and a non-blank parent in a resolution stands for at
    /// least one member under it that is not unmerged, so a path seals at
    /// most one ciphertext per member less the committer and the joiners.
    /// The bound counts all of those levels and ciphertexts, whatever blanks
    /// and filled parents the tree holds, and the largest leaf as it would be
    /// re-signed as a commit's: so it tells nothing of where a member sits,
    /// nor of who committed before.
    fn largest_path(&self, public_key: usize) -> usize {
        let ciphertext = vl(KEM_OUTPUT_BYTES) + vl(SEALED_PATH_NODE_BYTES);
        let mut leaf = 0;
        let mut members = 0usize;
        for i in 0..self.leaves {
            if let Some(Shape::Leaf {
                len,
                source,
                joiner: false,
            }) = self.leaf(i)
            {
                members += 1;
                leaf = leaf.max(len.saturating_sub(*source) + COMMIT_LEAF_SOURCE_BYTES);
            }
        }
        let sealed_to = members.saturating_sub(1);
        let levels = self.leaves.trailing_zeros() as usize;
        let node = public_key + varint_len(sealed_to * ciphertext);
        leaf + vl(levels * node + sealed_to * ciphertext)
    }
}

/// The length the commit's encrypted content (`PrivateMessageContent` and
/// the AEAD tag) is padded to: the same for whichever member builds it.
pub(crate) fn commit_padding_target(group: &MlsGroup, plan: &CommitPlan) -> Result<usize> {
    let mut tree = Tree::of(group)?;
    let public_key = group
        .own_leaf_node()
        .map(|leaf| leaf.encryption_key().tls_serialized_len())
        .ok_or(Error::NotAMember)?;
    tree.apply(plan);
    // A renewal's growth is counted whoever renews: it is a fact about what
    // the commit carries, so the target must not depend on whose leaf in the
    // tree is the largest.
    let largest_path = tree.largest_path(public_key) + plan.own_leaf_growth;
    // Every commit is counted as if it carried a change of the group's own
    // state (the state as it is now, plus [`STATE_CHANGE_ROOM`]), so a small
    // change (the disappearing timer, Advanced Chat Privacy) is the length
    // of a rotation or a renewal. Every member holds the same group context,
    // so this stays one figure whoever builds the commit. The room grows the
    // extensions vector's contents, so its length prefix is counted at the
    // grown size: at the state's cap it is two bytes longer.
    let extensions: usize = group
        .extensions()
        .iter()
        .map(|extension| extension.tls_serialized_len())
        .sum();
    let state_change = CommitPlan::inline_proposal(vl(extensions + STATE_CHANGE_ROOM));
    // Commit { proposals<V>, optional<UpdatePath> }, its authentication, the
    // tag; then up to the message block, so what a commit carries beyond that
    // (a joiner's key package, a rename that grows the state by more than the
    // room) shows in whole blocks and no finer.
    let proposals = plan.proposals_len.max(state_change);
    let content = vl(proposals) + 1 + largest_path + COMMIT_AUTH_BYTES + AEAD_TAG_BYTES;
    Ok(content.div_ceil(APPLICATION_PADDING_BLOCK) * APPLICATION_PADDING_BLOCK)
}

/// How much larger a leaf carrying `credential_len` and `capabilities_len`
/// would be than this device's own leaf now.
pub(crate) fn own_leaf_growth(
    group: &MlsGroup,
    credential_len: usize,
    capabilities_len: usize,
) -> usize {
    let Some(leaf) = group.own_leaf_node() else {
        return 0;
    };
    credential_len.saturating_sub(leaf.credential().tls_serialized_len())
        + capabilities_len.saturating_sub(leaf.capabilities().tls_serialized_len())
}

/// A commit-sourced leaf's `leaf_node_source`: the `commit` tag and its
/// 32-byte parent hash `<V>`.
const COMMIT_LEAF_SOURCE_BYTES: usize = 1 + 1 + 32;
/// A parent hash `<V>` under the suite's 32-byte hash.
const PARENT_HASH_BYTES: usize = 1 + 32;

impl Tree {
    /// The `nodes<V>` content of a ratchet tree no member's Welcome for this
    /// commit exceeds, read from the tree's width, its members and their
    /// leaves alone (joiners' leaves left out, as [`Tree::apply`] counts
    /// them): every node of the width, each leaf as a commit would re-sign
    /// it, each blank leaf one byte, and each parent filled, with a parent
    /// hash and an unmerged list as long as the leaves it covers or the
    /// members, whichever is fewer. It reads nothing of which parents earlier
    /// commits filled or which leaves they re-signed.
    fn welcome_bound_nodes_len(&self, public_key: usize) -> usize {
        let members = (0..self.leaves).filter(|&i| self.leaf(i).is_some()).count();
        (0..2 * self.leaves - 1)
            .map(|x| match &self.nodes[x as usize] {
                _ if level(x) > 0 => {
                    let covered = (1usize << level(x)).min(members);
                    2 + public_key + PARENT_HASH_BYTES + vl(4 * covered)
                }
                Some(Shape::Leaf {
                    len,
                    source,
                    joiner: false,
                }) => 2 + (*len).max(len.saturating_sub(*source) + COMMIT_LEAF_SOURCE_BYTES),
                Some(shape) => shape.encoded_len(),
                None => 1,
            })
            .sum()
    }
}

/// The ratchet tree a Welcome for this commit is padded to: the length of
/// its `nodes<V>` content, which no member's add exceeds
/// ([`Tree::welcome_bound_nodes_len`] plus the joiners' leaves). Read off the
/// tree BEFORE the commit, which every member holds alike.
#[derive(Debug, Clone)]
pub(crate) struct WelcomeTrees {
    bound: usize,
}

/// [`WelcomeTrees`] for a commit `plan` about to be built in `group`, whose
/// joiners' leaf nodes are `joiner_leaves` bytes in all.
pub(crate) fn welcome_trees(
    group: &MlsGroup,
    plan: &CommitPlan,
    joiner_leaves: usize,
) -> Result<WelcomeTrees> {
    let mut tree = Tree::of(group)?;
    let public_key = group
        .own_leaf_node()
        .map(|leaf| leaf.encryption_key().tls_serialized_len())
        .ok_or(Error::NotAMember)?;
    tree.apply(plan);
    Ok(WelcomeTrees {
        bound: tree.welcome_bound_nodes_len(public_key) + joiner_leaves,
    })
}

/// The raw Welcome length this commit's is padded to: the one this device
/// built, with its ratchet tree counted at [`WelcomeTrees`]' bound.
///
/// The Welcome this device built (`welcome`, raw) is the one exact
/// measurement; the bound differs from it only in the ratchet tree inside its
/// encrypted GroupInfo. That difference is carried up through every length
/// prefix it sits under (the tree's `nodes<V>`, the extension's data `<V>`,
/// the GroupInfo's `extensions<V>`, and the Welcome's
/// `encrypted_group_info<V>`), so a prefix that grows by two bytes past 16 KiB
/// grows in the bound too. Everything else the GroupInfo carries, the group
/// state (`peachy_group_meta`) included, is counted at its true length
/// (docs/delivery.md §The padded Welcome frame).
/// `group_info` is the GroupInfo the commit exported:
/// the Welcome's, with the external public key added.
pub(crate) fn welcome_bound_len(
    trees: &WelcomeTrees,
    group_info: &GroupInfo,
    welcome: &[u8],
) -> Result<usize> {
    let short = || Error::Mls("a Welcome is shorter than its own parts".into());
    let tree_bytes = group_info
        .extensions()
        .ratchet_tree()
        .ok_or_else(|| Error::Mls("the commit's GroupInfo carries no ratchet tree".into()))?
        .ratchet_tree()
        .tls_serialize_detached()
        .map_err(|err| Error::Mls(format!("could not encode the ratchet tree: {err}")))?;
    let own_tree = Reader {
        bytes: &tree_bytes,
        at: 0,
    }
    .varint()?;
    // The Welcome's GroupInfo extensions: the exported ones but the external
    // public key, which OpenMLS adds after it sealed the Welcome.
    let own_extensions: usize = group_info
        .extensions()
        .iter()
        .filter(|ext| !matches!(ext, Extension::ExternalPub(_)))
        .map(|ext| ext.tls_serialized_len())
        .sum();
    // MLSMessage { version, wire_format, Welcome { cipher_suite,
    // secrets<V>, encrypted_group_info<V> } }.
    let mut reader = Reader {
        bytes: welcome,
        at: 0,
    };
    reader.take(2 + 2 + 2)?;
    reader.opaque()?;
    let own_info = reader
        .opaque()?
        .len()
        .checked_sub(AEAD_TAG_BYTES)
        .ok_or_else(short)?;

    // Each total less the tree, once; then the tree at the bound. A tree past
    // it would mean the bound is wrong.
    debug_assert!(
        own_tree <= trees.bound,
        "a Welcome's tree ({own_tree}) is past its bound ({})",
        trees.bound
    );
    let tree = trees.bound.max(own_tree);
    let extensions_rest = own_extensions
        .checked_sub(vl(vl(own_tree)))
        .ok_or_else(short)?;
    let info_rest = own_info.checked_sub(vl(own_extensions)).ok_or_else(short)?;
    let welcome_rest = welcome
        .len()
        .checked_sub(vl(own_info + AEAD_TAG_BYTES))
        .ok_or_else(short)?;
    let extensions = extensions_rest + vl(vl(tree));
    let info = info_rest + vl(extensions);
    Ok(welcome_rest + vl(info + AEAD_TAG_BYTES))
}

/// The length a framed Welcome is padded to: the raw Welcome at the tree's
/// bound ([`welcome_bound_len`]), plus the frame's header, rounded up to the
/// frame's block ([`crate::welcome_frame`]). `with_gap`: a version 2 frame,
/// whose gap block (the same length in every one) is counted too.
pub(crate) fn welcome_padding_target(bound: usize, welcome: &[u8], with_gap: bool) -> usize {
    debug_assert!(welcome.len() <= bound, "a Welcome is past its bound");
    let largest = bound.max(welcome.len());
    if with_gap {
        crate::welcome_frame::framed_len_with_gap(largest)
    } else {
        crate::welcome_frame::framed_len(largest)
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn tree_math_matches_rfc_9420_appendix_c() {
        // 4 leaves: nodes 0..7, root 3.
        assert_eq!(root(4), 3);
        assert_eq!(direct_path(0, 4), vec![1, 3]);
        assert_eq!(copath(0, 4), vec![2, 5]);
        assert_eq!(direct_path(4, 4), vec![5, 3]);
        assert_eq!(copath(6, 4), vec![4, 1]);
        // 8 leaves: root 7.
        assert_eq!(direct_path(8, 8), vec![9, 11, 7]);
        assert_eq!(copath(8, 8), vec![10, 13, 3]);
        assert_eq!(copath(0, 1), Vec::<u32>::new());
    }

    /// The largest group there can be (1,024 member leaves), every leaf at
    /// the cap and the group's state at its own: the padded commit stays
    /// well under the 4 MiB the delivery service takes.
    #[test]
    fn the_largest_commit_fits_the_delivery_cap() {
        let leaves = crate::policy::MAX_GROUP_LEAVES as u32;
        let mut tree = Tree {
            nodes: vec![None; (2 * leaves - 1) as usize],
            leaves,
        };
        for i in 0..leaves {
            tree.nodes[(2 * i) as usize] = Some(Shape::Leaf {
                len: crate::policy::MAX_LEAF_NODE_BYTES,
                source: 0,
                joiner: false,
            });
        }
        // An X-Wing public key (1,216 bytes) as `<V>`.
        let path = tree.largest_path(vl(1216));
        let state = CommitPlan::inline_proposal(vl(
            crate::group_meta::MAX_GROUP_META_BYTES + STATE_CHANGE_ROOM
        ));
        let content = vl(state) + 1 + path + COMMIT_AUTH_BYTES + AEAD_TAG_BYTES;
        assert!(content < 1_300_000, "{content}");
        assert!(content < 4 * 1024 * 1024);
    }

    #[test]
    fn varints() {
        assert_eq!(vl(0), 1);
        assert_eq!(vl(63), 64);
        assert_eq!(vl(64), 66);
        assert_eq!(vl(16_383), 16_385);
        assert_eq!(vl(16_384), 16_388);
    }
}
