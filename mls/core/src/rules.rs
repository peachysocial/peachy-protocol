// SPDX-License-Identifier: MIT
//! Group policy: which proposals Peachy accepts, from whom.
//!
//! MLS says what is *cryptographically* valid. It says almost nothing about
//! what a product should accept. OpenMLS, unlike mls-rs, has no pluggable
//! `MlsRules` trait, so this is ours: a small, total function from a
//! [`ProposalContext`] to a [`PolicyDecision`], consulted by
//! [`crate::group::Client`] before a commit is merged and before a proposal is
//! queued.
//!
//! ## Why it is an enum and not a `bool`
//!
//! One golden fixture for these rules is replayed by every binding before
//! any client ships (docs/mls-core.md §Golden rules fixture). A
//! fixture needs a stable vocabulary. Every
//! variant of [`DenyReason`] has a fixed `#[repr(u32)]` discriminant and a
//! spelled-out [`DenyReason::name`], so the fixture can be a table of
//! (situation, expected decision) that Swift, Kotlin, TypeScript and Rust all
//! read the same way. Adding a variant is additive; renumbering one is a
//! breaking change to that fixture and should read like one.
//!
//! ## The policy this build ships
//!
//! | Situation | Decision | Why |
//! |---|---|---|
//! | Add, from a member | Allow | The ordinary case. The added key package is still identity-checked. |
//! | Remove, from any member | Allow | At this layer. Who may remove whom is the group's own policy ([`crate::policy`]), which every member judges after these rules on the same commit: removing somebody else needs an admin unless the group says otherwise. This layer refuses only removes from outside the group. |
//! | Update, from its own leaf | Allow | Self-rotation, the point of MLS. |
//! | Update, targeting another leaf | Deny | An Update proposal only ever refers to the sender's own leaf; anything else is malformed intent. |
//! | Any proposal from a non-member | Deny | See below. |
//! | External join (ExternalInit, or a `NewMember*` sender) | Deny | See below. |
//! | PreSharedKey | Deny | Nothing in Peachy mints PSKs yet. Accepting one would mean accepting key material from a source with no story for where it came from. |
//! | ReInit | Deny | A group reinitialisation changes the ciphersuite or version under the members' feet; none is accepted without a migration design. |
//! | GroupContextExtensions changing `peachy_group_meta`, and nothing else | Allow | At this layer (docs/sealed-messages.md §The name is in the group). The group's own policy then decides which member may change which key. The one group-context edit this build understands. |
//! | GroupContextExtensions changing anything else | Deny | The group context is what everyone's state agrees on. Nothing ELSE sets extensions yet, so a proposal to change them is unexplained. |
//! | SelfRemove | Deny | Not because leaving is wrong — because Peachy's leave is a Remove proposal for the leaver's own leaves (below), and two ways to leave is two code paths to keep honest. SelfRemove would also need every leaf to advertise it first. |
//! | Anything unrecognised | Deny | The default is no. A proposal type this build has never heard of cannot have been reasoned about. |
//! | A Remove BY REFERENCE of a leaf of its sender's own person | Allow | A LEAVE. A member cannot commit its own removal (RFC 9420 §12.2), so it proposes the removal of its own person's leaves and another member commits them. The group's policy lets anybody remove their own leaves. |
//! | Any other proposal BY REFERENCE (a standalone proposal, or a commit naming one) | Deny | See below. |
//!
//! Deny codes 10 to 15 belonged to a retired feature and are not reused.

//! ### Why external joins are refused
//!
//! An external commit lets a stranger holding a `GroupInfo` add themselves,
//! with no member's consent. Peachy's whole roster model is that membership is
//! something an existing member did, with the client rendering the roster from
//! the tree. If a party can arrive without an Add, that stops being true and the roster stops being a
//! record of decisions anybody made. The server-side `ExternalGroup` of
//! condition 2 watches commits; it is not a door.
//!
//! The refusal is at the *policy* layer and not merely "we never publish
//! GroupInfo", because a `GroupInfo` leaks the moment one member's storage
//! does, and a rule you enforce by not handing out the key is a rule you are
//! not enforcing.
//!
//! ### Why proposals by reference are refused
//!
//! Every change a Peachy client makes is a commit carrying its own proposals
//! inline, so every proposal in it is the committer's and is judged as theirs.
//! A standalone proposal is a member's change that somebody ELSE commits: the
//! group's policy would have to judge it as its proposer's, and every honest
//! committer would have to know which queued proposals it may carry. So none
//! is taken but one: a standalone proposal is refused when it arrives, before
//! it reaches the proposal store, and a commit that names a proposal by
//! reference is refused whole. Nothing a member queues can ride into a commit
//! somebody else builds.
//!
//! The one exception is a LEAVE: a Remove whose removed leaf belongs to the
//! proposer's own person (`removes_own_leaf`). Leaving is the one change a
//! member cannot commit itself, it is allowed to everybody, and an honest
//! committer carries nothing else with it
//! ([`crate::group::Client::commit_proposed_leaves`]).

/// The proposal types this policy can see. Mirrors RFC 9420 §12.1 plus the
/// SelfRemove extension OpenMLS models, with one catch-all.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum ProposalKind {
    Add = 1,
    Update = 2,
    Remove = 3,
    PreSharedKey = 4,
    ReInit = 5,
    ExternalInit = 6,
    GroupContextExtensions = 7,
    SelfRemove = 8,
    /// A proposal type this build does not model. Carries no payload on
    /// purpose: there is nothing we could do with it.
    Unrecognised = 9,
}

impl ProposalKind {
    /// Every variant, in discriminant order.
    ///
    /// Exhaustive by construction — the array length is written down, so
    /// adding a variant without adding it here does not compile. That is what
    /// lets `mls/core/tests/rules_fixture.rs` assert that
    /// `mls/fixtures/rules.json` has a case for every (sender, kind) cell:
    /// a new proposal type fails the fixture until somebody decides what the
    /// policy says about it (docs/mls-core.md §Golden rules fixture).
    pub const ALL: [ProposalKind; 9] = [
        Self::Add,
        Self::Update,
        Self::Remove,
        Self::PreSharedKey,
        Self::ReInit,
        Self::ExternalInit,
        Self::GroupContextExtensions,
        Self::SelfRemove,
        Self::Unrecognised,
    ];

    pub fn code(self) -> u32 {
        self as u32
    }

    /// The inverse of [`ProposalKind::name`], for reading a fixture case.
    ///
    /// Written as a search over [`ProposalKind::ALL`] rather than as a second
    /// `match`: a second match is a second place to forget a variant, and the
    /// whole point of the names is that one string means one thing in four
    /// languages.
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|kind| kind.name() == name)
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Add => "add",
            Self::Update => "update",
            Self::Remove => "remove",
            Self::PreSharedKey => "psk",
            Self::ReInit => "reinit",
            Self::ExternalInit => "external_init",
            Self::GroupContextExtensions => "group_context_extensions",
            Self::SelfRemove => "self_remove",
            Self::Unrecognised => "unrecognised",
        }
    }
}

/// Who sent it, in the terms RFC 9420 §6 uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum SenderKind {
    /// A leaf in the tree.
    Member = 1,
    /// A party named in the group's `external_senders` extension. Peachy sets
    /// no such extension, so in practice this is "somebody the group never
    /// authorised".
    External = 2,
    /// A stranger proposing to add themselves (RFC 9420 §12.1.8.1).
    NewMemberProposal = 3,
    /// A stranger committing themselves in (§12.1.8.2).
    NewMemberCommit = 4,
}

impl SenderKind {
    /// Every variant, in discriminant order. See [`ProposalKind::ALL`].
    pub const ALL: [SenderKind; 4] = [
        Self::Member,
        Self::External,
        Self::NewMemberProposal,
        Self::NewMemberCommit,
    ];

    pub fn code(self) -> u32 {
        self as u32
    }

    /// The inverse of [`SenderKind::name`]. See [`ProposalKind::from_name`].
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|sender| sender.name() == name)
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Member => "member",
            Self::External => "external",
            Self::NewMemberProposal => "new_member_proposal",
            Self::NewMemberCommit => "new_member_commit",
        }
    }

    /// Whether this sender is in the tree.
    pub fn is_member(self) -> bool {
        matches!(self, Self::Member)
    }
}

/// Everything the policy is allowed to look at. Nothing else: a rule that
/// reaches into the group state is a rule no fixture can reproduce.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProposalContext {
    pub kind: ProposalKind,
    pub sender: SenderKind,
    /// For an Update: whether the leaf it changes is the sender's own. For
    /// anything else, `true` is not consulted.
    pub targets_sender_leaf: bool,
    /// **GroupContextExtensions only.** Whether this proposal changes the
    /// group's `peachy_group_meta` (its own state) and nothing else
    /// (`crate::group_meta::group_meta_change`). Defaults to false, which is
    /// every case written before the extension existed.
    pub sets_group_meta: bool,
    /// Whether the proposal arrived BY REFERENCE: sent on its own, or named
    /// by a commit through its reference rather than carried in it. Refused
    /// unless it is a leave (see the module header). Defaults to false, which
    /// is every proposal a commit carries inline.
    pub by_reference: bool,
    /// **Remove only.** Whether the leaf it removes belongs to its sender's
    /// own person: by reference, a leave. Defaults to false.
    pub removes_own_leaf: bool,
}

impl ProposalContext {
    /// The common case: a proposal from a member, not an update to somebody
    /// else's leaf.
    pub fn from_member(kind: ProposalKind) -> Self {
        Self {
            kind,
            sender: SenderKind::Member,
            targets_sender_leaf: true,
            sets_group_meta: false,
            by_reference: false,
            removes_own_leaf: false,
        }
    }

    /// The same, from an arbitrary sender.
    pub fn from_sender(kind: ProposalKind, sender: SenderKind) -> Self {
        Self {
            sender,
            ..Self::from_member(kind)
        }
    }
}

/// Why a proposal was refused.
///
/// Stable discriminants. See the module header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum DenyReason {
    /// An `ExternalInit` proposal, or any proposal whose sender is joining
    /// themselves.
    ExternalJoin = 1,
    /// A sender named by the `external_senders` extension. Peachy sets none.
    ExternalSender = 2,
    /// A proposal from someone who is not in the tree, and is not trying to
    /// join either.
    NonMemberProposal = 3,
    /// PreSharedKey: nothing mints them yet.
    PreSharedKeyUnsupported = 4,
    /// ReInit: a ciphersuite migration needs a migration design.
    ReInitUnsupported = 5,
    /// GroupContextExtensions changing anything but `peachy_group_meta`.
    GroupContextExtensionsUnsupported = 6,
    /// SelfRemove: Peachy leaves by proposing a Remove of its own leaves.
    SelfRemoveUnsupported = 7,
    /// An Update naming a leaf that is not the sender's.
    UpdateOfAnotherLeaf = 8,
    /// A proposal type this build has never heard of.
    UnrecognisedProposal = 9,
    // 10 to 15 are retired (see the module header). Not reused.
    /// A member-rostered group's policy (`crate::policy`) lets only admins
    /// add, and the committer is not one.
    AddNeedsAdmin = 16,
    /// Removing another member's leaves takes an admin.
    RemoveNeedsAdmin = 17,
    /// The group's policy lets only admins change its name, topic or photo.
    MetaNeedsAdmin = 18,
    /// The group's policy lets only admins change its `acp` flag.
    AcpNeedsAdmin = 19,
    /// Changing the admins, the policy or the DM mark takes an admin.
    PolicyNeedsAdmin = 20,
    /// A commit sets group state a policy group cannot read, or that names
    /// no admin.
    MetaUnreadable = 21,
    /// A commit adds somebody the group has banned (docs/sealed-messages.md
    /// §Bans). Lifting the ban is a commit of its own, by an admin.
    AddBanned = 22,
    /// A proposal by reference: a standalone proposal, or a commit naming one.
    /// Every Peachy change is a commit carrying its own proposals.
    ProposalByReference = 23,
    /// A commit would seat a leaf whose account identity key is not the one
    /// the other leaves of its actor carry, or, for the reader's own actor,
    /// not the reader's own. One person's devices carry one account key.
    AccountKeyConflict = 24,
}

impl DenyReason {
    /// Every variant, in discriminant order. See [`ProposalKind::ALL`].
    pub const ALL: [DenyReason; 18] = [
        Self::ExternalJoin,
        Self::ExternalSender,
        Self::NonMemberProposal,
        Self::PreSharedKeyUnsupported,
        Self::ReInitUnsupported,
        Self::GroupContextExtensionsUnsupported,
        Self::SelfRemoveUnsupported,
        Self::UpdateOfAnotherLeaf,
        Self::UnrecognisedProposal,
        Self::AddNeedsAdmin,
        Self::RemoveNeedsAdmin,
        Self::MetaNeedsAdmin,
        Self::AcpNeedsAdmin,
        Self::PolicyNeedsAdmin,
        Self::MetaUnreadable,
        Self::AddBanned,
        Self::ProposalByReference,
        Self::AccountKeyConflict,
    ];

    pub fn code(self) -> u32 {
        self as u32
    }

    /// The inverse of [`DenyReason::name`]. See [`ProposalKind::from_name`].
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|reason| reason.name() == name)
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::ExternalJoin => "external_join",
            Self::ExternalSender => "external_sender",
            Self::NonMemberProposal => "non_member_proposal",
            Self::PreSharedKeyUnsupported => "psk_unsupported",
            Self::ReInitUnsupported => "reinit_unsupported",
            Self::GroupContextExtensionsUnsupported => "group_context_extensions_unsupported",
            Self::SelfRemoveUnsupported => "self_remove_unsupported",
            Self::UpdateOfAnotherLeaf => "update_of_another_leaf",
            Self::UnrecognisedProposal => "unrecognised_proposal",
            Self::AddNeedsAdmin => "add_needs_admin",
            Self::RemoveNeedsAdmin => "remove_needs_admin",
            Self::MetaNeedsAdmin => "meta_needs_admin",
            Self::AcpNeedsAdmin => "acp_needs_admin",
            Self::PolicyNeedsAdmin => "policy_needs_admin",
            Self::MetaUnreadable => "meta_unreadable",
            Self::AddBanned => "add_banned",
            Self::ProposalByReference => "proposal_by_reference",
            Self::AccountKeyConflict => "account_key_conflict",
        }
    }
}

impl std::fmt::Display for DenyReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// The verdict. Two states, and the refusal always says why.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyDecision {
    Allow,
    Deny(DenyReason),
}

impl PolicyDecision {
    pub fn is_allowed(self) -> bool {
        matches!(self, Self::Allow)
    }

    /// `Ok(())` or the reason, for call sites that just want `?`.
    pub fn into_result(self) -> crate::error::Result<()> {
        match self {
            Self::Allow => Ok(()),
            Self::Deny(reason) => Err(crate::error::Error::PolicyRefused(reason)),
        }
    }
}

/// Peachy's group policy.
///
/// The proposal-kind layer only. Admin authority is not here: it is the
/// group's own policy ([`crate::policy`]), judged after these rules on every
/// commit. `allow_remove_by_any_member` closes member Removes at THIS layer
/// when false; no shipped build sets it false, and the fixture pins both
/// settings so a binding cannot drop the block. Everything else here is a
/// denial that a flag would only make easier to turn off by accident.
#[derive(Debug, Clone, Copy)]
pub struct PeachyMlsRules {
    /// Whether this layer lets a member's Remove through to the group's
    /// policy. True in every shipped build; the policy still decides.
    pub allow_remove_by_any_member: bool,
}

impl Default for PeachyMlsRules {
    fn default() -> Self {
        Self {
            allow_remove_by_any_member: true,
        }
    }
}

impl PeachyMlsRules {
    pub fn new() -> Self {
        Self::default()
    }

    /// The whole policy, as one total function.
    pub fn evaluate(&self, ctx: &ProposalContext) -> PolicyDecision {
        use DenyReason as D;
        use PolicyDecision::{Allow, Deny};

        // Sender first. An external join is refused whatever it proposes, and
        // saying so here rather than per-kind is what makes it impossible to
        // add a proposal type that quietly lets one through.
        match ctx.sender {
            SenderKind::NewMemberCommit | SenderKind::NewMemberProposal => {
                return Deny(D::ExternalJoin)
            }
            SenderKind::External => return Deny(D::ExternalSender),
            SenderKind::Member => {}
        }
        // Then how it arrived. A proposal by reference is somebody's change
        // that a different member commits; Peachy takes none but a leave (a
        // Remove of the proposer's own leaf), so no other queued proposal can
        // ride into another member's commit.
        if ctx.by_reference && !(ctx.kind == ProposalKind::Remove && ctx.removes_own_leaf) {
            return Deny(D::ProposalByReference);
        }
        match ctx.kind {
            // The ordinary case. The added key package is still
            // identity-checked, by the caller, before it gets here.
            ProposalKind::Add => Allow,
            ProposalKind::Remove => {
                if self.allow_remove_by_any_member {
                    Allow
                } else {
                    // This layer has no roles to consult, so with removes
                    // closed here the only answer is no.
                    Deny(D::NonMemberProposal)
                }
            }
            ProposalKind::Update => {
                if ctx.targets_sender_leaf {
                    Allow
                } else {
                    Deny(D::UpdateOfAnotherLeaf)
                }
            }
            // Reachable only from a member, since the sender match above
            // already refused everyone who could plausibly send it — but an
            // ExternalInit inside a member's commit is still an external join
            // being smuggled, so it is named as one.
            ProposalKind::ExternalInit => Deny(D::ExternalJoin),
            ProposalKind::PreSharedKey => Deny(D::PreSharedKeyUnsupported),
            ProposalKind::ReInit => Deny(D::ReInitUnsupported),
            // The group's own name and photo: any member, our default for
            // a new group's attributes. Reached only when the
            // proposal changes the meta and NOTHING else, which is what
            // `group_meta_change` checks. Anything else carried by this
            // proposal type is an unexplained edit to the state every member
            // agrees on.
            ProposalKind::GroupContextExtensions => {
                if ctx.sets_group_meta {
                    Allow
                } else {
                    Deny(D::GroupContextExtensionsUnsupported)
                }
            }
            ProposalKind::SelfRemove => Deny(D::SelfRemoveUnsupported),
            ProposalKind::Unrecognised => Deny(D::UnrecognisedProposal),
        }
    }

    /// Evaluate a whole commit's worth of proposals. The FIRST denial wins, in
    /// the order given, so that a fixture's expected reason does not depend on
    /// iteration order inside this function.
    pub fn evaluate_all<'a>(
        &self,
        proposals: impl IntoIterator<Item = &'a ProposalContext>,
    ) -> PolicyDecision {
        for ctx in proposals {
            let decision = self.evaluate(ctx);
            if let PolicyDecision::Deny(reason) = decision {
                return PolicyDecision::Deny(reason);
            }
        }
        PolicyDecision::Allow
    }

    /// Whether a sender may commit at all. Separate from proposal evaluation
    /// because an external commit can carry no proposal this policy would
    /// object to and still be an external commit.
    pub fn evaluate_commit_sender(&self, sender: SenderKind) -> PolicyDecision {
        match sender {
            SenderKind::Member => PolicyDecision::Allow,
            SenderKind::NewMemberCommit | SenderKind::NewMemberProposal => {
                PolicyDecision::Deny(DenyReason::ExternalJoin)
            }
            SenderKind::External => PolicyDecision::Deny(DenyReason::ExternalSender),
        }
    }
}

// The OpenMLS types this policy is fed from. Kept in this module, next to the
// enums, so the mapping is one screen: a new OpenMLS proposal variant shows up
// here as a non-exhaustive match error rather than silently as `Unrecognised`.
mod from_openmls {
    use super::{ProposalKind, SenderKind};
    use openmls::prelude::{Proposal, Sender};

    impl From<&Proposal> for ProposalKind {
        fn from(proposal: &Proposal) -> Self {
            match proposal {
                Proposal::Add(_) => Self::Add,
                Proposal::Update(_) => Self::Update,
                Proposal::Remove(_) => Self::Remove,
                Proposal::PreSharedKey(_) => Self::PreSharedKey,
                Proposal::ReInit(_) => Self::ReInit,
                Proposal::ExternalInit(_) => Self::ExternalInit,
                Proposal::GroupContextExtensions(_) => Self::GroupContextExtensions,
                Proposal::SelfRemove => Self::SelfRemove,
                Proposal::Custom(_) => Self::Unrecognised,
            }
        }
    }

    impl From<&Sender> for SenderKind {
        fn from(sender: &Sender) -> Self {
            match sender {
                Sender::Member(_) => Self::Member,
                Sender::External(_) => Self::External,
                Sender::NewMemberProposal => Self::NewMemberProposal,
                Sender::NewMemberCommit => Self::NewMemberCommit,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_member_may_add_remove_and_update_itself() {
        let rules = PeachyMlsRules::new();
        for kind in [
            ProposalKind::Add,
            ProposalKind::Remove,
            ProposalKind::Update,
        ] {
            assert_eq!(
                rules.evaluate(&ProposalContext::from_member(kind)),
                PolicyDecision::Allow,
                "{} should be allowed from a member",
                kind.name()
            );
        }
    }

    #[test]
    fn every_denial_names_itself() {
        let rules = PeachyMlsRules::new();
        let cases: &[(ProposalContext, DenyReason)] = &[
            (
                ProposalContext::from_sender(ProposalKind::Add, SenderKind::NewMemberCommit),
                DenyReason::ExternalJoin,
            ),
            (
                ProposalContext::from_sender(ProposalKind::Add, SenderKind::NewMemberProposal),
                DenyReason::ExternalJoin,
            ),
            (
                ProposalContext::from_sender(ProposalKind::Add, SenderKind::External),
                DenyReason::ExternalSender,
            ),
            (
                ProposalContext::from_member(ProposalKind::ExternalInit),
                DenyReason::ExternalJoin,
            ),
            (
                ProposalContext::from_member(ProposalKind::PreSharedKey),
                DenyReason::PreSharedKeyUnsupported,
            ),
            (
                ProposalContext::from_member(ProposalKind::ReInit),
                DenyReason::ReInitUnsupported,
            ),
            (
                ProposalContext::from_member(ProposalKind::GroupContextExtensions),
                DenyReason::GroupContextExtensionsUnsupported,
            ),
            (
                ProposalContext::from_member(ProposalKind::SelfRemove),
                DenyReason::SelfRemoveUnsupported,
            ),
            (
                ProposalContext::from_member(ProposalKind::Unrecognised),
                DenyReason::UnrecognisedProposal,
            ),
            (
                ProposalContext {
                    targets_sender_leaf: false,
                    ..ProposalContext::from_member(ProposalKind::Update)
                },
                DenyReason::UpdateOfAnotherLeaf,
            ),
            (
                ProposalContext {
                    sets_group_meta: false,
                    ..ProposalContext::from_member(ProposalKind::GroupContextExtensions)
                },
                DenyReason::GroupContextExtensionsUnsupported,
            ),
            (
                ProposalContext {
                    by_reference: true,
                    ..ProposalContext::from_member(ProposalKind::Add)
                },
                DenyReason::ProposalByReference,
            ),
            (
                ProposalContext {
                    by_reference: true,
                    sets_group_meta: true,
                    ..ProposalContext::from_member(ProposalKind::GroupContextExtensions)
                },
                DenyReason::ProposalByReference,
            ),
            (
                ProposalContext {
                    by_reference: true,
                    ..ProposalContext::from_sender(ProposalKind::Add, SenderKind::External)
                },
                DenyReason::ExternalSender,
            ),
            (
                ProposalContext {
                    by_reference: true,
                    ..ProposalContext::from_member(ProposalKind::Remove)
                },
                DenyReason::ProposalByReference,
            ),
            (
                ProposalContext {
                    by_reference: true,
                    removes_own_leaf: true,
                    ..ProposalContext::from_member(ProposalKind::Update)
                },
                DenyReason::ProposalByReference,
            ),
        ];
        for (ctx, expected) in cases {
            assert_eq!(
                rules.evaluate(ctx),
                PolicyDecision::Deny(*expected),
                "{:?} should be denied as {}",
                ctx,
                expected.name()
            );
        }
    }

    #[test]
    fn the_first_denial_in_order_wins() {
        let rules = PeachyMlsRules::new();
        let proposals = [
            ProposalContext::from_member(ProposalKind::Add),
            ProposalContext::from_member(ProposalKind::ReInit),
            ProposalContext::from_member(ProposalKind::PreSharedKey),
        ];
        assert_eq!(
            rules.evaluate_all(proposals.iter()),
            PolicyDecision::Deny(DenyReason::ReInitUnsupported)
        );
    }

    /// The other half of the fixture contract. `mls/fixtures/rules.json` is
    /// written in NAMES, not numbers — a fixture full of `4`s would be
    /// unreadable and unreviewable — so `name` and `from_name` have to be
    /// exact inverses over every variant, or a case silently addresses
    /// something other than what it reads as. The `ALL` arrays are what make
    /// "every variant" checkable: their lengths are written down, so a new
    /// variant fails to compile until it is listed.
    #[test]
    fn names_round_trip_for_every_variant() {
        for kind in ProposalKind::ALL {
            assert_eq!(ProposalKind::from_name(kind.name()), Some(kind));
        }
        for sender in SenderKind::ALL {
            assert_eq!(SenderKind::from_name(sender.name()), Some(sender));
        }
        for reason in DenyReason::ALL {
            assert_eq!(DenyReason::from_name(reason.name()), Some(reason));
        }
        assert_eq!(ProposalKind::from_name("add "), None);
        assert_eq!(SenderKind::from_name("Member"), None);
        assert_eq!(DenyReason::from_name("nope"), None);

        // No two variants share a name, in any of the three vocabularies. A
        // duplicate would make `from_name` return the first one and a fixture
        // case quietly test the wrong cell.
        for (index, kind) in ProposalKind::ALL.iter().enumerate() {
            assert_eq!(
                ProposalKind::ALL
                    .iter()
                    .position(|k| k.name() == kind.name()),
                Some(index),
                "{} is not a unique proposal-kind name",
                kind.name()
            );
        }
        for (index, reason) in DenyReason::ALL.iter().enumerate() {
            assert_eq!(
                DenyReason::ALL
                    .iter()
                    .position(|r| r.name() == reason.name()),
                Some(index),
                "{} is not a unique deny-reason name",
                reason.name()
            );
        }
    }

    /// The fixture contract: these numbers are what every binding compares
    /// against, so a renumbering has to break a test rather than a release.
    #[test]
    fn discriminants_are_pinned() {
        assert_eq!(
            [
                ProposalKind::Add.code(),
                ProposalKind::Update.code(),
                ProposalKind::Remove.code(),
                ProposalKind::PreSharedKey.code(),
                ProposalKind::ReInit.code(),
                ProposalKind::ExternalInit.code(),
                ProposalKind::GroupContextExtensions.code(),
                ProposalKind::SelfRemove.code(),
                ProposalKind::Unrecognised.code(),
            ],
            [1, 2, 3, 4, 5, 6, 7, 8, 9]
        );
        assert_eq!(
            [
                SenderKind::Member.code(),
                SenderKind::External.code(),
                SenderKind::NewMemberProposal.code(),
                SenderKind::NewMemberCommit.code(),
            ],
            [1, 2, 3, 4]
        );
        assert_eq!(
            [
                DenyReason::ExternalJoin.code(),
                DenyReason::ExternalSender.code(),
                DenyReason::NonMemberProposal.code(),
                DenyReason::PreSharedKeyUnsupported.code(),
                DenyReason::ReInitUnsupported.code(),
                DenyReason::GroupContextExtensionsUnsupported.code(),
                DenyReason::SelfRemoveUnsupported.code(),
                DenyReason::UpdateOfAnotherLeaf.code(),
                DenyReason::UnrecognisedProposal.code(),
            ],
            [1, 2, 3, 4, 5, 6, 7, 8, 9]
        );
        assert_eq!(DenyReason::ProposalByReference.code(), 23);
        assert_eq!(DenyReason::AccountKeyConflict.code(), 24);
    }

    /// A leave is the one proposal taken by reference: a Remove of a leaf of
    /// the proposer's own person.
    #[test]
    fn a_leave_is_the_one_proposal_by_reference() {
        let rules = PeachyMlsRules::new();
        let leave = ProposalContext {
            by_reference: true,
            removes_own_leaf: true,
            ..ProposalContext::from_member(ProposalKind::Remove)
        };
        assert_eq!(rules.evaluate(&leave), PolicyDecision::Allow);
        assert_eq!(
            rules.evaluate(&ProposalContext {
                sender: SenderKind::External,
                ..leave
            }),
            PolicyDecision::Deny(DenyReason::ExternalSender)
        );
    }

    /// A rename is the one group-context edit a member may make, and only
    /// when it is a rename and nothing else.
    #[test]
    fn a_rename_is_the_only_group_context_edit() {
        let rules = PeachyMlsRules::new();
        assert_eq!(
            rules.evaluate(&ProposalContext {
                sets_group_meta: true,
                ..ProposalContext::from_member(ProposalKind::GroupContextExtensions)
            }),
            PolicyDecision::Allow
        );
        assert_eq!(
            rules.evaluate(&ProposalContext::from_member(
                ProposalKind::GroupContextExtensions
            )),
            PolicyDecision::Deny(DenyReason::GroupContextExtensionsUnsupported)
        );
    }
}
