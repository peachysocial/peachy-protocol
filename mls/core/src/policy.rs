// SPDX-License-Identifier: MIT
//! Who may change what in a member-rostered group: admins and a small policy,
//! carried in the group's own state (docs/sealed-messages.md §The
//! group's own state; docs/mls-core.md §The group's policy).
//!
//! The server keeps no roster, so it cannot refuse a non-admin's removal.
//! Every member's device refuses it instead,
//! before merging, with this one function — so four clients cannot disagree
//! about it (`mls/fixtures/rosters.json`, replayed through the fixture door in
//! every language).
//!
//! ## What the group state says
//!
//! Three optional keys of the `peachy_group_meta` JSON
//! (`mls/fixtures/formats/group-meta.json`):
//!
//! - `adm`: the actor ids of the group's admins. Every DM and private group a
//!   current client founds carries one. A group whose meta names no `adm`, or
//!   one that does not read, has NO ADMIN: nobody may do what the rule below
//!   gives admins alone (see "A group whose state names no policy"). A group
//!   with no meta at all (a call link's group, whose membership the link
//!   decides) is not judged.
//! - `pol`: `{"add": "any"|"adm", "meta": "any"|"adm", "acp": "any"|"adm",
//!   "rm": "any"|"adm"}`. Absent keys take the defaults: adds and
//!   name/topic/photo by anybody, the `acp` flag by admins — by anybody in a
//!   DM — and removing somebody else by admins. `rm: "any"` lets any
//!   member's device remove somebody else, for a group whose membership is
//!   decided outside it; honest clients then remove only someone who left
//!   there, and offer the Remove control to admins alone.
//! - `dm`: `true` for a two-person conversation (or a note to self).
//! - `lk`: the GROUP LINK (docs/sealed-messages.md), `{"k": <join key>, "r":
//!   <reader key>, "a": "any"|"adm"|"off"}` — who may join by the link
//!   (anyone, with admin approval, nobody). `k` is in the link; `r`
//!   never leaves the group, and is what reads and clears the link's inbox.
//!   Both are 16-byte keys as 22 base64url characters, and differ. Turning
//!   the link off keeps its keys, so turning it back on brings the same link
//!   back.
//! - `ban`: the actor ids (lowercase UUIDs, no duplicates) banned from
//!   joining by the link, oldest first, at most [`MAX_BANNED`]. An empty
//!   list and no list are the same state.
//!
//! ## The rule
//!
//! For a commit by `sender` in a group that carries a meta:
//!
//! - An UNIDENTIFIED sender (`""`: the caller could not name the actor, or
//!   the sender's leaf has lapsed on the tree clock) is nobody: never an
//!   admin, and no added or removed leaf is its own. It may still do what
//!   anybody may.
//! - A Remove of a leaf whose same SEAT the same commit re-adds is a RESEAT
//!   (`replace_member`): allowed to anybody, and neither half is judged again.
//!   The same seat is the same actor, the same device and the same account
//!   identity key. A Remove of one device's leaf with an Add of another
//!   device of that person, or of a leaf under another account key, is no
//!   reseat: both halves are judged on their own, so a member who may not
//!   remove somebody cannot swap that person's device for another device.
//!   The same device id under another DEVICE (signature) key is still a
//!   reseat to this policy; the adder refuses to build one
//!   (`replace_member`), and every receiver refuses it on its own, in every
//!   group, policy or none (`Client::process_commit`).
//! - An Add of the sender's own actor (seating their own new device) and a
//!   Remove of the sender's own leaves: allowed.
//! - A Remove of a leaf nobody can identify: allowed to anybody — an
//!   eviction, not a decision about a person. The caller decides what
//!   "identify" means, and today it counts a leaf whose credential has expired
//!   on the tree clock as unidentified even inside the grace that still lets
//!   its messages read, so a long-offline admin's leaf is removable by any
//!   member (docs/mls-core.md §The group's policy).
//! - An Add of somebody the group has BANNED: refused, whoever commits it,
//!   and checked before reseats cancel out, so not even a reseat.
//!   An admin who means to let them back lifts the ban first (a meta commit
//!   of its own): adding a banned person unbans them, spelled as two
//!   commits.
//! - Any other Add: `pol.add` — or, when the link is on and needs no
//!   approval, anybody: a member's device seats a link joiner off their seat
//!   ask, whoever may otherwise add (`a: "any"`).
//!   Any other Remove: `pol.rm` (admins by default).
//! - A meta change: the new value must read as the normative reader reads
//!   it (strict JSON with no duplicate key at any depth, and `v` exactly 1)
//!   and keep a non-empty `adm` (or none, where the prior meta had none);
//!   changing `adm`, `pol`, `dm`, `lk` or `ban`
//!   needs an admin; changing `acp` needs `pol.acp`; changing the name,
//!   topic, photo or disappearing-message timer (`dis`) needs `pol.meta` —
//!   the "Edit group info" access, which covers the timer too
//!   (docs/mls-core.md §The group's policy). Under `pol.meta: "adm"`, every
//!   other key needs an admin too, `v`, unknown keys and the keys of
//!   features this repository does not specify included, except the two a plain member's
//!   device writes on its own: `inv` (answering an invitation) and `dir` (a
//!   community group's directory, relisted by any member's device).
//!
//! ## A group whose state names no policy
//!
//! A meta with no `adm` is judged as a group with no admin, never as a group
//! where everybody is one: the `pol`, `lk` and `ban` it carries still read as
//! written, with their defaults, so a member may still add, rename and leave,
//! but nobody may remove somebody else (unless `pol.rm` says `any`) or change
//! `adm`, `pol`, `dm`, `lk` or `ban`. A new meta may leave `adm` out only when
//! the prior one did: nobody names the first admins of such a group.
//!
//! A part that does not read FAILS CLOSED: an unreadable `adm` names no admin,
//! an unreadable `pol` makes every rule the admins', an unreadable `lk` seats
//! nobody, an unreadable `ban` makes every add of somebody else the admins'
//! (a ban list nobody can read cannot be checked, and rewriting or dropping
//! it is a change to the bans), and a meta that is not a
//! JSON object at all names no admin and reads every key as changed.
//!
//! The committer refuses to build a commit this rule refuses
//! ([`judge_commit`]), and every receiver refuses it too.
//!
//! ## One person, one account key
//!
//! [`judge_account_keys`], judged on every commit whether or not the group
//! carries a policy: no leaf the commit adds may carry an account identity
//! key other than the one the other leaves of its actor carry, and no leaf it
//! adds for the reader's own actor may carry any key but the reader's own.
//! The server certifies devices, and could certify one of its own under a
//! key of its own making and the person's actor id. Without this rule the
//! person's own devices would seat it in their groups when the server hands
//! them its key package, and nothing would tell them: a device pins no key
//! for its own actor. With it, the add is refused by the person's own
//! device, and by every other member's.
//!
//! Enforced by members, not the server: a member running a modified client
//! can still commit a change this refuses, and every honest member then
//! refuses to merge it — the group is wedged at that epoch, which is the cost
//! of members enforcing the policy (docs/mls-core.md §Security
//! considerations).

use serde::de::{Deserialize, Deserializer, Error as _, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value};

use crate::rules::{DenyReason, PolicyDecision};

/// The most admins a group's state may name. With [`MAX_BANNED`], what keeps
/// a policy group's meta under [`crate::group_meta::MAX_GROUP_META_BYTES`]
/// with every other key at its longest (`mls/core/tests/group_meta.rs`).
pub const MAX_ADMINS: usize = 64;

/// The most people a group's state may ban (docs/sealed-messages.md §Bans).
/// A cap at the group size limit could not be reached inside
/// [`crate::group_meta::MAX_GROUP_META_BYTES`]; past the cap, a client
/// banning one more drops the oldest first.
pub const MAX_BANNED: usize = 100;

/// Whose a leaf is: the actor its credential names, and the device, account
/// identity key and device (signature) key it carries. `None` for a device or
/// key the caller does not know, which compares equal only to another `None`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Seat {
    pub actor: String,
    pub device: Option<String>,
    pub account_key: Option<[u8; 32]>,
    pub device_key: Option<[u8; 32]>,
}

impl Seat {
    /// A seat known only by its actor.
    pub fn of_actor(actor: impl Into<String>) -> Self {
        Self {
            actor: actor.into(),
            ..Self::default()
        }
    }
}

/// One leaf a commit removes.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RemovedLeaf {
    /// The actor the leaf's credential names, or `None` when the credential
    /// does not check out (past the grace, malformed): an unidentified leaf.
    pub actor: Option<String>,
    /// The device, account identity key and device key the leaf carries,
    /// when known.
    pub device: Option<String>,
    pub account_key: Option<[u8; 32]>,
    pub device_key: Option<[u8; 32]>,
}

impl RemovedLeaf {
    /// A removed leaf known only by its actor, or an unidentified one.
    pub fn of_actor(actor: Option<String>) -> Self {
        Self {
            actor,
            ..Self::default()
        }
    }

    /// Whether `seat` takes back this very seat: same actor, same device,
    /// same account key. The device key is not compared here (the module
    /// header): a reseat under another device key is refused by the adder,
    /// and by the receiver on its own, outside this policy.
    fn is_reseated_by(&self, seat: &Seat) -> bool {
        self.actor.as_deref() == Some(seat.actor.as_str())
            && self.device == seat.device
            && self.account_key == seat.account_key
    }
}

/// The inputs of one judgement.
#[derive(Debug, Clone)]
pub struct CommitFacts<'a> {
    /// The group's meta before the commit, or `None` when it has none.
    pub prior_meta: Option<&'a [u8]>,
    /// The sender's actor id, or `""` for a sender the caller cannot
    /// identify (a lapsed leaf among them), which this judges as nobody.
    pub sender: &'a str,
    /// Every leaf the commit adds.
    pub added: Vec<Seat>,
    /// Every leaf the commit removes.
    pub removed: Vec<RemovedLeaf>,
    /// The meta the commit sets, when it carries a GroupContextExtensions
    /// proposal.
    pub new_meta: Option<&'a [u8]>,
}

struct Policy {
    admins: Vec<String>,
    add_any: bool,
    meta_any: bool,
    acp_any: bool,
    rm_any: bool,
    /// The link is on and seats a joiner with no admin's approval.
    link_admits: bool,
    banned: Vec<String>,
}

/// A 16-byte key as the meta writes it: 22 unpadded base64url characters.
fn is_key(v: Option<&Value>) -> Option<&str> {
    match v {
        Some(Value::String(k))
            if k.len() == 22
                && k.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') =>
        {
            Some(k)
        }
        _ => None,
    }
}

/// An actor id: a lowercase hyphenated UUID.
fn is_actor(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 36
        && b.iter().enumerate().all(|(i, &c)| match i {
            8 | 13 | 18 | 23 => c == b'-',
            _ => c.is_ascii_digit() || (b'a'..=b'f').contains(&c),
        })
}

/// Whether `lk` seats a joiner with nobody's approval: `None` for a
/// malformed value, `Some(true)` only for a link whose access is `any`.
/// `k` is the link's join key and `r` the members' reader key for its inbox
/// (docs/sealed-messages.md §The group's own state); both are required and differ.
fn link_admits(map: &Map<String, Value>) -> Option<bool> {
    match map.get("lk") {
        None => Some(false),
        Some(Value::Object(link)) => {
            let k = is_key(link.get("k"))?;
            let r = is_key(link.get("r"))?;
            if k == r {
                return None;
            }
            match link.get("a") {
                Some(Value::String(a)) if a == "any" => Some(true),
                Some(Value::String(a)) if a == "adm" || a == "off" => Some(false),
                _ => None,
            }
        }
        Some(_) => None,
    }
}

/// `ban`: `None` for a malformed value, a duplicate, an entry that is not an
/// actor id, or a list past [`MAX_BANNED`]. An empty list reads as no list:
/// the two are the same state, so writing one for the other changes nothing.
fn banned_of(map: &Map<String, Value>) -> Option<Vec<String>> {
    match map.get("ban") {
        None => Some(Vec::new()),
        Some(Value::Array(items)) if items.len() <= MAX_BANNED => {
            let mut out: Vec<String> = Vec::with_capacity(items.len());
            for v in items {
                let s = v.as_str().filter(|s| is_actor(s))?;
                if out.iter().any(|o| o == s) {
                    return None;
                }
                out.push(s.to_owned());
            }
            Some(out)
        }
        Some(_) => None,
    }
}

fn parse(meta: &[u8]) -> Option<Map<String, Value>> {
    match serde_json::from_slice::<Value>(meta) {
        Ok(Value::Object(map)) => Some(map),
        _ => None,
    }
}

/// A NEW meta, read as the normative reader reads it
/// (`mls/fixtures/formats/group-meta.json`): strict JSON, no duplicate key
/// at any depth (compared after unescaping), and `v` exactly 1. Anything else
/// is a value every client treats as unreadable, so a commit writing it would
/// freeze what every member shows; it is refused as unreadable instead.
///
/// The PRIOR meta is read with [`parse`]: a group whose stored state is
/// unreadable to the normative reader keeps the policy it names rather than
/// falling open.
fn parse_new(meta: &[u8]) -> Option<Map<String, Value>> {
    serde_json::from_slice::<NoDuplicateKeys>(meta).ok()?;
    let map = parse(meta)?;
    (map.get("v").and_then(Value::as_u64) == Some(1)).then_some(map)
}

/// A JSON value walked only to refuse a duplicate key in any object.
struct NoDuplicateKeys;

impl<'de> Deserialize<'de> for NoDuplicateKeys {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(NoDuplicateKeysVisitor)
    }
}

struct NoDuplicateKeysVisitor;

impl<'de> Visitor<'de> for NoDuplicateKeysVisitor {
    type Value = NoDuplicateKeys;

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("a JSON value with no duplicate key")
    }

    fn visit_bool<E>(self, _: bool) -> Result<Self::Value, E> {
        Ok(NoDuplicateKeys)
    }

    fn visit_i64<E>(self, _: i64) -> Result<Self::Value, E> {
        Ok(NoDuplicateKeys)
    }

    fn visit_u64<E>(self, _: u64) -> Result<Self::Value, E> {
        Ok(NoDuplicateKeys)
    }

    fn visit_f64<E>(self, _: f64) -> Result<Self::Value, E> {
        Ok(NoDuplicateKeys)
    }

    fn visit_str<E>(self, _: &str) -> Result<Self::Value, E> {
        Ok(NoDuplicateKeys)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(NoDuplicateKeys)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        while seq.next_element::<NoDuplicateKeys>()?.is_some() {}
        Ok(NoDuplicateKeys)
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut seen = std::collections::BTreeSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !seen.insert(key) {
                return Err(A::Error::custom("a duplicate key"));
            }
            map.next_value::<NoDuplicateKeys>()?;
        }
        Ok(NoDuplicateKeys)
    }
}

/// The meta keys a plain member may change in a group whose `pol.meta` is
/// `"adm"`: those judged by a rule of their own (`adm`, `pol`, `dm`, `lk`,
/// `ban` by admins, `acp` by `pol.acp`), and the two a plain member's device
/// writes on its own, `inv` (an invitation's answer) and `dir` (a community
/// group's directory, relisted by any member's device). Every other key, `v`,
/// an unknown key and the name, topic, photo and timer among them, is the
/// admins' under `pol.meta: "adm"`.
const MEMBER_KEYS_UNDER_ADMIN_META: [&str; 8] =
    ["adm", "pol", "dm", "lk", "ban", "acp", "inv", "dir"];

/// `adm`: `None` for an unreadable value, `Some(None)` for none at all.
fn admins_of(map: &Map<String, Value>) -> Option<Option<Vec<String>>> {
    match map.get("adm") {
        None => Some(None),
        Some(Value::Array(items)) => items
            .iter()
            .map(|v| v.as_str().map(str::to_owned))
            .collect::<Option<Vec<String>>>()
            .map(Some),
        Some(_) => None,
    }
}

/// `pol`, as `[add, meta, acp, rm]`, each true for "any": `None` for an
/// unreadable value. Absent keys take their defaults.
fn rules_of(map: &Map<String, Value>) -> Option<[bool; 4]> {
    let dm = matches!(map.get("dm"), Some(Value::Bool(true)));
    let pol = match map.get("pol") {
        None => Map::new(),
        Some(Value::Object(p)) => p.clone(),
        Some(_) => return None,
    };
    let rule = |key: &str, default_any: bool| -> Option<bool> {
        match pol.get(key) {
            None => Some(default_any),
            Some(Value::String(s)) if s == "any" => Some(true),
            Some(Value::String(s)) if s == "adm" => Some(false),
            Some(_) => None,
        }
    };
    Some([
        rule("add", true)?,
        rule("meta", true)?,
        rule("acp", dm)?,
        rule("rm", false)?,
    ])
}

/// The policy a parsed meta carries with `admins` as its admins, or `None`
/// when its `pol`, `lk` or `ban` does not read.
fn policy_with_admins(map: &Map<String, Value>, admins: Vec<String>) -> Option<Policy> {
    let [add_any, meta_any, acp_any, rm_any] = rules_of(map)?;
    Some(Policy {
        admins,
        add_any,
        meta_any,
        acp_any,
        rm_any,
        link_admits: link_admits(map)?,
        banned: banned_of(map)?,
    })
}

/// The policy a parsed meta carries, or `None` when it carries no `adm` or
/// an unreadable `adm`, `pol`, `lk` or `ban`: a meta that names no readable
/// policy.
fn policy_of(map: &Map<String, Value>) -> Option<Policy> {
    let admins = admins_of(map)??;
    policy_with_admins(map, admins)
}

/// The policy a prior meta is judged by, which never falls open (the module
/// header, "A group whose state names no policy"): `map` is `None` for a
/// meta that is not a JSON object. A readable policy is itself; otherwise
/// no admin unless `adm` reads, and each other part as written when it
/// reads, or closed when it does not.
fn closed_policy_of(map: Option<&Map<String, Value>>) -> Policy {
    let locked = |admins: Vec<String>| Policy {
        admins,
        add_any: false,
        meta_any: false,
        acp_any: false,
        rm_any: false,
        link_admits: false,
        banned: Vec::new(),
    };
    let Some(map) = map else {
        return locked(Vec::new());
    };
    if let Some(policy) = policy_of(map) {
        return policy;
    }
    let admins = admins_of(map).flatten().unwrap_or_default();
    let [add_any, meta_any, acp_any, rm_any] = rules_of(map).unwrap_or([false; 4]);
    let banned = banned_of(map);
    // A ban list nobody can read cannot be checked, so nobody but an admin
    // adds somebody else, by the link or otherwise.
    let bans_read = banned.is_some();
    Policy {
        add_any: add_any && bans_read,
        meta_any,
        acp_any,
        rm_any,
        link_admits: bans_read && link_admits(map).unwrap_or(false),
        banned: banned.unwrap_or_default(),
        ..locked(admins)
    }
}

fn same_set(a: &[String], b: &[String]) -> bool {
    a.iter().all(|x| b.contains(x)) && b.iter().all(|x| a.contains(x))
}

fn key_changed(before: &Map<String, Value>, after: &Map<String, Value>, key: &str) -> bool {
    before.get(key) != after.get(key)
}

/// The most member leaves a group may hold: the most devices one send or
/// commit may name at the delivery service (docs/delivery.md
/// §SubmitCommit). A tree past it could take no further commit, the one that
/// shrinks it included, since every commit names every device in the tree.
pub const MAX_GROUP_LEAVES: usize = 1024;
/// The most accounts a group's leaves may name, for the same reason.
pub const MAX_GROUP_ACCOUNTS: usize = 256;
/// The largest leaf node, encoded, a commit may bring into a tree: the
/// largest credential the core reads
/// ([`crate::credential::MAX_TOKEN_BYTES`]) and 4 KiB for the rest (keys,
/// capabilities, extensions, signature). A current build's leaf is 1.9 to
/// 2.0 KB, so this is about six times that. Every member's commit is padded
/// to a bound that counts the tree's largest leaf (`crate::commit_padding`),
/// so one oversized leaf would set every other member's commit size.
pub const MAX_LEAF_NODE_BYTES: usize = crate::credential::MAX_TOKEN_BYTES + 4 * 1024;

/// What is over the caps in the tree a commit leaves: `leaves` its member
/// leaves, `accounts` the accounts they name, and `largest_leaf` the largest
/// leaf node the commit brings in, encoded. `None` when nothing is.
pub fn commit_size_refusal(leaves: usize, accounts: usize, largest_leaf: usize) -> Option<String> {
    if leaves > MAX_GROUP_LEAVES {
        return Some(format!(
            "the commit leaves {leaves} devices in the group, over {MAX_GROUP_LEAVES}"
        ));
    }
    if accounts > MAX_GROUP_ACCOUNTS {
        return Some(format!(
            "the commit leaves {accounts} accounts in the group, over {MAX_GROUP_ACCOUNTS}"
        ));
    }
    if largest_leaf > MAX_LEAF_NODE_BYTES {
        return Some(format!(
            "the commit carries a leaf of {largest_leaf} bytes, over {MAX_LEAF_NODE_BYTES}"
        ));
    }
    None
}

/// Judge one commit: what the committer checks before it sends, and what
/// every receiver refuses. See the module header for the rule. A group with no meta at all is not judged.
pub fn judge_commit(facts: &CommitFacts<'_>) -> PolicyDecision {
    use PolicyDecision::{Allow, Deny};
    let Some(prior_meta) = facts.prior_meta else {
        return Allow;
    };
    // Never falls open: a meta that names no readable policy is judged as
    // a group with no admin, every unreadable part closed.
    let parsed = parse(prior_meta);
    let policy = closed_policy_of(parsed.as_ref());
    let prior_map = parsed.unwrap_or_default();
    // An unidentified sender is nobody: never an admin, and nothing it adds
    // or removes is its own. Fails closed, so a lapsed leaf can pass no rule
    // an identified non-admin could not.
    let identified = !facts.sender.is_empty();
    let admin = identified && policy.admins.iter().any(|a| a == facts.sender);
    let own = |actor: &str| identified && actor == facts.sender;

    // A banned actor is never added, not even as a reseat of a leaf they
    // still hold: checked on every Add before reseats cancel out.
    if facts
        .added
        .iter()
        .any(|seat| policy.banned.contains(&seat.actor))
    {
        return Deny(DenyReason::AddBanned);
    }

    // Reseats cancel out, one removed leaf against one added leaf of the
    // same seat: actor, device and account key. The device key is not
    // compared here: a reseat under another one is refused by the adder,
    // and by the receiver outside this policy (`RemovedLeaf::is_reseated_by`).
    let mut added = facts.added.clone();
    let mut removed: Vec<&RemovedLeaf> = Vec::new();
    for leaf in &facts.removed {
        if let Some(i) = added.iter().position(|seat| leaf.is_reseated_by(seat)) {
            added.remove(i);
            continue;
        }
        removed.push(leaf);
    }

    for Seat { actor, .. } in &added {
        if !own(actor) && !admin && !policy.add_any && !policy.link_admits {
            return Deny(DenyReason::AddNeedsAdmin);
        }
    }
    for leaf in removed {
        match &leaf.actor {
            None => {}
            Some(actor) if own(actor) => {}
            Some(_) if admin || policy.rm_any => {}
            Some(_) => return Deny(DenyReason::RemoveNeedsAdmin),
        }
    }

    if let Some(new_meta) = facts.new_meta {
        let Some(next_map) = parse_new(new_meta) else {
            return Deny(DenyReason::MetaUnreadable);
        };
        // A group with no `adm` may keep none (its name and timer still
        // change by `pol.meta`); every other new meta names 1 to
        // [`MAX_ADMINS`] admins. Either way `pol`, `lk` and `ban` must read.
        let next_policy = match admins_of(&next_map) {
            Some(Some(admins)) if !admins.is_empty() && admins.len() <= MAX_ADMINS => {
                policy_with_admins(&next_map, admins)
            }
            Some(None) if !prior_map.contains_key("adm") => {
                policy_with_admins(&next_map, Vec::new())
            }
            _ => None,
        };
        let Some(next_policy) = next_policy else {
            return Deny(DenyReason::MetaUnreadable);
        };
        let governance = !same_set(&policy.admins, &next_policy.admins)
            || key_changed(&prior_map, &next_map, "pol")
            || key_changed(&prior_map, &next_map, "dm")
            || key_changed(&prior_map, &next_map, "lk")
            || policy.banned != next_policy.banned
            // A ban list that did not read was judged as none; dropping or
            // rewriting it is still a change to the bans.
            || (banned_of(&prior_map).is_none() && key_changed(&prior_map, &next_map, "ban"));
        if governance && !admin {
            return Deny(DenyReason::PolicyNeedsAdmin);
        }
        if key_changed(&prior_map, &next_map, "acp") && !admin && !policy.acp_any {
            return Deny(DenyReason::AcpNeedsAdmin);
        }
        // `dis`, the disappearing-message timer, sits with the name, topic
        // and photo under `pol.meta`: the group "attributes" access governs
        // the timer too (docs/mls-core.md §The group's policy).
        let described = ["n", "t", "a", "dis"]
            .iter()
            .any(|key| key_changed(&prior_map, &next_map, key));
        if described && !admin && !policy.meta_any {
            return Deny(DenyReason::MetaNeedsAdmin);
        }
        // Under `pol.meta: "adm"` the group's state is the admins' beyond the
        // keys a plain member writes: a member who could change `v`, or a key
        // this build does not know, could make the value unreadable for every
        // client, or change what a newer one reads, where only admins may.
        if !admin && !policy.meta_any {
            let unlisted = prior_map
                .keys()
                .chain(next_map.keys())
                .filter(|key| !MEMBER_KEYS_UNDER_ADMIN_META.contains(&key.as_str()))
                .any(|key| key_changed(&prior_map, &next_map, key));
            if unlisted {
                return Deny(DenyReason::MetaNeedsAdmin);
            }
        }
    }
    Allow
}

/// One person, one account key (the module header). `kept` is every leaf of
/// the tree the commit leaves in place, `added` every leaf it adds, and
/// `reader` the reader's own actor and account key when it has one.
///
/// Refused as [`DenyReason::AccountKeyConflict`] when an added leaf's actor
/// is the reader's and its key is not the reader's, or when an added leaf
/// and any other leaf of its actor, kept or added, both carry a key and the
/// keys differ. Leaves the commit does not add are not judged against each
/// other: a tree that already holds two keys for one person was let in by a
/// build without this rule, and refusing every commit on it would freeze the
/// group rather than mend it. Removing the old leaves mends it.
pub fn judge_account_keys(
    reader: Option<(&str, &[u8; 32])>,
    kept: &[Seat],
    added: &[Seat],
) -> PolicyDecision {
    for seat in added {
        if let Some((actor, key)) = reader {
            if seat.actor == actor && seat.account_key.as_ref() != Some(key) {
                return PolicyDecision::Deny(DenyReason::AccountKeyConflict);
            }
        }
        let Some(key) = seat.account_key else {
            continue;
        };
        let conflicts = kept
            .iter()
            .chain(added)
            .any(|other| other.actor == seat.actor && other.account_key.is_some_and(|k| k != key));
        if conflicts {
            return PolicyDecision::Deny(DenyReason::AccountKeyConflict);
        }
    }
    PolicyDecision::Allow
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    const ADA: &str = "aaaaaaaa-0000-4000-8000-000000000000";
    const BO: &str = "bbbbbbbb-0000-4000-8000-000000000000";
    const CY: &str = "cccccccc-0000-4000-8000-000000000000";

    fn meta(extra: &str) -> Vec<u8> {
        format!("{{\"v\":1,\"n\":\"x\",\"adm\":[\"{ADA}\"]{extra}}}").into_bytes()
    }

    fn facts<'a>(prior: &'a [u8], sender: &'a str) -> CommitFacts<'a> {
        CommitFacts {
            prior_meta: Some(prior),
            sender,
            added: vec![],
            removed: vec![],
            new_meta: None,
        }
    }

    #[test]
    fn no_meta_is_not_judged() {
        let mut f = facts(b"", BO);
        f.prior_meta = None;
        f.removed = vec![RemovedLeaf::of_actor(Some(CY.into()))];
        assert_eq!(judge_commit(&f), PolicyDecision::Allow);
    }

    /// A meta with no `adm` names no admin: it never lets everybody do
    /// everything, as it once did.
    #[test]
    fn no_admins_names_no_admin() {
        let prior = b"{\"v\":1,\"n\":\"x\"}".to_vec();
        let mut f = facts(&prior, BO);
        f.removed = vec![RemovedLeaf::of_actor(Some(CY.into()))];
        assert_eq!(
            judge_commit(&f),
            PolicyDecision::Deny(DenyReason::RemoveNeedsAdmin)
        );
        // What anybody may do in any group, they still may.
        f.removed = vec![
            RemovedLeaf::of_actor(Some(BO.into())),
            RemovedLeaf::of_actor(None),
        ];
        assert_eq!(judge_commit(&f), PolicyDecision::Allow);
        f.removed = vec![];
        f.added = vec![Seat::of_actor(CY)];
        assert_eq!(judge_commit(&f), PolicyDecision::Allow);
        f.added = vec![];
        // A rename that keeps `adm` out: `pol.meta`, anybody by default.
        let renamed = b"{\"v\":1,\"n\":\"y\"}".to_vec();
        f.new_meta = Some(&renamed);
        assert_eq!(judge_commit(&f), PolicyDecision::Allow);
        // Nobody names the first admin, not even themselves.
        let crowned = format!("{{\"v\":1,\"n\":\"x\",\"adm\":[\"{BO}\"]}}").into_bytes();
        f.new_meta = Some(&crowned);
        assert_eq!(
            judge_commit(&f),
            PolicyDecision::Deny(DenyReason::PolicyNeedsAdmin)
        );
        for next in [
            b"{\"v\":1,\"n\":\"x\",\"pol\":{\"rm\":\"any\"}}".to_vec(),
            b"{\"v\":1,\"n\":\"x\",\"dm\":true}".to_vec(),
            format!("{{\"v\":1,\"n\":\"x\",\"ban\":[\"{CY}\"]}}").into_bytes(),
        ] {
            let mut g = facts(&prior, BO);
            g.new_meta = Some(&next);
            assert_eq!(
                judge_commit(&g),
                PolicyDecision::Deny(DenyReason::PolicyNeedsAdmin),
                "{}",
                String::from_utf8_lossy(&next)
            );
        }
        // A `pol` the group carries still reads as written.
        let open = b"{\"v\":1,\"n\":\"x\",\"pol\":{\"rm\":\"any\",\"add\":\"adm\"}}".to_vec();
        let mut f = facts(&open, BO);
        f.removed = vec![RemovedLeaf::of_actor(Some(CY.into()))];
        assert_eq!(judge_commit(&f), PolicyDecision::Allow);
        f.removed = vec![];
        f.added = vec![Seat::of_actor(CY)];
        assert_eq!(
            judge_commit(&f),
            PolicyDecision::Deny(DenyReason::AddNeedsAdmin)
        );
    }

    /// Each part of a prior meta that does not read fails closed.
    #[test]
    fn an_unreadable_policy_fails_closed() {
        let remove_cy = |prior: &[u8], sender: &str| {
            let mut f = facts(prior, sender);
            f.removed = vec![RemovedLeaf::of_actor(Some(CY.into()))];
            judge_commit(&f)
        };
        let add_cy = |prior: &[u8], sender: &str| {
            let mut f = facts(prior, sender);
            f.added = vec![Seat::of_actor(CY)];
            judge_commit(&f)
        };
        let rename = |prior: &[u8], sender: &str| {
            let next = format!("{{\"v\":1,\"n\":\"y\",\"adm\":[\"{ADA}\"]}}").into_bytes();
            let mut f = facts(prior, sender);
            f.new_meta = Some(&next);
            judge_commit(&f)
        };
        let remove_needs = PolicyDecision::Deny(DenyReason::RemoveNeedsAdmin);
        let add_needs = PolicyDecision::Deny(DenyReason::AddNeedsAdmin);

        // Not a JSON object: no admin, nothing but what anybody may.
        for prior in [&b"not json"[..], b"[1]"] {
            let shown = String::from_utf8_lossy(prior);
            assert_eq!(remove_cy(prior, ADA), remove_needs, "{shown}");
            assert_eq!(add_cy(prior, ADA), add_needs, "{shown}");
            assert_ne!(rename(prior, ADA), PolicyDecision::Allow, "{shown}");
        }
        // An unreadable `adm` names no admin; the rest reads as written.
        let bad_adm = b"{\"v\":1,\"n\":\"x\",\"adm\":5}".to_vec();
        assert_eq!(remove_cy(&bad_adm, ADA), remove_needs);
        assert_eq!(add_cy(&bad_adm, ADA), PolicyDecision::Allow);
        assert_eq!(
            rename(&bad_adm, ADA),
            PolicyDecision::Deny(DenyReason::PolicyNeedsAdmin)
        );
        // An unreadable `pol`: every rule the admins', who still hold them,
        // and mending it is theirs too.
        let policy_needs = PolicyDecision::Deny(DenyReason::PolicyNeedsAdmin);
        let bad_pol = meta(",\"pol\":\"open\"");
        assert_eq!(remove_cy(&bad_pol, BO), remove_needs);
        assert_eq!(add_cy(&bad_pol, BO), add_needs);
        assert_eq!(rename(&bad_pol, BO), policy_needs);
        assert_eq!(remove_cy(&bad_pol, ADA), PolicyDecision::Allow);
        assert_eq!(add_cy(&bad_pol, ADA), PolicyDecision::Allow);
        assert_eq!(rename(&bad_pol, ADA), PolicyDecision::Allow);
        // An unreadable `ban` cannot be checked: adds are the admins', and
        // dropping it is a change to the bans, not a rename.
        let bad_ban = meta(",\"ban\":[\"not an actor\"]");
        assert_eq!(add_cy(&bad_ban, BO), add_needs);
        assert_eq!(add_cy(&bad_ban, ADA), PolicyDecision::Allow);
        assert_eq!(rename(&bad_ban, BO), policy_needs);
        assert_eq!(rename(&bad_ban, ADA), PolicyDecision::Allow);
        // An unreadable link seats nobody.
        let bad_link = meta(",\"pol\":{\"add\":\"adm\"},\"lk\":{\"a\":\"any\"}");
        assert_eq!(add_cy(&bad_link, BO), add_needs);
    }

    /// A group whose state names no readable policy is a group with no
    /// admin: removing somebody else is refused there.
    #[test]
    fn a_group_with_no_readable_policy_has_no_admin() {
        for prior in [
            b"{\"v\":1,\"n\":\"x\"}".to_vec(),
            b"not json".to_vec(),
            meta(",\"pol\":\"open\""),
        ] {
            let mut f = facts(&prior, BO);
            f.removed = vec![RemovedLeaf::of_actor(Some(CY.into()))];
            assert_eq!(
                judge_commit(&f),
                PolicyDecision::Deny(DenyReason::RemoveNeedsAdmin)
            );
        }
    }

    #[test]
    fn only_an_admin_removes_somebody_else() {
        let prior = meta("");
        let mut f = facts(&prior, BO);
        f.removed = vec![RemovedLeaf::of_actor(Some(CY.into()))];
        assert_eq!(
            judge_commit(&f),
            PolicyDecision::Deny(DenyReason::RemoveNeedsAdmin)
        );
        f.sender = ADA;
        assert_eq!(judge_commit(&f), PolicyDecision::Allow);
    }

    #[test]
    fn a_reseat_and_an_own_removal_are_anybodys() {
        let prior = meta(",\"pol\":{\"add\":\"adm\"}");
        let mut f = facts(&prior, BO);
        f.removed = vec![RemovedLeaf::of_actor(Some(CY.into()))];
        f.added = vec![Seat::of_actor(CY)];
        assert_eq!(judge_commit(&f), PolicyDecision::Allow);
        f.removed = vec![
            RemovedLeaf::of_actor(Some(BO.into())),
            RemovedLeaf::of_actor(None),
        ];
        f.added = vec![Seat::of_actor(BO)];
        assert_eq!(judge_commit(&f), PolicyDecision::Allow);
    }

    fn seat(actor: &str, device: &str, key: u8) -> Seat {
        Seat {
            actor: actor.into(),
            device: Some(device.into()),
            account_key: Some([key; 32]),
            device_key: Some([0x40; 32]),
        }
    }

    fn removed(seat: &Seat) -> RemovedLeaf {
        RemovedLeaf {
            actor: Some(seat.actor.clone()),
            device: seat.device.clone(),
            account_key: seat.account_key,
            device_key: seat.device_key,
        }
    }

    #[test]
    fn only_the_same_seat_is_a_reseat() {
        let prior = meta(",\"pol\":{\"add\":\"adm\"}");
        let phone = seat(CY, "cy-phone", 1);
        let mut f = facts(&prior, BO);
        f.removed = vec![removed(&phone)];
        f.added = vec![phone.clone()];
        assert_eq!(judge_commit(&f), PolicyDecision::Allow);
        // Another device of the same person: not a reseat.
        f.added = vec![seat(CY, "cy-laptop", 1)];
        assert_eq!(
            judge_commit(&f),
            PolicyDecision::Deny(DenyReason::AddNeedsAdmin)
        );
        // The same device id under another account key: not a reseat.
        f.added = vec![seat(CY, "cy-phone", 2)];
        assert_eq!(
            judge_commit(&f),
            PolicyDecision::Deny(DenyReason::AddNeedsAdmin)
        );
        // With adds open to anybody, the removal half is still judged.
        let open = meta("");
        let mut f = facts(&open, BO);
        f.removed = vec![removed(&phone)];
        f.added = vec![seat(CY, "cy-phone", 2)];
        assert_eq!(
            judge_commit(&f),
            PolicyDecision::Deny(DenyReason::RemoveNeedsAdmin)
        );
        f.sender = ADA;
        assert_eq!(judge_commit(&f), PolicyDecision::Allow);
        // The same device id and account key under another DEVICE key:
        // still a reseat to this policy; the adder refuses to build one, and
        // the receiver refuses it on its own (tests/own_device_ids.rs).
        let mut swapped = phone.clone();
        swapped.device_key = Some([0x41; 32]);
        let mut f = facts(&open, BO);
        f.removed = vec![removed(&phone)];
        f.added = vec![swapped];
        assert_eq!(judge_commit(&f), PolicyDecision::Allow);
    }

    #[test]
    fn one_person_one_account_key() {
        let ada_phone = seat(ADA, "ada-phone", 1);
        let bo_phone = seat(BO, "bo-phone", 2);
        let kept = [ada_phone.clone(), bo_phone.clone()];
        let reader = Some((BO, &[2u8; 32]));
        // Another device of Ada under her key: fine.
        assert_eq!(
            judge_account_keys(reader, &kept, &[seat(ADA, "ada-laptop", 1)]),
            PolicyDecision::Allow
        );
        // A device of Ada under another key, beside her phone: refused.
        assert_eq!(
            judge_account_keys(reader, &kept, &[seat(ADA, "ghost", 9)]),
            PolicyDecision::Deny(DenyReason::AccountKeyConflict)
        );
        // A device of the reader's own actor under another key, even with
        // none of the reader's leaves left beside it: refused.
        assert_eq!(
            judge_account_keys(
                reader,
                std::slice::from_ref(&ada_phone),
                &[seat(BO, "ghost", 9)]
            ),
            PolicyDecision::Deny(DenyReason::AccountKeyConflict)
        );
        // Two added leaves of one actor that disagree: refused.
        assert_eq!(
            judge_account_keys(None, &[], &[seat(CY, "a", 3), seat(CY, "b", 4)]),
            PolicyDecision::Deny(DenyReason::AccountKeyConflict)
        );
        // A newcomer the tree has never seen: the server's word, as ever.
        assert_eq!(
            judge_account_keys(reader, &kept, &[seat(CY, "cy-phone", 3)]),
            PolicyDecision::Allow
        );
        // Two keys already in the tree, nothing added: not judged.
        assert_eq!(
            judge_account_keys(reader, &[ada_phone, seat(ADA, "old", 7)], &[]),
            PolicyDecision::Allow
        );
    }

    #[test]
    fn an_unidentified_sender_is_nobody() {
        // Even a group whose state names "" as an admin, and a leaf that
        // names "" as its actor: an unidentified sender is never the admin
        // and never the leaf's owner.
        let prior =
            format!("{{\"v\":1,\"n\":\"x\",\"adm\":[\"{ADA}\",\"\"],\"pol\":{{\"add\":\"adm\"}}}}")
                .into_bytes();
        let mut f = facts(&prior, "");
        f.removed = vec![RemovedLeaf::of_actor(Some(CY.into()))];
        assert_eq!(
            judge_commit(&f),
            PolicyDecision::Deny(DenyReason::RemoveNeedsAdmin)
        );
        f.removed = vec![RemovedLeaf::of_actor(Some(String::new()))];
        assert_eq!(
            judge_commit(&f),
            PolicyDecision::Deny(DenyReason::RemoveNeedsAdmin)
        );
        f.removed = vec![];
        f.added = vec![Seat::of_actor("")];
        assert_eq!(
            judge_commit(&f),
            PolicyDecision::Deny(DenyReason::AddNeedsAdmin)
        );
        f.added = vec![];
        let next = format!("{{\"v\":1,\"n\":\"x\",\"adm\":[\"{BO}\"]}}").into_bytes();
        f.new_meta = Some(&next);
        assert_eq!(
            judge_commit(&f),
            PolicyDecision::Deny(DenyReason::PolicyNeedsAdmin)
        );
        // What anybody may do, it still may: evict a leaf nobody can identify.
        f.new_meta = None;
        f.removed = vec![RemovedLeaf::of_actor(None)];
        assert_eq!(judge_commit(&f), PolicyDecision::Allow);
    }

    #[test]
    fn adds_follow_the_policy() {
        let open = meta("");
        let mut f = facts(&open, BO);
        f.added = vec![Seat::of_actor(CY)];
        assert_eq!(judge_commit(&f), PolicyDecision::Allow);
        let closed = meta(",\"pol\":{\"add\":\"adm\"}");
        let mut f = facts(&closed, BO);
        f.added = vec![Seat::of_actor(CY)];
        assert_eq!(
            judge_commit(&f),
            PolicyDecision::Deny(DenyReason::AddNeedsAdmin)
        );
    }

    #[test]
    fn governance_is_the_admins() {
        let prior = meta("");
        let next = format!("{{\"v\":1,\"n\":\"x\",\"adm\":[\"{ADA}\",\"{BO}\"]}}").into_bytes();
        let mut f = facts(&prior, BO);
        f.new_meta = Some(&next);
        assert_eq!(
            judge_commit(&f),
            PolicyDecision::Deny(DenyReason::PolicyNeedsAdmin)
        );
        f.sender = ADA;
        assert_eq!(judge_commit(&f), PolicyDecision::Allow);
        let none = b"{\"v\":1,\"n\":\"x\",\"adm\":[]}".to_vec();
        f.new_meta = Some(&none);
        assert_eq!(
            judge_commit(&f),
            PolicyDecision::Deny(DenyReason::MetaUnreadable)
        );
    }

    #[test]
    fn acp_is_the_admins_in_a_group_and_anybodys_in_a_dm() {
        let group = meta("");
        let group_on = meta(",\"acp\":true");
        let mut f = facts(&group, BO);
        f.new_meta = Some(&group_on);
        assert_eq!(
            judge_commit(&f),
            PolicyDecision::Deny(DenyReason::AcpNeedsAdmin)
        );
        let dm = meta(",\"dm\":true");
        let dm_on = meta(",\"dm\":true,\"acp\":true");
        let mut f = facts(&dm, BO);
        f.new_meta = Some(&dm_on);
        assert_eq!(judge_commit(&f), PolicyDecision::Allow);
    }

    #[test]
    fn the_timer_follows_the_meta_rule() {
        let open = meta("");
        let open_on = meta(",\"dis\":604800");
        let mut f = facts(&open, BO);
        f.new_meta = Some(&open_on);
        assert_eq!(judge_commit(&f), PolicyDecision::Allow);
        let closed = meta(",\"pol\":{\"meta\":\"adm\"}");
        let closed_on = meta(",\"pol\":{\"meta\":\"adm\"},\"dis\":604800");
        let mut f = facts(&closed, BO);
        f.new_meta = Some(&closed_on);
        assert_eq!(
            judge_commit(&f),
            PolicyDecision::Deny(DenyReason::MetaNeedsAdmin)
        );
        f.sender = ADA;
        assert_eq!(judge_commit(&f), PolicyDecision::Allow);
    }

    /// Under `pol.meta: "adm"` a plain member cannot change `v`, a key of a
    /// feature this repository does not specify, or a key nobody knows: any of them can
    /// freeze or change what every client reads. The admin still can, and a
    /// plain member still answers an invitation and relists a directory.
    #[test]
    fn under_admin_meta_only_admins_change_unlisted_keys() {
        let closed = meta(",\"pol\":{\"meta\":\"adm\"}");
        let deny = PolicyDecision::Deny(DenyReason::MetaNeedsAdmin);
        for extra in [
            ",\"zz\":1",
            ",\"cg\":\"x\"",
            ",\"cm\":\"x\"",
            ",\"jk\":\"x\"",
            ",\"ev\":{}",
        ] {
            let next = meta(&format!(",\"pol\":{{\"meta\":\"adm\"}}{extra}"));
            let mut f = facts(&closed, BO);
            f.new_meta = Some(&next);
            assert_eq!(judge_commit(&f), deny, "{extra}");
            f.sender = ADA;
            assert_eq!(judge_commit(&f), PolicyDecision::Allow, "{extra}");
        }
        // Dropping a key is a change too.
        let with_cg = meta(",\"pol\":{\"meta\":\"adm\"},\"cg\":\"x\"");
        let mut f = facts(&with_cg, BO);
        f.new_meta = Some(&closed);
        assert_eq!(judge_commit(&f), deny);
        // `inv` and `dir` stay a plain member's.
        for extra in [",\"inv\":{\"t\":\"x\",\"r\":\"join\"}", ",\"dir\":[]"] {
            let next = meta(&format!(",\"pol\":{{\"meta\":\"adm\"}}{extra}"));
            let mut f = facts(&closed, BO);
            f.new_meta = Some(&next);
            assert_eq!(judge_commit(&f), PolicyDecision::Allow, "{extra}");
        }
        // Under the default `pol.meta`, unlisted keys stay anybody's.
        let open = meta("");
        let next = meta(",\"zz\":1");
        let mut f = facts(&open, BO);
        f.new_meta = Some(&next);
        assert_eq!(judge_commit(&f), PolicyDecision::Allow);
    }

    /// A new meta must read as every client reads it: `v` exactly 1 and no
    /// duplicate key at any depth. Nobody may write one that does not, an
    /// admin included, since it freezes what every member shows.
    #[test]
    fn a_new_meta_must_read_as_the_clients_read_it() {
        let open = meta("");
        let unreadable = PolicyDecision::Deny(DenyReason::MetaUnreadable);
        let cases: [&[u8]; 6] = [
            b"{\"v\":2,\"n\":\"x\",\"adm\":[\"aaaaaaaa-0000-4000-8000-000000000000\"]}",
            b"{\"v\":\"1\",\"n\":\"x\",\"adm\":[\"aaaaaaaa-0000-4000-8000-000000000000\"]}",
            b"{\"n\":\"x\",\"adm\":[\"aaaaaaaa-0000-4000-8000-000000000000\"]}",
            b"{\"v\":1,\"n\":\"x\",\"n\":\"y\",\"adm\":[\"aaaaaaaa-0000-4000-8000-000000000000\"]}",
            b"{\"v\":1,\"n\":\"x\",\"\\u006e\":\"y\",\"adm\":[\"aaaaaaaa-0000-4000-8000-000000000000\"]}",
            b"{\"v\":1,\"n\":\"x\",\"a\":{\"k\":1,\"k\":2},\"adm\":[\"aaaaaaaa-0000-4000-8000-000000000000\"]}",
        ];
        for next in cases {
            for sender in [BO, ADA] {
                let mut f = facts(&open, sender);
                f.new_meta = Some(next);
                assert_eq!(
                    judge_commit(&f),
                    unreadable,
                    "{}",
                    String::from_utf8_lossy(next)
                );
            }
        }
        // The same value with each key once reads.
        let next = meta(",\"a\":{\"k\":1}");
        let mut f = facts(&open, BO);
        f.new_meta = Some(&next);
        assert_eq!(judge_commit(&f), PolicyDecision::Allow);
    }
}
