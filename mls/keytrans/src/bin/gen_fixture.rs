// SPDX-License-Identifier: MIT
//! Writes `mls/fixtures/keytrans.json`, the golden fixture for key
//! transparency: the profile's configuration, labels and values, device
//! sets, commitments, VRF outputs, tree heads, and a small log with log tree
//! and prefix tree proofs, every one computed by this crate.
//!
//! From `mls/`:
//!
//! ```text
//! cargo run -p peachy-keytrans --features prover --bin gen_fixture
//! cargo run -p peachy-keytrans --features prover --bin gen_fixture -- --check
//! ```
//!
//! The first writes the file, the second exits 1 if the committed file is not
//! what this generator makes. The test at the bottom does the same check, so
//! `cargo test --workspace --all-features` fails when anything the fixture
//! pins changes without the fixture being regenerated.
//!
//! # The cases, and the door that replays them
//!
//! The file follows the other golden fixtures: a list of cases, each with an
//! `id`, `kind` (`"keytrans"`), a `call` naming the question, the inputs
//! whole, and either `expect` or `expectError` (the crate's error kind, by
//! name). Every case is written as a VERIFIER's question: it carries what a
//! client would receive (keys, proofs, signatures) and expects what a client
//! must compute or refuse. Nothing in a case needs a private key, so every
//! binding can replay it through one JSON-in, JSON-out door.
//!
//! Nothing here is random: keys come from recognizable 32-byte seeds,
//! commitment openings from a hash of the label and version, timestamps are
//! fixed, and Ed25519 and the VRF are deterministic. The generator checks its
//! own output as it goes (every proof verifies, every refusal refuses) and
//! fails rather than write a fixture that disagrees with the crate.
//!
//! # What is not here yet
//!
//! The prefix trees come from a small reference builder below, and the log
//! tree proofs from [`peachy_keytrans::log_tree::MemoryLog`]. Search,
//! monitor, update, distinguished and transparency proof responses need the
//! prover and the verifier; they join the file when those exist, from the
//! prover's own prefix tree, and every value already here must come out the
//! same.

use std::collections::{BTreeMap, BTreeSet};
use std::process::ExitCode;

use peachy_keytrans::codec::{decode, encode};
use peachy_keytrans::commitment::commit;
use peachy_keytrans::head::{
    auditor_tree_head_tbs, sign_auditor_tree_head, sign_tree_head, tree_head_tbs,
    verify_auditor_tree_head, verify_tree_head,
};
use peachy_keytrans::implicit::{distinguished_entries, rightmost_distinguished};
use peachy_keytrans::log_tree::{leaf_hash as log_leaf_hash, verify_batch, BatchSpec, MemoryLog};
use peachy_keytrans::prefix_proof::{
    bit, evaluate, leaf_hash as prefix_leaf_hash, parent_hash as prefix_parent_hash, PrefixSearch,
    EMPTY,
};
use peachy_keytrans::profile::device_set::empty_root;
use peachy_keytrans::profile::params::{
    check_configuration, label_kind, Auditor, Profile, ATTESTED_AUDITOR_START_POS, CIPHER_SUITE,
    CONFIG_VERSION, DAY_MS, DEPLOYMENT_MODE, DRAFT_REVISION, HOUR_MS, LABEL_KINDS,
    MAXIMUM_LIFETIME_MS, MAX_AHEAD_MS, MAX_AUDITOR_LAG_MS, MAX_BEHIND_MS, MIN_LIFETIME_WINDOWS,
    REASONABLE_MONITORING_WINDOW_MS,
};
use peachy_keytrans::profile::{
    AccountValue, AuditorInstance, DeviceEntry, DeviceInclusion, DeviceSet, Label, MappingValue,
};
use peachy_keytrans::suite::{hash, Hash, PublicKey, SecretKey, VrfOutput, OPENING_LEN};
use peachy_keytrans::vrf::{vrf_input, VrfPublicKey, VrfSecretKey};
use peachy_keytrans::wire::{
    Configuration, FullTreeHead, KeyedAuditorTreeHead, LogEntry, ModeConfig, PrefixLeaf,
    PrefixProof, PrefixSearchOutcome, PrefixSearchResult, TreeHead, UpdateValue,
};
use peachy_keytrans::Error;

/// Where the fixture lives, from this crate's manifest.
const FIXTURE_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../fixtures/keytrans.json");

type Gen<T> = std::result::Result<T, String>;

// ---------------------------------------------------------------------------
// The inputs: seeds, actors, a clock
// ---------------------------------------------------------------------------

/// The log's tree head signing key.
const LOG_SEED: [u8; 32] = [0x10; 32];
/// The log's VRF key.
const VRF_SEED: [u8; 32] = [0x20; 32];
/// Two auditors: the attested one (it processed the log from entry 0) and an
/// independent one that started at entry 4.
const AUDITOR_SEEDS: [([u8; 32], u64); 2] =
    [([0x30; 32], ATTESTED_AUDITOR_START_POS), ([0x31; 32], 4)];
/// An auditor no configuration names.
const STRANGER_AUDITOR_SEED: [u8; 32] = [0x3f; 32];
/// Ada's and Grace's account identity keys.
const ADA_ACCOUNT_SEED: [u8; 32] = [0x41; 32];
const GRACE_ACCOUNT_SEED: [u8; 32] = [0x42; 32];
/// The account that holds the 64-device set.
const MANY_ACCOUNT_SEED: [u8; 32] = [0x43; 32];
const ADA_ACTOR: [u8; 16] = [
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
];
const GRACE_ACTOR: [u8; 16] = [
    0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
];
/// The first log entry's timestamp, milliseconds since the Unix epoch.
const T0: u64 = 1_800_000_000_000;
/// The domain of the account certificate a device entry carries (the MLS
/// core's account identity format).
const ACCOUNT_DEVICE_DOMAIN: &[u8] = b"peachy-account-device-v1";

// ---------------------------------------------------------------------------
// A small JSON writer, laid out as `JSON.stringify(value, null, 2)` does
// ---------------------------------------------------------------------------

enum J {
    Null,
    Bool(bool),
    Num(u64),
    Str(String),
    Arr(Vec<J>),
    Obj(Vec<(String, J)>),
}

macro_rules! obj {
    ($($k:expr => $v:expr),* $(,)?) => {
        J::Obj(vec![$(($k.to_string(), $v)),*])
    };
}

fn s(text: &str) -> J {
    J::Str(text.to_string())
}

fn n(value: u64) -> J {
    J::Num(value)
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(char::from(DIGITS[usize::from(b >> 4)]));
        out.push(char::from(DIGITS[usize::from(b & 0x0f)]));
    }
    out
}

fn h(bytes: &[u8]) -> J {
    J::Str(hex(bytes))
}

fn hashes(values: &[Hash]) -> J {
    J::Arr(values.iter().map(|v| h(v)).collect())
}

fn nums(values: &[u64]) -> J {
    J::Arr(values.iter().map(|&v| n(v)).collect())
}

impl J {
    fn write(&self, out: &mut String, indent: usize) {
        let pad = |out: &mut String, depth: usize| out.push_str(&"  ".repeat(depth));
        match self {
            J::Null => out.push_str("null"),
            J::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
            J::Num(v) => out.push_str(&v.to_string()),
            J::Str(text) => {
                out.push('"');
                for c in text.chars() {
                    match c {
                        '"' => out.push_str("\\\""),
                        '\\' => out.push_str("\\\\"),
                        c if u32::from(c) < 0x20 => {
                            out.push_str(&format!("\\u{:04x}", u32::from(c)))
                        }
                        c => out.push(c),
                    }
                }
                out.push('"');
            }
            J::Arr(items) if items.is_empty() => out.push_str("[]"),
            J::Arr(items) => {
                out.push_str("[\n");
                for (i, item) in items.iter().enumerate() {
                    pad(out, indent + 1);
                    item.write(out, indent + 1);
                    out.push_str(if i + 1 < items.len() { ",\n" } else { "\n" });
                }
                pad(out, indent);
                out.push(']');
            }
            J::Obj(fields) if fields.is_empty() => out.push_str("{}"),
            J::Obj(fields) => {
                out.push_str("{\n");
                for (i, (key, value)) in fields.iter().enumerate() {
                    pad(out, indent + 1);
                    J::Str(key.clone()).write(out, indent + 1);
                    out.push_str(": ");
                    value.write(out, indent + 1);
                    out.push_str(if i + 1 < fields.len() { ",\n" } else { "\n" });
                }
                pad(out, indent);
                out.push('}');
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Cases
// ---------------------------------------------------------------------------

/// The crate's error kinds, by the names the fixture uses.
fn error_name(err: &Error) -> &'static str {
    match err {
        Error::Decode(_) => "decode",
        Error::Encode(_) => "encode",
        Error::InvalidKey => "invalid_key",
        Error::BadSignature => "bad_signature",
        Error::BadVrfProof => "bad_vrf_proof",
        Error::MalformedProof(_) => "malformed_proof",
        Error::ProofMismatch(_) => "proof_mismatch",
        Error::InvalidArgument(_) => "invalid_argument",
        _ => "other",
    }
}

/// A crate result, or the generator's failure naming what it was computing.
fn g<T>(result: peachy_keytrans::Result<T>, what: &str) -> Gen<T> {
    result.map_err(|err| format!("{what}: {err}"))
}

#[derive(Default)]
struct Cases {
    list: Vec<J>,
    ids: BTreeSet<String>,
}

impl Cases {
    fn push(&mut self, id: &str, call: &str, why: &str, input: J, outcome: (&str, J)) -> Gen<()> {
        if !self.ids.insert(id.to_string()) {
            return Err(format!("two cases share the id {id}"));
        }
        self.list.push(obj! {
            "id" => s(id),
            "kind" => s("keytrans"),
            "call" => s(call),
            "why" => s(why),
            "input" => input,
            outcome.0 => outcome.1,
        });
        Ok(())
    }

    /// A case the crate answers with `expect`.
    fn ok(&mut self, id: &str, call: &str, why: &str, input: J, expect: J) -> Gen<()> {
        self.push(id, call, why, input, ("expect", expect))
    }

    /// A case the crate must refuse; `outcome` is the crate's own answer.
    fn refuse<T>(
        &mut self,
        id: &str,
        call: &str,
        why: &str,
        input: J,
        outcome: peachy_keytrans::Result<T>,
    ) -> Gen<()> {
        match outcome {
            Ok(_) => Err(format!("{id}: the crate accepted what the fixture refuses")),
            Err(err) => self.push(id, call, why, input, ("expectError", s(error_name(&err)))),
        }
    }
}

// ---------------------------------------------------------------------------
// A reference prefix tree (draft §3.3), used only to make the log's prefix
// roots and proofs
// ---------------------------------------------------------------------------

#[derive(Clone)]
enum Tree {
    Empty,
    Leaf(PrefixLeaf),
    Parent(Box<Tree>, Box<Tree>),
}

impl Tree {
    fn insert(self, leaf: PrefixLeaf, depth: usize) -> Tree {
        match self {
            Tree::Empty => Tree::Leaf(leaf),
            Tree::Leaf(other) if other.vrf_output == leaf.vrf_output => Tree::Leaf(leaf),
            Tree::Leaf(other) => Tree::Parent(Box::new(Tree::Empty), Box::new(Tree::Empty))
                .insert(other, depth)
                .insert(leaf, depth),
            Tree::Parent(l, r) => {
                if bit(&leaf.vrf_output, depth) {
                    Tree::Parent(l, Box::new(r.insert(leaf, depth + 1)))
                } else {
                    Tree::Parent(Box::new(l.insert(leaf, depth + 1)), r)
                }
            }
        }
    }

    fn hash(&self) -> Hash {
        match self {
            Tree::Empty => EMPTY,
            Tree::Leaf(leaf) => prefix_leaf_hash(leaf),
            Tree::Parent(l, r) => prefix_parent_hash(&l.hash(), &r.hash()),
        }
    }

    fn search(&self, key: &VrfOutput) -> PrefixSearchResult {
        let mut node = self;
        let mut depth = 0u8;
        loop {
            let outcome = match node {
                Tree::Empty => PrefixSearchOutcome::NonInclusionParent,
                Tree::Leaf(leaf) if leaf.vrf_output == *key => PrefixSearchOutcome::Inclusion,
                Tree::Leaf(leaf) => PrefixSearchOutcome::NonInclusionLeaf { leaf: *leaf },
                Tree::Parent(l, r) => {
                    node = if bit(key, usize::from(depth)) { r } else { l };
                    depth += 1;
                    continue;
                }
            };
            return PrefixSearchResult { outcome, depth };
        }
    }

    fn prove(&self, keys: &[VrfOutput]) -> PrefixProof {
        let results = keys.iter().map(|k| self.search(k)).collect();
        let mut elements = Vec::new();
        self.copath(keys, 0, &mut elements);
        PrefixProof { results, elements }
    }

    fn copath(&self, keys: &[VrfOutput], depth: usize, out: &mut Vec<Hash>) {
        if keys.is_empty() {
            out.push(self.hash());
            return;
        }
        if let Tree::Parent(l, r) = self {
            let (right, left): (Vec<VrfOutput>, Vec<VrfOutput>) =
                keys.iter().partition(|k| bit(k, depth));
            l.copath(&left, depth + 1, out);
            r.copath(&right, depth + 1, out);
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers for the profile's structures
// ---------------------------------------------------------------------------

fn public(seed: &[u8; 32]) -> [u8; 32] {
    SecretKey::from_seed(seed).public_key().to_bytes()
}

/// A device entry whose certificate `account` really signed.
fn device(id: &str, seed: &[u8; 32], account: &SecretKey) -> Gen<DeviceEntry> {
    let device_key = public(seed);
    let mut message = ACCOUNT_DEVICE_DOMAIN.to_vec();
    message.push(0x00);
    message.extend_from_slice(&device_key);
    let account_sig = account.sign(&message);
    g(
        account.public_key().verify(&message, &account_sig),
        "account certificate",
    )?;
    Ok(DeviceEntry {
        device_id: id.as_bytes().to_vec(),
        device_key,
        account_sig,
    })
}

fn device_json(entry: &DeviceEntry) -> J {
    obj! {
        "deviceId" => J::Str(String::from_utf8_lossy(&entry.device_id).into_owned()),
        "deviceKey" => h(&entry.device_key),
        "accountSig" => h(&entry.account_sig),
    }
}

fn inclusion_json(inclusion: &DeviceInclusion) -> J {
    obj! {
        "index" => n(inclusion.index),
        "size" => n(inclusion.size),
        "path" => hashes(&inclusion.path),
    }
}

fn label_input(label: &Label) -> J {
    match label {
        Label::Account { actor_id } => obj! { "type" => s("account"), "actorId" => h(actor_id) },
        Label::Handle { handle } => obj! { "type" => s("handle"), "handle" => s(handle) },
        Label::Phone { lookup } => obj! { "type" => s("phone"), "lookup" => h(lookup) },
        Label::AuditorInstance { instance_key } => {
            obj! { "type" => s("auditor_instance"), "instanceKey" => h(instance_key) }
        }
    }
}

fn account_value_input(value: &AccountValue) -> J {
    match value {
        AccountValue::Live {
            account_identity_key,
            device_set_root,
        } => obj! {
            "type" => s("live"),
            "accountIdentityKey" => h(account_identity_key),
            "deviceSetRoot" => h(device_set_root),
        },
        AccountValue::Closed => obj! { "type" => s("closed") },
    }
}

fn mapping_value_input(value: &MappingValue) -> J {
    match &value.actor_id {
        Some(id) => obj! { "actorId" => h(id) },
        None => obj! { "actorId" => J::Null },
    }
}

fn auditor_instance_input(value: &AuditorInstance) -> J {
    obj! {
        "bootTime" => n(value.boot_time),
        "startPosition" => n(value.start_position),
        "predecessorKey" => value.predecessor_key.as_ref().map_or(J::Null, |k| h(k)),
        "handoffSig" => value.handoff_sig.as_ref().map_or(J::Null, |k| h(k)),
    }
}

fn result_json(result: &PrefixSearchResult) -> J {
    match result.outcome {
        PrefixSearchOutcome::Inclusion => {
            obj! { "type" => s("inclusion"), "depth" => n(u64::from(result.depth)) }
        }
        PrefixSearchOutcome::NonInclusionLeaf { leaf } => obj! {
            "type" => s("nonInclusionLeaf"),
            "depth" => n(u64::from(result.depth)),
            "leaf" => obj! { "vrfOutput" => h(&leaf.vrf_output), "commitment" => h(&leaf.commitment) },
        },
        PrefixSearchOutcome::NonInclusionParent => {
            obj! { "type" => s("nonInclusionParent"), "depth" => n(u64::from(result.depth)) }
        }
    }
}

fn searches_json(searches: &[PrefixSearch]) -> J {
    J::Arr(
        searches
            .iter()
            .map(|q| {
                obj! {
                    "vrfOutput" => h(&q.vrf_output),
                    "commitment" => q.commitment.as_ref().map_or(J::Null, |c| h(c)),
                }
            })
            .collect(),
    )
}

/// The opening the log "drew" for a label's version: deterministic here, so
/// the fixture regenerates byte for byte. A real log draws 16 random bytes.
fn opening(label: &[u8], version: u32) -> [u8; OPENING_LEN] {
    let digest = hash(&[
        b"peachy-kt-fixture-opening",
        &[0x00],
        label,
        &version.to_be_bytes(),
    ]);
    let mut out = [0u8; OPENING_LEN];
    out.copy_from_slice(&digest[..OPENING_LEN]);
    out
}

// ---------------------------------------------------------------------------
// The fixture
// ---------------------------------------------------------------------------

struct Deployment {
    log_key: SecretKey,
    vrf: VrfSecretKey,
    auditor_keys: Vec<SecretKey>,
    profile: Profile,
    configs: Vec<Configuration>,
}

fn deployment() -> Gen<Deployment> {
    let log_key = SecretKey::from_seed(&LOG_SEED);
    let vrf = g(VrfSecretKey::from_seed(&VRF_SEED), "VRF key")?;
    let auditor_keys: Vec<SecretKey> = AUDITOR_SEEDS
        .iter()
        .map(|(seed, _)| SecretKey::from_seed(seed))
        .collect();
    let auditors = AUDITOR_SEEDS
        .iter()
        .map(|(seed, start_pos)| Auditor {
            public_key: public(seed),
            start_pos: *start_pos,
        })
        .collect();
    let profile = g(
        Profile::new(
            log_key.public_key().to_bytes(),
            vrf.public_key().to_bytes(),
            auditors,
        ),
        "profile",
    )?;
    let configs = profile.configurations();
    Ok(Deployment {
        log_key,
        vrf,
        auditor_keys,
        profile,
        configs,
    })
}

fn configuration_cases(cases: &mut Cases, d: &Deployment) -> Gen<()> {
    for (i, (config, auditor)) in d.configs.iter().zip(d.profile.auditors()).enumerate() {
        g(check_configuration(config), "profile configuration")?;
        let bytes = g(encode(config), "configuration")?;
        cases.ok(
            &format!("configuration/auditor-{i}"),
            "configuration",
            "The draft's Configuration with the profile's parameters, one per auditor: what every tree head signature and auditor head signature covers",
            obj! {
                "signaturePublicKey" => h(d.profile.signature_public_key()),
                "vrfPublicKey" => h(d.profile.vrf_public_key()),
                "auditorPublicKey" => h(&auditor.public_key),
                "auditorStartPos" => n(auditor.start_pos),
            },
            obj! { "bytes" => h(&bytes) },
        )?;
    }
    let good = &d.configs[0];
    let good_bytes = g(encode(good), "configuration")?;
    cases.ok(
        "configuration-check/the-profile",
        "configuration_check",
        "A configuration carrying exactly the profile's parameters",
        obj! { "bytes" => h(&good_bytes) },
        obj! { "accepted" => J::Bool(true) },
    )?;
    let mut off: Vec<(&str, &str, Configuration)> = Vec::new();
    let mut c = good.clone();
    c.reasonable_monitoring_window = 14 * DAY_MS;
    off.push((
        "fourteen-day-window",
        "A fourteen-day monitoring window is the draft's example, not the profile's day",
        c,
    ));
    let mut c = good.clone();
    c.maximum_lifetime = Some(365 * DAY_MS);
    off.push((
        "a-lifetime",
        "The profile keeps every entry: a maximum lifetime is a new configuration version",
        c,
    ));
    let mut c = good.clone();
    c.max_ahead = 2 * DAY_MS;
    off.push((
        "wider-clock",
        "A head 48 hours ahead is outside the profile's clock window",
        c,
    ));
    let mut c = good.clone();
    c.mode = ModeConfig::ThirdPartyAuditing {
        max_auditor_lag: 30 * DAY_MS,
        auditor_start_pos: 0,
        auditor_public_key: d.profile.auditors()[0].public_key.to_vec(),
    };
    off.push((
        "lazy-auditor",
        "An auditor allowed thirty days of lag would let a split view last a month",
        c,
    ));
    let mut c = good.clone();
    c.mode = ModeConfig::ContactMonitoring {
        leaf_public_key: d.profile.auditors()[0].public_key.to_vec(),
    };
    off.push((
        "contact-monitoring",
        "The profile runs in third-party auditing mode only",
        c,
    ));
    for (name, why, config) in off {
        let bytes = g(encode(&config), "configuration")?;
        cases.refuse(
            &format!("configuration-check/{name}"),
            "configuration_check",
            why,
            obj! { "bytes" => h(&bytes) },
            check_configuration(&config),
        )?;
    }
    Ok(())
}

fn label_cases(cases: &mut Cases) -> Gen<()> {
    let good: Vec<(&str, &str, Label)> = vec![
        (
            "account",
            "0x61 followed by the actor id's 16 raw bytes",
            Label::account(ADA_ACTOR),
        ),
        (
            "handle",
            "0x68 followed by the handle as stored: lowercase UTF-8, no @",
            g(Label::handle("ada"), "label")?,
        ),
        (
            "handle-non-ascii",
            "A lowercase non-ASCII handle is carried as its UTF-8 bytes",
            g(Label::handle("zoë"), "label")?,
        ),
        (
            "handle-longest",
            "254 bytes is the longest handle: the label is opaque<0..255> and the kind takes one",
            g(Label::handle(&"a".repeat(254)), "label")?,
        ),
        (
            "phone",
            "0x70 followed by the 32-byte blind index of the number, never the number",
            Label::phone(phone_lookup()),
        ),
        (
            "auditor-instance",
            "0x6b followed by an auditor instance's Ed25519 key",
            Label::auditor_instance(public(&AUDITOR_SEEDS[0].0)),
        ),
    ];
    for (name, why, label) in good {
        let bytes = g(label.to_bytes(), "label")?;
        if g(Label::from_bytes(&bytes), "label")? != label {
            return Err(format!("label {name} does not round-trip"));
        }
        let kind = g(label_kind(&bytes), "label kind")?;
        cases.ok(
            &format!("label/{name}"),
            "label",
            why,
            label_input(&label),
            obj! { "bytes" => h(&bytes), "kind" => J::Str(char::from(kind).to_string()) },
        )?;
    }
    cases.refuse(
        "label/handle-uppercase",
        "label",
        "A handle label is built from the stored, lowercase handle; an uppercase one is a caller's bug",
        obj! { "type" => s("handle"), "handle" => s("Ada") },
        Label::handle("Ada"),
    )?;
    cases.refuse(
        "label/handle-too-long",
        "label",
        "255 bytes of handle plus the kind byte would not fit opaque label<0..255>",
        obj! { "type" => s("handle"), "handle" => J::Str("a".repeat(255)) },
        Label::handle(&"a".repeat(255)),
    )?;
    let bad: Vec<(&str, &str, Vec<u8>)> = vec![
        ("empty", "No kind byte", vec![]),
        (
            "unknown-kind",
            "A kind the profile does not define",
            b"zebra".to_vec(),
        ),
        (
            "account-short",
            "An actor id is exactly 16 bytes",
            [&[0x61][..], &[0x01; 15]].concat(),
        ),
        (
            "account-long",
            "An actor id is exactly 16 bytes",
            [&[0x61][..], &[0x01; 17]].concat(),
        ),
        (
            "phone-short",
            "A blind index is exactly 32 bytes",
            [&[0x70][..], &[0x11; 31]].concat(),
        ),
        (
            "auditor-instance-long",
            "An instance key is exactly 32 bytes",
            [&[0x6b][..], &[0x22; 33]].concat(),
        ),
        ("handle-empty", "A handle has at least one byte", vec![0x68]),
        ("handle-not-utf8", "A handle is UTF-8", vec![0x68, 0xff]),
        (
            "handle-uppercase",
            "A logged handle is lowercase",
            b"hAda".to_vec(),
        ),
    ];
    for (name, why, bytes) in bad {
        cases.refuse(
            &format!("label-decode/{name}"),
            "label_decode",
            why,
            obj! { "bytes" => h(&bytes) },
            Label::from_bytes(&bytes),
        )?;
    }
    Ok(())
}

fn phone_lookup() -> [u8; 32] {
    // A stand-in for the keyed blind index of an E.164 number: the real one
    // is an HMAC under a key only the contact-matching service holds.
    hash(&[b"peachy-kt-fixture-phone-lookup"])
}

fn value_cases(cases: &mut Cases) -> Gen<()> {
    let ada = SecretKey::from_seed(&ADA_ACCOUNT_SEED);
    let set = g(
        DeviceSet::new(vec![device("ada-phone", &[0xa1; 32], &ada)?]),
        "device set",
    )?;
    let live = AccountValue::Live {
        account_identity_key: ada.public_key().to_bytes(),
        device_set_root: set.root(),
    };
    for (name, why, value) in [
        (
            "live",
            "kind 1, the account identity key, the device set's root",
            live,
        ),
        (
            "closed",
            "kind 0 and nothing else: the account was deleted",
            AccountValue::Closed,
        ),
    ] {
        let bytes = value.to_bytes();
        if g(AccountValue::from_bytes(&bytes), "account value")? != value {
            return Err(format!("account value {name} does not round-trip"));
        }
        cases.ok(
            &format!("account-value/{name}"),
            "account_value",
            why,
            account_value_input(&value),
            obj! { "bytes" => h(&bytes) },
        )?;
    }
    let live_bytes = live.to_bytes();
    let bad: Vec<(&str, &str, Vec<u8>)> = vec![
        ("empty", "No kind", vec![]),
        ("unknown-kind", "Kind 2 is not defined", vec![2]),
        (
            "closed-with-data",
            "A closed value carries nothing after its kind",
            vec![0, 0],
        ),
        (
            "live-truncated",
            "A live value is exactly 65 bytes",
            live_bytes[..64].to_vec(),
        ),
        (
            "live-trailing",
            "Trailing bytes are refused",
            [&live_bytes[..], &[0]].concat(),
        ),
    ];
    for (name, why, bytes) in bad {
        cases.refuse(
            &format!("account-value-decode/{name}"),
            "account_value_decode",
            why,
            obj! { "bytes" => h(&bytes) },
            AccountValue::from_bytes(&bytes),
        )?;
    }

    for (name, why, value) in [
        (
            "held",
            "opaque actor_id<0..16> holding the 16-byte actor id",
            MappingValue {
                actor_id: Some(ADA_ACTOR),
            },
        ),
        (
            "released",
            "An empty actor id: the address was released",
            MappingValue { actor_id: None },
        ),
    ] {
        let bytes = value.to_bytes();
        if g(MappingValue::from_bytes(&bytes), "mapping value")? != value {
            return Err(format!("mapping value {name} does not round-trip"));
        }
        cases.ok(
            &format!("mapping-value/{name}"),
            "mapping_value",
            why,
            mapping_value_input(&value),
            obj! { "bytes" => h(&bytes) },
        )?;
    }
    let bad: Vec<(&str, &str, Vec<u8>)> = vec![
        ("empty", "No length", vec![]),
        ("one-byte-id", "An actor id is 0 or 16 bytes", vec![1, 7]),
        (
            "seventeen-bytes",
            "Longer than the vector allows",
            [&[17][..], &[0x01; 17]].concat(),
        ),
        ("trailing", "Trailing bytes are refused", vec![0, 0]),
    ];
    for (name, why, bytes) in bad {
        cases.refuse(
            &format!("mapping-value-decode/{name}"),
            "mapping_value_decode",
            why,
            obj! { "bytes" => h(&bytes) },
            MappingValue::from_bytes(&bytes),
        )?;
    }

    let predecessor = SecretKey::from_seed(&AUDITOR_SEEDS[0].0);
    let successor = public(&[0x32; 32]);
    let mut handoff_message = b"peachy-kt-fixture-handoff".to_vec();
    handoff_message.extend_from_slice(&successor);
    let first = AuditorInstance {
        boot_time: T0 - HOUR_MS,
        start_position: 0,
        predecessor_key: None,
        handoff_sig: None,
    };
    let handoff = AuditorInstance {
        boot_time: T0 + 3 * DAY_MS,
        start_position: 7,
        predecessor_key: Some(predecessor.public_key().to_bytes()),
        handoff_sig: Some(predecessor.sign(&handoff_message)),
    };
    let cold = AuditorInstance {
        handoff_sig: None,
        ..handoff
    };
    for (name, why, value) in [
        (
            "first",
            "The first instance: no predecessor, no handoff",
            first,
        ),
        (
            "handoff",
            "A relaunch the predecessor signed over (the signature's bytes are opaque here)",
            handoff,
        ),
        (
            "cold-start",
            "A predecessor but no handoff signature: a cold start, shown publicly as one",
            cold,
        ),
    ] {
        let bytes = g(value.to_bytes(), "auditor instance")?;
        if g(AuditorInstance::from_bytes(&bytes), "auditor instance")? != value {
            return Err(format!("auditor instance {name} does not round-trip"));
        }
        cases.ok(
            &format!("auditor-instance/{name}"),
            "auditor_instance",
            why,
            auditor_instance_input(&value),
            obj! { "bytes" => h(&bytes) },
        )?;
    }
    let orphan = AuditorInstance {
        predecessor_key: None,
        ..handoff
    };
    cases.refuse(
        "auditor-instance/orphan-signature",
        "auditor_instance",
        "A handoff signature needs the predecessor key it was made with",
        auditor_instance_input(&orphan),
        orphan.to_bytes(),
    )?;
    let first_bytes = g(first.to_bytes(), "auditor instance")?;
    let mut orphan_bytes = first_bytes[..17].to_vec();
    orphan_bytes.push(64);
    orphan_bytes.extend([0x44; 64]);
    let mut short_key = first_bytes[..16].to_vec();
    short_key.push(31);
    short_key.extend([0x33; 31]);
    short_key.push(0);
    let mut short_sig = first_bytes[..16].to_vec();
    short_sig.push(32);
    short_sig.extend([0x33; 32]);
    short_sig.push(63);
    short_sig.extend([0x44; 63]);
    for (name, why, bytes) in [
        (
            "orphan-signature",
            "A signature with no predecessor key",
            orphan_bytes,
        ),
        ("short-key", "A predecessor key is 0 or 32 bytes", short_key),
        (
            "short-signature",
            "A handoff signature is 0 or 64 bytes",
            short_sig,
        ),
        (
            "trailing",
            "Trailing bytes are refused",
            [&first_bytes[..], &[0]].concat(),
        ),
    ] {
        cases.refuse(
            &format!("auditor-instance-decode/{name}"),
            "auditor_instance_decode",
            why,
            obj! { "bytes" => h(&bytes) },
            AuditorInstance::from_bytes(&bytes),
        )?;
    }
    Ok(())
}

/// A device set case: name, why, the account that certified the devices,
/// the devices in the order given, the indexes to prove.
type SetCase<'a> = (String, &'a str, &'a SecretKey, Vec<DeviceEntry>, Vec<usize>);

fn device_set_cases(cases: &mut Cases) -> Gen<()> {
    let ada = SecretKey::from_seed(&ADA_ACCOUNT_SEED);
    let many = SecretKey::from_seed(&MANY_ACCOUNT_SEED);
    let mut sets: Vec<SetCase> = Vec::new();
    sets.push((
        "empty".into(),
        "The empty set's root is a fixed hash, not zeros",
        &ada,
        vec![],
        vec![],
    ));
    let phone = device("ada-phone", &[0xa1; 32], &ada)?;
    let laptop = device("ada-laptop", &[0xa2; 32], &ada)?;
    let tablet = device("ada-tablet", &[0xa3; 32], &ada)?;
    sets.push((
        "one".into(),
        "One device: the root is its leaf",
        &ada,
        vec![phone.clone()],
        vec![0],
    ));
    sets.push((
        "two".into(),
        "Two devices, given out of key order: entries are sorted by device key",
        &ada,
        vec![laptop.clone(), phone.clone()],
        vec![0, 1],
    ));
    sets.push((
        "three".into(),
        "Three devices: the left subtree holds the largest power of two below the count",
        &ada,
        vec![phone.clone(), laptop.clone(), tablet.clone()],
        vec![0, 1, 2],
    ));
    let mut sixty_four = Vec::new();
    for i in 0..64u8 {
        let mut seed = [0x5d; 32];
        seed[0] = i;
        sixty_four.push(device(&format!("device-{i:02}"), &seed, &many)?);
    }
    sets.push((
        "sixty-four".into(),
        "Sixty-four devices, a full tree six levels deep",
        &many,
        sixty_four,
        vec![0, 1, 31, 32, 62, 63],
    ));
    for (name, why, account, entries, indexes) in sets {
        let set = g(DeviceSet::new(entries.clone()), "device set")?;
        let root = set.root();
        if entries.is_empty() && root != empty_root() {
            return Err("the empty set's root".into());
        }
        let mut inclusions = Vec::new();
        for &i in &indexes {
            let inclusion = g(set.inclusion(i), "device inclusion")?;
            g(
                inclusion.verify(&set.entries()[i], &root),
                "device inclusion",
            )?;
            inclusions.push(inclusion_json(&inclusion));
        }
        cases.ok(
            &format!("device-set/{name}"),
            "device_set",
            why,
            obj! {
                "accountIdentityKey" => h(&account.public_key().to_bytes()),
                "devices" => J::Arr(entries.iter().map(device_json).collect()),
                "inclusionIndexes" => J::Arr(indexes.iter().map(|&i| n(i as u64)).collect()),
            },
            obj! {
                "root" => h(&root),
                "sortedDeviceKeys" => J::Arr(set.entries().iter().map(|e| h(&e.device_key)).collect()),
                "leafHashes" => J::Arr(set.entries().iter().map(|e| e.leaf_hash().map(|v| h(&v))).collect::<peachy_keytrans::Result<Vec<_>>>().map_err(|e| e.to_string())?),
                "inclusions" => J::Arr(inclusions),
            },
        )?;
    }

    let twin = DeviceEntry {
        device_id: b"ada-twin".to_vec(),
        ..phone.clone()
    };
    cases.refuse(
        "device-set/one-key-twice",
        "device_set",
        "Two entries with one device key",
        obj! { "accountIdentityKey" => h(&ada.public_key().to_bytes()), "devices" => J::Arr(vec![device_json(&phone), device_json(&twin)]), "inclusionIndexes" => J::Arr(vec![]) },
        DeviceSet::new(vec![phone.clone(), twin]),
    )?;
    let namesake = device("ada-phone", &[0xa4; 32], &ada)?;
    cases.refuse(
        "device-set/one-id-twice",
        "device_set",
        "Two entries with one device id",
        obj! { "accountIdentityKey" => h(&ada.public_key().to_bytes()), "devices" => J::Arr(vec![device_json(&phone), device_json(&namesake)]), "inclusionIndexes" => J::Arr(vec![]) },
        DeviceSet::new(vec![phone.clone(), namesake]),
    )?;
    let long_id = device(&"d".repeat(65), &[0xa5; 32], &ada)?;
    cases.refuse(
        "device-set/id-too-long",
        "device_set",
        "A device id is 1 to 64 ASCII bytes",
        obj! { "accountIdentityKey" => h(&ada.public_key().to_bytes()), "devices" => J::Arr(vec![device_json(&long_id)]), "inclusionIndexes" => J::Arr(vec![]) },
        DeviceSet::new(vec![long_id]),
    )?;

    let set = g(
        DeviceSet::new(vec![phone.clone(), laptop.clone(), tablet.clone()]),
        "device set",
    )?;
    let root = set.root();
    let at = |i: usize| -> Gen<(DeviceEntry, DeviceInclusion)> {
        Ok((
            set.entries()[i].clone(),
            g(set.inclusion(i), "device inclusion")?,
        ))
    };
    let (entry, good) = at(2)?;
    cases.ok(
        "device-inclusion/three-last",
        "device_inclusion",
        "The last of three devices proves its membership with one sibling, the left pair's node",
        obj! { "entry" => device_json(&entry), "inclusion" => inclusion_json(&good), "root" => h(&root) },
        obj! { "verified" => J::Bool(true) },
    )?;
    let (other, _) = at(0)?;
    let mut negatives: Vec<(&str, &str, DeviceEntry, DeviceInclusion, Hash)> = vec![
        (
            "another-device",
            "A path proves its own entry, not a sibling's",
            other,
            good.clone(),
            root,
        ),
        (
            "another-root",
            "The empty set's root is not this set's",
            entry.clone(),
            good.clone(),
            empty_root(),
        ),
    ];
    let mut outside = good.clone();
    outside.index = 3;
    negatives.push((
        "index-outside",
        "An index at or beyond the size",
        entry.clone(),
        outside,
        root,
    ));
    let mut long = good.clone();
    long.path.push([0; 32]);
    negatives.push((
        "path-too-long",
        "A sibling more than the tree has",
        entry.clone(),
        long,
        root,
    ));
    let mut short = good.clone();
    short.path.clear();
    negatives.push((
        "path-too-short",
        "A sibling fewer than the tree has",
        entry.clone(),
        short,
        root,
    ));
    let mut moved = good.clone();
    moved.index = 1;
    negatives.push((
        "wrong-index",
        "The same siblings at another position compute another root",
        entry,
        moved,
        root,
    ));
    for (name, why, entry, inclusion, root) in negatives {
        cases.refuse(
            &format!("device-inclusion/{name}"),
            "device_inclusion",
            why,
            obj! { "entry" => device_json(&entry), "inclusion" => inclusion_json(&inclusion), "root" => h(&root) },
            inclusion.verify(&entry, &root),
        )?;
    }
    Ok(())
}

fn commitment_cases(cases: &mut Cases) -> Gen<()> {
    let value = UpdateValue { value: vec![0xcc] };
    let c = g(commit(&[0x0f; 16], b"ab", 1, &value), "commitment")?;
    cases.ok(
        "commitment/independent",
        "commitment",
        "HMAC-SHA256 under Kc = d821f8790d97709796b4d7903357c3f5 over opening || label<1> || version<4> || value<4>, checked against openssl",
        obj! {
            "opening" => h(&[0x0f; 16]),
            "label" => h(b"ab"),
            "version" => n(1),
            "value" => h(&value.value),
        },
        obj! { "commitment" => h(&c) },
    )
}

/// One update in the log: a label's next version and its value.
struct Update {
    label: Label,
    value: Vec<u8>,
}

/// One version of a label as the log holds it.
#[derive(Clone)]
struct Logged {
    label: Vec<u8>,
    version: u32,
    leaf: PrefixLeaf,
}

struct History {
    timestamps: Vec<u64>,
    prefix_roots: Vec<Hash>,
    trees: Vec<Tree>,
    logged: Vec<Logged>,
    log: MemoryLog,
}

/// The log's history: who changed what, entry by entry.
fn history_updates() -> Gen<Vec<(u64, Vec<Update>)>> {
    let ada = SecretKey::from_seed(&ADA_ACCOUNT_SEED);
    let grace = SecretKey::from_seed(&GRACE_ACCOUNT_SEED);
    let phone = device("ada-phone", &[0xa1; 32], &ada)?;
    let laptop = device("ada-laptop", &[0xa2; 32], &ada)?;
    let grace_phone = device("grace-phone", &[0xb1; 32], &grace)?;
    let account = |key: &SecretKey, devices: Vec<DeviceEntry>| -> Gen<Vec<u8>> {
        let set = g(DeviceSet::new(devices), "device set")?;
        Ok(AccountValue::Live {
            account_identity_key: key.public_key().to_bytes(),
            device_set_root: set.root(),
        }
        .to_bytes())
    };
    let held = |actor: [u8; 16]| {
        MappingValue {
            actor_id: Some(actor),
        }
        .to_bytes()
    };
    let released = MappingValue { actor_id: None }.to_bytes();
    let attested = AuditorInstance {
        boot_time: T0 - HOUR_MS,
        start_position: 0,
        predecessor_key: None,
        handoff_sig: None,
    };
    let up = |label: Label, value: Vec<u8>| Update { label, value };
    Ok(vec![
        (
            T0,
            vec![
                up(
                    Label::account(ADA_ACTOR),
                    account(&ada, vec![phone.clone()])?,
                ),
                up(g(Label::handle("ada"), "label")?, held(ADA_ACTOR)),
            ],
        ),
        (
            T0 + 6 * HOUR_MS,
            vec![
                up(
                    Label::account(GRACE_ACTOR),
                    account(&grace, vec![grace_phone])?,
                ),
                up(g(Label::handle("grace"), "label")?, held(GRACE_ACTOR)),
            ],
        ),
        (
            T0 + 12 * HOUR_MS,
            vec![up(
                Label::auditor_instance(public(&AUDITOR_SEEDS[0].0)),
                g(attested.to_bytes(), "auditor instance")?,
            )],
        ),
        (
            T0 + DAY_MS,
            vec![up(
                Label::account(ADA_ACTOR),
                account(&ada, vec![phone, laptop.clone()])?,
            )],
        ),
        (
            T0 + DAY_MS + 6 * HOUR_MS,
            vec![up(Label::phone(phone_lookup()), held(GRACE_ACTOR))],
        ),
        (
            T0 + 2 * DAY_MS,
            vec![
                up(g(Label::handle("ada"), "label")?, released.clone()),
                up(g(Label::handle("lovelace"), "label")?, held(ADA_ACTOR)),
            ],
        ),
        (
            T0 + 2 * DAY_MS + HOUR_MS,
            vec![
                up(Label::account(GRACE_ACTOR), AccountValue::Closed.to_bytes()),
                up(g(Label::handle("grace"), "label")?, released.clone()),
                up(Label::phone(phone_lookup()), released),
            ],
        ),
        (
            T0 + 3 * DAY_MS,
            vec![up(Label::account(ADA_ACTOR), account(&ada, vec![laptop])?)],
        ),
        // An entry that changes nothing: the log still appends on its
        // cadence, and it may be distinguished.
        (T0 + 3 * DAY_MS + 12 * HOUR_MS, vec![]),
    ])
}

fn update_why(label: &Label, version: u32, value: &[u8]) -> String {
    let what = match label {
        Label::Account { .. } if value == [0] => "the account closed".to_string(),
        Label::Account { .. } => "the account's identity key and device set".to_string(),
        Label::Handle { handle } if value == [0] => format!("the handle {handle} released"),
        Label::Handle { handle } => format!("who holds the handle {handle}"),
        Label::Phone { .. } if value == [0] => "the phone number released".to_string(),
        Label::Phone { .. } => "who holds a phone number, by its blind index".to_string(),
        Label::AuditorInstance { .. } => "the attested auditor's first instance".to_string(),
    };
    format!("Version {version}: {what}. The VRF proof gives the prefix tree's search key; the opening gives the commitment")
}

fn log_cases(cases: &mut Cases, d: &Deployment) -> Gen<History> {
    let vrf_public = d.vrf.public_key();
    let mut versions: BTreeMap<Vec<u8>, u32> = BTreeMap::new();
    let mut tree = Tree::Empty;
    let mut history = History {
        timestamps: Vec::new(),
        prefix_roots: Vec::new(),
        trees: Vec::new(),
        logged: Vec::new(),
        log: MemoryLog::new(),
    };
    for (entry, (timestamp, updates)) in history_updates()?.into_iter().enumerate() {
        for (i, update) in updates.iter().enumerate() {
            let label = g(update.label.to_bytes(), "label")?;
            let version = *versions.get(&label).unwrap_or(&0);
            versions.insert(label.clone(), version + 1);
            let open = opening(&label, version);
            let value = UpdateValue {
                value: update.value.clone(),
            };
            let commitment = g(commit(&open, &label, version, &value), "commitment")?;
            let (proof, vrf_output) = g(d.vrf.prove_label(&label, version), "VRF")?;
            if g(vrf_public.verify_label(&label, version, &proof), "VRF")? != vrf_output {
                return Err("the VRF disagrees with itself".into());
            }
            let leaf = PrefixLeaf {
                vrf_output,
                commitment,
            };
            tree = tree.insert(leaf, 0);
            history.logged.push(Logged {
                label: label.clone(),
                version,
                leaf,
            });
            cases.ok(
                &format!("update/entry-{entry}-{i}"),
                "update",
                &update_why(&update.label, version, &update.value),
                obj! {
                    "vrfPublicKey" => h(&vrf_public.to_bytes()),
                    "label" => h(&label),
                    "version" => n(u64::from(version)),
                    "value" => h(&update.value),
                    "opening" => h(&open),
                    "vrfProof" => h(&proof),
                },
                obj! {
                    "vrfInput" => h(&g(vrf_input(&label, version), "VRF input")?),
                    "vrfOutput" => h(&vrf_output),
                    "commitment" => h(&commitment),
                },
            )?;
        }
        let root = tree.hash();
        let leaves: Vec<PrefixLeaf> = history.logged.iter().map(|l| l.leaf).collect();
        cases.ok(
            &format!("prefix-tree/entry-{entry}"),
            "prefix_tree",
            "The prefix tree's root over every label version logged so far: 0x02 leaves, 0x03 parents, a leaf at the shallowest depth no other key shares",
            obj! {
                "leaves" => J::Arr(leaves.iter().map(|l| obj! { "vrfOutput" => h(&l.vrf_output), "commitment" => h(&l.commitment) }).collect()),
            },
            obj! { "root" => h(&root) },
        )?;
        history.log.push(g(
            log_leaf_hash(&LogEntry {
                timestamp,
                prefix_tree: root,
            }),
            "log leaf",
        )?);
        history.timestamps.push(timestamp);
        history.prefix_roots.push(root);
        history.trees.push(tree.clone());
    }

    let size = history.log.len();
    let mut roots = Vec::new();
    for m in 1..=size {
        roots.push(g(history.log.root(m), "log root")?);
    }
    let leaf_hashes: Vec<Hash> = (0..size)
        .map(|i| g(history.log.leaf(i), "log leaf"))
        .collect::<Gen<_>>()?;
    let timestamps = history.timestamps.clone();
    let ts = |i: u64| -> peachy_keytrans::Result<u64> {
        usize::try_from(i)
            .ok()
            .and_then(|i| timestamps.get(i))
            .copied()
            .ok_or(Error::InvalidArgument("entry outside the log"))
    };
    let distinguished = g(
        distinguished_entries(size, REASONABLE_MONITORING_WINDOW_MS, ts),
        "distinguished entries",
    )?;
    let rightmost = g(
        rightmost_distinguished(size, REASONABLE_MONITORING_WINDOW_MS, ts),
        "rightmost distinguished",
    )?;
    if rightmost != distinguished.last().copied() {
        return Err("the rightmost distinguished entry is not the last one".into());
    }
    cases.ok(
        "log/history",
        "log",
        "Nine entries over three and a half days: each leaf is the hash of its LogEntry (timestamp, prefix root); roots at every size; the distinguished entries for a one-day window",
        obj! {
            "entries" => J::Arr(
                history
                    .timestamps
                    .iter()
                    .zip(&history.prefix_roots)
                    .map(|(t, r)| obj! { "timestamp" => n(*t), "prefixRoot" => h(r) })
                    .collect(),
            ),
            "reasonableMonitoringWindow" => n(REASONABLE_MONITORING_WINDOW_MS),
        },
        obj! {
            "leafHashes" => hashes(&leaf_hashes),
            "roots" => hashes(&roots),
            "distinguished" => nums(&distinguished),
            "rightmostDistinguished" => rightmost.map_or(J::Null, n),
        },
    )?;
    Ok(history)
}

fn prefix_proof_cases(cases: &mut Cases, d: &Deployment, history: &History) -> Gen<()> {
    let find = |label: &[u8], version: u32| -> Gen<PrefixSearch> {
        let logged = history
            .logged
            .iter()
            .find(|l| l.label == label && l.version == version)
            .ok_or_else(|| "no such logged version".to_string())?;
        Ok(PrefixSearch {
            vrf_output: logged.leaf.vrf_output,
            commitment: Some(logged.leaf.commitment),
        })
    };
    let absent = |label: &[u8], version: u32| -> Gen<PrefixSearch> {
        let (_, vrf_output) = g(d.vrf.prove_label(label, version), "VRF")?;
        Ok(PrefixSearch {
            vrf_output,
            commitment: None,
        })
    };
    let ada_account = g(Label::account(ADA_ACTOR).to_bytes(), "label")?;
    let ada_handle = g(g(Label::handle("ada"), "label")?.to_bytes(), "label")?;
    let nobody = g(g(Label::handle("nobody"), "label")?.to_bytes(), "label")?;
    let last = history.trees.len() - 1;
    let batches: Vec<(&str, &str, Tree, Vec<PrefixSearch>)> = vec![
        (
            "empty-tree",
            "A search in an empty tree ends at the missing root, depth 0; the root is 32 zero bytes",
            Tree::Empty,
            vec![absent(&ada_account, 0)?],
        ),
        (
            "entry-0-inclusion",
            "One inclusion in a two-leaf tree",
            history.trees[0].clone(),
            vec![find(&ada_account, 0)?],
        ),
        (
            "entry-8-batch",
            "A batch in the last entry's tree: two versions present, the next account version and an unknown handle absent",
            history.trees[last].clone(),
            vec![
                find(&ada_account, 2)?,
                absent(&ada_account, 3)?,
                find(&ada_handle, 1)?,
                absent(&nobody, 0)?,
            ],
        ),
    ];
    for (name, why, tree, searches) in batches {
        let keys: Vec<VrfOutput> = searches.iter().map(|q| q.vrf_output).collect();
        let proof = tree.prove(&keys);
        let root = g(evaluate(&searches, &proof), "prefix proof")?;
        if root != tree.hash() {
            return Err(format!("prefix proof {name} evaluates to another root"));
        }
        let bytes = g(encode(&proof), "prefix proof")?;
        if g(decode::<PrefixProof>(&bytes), "prefix proof")? != proof {
            return Err(format!("prefix proof {name} does not round-trip"));
        }
        cases.ok(
            &format!("prefix-proof/{name}"),
            "prefix_proof",
            why,
            obj! { "searches" => searches_json(&searches), "proof" => h(&bytes) },
            obj! {
                "root" => h(&root),
                "results" => J::Arr(proof.results.iter().map(result_json).collect()),
                "elementCount" => n(proof.elements.len() as u64),
            },
        )?;
        if name != "entry-8-batch" {
            continue;
        }
        let mut short = proof.clone();
        short.elements.pop();
        let mut long = proof.clone();
        long.elements.push([0x55; 32]);
        let mut blind = searches.clone();
        blind[0].commitment = None;
        for (bad, why, searches, proof) in [
            (
                "too-few-elements",
                "A copath value missing",
                searches.clone(),
                short,
            ),
            (
                "too-many-elements",
                "A copath value left over",
                searches.clone(),
                long,
            ),
            (
                "inclusion-without-commitment",
                "An inclusion result for a search that supplied no commitment",
                blind,
                proof.clone(),
            ),
        ] {
            let bytes = g(encode(&proof), "prefix proof")?;
            cases.refuse(
                &format!("prefix-proof/{name}-{bad}"),
                "prefix_proof",
                why,
                obj! { "searches" => searches_json(&searches), "proof" => h(&bytes) },
                evaluate(&searches, &proof),
            )?;
        }
    }
    Ok(())
}

fn log_proof_cases(cases: &mut Cases, history: &mut History) -> Gen<()> {
    let specs: Vec<(&str, &str, BatchSpec)> = vec![
        (
            "first-head",
            "A client with no head: the newest entry, the root, and the roots at both auditors' heads (sizes 9 and 7)",
            BatchSpec { tree_size: 9, leaves: vec![8], retained_size: None, extra_sizes: vec![9, 7] },
        ),
        (
            "refresh",
            "A client that verified size 5 and retains its full subtrees: consistency, two entries, both auditor roots",
            BatchSpec { tree_size: 9, leaves: vec![3, 8], retained_size: Some(5), extra_sizes: vec![9, 7] },
        ),
        (
            "several-entries",
            "Inclusion of three entries a search touched, no head retained",
            BatchSpec { tree_size: 9, leaves: vec![0, 2, 5], retained_size: None, extra_sizes: vec![] },
        ),
        (
            "consistency",
            "A balanced tree of 8 from a retained size of 3, with an auditor at 6",
            BatchSpec { tree_size: 8, leaves: vec![7], retained_size: Some(3), extra_sizes: vec![6] },
        ),
    ];
    let mut first = None;
    let mut refresh = None;
    for (name, why, spec) in specs {
        let proof = g(history.log.prove(&spec), "log proof")?;
        let leaf_values: Vec<(u64, Hash)> = spec
            .leaves
            .iter()
            .map(|&i| g(history.log.leaf(i), "log leaf").map(|v| (i, v)))
            .collect::<Gen<_>>()?;
        let retained = match spec.retained_size {
            Some(m) => g(history.log.full_subtree_values(m), "retained")?,
            None => Vec::new(),
        };
        let roots = g(
            verify_batch(&spec, &leaf_values, &retained, &proof),
            "log proof",
        )?;
        if roots.root != g(history.log.root(spec.tree_size), "log root")? {
            return Err(format!("log proof {name} reaches another root"));
        }
        for (&m, r) in spec.extra_sizes.iter().zip(&roots.extra_roots) {
            if *r != g(history.log.root(m), "log root")? {
                return Err(format!("log proof {name} reaches another extra root"));
            }
        }
        let input = |proof: &[Hash], retained: &[Hash]| {
            obj! {
                "treeSize" => n(spec.tree_size),
                "leaves" => nums(&spec.leaves),
                "retainedSize" => spec.retained_size.map_or(J::Null, n),
                "extraSizes" => nums(&spec.extra_sizes),
                "leafValues" => J::Arr(leaf_values.iter().map(|(i, v)| obj! { "index" => n(*i), "value" => h(v) }).collect()),
                "retained" => hashes(retained),
                "proof" => hashes(proof),
            }
        };
        cases.ok(
            &format!("log-proof/{name}"),
            "log_proof",
            why,
            input(&proof.elements, &retained),
            obj! {
                "root" => h(&roots.root),
                "extraRoots" => hashes(&roots.extra_roots),
                "fullSubtrees" => hashes(&roots.full_subtrees),
            },
        )?;
        if name == "first-head" {
            first = Some((spec.clone(), leaf_values.clone(), proof.elements.clone()));
        }
        if name == "refresh" {
            refresh = Some((
                spec.clone(),
                leaf_values.clone(),
                retained.clone(),
                proof.elements.clone(),
            ));
        }
        // The same proof in its wire encoding, once.
        if name == "refresh" {
            let bytes = g(encode(&proof), "inclusion proof")?;
            cases.ok(
                "log-proof/refresh-encoding",
                "inclusion_proof_decode",
                "The refresh proof as InclusionProof's bytes: a two-byte element count, then the hashes",
                obj! { "bytes" => h(&bytes) },
                obj! { "elements" => hashes(&proof.elements) },
            )?;
        }
    }
    let (spec, leaf_values, elements) = first.ok_or("no first-head proof")?;
    let mut short = elements.clone();
    short.pop();
    let proof = peachy_keytrans::wire::InclusionProof {
        elements: short.clone(),
    };
    cases.refuse(
        "log-proof/first-head-element-missing",
        "log_proof",
        "One subtree head fewer than the spec calls for",
        obj! {
            "treeSize" => n(spec.tree_size),
            "leaves" => nums(&spec.leaves),
            "retainedSize" => J::Null,
            "extraSizes" => nums(&spec.extra_sizes),
            "leafValues" => J::Arr(leaf_values.iter().map(|(i, v)| obj! { "index" => n(*i), "value" => h(v) }).collect()),
            "retained" => J::Arr(vec![]),
            "proof" => hashes(&short),
        },
        verify_batch(&spec, &leaf_values, &[], &proof),
    )?;
    let (spec, leaf_values, mut retained, elements) = refresh.ok_or("no refresh proof")?;
    // Retained values a forked log would have given this client.
    if let Some(first) = retained.first_mut() {
        first[0] ^= 1;
    }
    let proof = peachy_keytrans::wire::InclusionProof {
        elements: elements.clone(),
    };
    cases.refuse(
        "log-proof/refresh-forked-view",
        "log_proof",
        "The client's retained head disagrees with the tree the proof shows: a fork",
        obj! {
            "treeSize" => n(spec.tree_size),
            "leaves" => nums(&spec.leaves),
            "retainedSize" => spec.retained_size.map_or(J::Null, n),
            "extraSizes" => nums(&spec.extra_sizes),
            "leafValues" => J::Arr(leaf_values.iter().map(|(i, v)| obj! { "index" => n(*i), "value" => h(v) }).collect()),
            "retained" => hashes(&retained),
            "proof" => hashes(&elements),
        },
        verify_batch(&spec, &leaf_values, &retained, &proof),
    )?;
    Ok(())
}

fn head_cases(cases: &mut Cases, d: &Deployment, history: &mut History) -> Gen<()> {
    let size = history.log.len();
    let root = g(history.log.root(size), "log root")?;
    let head = g(
        sign_tree_head(&d.log_key, &d.configs, size, &root),
        "tree head",
    )?;
    let head_bytes = g(encode(&head), "tree head")?;
    if g(decode::<TreeHead>(&head_bytes), "tree head")? != head {
        return Err("the tree head does not round-trip".into());
    }
    for (i, config) in d.configs.iter().enumerate() {
        g(verify_tree_head(&head, config, &root), "tree head")?;
        let config_bytes = g(encode(config), "configuration")?;
        cases.ok(
            &format!("tree-head/auditor-{i}"),
            "tree_head",
            "The log signs one TreeHeadTBS per auditor's configuration; this is the signature naming that auditor",
            obj! { "configuration" => h(&config_bytes), "root" => h(&root), "head" => h(&head_bytes) },
            obj! { "tbs" => h(&g(tree_head_tbs(config, size, &root), "tree head TBS")?), "treeSize" => n(size) },
        )?;
    }
    let config0 = g(encode(&d.configs[0]), "configuration")?;
    let older_root = g(history.log.root(size - 1), "log root")?;
    cases.refuse(
        "tree-head/another-root",
        "tree_head",
        "The signature covers the root: the previous size's root does not verify",
        obj! { "configuration" => h(&config0), "root" => h(&older_root), "head" => h(&head_bytes) },
        verify_tree_head(&head, &d.configs[0], &older_root),
    )?;
    let mut resized = head.clone();
    resized.tree_size -= 1;
    cases.refuse(
        "tree-head/another-size",
        "tree_head",
        "The signature covers the tree size",
        obj! { "configuration" => h(&config0), "root" => h(&root), "head" => h(&g(encode(&resized), "tree head")?) },
        verify_tree_head(&resized, &d.configs[0], &root),
    )?;
    let stranger = d.profile.configuration(&Auditor {
        public_key: public(&STRANGER_AUDITOR_SEED),
        start_pos: 0,
    });
    cases.refuse(
        "tree-head/uncovered-auditor",
        "tree_head",
        "A head with no signature for an auditor the client carries is refused",
        obj! { "configuration" => h(&g(encode(&stranger), "configuration")?), "root" => h(&root), "head" => h(&head_bytes) },
        verify_tree_head(&head, &stranger, &root),
    )?;
    let mut swapped = head.clone();
    if swapped.signatures.len() == 2 {
        let first = swapped.signatures[0].signature.clone();
        swapped.signatures[0].signature = swapped.signatures[1].signature.clone();
        swapped.signatures[1].signature = first;
    }
    cases.refuse(
        "tree-head/signatures-swapped",
        "tree_head",
        "Each signature binds its own configuration: the other auditor's signature does not verify under this one's",
        obj! { "configuration" => h(&config0), "root" => h(&root), "head" => h(&g(encode(&swapped), "tree head")?) },
        verify_tree_head(&swapped, &d.configs[0], &root),
    )?;

    // Auditor heads: the attested auditor is current, the independent one
    // two entries behind. Each signs the timestamp of the rightmost entry
    // of the size it signs.
    let mut keyed = Vec::new();
    for (i, (key, config)) in d.auditor_keys.iter().zip(&d.configs).enumerate() {
        let at_size = size - 2 * i as u64;
        let at_root = g(history.log.root(at_size), "log root")?;
        let timestamp = history.timestamps[(at_size - 1) as usize];
        let ah = g(
            sign_auditor_tree_head(key, config, timestamp, at_size, &at_root),
            "auditor head",
        )?;
        g(
            verify_auditor_tree_head(&ah, config, &at_root),
            "auditor head",
        )?;
        let config_bytes = g(encode(config), "configuration")?;
        let ah_bytes = g(encode(&ah), "auditor head")?;
        cases.ok(
            &format!("auditor-tree-head/auditor-{i}"),
            "auditor_tree_head",
            "An auditor's signature over the configuration naming it, the rightmost entry's timestamp, the size and the root",
            obj! { "configuration" => h(&config_bytes), "root" => h(&at_root), "head" => h(&ah_bytes) },
            obj! {
                "tbs" => h(&g(auditor_tree_head_tbs(config, timestamp, at_size, &at_root), "auditor TBS")?),
                "timestamp" => n(timestamp),
                "treeSize" => n(at_size),
            },
        )?;
        if i == 0 {
            let mut later = ah.clone();
            later.timestamp += 1;
            cases.refuse(
                "auditor-tree-head/another-timestamp",
                "auditor_tree_head",
                "The signature covers the timestamp the lag bound is measured from",
                obj! { "configuration" => h(&config_bytes), "root" => h(&at_root), "head" => h(&g(encode(&later), "auditor head")?) },
                verify_auditor_tree_head(&later, config, &at_root),
            )?;
            let log_signed = g(
                sign_auditor_tree_head(key, config, timestamp, at_size, &at_root).map(|mut h| {
                    h.signature = d.log_key.sign(&h.signature).to_vec();
                    h
                }),
                "auditor head",
            )?;
            cases.refuse(
                "auditor-tree-head/not-the-auditors-key",
                "auditor_tree_head",
                "A signature by the log's key is not the auditor's",
                obj! { "configuration" => h(&config_bytes), "root" => h(&at_root), "head" => h(&g(encode(&log_signed), "auditor head")?) },
                verify_auditor_tree_head(&log_signed, config, &at_root),
            )?;
        }
        keyed.push(KeyedAuditorTreeHead {
            auditor_public_key: key.public_key().to_bytes().to_vec(),
            auditor_tree_head: ah,
        });
    }
    let full = FullTreeHead::Updated {
        tree_head: head.clone(),
        auditor_tree_heads: keyed.clone(),
    };
    let full_bytes = g(encode(&full), "full tree head")?;
    if g(decode::<FullTreeHead>(&full_bytes), "full tree head")? != full {
        return Err("the full tree head does not round-trip".into());
    }
    cases.ok(
        "full-tree-head/updated",
        "full_tree_head_decode",
        "head_type updated (2), the tree head with one signature per auditor, then one keyed auditor head per auditor",
        obj! { "bytes" => h(&full_bytes) },
        obj! {
            "headType" => s("updated"),
            "treeSize" => n(head.tree_size),
            "signatureAuditors" => J::Arr(head.signatures.iter().map(|sig| h(&sig.auditor_public_key)).collect()),
            "auditorHeads" => J::Arr(keyed.iter().map(|k| obj! {
                "auditorPublicKey" => h(&k.auditor_public_key),
                "timestamp" => n(k.auditor_tree_head.timestamp),
                "treeSize" => n(k.auditor_tree_head.tree_size),
            }).collect()),
        },
    )?;
    let same = g(encode(&FullTreeHead::Same), "full tree head")?;
    cases.ok(
        "full-tree-head/same",
        "full_tree_head_decode",
        "head_type same (1): the head the client advertised still stands, and nothing follows",
        obj! { "bytes" => h(&same) },
        obj! { "headType" => s("same") },
    )?;
    let mut trailing = full_bytes.clone();
    trailing.push(0);
    cases.refuse(
        "full-tree-head/trailing",
        "full_tree_head_decode",
        "Trailing bytes are refused",
        obj! { "bytes" => h(&trailing) },
        decode::<FullTreeHead>(&trailing),
    )?;
    let unknown = vec![3u8];
    cases.refuse(
        "full-tree-head/unknown-type",
        "full_tree_head_decode",
        "head_type 3 is not defined",
        obj! { "bytes" => h(&unknown) },
        decode::<FullTreeHead>(&unknown),
    )?;
    Ok(())
}

fn about() -> J {
    J::Arr(
        [
            "The golden fixture for key transparency: the Peachy profile of",
            "draft-ietf-keytrans-protocol-05 in mls/keytrans (crate peachy-keytrans).",
            "GENERATED by mls/keytrans/src/bin/gen_fixture.rs; do not edit by hand.",
            "Regenerate from mls/ with",
            "  cargo run -p peachy-keytrans --features prover --bin gen_fixture",
            "and the crate's tests fail until the committed file matches.",
            "",
            "Every case is a verifier's question: it carries what a client would receive",
            "(keys, VRF proofs, signatures, Merkle proofs) and expects what the client must",
            "compute, or the kind of error it must refuse with (`expectError`). No case needs",
            "a private key. Seeds in `keys` are recognizable test seeds, never real keys.",
            "",
            "Calls: configuration, configuration_check (the profile's parameters);",
            "label, label_decode, account_value(_decode), mapping_value(_decode),",
            "auditor_instance(_decode) (the profile's encodings); device_set and",
            "device_inclusion (the device-set Merkle root and paths); commitment and update",
            "(VRF output and commitment of one label version); prefix_tree and prefix_proof;",
            "log (leaf hashes, roots, distinguished entries); log_proof and",
            "inclusion_proof_decode (batch inclusion and consistency); tree_head,",
            "auditor_tree_head, full_tree_head_decode (signatures, one per auditor).",
            "",
            "The log is nine entries: two accounts, their handles, a phone label, the",
            "attested auditor's first instance, a device added and removed, a handle",
            "renamed, an account closed. Its prefix trees come from a reference builder in",
            "the generator; search, monitor and transparency proof responses are not here",
            "yet, and join when the prover and verifier do, with every value here unchanged.",
        ]
        .iter()
        .map(|line| s(line))
        .collect(),
    )
}

fn build() -> Gen<String> {
    let d = deployment()?;
    let mut cases = Cases::default();
    configuration_cases(&mut cases, &d)?;
    label_cases(&mut cases)?;
    value_cases(&mut cases)?;
    device_set_cases(&mut cases)?;
    commitment_cases(&mut cases)?;
    let mut history = log_cases(&mut cases, &d)?;
    prefix_proof_cases(&mut cases, &d, &history)?;
    log_proof_cases(&mut cases, &mut history)?;
    head_cases(&mut cases, &d, &mut history)?;

    let fixture = obj! {
        "version" => n(1),
        "about" => about(),
        "configVersion" => n(u64::from(CONFIG_VERSION)),
        "draft" => s(DRAFT_REVISION),
        "params" => obj! {
            "cipherSuite" => n(CIPHER_SUITE as u64),
            "deploymentMode" => n(DEPLOYMENT_MODE as u64),
            "maxAuditorLagMs" => n(MAX_AUDITOR_LAG_MS),
            "maxAheadMs" => n(MAX_AHEAD_MS),
            "maxBehindMs" => n(MAX_BEHIND_MS),
            "reasonableMonitoringWindowMs" => n(REASONABLE_MONITORING_WINDOW_MS),
            "maximumLifetimeMs" => MAXIMUM_LIFETIME_MS.map_or(J::Null, n),
            "minLifetimeWindows" => n(MIN_LIFETIME_WINDOWS),
            "labelKinds" => J::Arr(LABEL_KINDS.iter().map(|&k| obj! {
                "kind" => J::Str(char::from(k).to_string()),
                "byte" => n(u64::from(k)),
            }).collect()),
        },
        "keys" => obj! {
            "logSignatureSeed" => h(&LOG_SEED),
            "logSignaturePublicKey" => h(d.profile.signature_public_key()),
            "vrfSeed" => h(&VRF_SEED),
            "vrfPublicKey" => h(d.profile.vrf_public_key()),
            "auditors" => J::Arr(AUDITOR_SEEDS.iter().zip(d.profile.auditors()).map(|((seed, _), a)| obj! {
                "seed" => h(seed),
                "publicKey" => h(&a.public_key),
                "startPos" => n(a.start_pos),
            }).collect()),
            "accounts" => J::Arr(vec![
                obj! { "name" => s("ada"), "actorId" => h(&ADA_ACTOR), "seed" => h(&ADA_ACCOUNT_SEED), "publicKey" => h(&public(&ADA_ACCOUNT_SEED)) },
                obj! { "name" => s("grace"), "actorId" => h(&GRACE_ACTOR), "seed" => h(&GRACE_ACCOUNT_SEED), "publicKey" => h(&public(&GRACE_ACCOUNT_SEED)) },
            ]),
        },
        "cases" => J::Arr(cases.list),
    };
    let mut out = String::new();
    fixture.write(&mut out, 0);
    out.push('\n');
    // Every public key the file names parses as one.
    for seed in [LOG_SEED, ADA_ACCOUNT_SEED, GRACE_ACCOUNT_SEED] {
        g(PublicKey::from_bytes(&public(&seed)), "public key")?;
    }
    g(
        VrfPublicKey::from_bytes(d.profile.vrf_public_key()),
        "VRF key",
    )?;
    Ok(out)
}

fn main() -> ExitCode {
    let check = std::env::args().any(|a| a == "--check");
    let text = match build() {
        Ok(text) => text,
        Err(err) => {
            eprintln!("gen_fixture: {err}");
            return ExitCode::FAILURE;
        }
    };
    if check {
        return match std::fs::read_to_string(FIXTURE_PATH) {
            Ok(committed) if committed == text => ExitCode::SUCCESS,
            Ok(_) => {
                eprintln!(
                    "gen_fixture: {FIXTURE_PATH} is not what the generator makes; regenerate it"
                );
                ExitCode::FAILURE
            }
            Err(err) => {
                eprintln!("gen_fixture: {FIXTURE_PATH}: {err}");
                ExitCode::FAILURE
            }
        };
    }
    match std::fs::write(FIXTURE_PATH, &text) {
        Ok(()) => {
            eprintln!("gen_fixture: wrote {FIXTURE_PATH} ({} bytes)", text.len());
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("gen_fixture: {FIXTURE_PATH}: {err}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_committed_fixture_is_what_the_generator_makes() {
        let built = build().unwrap_or_else(|err| panic!("{err}"));
        assert!(
            built == include_str!("../../../fixtures/keytrans.json"),
            "mls/fixtures/keytrans.json is stale: regenerate it with \
             `cargo run -p peachy-keytrans --features prover --bin gen_fixture` from mls/"
        );
    }

    #[test]
    fn the_generator_is_deterministic() {
        assert!(
            build().unwrap_or_else(|err| panic!("{err}"))
                == build().unwrap_or_else(|err| panic!("{err}"))
        );
    }
}
