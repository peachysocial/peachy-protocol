// SPDX-License-Identifier: MIT
//! Replaying the golden fixtures — `mls/fixtures/rules.json` (group policy)
//! and `mls/fixtures/credentials.json` (device-credential rejections).
//!
//! The rule: one golden fixture for the group policy, replayed by every
//! binding before any client ships (docs/mls-core.md §Golden rules
//! fixture); here, `cargo test --workspace --all-features` in `mls/`. [`crate::rules`] was built with pinned
//! discriminants and spelled-out names *so that* one could be written; this is
//! the half that reads it.
//!
//! ## The door, and why it takes JSON
//!
//! One function — [`evaluate_case_json`](crate::fixture::evaluate_case_json) — takes a case object as text and
//! returns a verdict object as text. That is a deliberately unfashionable
//! signature for Rust, where [`crate::rules::PeachyMlsRules::evaluate`] is
//! right there and takes a struct. It is this shape because the point of the
//! fixture is the OTHER bindings: Swift, Kotlin and JavaScript each reach
//! this policy across a boundary that carries bytes, and a string in and a
//! string out is the one signature that crosses every one of them unchanged.
//! A per-field ABI would mean a hand-written mapping per binding from the same JSON, and
//! a disagreement between two of them would read as a policy disagreement.
//!
//! So each binding exposes exactly this: give it one case, get one verdict,
//! compare the verdict to the case's own `expect`. The replay loop is ordinary
//! code in each language; the decision is never re-implemented.
//!
//! ## Three fixtures, one door
//!
//! A case's `kind` says which question it asks — `"rules"` (the default, so
//! `mls/fixtures/rules.json` needed no edit when this arrived),
//! `"credential"`, which replays `mls/fixtures/credentials.json` against
//! [`crate::identity::PeachyIdentityProvider`] instead, or `"device_link"`,
//! which replays `mls/fixtures/device-link.json` against
//! [`crate::device_link`], or `"account_store"`, which replays
//! `mls/fixtures/account-store.json` against [`crate::account_store`], or
//! `"join_request"`, which replays `mls/fixtures/join-request.json` against
//! [`crate::join_request`], or `"call"`, which replays `mls/fixtures/calls.json`
//! against [`crate::call`], or `"welcome_frame"`, which replays
//! `mls/fixtures/welcome-frame.json` against [`crate::welcome_frame`], or
//! `"carried_commit"`, which replays `mls/fixtures/carried-commit.json`
//! against [`crate::carried_commit`], or `"steward"`, which replays
//! `mls/fixtures/steward.json` against [`crate::steward`], or
//! `"device_seal"`, which replays `mls/fixtures/device-seal.json` against
//! [`crate::device_seal`], or `"client_refusals"`, which replays
//! `mls/fixtures/client-refusals.json` against [`crate::client_refusals`]. A
//! **kind** and not a
//! second C function, deliberately: `peachy_mls_fixture_evaluate_case` is
//! already declared in the committed header, already wrapped by Swift, Kotlin
//! and wasm, and already proven to carry a JSON object each way. A second
//! entry point would mean a second header `#if`, a second JNI symbol, a second
//! wasm export and a second Swift shim — four more places for a marshalling
//! bug to hide, in order to ask the same question about a different table.
//!
//! A credential case carries its own inputs whole: the issuer seeds it trusts,
//! the seed of the key that signs, the device seed the credential binds, the
//! leaf's own key, and the instant the clock reads. **Seeds and never keys** —
//! the fixture synthesises its key material from 32-byte seeds written out in
//! hex, so nothing in it is, or could be mistaken for, a real Peachy signing
//! key, and every client mints the same bytes on every machine. The clock is
//! [`crate::identity::FixedClock`], which exists for exactly this: an expiry
//! test written against the wall clock is a test that starts failing on a date
//! nobody chose.
//!
//! ## What is NOT here
//!
//! This module does not read the fixture file, does not iterate cases and does
//! not assert. Those are the test's job in each language, and they differ —
//! Rust has `serde_json` and `include_str!`, Node has `JSON.parse` and
//! `node:test`. Keeping the file-reading out means the door is the same
//! everywhere and the ceremony is local.
//!
//! Behind the `fixture` cargo feature, off by default, for the same reason as
//! `test-issuer`: a shipped client has no use for a JSON-driven test harness,
//! and `serde_json`-shaped code that only tests call should not be in a
//! release binary. `mls/wasm` re-exports it under its own `fixture` feature.

use openmls::prelude::{Credential, CredentialType};
use serde::{Deserialize, Serialize};

use crate::credential::{encode_base64url, encode_standard, CredentialPayload};
use crate::error::{CredentialRejection, Error, Result};
use crate::identity::{
    FixedClock, MessageSenderVerdict, PeachyIdentity, PeachyIdentityProvider, TrustedServerKeys,
};
use crate::issuer::{device_key_pair, TestIssuer};
use crate::rules::{PeachyMlsRules, PolicyDecision, ProposalContext, ProposalKind, SenderKind};

/// `mls/fixtures/calls.json`, the `"call"` kind.
mod call_cases;

/// `mls/fixtures/welcome-frame.json`, the `"welcome_frame"` kind.
mod welcome_frame_cases;

/// `mls/fixtures/carried-commit.json`, the `"carried_commit"` kind.
mod carried_commit_cases;

/// `mls/fixtures/steward.json`, the `"steward"` kind.
mod steward_cases;

/// `mls/fixtures/device-seal.json`, the `"device_seal"` kind.
mod device_seal_cases;

/// The fixture format this build understands.
///
/// The fixture's own top-level `version` must equal it. Bumping this is a
/// statement that the *shape* of a case changed — a new `call`, a renamed
/// field — and it is the thing a client built from an older commit should
/// refuse rather than misread. Renaming a proposal kind is not a format
/// change; it is a policy change, and it fails on the name.
pub const FORMAT_VERSION: u32 = 1;

/// The rules configuration a case is evaluated under.
///
/// Optional in a case, defaulting to the fixture's top-level block, which in
/// turn defaults to [`PeachyMlsRules::default`]. It exists because
/// `allow_remove_by_any_member` is the one knob of the proposal rules (see
/// [`crate::rules::PeachyMlsRules`]), and a fixture that could only describe
/// one setting could not catch a binding that drops it.
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RulesConfig {
    pub allow_remove_by_any_member: bool,
}

impl From<RulesConfig> for PeachyMlsRules {
    fn from(config: RulesConfig) -> Self {
        Self {
            allow_remove_by_any_member: config.allow_remove_by_any_member,
        }
    }
}

/// One proposal, in the fixture's vocabulary.
///
/// Every field but `kind` and `sender` has a default, and every default is the
/// ordinary case, so a case says only what it is about.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProposalJson {
    kind: String,
    sender: String,
    /// Only consulted for an Update. Defaults to true, which is the ordinary
    /// case for every other kind and keeps 40-odd cases from each carrying a
    /// field that says nothing.
    #[serde(default = "yes")]
    targets_sender_leaf: bool,
    /// GroupContextExtensions only: whether the proposal changes the group's
    /// name and photo (`peachy_group_meta`) and nothing else. Defaults to
    /// false, every case written before the extension existed.
    #[serde(default)]
    sets_group_meta: bool,
    /// Whether the proposal arrived by reference (standalone, or named by a
    /// commit). Defaults to false, a proposal a commit carries inline.
    #[serde(default)]
    by_reference: bool,
    /// Remove only: whether the removed leaf is the sender's own person's,
    /// which by reference is a leave. Defaults to false.
    #[serde(default)]
    removes_own_leaf: bool,
}

fn yes() -> bool {
    true
}

impl ProposalJson {
    fn context(&self) -> Result<ProposalContext> {
        Ok(ProposalContext {
            kind: ProposalKind::from_name(&self.kind).ok_or_else(|| {
                Error::invalid(format!(
                    "unknown proposal kind {:?}; known: {}",
                    self.kind,
                    names(&ProposalKind::ALL.map(ProposalKind::name))
                ))
            })?,
            sender: SenderKind::from_name(&self.sender).ok_or_else(|| {
                Error::invalid(format!(
                    "unknown sender kind {:?}; known: {}",
                    self.sender,
                    names(&SenderKind::ALL.map(SenderKind::name))
                ))
            })?,
            targets_sender_leaf: self.targets_sender_leaf,
            sets_group_meta: self.sets_group_meta,
            by_reference: self.by_reference,
            removes_own_leaf: self.removes_own_leaf,
        })
    }
}

fn names(all: &[&'static str]) -> String {
    all.join(", ")
}

/// One case. `expect` is deserialised and ignored: the door answers what the
/// policy says, and the comparison belongs to the caller. Accepting the field
/// rather than rejecting it is what lets a caller hand over the case object
/// verbatim instead of stripping a key first — in every binding.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CaseJson {
    #[serde(default)]
    #[allow(dead_code)]
    id: Option<String>,
    call: String,
    rules: Option<RulesConfig>,
    proposal: Option<ProposalJson>,
    proposals: Option<Vec<ProposalJson>>,
    sender: Option<String>,
}

/// A verdict, as it is written in a case's `expect` and as
/// [`evaluate_case_json`] returns it.
///
/// `reason` and `reasonCode` are both present on a denial, and both absent on
/// an allow. Carrying the code beside the name is not redundancy: the name is
/// what a person reads and the number is what a C caller compares, and a
/// fixture that held only one of them could not catch a rename that left the
/// discriminant alone or a renumbering that left the name alone — which are
/// exactly the two ways this contract breaks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Verdict {
    pub decision: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<u32>,
}

impl From<PolicyDecision> for Verdict {
    fn from(decision: PolicyDecision) -> Self {
        match decision {
            PolicyDecision::Allow => Self {
                decision: "allow",
                reason: None,
                reason_code: None,
            },
            PolicyDecision::Deny(reason) => Self {
                decision: "deny",
                reason: Some(reason.name()),
                reason_code: Some(reason.code()),
            },
        }
    }
}

/// Which table a case belongs to, read before anything else.
///
/// Absent means `"rules"`, which is why `mls/fixtures/rules.json` needed no
/// edit and why every client built before `credentials.json` existed goes on
/// replaying the policy unchanged.
#[derive(Debug, Clone, Deserialize)]
struct KindJson {
    #[serde(default)]
    kind: Option<String>,
}

/// Evaluate one fixture case and return its verdict as JSON.
///
/// The case's `kind` picks the table: `"rules"` (the default), `"credential"`
/// — see `evaluate_credential_case` — or `"device_link"`, see
/// `evaluate_device_link_case`. Either way the whole case object goes in,
/// `expect` and `why` included and ignored, and a verdict object comes back as
/// text.
pub fn evaluate_case_json(case_json: &str) -> Result<String> {
    let envelope: KindJson = serde_json::from_str(case_json)
        .map_err(|err| Error::invalid(format!("could not read the fixture case: {err}")))?;

    match envelope.kind.as_deref() {
        None | Some("rules") => evaluate_rules_case(case_json),
        Some("credential") => evaluate_credential_case(case_json),
        Some("device_link") => evaluate_device_link_case(case_json),
        Some("account_store") => evaluate_account_store_case(case_json),
        Some("roster") => evaluate_roster_case(case_json),
        Some("join_request") => evaluate_join_request_case(case_json),
        Some("call") => call_cases::evaluate_call_case(case_json),
        Some("welcome_frame") => welcome_frame_cases::evaluate_welcome_frame_case(case_json),
        Some("carried_commit") => carried_commit_cases::evaluate_carried_commit_case(case_json),
        Some("steward") => steward_cases::evaluate_steward_case(case_json),
        Some("device_seal") => device_seal_cases::evaluate_device_seal_case(case_json),
        Some("typing") => evaluate_typing_case(case_json),
        Some("resend_commitment") => evaluate_resend_commitment_case(case_json),
        Some("client_refusals") => evaluate_client_refusals_case(case_json),
        Some(other) => Err(Error::invalid(format!(
            "unknown case kind {other:?}; known: rules, credential, device_link, account_store, \
             roster, join_request, call, welcome_frame, carried_commit, steward, device_seal, \
             typing, resend_commitment, client_refusals"
        ))),
    }
}

/// One case of `mls/fixtures/client-refusals.json` ([`crate::client_refusals`]).
///
/// | `call` | needs | returns |
/// | --- | --- | --- |
/// | `table` | — | `{"refusals":[{"name","compiledDefault"}]}` |
/// | `ratchet` | `held`, `served` (arrays of names) | `{"held"}` |
/// | `on` | `name`, `held` | `{"on"}` |
fn evaluate_client_refusals_case(case_json: &str) -> Result<String> {
    use crate::client_refusals;
    let case: serde_json::Value = serde_json::from_str(case_json)
        .map_err(|err| Error::invalid(format!("could not read the client-refusals case: {err}")))?;
    let call = case
        .get("call")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| Error::invalid("a client-refusals case needs a `call`"))?;
    let names = |key: &str| -> Result<Vec<String>> {
        case.get(key)
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| Error::invalid(format!("a `{call}` case needs a `{key}` array")))?
            .iter()
            .map(|v| {
                v.as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| Error::invalid(format!("`{key}` holds only strings")))
            })
            .collect()
    };
    let verdict = match call {
        "table" => serde_json::json!({
            "refusals": client_refusals::CLIENT_REFUSALS
                .iter()
                .map(|r| serde_json::json!({ "name": r.name, "compiledDefault": r.compiled_default }))
                .collect::<Vec<_>>(),
        }),
        "ratchet" => serde_json::json!({
            "held": client_refusals::ratchet(&names("held")?, &names("served")?),
        }),
        "on" => {
            let name = case
                .get("name")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| Error::invalid("an `on` case needs a `name`"))?;
            serde_json::json!({ "on": client_refusals::is_on(name, &names("held")?) })
        }
        other => {
            return Err(Error::invalid(format!(
                "unknown client-refusals call {other:?}; known: table, ratchet, on"
            )))
        }
    };
    Ok(verdict.to_string())
}

/// One typing case (`mls/fixtures/formats/typing.json`): its `call`
/// names a door of [`crate::typing::typing_case_json`].
fn evaluate_typing_case(case_json: &str) -> Result<String> {
    let case: serde_json::Value = serde_json::from_str(case_json)
        .map_err(|err| Error::invalid(format!("could not read the typing case: {err}")))?;
    let call = case
        .get("call")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| Error::invalid("a typing case needs a `call`"))?;
    Ok(crate::typing::typing_case_json(call, &case)?.to_string())
}

/// One case of the author's commitment (docs/sealed-messages.md
/// §Content hints): `call` is `commit` `{groupId, actorId, secret}` (all
/// text) -> `{"commitment": hex}`, `secret` `{hint, plaintext}` (plaintext
/// hex) -> `{"secret": hex|null}`, or `aad` `{aad}` (hex) ->
/// `{"hint": n|null, "commitment": hex|null}`.
fn evaluate_resend_commitment_case(case_json: &str) -> Result<String> {
    use crate::hint;
    let case: serde_json::Value = serde_json::from_str(case_json)
        .map_err(|err| Error::invalid(format!("could not read the commitment case: {err}")))?;
    let text = |key: &str| -> Result<String> {
        case.get(key)
            .and_then(serde_json::Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| Error::invalid(format!("a commitment case needs a text `{key}`")))
    };
    let hex = |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
    let verdict = match text("call")?.as_str() {
        "commit" => serde_json::json!({
            "commitment": hex(&hint::resend_author_commitment(
                text("groupId")?.as_bytes(),
                &text("actorId")?,
                text("secret")?.as_bytes(),
            )),
        }),
        "secret" => {
            let hint_byte = case
                .get("hint")
                .and_then(serde_json::Value::as_u64)
                .and_then(|n| u8::try_from(n).ok())
                .ok_or_else(|| Error::invalid("a `secret` case needs a byte `hint`"))?;
            let plaintext = crate::call::from_hex(&text("plaintext")?, "plaintext")?;
            serde_json::json!({
                "secret": hint::resend_secret_of(hint_byte, &plaintext).map(|s| hex(&s)),
            })
        }
        "aad" => {
            let aad = crate::call::from_hex(&text("aad")?, "aad")?;
            serde_json::json!({
                "hint": hint::hint_from_aad(&aad),
                "commitment": hint::commitment_from_aad(&aad).map(|c| hex(&c)),
            })
        }
        other => {
            return Err(Error::invalid(format!(
                "unknown commitment call {other:?}; known: commit, secret, aad"
            )))
        }
    };
    Ok(verdict.to_string())
}

/// Evaluate one case of `mls/fixtures/rules.json`.
///
/// `case_json` is one element of the fixture's `cases` array, verbatim —
/// `expect` included and ignored. The three calls, matching the three public
/// entry points of [`PeachyMlsRules`]:
///
/// | `call` | needs | evaluates |
/// | --- | --- | --- |
/// | `evaluate` | `proposal` | one proposal |
/// | `evaluateAll` | `proposals` | a commit's worth; the first denial wins |
/// | `evaluateCommitSender` | `sender` | who may commit at all |
///
/// Returns `{"decision":"allow"}` or
/// `{"decision":"deny","reason":"…","reasonCode":N}`.
///
/// Errors — an unknown `call`, an unknown name, a missing field — are
/// [`Error::InvalidArgument`] and are NOT verdicts. That distinction is the
/// one thing a replay must not blur: a case naming a proposal kind that no
/// longer exists has to fail loudly, because the alternative is a fixture that
/// goes on passing while it addresses nothing, which is the failure mode
/// the clients' identifier checks exist to catch on their side.
fn evaluate_rules_case(case_json: &str) -> Result<String> {
    let case: CaseJson = serde_json::from_str(case_json)
        .map_err(|err| Error::invalid(format!("could not read the fixture case: {err}")))?;

    let rules: PeachyMlsRules = case.rules.map(Into::into).unwrap_or_default();

    let decision = match case.call.as_str() {
        "evaluate" => {
            let proposal = case
                .proposal
                .as_ref()
                .ok_or_else(|| Error::invalid("an `evaluate` case needs a `proposal`"))?;
            rules.evaluate(&proposal.context()?)
        }
        "evaluateAll" => {
            let proposals = case
                .proposals
                .as_ref()
                .ok_or_else(|| Error::invalid("an `evaluateAll` case needs `proposals`"))?;
            let contexts = proposals
                .iter()
                .map(ProposalJson::context)
                .collect::<Result<Vec<_>>>()?;
            rules.evaluate_all(contexts.iter())
        }
        "evaluateCommitSender" => {
            let sender = case
                .sender
                .as_deref()
                .ok_or_else(|| Error::invalid("an `evaluateCommitSender` case needs a `sender`"))?;
            let sender = SenderKind::from_name(sender).ok_or_else(|| {
                Error::invalid(format!(
                    "unknown sender kind {sender:?}; known: {}",
                    names(&SenderKind::ALL.map(SenderKind::name))
                ))
            })?;
            rules.evaluate_commit_sender(sender)
        }
        other => {
            return Err(Error::invalid(format!(
                "unknown call {other:?}; known: evaluate, evaluateAll, evaluateCommitSender"
            )))
        }
    };

    serde_json::to_string(&Verdict::from(decision))
        .map_err(|err| Error::invalid(format!("could not write the verdict: {err}")))
}

// ---- Credential cases -------------------------------------------------------

/// How a case's credential is minted.
///
/// `deny_unknown_fields`, unlike the case itself: a case carries `why`,
/// `expect` and `kind` for the reader and the replay, but a `mint` block is
/// nothing but inputs, and a misspelled input that silently defaulted would be
/// a case quietly testing something other than what it reads as.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct MintJson {
    /// 32 bytes of hex — the seed of the key that actually SIGNS. Not
    /// necessarily a key the case trusts; that is how a forgery is written.
    signer_seed: String,
    /// Override the payload's `kid`. Defaults to the signer's own, so the only
    /// cases that name one are the ones about trust: a `kid` nobody holds, or
    /// a trusted `kid` over somebody else's signature.
    kid: Option<String>,
    /// The payload's `v`. Defaults to 1, so an ordinary case never writes it
    /// and the cases that DO are asking what happens to any other version.
    version: Option<u8>,
    /// The token's prefix. Defaults to `pdc1`; a case names another to prove
    /// it is refused.
    prefix: Option<String>,
    /// Fields added to the payload's JSON beside the ones the format has, and
    /// signed along with them. The door for the one forgery this crate's
    /// own types cannot express: a payload carrying a field the format does
    /// not have, signed by a trusted key. Every client must read it as `malformed`, never as a person.
    extra: Option<serde_json::Map<String, serde_json::Value>>,
    actor_id: String,
    /// Replace `actorId` with this many `a`s. The one input a fixture cannot
    /// write out literally: [`crate::credential::MAX_TOKEN_BYTES`] is 8 KiB,
    /// and a case that carried 9,000 characters of padding would bury the
    /// forty that matter.
    actor_id_fill: Option<usize>,
    device_id: String,
    /// 32 bytes of hex — the device key the credential BINDS.
    device_seed: String,
    /// Override the payload's `device_key` string verbatim, for the shapes a
    /// seed cannot express: not base64, or the right base64 of the wrong
    /// number of bytes.
    device_key: Option<String>,
    issued_at: i64,
    expires_at: i64,
    /// 32 bytes of hex — the ACCOUNT key (docs/account-store.md) whose derived
    /// identity key vouches for this device ([`crate::account_identity`]).
    /// Absent: a device its account has not let in, with both account fields
    /// empty.
    account_key: Option<String>,
    /// 32 bytes of hex — sign the account certificate with THIS account key
    /// while the payload names `accountKey`'s identity. The forgery a server
    /// would try: somebody's real identity key beside a signature it made.
    account_signer: Option<String>,
    /// Write the account identity key and leave the signature empty.
    #[serde(default)]
    account_sig_omitted: bool,
    /// Damage the token after it is signed. `"signature"` flips one character
    /// of the signature segment; `"payload"` swaps in a payload the signature
    /// does not cover — which is the forgery this crate's "never re-serialize
    /// what you verified" rule exists to catch.
    tamper: Option<String>,
    /// Write the token in a spelling other than the canonical one, signed by
    /// the signer all the same. `"spaced-payload"` puts a space after the
    /// payload's opening brace, before signing; `"padded-segments"` writes
    /// both base64url segments with `=` padding. The issuer's lever on a
    /// token's LENGTH, which every client refuses as `malformed`
    /// (docs/identity.md §Format).
    spelling: Option<String>,
}

/// One entry of a credential case's `trust` list.
///
/// Untagged: a bare hex string means "this issuer's key, published the way a
/// live server publishes it" (`use: device`). An entry written as
/// `{"seed": …, "use": …}` publishes it under that `use` instead, and goes
/// through the same reader a client runs on the live list
/// ([`TrustedServerKeys::from_published_json`]) — so a key published under any
/// use but `device` vouches for nothing.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
enum TrustEntryJson {
    /// The issuer's key, as a device key.
    Device(String),
    /// The issuer's key under a named use.
    Scoped {
        seed: String,
        #[serde(rename = "use")]
        key_use: String,
    },
}

/// One credential case. Everything it needs is in it — no defaults are merged
/// in from the fixture's top level, because a merge is a second opinion about
/// the fixture's shape, held once more in every binding.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CredentialCaseJson {
    #[serde(default)]
    #[allow(dead_code)]
    id: Option<String>,
    /// `validateToken`, `validateCredential`, `validateMember` — the door a
    /// PEER's leaf comes through, which also requires an account certificate
    /// — or `validateOwn`, this device's own credential checked against the
    /// account key it holds (`heldAccountKey`).
    call: String,
    /// What the verifier's clock reads, in unix seconds.
    now_unix: i64,
    /// The issuer seeds this verifier trusts, as
    /// `GET /healthz/device-credential-keys` would have handed them over. May
    /// be empty — a client that has fetched no key list trusts nobody.
    ///
    /// See [`TrustEntryJson`] for the two shapes an entry takes.
    trust: Vec<TrustEntryJson>,
    /// Mint the token from these inputs.
    mint: Option<MintJson>,
    /// …or hand over a literal token, for the shapes no minter can produce.
    token: Option<String>,
    /// 32 bytes of hex — the key the LEAF signs with. Defaults to the minted
    /// credential's own device key, so only the mismatch cases name one.
    leaf_seed: Option<String>,
    /// `validateCredential` only: `basic`, `x509`, `other:<u16>` or
    /// `grease:<u16>`. Defaults to `basic`.
    credential_type: Option<String>,
    /// `validateOwn` only: 32 bytes of hex, the ACCOUNT key this device holds
    /// (its identity key is derived from it, as a client does), or absent for
    /// a device that holds none.
    held_account_key: Option<String>,
    /// `judgeMessage` only: the second the delivery service received the
    /// message, absent (or 0) when the reader does not know it.
    received_at: Option<i64>,
    /// `judgeMessage` only: 32 bytes of hex, an ACCOUNT key that signed a
    /// revocation of the leaf's device key which the reader holds. It counts
    /// only if it verifies under the account key the credential names, as
    /// on a client.
    revoked_by: Option<String>,
    /// `judgeMessage` only, beside `revokedBy`: the second the delivery
    /// service said the revocation took effect, absent (or 0) when it did
    /// not say.
    revoked_at: Option<i64>,
    /// `judgeMessage` only: the tree clock of the epoch the message was
    /// sealed in, when that is the epoch the reader's group is in now;
    /// absent for a message from an epoch the group has left.
    tree_clock: Option<i64>,
}

/// A credential verdict, as a case's `expect` writes it and as
/// `evaluate_credential_case` returns it.
///
/// An acceptance carries the whole identity and not just the word "accepted".
/// Without that a passing accept case would say only "nothing was refused",
/// which is also what a verifier that had stopped reading the payload would
/// say. `actorId` and `deviceId` are the KEY layer
/// (docs/identity.md §Accounts, sessions and devices); no display
/// name appears here, or anywhere in this crate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialVerdict {
    pub decision: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<i64>,
    /// Hex of the verified account identity key, when the credential carries one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_key: Option<String>,
    /// `judgeMessage` only: true when the message is read inside the grace
    /// from a leaf whose credential is past `exp` on the reader's wall.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lapsed: Option<bool>,
}

impl From<PeachyIdentity> for CredentialVerdict {
    fn from(identity: PeachyIdentity) -> Self {
        Self {
            decision: "accepted",
            reason: None,
            reason_code: None,
            actor_id: Some(identity.actor_id),
            device_id: Some(identity.device_id),
            kid: Some(identity.kid),
            expires_at: Some(identity.expires_at),
            account_key: identity.account_key.map(|key| to_hex(&key)),
            lapsed: None,
        }
    }
}

impl CredentialVerdict {
    /// `{"decision":"revoked"}`: a `judgeMessage` sender whose own account
    /// signed its key out. It names no [`CredentialRejection`], the
    /// credential itself being sound.
    fn revoked() -> Self {
        Self {
            decision: "revoked",
            reason: None,
            reason_code: None,
            actor_id: None,
            device_id: None,
            kid: None,
            expires_at: None,
            account_key: None,
            lapsed: None,
        }
    }
}

impl From<CredentialRejection> for CredentialVerdict {
    fn from(rejection: CredentialRejection) -> Self {
        Self {
            decision: "rejected",
            reason: Some(rejection.name()),
            reason_code: Some(rejection.code()),
            actor_id: None,
            device_id: None,
            kid: None,
            expires_at: None,
            account_key: None,
            lapsed: None,
        }
    }
}

/// Evaluate one case of `mls/fixtures/credentials.json` and return its verdict
/// as JSON.
///
/// The calls, matching the doors a verifier actually uses:
///
/// | `call` | evaluates |
/// | --- | --- |
/// | `validateToken` | a bare `pdc1` token against a leaf signature key |
/// | `validateCredential` | an MLS `Credential` of some type, plus that key |
/// | `validateMember` | a peer's leaf, which must carry an account certificate |
/// | `validateOwn` | this device's own token, against the account key it holds |
/// | `judgeMessage` | an application message's sender: `validateMember` without the expiry, then [`crate::identity::judge_message_sender`] on `nowUnix`, `receivedAt`, `revokedBy` and `revokedAt` |
///
/// `judgeMessage` answers an acceptance (with `"lapsed":true` inside the
/// grace), `expired` (past the grace, or a lapsed sender's new message), or `{"decision":"revoked"}` for a key its own account signed
/// out. `treeClock` is the sealing epoch's tree clock, absent for a past
/// epoch.
///
/// Returns `{"decision":"accepted","actorId":…,"deviceId":…,"kid":…,"expiresAt":…}`
/// or `{"decision":"rejected","reason":"…","reasonCode":N}`.
///
/// Errors — an unknown `call`, a seed that is not 32 bytes of hex, a case with
/// neither a `mint` nor a `token` — are [`Error::InvalidArgument`] and are NOT
/// verdicts, for the same reason as in the rules half: a case that addresses
/// nothing has to fail loudly rather than go on passing over nothing.
fn evaluate_credential_case(case_json: &str) -> Result<String> {
    let case: CredentialCaseJson = serde_json::from_str(case_json)
        .map_err(|err| Error::invalid(format!("could not read the credential case: {err}")))?;

    // Every entry becomes one key in a published list, read by the same
    // reader a client runs on `GET /healthz/device-credential-keys`.
    let mut published = Vec::new();
    for entry in &case.trust {
        let (seed, key_use) = match entry {
            TrustEntryJson::Device(seed) => (seed, "device"),
            TrustEntryJson::Scoped { seed, key_use } => (seed, key_use.as_str()),
        };
        let issuer = TestIssuer::from_seed(&seed32(seed, "a `trust` entry")?);
        published.push(serde_json::json!({
            "kid": issuer.kid(),
            "publicKey": encode_standard(&issuer.public_key()),
            "current": true,
            "use": key_use,
        }));
    }
    let published = serde_json::json!({ "enabled": true, "keys": published }).to_string();
    let trusted = TrustedServerKeys::from_published_json(&published)?;
    let provider = PeachyIdentityProvider::with_clock(trusted, Box::new(FixedClock(case.now_unix)));

    let (token, minted_device_key) = match (&case.mint, &case.token) {
        (Some(mint), None) => {
            let (token, device_key) = mint_token(mint)?;
            (token, Some(device_key))
        }
        (None, Some(literal)) => (literal.clone().into_bytes(), None),
        (Some(_), Some(_)) => {
            return Err(Error::invalid(
                "a credential case takes a `mint` or a `token`, never both",
            ))
        }
        (None, None) => {
            return Err(Error::invalid(
                "a credential case needs a `mint` or a `token`",
            ))
        }
    };

    let leaf_key = match &case.leaf_seed {
        Some(seed) => device_key_pair(&seed32(seed, "`leafSeed`")?).1,
        None => minted_device_key.ok_or_else(|| {
            Error::invalid("a `token` case needs a `leafSeed`; there is no minted key to borrow")
        })?,
    };

    let mut judged = None;
    let outcome = match case.call.as_str() {
        "validateToken" => {
            if case.credential_type.is_some() {
                return Err(Error::invalid(
                    "`credentialType` belongs to a `validateCredential` case; a bare token \
                     has no MLS credential type at all",
                ));
            }
            provider.validate_token(&token, &leaf_key)
        }
        "validateCredential" => {
            let credential_type =
                credential_type_from_name(case.credential_type.as_deref().unwrap_or("basic"))?;
            provider.validate_credential(&Credential::new(credential_type, token), &leaf_key)
        }
        "validateMember" => {
            let credential_type =
                credential_type_from_name(case.credential_type.as_deref().unwrap_or("basic"))?;
            provider
                .validate_seated_credential(&Credential::new(credential_type, token), &leaf_key, 0)
                .map(|(identity, _lapsed)| identity)
        }
        "validateOwn" => {
            let held = match &case.held_account_key {
                Some(hex) => Some(crate::account_identity::account_identity_public_key(
                    &seed32(hex, "`heldAccountKey`")?,
                )?),
                None => None,
            };
            provider
                .validate_token(&token, &leaf_key)
                .and_then(|identity| {
                    crate::identity::check_own_account_key(&identity, held.as_ref())?;
                    Ok(identity)
                })
        }
        "judgeMessage" => {
            let credential_type =
                credential_type_from_name(case.credential_type.as_deref().unwrap_or("basic"))?;
            match provider.validate_seated_credential(
                &Credential::new(credential_type, token),
                &leaf_key,
                i64::MAX,
            ) {
                Ok((identity, _)) => {
                    let revoked = match &case.revoked_by {
                        Some(hex) => {
                            let signature = crate::revocation::sign_device_revocation(
                                &seed32(hex, "`revokedBy`")?,
                                &identity.device_key,
                            )?;
                            identity.account_key.is_some_and(|account| {
                                crate::revocation::verify_device_revocation(
                                    &account,
                                    &identity.device_key,
                                    &signature,
                                )
                            })
                        }
                        None => false,
                    };
                    judged = Some(crate::identity::judge_message_sender(
                        identity.expires_at,
                        case.now_unix,
                        case.received_at.unwrap_or(0),
                        revoked.then_some(case.revoked_at.unwrap_or(0)),
                        case.tree_clock,
                    ));
                    Ok(identity)
                }
                Err(err) => Err(err),
            }
        }
        other => {
            return Err(Error::invalid(format!(
                "unknown call {other:?}; known: validateToken, validateCredential, \
                 validateMember, validateOwn, judgeMessage"
            )))
        }
    };
    if case.held_account_key.is_some() && case.call != "validateOwn" {
        return Err(Error::invalid(
            "`heldAccountKey` belongs to a `validateOwn` case",
        ));
    }
    if (case.received_at.is_some()
        || case.revoked_by.is_some()
        || case.revoked_at.is_some()
        || case.tree_clock.is_some())
        && case.call != "judgeMessage"
    {
        return Err(Error::invalid(
            "`receivedAt`, `revokedBy`, `revokedAt` and `treeClock` belong to a `judgeMessage` case",
        ));
    }
    if case.revoked_at.is_some() && case.revoked_by.is_none() {
        return Err(Error::invalid("`revokedAt` belongs beside `revokedBy`"));
    }

    let verdict = match (outcome, judged) {
        (Ok(_), Some(MessageSenderVerdict::Revoked)) => CredentialVerdict::revoked(),
        (Ok(_), Some(MessageSenderVerdict::Expired)) => {
            CredentialVerdict::from(CredentialRejection::Expired)
        }
        (Ok(identity), Some(MessageSenderVerdict::ReadLapsed)) => CredentialVerdict {
            lapsed: Some(true),
            ..CredentialVerdict::from(identity)
        },
        (outcome, _) => match outcome {
            Ok(identity) => CredentialVerdict::from(identity),
            Err(Error::CredentialRejected(rejection)) => CredentialVerdict::from(rejection),
            // Anything else is the case being wrong, not the credential — a
            // trust seed that is not a valid Ed25519 point, say. Never a
            // verdict.
            Err(other) => return Err(other),
        },
    };

    serde_json::to_string(&verdict)
        .map_err(|err| Error::invalid(format!("could not write the verdict: {err}")))
}

/// Mint a case's token, returning it beside the device key it binds.
fn mint_token(mint: &MintJson) -> Result<(Vec<u8>, [u8; 32])> {
    let signer = TestIssuer::from_seed(&seed32(&mint.signer_seed, "`signerSeed`")?);
    let (_, device_key) = device_key_pair(&seed32(&mint.device_seed, "`deviceSeed`")?);

    let prefix = mint
        .prefix
        .clone()
        .unwrap_or_else(|| crate::credential::TOKEN_PREFIX.into());

    let payload = CredentialPayload {
        v: mint
            .version
            .unwrap_or(crate::credential::CREDENTIAL_VERSION),
        kid: mint.kid.clone().unwrap_or_else(|| signer.kid().to_string()),
        actor_id: match mint.actor_id_fill {
            Some(count) => "a".repeat(count),
            None => mint.actor_id.clone(),
        },
        device_id: mint.device_id.clone(),
        device_key: mint
            .device_key
            .clone()
            .unwrap_or_else(|| encode_standard(&device_key)),
        account_key: match &mint.account_key {
            Some(hex) => encode_standard(&crate::account_identity::account_identity_public_key(
                &seed32(hex, "`accountKey`")?,
            )?),
            None => String::new(),
        },
        account_sig: match (
            &mint.account_key,
            &mint.account_signer,
            mint.account_sig_omitted,
        ) {
            (_, _, true) => String::new(),
            (Some(hex), None, false) | (_, Some(hex), false) => {
                encode_standard(&crate::account_identity::sign_account_device(
                    &seed32(hex, "`accountKey`")?,
                    &device_key,
                )?)
            }
            (None, None, false) => String::new(),
        },
        iat: mint.issued_at,
        exp: mint.expires_at,
    };

    // With `extra`, the payload as a JSON object with those fields added,
    // signed as bytes. Without, exactly what the issuer would mint.
    let mut bytes = match &mint.extra {
        None => serde_json::to_vec(&payload),
        Some(extra) => {
            let mut object = match serde_json::to_value(&payload)
                .map_err(|err| Error::invalid(format!("could not encode a payload: {err}")))?
            {
                serde_json::Value::Object(object) => object,
                _ => return Err(Error::invalid("a payload always encodes as an object")),
            };
            for (key, value) in extra {
                object.insert(key.clone(), value.clone());
            }
            serde_json::to_vec(&object)
        }
    }
    .map_err(|err| Error::invalid(format!("could not encode a payload: {err}")))?;
    let spelling = mint.spelling.as_deref();
    match spelling {
        None | Some("padded-segments") => {}
        Some("spaced-payload") => bytes.insert(1, b' '),
        Some(other) => {
            return Err(Error::invalid(format!(
                "unknown spelling {other:?}; known: spaced-payload, padded-segments"
            )))
        }
    }
    let token = signer.issue_raw(&prefix, &bytes);
    let token = if spelling == Some("padded-segments") {
        pad_segments(token)?
    } else {
        token
    };
    let token = match mint.tamper.as_deref() {
        None => token,
        Some("signature") => flip_first_character_of_segment(token, 2)?,
        Some("payload") => {
            // A payload the signature does not cover. Not a random bit flip:
            // a flipped character can land on either Malformed or
            // BadSignature depending on which character it was, and a golden
            // fixture cannot expect "one of two". This is a whole, well-formed
            // payload for a different actor, over the original signature, so
            // the answer is BadSignature every time — and it is the exact
            // forgery that works against a verifier which re-serializes what
            // it parsed instead of checking the bytes as they arrived.
            let mut forged = payload.clone();
            forged.actor_id = format!("{}-evil", forged.actor_id);
            replace_payload_segment(token, &forged)?
        }
        Some(other) => {
            return Err(Error::invalid(format!(
                "unknown tamper {other:?}; known: payload, signature"
            )))
        }
    };

    Ok((token, device_key))
}

/// Flip the first character of one dot-separated segment of a token.
fn flip_first_character_of_segment(token: Vec<u8>, index: usize) -> Result<Vec<u8>> {
    let text =
        String::from_utf8(token).map_err(|_| Error::invalid("a minted token is always ASCII"))?;
    let mut parts: Vec<String> = text.split('.').map(str::to_string).collect();
    let segment = parts
        .get_mut(index)
        .ok_or_else(|| Error::invalid("a minted token has three segments"))?;
    let first = segment
        .chars()
        .next()
        .ok_or_else(|| Error::invalid("that segment is empty"))?;
    // base64url is dense, so any other character decodes to different bytes.
    let replacement = if first == 'A' { 'B' } else { 'A' };
    let rest: String = segment.chars().skip(1).collect();
    *segment = format!("{replacement}{rest}");
    Ok(parts.join(".").into_bytes())
}

/// Write a token's two base64url segments with `=` padding: the same bytes
/// and the same signature, in a longer spelling.
fn pad_segments(token: Vec<u8>) -> Result<Vec<u8>> {
    let text =
        String::from_utf8(token).map_err(|_| Error::invalid("a minted token is always ASCII"))?;
    let mut parts: Vec<String> = text.split('.').map(str::to_string).collect();
    for segment in parts.iter_mut().skip(1) {
        let padding = (4 - segment.len() % 4) % 4;
        segment.push_str(&"=".repeat(padding));
    }
    Ok(parts.join(".").into_bytes())
}

/// Swap a token's payload segment, leaving the signature alone.
fn replace_payload_segment(token: Vec<u8>, payload: &CredentialPayload) -> Result<Vec<u8>> {
    let encoded = serde_json::to_vec(payload)
        .map_err(|err| Error::invalid(format!("could not encode a payload: {err}")))?;
    let text =
        String::from_utf8(token).map_err(|_| Error::invalid("a minted token is always ASCII"))?;
    let mut parts: Vec<String> = text.split('.').map(str::to_string).collect();
    let segment = parts
        .get_mut(1)
        .ok_or_else(|| Error::invalid("a minted token has three segments"))?;
    *segment = encode_base64url(&encoded);
    Ok(parts.join(".").into_bytes())
}

/// The MLS credential type a `validateCredential` case asks about.
///
/// `other:` and `grease:` are here because RFC 9420 has a registry and a GREASE
/// range, and "anything that is not `basic`" is one branch in
/// [`PeachyIdentityProvider::validate_credential`] that has to be reached by
/// more than the one type a reader thinks of.
fn credential_type_from_name(name: &str) -> Result<CredentialType> {
    match name {
        "basic" => return Ok(CredentialType::Basic),
        "x509" => return Ok(CredentialType::X509),
        _ => {}
    }
    if let Some(value) = name.strip_prefix("other:") {
        return value
            .parse::<u16>()
            .map(CredentialType::Other)
            .map_err(|_| {
                Error::invalid(format!(
                    "credential type {name:?} needs a u16 after the colon"
                ))
            });
    }
    if let Some(value) = name.strip_prefix("grease:") {
        return value
            .parse::<u16>()
            .map(CredentialType::Grease)
            .map_err(|_| {
                Error::invalid(format!(
                    "credential type {name:?} needs a u16 after the colon"
                ))
            });
    }
    Err(Error::invalid(format!(
        "unknown credential type {name:?}; known: basic, x509, other:<u16>, grease:<u16>"
    )))
}

// ---- Device-link cases ------------------------------------------------------

/// One case of `mls/fixtures/device-link.json`.
///
/// Every input is optional at this level and required by the `call` that needs
/// it, so one struct covers four calls without four structs and four
/// deserialisers. `deny_unknown_fields` is deliberately OFF, like the other two
/// case types: `id`, `why`, `kind`, `expect` and `expectError` ride along and
/// are ignored, which is what lets a replay hand the case object over verbatim
/// in every binding instead of stripping keys first.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DeviceLinkCaseJson {
    #[serde(default)]
    #[allow(dead_code)]
    id: Option<String>,
    /// `statement`, `sign`, `verify`, `commitment`, `number`, `qr`,
    /// `qrMatches`, `waiterStep`, `signCommitment`, `verifyCommitment`,
    /// `approverStep`, and the account and key package calls.
    call: String,
    /// `devices.id` of the device being approved.
    device_id: Option<String>,
    /// The approved device's raw public key, hex.
    signing_key_hex: Option<String>,
    /// `sign` only: the APPROVING device's 32-byte seed, hex.
    seed_hex: Option<String>,
    /// `verify` only: the approving device's public key, hex.
    approver_key_hex: Option<String>,
    /// `verify` only: the signature under test, hex.
    signature_hex: Option<String>,
    /// `number` only: the new device's public key, hex. (The approver's is
    /// `approverKeyHex`, shared with `verify`.)
    new_device_key_hex: Option<String>,
    /// `number`: the approver's commitment, hex.
    commitment_hex: Option<String>,
    /// `number`: the new device's nonce, hex.
    device_nonce_hex: Option<String>,
    /// `commitment` and `number`: the approver's nonce, hex.
    approver_nonce_hex: Option<String>,
    /// `qrMatches` only: the text a camera read.
    scanned: Option<String>,
    /// `qr`: the waiting device's 32-byte link secret, hex.
    link_secret_hex: Option<String>,
    /// `waiterStep`: the approver of the exchange on the waiting device's row.
    /// (Its key is `approverKeyHex` and its commitment `commitmentHex`.)
    approver_device_id: Option<String>,
    /// `waiterStep`: what the pairing is bound to. Absent (or empty) is a
    /// pairing that has answered nothing yet.
    bound_approver_device_id: Option<String>,
    /// `waiterStep`: the approver key the pairing bound, hex.
    bound_approver_key_hex: Option<String>,
    /// `waiterStep`: the commitment the pairing answered, hex.
    bound_commitment_hex: Option<String>,
    /// `accountIdentity` and `signAccountDevice`: the 32-byte ACCOUNT key
    /// (the account store's secret), hex.
    account_secret_hex: Option<String>,
    /// `verifyAccountDevice`: the account's public identity key, hex.
    account_key_hex: Option<String>,
    /// `installRevocationTargets`: the removal or denial, the revoking
    /// install's own row ids, and the device list as this device judged it.
    #[serde(default)]
    request: Option<crate::revocation::InstallRevocationRequest>,
    /// `approverStep`: the waiting row's key the prompt was opened for, hex.
    pending_key_hex: Option<String>,
    /// `approverStep`: the device nonce this prompt fixed, hex. Absent (or
    /// empty) is a prompt that has fixed nothing yet.
    bound_device_nonce_hex: Option<String>,
    /// `approverStep`: the waiting row's key on this read, hex.
    listed_key_hex: Option<String>,
    /// `approverStep`: the commitment listed for this approver, hex; absent
    /// or empty when the row lists no exchange of ours.
    listed_commitment_hex: Option<String>,
    /// `approverStep`: the device nonce listed, hex; absent or empty for none.
    listed_device_nonce_hex: Option<String>,
    /// `approverStep`: the approver nonce listed, hex; absent or empty for none.
    listed_approver_nonce_hex: Option<String>,
    /// `signLinkKey` and `verifyLinkKey`: the waiting device's 1216-byte
    /// X-Wing link key, hex.
    link_key_hex: Option<String>,

    // ---- `keyPackageIdentity` only ----
    //
    // This call is the one that needs a whole client on each side: a key
    // package can only be produced by a device holding a credential, and the
    // reader's verdict depends on WHOSE keys it trusts and WHAT time it thinks
    // it is. Both are written into the case rather than taken from the
    // machine, for the reason the credential table gives: a fixture whose
    // answers move with the calendar is a fixture that starts failing on a
    // date nobody chose.
    /// The READER's clock, unix seconds.
    now_unix: Option<i64>,
    /// The READER's trusted issuer keys, as 32-byte signing seeds. The first
    /// also mints the reader's own credential, since a client validates its
    /// own leaf before it will open at all.
    #[serde(default)]
    trust: Vec<String>,
    /// The credential the key package's own device carries. Reuses the
    /// credential table's `mint` block verbatim, so the two tables cannot
    /// drift on what a `pdc1` is.
    mint: Option<MintJson>,
    /// The clock of the device that PRODUCED the key package. Defaults to the
    /// credential's `issuedAt`, which is what makes an expired-credential case
    /// writable at all: a device cannot mint a key package against a
    /// credential its own clock says is dead.
    produced_at_unix: Option<i64>,
    /// Literal key package bytes, hex, instead of minting one — the only way
    /// to write the "these are not a key package" case.
    key_package_hex: Option<String>,
    /// What the DIRECTORY claimed this key package's device id was. When
    /// present the verdict carries `matchesClaim`, which is the adder's actual
    /// question: does the package agree with what the server said about it.
    claimed_device_id: Option<String>,
}

/// A device-link verdict, as a case's `expect` writes it and as
/// `evaluate_device_link_case` returns it.
///
/// One struct with optional fields rather than one verdict type per call, and
/// every absent field is omitted rather than written as null — so a `number`
/// case's expected object is exactly `{"number":"47"}` and the whole-object
/// comparison every replay makes has nothing extra to forgive.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct DeviceLinkVerdict {
    /// `statement`: the exact bytes an approving device signs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub statement_hex: Option<String>,
    /// `sign`: the Ed25519 signature over them. Deterministic, which is what
    /// makes a golden signature a real assertion rather than a shape check.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_hex: Option<String>,
    /// `verify`: whether the approval holds. Never an error — see
    /// [`crate::device_link::verify_device_approval`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid: Option<bool>,
    /// `commitment`: the approver's commitment to its nonce.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commitment_hex: Option<String>,
    /// `number`: the two digits.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub number: Option<String>,
    /// `qr`: the text the new device's QR code carries.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub qr: Option<String>,
    /// `qrMatches`, when the code matches: the link secret it carried.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub link_secret_hex: Option<String>,
    /// `waiterStep`: `answer`, `continue`, `ignore` or `interrupted` —
    /// [`crate::device_link::DeviceLinkWaiterStep::as_str`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub waiter_step: Option<String>,
    /// `approverStep`: `commit`, `wait`, `reveal`, `show` or `interrupted` —
    /// [`crate::device_link::DeviceLinkApproverStep::as_str`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approver_step: Option<String>,
    /// `keyPackageIdentity`: the actor the key package's credential names.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor_id: Option<String>,
    /// `keyPackageIdentity`: the device id, read out of the package's own
    /// bytes and not out of whatever served them.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
    /// `keyPackageIdentity`: the leaf's Ed25519 signature key — the value a
    /// caller hands `verify_device_approval` as its `signing_key`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_key_hex: Option<String>,
    /// `keyPackageIdentity`: the account identity key that signed for the
    /// device — what the reader compares with its pin for that actor. Also
    /// `accountIdentity` and `signAccountDevice`'s answer, beside
    /// `signatureHex`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_key_hex: Option<String>,
    /// `keyPackageIdentity`: why the credential did not check out, when it did
    /// not. A VERDICT and not an error, exactly as on a roster.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rejection: Option<String>,
    /// The number beside the name, so a renumbering that left the name alone
    /// is caught too. The same codes `peachy_mls.h` spells out.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rejection_code: Option<u32>,
    /// `keyPackageIdentity` with a `claimedDeviceId`: whether the package
    /// agrees with what the directory said about it. `false` is the whole
    /// point — it is the caller noticing a swap it would otherwise have
    /// signed off on.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub matches_claim: Option<bool>,
    /// `linkKey`: the X-Wing link key a 32-byte seed derives.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub link_key_hex: Option<String>,
    /// `installRevocationTargets`: the row ids whose keys the removal signs,
    /// in list order; empty is "sign nothing".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub targets: Option<Vec<String>>,
}

/// Evaluate one case of `mls/fixtures/device-link.json` and return its verdict
/// as JSON.
///
/// The calls, matching the functions in [`crate::device_link`]:
///
/// | `call` | needs | returns |
/// | --- | --- | --- |
/// | `statement` | `deviceId`, `signingKeyHex` | `{"statementHex":"…"}` |
/// | `sign` | `seedHex`, `deviceId`, `signingKeyHex` | `{"signatureHex":"…"}` |
/// | `verify` | `approverKeyHex`, `deviceId`, `signingKeyHex`, `signatureHex` | `{"valid":true|false}` |
/// | `commitment` | `approverNonceHex` | `{"commitmentHex":"…"}` |
/// | `number` | `newDeviceKeyHex`, `approverKeyHex`, `commitmentHex`, `deviceNonceHex`, `approverNonceHex` | `{"number":"47"}` |
/// | `approverNumber` | the same as `number` | `{"number":"47"}` |
/// | `qr` | `deviceId`, `signingKeyHex`, `linkSecretHex` | `{"qr":"peachy-link:…"}` |
/// | `qrMatches` | `scanned`, `deviceId`, `signingKeyHex` | `{"valid":true,"linkSecretHex":"…"}` or `{"valid":false}` |
/// | `waiterStep` | `approverDeviceId`, `approverKeyHex`, `commitmentHex`, and optionally `boundApproverDeviceId`, `boundApproverKeyHex`, `boundCommitmentHex` | `{"waiterStep":"answer"|"continue"|"ignore"|"interrupted"}` |
/// | `signCommitment` | `seedHex`, `deviceId`, `signingKeyHex` (the waiting device's key), `commitmentHex` | `{"statementHex":"…","signatureHex":"…"}` |
/// | `verifyCommitment` | `approverKeyHex`, `deviceId`, `signingKeyHex`, `commitmentHex`, `signatureHex` | `{"valid":true|false}` |
/// | `approverStep` | `pendingKeyHex`, `commitmentHex`, `listedKeyHex`, and optionally `boundDeviceNonceHex`, `listedCommitmentHex`, `listedDeviceNonceHex`, `listedApproverNonceHex` | `{"approverStep":"commit"|"wait"|"reveal"|"show"|"interrupted"}` |
/// | `linkKey` | `seedHex` (the link key's seed) | `{"linkKeyHex":"…"}` |
/// | `signLinkKey` | `seedHex` (the waiting device's), `deviceId`, `commitmentHex`, `deviceNonceHex`, `linkKeyHex` | `{"statementHex":"…","signatureHex":"…"}` |
/// | `verifyLinkKey` | `signingKeyHex` (the waiting device's key), `deviceId`, `commitmentHex`, `deviceNonceHex`, `linkKeyHex`, `signatureHex` | `{"valid":true|false}` |
/// | `installRevocationTargets` | `request` (`named`, `denying`, `namedWith`, `ownDeviceIds`, `rows` of `id`, `twinOf`, `vouched`, `pinnedTwinOf`, `revokedAt`, `key`; for a PIN restore `restoredSince`, `ownKeys` and `restoreSnapshot`) | `{"targets":["…"]}` |
///
/// and a fifth that is about the same feature and not about the same module —
/// [`crate::group::Client::key_package_identity`], the door that lets a client
/// read the device id and signing key out of a key package instead of taking
/// them from the server that served it:
///
/// | `call` | needs | returns |
/// | --- | --- | --- |
/// | `keyPackageIdentity` | `nowUnix`, `trust`, and a `mint` or a `keyPackageHex` | `{"actorId","deviceId","deviceKeyHex"}` or `{"rejection","rejectionCode"}` |
///
/// It lives in this table rather than in `credentials.json` because it is the
/// second half of one feature: the approval says "this device id with this
/// signing key", and this is where those two values have to come from for the
/// statement to mean anything. A case may add a `claimedDeviceId` — what the
/// directory said — and the verdict then carries `matchesClaim`, which is the
/// adder's real question.
///
/// Every byte string crosses as lower-case hex with no prefix, in both
/// directions. Hex and not base64 because half this table is about LENGTHS —
/// a 31-byte key, a 63-byte signature — and hex is the encoding whose length a
/// reader can count.
///
/// `verify` is the one call that cannot fail: a malformed key, a wrong length
/// and a bad signature all come back as `{"valid":false}`, because a caller
/// that could tell them apart would be holding an oracle. Everything else —
/// an unknown `call`, a missing field, hex that is not hex, a signing key of
/// the wrong length on a `statement` or a `sign` — is
/// [`Error::InvalidArgument`] and is NOT a verdict, exactly as in the other
/// two tables. A case carrying `expectError` is a case that asserts that
/// refusal; the replays read it and the door never sees it.
/// A hex field a `device_link` call cannot do without, named in the refusal.
fn required_hex(case: &DeviceLinkCaseJson, hex: Option<&str>, field: &str) -> Result<Vec<u8>> {
    let hex =
        hex.ok_or_else(|| Error::invalid(format!("a `{}` case needs a `{field}`", case.call)))?;
    hex_bytes(hex, &format!("`{field}`"))
}

fn evaluate_device_link_case(case_json: &str) -> Result<String> {
    let case: DeviceLinkCaseJson = serde_json::from_str(case_json)
        .map_err(|err| Error::invalid(format!("could not read the device link case: {err}")))?;

    let device_id = |case: &DeviceLinkCaseJson| -> Result<String> {
        case.device_id
            .clone()
            .ok_or_else(|| Error::invalid(format!("a `{}` case needs a `deviceId`", case.call)))
    };
    let signing_key = |case: &DeviceLinkCaseJson| -> Result<Vec<u8>> {
        let hex = case.signing_key_hex.as_deref().ok_or_else(|| {
            Error::invalid(format!("a `{}` case needs a `signingKeyHex`", case.call))
        })?;
        hex_bytes(hex, "`signingKeyHex`")
    };

    let account_secret = |case: &DeviceLinkCaseJson| -> Result<Vec<u8>> {
        let hex = case.account_secret_hex.as_deref().ok_or_else(|| {
            Error::invalid(format!(
                "a `{}` case needs an `accountSecretHex`",
                case.call
            ))
        })?;
        hex_bytes(hex, "`accountSecretHex`")
    };

    let verdict = match case.call.as_str() {
        "statement" => DeviceLinkVerdict {
            statement_hex: Some(to_hex(&crate::device_link::device_approval_statement(
                &device_id(&case)?,
                &signing_key(&case)?,
            )?)),
            ..DeviceLinkVerdict::default()
        },
        "sign" => {
            let seed = hex_bytes(
                case.seed_hex
                    .as_deref()
                    .ok_or_else(|| Error::invalid("a `sign` case needs a `seedHex`"))?,
                "`seedHex`",
            )?;
            DeviceLinkVerdict {
                signature_hex: Some(to_hex(&crate::device_link::sign_device_approval(
                    &seed,
                    &device_id(&case)?,
                    &signing_key(&case)?,
                )?)),
                ..DeviceLinkVerdict::default()
            }
        }
        "verify" => {
            let approver = hex_bytes(
                case.approver_key_hex
                    .as_deref()
                    .ok_or_else(|| Error::invalid("a `verify` case needs an `approverKeyHex`"))?,
                "`approverKeyHex`",
            )?;
            let signature = hex_bytes(
                case.signature_hex
                    .as_deref()
                    .ok_or_else(|| Error::invalid("a `verify` case needs a `signatureHex`"))?,
                "`signatureHex`",
            )?;
            // The inputs are read the same way as everywhere else, but the
            // device id and the signing key are NOT required to be usable
            // here: an empty id and a short key are answers this call has,
            // and they are `false`.
            DeviceLinkVerdict {
                valid: Some(crate::device_link::verify_device_approval(
                    &approver,
                    case.device_id.as_deref().unwrap_or_default(),
                    &case
                        .signing_key_hex
                        .as_deref()
                        .map(|hex| hex_bytes(hex, "`signingKeyHex`"))
                        .transpose()?
                        .unwrap_or_default(),
                    &signature,
                )),
                ..DeviceLinkVerdict::default()
            }
        }
        "accountIdentity" => DeviceLinkVerdict {
            account_key_hex: Some(to_hex(
                &crate::account_identity::account_identity_public_key(&account_secret(&case)?)?,
            )),
            ..DeviceLinkVerdict::default()
        },
        "signAccountDevice" => DeviceLinkVerdict {
            signature_hex: Some(to_hex(&crate::account_identity::sign_account_device(
                &account_secret(&case)?,
                &signing_key(&case)?,
            )?)),
            ..DeviceLinkVerdict::default()
        },
        "signDeviceRevocation" => DeviceLinkVerdict {
            signature_hex: Some(to_hex(&crate::revocation::sign_device_revocation(
                &account_secret(&case)?,
                &signing_key(&case)?,
            )?)),
            ..DeviceLinkVerdict::default()
        },
        "installRevocationTargets" => DeviceLinkVerdict {
            targets: Some(crate::revocation::install_revocation_targets(
                case.request.as_ref().ok_or_else(|| {
                    Error::invalid("an `installRevocationTargets` case needs a `request`")
                })?,
            )),
            ..DeviceLinkVerdict::default()
        },
        "verifyDeviceRevocation" => {
            let account = hex_bytes(
                case.account_key_hex.as_deref().ok_or_else(|| {
                    Error::invalid("a `verifyDeviceRevocation` case needs an `accountKeyHex`")
                })?,
                "`accountKeyHex`",
            )?;
            let signature = hex_bytes(
                case.signature_hex.as_deref().ok_or_else(|| {
                    Error::invalid("a `verifyDeviceRevocation` case needs a `signatureHex`")
                })?,
                "`signatureHex`",
            )?;
            DeviceLinkVerdict {
                valid: Some(crate::revocation::verify_device_revocation(
                    &account,
                    &case
                        .signing_key_hex
                        .as_deref()
                        .map(|hex| hex_bytes(hex, "`signingKeyHex`"))
                        .transpose()?
                        .unwrap_or_default(),
                    &signature,
                )),
                ..DeviceLinkVerdict::default()
            }
        }
        "verifyAccountDevice" => {
            let account = hex_bytes(
                case.account_key_hex.as_deref().ok_or_else(|| {
                    Error::invalid("a `verifyAccountDevice` case needs an `accountKeyHex`")
                })?,
                "`accountKeyHex`",
            )?;
            let signature = hex_bytes(
                case.signature_hex.as_deref().ok_or_else(|| {
                    Error::invalid("a `verifyAccountDevice` case needs a `signatureHex`")
                })?,
                "`signatureHex`",
            )?;
            DeviceLinkVerdict {
                valid: Some(crate::account_identity::verify_account_device(
                    &account,
                    &case
                        .signing_key_hex
                        .as_deref()
                        .map(|hex| hex_bytes(hex, "`signingKeyHex`"))
                        .transpose()?
                        .unwrap_or_default(),
                    &signature,
                )),
                ..DeviceLinkVerdict::default()
            }
        }
        "commitment" => {
            let nonce = required_hex(
                &case,
                case.approver_nonce_hex.as_deref(),
                "approverNonceHex",
            )?;
            DeviceLinkVerdict {
                commitment_hex: Some(to_hex(&crate::device_link::device_link_commitment(&nonce)?)),
                ..DeviceLinkVerdict::default()
            }
        }
        "number" | "approverNumber" => {
            let new_key =
                required_hex(&case, case.new_device_key_hex.as_deref(), "newDeviceKeyHex")?;
            let approver = required_hex(&case, case.approver_key_hex.as_deref(), "approverKeyHex")?;
            let commitment = required_hex(&case, case.commitment_hex.as_deref(), "commitmentHex")?;
            let device_nonce =
                required_hex(&case, case.device_nonce_hex.as_deref(), "deviceNonceHex")?;
            let approver_nonce = required_hex(
                &case,
                case.approver_nonce_hex.as_deref(),
                "approverNonceHex",
            )?;
            let derive = if case.call == "number" {
                crate::device_link::device_link_number
            } else {
                crate::device_link::device_link_approver_number
            };
            DeviceLinkVerdict {
                number: Some(derive(
                    &new_key,
                    &approver,
                    &commitment,
                    &device_nonce,
                    &approver_nonce,
                )?),
                ..DeviceLinkVerdict::default()
            }
        }
        "waiterStep" => {
            let approver_id = case
                .approver_device_id
                .clone()
                .ok_or_else(|| Error::invalid("a `waiterStep` case needs an `approverDeviceId`"))?;
            let approver_key =
                required_hex(&case, case.approver_key_hex.as_deref(), "approverKeyHex")?;
            let commitment = required_hex(&case, case.commitment_hex.as_deref(), "commitmentHex")?;
            // The binding is optional as a whole: absent fields are a pairing
            // that has answered nothing, which is exactly what empty means to
            // the function.
            let optional_hex = |hex: Option<&str>, field: &str| -> Result<Vec<u8>> {
                hex.map(|hex| hex_bytes(hex, &format!("`{field}`")))
                    .transpose()
                    .map(Option::unwrap_or_default)
            };
            let bound_key = optional_hex(
                case.bound_approver_key_hex.as_deref(),
                "boundApproverKeyHex",
            )?;
            let bound_commitment =
                optional_hex(case.bound_commitment_hex.as_deref(), "boundCommitmentHex")?;
            DeviceLinkVerdict {
                waiter_step: Some(
                    crate::device_link::device_link_waiter_step(
                        case.bound_approver_device_id.as_deref().unwrap_or_default(),
                        &bound_key,
                        &bound_commitment,
                        &approver_id,
                        &approver_key,
                        &commitment,
                    )?
                    .as_str()
                    .to_string(),
                ),
                ..DeviceLinkVerdict::default()
            }
        }
        "signCommitment" => {
            let seed = required_hex(&case, case.seed_hex.as_deref(), "seedHex")?;
            let commitment = required_hex(&case, case.commitment_hex.as_deref(), "commitmentHex")?;
            let id = device_id(&case)?;
            let key = signing_key(&case)?;
            DeviceLinkVerdict {
                statement_hex: Some(to_hex(
                    &crate::device_link::device_link_commitment_statement(&id, &key, &commitment)?,
                )),
                signature_hex: Some(to_hex(&crate::device_link::sign_device_link_commitment(
                    &seed,
                    &id,
                    &key,
                    &commitment,
                )?)),
                ..DeviceLinkVerdict::default()
            }
        }
        "verifyCommitment" => {
            // Like `verify`: never a refusal over the inputs it judges.
            let optional = |hex: Option<&str>, field: &str| -> Result<Vec<u8>> {
                hex.map(|hex| hex_bytes(hex, &format!("`{field}`")))
                    .transpose()
                    .map(Option::unwrap_or_default)
            };
            DeviceLinkVerdict {
                valid: Some(crate::device_link::verify_device_link_commitment(
                    &required_hex(&case, case.approver_key_hex.as_deref(), "approverKeyHex")?,
                    case.device_id.as_deref().unwrap_or_default(),
                    &optional(case.signing_key_hex.as_deref(), "signingKeyHex")?,
                    &optional(case.commitment_hex.as_deref(), "commitmentHex")?,
                    &required_hex(&case, case.signature_hex.as_deref(), "signatureHex")?,
                )),
                ..DeviceLinkVerdict::default()
            }
        }
        "approverStep" => {
            let optional = |hex: Option<&str>, field: &str| -> Result<Vec<u8>> {
                hex.map(|hex| hex_bytes(hex, &format!("`{field}`")))
                    .transpose()
                    .map(Option::unwrap_or_default)
            };
            DeviceLinkVerdict {
                approver_step: Some(
                    crate::device_link::device_link_approver_step(
                        &required_hex(&case, case.pending_key_hex.as_deref(), "pendingKeyHex")?,
                        &required_hex(&case, case.commitment_hex.as_deref(), "commitmentHex")?,
                        &optional(case.bound_device_nonce_hex.as_deref(), "boundDeviceNonceHex")?,
                        &required_hex(&case, case.listed_key_hex.as_deref(), "listedKeyHex")?,
                        &optional(case.listed_commitment_hex.as_deref(), "listedCommitmentHex")?,
                        &optional(case.listed_device_nonce_hex.as_deref(), "listedDeviceNonceHex")?,
                        &optional(
                            case.listed_approver_nonce_hex.as_deref(),
                            "listedApproverNonceHex",
                        )?,
                    )?
                    .as_str()
                    .to_string(),
                ),
                ..DeviceLinkVerdict::default()
            }
        }
        "qr" => DeviceLinkVerdict {
            qr: Some(crate::device_link::device_link_qr(
                &device_id(&case)?,
                &signing_key(&case)?,
                &required_hex(&case, case.link_secret_hex.as_deref(), "linkSecretHex")?,
            )?),
            ..DeviceLinkVerdict::default()
        },
        "qrMatches" => {
            let scanned = case
                .scanned
                .clone()
                .ok_or_else(|| Error::invalid("a `qrMatches` case needs a `scanned`"))?;
            let secret = crate::device_link::device_link_qr_secret(
                &scanned,
                case.device_id.as_deref().unwrap_or_default(),
                &case
                    .signing_key_hex
                    .as_deref()
                    .map(|hex| hex_bytes(hex, "`signingKeyHex`"))
                    .transpose()?
                    .unwrap_or_default(),
            );
            DeviceLinkVerdict {
                valid: Some(secret.is_some()),
                link_secret_hex: secret.map(|secret| to_hex(&secret)),
                ..DeviceLinkVerdict::default()
            }
        }
        "linkKey" => DeviceLinkVerdict {
            link_key_hex: Some(to_hex(&crate::device_link::device_link_kem_public_key(
                &required_hex(&case, case.seed_hex.as_deref(), "seedHex")?,
            )?)),
            ..DeviceLinkVerdict::default()
        },
        "signLinkKey" => {
            let seed = required_hex(&case, case.seed_hex.as_deref(), "seedHex")?;
            let commitment = required_hex(&case, case.commitment_hex.as_deref(), "commitmentHex")?;
            let nonce = required_hex(&case, case.device_nonce_hex.as_deref(), "deviceNonceHex")?;
            let link_key = required_hex(&case, case.link_key_hex.as_deref(), "linkKeyHex")?;
            let id = device_id(&case)?;
            DeviceLinkVerdict {
                statement_hex: Some(to_hex(&crate::device_link::device_link_kem_statement(
                    &id,
                    &commitment,
                    &nonce,
                    &link_key,
                )?)),
                signature_hex: Some(to_hex(&crate::device_link::sign_device_link_kem(
                    &seed,
                    &id,
                    &commitment,
                    &nonce,
                    &link_key,
                )?)),
                ..DeviceLinkVerdict::default()
            }
        }
        "verifyLinkKey" => {
            // Like `verify`: never a refusal over the inputs it judges.
            let optional = |hex: Option<&str>, field: &str| -> Result<Vec<u8>> {
                hex.map(|hex| hex_bytes(hex, &format!("`{field}`")))
                    .transpose()
                    .map(Option::unwrap_or_default)
            };
            DeviceLinkVerdict {
                valid: Some(crate::device_link::verify_device_link_kem(
                    &required_hex(&case, case.signing_key_hex.as_deref(), "signingKeyHex")?,
                    case.device_id.as_deref().unwrap_or_default(),
                    &optional(case.commitment_hex.as_deref(), "commitmentHex")?,
                    &optional(case.device_nonce_hex.as_deref(), "deviceNonceHex")?,
                    &optional(case.link_key_hex.as_deref(), "linkKeyHex")?,
                    &required_hex(&case, case.signature_hex.as_deref(), "signatureHex")?,
                )),
                ..DeviceLinkVerdict::default()
            }
        }
        "keyPackageIdentity" => evaluate_key_package_identity_case(&case)?,
        other => {
            return Err(Error::invalid(format!(
                "unknown call {other:?}; known: statement, sign, verify, commitment, number, \
                 approverNumber, qr, qrMatches, accountIdentity, signAccountDevice, verifyAccountDevice, \
                 signDeviceRevocation, verifyDeviceRevocation, keyPackageIdentity, waiterStep, signCommitment, verifyCommitment, approverStep, \
                 linkKey, signLinkKey, verifyLinkKey, installRevocationTargets"
            )))
        }
    };

    serde_json::to_string(&verdict)
        .map_err(|err| Error::invalid(format!("could not write the verdict: {err}")))
}

// ---- Join-request cases -----------------------------------------------------

/// How a `verify` case's proof is made: signed here from a seed, so the file
/// stays readable, or written out literally for the shapes a signer cannot
/// produce.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct JoinProofJson {
    /// The 32-byte seed that SIGNS. The asker's own for an honest request,
    /// somebody else's for a forgery.
    seed_hex: String,
    /// What the signer signed, each defaulting to the case's own value, so a
    /// case only writes the part it lies about.
    group_id: Option<String>,
    actor_id: Option<String>,
    device_id: Option<String>,
    issued_at: i64,
    nonce_hex: String,
}

/// One case of `mls/fixtures/join-request.json`. The same conventions as
/// [`DeviceLinkCaseJson`]: every input optional here and required by the
/// `call` that reads it, byte strings as lower-case hex, and `id`, `why`,
/// `kind`, `expect` and `expectError` riding along ignored.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct JoinRequestCaseJson {
    /// `statement`, `sign`, `verify` or `roundTrip`.
    call: String,
    /// The group the request is for, as UTF-8 (a Peachy group id is a uuid).
    group_id: Option<String>,
    actor_id: Option<String>,
    device_id: Option<String>,
    issued_at: Option<i64>,
    nonce_hex: Option<String>,
    /// `sign`: the asker's 32-byte seed.
    seed_hex: Option<String>,
    /// `verify`, `roundTrip`: the VERIFIER's clock.
    now_unix: Option<i64>,
    /// `verify`, `roundTrip`: the verifier's trusted issuer seeds.
    #[serde(default)]
    trust: Vec<String>,
    /// `verify`, `roundTrip`: the asker's credential, from which the asker's
    /// key package is produced exactly as a device would.
    mint: Option<MintJson>,
    /// `verify`: literal key package bytes instead of a minted one.
    key_package_hex: Option<String>,
    /// `verify`: how the proof is made.
    proof: Option<JoinProofJson>,
    /// `verify`: a literal proof instead.
    proof_hex: Option<String>,
    /// `roundTrip`: the ASKER's clock when it signs.
    signed_at_unix: Option<i64>,
    /// `verify`, `roundTrip`: the people the reader is still trying to add
    /// ([`crate::group::Client::verify_join_request`]'s escape hatch). The
    /// reader holds no copy of the group, so anybody not named here is
    /// `not_a_member`.
    #[serde(default)]
    pending_actors: Vec<String>,
}

/// A join-request verdict, as a case's `expect` writes it. Absent fields are
/// omitted, so every call's expected object is exactly its own shape.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct JoinRequestCaseVerdict {
    /// `statement`: the exact bytes signed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub statement_hex: Option<String>,
    /// `sign`: the 89-byte proof.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof_hex: Option<String>,
    /// `verify`, `roundTrip`: the verdict's name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verdict: Option<String>,
    /// `verify`, `roundTrip`: its number.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verdict_code: Option<u32>,
}

impl JoinRequestCaseVerdict {
    fn of(verdict: crate::join_request::JoinRequestVerdict) -> Self {
        Self {
            verdict: Some(verdict.name().to_string()),
            verdict_code: Some(verdict.code()),
            ..Self::default()
        }
    }
}

/// Evaluate one case of `mls/fixtures/join-request.json` and return its verdict
/// as JSON.
///
/// | `call` | needs | returns |
/// | --- | --- | --- |
/// | `statement` | `groupId`, `actorId`, `deviceId`, `issuedAt`, `nonceHex` | `{"statementHex"}` |
/// | `sign` | the same and `seedHex` | `{"proofHex"}` |
/// | `verify` | `nowUnix`, `trust`, a `mint` or `keyPackageHex`, `groupId`, `actorId`, `deviceId`, a `proof` or `proofHex` | `{"verdict","verdictCode"}` |
/// | `roundTrip` | `nowUnix`, `trust`, `mint`, `groupId`, optional `signedAtUnix` | `{"verdict","verdictCode"}` |
///
/// `verify` is [`crate::group::Client::verify_join_request`], the door a
/// client calls, run by a reader that trusts the case's keys at the case's
/// clock. `roundTrip` has the asker's own client sign through
/// [`crate::group::Client::sign_join_request`] (a random nonce, its own clock)
/// and the reader verify it: the one call whose bytes cannot be pinned, and so
/// the one that proves the two doors agree.
fn evaluate_join_request_case(case_json: &str) -> Result<String> {
    let case: JoinRequestCaseJson = serde_json::from_str(case_json)
        .map_err(|err| Error::invalid(format!("could not read the join request case: {err}")))?;
    let need_str = |value: &Option<String>, name: &str| -> Result<String> {
        value
            .clone()
            .ok_or_else(|| Error::invalid(format!("a `{}` case needs a `{name}`", case.call)))
    };
    let need_i64 = |value: Option<i64>, name: &str| -> Result<i64> {
        value.ok_or_else(|| Error::invalid(format!("a `{}` case needs a `{name}`", case.call)))
    };

    // The reader holds no copy of the group, so the asker counts as a member
    // only when the case names them among the people the reader is trying to
    // add: the people the reader itself invited.
    let pending: Vec<&str> = case.pending_actors.iter().map(String::as_str).collect();
    let verdict = match case.call.as_str() {
        "statement" => JoinRequestCaseVerdict {
            statement_hex: Some(to_hex(&crate::join_request::join_request_statement(
                need_str(&case.group_id, "groupId")?.as_bytes(),
                &need_str(&case.actor_id, "actorId")?,
                &need_str(&case.device_id, "deviceId")?,
                need_i64(case.issued_at, "issuedAt")?,
                &hex_bytes(&need_str(&case.nonce_hex, "nonceHex")?, "`nonceHex`")?,
            )?)),
            ..JoinRequestCaseVerdict::default()
        },
        "sign" => JoinRequestCaseVerdict {
            proof_hex: Some(to_hex(&crate::join_request::sign_join_request(
                &hex_bytes(&need_str(&case.seed_hex, "seedHex")?, "`seedHex`")?,
                need_str(&case.group_id, "groupId")?.as_bytes(),
                &need_str(&case.actor_id, "actorId")?,
                &need_str(&case.device_id, "deviceId")?,
                need_i64(case.issued_at, "issuedAt")?,
                &hex_bytes(&need_str(&case.nonce_hex, "nonceHex")?, "`nonceHex`")?,
            )?)),
            ..JoinRequestCaseVerdict::default()
        },
        "verify" => {
            let now = need_i64(case.now_unix, "nowUnix")?;
            let group_id = need_str(&case.group_id, "groupId")?;
            let actor_id = need_str(&case.actor_id, "actorId")?;
            let device_id = need_str(&case.device_id, "deviceId")?;
            let key_package = match (&case.mint, &case.key_package_hex) {
                (Some(mint), None) => produce_key_package(mint, None)?,
                (None, Some(literal)) => hex_bytes(literal, "`keyPackageHex`")?,
                _ => {
                    return Err(Error::invalid(
                        "a `verify` case takes exactly one of `mint` and `keyPackageHex`",
                    ))
                }
            };
            let proof = match (&case.proof, &case.proof_hex) {
                (Some(p), None) => crate::join_request::sign_join_request(
                    &hex_bytes(&p.seed_hex, "`proof.seedHex`")?,
                    p.group_id.as_deref().unwrap_or(&group_id).as_bytes(),
                    p.actor_id.as_deref().unwrap_or(&actor_id),
                    p.device_id.as_deref().unwrap_or(&device_id),
                    p.issued_at,
                    &hex_bytes(&p.nonce_hex, "`proof.nonceHex`")?,
                )?,
                (None, Some(literal)) => hex_bytes(literal, "`proofHex`")?,
                _ => {
                    return Err(Error::invalid(
                        "a `verify` case takes exactly one of `proof` and `proofHex`",
                    ))
                }
            };
            let reader = open_reader(&case.trust, now)?;
            JoinRequestCaseVerdict::of(reader.verify_join_request(
                group_id.as_bytes(),
                &actor_id,
                &device_id,
                &proof,
                &key_package,
                &pending,
            ))
        }
        "roundTrip" => {
            let now = need_i64(case.now_unix, "nowUnix")?;
            let group_id = need_str(&case.group_id, "groupId")?;
            let mint = case
                .mint
                .as_ref()
                .ok_or_else(|| Error::invalid("a `roundTrip` case needs a `mint`"))?;
            let signer = TestIssuer::from_seed(&seed32(&mint.signer_seed, "`signerSeed`")?);
            let (token, _) = mint_token(mint)?;
            let asker = crate::group::Client::new(crate::group::ClientConfig {
                clock: Some(Box::new(FixedClock(case.signed_at_unix.unwrap_or(now)))),
                ..crate::group::ClientConfig::new(
                    token,
                    seed32(&mint.device_seed, "`deviceSeed`")?,
                    signer.trusted_keys()?,
                )
                .with_own_account_identity(held_by(mint)?)
            })?;
            let proof = asker.sign_join_request(group_id.as_bytes())?;
            let key_package = asker.generate_key_package()?;
            let reader = open_reader(&case.trust, now)?;
            JoinRequestCaseVerdict::of(reader.verify_join_request(
                group_id.as_bytes(),
                &mint.actor_id,
                &mint.device_id,
                &proof,
                &key_package,
                &pending,
            ))
        }
        other => {
            return Err(Error::invalid(format!(
                "unknown call {other:?}; known: statement, sign, verify, roundTrip"
            )))
        }
    };

    serde_json::to_string(&verdict)
        .map_err(|err| Error::invalid(format!("could not write the verdict: {err}")))
}

// ---- Account-store cases ----------------------------------------------------

/// One case of `mls/fixtures/account-store.json`. The same conventions as
/// [`DeviceLinkCaseJson`]: every input optional here and required by the
/// `call` that reads it, byte strings as lower-case hex, and `id`, `why`,
/// `kind`, `expect` and `expectError` riding along ignored.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AccountStoreCaseJson {
    /// `recordKey`, `storeOpen`, `boxOpen`, `boxAccept`, `boxAcceptHybrid`,
    /// `noteSender`, `noteOpenSigned` or `transferKeyOpen`.
    call: String,
    /// `recordKey`, `storeOpen`: the 32-byte account key.
    account_key_hex: Option<String>,
    /// `recordKey`, `storeOpen`: the record id (16 bytes, or not — the
    /// refusals are half the table).
    id_hex: Option<String>,
    /// `storeOpen`: the sealed value.
    value_hex: Option<String>,
    /// `boxOpen`: the RECIPIENT device's 32-byte Ed25519 seed.
    recipient_seed_hex: Option<String>,
    /// `boxOpen`: the approving device's public key.
    approver_key_hex: Option<String>,
    /// `boxOpen`: the recipient's `devices.id`.
    device_id: Option<String>,
    /// `boxOpen`: the 93-byte box.
    box_hex: Option<String>,
    /// `boxAccept`: the link secret this device's QR code showed, hex. Absent
    /// is none.
    link_secret_hex: Option<String>,
    /// `boxAccept`: the approver key the person confirmed by its number, hex.
    /// Absent is none.
    confirmed_approver_key_hex: Option<String>,
    /// `boxAccept`: the device's own switch for server-run approvals.
    #[serde(default)]
    server_approval_allowed: bool,
    /// `noteOpenSigned`: the 32-byte public key the receiver's device list
    /// gives the sender (`deviceId`).
    sender_key_hex: Option<String>,
    /// `noteOpenSigned`: the receiver's clock, unix milliseconds.
    now_ms: Option<i64>,
    /// `boxAcceptHybrid`: the seed of the link key this device posted, hex.
    /// Absent is none.
    link_key_seed_hex: Option<String>,
}

/// An account-store verdict. One field per call, the others omitted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct AccountStoreVerdict {
    /// `recordKey`: `k(id)`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_hex: Option<String>,
    /// `storeOpen`: the plaintext, unpadded.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plaintext_hex: Option<String>,
    /// `boxOpen`: the 32-byte account key.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_key_hex: Option<String>,
    /// `noteSender`: the device a signed note says sent it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sender_device_id: Option<String>,
    /// `transferKeyOpen`: the 32-byte attachment key.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transfer_key_hex: Option<String>,
}

/// Evaluate one case of `mls/fixtures/account-store.json`.
///
/// | `call` | needs | returns |
/// | --- | --- | --- |
/// | `recordKey` | `accountKeyHex`, `idHex` | `{"keyHex":"…"}` |
/// | `storeOpen` | `accountKeyHex`, `idHex`, `valueHex` | `{"plaintextHex":"…"}` |
/// | `boxOpen` | `recipientSeedHex`, `approverKeyHex`, `deviceId`, `boxHex` | `{"accountKeyHex":"…"}` |
/// | `boxAccept` | `boxOpen`'s, and optionally `linkSecretHex`, `confirmedApproverKeyHex`, `serverApprovalAllowed` | `{"accountKeyHex":"…"}` |
/// | `boxAcceptHybrid` | `boxOpen`'s, and optionally `linkKeySeedHex`, `confirmedApproverKeyHex`, `serverApprovalAllowed` | `{"accountKeyHex":"…"}` |
/// | `noteSender` | `accountKeyHex`, `idHex`, `valueHex` | `{"senderDeviceId":"…"}` |
/// | `noteOpenSigned` | `noteSender`'s, `deviceId` (the sender), `senderKeyHex`, `nowMs` | `{"plaintextHex":"…"}` |
/// | `transferKeyOpen` | `recipientSeedHex`, `deviceId`, `boxHex` | `{"transferKeyHex":"…"}` |
///
/// Only the OPENING side is here. Sealing takes a fresh nonce (and, for a
/// box, a fresh ephemeral) every time, so a sealed value is not a golden
/// value; what four clients must agree on is what a given value opens to, and
/// that every wrong input is refused. Every refusal is
/// [`Error::InvalidArgument`] and a case carrying `expectError` asserts it.
fn evaluate_account_store_case(case_json: &str) -> Result<String> {
    let case: AccountStoreCaseJson = serde_json::from_str(case_json)
        .map_err(|err| Error::invalid(format!("could not read the account store case: {err}")))?;

    let field = |value: &Option<String>, name: &str| -> Result<Vec<u8>> {
        let hex = value
            .as_deref()
            .ok_or_else(|| Error::invalid(format!("a `{}` case needs a `{name}`", case.call)))?;
        hex_bytes(hex, &format!("`{name}`"))
    };

    let verdict = match case.call.as_str() {
        "recordKey" => AccountStoreVerdict {
            key_hex: Some(to_hex(&crate::account_store::record_key(
                &field(&case.account_key_hex, "accountKeyHex")?,
                &field(&case.id_hex, "idHex")?,
            )?)),
            ..AccountStoreVerdict::default()
        },
        "noteSender" => AccountStoreVerdict {
            sender_device_id: Some(crate::account_store::note_sender(
                &field(&case.account_key_hex, "accountKeyHex")?,
                &field(&case.id_hex, "idHex")?,
                &field(&case.value_hex, "valueHex")?,
            )?),
            ..AccountStoreVerdict::default()
        },
        "noteOpenSigned" => {
            let sender = case
                .device_id
                .clone()
                .ok_or_else(|| Error::invalid("a `noteOpenSigned` case needs a `deviceId`"))?;
            let now_ms = case
                .now_ms
                .ok_or_else(|| Error::invalid("a `noteOpenSigned` case needs a `nowMs`"))?;
            AccountStoreVerdict {
                plaintext_hex: Some(to_hex(&crate::account_store::note_open_signed(
                    &field(&case.account_key_hex, "accountKeyHex")?,
                    &field(&case.id_hex, "idHex")?,
                    &field(&case.value_hex, "valueHex")?,
                    &sender,
                    &field(&case.sender_key_hex, "senderKeyHex")?,
                    now_ms,
                )?)),
                ..AccountStoreVerdict::default()
            }
        }
        "storeOpen" => AccountStoreVerdict {
            plaintext_hex: Some(to_hex(&crate::account_store::store_open(
                &field(&case.account_key_hex, "accountKeyHex")?,
                &field(&case.id_hex, "idHex")?,
                &field(&case.value_hex, "valueHex")?,
            )?)),
            ..AccountStoreVerdict::default()
        },
        "boxAccept" => {
            let device_id = case
                .device_id
                .clone()
                .ok_or_else(|| Error::invalid("a `boxAccept` case needs a `deviceId`"))?;
            let optional = |value: &Option<String>, name: &str| -> Result<Vec<u8>> {
                value
                    .as_deref()
                    .map(|hex| hex_bytes(hex, &format!("`{name}`")))
                    .transpose()
                    .map(Option::unwrap_or_default)
            };
            AccountStoreVerdict {
                account_key_hex: Some(to_hex(&crate::account_store::account_key_accept(
                    &field(&case.recipient_seed_hex, "recipientSeedHex")?,
                    &field(&case.approver_key_hex, "approverKeyHex")?,
                    &device_id,
                    &field(&case.box_hex, "boxHex")?,
                    &optional(&case.link_secret_hex, "linkSecretHex")?,
                    &optional(&case.confirmed_approver_key_hex, "confirmedApproverKeyHex")?,
                    case.server_approval_allowed,
                )?)),
                ..AccountStoreVerdict::default()
            }
        }
        "boxAcceptHybrid" => {
            let device_id = case
                .device_id
                .clone()
                .ok_or_else(|| Error::invalid("a `boxAcceptHybrid` case needs a `deviceId`"))?;
            let optional = |value: &Option<String>, name: &str| -> Result<Vec<u8>> {
                value
                    .as_deref()
                    .map(|hex| hex_bytes(hex, &format!("`{name}`")))
                    .transpose()
                    .map(Option::unwrap_or_default)
            };
            AccountStoreVerdict {
                account_key_hex: Some(to_hex(&crate::account_store::account_key_accept_hybrid(
                    &field(&case.recipient_seed_hex, "recipientSeedHex")?,
                    &field(&case.approver_key_hex, "approverKeyHex")?,
                    &device_id,
                    &field(&case.box_hex, "boxHex")?,
                    &optional(&case.link_key_seed_hex, "linkKeySeedHex")?,
                    &optional(&case.confirmed_approver_key_hex, "confirmedApproverKeyHex")?,
                    case.server_approval_allowed,
                )?)),
                ..AccountStoreVerdict::default()
            }
        }
        "transferKeyOpen" => {
            let device_id = case
                .device_id
                .clone()
                .ok_or_else(|| Error::invalid("a `transferKeyOpen` case needs a `deviceId`"))?;
            AccountStoreVerdict {
                transfer_key_hex: Some(to_hex(&crate::account_store::transfer_key_open(
                    &field(&case.recipient_seed_hex, "recipientSeedHex")?,
                    &device_id,
                    &field(&case.box_hex, "boxHex")?,
                )?)),
                ..AccountStoreVerdict::default()
            }
        }
        "boxOpen" => {
            let device_id = case
                .device_id
                .clone()
                .ok_or_else(|| Error::invalid("a `boxOpen` case needs a `deviceId`"))?;
            AccountStoreVerdict {
                account_key_hex: Some(to_hex(&crate::account_store::account_key_open(
                    &field(&case.recipient_seed_hex, "recipientSeedHex")?,
                    &field(&case.approver_key_hex, "approverKeyHex")?,
                    &device_id,
                    &field(&case.box_hex, "boxHex")?,
                )?)),
                ..AccountStoreVerdict::default()
            }
        }
        other => {
            return Err(Error::invalid(format!(
                "unknown call {other:?}; known: recordKey, storeOpen, boxOpen, boxAccept, boxAcceptHybrid, \
                 noteSender, noteOpenSigned, transferKeyOpen"
            )))
        }
    };

    serde_json::to_string(&verdict)
        .map_err(|err| Error::invalid(format!("could not write the verdict: {err}")))
}

/// The `keyPackageIdentity` half of [`evaluate_device_link_case`]: build a real
/// key package, hand a real reader its raw bytes, and report what the reader
/// read out of them.
///
/// Two clients, deliberately. A key package only exists because some device
/// with a credential produced one, and the question this call answers is what a
/// DIFFERENT device — with its own trusted keys and its own clock — makes of the
/// bytes. Collapsing them into one would make every case say "a device believes
/// itself", which is not the question anybody is asking.
///
/// The reader's own credential is minted from the FIRST `trust` seed, because a
/// client validates its own leaf before it will open at all. That is plumbing
/// and not part of what any case asserts: no verdict mentions the reader.
fn evaluate_key_package_identity_case(case: &DeviceLinkCaseJson) -> Result<DeviceLinkVerdict> {
    let now = case.now_unix.ok_or_else(|| {
        Error::invalid("a `keyPackageIdentity` case needs a `nowUnix` — the READER's clock")
    })?;

    // The bytes under test: either a key package a real device really
    // produced, or whatever literal the case wrote.
    let key_package = match (&case.mint, &case.key_package_hex) {
        (Some(mint), None) => produce_key_package(mint, case.produced_at_unix)?,
        (None, Some(literal)) => hex_bytes(literal, "`keyPackageHex`")?,
        (Some(_), Some(_)) => {
            return Err(Error::invalid(
                "a `keyPackageIdentity` case takes a `mint` or a `keyPackageHex`, never both",
            ))
        }
        (None, None) => {
            return Err(Error::invalid(
                "a `keyPackageIdentity` case needs a `mint` or a `keyPackageHex`",
            ))
        }
    };

    let reader = open_reader(&case.trust, now)?;
    let verdict = reader.key_package_identity(&key_package)?;

    Ok(match verdict {
        Ok(identity) => DeviceLinkVerdict {
            actor_id: Some(identity.actor_id.clone()),
            device_id: Some(identity.device_id.clone()),
            device_key_hex: Some(to_hex(&identity.device_key)),
            account_key_hex: identity.account_key.map(|key| to_hex(&key)),
            // Present only when the case supplied a claim, so an ordinary read
            // keeps the three-field verdict it would otherwise have.
            matches_claim: case
                .claimed_device_id
                .as_deref()
                .map(|claimed| claimed == identity.device_id),
            ..DeviceLinkVerdict::default()
        },
        Err(rejection) => DeviceLinkVerdict {
            rejection: Some(rejection.name().to_string()),
            rejection_code: Some(rejection.code()),
            // A rejected package answers the claim question too, and the
            // answer is `false`: nothing was read, so nothing agrees with
            // anything. Saying `true` here would be the worst possible bug in
            // this table.
            matches_claim: case.claimed_device_id.as_ref().map(|_| false),
            ..DeviceLinkVerdict::default()
        },
    })
}

/// Produce a real key package from a real device holding the case's minted
/// credential.
///
/// The producing client's clock defaults to the credential's `issuedAt` rather
/// than to the reader's `nowUnix`, and that default is what makes an
/// expired-credential case writable: a device cannot build a key package
/// against a credential its own clock says is already dead, so the two halves
/// of "issued in March, read in July" need two clocks.
fn produce_key_package(mint: &MintJson, produced_at: Option<i64>) -> Result<Vec<u8>> {
    let signer = TestIssuer::from_seed(&seed32(&mint.signer_seed, "`signerSeed`")?);
    let (token, _) = mint_token(mint)?;
    let client = crate::group::Client::new(crate::group::ClientConfig {
        clock: Some(Box::new(FixedClock(produced_at.unwrap_or(mint.issued_at)))),
        ..crate::group::ClientConfig::new(
            token,
            seed32(&mint.device_seed, "`deviceSeed`")?,
            signer.trusted_keys()?,
        )
        .with_own_account_identity(held_by(mint)?)
    })?;
    // A mint with no `accountKey` is a device its account never let in, and
    // no honest client makes a key package for one; the fixture forges it so
    // a case can show every reader refusing it.
    if mint.account_key.is_none() {
        return client.forge_unapproved_key_package();
    }
    client.generate_key_package()
}

/// The account identity key the device a `mint` describes holds: the one its
/// `accountKey` derives, or none for a device its account never let in. A
/// device holding no key refuses any certified credential of its own, so a
/// fixture that opens a client on a certified mint names this, as every
/// product client names the key it holds.
fn held_by(mint: &MintJson) -> Result<Option<[u8; 32]>> {
    mint.account_key
        .as_deref()
        .map(|hex| {
            crate::account_identity::account_identity_public_key(&seed32(hex, "`accountKey`")?)
        })
        .transpose()
}

/// The reader: a client that trusts exactly the case's `trust` keys and
/// believes it is `now`.
///
/// Its own identity is fixed and never asserted on. What varies between cases
/// is what it TRUSTS and when it thinks it is, because those are the two
/// inputs that turn the same bytes into an acceptance, an `unknown_kid` or an
/// `expired`.
fn open_reader(trust: &[String], now: i64) -> Result<crate::group::Client> {
    let first = trust.first().ok_or_else(|| {
        Error::invalid(
            "a `keyPackageIdentity` case needs at least one `trust` seed: a client validates \
             its own credential before it will open, so a reader that trusts nobody cannot \
             exist to read anything",
        )
    })?;
    let issuer = TestIssuer::from_seed(&seed32(first, "a `trust` entry")?);

    let mut trusted = TrustedServerKeys::new();
    for seed in trust {
        let entry = TestIssuer::from_seed(&seed32(seed, "a `trust` entry")?);
        trusted.insert(entry.kid().to_string(), &entry.public_key())?;
    }

    const READER_SEED: [u8; 32] = [0xEE; 32];
    let (_, reader_key) = device_key_pair(&READER_SEED);
    let credential = issuer.issue(
        "actor-the-reader",
        "device-the-reader",
        &reader_key,
        now - 3600,
        now + 3600,
    )?;

    let held = crate::account_identity::account_identity_public_key(
        &TestIssuer::test_account_key("actor-the-reader"),
    )?;
    crate::group::Client::new(crate::group::ClientConfig {
        clock: Some(Box::new(FixedClock(now))),
        ..crate::group::ClientConfig::new(credential, READER_SEED, trusted)
            .with_own_account_identity(Some(held))
    })
}

/// Read a 32-byte seed written as 64 hex characters.
///
/// Hand-rolled rather than through the `hex` crate, which is a dev-dependency
/// here and would have to become a real one to be reachable from a feature the
/// bindings turn on. Sixteen lines against a dependency in three build
/// systems is the cheaper side of that trade.
fn seed32(hex: &str, field: &str) -> Result<[u8; 32]> {
    let digits = hex.as_bytes();
    if digits.len() != 64 {
        return Err(Error::invalid(format!(
            "{field} must be 64 hex characters (a 32-byte seed), got {}",
            digits.len()
        )));
    }
    let mut seed = [0u8; 32];
    for (index, pair) in digits.chunks(2).enumerate() {
        let high = hex_digit(pair.first().copied(), field, hex)?;
        let low = hex_digit(pair.get(1).copied(), field, hex)?;
        if let Some(slot) = seed.get_mut(index) {
            *slot = high * 16 + low;
        }
    }
    Ok(seed)
}

/// Read a byte string written as an even number of hex characters, of
/// whatever length the case wrote.
///
/// [`seed32`]'s sibling, and separate from it on purpose: a seed is 32 bytes
/// or it is a case-author mistake, whereas half the device-link table is ABOUT
/// lengths — a 31-byte key, a 63-byte signature — and a reader that insisted
/// on 32 could not express them.
fn hex_bytes(hex: &str, field: &str) -> Result<Vec<u8>> {
    let digits = hex.as_bytes();
    if !digits.len().is_multiple_of(2) {
        return Err(Error::invalid(format!(
            "{field} must be an even number of hex characters, got {}",
            digits.len()
        )));
    }
    let mut bytes = Vec::with_capacity(digits.len() / 2);
    for pair in digits.chunks(2) {
        let high = hex_digit(pair.first().copied(), field, hex)?;
        let low = hex_digit(pair.get(1).copied(), field, hex)?;
        bytes.push(high * 16 + low);
    }
    Ok(bytes)
}

/// Lower-case hex, no prefix — how every byte string is written on this
/// fixture's wire.
fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn hex_digit(byte: Option<u8>, field: &str, whole: &str) -> Result<u8> {
    match byte {
        Some(digit @ b'0'..=b'9') => Ok(digit - b'0'),
        Some(digit @ b'a'..=b'f') => Ok(digit - b'a' + 10),
        Some(digit @ b'A'..=b'F') => Ok(digit - b'A' + 10),
        _ => Err(Error::invalid(format!("{field} is not hex: {whole:?}"))),
    }
}

#[cfg(test)]
// The crate denies `expect` at lint level, and means it — for the LIBRARY. A
// test that cannot proceed should stop on the line that failed, with the
// sentence explaining what it wanted; threading a `Result` through an assertion
// buys nothing and hides which call gave up.
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn an_allow_carries_no_reason() {
        let out = evaluate_case_json(
            r#"{"call":"evaluate","proposal":{"kind":"add","sender":"member"}}"#,
        )
        .expect("a member's add evaluates");
        assert_eq!(out, r#"{"decision":"allow"}"#);
    }

    #[test]
    fn a_denial_carries_both_the_name_and_the_number() {
        let out = evaluate_case_json(
            r#"{"call":"evaluate","proposal":{"kind":"reinit","sender":"member"}}"#,
        )
        .expect("a reinit evaluates");
        assert_eq!(
            out,
            r#"{"decision":"deny","reason":"reinit_unsupported","reasonCode":5}"#
        );
    }

    #[test]
    fn the_rules_block_is_honoured() {
        let permissive = r#"{"call":"evaluate","proposal":{"kind":"remove","sender":"member"}}"#;
        assert_eq!(
            evaluate_case_json(permissive).expect("evaluates"),
            r#"{"decision":"allow"}"#
        );

        let strict = r#"{"call":"evaluate","rules":{"allowRemoveByAnyMember":false},
            "proposal":{"kind":"remove","sender":"member"}}"#;
        assert_eq!(
            evaluate_case_json(strict).expect("evaluates"),
            r#"{"decision":"deny","reason":"non_member_proposal","reasonCode":3}"#
        );
    }

    #[test]
    fn an_expect_field_is_accepted_and_ignored() {
        // The whole case object goes in, verbatim. If this ever stopped being
        // true every binding would need to strip a key first.
        let out = evaluate_case_json(
            r#"{"id":"x","call":"evaluate","proposal":{"kind":"add","sender":"external"},
                "why":"prose","expect":{"decision":"deny","reason":"external_sender"}}"#,
        )
        .expect("evaluates");
        assert_eq!(
            out,
            r#"{"decision":"deny","reason":"external_sender","reasonCode":2}"#
        );
    }

    #[test]
    fn a_name_that_does_not_exist_is_an_error_and_not_a_denial() {
        let err = evaluate_case_json(
            r#"{"call":"evaluate","proposal":{"kind":"teleport","sender":"member"}}"#,
        )
        .expect_err("an unknown kind is refused");
        let message = err.to_string();
        assert!(message.contains("teleport"), "{message}");
        assert!(message.contains("external_init"), "{message}");

        let err = evaluate_case_json(r#"{"call":"evaluateSomething"}"#)
            .expect_err("an unknown call is refused");
        assert!(err.to_string().contains("evaluateCommitSender"));
    }

    #[test]
    fn a_missing_field_names_what_is_missing() {
        let err = evaluate_case_json(r#"{"call":"evaluateAll"}"#).expect_err("refused");
        assert!(err.to_string().contains("`proposals`"), "{err}");
    }
}

/// One case of `mls/fixtures/rosters.json`: the pieces of a member-rostered
/// conversation four clients must agree on byte for byte — its handle, its
/// envelope, and its group policy
/// (docs/delivery.md §Handles and sender-addressed delivery).
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RosterCaseJson {
    call: String,
    /// `handle`, `seal`: the group id, as UTF-8 (a conversation uuid).
    group_id: Option<String>,
    /// `open`: the groups the reader holds.
    #[serde(default)]
    group_ids: Vec<String>,
    /// `seal`: the envelope kind.
    envelope_kind: Option<u8>,
    /// `seal`: the inner bytes.
    inner_hex: Option<String>,
    /// `seal`: the 12-byte nonce.
    nonce_hex: Option<String>,
    /// `seal`: an epoch's 32-byte envelope secret; present, the envelope is
    /// sealed by the epoch (version 3) and `groupId` is not read.
    epoch_secret_hex: Option<String>,
    /// `open`: the epoch envelope secrets the reader holds, tried after
    /// `groupIds`.
    #[serde(default)]
    epoch_secrets_hex: Vec<String>,
    /// `open`: the envelope.
    envelope_hex: Option<String>,
    /// `judge`: the group's meta before the commit, as JSON text.
    prior_meta: Option<String>,
    /// `judge`: the committer's actor id.
    sender: Option<String>,
    /// `judge`: each leaf added: its actor, or a [`SeatJson`].
    #[serde(default)]
    added: Vec<SeatJson>,
    /// `judge`: each leaf removed: its actor, a [`SeatJson`], or `null` for a
    /// leaf nobody can identify.
    #[serde(default)]
    removed: Vec<Option<SeatJson>>,
    /// `judge`: the meta the commit sets, as JSON text.
    new_meta: Option<String>,
    /// `judge`: every leaf the commit leaves in place, for the account-key
    /// rule (`crate::policy::judge_account_keys`).
    #[serde(default)]
    kept: Vec<SeatJson>,
    /// `judge`: the reading device's own actor and account key, when the
    /// case judges as one.
    reader: Option<SeatJson>,
}

/// A leaf in a `judge` case: a bare actor id, or `{"actor", "device",
/// "accountKey", "deviceKey"}` with each key as 64 hex characters. A bare
/// actor knows no device and no key; a leaf without `deviceKey` knows no
/// device key.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
enum SeatJson {
    Actor(String),
    Seat {
        actor: String,
        device: Option<String>,
        #[serde(rename = "accountKey")]
        account_key: Option<String>,
        #[serde(rename = "deviceKey", default)]
        device_key: Option<String>,
    },
}

impl SeatJson {
    fn seat(&self) -> Result<crate::policy::Seat> {
        Ok(match self {
            Self::Actor(actor) => crate::policy::Seat::of_actor(actor.clone()),
            Self::Seat {
                actor,
                device,
                account_key,
                device_key,
            } => crate::policy::Seat {
                actor: actor.clone(),
                device: device.clone(),
                account_key: match account_key {
                    None => None,
                    Some(hex) => Some(
                        hex_bytes(hex, "`accountKey`")?
                            .try_into()
                            .map_err(|_| Error::invalid("an `accountKey` is 32 bytes"))?,
                    ),
                },
                device_key: match device_key {
                    None => None,
                    Some(hex) => Some(
                        hex_bytes(hex, "`deviceKey`")?
                            .try_into()
                            .map_err(|_| Error::invalid("a `deviceKey` is 32 bytes"))?,
                    ),
                },
            },
        })
    }
}

/// A roster verdict. One shape per call, the others' fields omitted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct RosterVerdict {
    /// `handle`: the 32-byte handle.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub handle_hex: Option<String>,
    /// `seal`: the envelope.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub envelope_hex: Option<String>,
    /// `open`: whether any held group opened it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub opened: Option<bool>,
    /// `open`: the group that opened it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group_id: Option<String>,
    /// `open`: the epoch secret that opened it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub epoch_secret_hex: Option<String>,
    /// `open`: its kind.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub envelope_kind: Option<u8>,
    /// `open`: its inner bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inner_hex: Option<String>,
    /// `judge`: `allow` or `deny`, as a rules verdict writes it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decision: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<u32>,
}

/// Evaluate one case of `mls/fixtures/rosters.json`.
///
/// | `call` | needs | returns |
/// | --- | --- | --- |
/// | `handle` | `groupId` | `{"handleHex":"…"}` |
/// | `seal` | `groupId` (version 2) or `epochSecretHex` (version 3), `envelopeKind`, `innerHex`, `nonceHex` | `{"envelopeHex":"…"}` |
/// | `open` | `groupIds` and/or `epochSecretsHex`, `envelopeHex` | `{"opened":true,"groupId"|"epochSecretHex":…,"envelopeKind":N,"innerHex":…}` or `{"opened":false}` |
/// | `judge` | `priorMeta`, `sender`, `added`, `removed`, `newMeta`, and optionally `kept`, `reader`, `received` | `{"decision":"allow"}` or `{"decision":"deny","reason":…,"reasonCode":N}` |
fn evaluate_roster_case(case_json: &str) -> Result<String> {
    let case: RosterCaseJson = serde_json::from_str(case_json)
        .map_err(|err| Error::invalid(format!("could not read the roster case: {err}")))?;
    let need = |value: &Option<String>, name: &str| -> Result<String> {
        value
            .clone()
            .ok_or_else(|| Error::invalid(format!("a `{}` case needs a `{name}`", case.call)))
    };
    let verdict = match case.call.as_str() {
        "handle" => RosterVerdict {
            handle_hex: Some(to_hex(&crate::envelope::group_handle(
                need(&case.group_id, "groupId")?.as_bytes(),
            )?)),
            ..RosterVerdict::default()
        },
        "seal" => {
            let kind = case
                .envelope_kind
                .ok_or_else(|| Error::invalid("a `seal` case needs an `envelopeKind`"))?;
            let inner = hex_bytes(&need(&case.inner_hex, "innerHex")?, "`innerHex`")?;
            let nonce = hex_bytes(&need(&case.nonce_hex, "nonceHex")?, "`nonceHex`")?;
            let envelope = match &case.epoch_secret_hex {
                Some(secret) => crate::envelope::seal_epoch_envelope_with_nonce(
                    &hex_bytes(secret, "`epochSecretHex`")?,
                    kind,
                    &inner,
                    &nonce,
                )?,
                None => crate::envelope::seal_envelope_with_nonce(
                    need(&case.group_id, "groupId")?.as_bytes(),
                    kind,
                    &inner,
                    &nonce,
                )?,
            };
            RosterVerdict {
                envelope_hex: Some(to_hex(&envelope)),
                ..RosterVerdict::default()
            }
        }
        "open" => {
            let envelope = hex_bytes(&need(&case.envelope_hex, "envelopeHex")?, "`envelopeHex`")?;
            let opened = crate::envelope::open_envelope_among(
                case.group_ids.iter().map(|gid| gid.as_bytes()),
                &envelope,
            )?;
            let mut by_epoch = None;
            if opened.is_none() {
                for secret in &case.epoch_secrets_hex {
                    let bytes = hex_bytes(secret, "`epochSecretsHex`")?;
                    if let Ok(found) = crate::envelope::open_epoch_envelope(&bytes, &envelope) {
                        by_epoch = Some((secret.clone(), found));
                        break;
                    }
                }
            }
            match (opened, by_epoch) {
                (Some(opened), _) => RosterVerdict {
                    opened: Some(true),
                    group_id: Some(String::from_utf8_lossy(&opened.group_id).into_owned()),
                    envelope_kind: Some(opened.kind),
                    inner_hex: Some(to_hex(&opened.inner)),
                    ..RosterVerdict::default()
                },
                (None, Some((secret, (kind, inner)))) => RosterVerdict {
                    opened: Some(true),
                    epoch_secret_hex: Some(secret),
                    envelope_kind: Some(kind),
                    inner_hex: Some(to_hex(&inner)),
                    ..RosterVerdict::default()
                },
                (None, None) => RosterVerdict {
                    opened: Some(false),
                    ..RosterVerdict::default()
                },
            }
        }
        "judge" => {
            let sender = need(&case.sender, "sender")?;
            let added = case
                .added
                .iter()
                .map(SeatJson::seat)
                .collect::<Result<Vec<_>>>()?;
            let mut removed = Vec::with_capacity(case.removed.len());
            for leaf in &case.removed {
                removed.push(match leaf {
                    None => crate::policy::RemovedLeaf::of_actor(None),
                    Some(leaf) => {
                        let seat = leaf.seat()?;
                        crate::policy::RemovedLeaf {
                            actor: Some(seat.actor),
                            device: seat.device,
                            account_key: seat.account_key,
                            device_key: seat.device_key,
                        }
                    }
                });
            }
            let kept = case
                .kept
                .iter()
                .map(SeatJson::seat)
                .collect::<Result<Vec<_>>>()?;
            let reader = case.reader.as_ref().map(SeatJson::seat).transpose()?;
            let reader_key = match &reader {
                Some(crate::policy::Seat {
                    actor,
                    account_key: Some(key),
                    ..
                }) => Some((actor.as_str(), key)),
                _ => None,
            };
            let facts = crate::policy::CommitFacts {
                prior_meta: case.prior_meta.as_deref().map(str::as_bytes),
                sender: &sender,
                added: added.clone(),
                removed,
                new_meta: case.new_meta.as_deref().map(str::as_bytes),
            };
            // The account-key rule first, as the core runs it on a commit:
            // after the group's policy, but in every group, so a case that
            // trips both reads the policy's reason. A group with no policy
            // still meets the account-key rule.
            let policy = crate::policy::judge_commit(&facts);
            let decision = match policy {
                PolicyDecision::Allow => {
                    crate::policy::judge_account_keys(reader_key, &kept, &added)
                }
                deny => deny,
            };
            match decision {
                PolicyDecision::Allow => RosterVerdict {
                    decision: Some("allow".into()),
                    ..RosterVerdict::default()
                },
                PolicyDecision::Deny(reason) => RosterVerdict {
                    decision: Some("deny".into()),
                    reason: Some(reason.name().into()),
                    reason_code: Some(reason.code()),
                    ..RosterVerdict::default()
                },
            }
        }
        other => {
            return Err(Error::invalid(format!(
                "unknown call {other:?}; known: handle, seal, open, judge"
            )))
        }
    };
    serde_json::to_string(&verdict)
        .map_err(|err| Error::invalid(format!("could not write the verdict: {err}")))
}
