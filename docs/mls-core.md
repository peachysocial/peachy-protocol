<!-- SPDX-License-Identifier: CC0-1.0 -->
# MLS core

**Status:** describes the protocol as implemented by the `peachy-protocol`
0.2.0 release. **Revision:** 1, 2026-11-19. **Editor:** Peachy Social, Inc.

This is a guide to the `mls/` workspace: the Rust engine every Peachy client uses for end-to-end encryption, and its C, JavaScript and Swift bindings. It fixes the MLS profile a conforming client MUST speak (ciphersuite, extensions, capabilities, ratchet limits, padding, wire format), the leaf credential, the group policy every member enforces, and the key-package and leaf-rotation rules. It also says how to build, test and cross-compile the workspace, and which golden fixtures pin each rule. Transport is in [delivery](delivery.md); the credential format is in [identity](identity.md).

## Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY" and
"OPTIONAL" in this document are to be interpreted as described in BCP 14
(RFC 2119, RFC 8174) when, and only when, they appear in all capitals, as
shown here.

## What exists

| Path | What it is | Shipped in a client |
|---|---|---|
| `mls/core` | Crate `peachy-mls-core`. The engine: RFC 9420 groups on OpenMLS, the Peachy identity provider, group policy, storage, the mailbox envelope, the account store primitives, device linking. | Yes |
| `mls/cabi` | Crate `peachy-mls-cabi`. The C ABI over the core: a `staticlib`, a `cdylib` and an `rlib`. The committed header is `mls/cabi/include/peachy_mls.h`. | Yes |
| `mls/wasm` | Crate `peachy-mls-wasm`. A `wasm-bindgen` binding over the core (not over the C ABI). | Yes (web) |
| `mls/swift` | Swift package `PeachyMLS` over the C ABI, plus `build-xcframework.sh`. | Yes (Apple) |
| (Android) | A Kotlin binding over the C ABI through JNI, replaying the same fixtures. | Not in this tree |
| `mls/keytrans` | Crate `peachy-keytrans`. Key transparency verification (draft-ietf-keytrans-protocol-05). No binding uses it. | No |
| `mls/fixtures` | Golden JSON tables replayed in every language. | No (tests) |
| `mls/fuzz` | `cargo-fuzz` targets. Its own workspace; needs a nightly toolchain. | No |
| `mls/formal` | ProVerif models. They cover calls only. | No |

`mls/Cargo.toml` is the workspace; its members are `core`, `cabi`, `wasm` and `keytrans`. Every dependency is pinned with `=`, and `Cargo.lock` holds the tree. The four OpenMLS crates (`openmls` 0.9.0; `openmls_traits`, `openmls_rust_crypto` and `openmls_basic_credential` 0.6.0) are built with the feature `draft-ietf-mls-pq-ciphersuites`, which makes ciphersuite 0x004F available.

The release profile sets `lto = true`, `codegen-units = 1`, `panic = "unwind"` and `strip = "debuginfo"`. `panic = "unwind"` is required: the C ABI catches panics at its edge ([The C ABI contract](#the-c-abi-contract)).

The core crate is `#![forbid(unsafe_code)]` and denies `unwrap`, `expect` and `panic!` through Clippy. Errors are returned as data. The core logs through the `log` facade, at debug to error, only what a `Result` cannot carry; a log line is fixed text, at most followed by an error's message, and names no group, handle, key, credential field or content.

The call cryptography (`mls/core/src/call`: key schedule, signal codec, ring reducer) is specified in [Calls](calls.md). The call rpcs, the media server and push are not specified here.

### Core features

| Feature | Default | What it adds | Shipped |
|---|---|---|---|
| (none) | yes | The engine, in-memory storage. | yes |
| `sqlite` | no | `SqliteKv`, an encrypted SQLite store (SQLCipher). The C ABI always enables it. | yes |
| `test-issuer` | no | An in-process credential issuer. See [The `test-issuer` door](#the-test-issuer-door). | never |
| `fixture` | no | The JSON fixture door. Implies `test-issuer`. | never |
| `test-forgery` | no | Hidden `forge_*` methods that build messages an honest client never sends, so tests can prove peers refuse them. Only `cargo test --all-features` turns it on. | never |
| `insecure-plaintext-store` | no | `SqliteKv::open` and a C store path with no key: a store written in the clear. Tests and tools only. | never |
| `development-keys` | no | The `development` set of carried server keys: the fixed key local and test servers sign with, whose seed is public. Without it that set is empty. See [The `test-issuer` door](#the-test-issuer-door). | never |

## The MLS profile

A Peachy group is an RFC 9420 group with the parameters below. A client that wants to join, add to, or read Peachy groups MUST use exactly this profile. The constants live in `mls/core/src/group.rs` and `mls/core/src/group_meta.rs`.

### Ciphersuite 0x004F

Every group, key package and leaf uses one ciphersuite:

`MLS_128_MLKEM768X25519_AES128GCM_SHA256_Ed25519`, code point `0x004F` (core constant `PEACHY_CIPHERSUITE`).

| Component | Algorithm |
|---|---|
| KEM | X-Wing: ML-KEM-768 combined with X25519 |
| AEAD | AES-128-GCM |
| Hash / KDF | SHA-256 / HKDF-SHA256 |
| Signature | Ed25519 |

Both identifiers are provisional. `0x004F` is the code point OpenMLS 0.9.0 (`openmls_traits` 0.6.0) gives the placeholder "TBD1" of [draft-ietf-mls-pq-ciphersuites]; no published revision of that draft assigns it, and IANA has not. The KEM is X-Wing as specified by draft-connolly-cfrg-xwing-kem-06 [X-Wing], under the HPKE KEM id `0x004D` that `openmls_traits` 0.6.0 names `XWingKemDraft6`, implemented by `hpke-rs` 0.7.0 over the `x-wing` crate 0.1.0. A later revision of either draft that changes the combiner or the code points is a different suite, and a conforming client MUST NOT treat it as this one.

All HPKE encryption to leaves and init keys goes through the hybrid KEM. Signatures are classical: the leaf signature key MUST be the device's Ed25519 key, byte for byte ([The leaf credential is a Peachy device credential](#the-leaf-credential-is-a-peachy-device-credential)). No group negotiates: a key package in any other suite is refused, and leaves advertise only `0x004F`. A key package is about 3.2 KB, and the commit that adds a second member about 6.7 KB (`mls/core/tests/post_quantum.rs`, with `--nocapture`).

### Group configuration

| Setting | Value | Meaning |
|---|---|---|
| Wire format policy | `PURE_CIPHERTEXT` (`PEACHY_WIRE_FORMAT_POLICY`) | Every handshake and application message is a `PrivateMessage`, outgoing and incoming. A `PublicMessage` is refused. |
| Ratchet tree extension | on | The Welcome carries the ratchet tree. |
| Retained past epochs | 4 (`RETAINED_PAST_EPOCHS`) | Application messages from the current epoch and up to 4 epochs back open; nothing older. No time bound ([Retained past epochs](#retained-past-epochs)). |
| Out-of-order tolerance | 1000 (`OUT_OF_ORDER_TOLERANCE`) | A message may arrive up to 1000 generations behind the newest one already read from that sender in that epoch. |
| Maximum forward distance | 1000 (`MAXIMUM_FORWARD_DISTANCE`) | A message may be up to 1000 generations ahead of the newest one read from that sender. |
| Application padding | 256 (`APPLICATION_PADDING_BLOCK`) | RFC 9420 section 6.3.1 padding. The sender pads content, signature and AEAD tag together to a multiple of 256 bytes. Receivers MUST check the padding is all zeros. An unpadded message still opens. |
| Commit padding | the longest commit any member could make (`mls/core/src/commit_padding.rs`) | Padded to a size no surviving member's commit could exceed, set by the tree's width, its member count and its largest leaf, its proposals counted as at least the group's state plus 64 bytes, rounded up to 256 bytes ([Size-hiding padding](sealed-messages.md#size-hiding-padding)). |

A client MUST apply the same configuration to every group it creates or joins. The core re-applies it to stored groups when it opens them.

#### Retained past epochs

Past epochs are kept only for a message sealed at epoch N and placed after the commit to N+1 ([The ordering rule](delivery.md#the-ordering-rule)). A device that was away needs none: it drains in placement order, so each message opens at the epoch it was sealed in.

The bound is the current epoch and 4 before it, the five sending chains a pairwise ratchet keeps. There is no time bound; OpenMLS's time-based deletion is not used. A message more than 4 commits late does not open, and its content hint asks for it again ([Content hints](sealed-messages.md#content-hints)). A seized device gives up the last five epochs' unread traffic.

### Extensions and capabilities

| Type | Code | Where | Meaning |
|---|---|---|---|
| `peachy_group_meta` | `0xF1A9` | GroupContext | The group's own state as opaque UTF-8 JSON (name, photo, topic, admins, policy). Private-use code point. |
| `last_resort` | `0x000A` | KeyPackage | RFC 9420 last-resort extension. Only on last-resort key packages. |
| `peachy_reads_epoch_envelopes` | `0xF1AA` | leaf capabilities only | Reserved: every leaf lists it, and it is never sent as an extension. Private-use code point. |

Leaf capabilities:

- `ciphersuites`: `[0x004F]`.
- `extensions`: `[0xF1A9, 0xF1AA]`. Every key package and every leaf MUST advertise `0xF1A9`. A leaf without it cannot be added to a group that has group meta set. `0xF1AA` is listed by every leaf and never required of a group.
- A last-resort key package's leaf also lists `0x000A`.

Group meta rules (`mls/core/src/group_meta.rs`):

- The value is non-empty UTF-8 JSON, at most 16 384 bytes (`MAX_GROUP_META_BYTES`). A change that would pass the cap is refused on the device making it.
- The core treats it as opaque, except for the policy keys in [Group policy](#group-policy).
- Setting it adds `0xF1A9` to the group's `required_capabilities`, merged as a set with whatever is already required.
- It changes only through a commit that carries a GroupContextExtensions proposal and changes nothing but the meta.

Code points `0xF1A7` and `0xF1A8` are reserved and MUST NOT be reused.

### Content hint

An application message sealed with a hint (`encrypt_with_hint`, or `encrypt`, which uses hint 0) carries the `authenticated_data` `0x70 0x01 <hint> <commitment>` (`mls/core/src/hint.rs`): a tag, a version, the hint and the author's 16-byte commitment, zeros for none ([Asking for a message again](sealed-messages.md#asking-for-a-message-again)). A receiver reads a hint from any `authenticated_data` that starts `0x70 0x01` followed by a hint value in the table below, whatever follows it, and a commitment from the next 16 bytes when they are present and not all zero. Anything else is "no hint", including the `0x63 0x01` (followed by 16 zero bytes) every call signal on the MLS lane carries ([The two lanes](calls.md#the-two-lanes)).

| Hint | Value | Meaning for a receiver that cannot open the message |
|---|---|---|
| default | 0 | Show the loss now. Ask for nothing. |
| resendable | 1 | Hide the loss, ask the sender's device for the message again, and show the loss only if no answer comes. |
| implicit | 2 | Count the loss and show nothing. |
| resendable lane | 3 | As resendable, for a reaction, an edit or a delete; only a resent lane frame answers it. |

The hint and the commitment are readable without any key (`peek_message`), and authenticated once the message opens ([The content hint is read before the message is authenticated](#security-considerations)). The delivery service never sees them: every message travels inside a mailbox envelope ([delivery](delivery.md)). Which hint each payload uses is set in [Content hints](sealed-messages.md#content-hints).

## The leaf credential is a Peachy device credential

Every leaf carries an MLS `BasicCredential` whose `identity` bytes are a Peachy device credential token: the ASCII string `pdc1.<payload>.<signature>`, specified in [identity](identity.md). This section covers what the MLS layer checks (`mls/core/src/identity.rs`, `mls/core/src/credential.rs`).

A credential of any other MLS type is refused as `wrong_credential_type`. Then the checks run in this order, and the first failure names the rejection:

1. Parse. The token is at most 8192 bytes. A payload whose `v` is not `1` is `unsupported_version`. The payload is JSON with exactly the keys `v`, `kid`, `actor_id`, `device_id`, `device_key`, `account_key`, `account_sig`, `iat`, `exp`. Unknown keys are refused. The token must be the canonical spelling of its fields, with a `kid` of 8 lowercase hex characters ([Format](identity.md#format)); any other spelling is `malformed`.
2. `kid` must name a trusted server key.
3. Ed25519 `verify_strict` over the payload bytes exactly as they arrived.
4. Expiry. `exp` is exclusive. See the grace rule below.
5. Not-before. `iat` may be at most 60 seconds in the future (`CLOCK_SKEW_SECONDS`).
6. Plausible lifetime. `iat` must not be after `exp`, and `exp - iat` must be at most 31 days.
7. The leaf's signature key MUST equal `device_key`, compared as 32 raw bytes. This binds the MLS leaf to the device.
8. The account certificate (`account_key`, `account_sig`) must verify. A credential without one is `not_approved`.

### Rejection codes

These numbers are stable across all bindings (`CredentialRejection` in `mls/core/src/error.rs`):

| Code | Name |
|---|---|
| 1 | `malformed` |
| 2 | `unknown_kid` |
| 3 | `bad_signature` |
| 4 | `expired` |
| 5 | `not_yet_valid` |
| 6 | `leaf_key_mismatch` |
| 7 | `unsupported_version` |
| 8 | `wrong_credential_type` |
| 9 | reserved, never reused |
| 10 | `implausible_lifetime` |
| 11 | `account_signature` |
| 12 | `not_approved` |
| 13 | `not_own_account_key` |

A client is held to the account key its device holds (`own_account_identity`, the identity key derived from that account key): it refuses to open on, or to install, a credential certified under any other key, as `not_own_account_key`, and keeps the credential it had. A client given no key refuses every certified credential the same way and runs only uncertified ([Verifying a credential](identity.md#verifying-a-credential)).

### Trusted server keys

A client is constructed with the server's published credential keys, narrowed to those its build carries, as JSON:

```json
{"enabled": true, "keys": [{"kid": "fe812c12", "publicKey": "<base64>", "current": true, "use": "device"}]}
```

- `publicKey` is a raw 32-byte Ed25519 key in standard base64 with padding.
- A key whose `use` is present and is not `"device"` is dropped. A key with no `use` is a device key.
- The list holds the current key and every previous key still vouching for live credentials. A client MUST narrow it with `server_keys_pinned_json` to the keys its build carries before handing it to the core, which then trusts every key in it, current or previous ([The trusted server keys](identity.md#the-trusted-server-keys)).

Where a client fetches this list is in [identity](identity.md).

### Time rules

| Constant | Value | Use |
|---|---|---|
| `CLOCK_SKEW_SECONDS` | 60 | Allowed future `iat`. |
| `CREDENTIAL_REFRESH_WINDOW_SECONDS` | 10 days | A device renews its own leaf when its credential has less than this left. |
| `EXPIRED_LEAF_GRACE_SECONDS` | 56 days | How long after `exp` a seated leaf still identifies its sender. |
| `RENEWAL_CUTOFF_MARGIN_SECONDS` | 1 day | Margin used by the tree clock bound. |
| Credential lifetime | 30 to 31 days | What the issuer mints. A verifier refuses more than 31 days. |
| `MAX_TREE_CLOCK_JUMP_SECONDS` | 85 days | How far one commit may move the tree clock. |

Two clocks judge leaves:

- **Application messages** are judged on the receiver's wall clock. A leaf whose credential expired up to 56 days ago still identifies its sender. A message from a device whose account signed it out, when the receiver holds that signature, is judged on the delivery service's receive time instead ([A revoked leaf's messages](identity.md#a-revoked-leafs-messages)).
- **Proposals and commits** are judged on the **tree clock**: the latest `iat` among the group's person leaves, plus any leaves the commit introduces. A commit that would move the tree clock by more than 85 days is refused.

A member whose own leaf has lapsed past the grace may commit only a renewal of that leaf.

## Group policy

Policy runs on every member's device before it merges a commit. The server holds no roster, except through the members it runs in the store-review login's demo conversations ([Metadata](metadata.md#what-the-server-never-holds)), and enforces none of this. Two layers judge each commit: the proposal rules, then the group's own policy.

### The proposal rules

`mls/core/src/rules.rs` decides which senders may send which proposals. The sender is checked before the proposal kind.

| Sender | Code |
|---|---|
| member | 1 |
| external | 2 |
| new_member_proposal | 3 |
| new_member_commit | 4 |

| Proposal | Code | Rule |
|---|---|---|
| add | 1 | From a member: allowed (still subject to group policy). |
| update | 2 | Allowed only for the sender's own leaf. |
| remove | 3 | From a member: allowed (still subject to group policy). |
| psk | 4 | Refused. |
| reinit | 5 | Refused. |
| external_init | 6 | Refused. |
| group_context_extensions | 7 | Allowed only if the only change is `peachy_group_meta`. |
| self_remove | 8 | Refused. A leave is a Remove by reference instead (below). |
| unrecognised | 9 | Refused. |

External joins and external senders are refused outright. When a commit carries several proposals, the first denial wins.

Every proposal travels inline, inside the commit of the member who makes the change, except a **leave**. A proposal by reference is refused whatever its kind (`proposal_by_reference`), after the sender check and before the kind, unless it is a Remove of a leaf of its proposer's own person (`removesOwnLeaf` in the fixture): a member proposes its own removal and another member commits it ([Leaving](sealed-messages.md#leaving)). Any other standalone proposal is refused when it arrives and never enters the proposal store, and a commit that names any other proposal by reference is refused whole. A committer MUST NOT include any other queued proposal in its commit; the core never does. The message door takes a leave and no other proposal, and `Incoming::ProposalQueued` reports it kept.

Deny reasons, stable across bindings:

| Code | Reason |
|---|---|
| 1 | `external_join` |
| 2 | `external_sender` |
| 3 | `non_member_proposal` |
| 4 | `psk_unsupported` |
| 5 | `reinit_unsupported` |
| 6 | `group_context_extensions_unsupported` |
| 7 | `self_remove_unsupported` |
| 8 | `update_of_another_leaf` |
| 9 | `unrecognised_proposal` |
| 10 to 15 | reserved, never reused |
| 16 | `add_needs_admin` |
| 17 | `remove_needs_admin` |
| 18 | `meta_needs_admin` |
| 19 | `acp_needs_admin` |
| 20 | `policy_needs_admin` |
| 21 | `meta_unreadable` |
| 22 | `add_banned` |
| 23 | `proposal_by_reference` |
| 24 | `account_key_conflict` |

Code 24 is the account-key rule ([One account key per person](identity.md#one-account-key-per-person)), not a proposal rule; it shares the table so every binding reports it the same way.

### The group's policy

`mls/core/src/policy.rs` reads these keys of the group meta JSON:

| Key | Type | Meaning |
|---|---|---|
| `adm` | array of actor ids (lowercase hyphenated UUIDs), at most 64 | The group's admins. A group whose `adm`, `pol`, `lk` and `ban` all read is a **policy group**. |
| `pol` | object `{"add", "meta", "acp", "rm"}`, each `"any"` or `"adm"` | Who may add, edit name/topic/photo/timer, change `acp`, and remove others. |
| `dm` | `true` | A direct chat: a 1:1, a note to self, or an unnamed chat of several people (see [Delivery](delivery.md#founding-a-conversation)). |
| `acp` | any | The group's AI-relay opt-out flag. |
| `n`, `t`, `a`, `dis` | any | Name, topic, photo, disappearing-message timer. |
| `lk`, `ban` | object, array | Belong to a feature that is out of scope. A client MUST carry them over unchanged when it rewrites the meta. The policy still reads them: `lk` is absent or an object whose `k` and `r` are different 22-character base64url strings and whose `a` is `"any"`, `"adm"` or `"off"`; `ban` is absent or an array of at most 100 distinct actor ids. |

Absent `pol` keys default to: `add` any, `meta` any, `acp` admins (any in a `dm` group), `rm` admins.

Each proposal is judged as its own sender's (inline, that is the committer), and the commit is refused whole if any sender's share is refused. The rule, for the proposals of `sender`:

- A group with no meta at all is not judged. Only a call link's group is one: the link decides its membership.
- A prior meta that names no readable policy never falls open. No `adm` names no admin: the `pol`, `lk` and `ban` it carries still read, with their defaults, so nobody may remove somebody else (unless `pol.rm` is `any`) or change `adm`, `pol`, `dm`, `lk` or `ban`. Each part that does not read is closed: an unreadable `adm` names no admin, an unreadable `pol` makes every rule `adm`, an unreadable `lk` lets nobody in, an unreadable `ban` makes every add of somebody else need an admin, and rewriting or dropping it is a change to `ban`. A meta that is not a JSON object names no admin, and every key of a new meta counts as changed. A receiver refuses what this rule refuses, as the committer does ([Every member enforces the policy](#security-considerations)).

- A sender whose own leaf credential has expired on the tree clock, or whose actor cannot be read, is unidentified. An unidentified sender is never an admin, and no added or removed leaf is its own; it may still do what any member may.
- An add of an actor in `ban` is refused, whoever commits it.
- A remove and an add of the same seat in one commit is a **reseat** and cancels out. It is allowed to anyone. The same seat is the same actor, the same device id and the same account identity key. A remove of one device's leaf together with an add of another device, or of a leaf under another account key, is not a reseat: each half is judged by the rules below. The same device id under another device key is refused, by the adder (`replace_member`) and by every receiver, as is a commit that leaves two leaves under one device id.

- Adding one's own actor (a new device) and removing one's own leaves is always allowed.
- Removing a leaf whose credential no longer identifies anyone is always allowed, including a leaf expired on the tree clock but inside its grace.
- Any other add needs `pol.add`, unless the prior meta's `lk` has `a` of `any`, which lets any member add. Any other remove needs `pol.rm`.
- A meta change must parse as strict JSON with no duplicate key at any depth, carry `v` of exactly 1, keep a non-empty `adm` of at most 64 entries (or no `adm`, only where the prior meta had none), and keep `pol`, `lk` and `ban` readable, or it is `meta_unreadable`. Changing `adm`, `pol`, `dm`, `lk` or `ban` needs an admin. Changing `acp` needs `pol.acp`. Changing `n`, `t`, `a` or `dis` needs `pol.meta`. Under `pol.meta` of `adm`, changing any other key needs an admin too, `v` and unknown keys included, except `inv` and `dir`, which a member's device writes on its own (an invitation's answer, a community group's directory). The prior meta is read leniently.

After the policy, every commit is judged by the account-key rule ([One account key per person](identity.md#one-account-key-per-person)), refused as `account_key_conflict`.

A committing client runs the same checks on its own commit before it submits; if its peers would refuse the commit, the core clears it and returns the error. A modified client's commit that the policy refuses is refused by every honest member, and the group cannot advance past that epoch.

### Golden rules fixture

`mls/fixtures/rules.json` is the table of (inputs, expected verdict) for the proposal rules: 66 cases across three calls, `evaluate` (one proposal), `evaluateAll` (a commit's proposals, first denial wins) and `evaluateCommitSender`. The grid is exhaustive over every sender kind and every proposal kind, and reaches every deny reason. Cases name kinds and reasons by string, carry the numeric `reasonCode`, and each has a `why`. A proposal may carry `byReference: true` (default false, inline). A Remove may carry `removesOwnLeaf: true`; with `byReference` that is a leave.

`mls/fixtures/rosters.json` pins the group policy and the account-key rule (kind `"roster"`, call `judge`), together with group handles and envelope sealing ([delivery](delivery.md)). A `judge` case names each leaf by actor id or as `{actor, device, accountKey}`; `kept` (the leaves the commit leaves in place) and `reader` (the judging device's own seat), when present, feed the account-key rule. A case judges as the committer; `received: true` judges as a receiver.

A new implementation SHOULD replay both tables before talking to a real group. See [The fixture door](#the-fixture-door).

### Golden credential fixture

`mls/fixtures/credentials.json` (kind `"credential"`) pins the leaf credential checks through `validateToken` (a token alone), `validateCredential` (a token inside an MLS credential with a leaf key), `validateMember`, `validateOwn` (a device's own token against the account key it holds, `heldAccountKey`) and `judgeMessage`. `judgeMessage` judges an application message's sender: `validateMember` without the expiry, then the message rule on `receivedAt` (the second the delivery service received it), `revokedBy` (an account key whose revocation of the device key the reader holds) with `revokedAt` (when it took effect; absent is unknown), and `treeClock` (the tree clock of the sealing epoch when the reader's group is in it now; absent for a past epoch). It answers an acceptance, with `"lapsed": true` inside the grace, `expired` (a lapsed sender's new message among them: [A lapsed leaf's new messages](identity.md#a-lapsed-leafs-new-messages)), or `{"decision": "revoked"}`. Each case mints its own token from 32-byte hex seeds and fixes the clock with `nowUnix`. An accepted verdict carries back `actorId`, `deviceId`, `kid` and `expiresAt`. Every rejection code is reached, and some cases pin the check order with a token that fails two checks.

## The commit lifecycle

The core never applies its own commit by itself. Every operation that changes the tree stages a commit and returns it; the client submits it ([delivery](delivery.md)) and tells the core the outcome.

1. **Stage.** One of `add_member`, `remove_member`, `replace_member`, `self_update`, `set_group_meta`, `refresh_credential` or `commit_proposed_leaves`. Each commit carries exactly its own change, inline, and nothing from the proposal store, except `commit_proposed_leaves`, which names by reference every kept leave that is not its own person's and carries nothing else (`None` when there is none); its commit carries the proposal messages it names ([The carried commit](delivery.md#the-carried-commit)), while the stage is the bare commit. `propose_leave` and `begin_leave` stage nothing: they return the proposals to send, and `begin_leave` keeps the group as a leaving stub that `follow_leave` takes each commit of ([Leaving](sealed-messages.md#leaving)).

   `remove_member` names the leaf by its index and its tree signature key, both read from one roster entry (`RosterEntry::leaf_key`; `out_leaf_key` of `peachy_mls_group_member`, `leafKey` in wasm). If the key no longer matches the leaf at that index in the stored tree, it refuses with `NoSuchMember`, staging nothing; the client reads the roster again.

   A commit's outcome names who left in it (`CommitOutcome::left`, sorted actor ids): each person all of whose leaves it removed by that person's own proposals. It returns a `CommitBundle`: the commit (an `MLSMessage`), an optional Welcome, and the epoch the commit will produce (current epoch + 1). The commit's own build epoch is `epoch()`. A group holds at most one staged commit.
2. **Submit** the commit to the delivery service.
3. **Merge or discard.**
   - Accepted: call `merge_pending_commit`. The group moves to the new epoch. It is an error to merge with nothing staged.
   - Refused (for example, another device won the epoch): call `clear_pending_commit`, process the winning commit, and try again if still needed. Clearing with nothing staged is safe.

No store transaction spans the request to the delivery service. The stage is a write, committed before the stage returns on every outcome, a refusal included. `merge_pending_commit` or `clear_pending_commit` applies the server's answer in a write of its own. A client SHOULD merge as soon as the delivery service answers.

### A commit saved across a restart

A client that opens a store and finds a commit staged does not know whether the delivery service took it, so the open keeps it, writes nothing for it, and marks it saved (`has_saved_commit(group_id)`). The core stores the SHA-256 of every staged commit's bytes (namespace `staged_commit`) from the stage to its merge or clear, since the author cannot open its own echo.

The app that owns the store settles a saved commit before it processes anything for the group: it reads the group's head and calls `settle_saved_commit(group_id, head_epoch, head_verifier)`, a write of its own:

- **Merged** (1): the head is at the commit's epoch, and its send-key verifier is the one the commit produces. The group moves to the new epoch.
- **Cleared** (2): the head is at or below the group's own epoch, or at the commit's epoch with another verifier.
- **Waiting** (3): the head is past the commit's epoch. The commit stays staged until the verifier log settles it (below).

On **Waiting**, the client reads the verifier the delivery service logged at the epoch the commit makes ([FetchVerifierAt](delivery.md#fetchverifierat)) and calls `settle_saved_commit` again with that epoch and that verifier: the commit's own verifier merges it, any other clears it. It is the same settle the recovery driver's `SETTLE_FIRST` step asks for ([Group recovery](#group-recovery)). It must not wait for the echo: a client that drops its own envelopes unopened never hands the echo to the core, and a commit the delivery service took then stays saved for good, the group one epoch below everyone, every later commit and message refused with `STALE_COPY`, and every forget and Welcome back refused with `SETTLE_FIRST`. A log with no row there proves nothing, and the commit stays staged.

A client that cannot read the head settles nothing, processes nothing for the group, and never rejoins while the verdict is unknown. A saved commit refuses what any staged commit refuses (sealing, staging another commit), and `clear_pending_commit` leaves it alone. `forget_group`, `join_contested_welcome` and a Welcome that would replace the held group refuse with `SETTLE_FIRST` (19) and change nothing; the client settles and tries again. `settle_saved_commit` refuses with `INVALID_ARGUMENT` when the group has no saved commit. Only the app settles; a notification extension on the same store leaves the commit as it found it.

### Staging and joining

- `add_member` takes an `MLSMessage`-wrapped KeyPackage. It refuses a key package whose credential fails the checks above, including one with no account certificate.
- `replace_member` removes a leaf and adds a fresh key package for the same actor, device and account key in one commit. It refuses to replace the committer's own leaf or a leaf it cannot identify.
- `refresh_credential` is a self-update with an update path and no proposals, carrying the device's current credential ([Periodic leaf rotation](#periodic-leaf-rotation)).
- `create_group` refuses an empty group id, a duplicate id, and a device with no account certificate.
- `join_from_welcome` takes only a padded Welcome frame, and refuses a raw Welcome or a malformed frame ([The padded Welcome frame](delivery.md#the-padded-welcome-frame)). The Welcome of every add and reseat is a padded frame.
- `welcome_group(welcome)` reads a Welcome's group id and epoch without taking it; bytes that are not a whole frame (a raw Welcome among them) it refuses as the doors do, spending the key package they are sealed to. The apps take every Welcome through `join_from_welcome_at_head(welcome, head_epoch, head_verifier)`, or, below the head, `join_from_welcome_at_head_logged(welcome, head_epoch, head_verifier, logged_verifier, kept_from)` with the verifier the server logged and the log's floor ([FetchVerifierAt](delivery.md#fetchverifierat); no floor is `PEACHY_MLS_NO_FLOOR` at the C door, null in the bindings). `join_from_welcome` reads no head, so its seat is unconfirmed; it keeps a Welcome into a group the device is active in as the contested Welcome (`contested_welcome_group_id`), judged by `join_contested_welcome(head_epoch, head_verifier)`. Every door checks the tree's members with the expired-leaf grace, refuses with `POLICY` (`account_key_conflict`) a tree holding the device's own person under another account key or one person under two, records the actor whose commit produced it (`welcome_sender`), and refuses with `ALREADY_A_MEMBER` a Welcome at or below the epoch mark or a second taking of a last-resort seat. The key package is spent on every outcome, a refused frame included, except that `join_from_welcome_at_head` puts it back when it refuses with `SETTLE_FIRST`. The rest of what each door takes and refuses is in [Welcome semantics](delivery.md#welcome-semantics) and [Two seats under one group id](delivery.md#two-seats-under-one-group-id). A seat no head or log answer places names no `dropped_devices`.
- `confirm_head(group_id, head_epoch, head_verifier)`: a copy at the head is **confirmed**; a confirmed copy at the head's epoch under another send key **lapses**. An unconfirmed copy is confirmed by a matching head at one of its last 64 epochs (or the head it was seated against, once it reaches that epoch) and **contested** by a mismatch, as by 16 of its own commits refused in a row (the rejoin report says `contested`). A merge of an own commit confirms the copy, and `create_group` founds it confirmed.
- A Welcome signed by a forgotten own device (by its id or by any key it was seen holding) is refused with `WELCOME_FROM_OUTSIDER` into any group.
- A Welcome that would restore or replace a group this device knew is taken from anybody else and leaves a **rejoin report**; one whose signer does not identify is refused with `WELCOME_FROM_OUTSIDER`. The report's fields and fold are in [A Welcome into a group this device knew](delivery.md#a-welcome-into-a-group-this-device-knew). `peek_rejoin_report(group_id, now_ms)` returns the oldest, fixing its `drawn_at_ms` at the first peek: `now_ms`, or the millisecond after the group's last report's lines (a report spans `line_span`, 4 plus one per person added or gone; the end is kept as `rejoin_draw_floor`). `drop_rejoin_report(group_id, id)` removes the report with that random nonzero `id`; `take_rejoin_report(group_id)` peeks and drops at once, answering `id` 0. Its fields: `readded_by_untrusted`, `admins_changed`, `added_actors`, `departed_actors`, `dropped_devices`, `contested`. Past 32 waiting (`REJOIN_REPORTS_KEPT`), a new report is folded into the newest.

### Receiving

- `process_message(group_id, message)` and `process_commit(group_id, message)` return one of: `application` (with plaintext and sender), `proposal`, `commit` (with `removed_self` and the new epoch) or `echo` (the device's own message, read back). `proposal` comes back only for a leave, the one standalone proposal the message door keeps (`Incoming::ProposalQueued`, [The proposal rules](#the-proposal-rules)); every other standalone proposal is refused.
- `is_behind(group_id, epoch)` is true when the group's local epoch is lower than `epoch`. After a complete drain, a client passes the head's epoch ([delivery](delivery.md#the-client-contract-on-behind_retention)). Equality is not behind.
- `process_message` refuses with `NOT_FROM_A_MEMBER` an application message that opened and verified at a past epoch from a leaf no longer in the tree, and one from a device whose account's signed revocation of its key the device holds (kept by `stale_leaf_removable`) when it cannot place the message's receipt before the revocation. `process_message_received_at(group_id, message, received_at)` takes the mailbox envelope's `received_at`; `process_message` passes 0, unknown, which counts as after ([A revoked leaf's messages](identity.md#a-revoked-leafs-messages)).
- `process_message` refuses a lapsed sender's NEW message (received at or after its `exp`, or sealed in the current epoch at or past it on the tree clock) as `EXPIRED` ([A lapsed leaf's new messages](identity.md#a-lapsed-leafs-new-messages)). `encrypt` refuses with `EXPIRED` once the leaf's `exp` is at or before the tree clock, or within 60 seconds of this device's own clock (`CLOCK_SKEW_SECONDS`).
- `process_message` refuses with `DUPLICATE` the exact bytes of a message this device already opened, before the engine reads them. Each application message that opens and verifies is recorded under `opened` in the write that spends its key; the last 4096 a group opened are kept (`OPENED_KEPT`). Processing is all or nothing: on any refusal (a tag or signature that fails, a sender the group removed, a lapsed credential) the core rolls back every write the call made and reloads the group, so a forged copy cannot burn the real message's key. A spent key (OpenMLS's `SecretReuseError`) the record does not hold is `MLS`, never `DUPLICATE` ([Replays](delivery.md#security-considerations)).
- `process_message_as(group_id, message, envelope_id)` is `process_message` for one mailbox envelope's message. It keeps what an application message opened to (sender and plaintext) under `opened_content`, keyed by envelope id and digest, in the write that spends its key, and answers the same envelope handed over again with it. A keep that cannot be written refuses the message, spending nothing; a second message under one id is kept beside the first. `release_opened(envelope_id)` drops every record under the id once the client's own copy is stored, in a write that ends erased; `release_opened_all(envelope_ids)` does so for many ids in one write. A client releases the envelopes a page acknowledges together, once each is stored ([An envelope left for the next drain](delivery.md#fetchmailbox-and-ackmailbox)). Records older than 30 days, and the oldest past 1000, go at a client's first keep or release and hourly after. An empty id, or one holding a NUL, keeps nothing.
- `commit_strands(group_id, message)`, asked after the commit door refused an entry, is true exactly when the message is the commit at this device's epoch that the door refused last, and it opened and verified before it was refused: the device must rejoin ([delivery](delivery.md#a-commit-this-device-cannot-apply)). Otherwise it is false and the client reads the group's head.
- `forget_group` drops the group's state. A copy a head matched once (confirmed or lapsed) leaves its roster (every leaf's person, with account keys, read from the credentials without verifying again) and its group state, for a Welcome back to be drawn against; a confirmed copy also raises the epoch mark to its epoch. A copy no head ever matched leaves only its roster (`remembered_unvouched`). A copy the device was removed from together with its person leaves nothing. A Welcome into an id the device keeps nothing for, and holds no copy it still has a claim on (active, or with another device of its person seated), is a first join with no report. `forget_remembered_roster` drops all of it except the epoch mark.
- `verify_join_request(group_id, actor_id, device_id, proof, key_package, pending_actors)` judges a signed seat ask. Once the proof holds, the asker's person must hold a leaf in this device's copy, be this device's own person, or be in `pending_actors` (the caller's own invitations, never read off the ask), else verdict 7, `not_a_member`. An ask of this device's own person from a device the account forgot, or whose key package names no device, is also verdict 7. `pending_actors` is not honored for a person whose last leaf this device saw leave the group, until they hold a leaf again or `forget_remembered_roster` drops the record.
- `add_member_for_ask(group_id, key_package, pending_actors)` is `add_member` for a seat ask `verify_join_request` accepted, whose device holds no leaf. Under the add's write lock it judges the membership step again for the person and device the package names, and refuses with `INVALID_ARGUMENT` naming the verdict, staging nothing, unless it is still `accepted`.
- `verify_admitted_join_request(group_id, actor_id, device_id, proof, key_package)` makes the same checks except membership, for a person this device admits by its own rule (an open group's join inbox, a group link it approved). It is never used for a rejoin's seat ask.

### Group recovery

A copy that fell behind the group's head with nothing to carry it up, or
forked off it, does not recover by itself. The core decides when to forget
the group and ask back in, so every client recovers the same way; the
client reads the head and sends the seat ask.

- `recovery_begin(group_id)` snapshots the copy's epoch, its verifier and
  the last complete drain, and answers `READ_HEAD` (11), `HELD` (3) or
  `NO_COPY` (9). The head is read after it.
- `recovery_judge(group_id, kind, head, fresh, now_ms)` judges that head
  (`None` when the server holds none) and answers the step. `kind` is
  `CHECK` (0), `SEALED_AHEAD` (1, a `STALE_COPY` refusal) or `LOST` (2, a
  lost mailbox). `fresh`: the read began after the begin. The head is handed
  to `confirm_head`, and the read noted (`note_head_read`) outside a fork
  backoff.
- `recovery_read_due(group_id, sealed_ahead, now_ms)`: whether messages that
  would not open owe a head read now (one a minute per group, unless one was
  sealed past the copy and the minute's read did not know of one).
- `recovery_drain_complete(started_at_ms, evidence, now_ms)`: a mailbox
  drain ran to the end; answers the groups owed a second read.

The steps (`PEACHY_MLS_RECOVERY_*`):

| # | Step | The client |
|---|---|---|
| 0 | `IN_STEP` | does nothing |
| 1 | `BEHIND` | lets the mailbox catch the copy up |
| 2 | `ROLLED_BACK` | keeps the copy |
| 3 | `HELD` | does nothing: the group is held for its steward |
| 4 | `HOLD_ENTERED` | never reached (no group has a steward); the commit fetch it would use is not specified here |
| 5, 6, 7 | `REJOIN_FORKED`, `REJOIN_STUCK`, `REJOIN_LOST` | forgets the group and asks back in ([Rejoin with a sealed seat ask](delivery.md#rejoin-with-a-sealed-seat-ask)) |
| 8 | `BACKOFF` | waits: a fork rejoin of the group is too recent |
| 9 | `NO_COPY` | does nothing |
| 10 | `READ_AGAIN` | reads the head again, fresh, and judges again |
| 11 | `READ_HEAD` | reads the head, then judges |
| 12 | `SETTLE_FIRST` | settles the saved commit by the verifier logged at the copy's epoch plus one ([FetchVerifierAt](delivery.md#fetchverifierat)), then begins again |

The rules are [A commit the server refuses](delivery.md#a-commit-the-server-refuses)
and [Retention](delivery.md#retention). Steps 3 and 4 are for a group with a
steward, which no group has. A fork at the copy's own epoch shows
only in the verifier, so the head's verifier is always compared. The counts
are kept in memory, per client.

### Exporter secrets

`export_secret(group_id, label, context, length)` is the RFC 9420 MLS-Exporter for the current epoch. The label MUST be non-empty, and the length MUST be 1 to 65535. `export_pending_secret` exports from the epoch a staged commit will produce. The exporter labels Peachy uses are specified where each one is used.

## Last-resort key packages

A device publishes one-time key packages and one **last-resort** key package (`PublishKeyPackages` with `last_resort` set). The directory hands out the last-resort package only when the device's one-time pool is empty. It carries the RFC 9420 `last_resort` extension (`0x000A`), so the device keeps its private half after use.

| Constant | Value |
|---|---|
| `LAST_RESORT_ROTATION_INTERVAL_SECONDS` | 2 days |
| `LAST_RESORT_ARCHIVE_AGE_SECONDS` | 30 days |

Rules (`mls/core/src/group.rs`):

- `last_resort_rotation_due()` is true when the device holds no last-resort package or its newest is 2 days old or more. The client then mints one with `generate_last_resort_key_package_with_ref` and publishes it.
- Each mint prunes the old ones: keep the newest; of the rest, delete those older than 30 days except the youngest of them. A Welcome sealed to a replaced package still opens for at least 30 days.
- A device that joins a group through its last-resort package marks its leaf there due for rotation at once. It records the seat each such Welcome opened (`welcome_taken`) and refuses that seat again until it drops the package.

Both mint calls return the package as an `MLSMessage` and its `KeyPackageRef`, `RefHash("MLS 1.0 KeyPackage Reference", KeyPackage)` over the bare KeyPackage, not the wrapper. A device with no account certificate cannot mint (`not_approved`). Every mint is flushed before it returns (on the wasm binding, durable once the host's `flush()` lands, which it MUST await before publishing the package), since a key package handed out and then lost is a Welcome no one can open. Key packages use the OpenMLS default lifetime, an hour before the device's now to 84 days after it ([A KeyPackage's lifetime is checked by its adder](identity.md#a-keypackages-lifetime-is-checked-by-its-adder)).

## Periodic leaf rotation

MLS heals a compromised member only when that member commits a new leaf (RFC 9420 section 16.6). The core rotates each of the device's own leaves on a schedule.

| Constant | Value |
|---|---|
| `LEAF_ROTATION_INTERVAL_SECONDS` | 7 days |
| `LEAF_ROTATION_FRAME_BUDGET` | 250 |
| `ROUND_TRIP_ROTATION_MIN_SECONDS` | 10 minutes |

A leaf is **due** when any of these holds:

- It was put in the tree 7 days ago or more: the later of the device's own record (written when it created the group, joined from a Welcome, or merged its own commit with an update path) and the `iat` of the leaf's credential.
- The device has sealed 250 application messages on it.
- **The round trip.** The group seats exactly two people (counted by the actor ids of the leaves' credentials), the device has opened an application message from the other person since the leaf was put in the tree, and the leaf is 10 minutes old or more. A message from another device of the device's own person does not count. Opening one sets a mark kept with the group (`peer_heard`); a new leaf clears it.

The round trip is the MLS form of a pairwise ratchet's healing; the 10-minute floor bounds it to six rotations an hour per device. Groups of three or more people keep the 7-day and 250-frame schedule.

It is never due while the device has a staged commit, or in a group where the device is not active.

When a leaf is due, `leaf_credential_expiring` and `credential_refresh_due` answer true, and the client calls `refresh_credential`, which stages a self-update with a fresh HPKE key (and the device's current credential). A leaf whose capabilities lack something this build requires is due too. A client asks at the two moments [Refreshing a seated leaf](identity.md#refreshing-a-seated-leaf) names: before its next send into the group, and in one pass over every group when the app starts or returns to the foreground.

## Storage layout

The core keeps all state behind one key-value interface, `KvStore` in `mls/core/src/storage.rs`:

| Method | Contract |
|---|---|
| `get(key)` | The value, or none. |
| `put(key, value)` | Write. |
| `delete(key)` | Remove. Removing a missing key is not an error. |
| `scan(prefix)` | Every pair whose key starts with `prefix`, in key byte order. |
| `flush()` | Make everything written so far durable, as one unit. |
| `rollback()` | Discard everything written since the last `flush`, and release the write lock. Defaults to an error, for a backend that cannot undo. |
| `erase_superseded()` | Remove from the medium what flushed operations replaced or deleted. Returns whether nothing superseded remains; `false` means "busy, will retry at the next flush", not an error. Defaults to `true`. |
| `begin_write()` | Take the store's write lock now and hold it until the next `flush`. Defaults to nothing, for a backend only this process writes. |
| `foreign_generation()` | A value that changes whenever another writer has committed since this connection last looked, and not for this connection's own commits. `None` when the backend cannot tell ([A store two processes share](#a-store-two-processes-share)). |

The core calls `flush` after every operation that changes state, so a crash loses at most the last operation, whole. On the SQLite backend that flush is the commit; on the wasm binding nothing is durable until the host's own `flush()` lands ([wasm binding](#wasm-binding)). A refusal that follows a write is flushed too: processing a message, and joining from a Welcome, flush on every outcome. No call returns with a store transaction open.

Once any read or write of an operation has failed, or an OpenMLS value it read did not decode, the store refuses that operation's later writes and rolls it back at the flush (and on drop). The core then reloads its groups and returns the error, so the device is where it was before the call and a retry succeeds (`mls/core/tests/store_fault_rollback.rs`).

After the flush of every operation that replaces or deletes a secret (merging or processing a commit, opening or sealing an application message, joining from a Welcome, forgetting a group, pruning a last-resort key package), the core calls `erase_superseded`. A failed or busy erase never fails the operation.

Opening a client over an existing store MUST only read it when nothing in it needs migrating or repairing: on SQLite a write at the top of the open would hold the write lock across the read of every group, and some platforms kill a suspended process that holds a write lock on a shared database. Repair (a group whose stored join configuration is out of date, an id with no state behind it) is written at the tail of the open under the write lock; if another connection committed since the open began, the open loads every group again first.

The store is stamped with its schema version (`STORAGE_SCHEMA_VERSION`, currently `0x01`, the first byte of every key). A store with a newer version is refused (`STORAGE`); an older one is re-stamped, and its old keys are not read. The layout of every key and value is in `mls/core/STORAGE.md`.

A Peachy-owned value of any other length, or a Peachy-owned JSON value that does not parse, is read as absent, except where absent would loosen a check. Those fail closed: an unreadable `epoch_mark` reads as the highest epoch there is; a `head_confirmed` value other than the one byte `0` or `2` reads as confirmed; and an unreadable `last_resort` time reads as minted at second 0. An unreadable `remembered_roster` can make a Welcome back into the id a new invitation, and an unreadable `rejoin_report` drops the reports not yet dropped.

The store holds every group secret this device has. A client MUST NOT let it be copied to another device or restored from a backup: a copied store is two devices sharing one leaf, and the copy reads everything the original reads until the original rotates.

### Backends

- **`MemoryKv`**: in memory. Gone when the client is dropped. For tests and short-lived clients.
- **`SqliteKv`** (feature `sqlite`): one table, `mls_kv (k BLOB PRIMARY KEY, v BLOB NOT NULL) WITHOUT ROWID`, in WAL mode with `synchronous = FULL` and `checkpoint_fullfsync = ON`. Writes go into one transaction, which `flush` commits; an operation that writes group state opens it with the write lock already taken. Dropping the store also commits. The library is SQLCipher. The key is raw (no passphrase KDF), so it MUST be 256 random bits:
  - 32-byte key: every page is AES-256 ciphertext, including the header.
  - 48-byte keyspec (32-byte key then 16-byte salt): the first 32 bytes of the file stay a plaintext SQLite header, which some platforms need to keep a WAL database open while the app is suspended.
  - No key: plain SQLite (`SqliteKv::open`). It exists only in a build with the `insecure-plaintext-store` feature, which no shipped archive turns on; any other build has no door that writes the file in the clear, and the C door refuses a store path with no key.
  A wrong key fails as `STORAGE`. A file written in the clear, opened under a key (`SqliteKv::open_store`), fails as `PLAINTEXT_STORE` without being touched: no retry opens it, and deleting it to start over drops the device out of every group. `store_encrypt_in_place` (`peachy_mls_store_encrypt_in_place`) is the way out: it folds the log in, exports every row into a new file under the key, checks the row count, and renames the new file over the old one, with the old one's permissions, leaving no plaintext copy, log or index beside it. The old file's blocks are freed, not overwritten ([Erasure is at the SQLite file](#security-considerations)). A failure before the rename leaves the store in the clear, as it was. Whether a file is in the clear is read from its first 100 bytes (`SqliteKv::is_plaintext_store`), without opening it as a database. The store never repairs or falls back on its own.

  Every open, and `store_encrypt_in_place`, first refuses a store whose file, `-wal`, `-shm` or `-journal` is writable by group or others, or is a symbolic link, as `INSECURE_STORE` (`sqlite::check_store_permissions`), with nothing opened: the bundled SQLite trusts a `-wal` it finds beside the store (RUSTSEC-2026-0459). The files the core creates are its owner's alone to write. The directory is the caller's to keep private: one others can write lets them add a file after the check, and the check reads each file's mode, not its owner. Not judged off Unix.

  `peachy_mls_client_open_existing` opens a store that must already be there: a path with no file is `INVALID_ARGUMENT` and nothing is created, so a store lost to a crash or a bad migration is an error rather than a fresh store that has dropped out of every group. A long-running client reopening its own store calls it. Such a client SHOULD keep its store key apart from the store (a keystore, or a file readable only by its own user on another volume): a key beside the file is no key.

  Every connection sets `secure_delete = ON` and `journal_size_limit = 0`. On open, and in `erase_superseded`, the store runs `wal_checkpoint(TRUNCATE)`; if another process holds the file, the checkpoint reports busy and the next flush tries again ([Erasure is at the SQLite file](#security-considerations)).
- **wasm `CacheKv`**: an in-memory cache over a store the host provides. See [wasm binding](#wasm-binding). Its `erase_superseded` is the default.

### A store two processes share

Two processes may hold a client on one SQLite store at once, such as an app and its notification extension. A client acting on a stale copy of a group would write back a message key the other process spent, or an epoch the group has left.

So every operation that writes group state takes the write lock before it reads anything (`BEGIN IMMEDIATE`), reloads every group if SQLite's `data_version` says another connection committed since they were loaded, acts, and commits before it returns. These are the stage doors, `merge_pending_commit`, `clear_pending_commit`, `settle_saved_commit`, both receive doors, sealing, `create_group`, `forget_group` and the Welcome joins; the own-device doors (`remember_own_approver`, `forget_own_device` and `forget_own_device_with_key`, `own_sibling_leaves`, `check_own_device_approval`); the seat-ask record (`first_sight_of_join_request`, `join_request_seen`); the rejoin reports (`peek_rejoin_report`, `drop_rejoin_report`, `take_rejoin_report`, `forget_remembered_roster`); and the account-key pins (`observe_account_keys`). Minting a key package, and the pruning it runs, write no group state and run outside the lock. A client that reloads keeps its own stage, and treats a stage it did not make as a saved commit ([A commit saved across a restart](#a-commit-saved-across-a-restart)).

Every read door of the C ABI (the roster, from `peachy_mls_group_member_count`; the epoch; the group's state; whether it is active or behind; the exporters; the call doors; and the seat-ask verdict) first compares `data_version` with the value its groups were loaded at, and only when it moved reloads them under the lock, writing nothing (`refresh_if_moved`). A Rust caller of the core's reads calls `refresh_if_moved` itself. The lock is held for one operation, never across a request to the delivery service. A backend whose `foreign_generation` is `None` (`MemoryKv`, the wasm `CacheKv`) never reloads, so each such store MUST have one live client at a time.

Where the store key lives is the client's choice. It SHOULD be wrapped by the platform keystore.

## Account store

The encrypted account store is specified in [account store](account-store.md). The core provides only its primitives, so every client derives the same keys and bytes: the account key box (`account_key_seal` / `account_key_accept_hybrid`; `account_key_open`, the unvouched opener, only in `fixture` builds), record sealing (`store_seal` / `store_open`), note-to-self sealing (`note_seal_signed` / `note_open_signed`), and the account identity key used to vouch for devices. `mls/fixtures/account-store.json` pins them (kind `"account_store"`). The core never contacts the server, and never decides what a record means.

## The C ABI contract

`mls/cabi/src/lib.rs` defines the ABI. `mls/cabi/include/peachy_mls.h` is the header, generated by `cbindgen` and committed.

### Rules

1. **No unwinding across the edge.** Every exported function runs inside `catch_unwind`. A panic returns `PEACHY_MLS_ERR_PANIC` (99).
2. **Status codes and a thread-local message.** Every fallible function returns an `int32_t` status. On failure, `peachy_mls_last_error()` returns a NUL-terminated UTF-8 message, valid until the next `peachy_mls_*` call on the same thread. The caller MUST NOT free it, and MUST read it on the same thread before any other call.
3. **Every returned buffer is the caller's to free, once.** Bytes come back as `PeachyMlsBuffer { uint8_t *data; uintptr_t len; }`. Free each with `peachy_mls_buffer_free`, never with the caller's own allocator. It wipes the bytes and sets the struct back to empty (`data = NULL, len = 0`), so a second free is a no-op. An empty result is `data = NULL, len = 0`. A `PeachyMlsIncoming` is freed whole with `peachy_mls_incoming_free`.
4. **Null pointers are errors, not crashes.** A required pointer that is NULL returns `PEACHY_MLS_ERR_NULL_ARGUMENT`. So does a NULL data pointer with a non-zero length.
5. **Out-parameters are checked first and written only on success.** A missing out-pointer is refused before any irreversible work. On failure, out-parameters are left untouched, except that a door whose answer could let somebody in first writes the answer that admits nobody: the two own-device checks `PEACHY_MLS_OWN_DEVICE_UNANCHORED`; both join-request checks `PEACHY_MLS_JOIN_REQUEST_MALFORMED`; `peachy_mls_group_member` and `peachy_mls_key_package_identity` a malformed-credential rejection; the approval, account-device and link-commitment checks and the link QR match `false`; the two device-link steps `PEACHY_MLS_LINK_IGNORE` and `PEACHY_MLS_APPROVER_WAIT`; `peachy_mls_first_sight_of_join_request` `false`; and `peachy_mls_join_request_seen` `true`. A caller that ignores the return code reads a refusal.
6. **No call leaves a store transaction open.** What a call wrote is committed before it returns, success or error. A caught panic is rolled back, and the handle is closed: every later call but `peachy_mls_client_free` returns `PEACHY_MLS_ERR_PANIC` without running, and the caller opens a new client over the same store.
7. **A list of strings is length-prefixed, never joined.** A u32 big-endian count, then each item as a u32 big-endian byte length and its UTF-8 bytes. An empty input buffer is the empty list; a list that is not consumed exactly is refused (`INVALID_ARGUMENT`).

Handles are opaque: `PeachyMlsClient *` (free with `peachy_mls_client_free`) and, in test builds only, `PeachyMlsTestIssuer *`. **A client handle is not thread-safe.** The caller MUST serialize every call on one handle, including the `peachy_mls_last_error` read that follows a failure. Input strings are NUL-terminated UTF-8. Input byte arrays are pointer plus length and are only borrowed for the call.

**The ABI version.** The C ABI is version 2: `peachy_mls_abi_version()` returns the `PEACHY_MLS_ABI_VERSION` the library was built with. It is raised whenever a signature, a struct layout, a constant's value or the meaning of an existing status code changes; never for an addition alone. A caller compares it with the constant in its own copy of the header before any other call and refuses to run on a mismatch: a struct written by hand against another header reads memory laid out differently. `peachy_mls_version()` names the crate release.

**Enumerated outputs.** Where a door writes a code from a fixed list, the header names each value (`PEACHY_MLS_HELD_ORDINARY`, `PEACHY_MLS_HELD_FORMER_MEMBER` and `PEACHY_MLS_HELD_ORPHAN` for `peachy_mls_held_disposition`), and a caller MUST read a value it does not know as the most cautious one the door names: for a held envelope's fate that is `PEACHY_MLS_HELD_FORMER_MEMBER`, never "take it through".

### Status codes

| Code | Name | Meaning |
|---|---|---|
| 0 | `PEACHY_MLS_OK` | Success. |
| 1 | `PEACHY_MLS_ERR_NULL_ARGUMENT` | A required pointer was NULL, or a pointer and length disagree. |
| 2 | `PEACHY_MLS_ERR_CREDENTIAL` | A credential failed a check. The message names the rejection. |
| 3 | `PEACHY_MLS_ERR_POLICY` | The proposal rules or group policy refused. From a Welcome door: a Welcome whose tree holds one person under two account keys, or this device's person under another key (nothing was taken; drop it, and, while waiting to rejoin, ask for a seat again). |
| 4 | `PEACHY_MLS_ERR_MLS` | OpenMLS refused (bad message, an epoch the copy has passed, failed decrypt). An epoch past the copy's is `STALE_COPY` (23). |
| 5 | `PEACHY_MLS_ERR_CODEC` | Bytes did not decode. |
| 6 | `PEACHY_MLS_ERR_NO_SUCH_GROUP` | No state for that group id. |
| 7 | `PEACHY_MLS_ERR_NOT_A_MEMBER` | This device is not active in the group. |
| 8 | `PEACHY_MLS_ERR_NO_SUCH_MEMBER` | No leaf at that index, or the leaf there no longer holds the key the caller read. |
| 9 | `PEACHY_MLS_ERR_UNSUPPORTED` | A valid request the core does not support. |
| 10 | `PEACHY_MLS_ERR_INVALID_ARGUMENT` | A value out of range: wrong seed length, empty label, nothing staged to merge. |
| 11 | `PEACHY_MLS_ERR_STORAGE` | The store failed. Retryable, except for a wrong store key or a store from a newer build, which fail the same way every time. |
| 12 | `PEACHY_MLS_ERR_ALREADY_A_MEMBER` | A Welcome at or below the group's epoch mark, or taken once already through a last-resort package; against the head, one above the head's epoch or at it under another send key; and one for a group this device is already active in, unless it is at the head and the held copy is not, when it replaces the copy. |
| 13 | `PEACHY_MLS_ERR_EXTENSION_UNSUPPORTED` | A member's leaf lacks a capability the change needs. |
| 14, 15 | reserved | Never reused. |
| 16 | `PEACHY_MLS_ERR_WRONG_DOOR` | The entry came through the wrong door. `process_mailbox_entry` refuses a commit outside a COMMIT entry, a message outside an MLS entry, and a seat ask or call signal. `process_door` refuses a commit, or any proposal but a leave this device can queue, at the message door, and anything but a commit at the commit door. Nothing moved. |
| 17 | `PEACHY_MLS_ERR_NOT_FROM_A_MEMBER` | An application message that opened and verified, signed by a leaf no longer in the group, or by a device whose account signed it out, received at or after the revocation. Drop it in silence. |
| 18 | `PEACHY_MLS_ERR_WELCOME_FROM_OUTSIDER` | A Welcome signed by a forgotten own device, into any group; or a Welcome into a group this device knew whose signer does not identify. Nothing was taken. Drop it and log it. |
| 19 | `PEACHY_MLS_ERR_SETTLE_FIRST` | `forget_group`, a Welcome taken against the head, or a contested Welcome, into a group that holds a saved commit. Nothing changed. Settle the commit and call again ([A commit saved across a restart](#a-commit-saved-across-a-restart)). |
| 20 | `PEACHY_MLS_ERR_DUPLICATE` | An application message this device already opened ([Receiving](#receiving)). Nothing moved. Drop it in silence: no placeholder, no resend ask, no notification ([A message that will not open](delivery.md#a-message-that-will-not-open)). |
| 21 | `PEACHY_MLS_ERR_PLAINTEXT_STORE` | A store key was given and the file at the path was written in the clear. Nothing was touched. Not retryable: encrypt it with `peachy_mls_store_encrypt_in_place` and open it again ([Backends](#backends)). |
| 22 | `PEACHY_MLS_ERR_INSECURE_STORE` | The store, or its `-wal`, `-shm` or `-journal`, is writable by group or others, or is a symbolic link. Nothing was opened. Not retryable: make the files writable only by their owner. A symbolic link at the store's own path may be replaced with the file it names (for example with `mv`). A link at `-wal`, `-shm` or `-journal` is none the core or SQLite makes: never adopt the file it names; find out who made it, and remove the link only once the store's owner is known to have made it. Then open it again; never delete the store ([Backends](#backends)). |
| 23 | `PEACHY_MLS_ERR_STALE_COPY` | A message or commit framed at an epoch past this copy's: the copy is behind or forked and will not catch up from what was delivered. Nothing moved. Judge the head ([Group recovery](#group-recovery)); never rejoin on this alone. From the client's envelope door (`Client::seal_envelope`, `peachy_mls_client_seal_envelope`): a message or commit made at an epoch this copy no longer keeps; nothing was sealed, so encrypt it again. |
| 99 | `PEACHY_MLS_ERR_PANIC` | A panic was caught, in this call or an earlier one on the same handle. The handle is closed: free it and open a new client over the store (rule 6). |

`peachy_mls_group_process_door` reports what arrived through `PeachyMlsIncoming`:

```c
typedef struct {
  int32_t kind;                     /* 1 application, 2 proposal, 3 commit, 4 echo */
  PeachyMlsBuffer sender_actor_id;  /* empty for echo */
  PeachyMlsBuffer sender_device_id; /* empty for echo */
  PeachyMlsBuffer plaintext;        /* application only */
  uint32_t proposal_kind;           /* proposal only; codes in "The proposal rules" */
  bool removed_self;                /* commit only */
  uint64_t epoch;                   /* the epoch after processing */
  PeachyMlsBuffer left_actor_ids;   /* commit only: the people who left, a sorted string list */
} PeachyMlsIncoming;
```

A client routes each mailbox entry through `peachy_mls_group_process_mailbox_entry` (`processMailboxEntry` in wasm and in the Swift package), which takes the entry's mailbox kind beside the sealed kind. `peachy_mls_group_process_door` is deprecated and stays, unchanged, until a later ABI version: its caller picks `PEACHY_MLS_DOOR_MESSAGE` (1) on its message path or `PEACHY_MLS_DOOR_COMMIT` (2) on its commit path, and one that picks it from the sealed kind alone takes a commit nobody ordered. There is no doorless entry point, in the C ABI or in the core (`process_message`, `process_commit`). A commit is merged only on the commit path, and only from an entry the head ordered ([delivery](delivery.md)).

### Opening a client

```c
int32_t peachy_mls_client_open(const uint8_t *credential, uintptr_t credential_len,
                               const uint8_t *signature_seed, uintptr_t signature_seed_len,
                               const char *trusted_keys_json,
                               const char *store_path,
                               const uint8_t *store_key, uintptr_t store_key_len,
                               const uint8_t *own_account_identity,
                               uintptr_t own_account_identity_len,
                               PeachyMlsClient **out_client);
```

- `credential` is the `pdc1` token. `signature_seed` is the device's 32-byte Ed25519 seed. `trusted_keys_json` is the server key list.
- `store_path` NULL or empty opens an in-memory client.
- `store_key_len` is 32, 48, or 0 with `store_key` NULL (unencrypted). Any other length, or a key without a path, is `INVALID_ARGUMENT`. So is a path with no key, unless the library is built with `insecure-plaintext-store`, a test-only feature no shipped archive enables.
- A store that cannot be opened, a wrong key, or a newer schema is `STORAGE`. The client never falls back to memory.
- `own_account_identity` is the 32-byte account identity key derived from the account key the device holds (`account_identity_public_key`), or NULL with length 0 when it holds none. It MUST be derived on the device: a key read off the device's own credential, or one the server hands over, passes the check whoever certified the credential. A credential certified under any other key, or certified at all when the pair is NULL, is `CREDENTIAL` (`not_own_account_key`). `peachy_mls_client_update_credential` takes the same pair, and a client opened with a key keeps holding to it.

`peachy_mls_client_new` takes the same first five parameters and `out_client`, holds to no account key, and is always in memory. The C surface has no clock override: the core reads the system clock.

The header documents every function: identity and key packages; server key pins (`peachy_mls_server_key_pin_report`, `peachy_mls_server_keys_pinned`); device approval and linking ([identity](identity.md)); account store primitives ([account store](account-store.md)); group lifecycle and commits; group meta and handles; mailbox envelopes ([delivery](delivery.md)); members; join requests; encryption, `peek_message`, `process_door` and exporters; call cryptography ([calls](calls.md)).

### Regenerating the header

`mls/cabi/build.rs` writes the header into Cargo's `OUT_DIR` and nowhere else. `mls/cabi/tests/header.rs` fails if it differs from the committed copy, and prints a `cp` command, run from `mls/`, that updates it:

```sh
cd mls
cargo test -p peachy-mls-cabi --test header
```

Test-only declarations sit behind `#if defined(PEACHY_MLS_TEST_ISSUER)` and `#if defined(PEACHY_MLS_FIXTURE)`.

## wasm binding

`mls/wasm` wraps the core directly with `wasm-bindgen`, not through the C ABI.

- Bytes are `Uint8Array`. Records are plain objects. Epochs are numbers.
- Every failure throws a JavaScript `Error` whose message is the core's error text. There are no numeric codes.
- Methods are the core's names in camelCase: `createGroup`, `joinFromWelcome`, `addMember`, `mergePendingCommit`, `clearPendingCommit`, `encryptWithHint`, `processMessage`, `processCommit`, `exportSecret`, and so on. Free functions such as `sealEnvelope`, `messageEpoch`, `messageHint`, and the server key pins `serverKeyPinReport` and `serverKeysPinned` ([The trusted server keys](identity.md#the-trusted-server-keys)), need no client.

Two constructors:

- `new MlsClient(trustedKeysJson, credentialToken, seed32, ownAccountIdentity?)`: in memory.
- `await MlsClient.open(trustedKeysJson, credentialToken, seed32, store, ownAccountIdentity?)`: persistent, over a host store.

`ownAccountIdentity` is the 32-byte account identity key the device derives from the account key it holds (`accountIdentityPublicKey`), or absent when it holds none, as in the [C ABI](#opening-a-client). A device that holds the account key MUST pass it on every open; without it a certified credential is refused (`not_own_account_key`). `updateCredential(credential, ownAccountIdentity?)` takes it too, and with none given holds to the key the client was opened with.

The host store implements:

```ts
interface MlsKvStore {
  get(key: Uint8Array): Promise<Uint8Array | null | undefined>;
  writeBatch(entries: Array<[Uint8Array, Uint8Array | null]>): Promise<void>; // null = delete
  iterate(prefix: Uint8Array): Promise<Array<[Uint8Array, Uint8Array]>>;     // byte order
}
```

`open` reads the schema stamp with `get`, then loads everything with one `iterate`. During operations the core works on its in-memory cache and calls nothing. `client.flush()` sends every dirty key in one `writeBatch`. `writeBatch` MUST apply all entries atomically, and its promise MUST NOT resolve until the write is durable (the web client's IndexedDB store opens its transaction with `durability: "strict"`). `pendingWrites` counts what has not been flushed. A client SHOULD `await flush()` after every operation that changes state, and before closing. `free()` does not flush.

A host MUST `await flush()` before it hands the server anything the client produced or consumed: a ciphertext, a commit, KeyPackages, or the acknowledgement of a mailbox entry the client processed. Otherwise a closed tab keeps the server's side and loses its own: a replayed message opens twice, or a sender generation is handed out again.

The wasm binding does not encrypt at rest. Protecting the host store is the host's job.

The core cannot see another client's writes to the host store ([A store two processes share](#a-store-two-processes-share)). A host where several clients can open one store, such as several browser tabs, MUST let only one of them write at a time, and MUST rebuild a client whose store another one has written since it opened, before that client acts.

A panic in the wasm binding is a trap (`WebAssembly.RuntimeError`): `wasm32-unknown-unknown` cannot unwind. The binding's panic hook marks the instance POISONED before the trap. From then on every export refuses: a call throws an `Error` whose message starts `poisoned:`, `flush()` rejects with it before a byte reaches the store, and `MlsClient.open` and the free functions refuse too. `isPoisoned()` is the one export that still answers. Only a fresh module instance (a reload, or the glue's `__wbg_reset_state`) clears the mark. The host MUST then discard the instance and reopen the client over its store from a fresh one; the store holds the last flushed state, and whatever the client did after that flush is lost. A host SHOULD treat a `poisoned:` refusal as the panic it records, for a trap it did not see happen. `panicForTest()`, behind the `fixture` feature, is the panic `mls/wasm/tests/node/poison.test.mjs` poisons with.

On `wasm32`, the build enables `getrandom`'s `wasm_js` backend (and `getrandom` 0.2 `js`) and OpenMLS's `js` feature, so randomness and time come from the JavaScript host.

## Swift binding

`mls/swift` is a Swift package over the C ABI. Minimum platforms: iOS 17 and macOS 14. Tools version 5.9.

| Target | What it is |
|---|---|
| `PeachyMLSCore` | A system library: `module.modulemap` over the C header (`include/peachy_mls.h` is a symlink to the committed header). It links the Security framework. |
| `PeachyMLS` | The Swift API. Product `PeachyMLS`. |
| `PeachyMLSTests` | Tests. They link a host build of the C library with the test features. |

The package carries no binary. An app adds `PeachyMLS` and links `PeachyMLSCore.xcframework`, which `build-xcframework.sh` builds ([Cross-compiling](#cross-compiling)).

`MLSClient` (`mls/swift/Sources/PeachyMLS/MLSClient.swift`):

- Takes an internal lock around every call, including the `peachy_mls_last_error` read after a failure, so it is `@unchecked Sendable` and usable from any thread.
- `init(credential:signatureSeed:trustedKeysJSON:storePath:storeKey:ownAccountIdentity:)` opens a store at a path. The URL variant also excludes the database and its `-wal` and `-shm` files from backup, as [Storage layout](#storage-layout) requires, and `storeURL(forDevice:in:)` puts it in Application Support.
- `ownAccountIdentity`, on both initializers and on `updateCredential(_:ownAccountIdentity:)`, works as in the [C ABI](#opening-a-client). A device that holds the account key MUST pass it on every open, in every process that opens the store.
- `MLSClient.serverKeyPinReport` and `MLSClient.serverKeysPinned` are the server key pins ([The trusted server keys](identity.md#the-trusted-server-keys)); they need no client.
- `close()` frees the handle and releases the file; every later call throws `MLSError.closed`. `destroyStore(at:)` deletes the database and both journal files; call `close()` first.

The rest of the API is documented in `MLSClient.swift`.

## The `test-issuer` door

The `test-issuer` feature adds an in-process issuer (`mls/core/src/issuer.rs`) that mints `pdc1` tokens from a 32-byte seed and publishes its key in the trusted-keys JSON shape, so tests need no server. The C ABI exposes it as `peachy_mls_test_issuer_new`, `peachy_mls_test_issuer_published_keys`, `peachy_mls_test_issuer_issue` and `peachy_mls_test_issuer_free`; the wasm binding, under its own `test-issuer` feature.

The `fixture` feature implies `test-issuer` and adds the fixture door below and the sealers that take a caller's nonce (`seal_envelope_with_nonce`, `seal_live_frame_with_nonce`, `store_seal_with`). A build without `fixture` has only the random-nonce sealers.

**Neither feature is ever built into a shipped client:** one with `test-issuer` can mint credentials that any peer trusting the test key accepts. A release build MUST be built with no features beyond `sqlite`, as the release paths in this document are. Every `cargo test` of the core or the C binding turns `test-issuer` on through a dev-dependency, as do the Swift host archive and the Node test bundle, so the release checks instead assert with `cargo tree` that the C and wasm bindings' shipped graphs turn on no `test-issuer`, `fixture`, `development-keys`, `insecure-plaintext-store` or `test-forgery` feature of the core.

The `development-keys` feature is never built into a shipped client either: its key's seed is public, so a build with it that talks to a server other than production would trust credentials anyone can mint. Without it the `development` set is empty, so a build that talks to a local or test server reports each key that server publishes as not carried and trusts none of them. `cargo test --all-features` and the Swift host archive turn it on, as do app builds for local development and testing (`--development-keys` on `build-xcframework.sh`); the release checks also run the pin tests without it.

### The fixture door

One function evaluates a case from any golden table:

| Language | Entry point |
|---|---|
| Rust | `peachy_mls_core::fixture::evaluate_case_json(case_json) -> Result<String>` |
| C | `peachy_mls_fixture_evaluate_case(const char *case_json, PeachyMlsBuffer *out_verdict)` |
| JavaScript | `evaluateFixtureCase(caseJson)` |

The whole case object goes in, `expect` and `why` included and ignored. A verdict object comes back as JSON text, to compare with the case's `expect`. The case's `kind` picks the table:

| `kind` | Table |
|---|---|
| absent or `"rules"` | `mls/fixtures/rules.json` |
| `"credential"` | `mls/fixtures/credentials.json` |
| `"device_link"` | `mls/fixtures/device-link.json` |
| `"account_store"` | `mls/fixtures/account-store.json` |
| `"join_request"` | `mls/fixtures/join-request.json` |
| `"roster"` | `mls/fixtures/rosters.json` |
| `"call"` | `mls/fixtures/calls.json` ([Calls](calls.md)) |
| `"welcome_frame"` | `mls/fixtures/welcome-frame.json` ([The padded Welcome frame](delivery.md#the-padded-welcome-frame)) |
| `"carried_commit"` | `mls/fixtures/carried-commit.json` ([The carried commit](delivery.md#the-carried-commit)) |
| `"typing"` | `mls/fixtures/formats/typing.json` ([Typing inside the group](sealed-messages.md#typing-inside-the-group)) |
| `"resend_commitment"` | `mls/fixtures/formats/resend.json` ([Content hints](sealed-messages.md#content-hints)) |

An unknown `kind` or a missing field is an error, never a silent pass. The door does not read files or assert; each language's test does that.

## Building and testing locally

Requirements:

- Rust through `rustup`. `mls/rust-toolchain.toml` pins the toolchain (with `rustfmt` and `clippy`). The minimum supported Rust version is 1.91.
- A C compiler. SQLCipher is compiled from source. Off Apple platforms its OpenSSL is compiled from source too, which also needs `perl` and `make`.
- For wasm: `wasm-pack` (checked against 0.13.1) and Node.js.
- For Swift: Xcode with the iOS SDK, on an Apple silicon Mac.

### Rust

The checks every release passes, run from `mls/`, are in the README's Building and testing section.

`--all-features` is required: most tests need `test-issuer`, `fixture`, `sqlite` and `test-forgery`. Build output goes to `mls/target/`.

#### Release checks

The README's two narrower test runs (`server_key_pins`, `shipped_store`) leave out what a release leaves out and `--all-features` never does: the carried server keys without `development-keys`, and the C store door without `test-issuer`. The release checks also run these two commands, and fail if any line they print turns on the core's `test-issuer`, `fixture`, `development-keys`, `insecure-plaintext-store` or `test-forgery` feature (a line `peachy-mls-core feature "<name>"`); a release prints only `default` and `sqlite`:

```sh
cargo tree -p peachy-mls-cabi -e features,normal -i peachy-mls-core
cargo tree -p peachy-mls-wasm --target wasm32-unknown-unknown -e features,normal -i peachy-mls-core
```

### wasm

From the repository root:

```sh
# Rust tests compiled to wasm32 and run under Node
wasm-pack test --node mls/wasm

# The release bundle a web client ships (no test features)
wasm-pack build mls/wasm --target web --release --out-dir pkg
```

The Node bundle and the JavaScript replays are in the README. `mls/wasm/tests/journey.rs` runs only under `wasm-pack test`.

### Swift

`./build-xcframework.sh` in `mls/swift` builds all slices plus the host test archive; `--host` builds only the archive `swift test` needs (README).

### Fuzzing

`mls/fuzz` holds a libFuzzer target for every function in `mls/core` that
parses or opens bytes a peer or the server chose, or a path that reaches
them only through one; `mls/fuzz/README.md` lists the targets and how to run
them.

## The tests

Each file under `mls/core/tests/` pins one claim and says which in its header; `mls/cabi/tests/`, `mls/wasm/tests/node/` and `mls/swift/Tests/PeachyMLSTests/` run the same journeys and fixtures through the C, JavaScript and Swift doors. The RFC 9420 vectors are in the README.

## Cross-compiling

The C ABI is the door for every native platform. Build `peachy-mls-cabi` for the target and link the `staticlib` (or the `cdylib`) with the committed header. A release build MUST NOT pass `--features`.

### Apple

`mls/swift/build-xcframework.sh` builds three release slices of `peachy-mls-cabi`, with no features:

| Rust target | Slice |
|---|---|
| `aarch64-apple-ios` | `ios-arm64` |
| `aarch64-apple-ios-sim` | `ios-arm64-simulator` |
| `aarch64-apple-darwin` | `macos-arm64` |

It sets `IPHONEOS_DEPLOYMENT_TARGET=17.0` and `MACOSX_DEPLOYMENT_TARGET=14.0`, passes `-DSQLITE_ENABLE_SNAPSHOT` to SQLite, checks that each archive contains SQLCipher, link-checks each slice, and assembles `mls/swift/build/PeachyMLSCore.xcframework` with `xcodebuild -create-xcframework`. There are no `x86_64` slices. On Apple targets SQLCipher uses CommonCrypto.

It also builds a host archive with `--features test-issuer,fixture,development-keys,insecure-plaintext-store` at `mls/swift/build/host/libpeachy_mls_cabi.a`. Only `swift test` links it. An app MUST NOT. With `--development-keys` the three slices carry the `development` server keys, for a local or test build only.

### Other targets

Any target Rust and OpenMLS support should work through the C ABI:

```sh
cd mls
rustup target add <target>
cargo build --release -p peachy-mls-cabi --target <target>
```

Off Apple platforms the `sqlite` feature builds SQLCipher against a vendored OpenSSL compiled from source, so cross-compiling needs a C cross-compiler for the target, with `CC_<target>` / `AR_<target>` set the way the `cc` crate expects. Android goes through the NDK the same way.

## Security considerations

- **The suite is provisional.** Both code points in
  [Ciphersuite 0x004F](#ciphersuite-0x004f) come from drafts.
  The suite's confidentiality is hybrid post-quantum, its authentication
  classical Ed25519.
- **Every member enforces the policy.** A group with no readable `adm` has no
  admin and can never gain one; its recovery is a new group
  ([The group's policy](#the-groups-policy)).
- **The content hint is read before the message is authenticated**
  ([Content hint](#content-hint)), so a receiver MUST treat it as a hint.
- **The test doors forge credentials.** A build with `test-issuer`, `fixture`
  or `test-forgery` can mint or forge what peers accept
  ([The `test-issuer` door](#the-test-issuer-door)), so a build for people
  MUST NOT enable them.
- **Erasure is at the SQLite file.** The store zeroes what it frees and cuts
  its log ([Backends](#backends)); what lies below the file is the
  platform's. A group keeps its last 4 epochs of message secrets on purpose.

## IPR

This document is dedicated to the public domain under CC0 1.0.

## References

- [RFC 2119] "Key words for use in RFCs to Indicate Requirement Levels", BCP 14, RFC 2119, March 1997. <https://www.rfc-editor.org/rfc/rfc2119>
- [RFC 8174] "Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words", BCP 14, RFC 8174, May 2017. <https://www.rfc-editor.org/rfc/rfc8174>
- [RFC 9420] "The Messaging Layer Security (MLS) Protocol", RFC 9420, July 2023. <https://www.rfc-editor.org/rfc/rfc9420>
- [RFC 9180] "Hybrid Public Key Encryption", RFC 9180, February 2022. <https://www.rfc-editor.org/rfc/rfc9180>
- [X-Wing] "X-Wing: general-purpose hybrid post-quantum KEM", draft-connolly-cfrg-xwing-kem-06, work in progress. The revision implemented here. <https://datatracker.ietf.org/doc/html/draft-connolly-cfrg-xwing-kem-06>
- [draft-ietf-mls-pq-ciphersuites] The MLS working group's draft of post-quantum and hybrid ciphersuites for MLS, work in progress. Ciphersuite 0x004F is OpenMLS 0.9.0's provisional code point for its suite "TBD1". <https://datatracker.ietf.org/doc/draft-ietf-mls-pq-ciphersuites/>
- [FIPS 203] NIST, "Module-Lattice-Based Key-Encapsulation Mechanism Standard", FIPS 203, August 2024. <https://doi.org/10.6028/NIST.FIPS.203>
- [RFC 7748] "Elliptic Curves for Security", RFC 7748, January 2016. <https://www.rfc-editor.org/rfc/rfc7748>
- [RFC 8032] "Edwards-Curve Digital Signature Algorithm (EdDSA)", RFC 8032, January 2017. <https://www.rfc-editor.org/rfc/rfc8032>
- [RFC 5869] "HMAC-based Extract-and-Expand Key Derivation Function (HKDF)", RFC 5869, May 2010. <https://www.rfc-editor.org/rfc/rfc5869>
- [FIPS 180-4] NIST, "Secure Hash Standard (SHS)", FIPS 180-4, August 2015. <https://doi.org/10.6028/NIST.FIPS.180-4>
- [SP 800-38D] NIST, "Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC", SP 800-38D, November 2007. <https://doi.org/10.6028/NIST.SP.800-38D>
- [RFC 8259] "The JavaScript Object Notation (JSON) Data Interchange Format", STD 90, RFC 8259, December 2017. <https://www.rfc-editor.org/rfc/rfc8259>
