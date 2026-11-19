<!-- SPDX-License-Identifier: CC0-1.0 -->
# Protocol changelog

**Status:** what changed on the wire and in the core's API, newest first,
for anyone building a client of their own. **Editor:** Peachy Social, Inc.

Each entry says what changed, what is refused, and what a client of your own
must do. The rules a client most often gets wrong are collected in
[Third-party client conformance](delivery.md#third-party-client-conformance).

Which envelope versions the server takes, the next it will refuse and from
when, and the client refusals switched on are in `GetMinSupportedVersion`
with the platform `protocol`
([The protocol floor](delivery.md#the-protocol-floor)). Ask it at start-up:
that answer, not this file, is the live source.

## 2026-11-19: peachy-protocol 0.2.0, the first public release

The core is `peachy-mls-core` 0.2.0, and its C ABI version is 2. The server
and the web client run what this entry describes. Peachy's iOS, Android and
Mac apps at their minimums are built from an earlier copy that differs in how
it settles the security-code notice
([Security code changed](identity.md#security-code-changed)). A build exempt
while in store review differs further
([Retired builds](delivery.md#retired-builds)).

### Envelopes

- **Version 3 by the epoch.** A member seals version 3 into every group it
  holds, under the keys of the epoch it seals at. Version 2 (keyed by the
  group id) is sealed only for a seat ask and a link preview, whose reader
  holds no epoch of the group. Every current reader opens versions 2 and 3,
  and nothing else ([The wrapped envelope](delivery.md#the-wrapped-envelope)).
  **Do:** the same; seal through the core's client door, which picks the
  version.
- **Version 1 is refused, and a commit is version 2 or 3.** `SendSealed`
  and `SubmitCommit` refuse a version 1 envelope (unpadded, keyed by the
  group id) with `failed_precondition`; one already in a mailbox is
  delivered, and current readers drop it unread. A commit in any other
  version, or too short to be an envelope, is `invalid_argument`. Both carry
  `peachy-refusal: envelope-retired`; `update-required` answers only a
  Peachy app below its platform's minimum.
  **Do:** stop sealing that version, and seal commits and everything else
  through `Client::seal_envelope`.
- **The clientless envelope door seals seat asks and link previews only.**
  `seal_envelope` (`peachy_mls_seal_envelope`, the free `sealEnvelope` in
  wasm) refuses every other kind with `INVALID_ARGUMENT`. A message, commit,
  typing frame or call signal sealed by the group id would open for a removed
  member or a link holder.
  **Do:** seal everything else through the client's door.
- **The client's envelope door never falls back to the group id.**
  `Client::seal_envelope` refuses a message or commit made at an epoch the
  copy no longer keeps with `STALE_COPY`, anything but a seat ask or a link
  preview from a copy no longer in the group with `NOT_A_MEMBER`, and from a
  group the client does not hold with `NO_SUCH_GROUP`. Receivers still open
  and route a version-2 envelope of kinds 1, 2, 4 and 6; what is inside
  authenticates itself.
  **Do:** on `STALE_COPY` from a seal, encrypt the message again and seal
  that; never resend the old bytes, and do not judge the head.
- **No attachment list beside the envelope.** A `SendSealed` that sets
  `sealed_attachments` (field 7, reserved) is refused with
  `invalid_argument`, and nothing of it is stored: a key named beside the
  envelope ties a sessionless send to the account that uploaded the blob.
  **Do:** name attachments only inside the envelope.

### Builds and devices

- **A retired build is refused.** A call with a session that names a Peachy
  app's build below its platform's minimum (`x-peachy-build`) is refused
  before its handler runs: `failed_precondition`, `peachy-refusal:
  update-required`, unless the operator exempts that build
  ([Retired builds](delivery.md#retired-builds)). A client that sends no such
  header is not judged.
  **Do:** send no `x-peachy-build` and no Peachy app's user agent.
- **Retired devices.** A refused login's devices are sent nothing and
  seated by nobody, and `SendSealed` and `SubmitCommit` name them in
  `retired_device_ids` ([Retired devices](delivery.md#retired-devices)).
  **Do:** act on `retired_device_ids` only through `remove_stale_leaf`, and
  forget each id ten minutes after the server last named it.
- **The protocol floor is published**
  ([The protocol floor](delivery.md#the-protocol-floor)).
  **Do:** read it at start-up, as above, and plan for the date.
- **One-way client refusals.** The same answer names checks switched on for
  good, for every client (`client_refusals`) or for the caller's account
  (`account_client_refusals`); the core enforces each name it knows once
  handed them (`Client::adopt_client_refusals`) and ignores the rest.
  **Do:** hand the core the lists at every open and after every ask, and
  read [Client refusals](#client-refusals) for what each name refuses.
- **A new login proves the device key.** A login new to an install's row
  is refused with `permission_denied` without a valid `key_proof`
  ([Taking over a row](identity.md#taking-over-a-row)).
  **Do:** send `key_proof` on every registration.
- **No device name on the server.** `RegisterDeviceRequest` field 4 (`name`)
  is reserved: the server keeps no device name and drops one an app sends.
  An app seals each device's name in the account store.
- **`ClaimSoleDevice` keeps only the caller's own device.** A kept device
  that did not register under the calling login, or a kept row that is
  neither its twin nor the same login's, is `permission_denied`. The
  identity key a claim clears is never pinned again
  ([ClaimSoleDevice](identity.md#claimsoledevice)).
  **Do:** keep the device this login registered and its twins.

### Welcomes, frames and the account key

- **Only the padded Welcome frame.** A reader refuses a raw Welcome; only
  the padded frame is taken
  ([The padded Welcome frame](delivery.md#the-padded-welcome-frame)). A
  refused frame still spends the key package it names.
  **Do:** keep the key package pool full, and take Welcomes only from the
  delivery service.
- **Signed frames only.** An unsigned typing frame is dropped
  ([Typing](delivery.md#typing)).
- **The account key travels sealed to a link key.** A new device takes the
  account key with `account_key_accept_hybrid`
  ([Pairing a device with no screen](identity.md#pairing-a-device-with-no-screen)).
- **The unvouched account-key opener is out of shipped builds.**
  `account_key_open` exists only with the `fixture` feature;
  `peachy_mls_account_key_open` answers `UNSUPPORTED` otherwise.
  **Do:** open a new device's account key with `account_key_accept_hybrid`.
- **The server-approval switch does not open a version-3 box.** Under
  `server_approval_allowed`, `account_key_accept_hybrid` still opens a
  version-1 box from any approver the server lists, but a version-3 box
  opens only from the approver key the person confirmed on the device,
  switch or not.
  **Do:** a test harness that approves a device with a version-3 box confirms
  the approver key, or seals version 1.
- **What the client door trusts.** Hand the core the trusted server keys
  narrowed by `server_keys_pinned_json`, and an `own_account_identity`
  derived on the device from the account key it holds
  ([The trusted server keys](identity.md#the-trusted-server-keys)).

### Calls

- **A signed call `Joined` binds only with a usable X-Wing key.** One whose
  `media_key_pq` fails ML-KEM-768's modulus check binds nothing, and grants
  are sealed to each participant on its own. A live frame of a signal type
  the core does not know is refused
  ([Participant media keys](calls.md#participant-media-keys)). A live frame
  is checked against the replay window as soon as its signature holds, before
  anything reads the whole tree
  ([The live lane's replay window](calls.md#the-live-lanes-replay-window)).
  A signed `Joined` or `MediaKey` without its participation mark is refused;
  every build at or above the minimum sends it, and `started_at_ms` does not
  order participations.
  **Do:** let the core fill in the `Joined`; never build one by hand.

### The core's API

- **The C ABI is version 2** (`PEACHY_MLS_ABI_VERSION`, returned by
  `peachy_mls_abi_version()`;
  [The C ABI contract](mls-core.md#the-c-abi-contract)).
  The Swift package reads it as `MLSClient.abiVersion` (`abiMatches`
  compares it with its header).
  **Do:** generate every struct and binding from the header, and refuse to
  run when the library's ABI version differs from your header's.
- **One door per mailbox entry.** `process_mailbox_entry`
  (`peachy_mls_group_process_mailbox_entry`, `processMailboxEntry` in wasm
  and Swift) takes the
  mailbox kind with the envelope kind and refuses a commit outside a commit
  entry; `envelope_door` answers the table
  ([MailboxKind](delivery.md#mailboxkind)).
  `peachy_mls_group_process_door` is deprecated, and stays unchanged until
  the ABI version is raised.
  **Do:** route every entry through `process_mailbox_entry`, never by the
  envelope kind alone.
- **One door that judges and removes a server-named leaf.**
  `remove_stale_leaf` (`peachy_mls_group_remove_stale_leaf`, `removeStaleLeaf`)
  stages a removal only where `stale_leaf_removable` allows one, never of
  this device's own leaf.
  **Do:** act on `stale_device_ids` and `retired_device_ids` only through it.
- **Group recovery is in the core.** `recovery_begin`, `recovery_judge`,
  `recovery_read_due` and `recovery_drain_complete`
  (`peachy_mls_group_recovery_begin` and the rest; `recoveryBegin` and the
  rest in wasm and Swift) decide when a copy behind or forked
  forgets the group and asks back in, comparing the head's verifier as well
  as its epoch ([Group recovery](mls-core.md#group-recovery)).
  **Do:** read the head when the core asks, judge it there, and send a seat
  ask on every `REJOIN_*` step.
- **A message sealed past the copy is `STALE_COPY`.** A message or commit
  framed at an epoch past this copy's is `PEACHY_MLS_ERR_STALE_COPY` (23).
  Nothing moved.
  **Do:** treat it as a message that will not open, and judge the head with
  `SEALED_AHEAD`; never rejoin on it alone. From the client's envelope door
  it means what Envelopes above says.
- **A store in the clear is its own error.** A store opened under a key
  that turns out to be plain SQLite is `PEACHY_MLS_ERR_PLAINTEXT_STORE` (21),
  left untouched; `peachy_mls_store_encrypt_in_place` encrypts it, and
  `peachy_mls_client_open_existing` refuses a path with no store
  ([Backends](mls-core.md#backends)).
  **Do:** encrypt, keep the key apart from the store, and never delete a
  store to start over.
- **A store others can write is refused** with
  `PEACHY_MLS_ERR_INSECURE_STORE` (22) when the store or its `-wal`, `-shm`
  or `-journal` is writable by group or others, or is a symbolic link
  (judged on Unix only; [Backends](mls-core.md#backends)).
  **Do:** `chmod go-w` the files, move a store that is itself a link onto
  the file it names, never adopt the file a `-wal`, `-shm` or `-journal`
  link names, and open again; never delete the store.
- **The bundled SQLite trusts a `-wal` file beside the store.** SQLite before
  3.54 (RUSTSEC-2026-0459) can hand back stale memory when it opens a
  database beside a crafted `-wal` file. The bundled SQLCipher carries such
  a SQLite, so the core's dependency check carries an exception for it.
  **Do:** keep the store and its `-wal` in storage only this client can
  write ([Third-party client conformance](delivery.md#third-party-client-conformance)).
- **Named held fates.** `peachy_mls_held_disposition` writes
  `PEACHY_MLS_HELD_ORDINARY`, `PEACHY_MLS_HELD_FORMER_MEMBER` or
  `PEACHY_MLS_HELD_ORPHAN`.
  **Do:** read any other value as a former member's.

## Client refusals

The names `client_refusals` can carry, and what each refuses. Whether a
name is on now is in the live answer (`GetMinSupportedVersion`), not here.

| Name | What it refuses | Who enforces it |
|---|---|---|
| `signed_revocations` | Removing a person's leaf the server named without the account's signed revocation or a lapsed credential: `stale_leaf_removable` and `remove_stale_leaf` keep a sibling leaf. | the core |
| `own_seat_check` | Seating a device of one's own account whose approval does not verify under a key this device already trusts (`check_own_device_approval`). | each app |

## IPR

This document is dedicated to the public domain under CC0 1.0.
