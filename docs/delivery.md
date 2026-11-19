<!-- SPDX-License-Identifier: CC0-1.0 -->
# Delivery

**Status:** describes the protocol as implemented by the `peachy-protocol`
0.2.0 release. **Revision:** 1, 2026-11-19. **Editor:** Peachy Social, Inc.

This document specifies how a client moves sealed bytes through the Peachy
server: conversation handles, the wrapped envelope, the per-device mailbox,
commits and Welcomes, the KeyPackage directory, the realtime pokes and sealed
media. The server is an MLS (RFC 9420) Delivery Service that decrypts
nothing. Of a Welcome it reads the cleartext KeyPackageRefs
([A Welcome names a package its device published](#a-welcome-names-a-package-its-device-published)).
A send does not tell it which conversation the envelope belongs to; a commit
names its conversation's opaque handle. What the server learns is stated in
[Metadata](metadata.md). What goes inside
the MLS application messages is in [Sealed messages](sealed-messages.md);
devices, credentials and the account key are in [Device identity](identity.md).

## Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY" and
"OPTIONAL" in this document are to be interpreted as described in BCP 14
(RFC 2119, RFC 8174) when, and only when, they appear in all capitals, as
shown here.

- `‖` is byte concatenation. `SHA-256(x)` is the 32-byte digest.
- A **group id** is a random version-4 UUID minted by the device that founds
  the conversation, written in its 36-character lowercase hyphenated form. The
  MLS group id is the UTF-8 bytes of that string (36 bytes). It is also the
  client's local conversation id. It never leaves a member's device except
  inside MLS.
- `MLS-Exporter(label, context, length)` is the RFC 9420 exporter of the
  group's current epoch (`export_secret` in `mls/core`). Every exporter in this
  document uses the group id bytes as its context and a length of 32.
- An **account** is named by its actor id (a UUID). A **device** is named by
  the id of its MLS device row (see
  [One install, two rows](identity.md#one-install-two-rows)). Every recipient,
  mailbox and Welcome in this document names that MLS device id.
- Errors are Connect codes, written in their wire spelling
  (`invalid_argument`, `permission_denied`, ...).
- The ciphersuite is `0x004F`, MLS_128_MLKEM768X25519_AES128GCM_SHA256_Ed25519.
  The wire format policy is pure ciphertext: every handshake is a
  `PrivateMessage` (`PEACHY_WIRE_FORMAT_POLICY` in `mls/core/src/group.rs`).

The rpcs in scope are `CreateHandle`, `FetchConversationHead`, `SubmitCommit`,
`SendSealed`, `FetchMailbox`, `AckMailbox`, `SendSelfNote`,
`PublishKeyPackages`, `FetchKeyPackages`, `FetchKeyPackagesAnonymous`,
`KeyPackagePoolStatus`, `SetAccessKey`, `CreateUpload`,
`CreateSealedMetaUpload`, `GetCallTokenKeys`, `IssueCallTokens`,
`AbandonUpload`, `DeleteSealedObject`, `StreamEvents`, `BeatStream`,
`GetMinSupportedVersion` and `FetchVerifierAt`. Group links, join inboxes,
the call signaling rpcs (not the call-token doors) and push registration are
out of scope. Call signals travel as envelopes of kind 6
([Calls](calls.md)).

## Handles and sender-addressed delivery

Every DM and private group is **member-rostered**. Its members are the leaves
of its MLS tree and nothing else. The server holds no group row, no member
list and no group id, except for the demo conversations of Peachy's
store-review login, whose other members are devices the server runs
([Metadata](metadata.md#what-the-server-never-holds)). While a commit or a
Welcome waits to be collected,
though, the rows it wrote tie the handle to the devices still owed it and to
their accounts ([The verifier log](metadata.md#the-verifier-log)). It keys
the conversation by an opaque handle, and every send names its recipient
devices itself.

### The derived values

The reference implementation is `mls/core/src/envelope.rs` (`group_handle`,
`seal_envelope`, `open_envelope_among`) and `mls/core/src/group.rs`
(`export_secret`, `export_pending_secret`).

| Value | Derivation | Length | Who sees it |
|---|---|---|---|
| handle | `SHA-256("peachy handle v1" ‖ group_id)` | 32 | the server |
| envelope key | `SHA-256("peachy envelope v1" ‖ group_id)` | 32 | members |
| route key | `SHA-256("peachy route v1" ‖ group_id)` | 32 | members |
| epoch envelope secret | `MLS-Exporter("peachy envelope epoch v1", group_id, 32)` | 32 | members of that epoch |
| epoch envelope key | `SHA-256("peachy epoch envelope v1" ‖ epoch_envelope_secret)` | 32 | members of that epoch |
| epoch route key | `SHA-256("peachy epoch route v1" ‖ epoch_envelope_secret)` | 32 | members of that epoch |
| send key | `MLS-Exporter("peachy sealed-sender v1", group_id, 32)` | 32 | members; presented to the server in `SubmitCommit` |
| verifier | `SHA-256(send_key)` | 32 | the server |
| next verifier | `SHA-256(export_pending_secret("peachy sealed-sender v1", group_id, 32))` over the staged commit | 32 | the server |
| typing key | `MLS-Exporter("peachy typing v1", group_id, 32)` | 32 | members |
| access key | 16 bytes derived from the profile key ([Format](profiles.md#format)) | 16 | the account, and the people who have opened a message it wrote; the server keeps `SHA-256` |

Labels are ASCII with no terminator, hashed directly in front of the group id
bytes (or the epoch envelope secret's), with no separator.

Worked example, from `mls/fixtures/rosters.json` (case `handle-11111111`):

```
group_id = "11111111-1111-4111-8111-111111111111"
handle   = 82e34558853d8a1d2d9a2f84db0f092338b8f6c1fd25736c7bd032d7557e2e34
```

### What each value authorizes

| rpc | Session | Authorized by |
|---|---|---|
| `CreateHandle` | none | nothing; the first create of a handle wins |
| `FetchConversationHead` | none by handle; a session for the sweep | nothing; it reveals epochs and verifiers |
| `SubmitCommit` | none, or a session | the current epoch's **send key**, AND either every recipient account's **access key** or a session |
| `SendSealed` | none, or a session | every recipient account's **access key**, or a session |
| `FetchKeyPackagesAnonymous` | none | the target account's **access key** |
| `FetchKeyPackages` | required | the session |
| `SetAccessKey` | required | the session |
| `FetchMailbox`, `AckMailbox` | required | the session, and a device that registered under that session |
| `SendSelfNote` | required | the session; a named target is any live device of that account |
| `FetchVerifierAt` | none | nothing; it reveals a verifier the head already showed |

The send key proves "a member of this epoch made this commit", not which
member. The envelope, route and typing keys authorize nothing at the server;
they only hide routing from it. A member removed at a commit does not hold
the next epoch's envelope and route keys, so it cannot recognize, open or
forge an envelope sealed under them.

### Access keys

Every account has one access key, derived from its profile key
([Format](profiles.md#format)) and kept in the encrypted account store (the
`account` record, field `accessKey`, standard padded base64, 24 characters).

- The device registers it with `SetAccessKey { access_key }`. The server
  stores `SHA-256(access_key)` for the account. A key that is not 16 bytes is
  `invalid_argument`. A new call replaces the old key.
- Peers learn it from the `ak` field of the transcript frames it writes, and
  of a hello ([Hellos](sealed-messages.md#hellos)), and keep it in the
  `contact` record of their own account store. No other frame, nor the
  group's state, nor a Welcome carries it. Every member device sends a hello
  after it joins and after an account new to the tree is added, within about
  30 seconds.
- A client MUST NOT present its own account's key until `SetAccessKey` for
  that key has succeeded. Until then it sends identified.
- A client MUST NOT change where its key travels because it blocked
  somebody: that would tell the server whom it blocked. A block does mint a
  new key, which goes wherever the old one went
  ([Rotation](profiles.md#rotation)); what the server learns from the change
  is in [G5](metadata.md#what-the-server-never-holds).
  Removing a member from a group does not change any key.

**The check.** For a sessionless call the server computes, for every account
the call names, `SHA-256(presented key)` and compares it in constant time with
the stored hash, each account on its own key. A missing key, a wrong key, a
key of the wrong length, an account that never set a key, or an unknown
account all fail the **whole** call with one `permission_denied` ("access
denied"). Every account is compared whether or not an earlier one failed.
A deleted account has no key and passes whatever is presented for it (a
dummy is still compared): a send or commit places nothing for its devices,
which come back in `stale_device_ids`, and `FetchKeyPackagesAnonymous`
answers with no packages. So a conversation that
still seats a deleted person's devices goes on sending without a session.

**Meters come after the check.** `FetchKeyPackagesAnonymous` is metered per
connecting IP address and per named account. The account's meter is charged
only once the key has matched, or the account is found deleted, so a caller
without the key cannot spend a live person's meter.

**Identified sends.** A call that carries a session is authorized by the
session alone and ignores `access_keys`. A client SHOULD go sessionless when
it holds the key of every account it names and MUST otherwise send with its
session ([G7](metadata.md#what-the-server-never-holds)).

**The sessionless transport.** A sessionless call MUST travel on a connection,
TCP and TLS, that has never carried `authorization`, and MUST NOT resume a TLS
session from one that has. It MUST NOT carry a cookie, or any header that
names the account, the device or the build; the user agent says only which
kind of app it is. A client SHOULD close an idle sessionless connection after
a short while, so that one connection does not string a long run of
sessionless calls together. The IP address is not hidden
([Metadata](metadata.md#what-the-server-never-holds)).

### The wrapped envelope

Every sealed byte of a conversation (an MLS message, a commit, a seat ask, a
typing frame) is wrapped before it leaves the device, because an MLS
`PrivateMessage` carries its group id and epoch in the clear.

```
envelope  = version ‖ nonce(12) ‖ tag(16) ‖ AES-256-GCM(enc_key, nonce, aad, plaintext)
tag       = SHA-256(route_key ‖ nonce)[0..16]
aad       = version ‖ tag
plaintext = kind(1) ‖ u32be(len(inner)) ‖ inner ‖ 0x00 … 0x00

version 2:  under the envelope and route keys of the group id
version 3:  under the epoch envelope and route keys of the epoch it was sealed at
```

- `nonce` is 12 fresh random bytes per envelope.
- The header (version, nonce, tag) is 29 bytes and the ciphertext carries the
  16-byte GCM tag at its end, so an envelope adds 50 bytes to its inner bytes
  before padding.
- **Padding.** The zeros make the whole envelope
  `max(512, padme(50 + len(inner)))` bytes long, where `padme(L)` rounds `L`
  up so that only its top `floor(log2(floor(log2 L))) + 1` bits may be
  non-zero (Padmé [PURBs]; at most 12% overhead). The length depends on the
  inner length alone, never on the kind, so every short envelope (a short
  message, a reaction, a receipt, a seat ask, a typing frame, a call frame)
  is exactly 512 bytes. `padded_envelope_len` in `mls/core` computes it.
- A receiver MUST refuse a version 2 or 3 envelope whose length field runs
  past its end or whose padding is not all zeros.
- A receiver MUST open versions `0x02` and `0x03`. Anything else, `0x01`
  included, does not open. The version byte is authenticated (it is in the
  `aad`): a version 3 envelope relabeled `0x02` opens under no key.

**Which version is sent.** A member MUST seal version 3 into every group it
holds, or send nothing. Version 2 is sent only for a seat ask (kind 3) and
a link preview (kind 5), whose reader holds no epoch of the group. A member
MUST NOT seal a message, commit, typing frame or call signal by the group
id: it would open for a removed member or a link holder, and its version
byte would set the client that sent it apart. A receiver still opens and
routes a version-2 envelope of kinds 1, 2, 4 and 6; what is inside
authenticates itself.

`Client::seal_envelope` in `mls/core` seals by this rule, and refuses a
message, commit, typing frame or call signal for a group the device does not
hold (`NO_SUCH_GROUP`). The core's clientless door (`envelope::seal_envelope`,
`peachy_mls_seal_envelope`, the free `sealEnvelope` in wasm) seals only kinds
3 and 5 and refuses every other.

**The epoch sealed at.** A message, a typing frame and a call signal are
sealed at the sender's current epoch. A commit is wrapped after the
committer merged it, when its receivers are still an epoch behind: kind 2
(and kind 1, which carries a carried commit) is sealed at the epoch the MLS
message inside says it was built in, read from its clear header. A member
keeps the epoch envelope secret of its current epoch and the 31 before it
(`ENVELOPE_PAST_EPOCHS`), so a sender one commit behind still reaches the
members that moved on, and a reseat can hand a returning device the epochs it
missed ([Rejoin with a sealed seat ask](#rejoin-with-a-sealed-seat-ask)).
That is more than the four past epochs whose message secrets it keeps
(`RETAINED_PAST_EPOCHS`): an envelope secret opens only the envelope. With
each secret the member keeps a digest of the device keys the commit that left
that epoch added (`added_next`).

A client MUST NOT send a message or commit made at an epoch its copy no
longer keeps, nor anything but a seat ask or a link preview from a copy no
longer in the group: it encrypts the message again at its current epoch and
never resends the old bytes. The client's door refuses the first with
`STALE_COPY` and the second with `NOT_A_MEMBER`, and seals nothing.

| Kind | Name | Inner bytes | Sent through |
|---|---|---|---|
| 1 | MESSAGE | an MLS `PrivateMessage` of content type application | `SendSealed` |
| 2 | COMMIT | an MLS `PrivateMessage` carrying a commit | `SubmitCommit` |
| 3 | SEAT_ASK | the seat-ask JSON ([Rejoin with a sealed seat ask](#rejoin-with-a-sealed-seat-ask)) | `SendSealed` |
| 4 | TYPING | a typing frame ([Typing](#typing)) | `SendSealed` with `ephemeral` |
| 5 | LINK_PREVIEW | reserved for group links, out of scope | never in a mailbox |
| 6 | CALL | a call signal ([Calls](calls.md)) | `SendSealed` |

A receiver MUST refuse any other kind. A Welcome is never wrapped: it is
sealed to one device's init key and routed by device.

**Opening.** The receiver does not know the group. For a version 2 envelope,
for each group it holds, it computes `SHA-256(route_key ‖ nonce)[0..16]` and
compares it with the tag; on a match it decrypts with that group's envelope
key. For a version 3 envelope it does the same with the epoch route and
envelope keys of each held group's current epoch, then of the past epochs it
kept. A failed decryption, a bad version or no matching group means the
envelope does not open (`open_envelope_among`, `Client::open_envelope`).

Worked example, `mls/fixtures/rosters.json` case `seal-message-v2`
(`envelopeVersion: 2`): group `11111111-1111-4111-8111-111111111111`, kind 1,
inner `68656c6c6f` ("hello"), nonce `000102030405060708090a0b`:

```
02                                  version
000102030405060708090a0b            nonce
5ccbefd44abeb17df395e2a8edfd31b5    tag
e4dcd644ef1d33e394d901d052 …        AES-256-GCM(0x01 ‖ 00000005 ‖ "hello" ‖ 457 zeros), 467 bytes
… 3dd634065dde0c6b37ac7949          GCM tag, the last 16 bytes
```

The envelope is 512 bytes, the floor. The same, case `seal-message-v3`,
sealed by the epoch envelope secret `0102…1f20` (the 32 bytes 0x01 to 0x20):

```
03                                  version
000102030405060708090a0b            nonce
ab187f5a712cdeddc17233e9d8db7147    tag
d69928d71fd6e88c60291f7ca4 …        AES-256-GCM(0x01 ‖ 00000005 ‖ "hello" ‖ 457 zeros), 467 bytes
… 0ac0959e39ecf1dc2b884e7a          GCM tag, the last 16 bytes
```

The fixture also pins a commit, a seat ask and a typing frame, and opening
among several groups or epochs, a non-member, another epoch, a version 3
envelope tried by group id, a tampered byte, a relabelled version, an unknown
version and a non-envelope.

### Founding a conversation

1. Mint the group id (random UUID v4).
2. Create the MLS group (`create_group`), then, on the group of one, run
   steps 5.1 and 5.2. A founding that fails there forgets its group and
   sends nothing more.
3. `CreateHandle { handle, verifier }`, where `verifier` is
   `SHA-256(send key at epoch 0)`.
4. Commit the group's initial state (`peachy_group_meta`) with
   `SubmitCommit`, addressed to nobody (`recipients` empty), and merge it once
   accepted.
5. Seat the other people's devices and the founder's own other devices
   (`mls/core/src/founding.rs`):
   1. Fetch one KeyPackage of every device to seat, **this device's own
      included**, once: through `FetchKeyPackagesAnonymous` for each
      account whose access key this device holds (its own under its own
      key, once `SetAccessKey` has succeeded), and through
      `FetchKeyPackages` with its session for the rest, skipping no device
      of its own account ([G7](metadata.md#what-the-server-never-holds)).
      Fetch the accounts sorted bytewise by account id, the founder's own
      among them, never in the order she picked people in. Fetch once and
      never repeat: a repeat only a founder makes would tell the server who
      founded. If this device's own package did not come back, or
      `key_package_identity` does not read it as a valid KeyPackage of
      this device's own id and device key, fail the founding.
      The server labels each package with a device id of its choosing;
      `seat_founding` refuses any other package as this device's seat, but
      only after `CreateHandle`.
   2. Take the other packages in the order of the device ids the server
      labeled them with (sorted bytewise), up to `FOUNDING_MAX_SEATS` (32)
      with this device's own. Leave out every package `founding_refusals`
      names, first come first seated: one the core refuses at an add (its
      credential and KeyPackage checks, its lifetime on the founder's clock,
      a leaf that does not list `peachy_group_meta`, and one person under one
      account key, judged against this device and the packages accepted
      before it), one whose device already holds a leaf, one of the founder's
      own devices that her device forgot as removed (`forget_own_device`, by
      its id or any key it was seen holding), a second package for a device
      id an earlier accepted package carries, and one the MLS founding commit
      would refuse (another cipher suite, leaf capabilities that don't list
      the group's suite or credential type, or keys another package or leaf
      already uses). A package that commit refuses is left out before the
      other checks run again, so it claims no device id or account key ahead
      of a later package. The founder's own
      other devices are judged by these rules alone, with no call to the
      server. If the founding means to seat another person, packages of
      another person came back, and none of them is left, fail the founding.
      If no other person's package came back at all, go on with the
      founder's own devices: each other person is added one commit each once
      a package of theirs appears. A founding that means to seat only the
      founder's own devices (a note to self, a community's own group) fails
      only when some came back and none is left; with no other device to
      seat, there is no seating commit.
   3. Build **one commit** (`seat_founding`) that adds every device left
      but this one. Its one Welcome carries a secrets entry for each, plus
      one sealed to this device's own fetched KeyPackage, as long as the
      others, sorted by KeyPackageRef. The core seats the devices in an order
      drawn at random. If the core still refuses it, fail the founding.
   4. Submit it addressed to nobody, with that Welcome to every device it
      seats and to this one, listed in device-id order, and merge it once
      accepted.
   5. Then add each device left out or past the cap one commit each. A
      left-out package is refused there too, except one left out only
      because an earlier package carried, as its HPKE init key, this
      package's init key or leaf key: init keys are not in the tree, so that
      add can seat it.

A founding never falls back to one add per commit. Only a package whose
credential lapses between steps 5.2 and 5.3 can fail the founding after
`CreateHandle`.

The founder's own Welcome entry does not open: the core erases a one-time
package's private half once it seals the entry. Her device sweeps the heads
for the page that holds it, as every recipient does for a page holding a
Welcome, and acknowledges it like any Welcome it cannot open
([Two seats under one group id](#two-seats-under-one-group-id)). A reader
finds its own entry by its KeyPackageRef and ignores the others (RFC 9420
§12.4.3.1).

`CreateHandle` is sessionless and metered per IP. `handle` and `verifier`
MUST be 32 bytes (`invalid_argument` otherwise). It opens the head at epoch 0.
An identical retry succeeds. Any other create of an existing handle is
`already_exists` ("that handle is taken").

**A direct chat.** A conversation with `dm` set is a direct chat: a 1:1, a
note to self (only the founder's own devices), or an unnamed chat of several
people. Its initial state is:

```json
{"v":1,"n":"","adm":["<every member's actor id, the founder's included>"],"dm":true}
```

plus `dis` when the founder's default disappearing timer is on. Every member
of a direct chat is an admin from the first commit.

**One direct chat per set of people.** A direct chat's identity is its
member set: the actor ids in `adm`, the actors that hold a leaf, and the
viewer's own, deduplicated and sorted. Leaving does not take anybody out of
`adm`. If two active direct chats have the same member set, each device MUST
show only the one whose handle sorts lower, compared bytewise, and SHOULD
file messages that arrive in the other under it. A client starting a direct
chat SHOULD first look for an active one with the same member set and reopen
it.

### Sending

`SendSealedRequest`:

| Field | Rule |
|---|---|
| `payload` | the wrapped envelope. 1 byte to 1 MiB, or 1 to 4096 bytes when `ephemeral` |
| `recipients` | `SealedRecipient { user_id, device_id }`. Required; empty is `invalid_argument` |
| `access_keys` | `RecipientAccessKey { user_id, access_key }`, one per account named, for a sessionless send |
| `urgent` | set exactly when the content hint is 1 or 3 ([The urgent bit](#the-urgent-bit)). Drives push and the rate lane |
| `ephemeral` | relay to open streams only; never stored (a typing frame, a live-lane call frame) |
| `client_message_id` | the retry key. A client MUST send one on every stored send, a UUID ([Idempotency](#idempotency)); not sent with `ephemeral` |

**Who to address.** A sender MUST name exactly the devices of the leaves in
its current tree, **its own device included**, and its own account's other
seated devices with them, and no other device. A device of its account that
holds no leaf in this conversation gets nothing until it is seated
([Seating your own new devices](sealed-messages.md#seating-your-own-new-devices)).
So every send from a device at the same epoch names the same set.
A sender MUST list `recipients` sorted bytewise by device id (the canonical
lowercase UUID string), once each, and `access_keys` in the order their
accounts first appear in `recipients`, then in `welcomes`; the same holds for
`SubmitCommit`, which lists its `welcomes` sorted by device id too. A sender
MUST NOT list `recipients` in the tree's leaf order, which is join history.
Neither the server nor a receiver checks the order. If the only leaf is the
sender's own device, the client sends nothing. This holds for every frame,
receipts and typing included.

One exception: a group ring's `*_elsewhere` reply is sent to the replier's
own devices alone
([The ring is a message](calls.md#the-ring-is-a-message)).

**Server checks**, in order:

1. Payload size, `recipients` present, and a `client_message_id` that is a
   UUID when present (`invalid_argument`). A request that sets
   `sealed_attachments` (field 7) is refused (`invalid_argument`), and so is a
   version 1 envelope (`failed_precondition`, `peachy-refusal:
   envelope-retired`; [Retired builds](#retired-builds)).
2. At most 1024 recipient devices and 256 distinct accounts
   (`invalid_argument`). Pairs whose ids are not UUIDs are ignored.
3. Authorization ([Access keys](#access-keys)).
4. Rate meters: per IP for sessionless calls, per caller for identified ones,
   and per recipient account, in three lanes: urgent (messages, reactions,
   edits, deletes, call rings), not urgent (control frames such as
   receipts), and ephemeral (typing frames, live-lane call frames). Each
   sender (the caller, or a sessionless call's IP address or IPv6 /64) has
   an allowance of its own in each lane, which no other sender draws on. A
   send inside it is charged to no recipient. Only a send past it is
   charged to each account it names, from that account's budget, which
   only senders past their allowances share. So a send is refused only
   when its sender is past its allowance and some account it names is
   spent. A sender within its allowance is never refused because of another
   sender's traffic; senders past theirs share each recipient's budget. An
   exceeded meter is `resource_exhausted` for the whole send, and nothing
   is charged. A client MUST back off and retry later. It MUST NOT spread
   one send across smaller calls to dodge the meter.
5. For each pair, the device must be that account's own, unrevoked, approved
   device that has a mailbox (a device gets one when it first publishes
   KeyPackages). Pairs that fail are **dropped silently**. Device ids that do
   not exist or are revoked come back in `stale_device_ids`. A device marked
   retired gets nothing and comes back in `retired_device_ids`
   ([Retired devices](#retired-devices)).

The server then stores the payload once, with one mailbox entry per accepted
device, and returns `SendSealedResponse { id, received_at, stale_device_ids,
stale_revocations, retired_device_ids }`.

- `id` is the envelope's UUID, the same in every recipient's mailbox. Members
  use it to name a sealed message to each other outside the ciphertext (for
  example a resend ask).
- `received_at` is whole seconds.
- When `urgent` is set, each recipient account that still holds the envelope
  after a short delay gets a push.
- Every account given an entry is poked with `STATE_DOMAIN_MAILBOX`.

**Stale devices.** A client receiving `stale_device_ids` SHOULD remove those
leaves from the group in a later commit, each one the core allows on the
account's revocation in `stale_revocations` (the signature `ListDevices`
shows as `Device.revocation`) or a lapsed credential (see
[Revocation reaches a seated leaf through the roster](identity.md#revocation-reaches-a-seated-leaf-through-the-roster)).

#### The urgent bit

`urgent` is the one thing a stored send tells the server about what it
carries, derived from the content hint alone (see
[Sealed messages](sealed-messages.md)):

| Content hint | What it carries | `urgent` |
|---|---|---|
| 1 RESENDABLE | a transcript message | set |
| 3 RESENDABLE_LANE | a reaction, an edit, a delete | set |
| 2 IMPLICIT | a receipt, a resend ask or answer, a history share, a group event | clear |
| 0 DEFAULT | a call record | clear |

An envelope of kind 6 (CALL) sets it for a ring, an answer and a hang-up and
clears it for every other call signal (`call_signal_is_urgent`). Kinds 2, 3
and 4 clear it. A client MUST NOT set it any other way. A device that opens
any urgent frame from somebody else owes the same delivered mark
([Receipts](sealed-messages.md#receipts)). A client never reads the bit
back ([MailboxKind](#mailboxkind)).

#### Idempotency

Every stored send carries a retry key in `client_message_id`. When an
envelope with that key is still stored anywhere, the server places nothing
and returns the earlier `id` and `received_at`. After every recipient has
acknowledged the envelope, or after 30 days, a retry with the same key is a
new send. A stored send without a key is placed with no dedupe.

The key MUST be one nobody but the sending device can compute, because
whoever can present it learns from the answer whether the envelope is still
waiting:

- For a transcript message, the device keeps a 32-byte **retry secret**,
  random per install and never sent anywhere, and computes
  `HMAC-SHA256(retry_secret, "peachy retry key v1" ‖ message id)` [RFC 2104],
  the message id as its UTF-8 string, and takes the first 16 bytes with the
  UUID version-4 and variant bits set. The message id is the frame's `i`, so
  every retry of the same message, from an outbox that survives a restart,
  presents the same key.
- Every other stored send uses a random UUID kept with the pending send.
- A client MUST NOT use a message id, or anything else a recipient sees, as
  the key.

Every stored send keeps its key from when it is queued until it is placed,
and presents it on every retry. A client MUST NOT derive the key of a lane
frame from the message it names or from its content: two frames about one
message would share a key. Every urgent send is retried under the same
policy, in order per conversation.

`retryKey` in `mls/fixtures/formats/content-hint.json`
([Formats](formats.md#content-hintjson)) pins the derivation. A device that
loses its retry secret makes a new one.

**One stale-epoch retry.** If a send fails because the device's epoch is
behind (a refusal that a drain would fix), the client drains, re-encrypts the
same content at the new epoch, and sends the **new** bytes once. It MUST NOT
resend old ciphertext.

### Own sends come back

A device that names itself receives its own envelopes, and MLS will not
decrypt a device's own application message. So:

- Before sending, the device MUST remember each envelope's nonce (the 12 bytes
  after the version byte) durably.
- When an envelope with a remembered nonce comes back through its mailbox, the
  device MUST acknowledge it **without processing it**, with the rest of its
  page, at the page's floor ([The ack's floor](#the-acks-floor)).
- An own envelope the device no longer remembers is harmless: each door
  answers an own message, or a commit still staged, as an echo, and an own
  commit already merged is below the local epoch and is skipped
  ([A commit this device cannot apply](#a-commit-this-device-cannot-apply)).

### Typing

A typing frame ([Typing inside the group](sealed-messages.md#typing-inside-the-group))
is the inner bytes of an envelope of kind 4.

- It is sent with `SendSealed { ephemeral: true, urgent: false }`, no
  `client_message_id`, to the whole tree. The server relays it as
  `EphemeralEvent.payload` to every open `StreamEvents` stream of each
  recipient account, and stores and pushes nothing.
- A frame is 284 bytes and signed; an unsigned frame is dropped. Wrapped, it
  is 512 bytes, like any other short envelope.

- A frame from an epoch the receiver has left does not open, and is ignored
  without a log.

## The ordering rule

The server orders commits and nothing else:

> A commit names the epoch it was built in, and is accepted only if that is
> still the head's epoch. Accepting it moves the head to the next epoch.

Each handle has one head: `(epoch, verifier)`. `SubmitCommit` locks the head,
compares, advances it and places every envelope the commit produces in one
atomic step. So:

- **Commits arrive in epoch order.** Within one device's mailbox, entries
  come back in the order they were placed. A commit into epoch N+1 is placed
  in the same step that moves the head to N+1, and any envelope a member seals
  at N+1 is placed after it in every mailbox that holds both.
- **Application messages are not ordered by the server.** A message sealed at
  epoch N may arrive after the commit to N+1. The receiver keeps the secrets
  of the 4 epochs before its current one (`RETAINED_PAST_EPOCHS` in
  `mls/core/src/group.rs`) to open it
  ([Retained past epochs](mls-core.md#retained-past-epochs)).

### SubmitCommit

`SubmitCommitRequest`:

| Field | Rule |
|---|---|
| `handle` | 32 bytes |
| `epoch` | the epoch the commit was built in |
| `commit` | the wrapped commit (envelope kind 2). 1 byte to 4 MiB |
| `send_key` | the send key of `epoch`, 32 bytes |
| `next_verifier` | `SHA-256` of the send key the commit produces, 32 bytes |
| `recipients` | every device in the tree **before** the commit, the committer's own included; none for a founding's commits addressed to nobody ([Founding a conversation](#founding-a-conversation)) |
| `welcomes` | `MlsWelcome { recipient_device_id, recipient_user_id, welcome }`, at most 512, each 1 byte to 4 MiB |
| `access_keys` | for every account in `recipients` and `welcomes`, for a sessionless commit |
| `meta_object_keys` | at most 4 `sealed-meta/<uuid>.bin` keys the new group state points at |

Server behavior:

1. Shapes: `invalid_argument` for a bad handle or `next_verifier` length, an
   empty or oversized commit or Welcome, too many Welcomes, a malformed
   Welcome recipient, or a bad `meta_object_keys` list. A version 1 commit is
   refused with `failed_precondition`, and any other commit that is not a
   version 2 or 3 envelope with `invalid_argument`, both with
   `peachy-refusal: envelope-retired` ([Retired builds](#retired-builds)).
2. Authorization, exactly as for `SendSealed`, over `recipients` plus every
   Welcome recipient: at most 1024 devices and 256 distinct accounts counted
   together (`invalid_argument`), then [Access keys](#access-keys).
3. Every Welcome's device MUST be its named account's live device; otherwise
   the whole commit is `invalid_argument`. Every Welcome MUST name a package
   that device published, which the server checks
   ([A Welcome names a package its device published](#a-welcome-names-a-package-its-device-published)).
4. Lock the head. No head: `not_found` ("no such conversation"). A head at
   another epoch: `failed_precondition`. `SHA-256(send_key)` not equal to the
   head's verifier, or a send key that is not 32 bytes: `permission_denied`
   ("not allowed").
   Then the handle's commit budget, and each Welcome's person's
   ([Welcomes are metered per person](#welcomes-are-metered-per-person)): a
   short one is `resource_exhausted`, and nothing is placed or charged.
5. Move the head to `epoch + 1` with `next_verifier`. Mark the group-photo
   objects in `meta_object_keys` taken, so the sweep keeps them; one minted
   with a session is left as it was ([Abandon, delete](#abandon-delete)).

6. Place the commit (`MAILBOX_KIND_COMMIT`) for every accepted recipient
   device **except** the devices that receive a Welcome, and except a device
   marked retired, which comes back in `retired_device_ids`. Place each
   Welcome (`MAILBOX_KIND_WELCOME`) for its one device.
7. Poke every account given an entry with `STATE_DOMAIN_MAILBOX`. A commit
   made with a session also pokes the caller's account with
   `STATE_DOMAIN_MLS`.

**The group's size.** Since every commit names every device in the tree, a
tree of more than 1024 member leaves or 256 accounts could take no further
commit. A device stages no commit that leaves more, nor one that brings in a
leaf node over 12 KiB (`MAX_LEAF_NODE_BYTES`), and a receiver refuses such a
commit (`mls/core/src/policy.rs`). Every member pads its commits to carry the
largest leaf.

The response is `SubmitCommitResponse { seq, epoch, stale_device_ids,
stale_revocations, retired_device_ids }`, where `epoch` is the new epoch and
`seq` equals it. Commits are not metered per recipient; Welcomes are, per person
([Welcomes are metered per person](#welcomes-are-metered-per-person)).

**On success** the committer merges its staged commit
(`merge_pending_commit`). **On `failed_precondition`** it MUST NOT resend the
same bytes. It clears the staged commit, drains its mailbox, applies what it
missed, rebuilds the same intent against the new tree, and submits again.

**A submit whose answer was lost.** If the call fails without an answer, the
commit may have been taken. Before treating it as refused, the client MUST
read the head with `FetchConversationHead`. If the head's epoch is
`epoch + 1` and its verifier equals the `next_verifier` the commit carried,
the commit was taken: the client merges it.

### The carried commit

A leave is the one proposal a commit names by reference
([Leaving](sealed-messages.md#leaving)), and a member that never received a
proposal cannot apply a commit that names it (RFC 9420 §12.4). So a commit
of leaves carries the proposal messages it names, exactly as the committer
took them in, in the same entry:

```text
raw     = MLSMessage(commit)                          starts 00 01
carried = ff 4c 43 01 ‖ n ‖ n × (uint32 len ‖ proposal) ‖ commit
```

`n` is one byte, 1 to 64, and each `len` is big-endian. The commit is
everything after the last proposal and is never empty
(`mls/core/src/carried_commit.rs`, `mls/fixtures/carried-commit.json`). The
frame sits inside the kind-2 envelope where a raw commit does. A reader tells
the two forms apart by the first byte. It takes each carried proposal through
the message door first (one it already holds, or one the door refuses,
changes nothing) and then the commit; anything carried that is not a proposal
is not opened. A frame with no proposal, more than 64, a length that runs
past its end, an empty proposal or no commit is refused. Every member that
commits a given leave carries the same proposal bytes.

### FetchConversationHead

Each `ConversationHead { handle, epoch, verifier }` gives a head's epoch and
that epoch's verifier. A member compares the verifier with `SHA-256` of its
own send key to learn whether its tree is the one the head was built on. A
list of handles read together is a list of one device's conversations, so the
call has two forms.

**The sweep**, `FetchConversationHead { every: true, after }`, reads every
head on the server, a page of at most 5000 in ascending handle order (about
80 bytes a head), naming none. `after` is empty for the first page and
otherwise the last handle of the page before, 32 bytes; `more` says whether
another page follows. The sweep requires a session and is metered per IP;
`handles` beside `every`, or an `after` of another length, is
`invalid_argument`. A client MUST use the sweep whenever it checks more than
the one handle it just committed to. It MUST read every page of a sweep it
starts, to the last, whatever it finds on the way. It stops after 1,000
pages (5,000,000 heads) and takes what those pages hold. It SHOULD reuse one
sweep for 30 seconds.

A reused sweep can be older than a commit the device
has applied since, so a head from it below the local epoch says nothing yet:
the client MUST judge such a head only on a sweep begun after it read its
local epoch ([A commit the server refuses](#a-commit-the-server-refuses)).

**By handle**, `FetchConversationHead { handles }`, is sessionless and metered
per IP. At most 500 handles (`invalid_argument` otherwise). Handles that are
not 32 bytes are ignored; unknown handles are absent from the answer. A
client MUST use it only for the handle of a commit it just submitted itself
(a submit whose answer was lost, or one the server refused).

### The sealed stamp

On every commit the server seals what it was told, under a key only members
of the commit's epoch derive, and attaches it to the commit's mailbox entry
(`MailboxEnvelope.commit_stamp`):

```text
key   = HKDF-SHA256(ikm = send_key_E, salt = empty, info = "peachy commit stamp v1")
plain = S ‖ K ‖ M                                                     96 bytes
stamp = 01 ‖ nonce(12) ‖ AES-256-GCM(key, nonce, plain, aad = 01 ‖ BE64(E))   125 bytes
```

`S` is the `next_verifier` the commit was submitted with. `K` is a steward
key the server holds for the handle and `M` a MAC from the committer, each
32 zero bytes when there is none. No client supplies either, so the server
seals zeros for both. Receivers still read them: `K` against the steward key
a group's meta names (`stw.k`), and `M` to tell `blame` from `repair`. No
commit is taken or refused for either; a `K` that is not zero only narrows
when a head reads as rolled back
([A commit the server refuses](#a-commit-the-server-refuses)). A stamp names
no handle.

A receiver hands the stamp to the core before the commit door
(`note_commit_stamp`), and after the merge takes the core's check
(`take_commit_check`). The core opens the stamp with the epoch's send key,
computes `V`, the verifier the commit really produces, and compares:

| Observation | Verdict | Meaning |
|---|---|---|
| no stamp | `absent` | the server sent none |
| the stamp does not open | `unopened` | not this epoch's stamp |
| `S = V` | `match` | the head is the one the group holds |
| `S ≠ V`, `M` a valid MAC | `blame` | the committer named a verifier its commit does not produce |
| `S ≠ V`, otherwise | `repair` | the server or the committer named a verifier the commit does not produce, and the two cannot be told apart |
| the commit removed this device | `unjudged` | no `V` to compute |

The check also compares `K` with the steward key the meta names once the
commit merges (`mismatch`). A stamp the core cannot check (the copy cannot
export its keys) is `unjudged`. No commit is refused for its stamp; a verdict
other than `match` is logged, and the person is shown nothing.

### FetchVerifierAt

`FetchVerifierAt { handle, epoch }` returns `{ verifier, kept_from }`: the
verifier the handle's head held at `epoch`, from the **verifier log**, or
empty when the log holds none, and the log's **floor**. Every handle is
logged: the server writes the row for epoch 0 at `CreateHandle`, and the row
for each epoch the head moves to in the transaction that moves it
(`SubmitCommit`, a group link's or a call link's commit, the founding of a
call link), so a Welcome placed by a commit always has its row. The log
keeps a handle's last 4096 epochs, trimmed by count
in the statement that writes a row, never by age; a row holds the handle, the
epoch and the verifier, and no timestamp, though its transaction id orders it
among the server's other writes ([The verifier log](metadata.md#the-verifier-log)).

`kept_from` is the first epoch of the unbroken run of rows that ends at the
head's own epoch. It is absent when the head's own epoch has no row. The
floor is kept on the head, moved in the statement that
writes each row; it is only ever at or above the run's true start, so it
never refuses a real Welcome.

The call is sessionless and authorized by nothing: every verifier it answers
is one the head showed to anybody who asked by handle. It is metered per IP.
A negative epoch, one out of range, an unknown handle and an epoch with no
row all answer an empty verifier.

A device calls it for a Welcome **below** its group's head, after reading the
Welcome's group and epoch (`welcome_group`) and finding the head in the
page's sweep, with no session, and passes the answer to
`join_from_welcome_at_head_logged(welcome, head_epoch, head_verifier,
logged_verifier, kept_from)`. The core compares the verifier with `SHA-256`
of the Welcome's send key:

- **A mismatch** refuses the Welcome with `already a member`: the seat is in
  a group somebody founded under the id.
- **A match** places the seat as a Welcome at the head is placed, confirmed
  and able to replace a held copy that is not at the head
  ([Two seats under one group id](#two-seats-under-one-group-id)), except
  that it never replaces a live copy at or above its own epoch.
- **No verifier, at an epoch at or above `kept_from`** refuses it too. An
  empty answer, or one that is not 32 bytes, is none.
- **No verifier, below `kept_from` or with none named** is judged as without
  the log, and the client logs a warning. The seat is unconfirmed until its
  commits carry it up to a head, and names no devices of its people's that
  the new tree left out.

The read runs outside the group's lock. **A read that fails holds the
Welcome** in the mailbox for the next drain; an answer that could not be
read, `unimplemented` included, is never taken for "nothing logged".

## A commit this device cannot apply

A device drains its mailbox in order and hands each envelope to the engine
through the door for its kind (`process_message` or `process_commit`). When
the commit door refuses an entry, the client MUST decide among three
outcomes, using `commit_strands(group_id, message)` in `mls/core`
(`peachy_mls_group_commit_strands` in the C ABI), never the server's label on
the entry. It answers true exactly when the group is held and active, the
bytes are the commit at the device's local epoch that the commit door refused
last, and that commit **opened and verified** before it was refused: a member
of the group at this epoch built it, and this device's own checks (the group
policy, a credential) refused what the rest of the group merged.

A commit that did not open never strands, whatever its epoch: its framing is
in the clear, and anyone who holds the group id can write it. Such a commit,
framed at or above the local epoch, is skipped, and the client reads the
group's head ([A commit the server refuses](#a-commit-the-server-refuses))
at most once a minute per group.

| Case | Outcome |
|---|---|
| A transient failure: storage error, closed client, a panic, `commit_strands` itself failing | **hold**: do not acknowledge; stop the page; try again on the next drain |
| `commit_strands` true | **strand**: forget the group and ask back in ([Rejoin](#rejoin-with-a-sealed-seat-ask)) |
| A commit framed at or above the local epoch that did not open | **skip**, and read the head: `behind` with the commit framed above the local epoch, `behind` that does not clear, or `forked` rejoins |
| Anything else: a commit below the local epoch (a duplicate or replay), not a commit, unparseable, another group's | **skip**: acknowledge and go on |

Once the rejoin's Welcome lands, every commit that stranded the device is
below its epoch and is skipped. A group already waiting on a rejoin is
forgotten again if it came back, but no second ask is sent.

### A message that will not open

An application message the message door refuses falls in one of these
groups.

- **One this device already opened**, handed over again under a fresh
  envelope id: `Error::Duplicate` (`PEACHY_MLS_ERR_DUPLICATE`, 20), said only
  when the core's own record shows it opened exactly these bytes
  ([Receiving](mls-core.md#receiving)). The client acknowledges it and drops
  it in silence: no placeholder, no resend ask, no decrypt-health report, no
  notification, no head read.
- **From a device no longer in the group.** It opened and its signature
  verified, at an epoch the device still holds keys for, but the leaf that
  signed it is not in the current tree: `Error::NotFromAMember`
  (`PEACHY_MLS_ERR_NOT_FROM_A_MEMBER`, 17). The client drops it in silence,
  as above. A message a member sealed just before its removal and delivered
  after it is dropped the same way. A message from a current member sealed at
  a past epoch still opens.
- **Transient**: held, as for a commit.
- **Sealed past this copy's epoch**: `Error::StaleCopy`
  (`PEACHY_MLS_ERR_STALE_COPY`, 23). The copy is behind or forked. The
  client reads the head as below, outside the minute's limit when the last
  read did not know of such a message, and a `behind` reading strands the
  copy at once ([A commit the server refuses](#a-commit-the-server-refuses)).
- **Anything else** (it does not decrypt at all): handled by its content hint
  ([sealed-messages.md](sealed-messages.md)), and the client reads the head at
  most once a minute per group. Bytes that do not decrypt cannot be
  attributed.

**An envelope that opens for no group.** A version 2 envelope that no held
group opens is for a group this device is not in, and is acknowledged and
dropped. A version 3 envelope that opens for no group may be that too, or one
sealed at an epoch this device's copy never reached, the only trace a copy
that fell behind or forked sees. The client MUST then check every group it
holds against its head, as after a lost mailbox ([Retention](#retention)),
and SHOULD do so at most once every ten minutes. The envelope itself is
acknowledged.

Before acknowledging a version 3 message envelope (mailbox kind MLS) that
opened for no group, the client hands it to its core to keep
(`Client::hold_envelope_sealed`, with the mailbox's id, kind and receive time,
and an empty seal). The same bytes are held once, whatever mailbox id they
come under. The core keeps at most 100 (`HELD_ENVELOPES_KEPT`; the oldest
goes first) and none older than 30 days (`HELD_ENVELOPE_MAX_AGE_MS`).

After every mailbox pass the client asks for each one that opens now
(`Client::next_reopenable`, oldest first, until it answers none) and takes it
through the same path as a fresh envelope, unacknowledged. The core keeps
each one it hands out until the client releases it (`Client::release_held`),
which the client does only once the placeholder and the owed resend ask are
stored, or once it finds it is not a message. The owed ask is settled once
the server took it, or once the group is inside its rejoin window, where the
device rejoins instead.

A reseat's gap block ([The padded Welcome frame](#the-padded-welcome-frame))
makes a held envelope open: it puts the device back at the group's epoch; the
envelope opens, and the message inside, sealed at an epoch whose message
secrets the device never had, does not decrypt, so its content hint and
author's commitment make a placeholder and a resend ask to the person the
commitment names ([sealed-messages.md](sealed-messages.md#content-hints)).
Only messages are taken back; a commit, a typing frame or a call signal is
stale by the time it opens.

### A commit the server refuses

`SubmitCommit` refuses two different situations with the same codes: an
ordinary lost race (`failed_precondition`) or a recipient's bad access key
(`permission_denied`), and a **fork**, where this device merged a commit the
server never took. After a refusal with `failed_precondition` or
`permission_denied`, the client reads the head and compares it with its own
state:

| Head | Verdict |
|---|---|
| no head | retry |
| head epoch above the local epoch | **behind**: drain, apply, rebuild, resubmit |
| head epoch below the local epoch and below an epoch the group's own head stood at on this copy, naming the verifier this copy had there (or below every epoch it keeps, on a copy that kept 64 since its seat, opened a stamp since then, and has never seen a steward key) | **rolled back**: keep the copy |
| head epoch below the local epoch, anything else | **forked** |
| same epoch, verifier equals `SHA-256` of the local send key | retry |
| same epoch, verifier differs | **forked** |
| same epoch, no verifier | retry |

Any other code is retry, with no head read.

The core applies this table and the rules below
([Group recovery](mls-core.md#group-recovery)): the client reads the head
between `recovery_begin` and `recovery_judge`, and does the step it answers.

After its own refused commit the client reads that one head by handle. A
client MAY run the same comparison when a group's messages keep failing to
open with no commit of its own in flight, taking the head from a sweep
([FetchConversationHead](#fetchconversationhead)).

A client also runs it when the person opens a conversation whose head it last
read a week ago or more, never read for the copy
it holds, or read at a time its clock now places in the future. The time of
the last head read that answered is kept in the group's own records in the
MLS store (`note_head_read` / `last_head_read` in `mls/core`), dropped with
the copy. A read made while a fork rejoin of the group is still in its
backoff is not kept. The read is under the same once-a-minute limit per
group, and the conversations opened share at most one sweep per ten minutes.

- **Behind that does not clear is stranded.** If the client reads `behind` at
  the same local epoch twice with a complete mailbox drain begun between the
  two readings, or at least three times over at least five minutes (readings
  more than 30 minutes apart start over), or once after a message sealed past
  its epoch, it rejoins as for `forked`. A
  `behind` reading that strands nothing is read again after the next complete
  drain begun after it, outside the once-a-minute limit.
- **`forked`** rejoins: forget the group, ask back in.
- **Rolled back** keeps the copy (`head_rolled_back` in `mls/core`). Within
  the last 64 epochs the copy keeps verifiers for (`COPY_VERIFIERS_KEPT`), the
  head's epoch and verifier must be one this copy itself held. Below all of
  them, the head reads rolled back only on a copy that has kept 64 epochs
  since its seat and opened at least one of the server's stamps on a commit
  it merged since its seat, when every stamp it opened since then named no
  steward key (`K` zero) and nothing it holds names one. Below a seat the
  copy still keeps, such a head reads `forked`. The group's own head
  counts as having stood at an epoch of the copy when a head read under the
  group's handle named the copy's verifier there, when the copy was seated by
  a Welcome at such a head, or when the device merged its own commit there
  (`head_vouched`); a commit merely placed for the device vouches for nothing.
  The device neither forgets the group nor spends the fork backoff; its own
  commits are refused until the head comes back up to it, and its messages
  still go out at its own epoch.
- **Fork rejoins are rate-limited per group**: after the first, the next may
  go ahead only after 10 minutes, doubling each time, capped at 6 hours.

The ask grants nothing: a member seats only a person who still holds a leaf
in its own tree.

### Rejoin with a sealed seat ask

A device that has fallen off a group's ratchet cannot remove its own leaf or
encrypt. Everything it can do is local, plus one envelope.

1. `forget_group(group_id)` locally. It keeps what the Welcome that brings
   the device back is drawn against, chiefly the roster the device last saw
   in the group ([A Welcome into a group this device knew](#a-welcome-into-a-group-this-device-knew)),
   and the group's epoch mark.
   While the group holds a saved commit, `forget_group` (and a replacing or
   contested Welcome) refuses with `SETTLE_FIRST` (19) and changes nothing
   ([A commit saved across a restart](mls-core.md#a-commit-saved-across-a-restart)).
2. Make sure its KeyPackage pool is published
   ([The KeyPackage lifecycle](#the-keypackage-lifecycle)).
3. Send a **seat ask**: an envelope of kind 3, wrapped with the group's keys
   (which it can still derive from the group id), sent with `SendSealed`
   (`urgent: false`) to the leaves it last saw. The device MUST remember the
   leaves before forgetting the group.

The inner bytes are JSON:

```
{"d":"<asking device id>","a":"<asking actor id>","p":"<proof, standard padded base64>"}
```

The proof is 89 bytes (`mls/core/src/join_request.rs`,
`sign_join_request`):

```
proof     = 0x01 ‖ i64be(issued_at) ‖ nonce(16) ‖ Ed25519 signature(64)
statement = "peachy-join-request-v1" ‖ 0x00
          ‖ u32be(len) ‖ group_id ‖ u32be(len) ‖ actor_id ‖ u32be(len) ‖ device_id
          ‖ i64be(issued_at) ‖ nonce
```

`issued_at` is Unix seconds. The signature is by the asking device's MLS
signing key over `statement`. `mls/fixtures/join-request.json` pins it.

**A member serving the ask** (any member's device that drains it):

1. Ignore it if it has no proof, names this very device, or is for a group this
   device does not hold.
2. Read the asker's owner from this device's own tree: the actor of the leaf
   holding device `d`, or, when no leaf holds it, the hinted `a`. Ignore it if
   that actor is not a current member.
3. Decide against the tree:
   - **add** when device `d` holds no leaf;
   - **replace** when it holds a leaf and the local epoch has not moved since
     this device drained the ask;
   - **drop** otherwise.
4. Fetch exactly that device's KeyPackage: `FetchKeyPackagesAnonymous` with
   the asker's actor id, the access key this device holds for that account
   and `only_device_ids: [d]`; without the key, or when the asker is this
   device's own person, `FetchKeyPackages` with `user_ids: [asker]` and
   `only_device_ids: [d]` (`only_device_ids` filters within `user_ids`).
5. Verify the proof against the KeyPackage's credential key
   (`verify_join_request`). The credential must name the same actor and
   device. The ask must be at most 86,400 seconds old and at most 60 seconds
   in the future. Last, the asker must be a member: their person holds a leaf
   in this device's own tree, or is this device's own person, or is among the
   people the caller names as still being added (`pending_actors`). An ask
   of this device's own person from a device the account forgot, by its id
   or by any key it was seen holding, is not a member's. Verdicts:
   0 accepted, 1 malformed, 2 credential rejected, 3 identity mismatch, 4 bad
   signature, 5 stale, 6 from the future, 7 not a member. Anything but 0
   seats nobody.
   - `pending_actors` MUST hold only people this device is itself inviting
     and has not seated yet. It MUST NOT be filled from the ask, and so never
     with the owner from step 2.
   - A person whose last leaf this device saw leave the group (removed by a
     commit it applied, or left out of the Welcome that brought it back) is
     verdict 7 even when `pending_actors` names them, until they hold a leaf
     again.
6. Judge the tree again (the fetch awaited). On a store two processes share,
   the verdict of step 5 is taken from the store as it stands after the fetch,
   and the commit follows it with no request to the delivery service in
   between, except, for a device of this device's own person, `ListDevices`.
   Then commit: `add_member_for_ask(group_id, key_package, pending_actors)`
   for an add, which judges the ask again on the store it commits on, under
   the same write lock; `replace_member(group_id, leaf_index, key_package)`
   for a replace (Remove and Add in one commit), which needs the device's own
   leaf still at that index. The core refuses a replace that would give the
   leaf to another device or account, or to the same device id under another
   device key, and an add for a device id that already holds a leaf. The
   Welcome goes to device `d`.

   A receiver refuses a commit that seats a
   second leaf for one device id, or re-seats a device id under another
   device key.

Messages the device missed while off the ratchet stay undecryptable to it;
that is the forward secrecy MLS provides. A reseat's Welcome carries a gap
block, the envelope secrets of the epochs the device's seat was held through
while it could not follow
([The padded Welcome frame](#the-padded-welcome-frame)), so each envelope the
device kept ([A message that will not open](#a-message-that-will-not-open))
opens, and the message inside becomes a placeholder and a resend ask to its
author. The member who made the reseat walks its kept epochs from the newest
down and stops at the first it holds no secret for, whose adds it does not
know, or whose commit added the device being reseated. A plain add carries
no gap block.

**A rejoin forgets MLS state, not history.** `forget_group` drops the
group's secrets and tree; the conversation and its placeholders stay on the
device. Once the Welcome lands, each placeholder can be asked for again
([sealed-messages.md](sealed-messages.md)): the line a device draws for
"sent before this device joined" is its first join. The author answers the
re-seated leaf, which carries the same device id, under the usual rules;
what an author has answered is kept in memory for one run, keyed by the
author's epoch when it answered. The forget and the Welcome re-arm the
group's asks, inside the 14 days that began when the message arrived
([Rejoining](sealed-messages.md#rejoining)).

**Asking without forgetting.** A device also sends a seat ask, but keeps the
group, when it is no longer seated while its person still is: a commit removed
this device while the tree it last saw still holds another of its account's
devices, or its own leaf credential lapsed past its grace period (see
[Refreshing a seated leaf](identity.md#refreshing-a-seated-leaf)). If the
last tree it saw holds none of its account's devices, the removal was real and
it MUST NOT ask.

A rejoin needs another member's device to drain the ask; the ask waits in
mailboxes for up to 30 days.

### Seat asks are taken in once

The proof is good for a day, and the server carries it, so each device keeps
a record of the asks it has taken in, keyed by `SHA-256(group_id)`, the
proof's nonce and its signature, until the proof is too old to verify
(`first_sight_of_join_request`, `peachy_mls_first_sight_of_join_request`). An
ask is checked on arrival, and one seen before is acknowledged and dropped. A
stale, future-dated or malformed proof is not recorded; the verdict refuses
it anyway. The record is per device and pruned by the device's clock.

## The mailbox

Every sealed byte a device is owed is an entry in that device's mailbox: one
stored payload, one entry per recipient device. There is no other copy and no
conversation history on the server.

### MailboxKind

| Value | Name | Payload | Placed by |
|---|---|---|---|
| 0 | `MAILBOX_KIND_UNSPECIFIED` | never used | |
| 1 | `MAILBOX_KIND_MLS` | a wrapped envelope (any kind but 2) | `SendSealed` |
| 2 | `MAILBOX_KIND_WELCOME` | an MLS Welcome, not wrapped | `SubmitCommit` |
| 3 | reserved | | |
| 4 | `MAILBOX_KIND_SELF_NOTE` | `id(16) ‖ note_seal_signed(...)` | `SendSelfNote` |
| 5 | `MAILBOX_KIND_COMMIT` | a wrapped commit (kind 2) | `SubmitCommit` |

The mailbox kind is what the server knows; the envelope kind inside is what
the receiver learns on opening. A seat ask and a message both arrive as
`MAILBOX_KIND_MLS`.

The receiver holds the two kinds to the table: a kind-2 envelope is a commit
only inside `MAILBOX_KIND_COMMIT`, and `MAILBOX_KIND_COMMIT` carries only kind
2. Any other pairing is acknowledged and dropped, since a commit that went
through `SendSealed` skipped the head.

The engine's message door and commit
door each refuse the other MLS content type unread, but they cannot see the
mailbox kind: a client that picks the door from the envelope kind alone
would merge a kind-2 commit a member sealed into a `MAILBOX_KIND_MLS` entry.
The core's mailbox door (`process_mailbox_entry`;
`peachy_mls_group_process_mailbox_entry` in C, `processMailboxEntry` in
wasm and in the Swift package) takes both kinds and refuses any other pairing unread, and
`envelope_door` answers the table itself. A client routes through those, not
by the envelope kind. `process_mailbox_entry` keeps nothing of what it opened,
so a message whose words are lost before the archive takes them reads as a
duplicate when it comes again. A client that leaves envelopes for the next
drain (below) asks `envelope_door` first and hands a message entry to
`process_message_as` with the entry's id, which keeps the words with the key
they spent ([Receiving](mls-core.md#receiving)).

`MailboxEnvelope { id, kind, payload, received_at, commit_stamp }`: `id` is a
UUID and `received_at` has whole-second precision. `commit_stamp` is a COMMIT
entry's sealed stamp, empty for every other kind
([The sealed stamp](#the-sealed-stamp)). What an envelope that will not open
was is read from its content hint, inside the envelope (see
[Sealed messages](sealed-messages.md)).

### FetchMailbox and AckMailbox

`FetchMailbox { device_id, limit }` needs a session, and `device_id` must be
the device that registered under that session. An unknown or other
account's device is `not_found`. Another device of the same account is
`permission_denied`, and so is a revoked device. A device still waiting
for approval reaches its own mailbox. `limit` 0 means 200; the
maximum is 500. The response is `{ envelopes, more, lost, server_time }`:

- `envelopes`: the oldest entries, in placement order.
- `more`: more entries remain after this page.
- `lost`: something addressed to this device expired uncollected since the
  last fetch. The server reports it once and clears it.
- `server_time`: the server's clock, to compute an envelope's age as
  `server_time - received_at`.

Reading removes nothing. `AckMailbox { device_id, ids }` removes entries,
under the same device rule as `FetchMailbox`: at most 1000 ids per call
(`invalid_argument`); ids that are not UUIDs, or not in this device's mailbox,
are ignored, so an ack is idempotent. The call returns after the delete is
durable. A payload is deleted when its last entry is.

**The drain loop.** A client MUST:

1. Fetch a page.
2. Process each envelope in order: open it, apply it, and make the result
   durable.
3. Acknowledge what it processed, in one call, only after step 2 is durable,
   and no sooner than the page's floor ([The ack's floor](#the-acks-floor)).
4. If an envelope was **held**, stop: do not acknowledge it or anything after
   it, and try again on the next drain.
5. Otherwise, while `more`, go to 1. A page followed by another fetch MUST be
   acknowledged before that fetch, which would otherwise return it again.

**An envelope left for the next drain.** A message that opened but whose
words the client's archive would not take, or whose handling failed after
the open, is **left**: not acknowledged, its words kept with the key it spent
([Receiving](mls-core.md#receiving)), and the page goes on past it. Every
later page of the same drain passes over it, and a page holding nothing but
envelopes left ends the drain. Once one has failed 5 times over at least an
hour, the client gives it up: it draws the message as one that did not open,
by its content hint, arms the resend ask, and acknowledges it; an envelope
that is not a message, or a message already stored, is acknowledged and
dropped. The count is kept per envelope on the device, and is dropped at the
ack, at sign-out, or after 31 days.

Only a failure of that envelope counts. Before counting one, the client
writes a probe record of its own to the same store; a store that takes no
write at all is down, so nothing is counted and the envelope is held as in
step 4: nothing behind it applies until the store recovers, or the server
expires the envelope after 30 days ([Retention](#retention)).

A drain that left an envelope whose words are kept is still a complete
drain. One whose handling failed before the client knew what it carried is
not.

A message with nothing in it (no words, no attachments, no place and no story
mention, for example a frame of nothing but extras, `0xFF 0x05 {"i": …}`, or
one whose only extras are unknown or malformed) is what the archive refuses.
A client MUST treat such a frame as unreadable before it asks its store,
drawing it as a message that did not open, so no member can leave an
envelope that no try will ever store.

A client SHOULD keep the ids it has processed (for at least 35 days) so that a
redelivery after a crash between steps 2 and 3 is harmless.

**Per kind:**

- `MLS` and `COMMIT`: open the envelope ([Opening](#the-wrapped-envelope)). An
  envelope no held group opens, or one for a group the device has not
  joined, is acknowledged and dropped. Otherwise hand the inner bytes to the
  engine by envelope kind. Own envelopes are acknowledged unprocessed
  ([Own sends come back](#own-sends-come-back)).
- `WELCOME`: join ([Welcome semantics](#welcome-semantics)).
- `SELF_NOTE`: open with the account key, by the note's first byte; see
  [Self-notes](#self-notes).

#### The ack's floor

`AckMailbox` is made with the session, and a device's own copies are
acknowledged unprocessed, so a device that acknowledged each page the moment
it was done would name the maker of a sessionless commit and the sender of a
sessionless send.

So when a page's `FetchMailbox` answer arrives, before it looks at the page,
the client MUST draw the page's floor, uniformly between 1 and 3 seconds,
and MUST NOT acknowledge the page sooner than that after the answer. It
acknowledges it at the floor, or once step 2 is durable if that takes
longer. The rule holds for every page, whatever it holds. The last page's
acknowledgement MAY go after the drain has otherwise finished; a drain that
starts before it lands meets those envelopes again, already processed, and
acknowledges them at its own page's floor.

### Self-notes

`SendSelfNote { payload, device_id }` places one entry in the mailbox of every
approved mailbox device of the caller's own account (the caller's device
included), or only in `device_id` when set. It needs a session. The payload
is 1 byte to 1 MiB (`invalid_argument` otherwise). It is rate-limited per
account (`resource_exhausted`). A named device must be the caller's own and
unrevoked; if it cannot receive notes yet, the call is `failed_precondition`.
The response is `{ id }`.

The payload is `id ‖ note`, where `id` is 16 random bytes and `note` is
sealed under the account key and signed by the sending device
([Self-notes](sealed-messages.md#self-notes)).
A device without the account key cannot read or write notes. The note kinds
inside are listed in [Sealed messages](sealed-messages.md).

## Retention

| What | Kept until |
|---|---|
| A mailbox entry | acknowledged by its device, its device is revoked or deleted, or 30 days after `received_at` |
| A stored payload | its last entry is gone |
| An ephemeral payload (a typing frame, a live-lane call frame) | never stored |
| A `sealed/` object (message attachment) | 30 days after upload |
| A `sealed-meta/` object (group photo) | deleted with its delete token; or 7 days after upload if no accepted commit named it |
| An unconsumed, live KeyPackage | consumed, or its credential lapses |
| A consumed KeyPackage, with when it was handed out (to the second) | at most about ten minutes after it was handed out; its device keeps the day of its latest one for 30 days |
| A device's last-resort KeyPackage | 30 days after the device publishes another |
| A head | the server keeps it; it holds a handle, an epoch, a verifier and the time of its last commit, to the second |
| A spent token's hash ([Tokens](#upload)) | its key expires (at most two weeks), then the next sweep (at most hourly, on a key fetch) |

The receive time of an envelope is kept to the second, and only while the
envelope is undelivered; the head keeps its latest commit's. An envelope that
expires uncollected sets that device's `lost` flag.

### The client contract on `behind_retention`

`behind_retention` names the state of a device that was away longer than the
30-day mailbox retention, or otherwise lost envelopes. The wire signal is
`FetchMailboxResponse.lost`. The commits it missed are gone, so it must
rejoin.

On `lost`, the client MUST:

0. **Get a second opinion.** Finish the drain (until `more` is false), then
   sweep every head ([FetchConversationHead](#fetchconversationhead)) and
   compare each active group's local epoch with its head's
   (`is_behind(group_id, head_epoch)` in `mls/core`). The flag alone MUST NOT
   make a device forget a group: forgetting cannot be undone.
1. **Forget** each group that is behind (`forget_group`).
2. **Ask back in** with a sealed seat ask to the leaves it last saw
   ([Rejoin with a sealed seat ask](#rejoin-with-a-sealed-seat-ask)).
3. **Wait** for a member's device to re-seat it with `replace_member`, and join
   on the Welcome.

Groups where the device is not behind are kept.

## Welcome semantics

A Welcome is sealed to one device's init key. The server cannot tell which
group it is for, so the committer says which device gets it.

- A Welcome is submitted **with the commit that produced it**, in the same
  `SubmitCommit`, with `recipient_user_id` beside `recipient_device_id`. A
  commit that adds a device MUST carry that device's Welcome. The same
  Welcome bytes MAY be addressed to each device the commit adds.
- A welcomed device does not receive the commit that added it. Everything
  after the Welcome in its mailbox is at or after the epoch the Welcome joins.
- On a `WELCOME` entry the device reads which group the Welcome is for
  (`welcome_group`), finds that group's head in the sweep the page earned
  whether or not the Welcome opens, and calls `join_from_welcome_at_head`,
  which returns the group id
  ([Two seats under one group id](#two-seats-under-one-group-id)). The local
  conversation is built entirely from the group: the members are the leaves,
  and the name, photo, admins and other state come from `peachy_group_meta`.
- `welcome_sender` names the adder. A client decides from it, and from its own
  account store, whether the new conversation is a request. It names the
  actor, not the device. One from a device the account forgot is refused
  (error 18).
- A Welcome for a group the device holds and is still active in is refused by
  the engine (`ALREADY_A_MEMBER`, 12) and acknowledged, unless it is at the
  head and the held copy is not, when it replaces the copy
  ([Two seats under one group id](#two-seats-under-one-group-id)). A Welcome
  for a group the device holds but is no longer active in replaces the local
  group. Either way, and for a group the device forgot, the Welcome is drawn
  against the people the device knew there, except for a copy its whole
  person was removed from, which makes it a first join
  ([A Welcome into a group this device knew](#a-welcome-into-a-group-this-device-knew)).
- A Welcome at or below the group's **epoch mark** is refused
  (`ALREADY_A_MEMBER`, 12), acknowledged and dropped, before anything is
  judged or kept, whatever head is given. The mark is the highest epoch the
  head vouched for on this device: the epoch of a seat taken against the
  head, and every epoch a copy reaches while **confirmed** (once a head named
  it or its own commit merged). A seat taken below the head raises the mark
  only to its own epoch. A seat taken with no head, the later epochs of a copy
  no head confirmed, and the epochs a copy reaches after a head found it
  beside the group (same epoch, another verifier) raise nothing. No head ever
  lowers the mark. The mark survives a removal, a leave and a forget. A
  Welcome sealed to a last-resort key package is taken once: the device
  records the seat it opened (the group, epoch and transcript its signed
  group info names) until it drops that package, and refuses that seat again
  with the same error, however the Welcome around it was re-encoded
  (`mls/core/tests/stale_welcome.rs`, `mls/core/tests/epoch_mark_squat.rs`).
- A Welcome that cannot be processed because of a transient local failure is
  held, like a commit.

### A Welcome names a package its device published

An RFC 9420 Welcome names each joiner in the clear, by the KeyPackageRef of
the package its secrets are sealed to, so a joiner can find its own entry.
That ref is the one the joiner's device published beside the package
(`PublishKeyPackages` `key_package_ref`). The server reads the refs of each
framed Welcome a `SubmitCommit` carries, and checks that at least one
is a package of the Welcome's recipient device that the directory handed
out: consumed, or that device's last-resort package. The server counts a
Welcome that names no such package, and still places it.

It does not bind a Welcome to its commit, which the server cannot read, nor a
package to whoever fetched it, which the directory does not record. The refs
it reads are not kept; the meter below keeps a count per person.

### Welcomes are metered per person

Each `SubmitCommit` charges every person it welcomes one seat, however many
of their devices it names, all or none, after the head has proved the send
key, from buckets a server restart does not refill. What is kept is, for each
person and bucket, what is left and when a seat was last taken, to the
millisecond, until the bucket would read full again (at most about two
hours). The row names no group, handle or committer, but it is written in the
commit's own transaction, so until then it ties the person to the
conversation ([The verifier log](metadata.md#the-verifier-log)).

| Who commits | Bucket | Size |
|---|---|---|
| the person's own account (identified) | none | |
| sessionless, every access key proved | `keyed` | 1,000, then 0.4 a second |
| identified: a friend, or a member of a community the person is in | `related` | 100, then 120 an hour |
| identified: anybody else | `stranger` | 100, then 120 an hour |

An honest seat by somebody else names a package fetched for it, and the
directory answers at most 80 fetches naming one person at once, then 120 an
hour, across both doors. A refusal is `resource_exhausted`; a client backs
off and retries, as for any meter on this door.

### The padded Welcome frame

Every Welcome is sent framed and padded:

```text
raw    = MLSMessage(Welcome)               starts 00 01 (the MLS version)
framed = ff 50 57 01 ‖ uint32 len ‖ welcome ‖ zero fill
```

`len` is big-endian and names the Welcome's own bytes. The fill is zeros, and
the frame's whole length is the Welcome with its tree taken at a bound read
from the tree's shape alone (its width, its member count and its leaves'
sizes, every parent counted filled and every leaf as a commit re-signs it)
and the rest, the group state included, at its true size, plus the 8-byte
header, rounded up to 256 bytes
(`mls/core/src/welcome_frame.rs`, the target in
`mls/core/src/commit_padding.rs`; `mls/fixtures/welcome-frame.json`). Adds,
reseats (`replace_member`) and a device seating its own person's new device
all pad this way.

A reader refuses a raw Welcome (one that does not start `ff`), and a frame
whose length runs past its end, that holds no Welcome, or whose fill is not
all zeros.

The server checks the KeyPackageRefs inside
([A Welcome names a package its device published](#a-welcome-names-a-package-its-device-published)).

**The gap block.** A reseat (`replace_member`) sends a version 2 frame,
which carries the envelope secrets of the epochs the returning device missed
([Rejoin with a sealed seat ask](#rejoin-with-a-sealed-seat-ask)):

```text
framed    = ff 50 57 02 ‖ uint32 len ‖ welcome ‖ gap block ‖ zero fill
gap block = nonce(12) ‖ AES-256-GCM(key, count ‖ (uint64 epoch ‖ secret(32)) × count ‖ zeros) ‖ tag(16)
key       = MLS-Exporter("peachy welcome gap v1", group_id, 32) of the epoch the Welcome opens
```

The associated data is the label `peachy welcome gap v1`. The plaintext is
always room for 32 entries (`WELCOME_GAP_EPOCHS`), so the block is always
1,309 bytes (`WELCOME_GAP_BLOCK_BYTES`); the frame's padding target counts it.
Only the reseated device and the members of the new epoch can open it. A
reader refuses a version 2 frame that ends before a whole block or whose fill
after it is not all zeros; a block that does not open, opens to more than 32
entries or to fill that is not zeros, is ignored and the Welcome is taken
without it. The joiner keeps the secrets of epochs before the one the
Welcome seats it at beside its copy (`envelope_gap`) until the copy is
replaced or forgotten. Adds send version 1 frames.

### Two seats under one group id

Anyone who knows a group's id can found a group of their own under it, at
any epoch they sign, and seat a device in it with a Welcome. Nothing in the
Welcome says which is the real group.

The head does. `SubmitCommit` moves a handle's head and places the Welcomes
of the commit that moved it in one step, so the Welcome of a real add is
never above the head, and is at the head's epoch under the head's verifier
until the group moves again. So a device takes every Welcome against the
head. It reads the Welcome's group and epoch without taking it
(`welcome_group`), finds that group's head in a sweep of every head
([FetchConversationHead](#fetchconversationhead)) begun after the mailbox
page was fetched, and calls
`join_from_welcome_at_head(welcome, head_epoch, head_verifier)`.

**The sweep follows the page, not the Welcome.** A device begins the sweep
once it has fetched a mailbox page holding any `WELCOME` entry it has not
seen, before it reads any Welcome on the page, and it does so for every such
page, including one whose Welcome `welcome_group` cannot read: whether a
device sweeps must not depend on whether the Welcome opens. It acknowledges
the page only after the sweep. The join reads its head out of that sweep. A
sweep that fails holds the page at its first unseen Welcome, before reading
it.

| Welcome | Held copy | Result |
|---|---|---|
| above the head's epoch, or at it under another verifier | any | refused (`already a member`): it seats the device in no group the server holds |
| at the head | none, or inactive | taken, and confirmed |
| at the head | active, not at the head, and below the Welcome's epoch | the Welcome replaces the held copy, drawn against its roster, and is confirmed |
| at the head | active, not at the head, at or above the Welcome's epoch, and a head matched it once | keep the held copy; the Welcome is dropped (`already a member`): a live copy never moves back |
| at the head | active, not at the head, and no head ever matched it | the Welcome replaces the held copy, drawn against its roster, and is confirmed |
| at the head | active and at the head | keep the held copy; the Welcome is dropped (`already a member`) |
| below the head, and its send key is not the verifier logged at its epoch | any | refused (`already a member`): it seats the device in a group somebody founded under the id |
| below the head, and its send key is the verifier logged at its epoch | any | as at the head: taken and confirmed, replacing a held copy that is not at the head |
| below the head, nothing logged at its epoch | none, or inactive | taken unconfirmed; confirmed when a head names the epoch its commits carry it to |
| below the head, nothing logged at its epoch | active | keep the held copy; the Welcome is dropped (`already a member`) |
| at or below the epoch mark | any | refused (`already a member`), whatever the head says |

Since only an epoch the head vouched for raises the mark, a group somebody
founded under the id raises it no further than the real group's head. A copy
no head ever matched is the one kind of live copy a Welcome at the head may
replace at or below the copy's own epoch.

The client hands every head it reads (a Welcome's, the fork check's, the
lost-mailbox check's) to `confirm_head`, a head below the copy included. A
copy at the head is confirmed. A confirmed copy at the head's epoch under
another verifier **lapses**: the mark is first raised to its epoch, and its
later epochs raise nothing until a head matches it again. A confirmed or
lapsed copy is not judged by a head below it. A merge of the device's own
commit confirms the copy too, and a group the device founded starts
confirmed. Only a confirmed copy raises the mark as it moves. A group with no
head at all is joined with `join_from_welcome`, which reads none, so the seat
is unconfirmed; a device that cannot read the heads holds the Welcome in its
mailbox and tries again.

**A copy no head has matched yet is held to its own history.** For the copy
it holds, the device keeps the verifier of each of the copy's last 64 epochs,
and, for a seat taken below the head, the head it was taken against. A head
at one of those epochs, or the seat's own head once the copy's commits carry
it to that epoch, confirms the copy when the verifiers match. When they
differ, the copy is **contested**: the server holds another group under the
id. A later head that matches the copy's history still confirms it, and so
does a merge of the device's own commit. A contested copy vouches for
nothing, so the real group's Welcome at the head can still replace it, and
the conversation says so once: "This chat's members couldn't be confirmed
with the server". The same line is drawn when the delivery service refuses
16 of the device's own commits in a row in a copy no head has matched (each
staged commit cleared without a merge counts). A head above the copy, or at
an epoch the copy has no verifier for, changes nothing.

**A Welcome below the head is held to the verifier log.** The device reads
the verifier the head held at the Welcome's own epoch
([FetchVerifierAt](#fetchverifierat)) and hands it to the join: an impostor's
Welcome, founded under the id at an epoch the real group also passed
through, carries another send key there and is refused
(`mls/core/tests/impostor_welcome_guard.rs`).

The head never moves a group silently: a Welcome that replaces anything is drawn against the roster
of the copy it would replace, or the one kept when the device forgot the
group ([A Welcome into a group this device knew](#a-welcome-into-a-group-this-device-knew)),
and is never passed over as a first join (`mls/core/tests/head_lapse.rs`).

`join_from_welcome`, which reads no head, keeps a Welcome into a group the
device is active in as the **contested Welcome**
(`contested_welcome_group_id`), for `join_contested_welcome(head_epoch,
head_verifier)`, which replaces the held copy only when the copy is not at
the head and the Welcome is, under the same mark, rollback and roster rules
as `join_from_welcome_at_head`. Only the latest contested Welcome is kept,
and only until the next Welcome.

### A Welcome into a group this device knew

A group id is not a secret, and a Welcome proves who signed the group it
creates, not that the group is the one this device was in. So a Welcome that
would restore or replace a group the device knew is **drawn against the
people the device last saw there**. Nobody is refused for who they are,
except a device the account removed.

- **What is kept.** `forget_group` keeps the roster of the copy it forgets:
  each person's actor id with their account identity key, the device's own
  person included, and the group's state (its admins and policy) when a head
  matched the copy once. A copy the device still holds, active or ended by a
  removal while another device of its own person is still seated, is drawn
  against by its own roster. Every leaf of a held copy counts, read from its
  credential without verifying it again. A held group with no leaf of its
  person left is a real removal and keeps nothing. The kept roster loses each
  person the device sees leave afterwards, by any commit it applies or seat it
  takes, and never gains anyone; who left is kept too, so a seat ask from them
  is not answered ([Rejoin with a sealed seat ask](#rejoin-with-a-sealed-seat-ask)).
  That holds for a seat no head has confirmed too. All of it survives a
  restart, and goes once a copy in the id is confirmed. A Welcome into an id
  the device holds a copy of that it still has a claim on (active, or with
  another device of its person seated), or kept a roster for, is always
  drawn, even when that copy names nobody but the device's own person. Any
  other Welcome is a first join, with no report: into an id the device never
  held, one it left on purpose (`forget_remembered_roster`), or one it was
  removed from together with its person.
- **What is refused.** A Welcome signed by a device the account forgot (by
  its id or by any key it was seen holding) is refused with `welcome from
  outside the group` (error 18), into this group or any new one. A Welcome
  into a group the device knew whose signer's credential does not identify is
  refused the same way. A Welcome whose tree holds one person under two
  account keys, or this device's person under another key, is refused with
  `group policy refused` (error 3)
  ([One account key per person](identity.md#one-account-key-per-person)).
  Nothing changes; the client acknowledges and drops it. A device waiting to
  rejoin keeps waiting after the first, and asks again after the second (at
  most once per group per ten minutes).
- **What is told.** Every other such Welcome is taken, and leaves a **rejoin
  report**: who re-seated the device and from which of their devices,
  whether that device is one of the device's own person that it does not
  trust (`readded_by_untrusted`), whether the admins changed against the
  state it kept, every person the new tree holds whom the roster did not,
  every person of the roster it leaves out, and every device of a person it
  keeps that the new tree leaves out (`dropped_devices`, actor and device
  id, matched against the devices of the copy held or kept when the device
  forgot the group; this device's own and its person's forgotten devices
  excepted). People are matched by actor and account key, but the report
  names actors only. Each Welcome leaves its own report, kept in order until
  the client drops it. Past 32 waiting, a new report is folded into the
  newest, which keeps every flag and everybody either names as added or gone,
  but names only the newest re-adder, or an untrusted earlier one over a
  trusted newer one (a report of a contested copy alone names none, and
  leaves the earlier one). Every report carries a random nonzero id.
  **A report is kept until it is drawn.** The client peeks the oldest
  (`peek_rejoin_report(group, now_ms)`), draws it, and only then drops it by
  its id (`drop_rejoin_report`). The first peek fixes `drawn_at_ms`, which
  every later peek answers, so a draw repeated after a crash writes the same
  rows; a client passes `now_ms` plus the report's place in the pass. Peek and
  drop run under the store's write lock
  ([A store two processes share](mls-core.md#a-store-two-processes-share));
  `take_rejoin_report` does both in one step. The client draws
  each report: "{name} re-added this device", unless that is the device's own
  person; "{name} changed who the admins are"; "{name} was added while this
  device was away" for each newcomer; and "{name} is no longer in this chat"
  for each person gone, named through the client's one identity resolver. A
  contested copy draws "This chat's members couldn't be confirmed with the
  server". A dropped device draws no line: one of the device's own person's
  sets the own-seat pass going at once
  ([Seating your own new devices](sealed-messages.md#seating-your-own-new-devices)),
  and another person's waits for that device to ask back in itself.
- **One's own devices.** A Welcome signed as the device's own person is drawn
  as one of its own, and draws no re-add line, only when the signing device is
  not this device's own id, is not one the account forgot, was not seen seated
  from outside the own-device check
  ([What the adder checks](identity.md#what-the-adder-checks)), and is on
  this device's approval chain. Any other draws "A device that isn't one of
  yours added this device back to the chat" in place of the re-add line.
- **Leaving on purpose.** A person who leaves calls
  `forget_remembered_roster` after `forget_group`. A later Welcome into the
  id is then a new invitation, and any report not yet dropped goes with the
  roster.

## The KeyPackage lifecycle

Publish, consume, replenish, with one standing fallback.

### Publish

`PublishKeyPackages { device_id, key_packages }` needs a session.
`device_id` must be the caller's own unrevoked MLS device, registered under
the calling session (`permission_denied` from any other session of the
account), and approved for the account (`failed_precondition` while it is
pending). Each
`MlsKeyPackage { ciphersuite, key_package, key_package_ref, last_resort }`:

| Field | Rule |
|---|---|
| `ciphersuite` | MUST be `0x004F` (79) |
| `key_package` | the serialized KeyPackage, at most 32 KiB |
| `key_package_ref` | the RFC 9420 KeyPackageRef, at most 128 bytes, computed by the client (`generate_key_package_with_ref` in the core, `peachy_mls_key_package_with_ref` in the C ABI) |
| `last_resort` | at most one per call |

1 to 100 packages per call. Anything else is `invalid_argument`. Publishing
is idempotent on `key_package_ref`. A new last-resort package retires the
previous one. The response is `{ published, available, has_last_resort }`,
counting only live packages. A device's mailbox exists from its first publish.
A successful publish pokes the account with `STATE_DOMAIN_SESSIONS`.

**Liveness.** A package is live while its credential's `exp` is more than 5
days away; a package whose credential carries no readable `exp` is live for 25
days from publish. A stale package is never served or counted. A device MUST
publish packages minted with a fresh credential (see
[The credential](identity.md#the-credential)).

### Consume

`FetchKeyPackages { user_ids, skip_device_ids, only_device_ids }` needs a
session. 1 to 128 user ids, each a known account. At most 16 ids in each
device filter. It names no group. For each approved, unrevoked device of each
person (minus `skip_device_ids`, or only `only_device_ids`), the server:

- hands out and **consumes** that device's oldest live ordinary package;
- otherwise hands out its live last-resort package with
  `used_last_resort: true`, without consuming it;
- otherwise lists the device in `devices_without_packages`.

Each `FetchedKeyPackage` carries `user_id`, `device_id`, `ciphersuite`,
`key_package`, `key_package_ref` and `used_last_resort`. Two concurrent
callers never receive the same ordinary package.

Fetching is metered per (caller, person) and per caller, and is
`resource_exhausted` beyond it. A caller fetching its own account's packages
skips the per-person meter. Across both doors, at most 80 fetches naming
one person are answered at once, then 120 an hour
([Welcomes are metered per person](#welcomes-are-metered-per-person)).

`FetchKeyPackagesAnonymous { user_id, access_key, only_device_ids }` is the
same handout for **one** person, with no session. The key is checked in
constant time. A wrong key, a missing key, an account that never set a key
and an unknown account all answer the same `permission_denied`. A deleted
account passes with any key and gets an empty handout
([The check](#access-keys)). It is metered per target and per IP. A client
SHOULD use it whenever it holds the person's access key. Only
`permission_denied` sends a client to `FetchKeyPackages` for that person
(its key is stale). On `resource_exhausted` from
`FetchKeyPackagesAnonymous` a client MUST back off and retry later, and MUST
NOT fall back to `FetchKeyPackages`.

A device seating its own account's other devices passes its own id in
`skip_device_ids`, except at a founding, which needs its own package too
and skips nothing ([Founding a conversation](#founding-a-conversation)).

The adder MUST verify each package before adding it (see
[What the adder checks](identity.md#what-the-adder-checks)).

### Replenish

`KeyPackagePoolStatus` returns `{ devices, low_water }` for the caller's
unrevoked devices, each `{ device_id, platform, available, has_last_resort,
low }`. A device SHOULD check its own entry on launch, on every stream
connect and return to the foreground, and on every `STATE_DOMAIN_MLS` poke,
and when `low` or `!has_last_resort`, publish up to
`2 × low_water` live ordinary packages plus a last-resort package if it has
none.

When a handout leaves a device below `low_water`, the server pokes that
device's account with `STATE_DOMAIN_MLS`.

**Last resort.** Every device keeps one last-resort package (it carries the
`last_resort` extension, so it can open more than one Welcome) and replaces it
every 2 days (`LAST_RESORT_ROTATION_INTERVAL_SECONDS`, `last_resort_rotation_due`
in `mls/core`). Every joiner served from it shares one init key until it is
replaced. It exists so that a device that has been offline can still be added.

## Realtime: StreamEvents

`StreamEvents` is a server stream and needs a session. The fields in scope
of `StreamEventsResponse` are:

| Field | Meaning |
|---|---|
| `state_versions` | the first event only: the server's current version of each store domain it versions |
| `state_changed` | `{ domains, versions }`: a successful call dirtied these domains for this account |
| `ephemeral` | `{ payload }`: a typing or live-lane call envelope relayed as sent |
| `reconnect` | `{ after_ms }`: the server is closing the stream on purpose; wait, then reconnect |
| `mailbox` | a page of this device's mailbox, on a stream that asked for it ([The mailbox on the stream](#the-mailbox-on-the-stream)) |
| `beat` | the beat this session asked for with `BeatStream`, never sent otherwise |

Other fields belong to out-of-scope features; a client ignores them.

A poke carries no data. The client answers it by fetching:

| Domain | Value | Sent when | Client answer |
|---|---|---|---|
| `STATE_DOMAIN_MAILBOX` | 18 | an envelope was placed for one of this account's devices | `FetchMailbox` (drain) |
| `STATE_DOMAIN_MLS` | 14 | this account's KeyPackage pool fell low, or one of its devices committed with a session | `KeyPackagePoolStatus` and replenish; drain |
| `STATE_DOMAIN_ACCOUNT_STORE` | 17 | a `WriteStore` landed | `ReadStore` the manifest |
| `STATE_DOMAIN_SESSIONS` | 5 | the account's devices or sessions changed, including a publish | `ListDevices` / `ListSessions` |
| `STATE_DOMAIN_PEOPLE` | 20 | somebody the server knows this account holds changed their public row | `GetUsers` for the people held |

Pokes are fire-and-forget. `STATE_DOMAIN_MAILBOX` and `STATE_DOMAIN_MLS`
have no version. A client MUST drain its mailbox on every stream connect and
every return to the foreground, not only on a poke. `STATE_DOMAIN_PEOPLE`
does not cover co-members a client knows only from a group: a client SHOULD
refresh those with `GetUsers` on returning to the foreground.

### The mailbox on the stream

A client MAY name its own device when it opens the stream
(`StreamEventsRequest.mailbox_device_id`, held to the rule `FetchMailbox`
holds `device_id` to). The server then hands it that device's mailbox on the
stream, envelope by envelope as each is placed, and a message costs no
`FetchMailbox` round trip:

- The opening frame (`state_versions`) also carries `mailbox`: a page, exactly
  what `FetchMailbox` would answer, so a connect drains without a fetch.
- Each time something is placed for the device, the stream sends a new
  `mailbox` page in place of the `STATE_DOMAIN_MAILBOX` poke. A burst of
  placements is carried by one read where it can be.
- An envelope this stream has already carried comes back with its `id`,
  `kind` and `received_at` and an **empty** `payload`. A placed envelope never
  has an empty payload, so this means only "you were handed this one". Bytes
  cross once per stream.
- A page carries at most 256 KiB of payload and says `more` when it stops
  short; the client fetches the rest.
- `lost` is never set on a stream page and `notices_waiting` never is either.
  A device owed `lost` is sent the poke instead, and fetches.

The client treats a page as the first page of a drain: the drain loop
([FetchMailbox and AckMailbox](#fetchmailbox-and-ackmailbox)) runs unchanged,
the ack's floor counted from the page's arrival. It MUST fetch instead of
using the page when an empty-payload envelope on it is one the client has not
processed and does not hold from an earlier page, which is the case for
anything left or held by an earlier drain.

A server that does not do this ignores the field, and the stream carries
pokes as before. A server may also turn it off, and then pokes every stream;
a client handles both.

**Nothing changes in what the server learns.** The stream is the session's
own, the device is checked as `FetchMailbox` checks it, and the bytes are the
ones `FetchMailbox` would hand the same session. There is no fetch for the
server to time.

**A send need not drain first.** While its stream is open, every placement
for the device reaches it on the stream, so a client whose last drain was
clean, with no page or poke since, holds everything the server holds for it.
It MAY then seal without draining first, within 60 seconds of that drain
ending, and only while the stream has sent it something within the last 25
seconds. A refusal for a stale epoch still drains and re-seals.

That rests on the stream being live, and a stream can die without either end
knowing: a network path that changes under it (Wi-Fi to cellular, a NAT
rebind) is noticed only when the stream stays silent past its heartbeat,
while other calls already go the new way. So on every network path change it
is told of, a client MUST stop treating the mailbox as quiet until it knows
its stream still reaches it: the beat it asks for arrives
([A network change](#a-network-change)), or a new stream's opening page has
been drained. A heartbeat or page that arrives meanwhile does not count; it
may have been on its way before the change. Not every change is told: a
desktop browser reports only going offline and coming back online, so a move
from Wi-Fi to Ethernet or a NAT rebind there passes unseen. What bounds
those is the heartbeat. The server sends something on every stream at least
every 20 seconds, so a stream silent for 25 has stopped vouching, whatever
the client was told.

Two races are left. The first is the one any drain before a send leaves: a
commit placed after the drain's last read while the stream is live, its page
or poke still on the way when the send seals. The second: a commit that lands
after the drain's last read, on a stream that has died with no path change
the client was told of, and a send within 25 seconds of the last thing that
stream sent. Either way the message is sealed at the epoch before the commit.
Every member still opens it (`RETAINED_PAST_EPOCHS`), and so does a member
that commit removed. A drain before every send left the first race too,
between its fetch and the send, only narrower.

### A network change

When the network moves under a client (Wi-Fi to cellular, offline and back),
its stream may have died without either end knowing, or may be fine. Rather
than end a stream that may be fine, which costs a reconnect and a catch-up,
the client probes it:

1. It waits until the changes have stopped for a second: a burst of them is
   one change.
2. It calls `BeatStream` with a nonce of its own. The server sends a
   `StreamBeat` carrying that nonce on the calling session's own streams, and
   on no one else's, and answers whether the session holds a stream at all.
3. If the beat arrives on the stream within 5 seconds of the call, the stream
   reaches the client: it is kept, with no reconnect and no catch-up, and
   vouches for a quiet mailbox again.
4. Anything else ends the stream and opens the next one at once: no beat
   within the 5 seconds, `streaming` false, or the call failing.

`BeatStream` is rate-limited per session (`resource_exhausted`). Nothing is
written; the server only sends the beat.

A client that does not probe ends its stream on every change it is told of,
and loses only the reconnect, and a client that never calls `BeatStream` is
never sent a beat.

## Sealed media

A sealed attachment is ciphertext in public storage. The pointer that names
it, and the encryption format, are in [Sealed messages](sealed-messages.md).

### Upload

`CreateUpload` needs a session:

| Field | Value |
|---|---|
| `kind` | `UPLOAD_KIND_FILE`. A sealed class with any other kind is `invalid_argument` |
| `content_type` | `application/octet-stream` (required; image and video types are refused for a FILE) |
| `content_length` | the exact ciphertext length, greater than 0 |
| `sealed_class` | `SEALED_CLASS_ATTACHMENT` (1) or `SEALED_CLASS_META` (2) |
| `resumable` | ATTACHMENT only: ask for a multipart upload ([Resumable upload](#resumable-upload)). A client SHOULD ask when the object is larger than 8,388,608 bytes |

| Class | Object key | Size limit | Lifetime |
|---|---|---|---|
| ATTACHMENT | `sealed/<uuid>.bin` | 100,000,000 bytes | 30 days after upload |
| META (a group photo, or a sealed profile's photo) | `sealed-meta/<uuid>.bin` | 8,000,000 bytes | until deleted with its token |

A group photo MUST go up with no session, so nothing the server records
ties the object, or the commit that later names its key, to an account; the
request's address and timing remain
([G7](metadata.md#what-the-server-never-holds)). A META object
minted with `CreateUpload` is the account's own: the server records the
account against it, only that account's `SetSealedProfile` keeps it, and a
commit that names it leaves it pending ([Abandon, delete](#abandon-delete)).

`CreateSealedMetaUpload { content_length, token }` is sessionless and metered
per IP. `token` is one anonymous token of the `group-photo` purpose. A token
that is not one (wrong length or type), or a length of 0 or over the META
limit, is `invalid_argument` and spends nothing; a spent token is
`permission_denied`; one of another purpose, under a lapsed key or with a bad
signature is `unauthenticated` (refetch the keys and retry once with a fresh
token). It mints a META object and answers exactly as `CreateUpload` does. A
client MUST NOT fall back to `CreateUpload` when it is refused, and one that
holds no token sets no group photo.

**Tokens** are RFC 9578 type 2 for the TokenChallenge with issuer_name
`pchy.app`, an empty redemption_context and origin_info `group-photo`,
blind-signed by `IssueCallTokens` (with a session) under a key
`GetCallTokenKeys` (sessionless) lists. A client checks that a key's id is
its hash. A client keeps a stock of tokens.

The response `{ upload_url, object_key, public_url, delete_token, resumable }`:

- `upload_url` is a presigned HTTPS `PUT` URL, valid for 10 minutes. The
  client MUST send the body with exactly these headers, which the signature
  covers: `Content-Type: application/octet-stream`,
  `Content-Disposition: attachment`, and a `Content-Length` equal to
  `content_length`. Any 2xx status is success.
- `object_key` is what the sealed pointer (inside the ciphertext) or the
  commit (`meta_object_keys`) names. The server records no account against a
  sealed attachment or a group photo.
- `public_url` is where anyone can `GET` the ciphertext with plain HTTPS and no
  credentials.
- `delete_token` is set for META only: 32 random bytes, base64url without
  padding. The server keeps only its `SHA-256`. The uploader writes it into the
  group state beside the photo pointer, so any member can later delete the
  object.
- `resumable` is set only when the request asked for it, for an ATTACHMENT,
  the server offers parts at all (an operator switch), and it could open a
  multipart upload. `upload_url` is still a working single `PUT` to the same
  object.

### Resumable upload

An attachment larger than one part goes up in parts, so an interrupted upload
continues from the last part the storage holds. The server opens a multipart
upload in the storage for the object it minted, pins the object's headers
there (`Content-Type: application/octet-stream`,
`Content-Disposition: attachment`), and presigns every step:

| Field | Meaning |
|---|---|
| `upload_id` | The storage's id for the multipart upload |
| `part_bytes` | Every part but the last is exactly this long; the last is the rest. 8,388,608 now; a client MUST take it from here |
| `part_urls` | One presigned `PUT` per part, in order: `part_urls[i]` is part number `i + 1`, bytes `[i · part_bytes, min(length, (i + 1) · part_bytes))` of the object. The signature covers the part's `Content-Length` |
| `list_parts_url` | Presigned `GET` of the storage's `ListParts` XML: each held part's `PartNumber`, `ETag` and `Size` |
| `complete_url` | Presigned `POST` of the `CompleteMultipartUpload` XML: every part's `PartNumber` and `ETag`, in order |
| `abort_url` | Presigned `DELETE`: give the upload up |
| `expires_at` | Unix seconds after which none of these URLs works (6 hours) |

A client:

1. `GET`s `list_parts_url` and sends only the parts that are missing or of the
   wrong size. A part `PUT` carries the part's bytes and no other header the
   signature needs. Repeating a part `PUT` replaces the part.
2. When every part is held, takes the ETags from `list_parts_url` (or from
   each `PUT`'s `ETag` header) and `POST`s the complete. Success is a `2xx`
   whose body is not an `<Error>` document.
3. After any failure, waits and goes back to 1.
4. Reads a `404` from `list_parts_url` or `complete_url` as "this upload is
   finished or gone": a `HEAD` of `public_url` whose `Content-Length` is the
   object's length means an earlier complete succeeded and its answer was
   lost; anything else means starting over with a new `CreateUpload`.
5. Starts over with a new `CreateUpload` once `expires_at` is less than five
   minutes away.
6. On a canceled send, or once it gives the upload up, `DELETE`s `abort_url`,
   best effort.

A client that cannot use the parts falls back to `upload_url`. A part,
`list_parts_url` or complete answered with a refusal that waiting will not
change (a `4xx` other than `404`, `408` and `429`, or a `501`) makes the
client give the upload up and send the object by one `PUT` to a new
`CreateUpload` that does not ask for parts, once per object. A browser cannot
use parts until the storage's CORS policy allows the `POST` and `DELETE` and
exposes each part's answer. A complete that gets no answer while
`list_parts_url` still answers, twice, is that refusal; once is the network.

The server keeps nothing about a resumable upload: not its id, not its key,
not who asked.

### Abandon, delete

- A META object is pending until something keeps it, and one still pending
  after 7 days is deleted. A group photo (minted by `CreateSealedMetaUpload`)
  is kept by an accepted `SubmitCommit` that lists it in `meta_object_keys`,
  and the server records no uploader for it. A META object minted by
  `CreateUpload` names its account, and only that account's `SetSealedProfile`
  keeps it; a commit naming it leaves it pending. `SetSealedProfile` also
  keeps a pending group-photo object it names, which becomes the account's.

- An account keeps at most 4 META objects for its profile, ordered by when its
  profile last named each (a profile names its photo and cover on every
  write), and holds at most 8 it minted with a session and nothing has kept.
  Past either, the server deletes the oldest at once. Deleting the account
  deletes them all.

- `AbandonUpload` does not apply to sealed objects: it returns
  `{ abandoned: false }`. A canceled attachment expires with its prefix.
- **Orphans expire by age.** An attachment uploaded and never sent costs
  storage until the 30 days every `sealed/` object gets. A multipart upload
  nobody finished is aborted by the server's sweep 8 to 14 hours after it
  began (its URLs die at 6; the sweep runs every 6 hours and waits 2 past
  that), and by the storage's lifecycle rule a day after.
- `DeleteSealedObject { object_key, delete_token }` is sessionless and metered
  per IP. The key MUST be a `sealed-meta/` key and the token MUST hash to the
  stored hash; otherwise `permission_denied` ("not allowed"). An unknown or
  already deleted object succeeds. The member who replaces a group photo
  SHOULD delete the old one.

### Download

A recipient downloads with a plain `GET` of the pointer's URL as soon as the
envelope arrives, because the object expires 30 days after upload. A `403`,
`404` or `410` means the object is gone.

A chunked object (pointer version 2 or 3) is opened as it arrives, one
authenticated chunk at a time
([Reading as it arrives](sealed-messages.md#reading-as-it-arrives)). A body
that breaks off, or ends cleanly before the object does, SHOULD be resumed
with `Range: bytes=<offset>-`, where the offset is the start of the first
chunk that has not verified; a `206` continues there, and a `200` is the whole
object again, read from the start. A body that breaks off after the last chunk
is in needs nothing more: the digest decides.

## Retired builds

A build below its platform's minimum supported version is turned away by the
server, not only by its own update screen.

**The session's door.** A native client names its build number in the
`x-peachy-build` header of its authenticated calls, and its platform in its
User-Agent. On every rpc that needs a session, a call naming a build below
its platform's minimum (the last component of the version
`GetMinSupportedVersion` answers: `1.0.100` is build number 100) is refused
before its handler runs: `failed_precondition`, `peachy-refusal:
update-required`.
So a retired build can no longer drain its mailbox, open its stream, publish
key packages or send identified. Build numbers only rise. A build at the
minimum is served. So is a build an app store is still reviewing, which the
operator may exempt from the minimum; it runs an older core that differs from
these documents.

**The sessionless door.** Sealed-sender sends and commits carry no session
and, on purpose, no build, which would narrow an anonymous send to the
installs on that build. So this door judges the envelope's version byte,
which is in the clear. No build at or above any platform's minimum seals
version 1 (unpadded, keyed by the group id), so the server refuses a version
1 envelope as a `SendSealed` payload or a `SubmitCommit` commit:
`failed_precondition`, `peachy-refusal: envelope-retired` (the format is
refused, not a build), and a retired build's commit never moves a head that
current devices cannot follow. Version 1 envelopes already in mailboxes are
not touched. A `SubmitCommit` commit must be a version 2 or 3 envelope, the
only versions current readers open; any other version byte, or bytes too
short to be an envelope, is `invalid_argument` with the same mark.

**The published core counts too.** A client built on the published core
(`peachy-protocol`) has no minimum the server can hold it to. So a format is
refused only while the published core writes a version the server still
takes; otherwise the refusal holds off.

### The protocol floor

Every `GetMinSupportedVersion` answer carries `protocol`, a `ProtocolFloor`:
the envelope versions `SendSealed` and `SubmitCommit` take now
(`envelope_versions`), and, when one is scheduled, the version to be
refused next (`next_refused_envelope_version`, 0 for none) and from when
(`next_refused_at`). It is the same in every answer, whatever the platform
asked and whoever asks: it says nothing about the caller, and the caller
says nothing to get it. A client that is not one of Peachy's apps asks with
the platform `protocol`, which has no minimum, and SHOULD ask at start-up
and plan for the date.

`client_refusals` names checks switched on for every client; a client keeps
each name it knows for good, so the server can turn a check on and never off.

A signed-in caller's answer also carries `account_client_refusals`: checks
switched on for its account alone, so that one can be tried on a share of
accounts before everyone. It is empty without a session, and a client keeps
those names the same way, for good. A client hands both lists to its core
(`Client::adopt_client_refusals`, `peachy_mls_client_adopt_refusals`), which
keeps every name it knows and ignores the rest. The names are listed in
[Client refusals](CHANGELOG.md#client-refusals).

**It fails open.** Only a request positively identified as a retired build is
refused. A request with no build header, a header that is not a number, an
app or script that is not Peachy's, a platform with no minimum, or a minimum
that does not end in a number is served.

**Lockout only with somewhere to go.** The refusal reads the same minimum the
clients read, and Peachy raises a minimum only once the store each
platform's installs update from serves a build at or above it. So a build is
refused only when a build to update to is available.

The web is never refused: a web bundle sends no build, and an open tab asks
the minimum again each time it returns to the foreground.

The operator can turn the session's door off. Turned off, it also releases
every retired device (below): no mark holds while it is off. The envelope
refusal is held apart from it: current readers drop a version 1 envelope
whatever the server does, so taking one again would let a version 1 commit
become a group's head that current members silently skip.

**The build refuses itself too.** A current build that learns it is retired
(its own minimum check, its build expiry reaching the wall, or any answer
carrying `peachy-refusal: update-required`) stops sending on both doors
before a request leaves: sealed sends, commits, join asks and the other writes
into group state. Reads stay open, so the wall can still learn there is a
build to update to. This covers the sessionless door, which the server cannot
judge by build.

### Retired devices

Refusing a build does not stop current devices sealing to it, and its leaf
stays in their trees. So the server marks the devices a refused login speaks
for as retired, with the build number of the minimum it fell below, which is
public, never the device's own build.
While a device is marked, and its platform's minimum is still at or above that
number:

- **It is sent nothing.** A sender that names it gets nothing placed for it,
  as for a revoked device. A Welcome to it is still placed, so a device that
  updates can be seated by a commit already in flight.
- **Senders are told.** `SendSealed` and `SubmitCommit` answer with
  `retired_device_ids`. A current device removes such a leaf only through
  the core's `remove_stale_leaf`, where `stale_leaf_removable` allows a
  removal without a signed revocation (another live leaf of the same person,
  or a lapsed credential), with no row in the transcript. A person's last leaf
  stays until 56 days past its credential's expiry
  (`EXPIRED_LEAF_GRACE_SECONDS`), when every client evicts it anyway, and any
  leaf goes on the account's signed revocation. These are the remover's rules
  ([Revocation reaches a seated leaf through the roster](identity.md#revocation-reaches-a-seated-leaf-through-the-roster)).
  A client forgets each id ten minutes after it was last told.
- **Nobody seats it again.** Its key packages are not handed out.

Retired ids travel apart from `stale_device_ids` on purpose: a client may
remember a stale id for as long as it runs, which would remove an updated
device again each time it asked back in. A retired id is a note, forgotten
after ten minutes; the server's next answer is the truth.

An updated device's first served call clears the mark, relaunched or not. It
finds itself behind or removed and asks back in with the ordinary sealed seat
ask (envelope kind 3), visible in no transcript.

**What a current device drops.** A frame a retired device seals after its leaf
is gone, at an epoch it was in, is refused by the core as not from a member
(code 17). A version 1 envelope, which only builds below every minimum seal, is
not opened at all. Both are acknowledged and dropped: no head check, no count
toward being behind, no reset, no rejoin and no row. Only an unopenable
version 3 envelope, which names an epoch the device does not hold, leads to a
head check. A frame in a retired form is never evidence that this device is
behind ([Retiring a wire format](formats.md#retiring-a-wire-format)).

## Third-party client conformance

A client other than Peachy's apps, such as a bot or a relay built on the
published core, is held to every rule in these documents. These are the ones
such a client most often gets wrong. Most are enforced by the core or the
server; the rest only the client can keep.

- **Seal through the client** (`Client::seal_envelope`,
  `peachy_mls_client_seal_envelope`), by the epoch, so a removed member
  cannot open it. The clientless door seals only a seat ask and a link
  preview ([The wrapped envelope](#the-wrapped-envelope)).
- **Choose the door from the mailbox kind**: `process_mailbox_entry` with
  the entry's kind, or `envelope_door` and then `process_message_as`
  ([MailboxKind](#mailboxkind)).
- **Take only the padded Welcome frame, and only from the delivery
  service.** A refused frame still spends its key package, so keep the pool
  full ([The padded Welcome frame](#the-padded-welcome-frame)).
- **Remove a stale or retired leaf only through `remove_stale_leaf`**, never
  this device's own; while signed revocations are not enforced, it takes one
  on the server's word that the person keeps another live leaf
  ([Revocation reaches a seated leaf through the roster](identity.md#revocation-reaches-a-seated-leaf-through-the-roster)).
  Forget a retired id ten minutes after the server last named it
  ([Retired devices](#retired-devices)).
- **Keep the store encrypted, its key apart, and its files private.** Open
  it with a key; one found in the clear (`PLAINTEXT_STORE`) is encrypted in
  place, never replaced, and a long-running client reopens it with
  `peachy_mls_client_open_existing` ([Backends](mls-core.md#backends)). The
  bundled SQLite trusts a `-wal` file beside the store; the core refuses
  files group or others can write (`INSECURE_STORE`), and the directory is
  yours to keep private.
- **Detect a copy behind or forked, and ask back in**, as the core's
  recovery steps say ([Group recovery](mls-core.md#group-recovery)), never
  on `STALE_COPY` alone, keeping the backoff the core keeps
  ([Rejoin with a sealed seat ask](#rejoin-with-a-sealed-seat-ask)).
- **Derive `own_account_identity` on the device** from the account key it
  holds: one read off its own credential, or handed over by the server,
  passes the check for any credential
  ([The C ABI contract](mls-core.md#the-c-abi-contract)).
- **Trust only the pinned server keys**, narrowed by
  `server_keys_pinned_json`
  ([The trusted server keys](identity.md#the-trusted-server-keys)).
- **Take the account key only from a vouched box**
  (`account_key_accept_hybrid`), and set `server_approval_allowed` only for
  a test server or a 555-01xx sign-in
  ([Which approver to believe](identity.md#fetching-and-opening-the-account-key)).
- **Send hellos and `ak`**, or every co-member's send to this client is
  identified ([G7](metadata.md#what-the-server-never-holds)). Its own sealed
  sends are still told apart by its address and client fingerprint.
- **Do not present as an app.** Send no `x-peachy-build` and no Peachy app's
  user agent: one that copies a retired build's header is refused, its
  devices are marked retired, and its peers remove its leaves where
  [Retired devices](#retired-devices) allows (a person's last leaf only
  after its grace).

## Security considerations

What the server holds is in [Metadata](metadata.md). Beyond that:

- **The server is trusted for availability, not for content.** It can
  withhold, delay or drop envelopes and commits, and it decides which of two
  competing commits comes first ([The ordering rule](#the-ordering-rule)). It
  cannot read or forge them, except in the store-review login's demo
  conversations, where it runs the other members' devices
  ([Metadata](metadata.md#what-the-server-never-holds)).
- **The web client is the server's to send.** Peachy's web client is loaded
  from Peachy's server each time it opens, so a person using it trusts that
  server with the code as well as the delivery. Any script that runs in the
  page can use its keys.
- **Replays.** A receiver drops a replayed message only while its record of
  the last 4096 it opened holds it. An older one fails to open.

## IPR

This document is dedicated to the public domain under CC0 1.0.

## References

- [RFC 2119] "Key words for use in RFCs to Indicate Requirement Levels", BCP 14, RFC 2119, March 1997. <https://www.rfc-editor.org/rfc/rfc2119>
- [RFC 8174] "Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words", BCP 14, RFC 8174, May 2017. <https://www.rfc-editor.org/rfc/rfc8174>
- [RFC 9420] "The Messaging Layer Security (MLS) Protocol", RFC 9420, July 2023. <https://www.rfc-editor.org/rfc/rfc9420>
- [RFC 7748] "Elliptic Curves for Security", RFC 7748, January 2016. <https://www.rfc-editor.org/rfc/rfc7748>
- [RFC 8032] "Edwards-Curve Digital Signature Algorithm (EdDSA)", RFC 8032, January 2017. <https://www.rfc-editor.org/rfc/rfc8032>
- [SP 800-38D] NIST, "Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC", SP 800-38D, November 2007. <https://doi.org/10.6028/NIST.SP.800-38D>
- [FIPS 180-4] NIST, "Secure Hash Standard (SHS)", FIPS 180-4, August 2015. <https://doi.org/10.6028/NIST.FIPS.180-4>
- [RFC 4648] "The Base16, Base32, and Base64 Data Encodings", RFC 4648, October 2006. <https://www.rfc-editor.org/rfc/rfc4648>
- [RFC 8259] "The JavaScript Object Notation (JSON) Data Interchange Format", STD 90, RFC 8259, December 2017. <https://www.rfc-editor.org/rfc/rfc8259>
- [RFC 9562] "Universally Unique IDentifiers (UUIDs)", RFC 9562, May 2024. <https://www.rfc-editor.org/rfc/rfc9562>
- [RFC 9474] "RSA Blind Signatures", RFC 9474, October 2023. <https://www.rfc-editor.org/rfc/rfc9474>
- [RFC 9578] "Privacy Pass Issuance Protocols", RFC 9578, June 2024. <https://www.rfc-editor.org/rfc/rfc9578>
- [RFC 2104] "HMAC: Keyed-Hashing for Message Authentication", RFC 2104, February 1997. <https://www.rfc-editor.org/rfc/rfc2104>
- [PURBs] K. Nikitin et al., "Reducing Metadata Leakage from Encrypted Files and Communication with PURBs", Proceedings on Privacy Enhancing Technologies 2019(4). <https://doi.org/10.2478/popets-2019-0056>
