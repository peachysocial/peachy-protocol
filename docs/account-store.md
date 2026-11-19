<!-- SPDX-License-Identifier: CC0-1.0 -->
# Account store

**Status:** describes the protocol as implemented by the `peachy-protocol`
0.2.0 release. **Revision:** 1, 2026-11-19. **Editor:** Peachy Social, Inc.

The account store holds a person's settings and lists (blocks, mutes, hidden
and archived chats, accepted message requests, privacy switches), sealed so
that every device of theirs agrees and the server reads none of it, Peachy's
own store-review accounts excepted. The server keeps opaque ids, sealed
values and one version number.

## Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY" and
"OPTIONAL" in this document are to be interpreted as described in BCP 14
(RFC 2119, RFC 8174) when, and only when, they appear in all capitals, as
shown here.

## The model

- Every account has one **account key**: 32 random bytes, minted by its first
  device and held by its approved devices and, for a person who sets a PIN,
  by the PIN vault, sealed under a key derived from the PIN
  ([UnlockRegistration](identity.md#unlockregistration)). The server never
  holds it, except for Peachy's own store-review accounts
  ([Security considerations](identity.md#security-considerations)).
  The account identity key derives from it
  ([Device identity](identity.md#the-account-identity-key)).
- The store is a set of **records**. Each record has a 16-byte random id and
  a sealed value.
- One **manifest** lists every live record id. It is sealed under the
  reserved id of 16 zero bytes.
- The store has one **version**, a counter the server increments on every
  write. Version 0 means there is no store.
- Each record holds one **subject**: one contact, one chat, or the account
  itself.

A client without the account key MUST NOT write the store. See
[A device without the key](#a-device-without-the-key).

## Encryption

Implemented by `mls/core/src/account_store.rs` (`store_seal`, `store_open`,
`generate_account_key`) and pinned by `mls/fixtures/account-store.json`.

### Record key

```
k(id) = HKDF-SHA256(ikm = account_key (32), salt = empty,
                    info = "peachy store v1" || 0x00 || id (16), L = 32)
```

### Sealed value

```
value = 0x01 || nonce (12) || AES-256-GCM(k(id), nonce, pad(plaintext), aad = id)
```

- `0x01` is the format version. A reader MUST refuse any other, and a record
  value it refuses is missing, not another client's
  ([A complete answer](#a-complete-answer)).
- `nonce` is 12 fresh random bytes per seal. A writer MUST NOT reuse a nonce.
- The GCM tag (16 bytes) is appended to the ciphertext.
- A reader opens a record whose plaintext is at most 65,536 bytes before
  padding, and a manifest whose plaintext is at most 360,000 bytes, enough
  for the 10,000 ids the server allows. The server stores a record value of
  at most 8,192 bytes, so a record a client writes carries at most 7,935
  bytes of plaintext ([WriteStore](#writestore)).

### Padding

```
pad(p) = p || 0x80 || 0x00 ... 0x00
```

The zeros fill the result to the next multiple of 256 bytes, so a 256-byte
plaintext pads to 512 bytes. To unpad, strip trailing zero bytes, then
exactly one `0x80`. Anything else MUST be refused. Every sealed value is
`29 + 256·n` bytes for some `n >= 1`; the smallest is 285 bytes.

### Self-notes

`SendSelfNote` carries notes between an account's own devices, sealed under
the account key in a key domain of their own, so a note is never taken as a
record or the reverse. Each note is signed by the device that sent it
([Self-notes](sealed-messages.md#self-notes)). Per-conversation read
positions travel this way, not as store records.

### Key derivation domains

Every key derived from one input keying material shares one HKDF
pseudorandom key (the salt is always empty), so only the `info` string keeps
two derived keys apart:

| Input keying material | `info` | Derives |
|---|---|---|
| account key | `"peachy account identity v1"`, nothing after | the account identity key's seed ([The account identity key](identity.md#the-account-identity-key)) |
| account key | `"peachy store v1" ‖ 0x00 ‖ id (16)` | a record's key ([Record key](#record-key)) |
| account key | `"peachy store v1" ‖ 0x00 ‖ id`, id = SHA-256(`"peachy-signed-out-handover-v1"` ‖ 0x00 ‖ device id (ASCII))[0..16] | the key of the `signed_out_box` sealed, as a record value under that id, to that device ([RevokeDevice](identity.md#revokedevice)) |
| account key | `"peachy self note v1" ‖ 0x00 ‖ id (16)` | the retired unsigned note's key: never sealed or opened, and kept so no new domain reuses it |
| account key | `"peachy self note v2" ‖ 0x00 ‖ id (16)` | a signed note's key ([Self-notes](sealed-messages.md#self-notes)) |
| account key | `"peachy registration lock v1"`, nothing after | the registration lock's token ([UnlockRegistration](identity.md#unlockregistration); the server keeps a salted hash) |
| the box's two agreements | `"peachy account key v1" ‖ 0x00 ‖ A ‖ B ‖ device id (ASCII)` | a version-1 box's key, for a server-run device (test servers; the store-review login) ([Fetching and opening the account key](identity.md#fetching-and-opening-the-account-key)) |
| the box's two agreements and the link secret | `"peachy account key v2" ‖ 0x00 ‖ A ‖ B ‖ device id (ASCII)` | the reserved version-2 box's key: never sealed or opened, and kept so no new domain reuses it |
| the box's two agreements and the link key's HPKE export | `"peachy account key v3" ‖ 0x00 ‖ A ‖ B ‖ SHA-256(L) ‖ device id (ASCII)` | a version-3 box's key and its HPKE `info` (same section) |
| the ephemeral key's agreement with the recipient's signing key | `"peachy transfer key v1" ‖ 0x00 ‖ E ‖ R ‖ device id (ASCII)` | a hand-off's key box (`kb`, [Handing history to your own new device](sealed-messages.md#handing-history-to-your-own-new-device)) |

No domain is a prefix of another, and none contains `0x00`: a new domain
MUST keep both, so that no `info` one derivation uses can be another's with
bytes appended. A unit test in `mls/core/src/lib.rs`
(`no_derivation_domain_is_a_prefix_of_another`) holds the list. Call keys
use their own labels and salts ([calls](calls.md)).

## Plaintexts

Both plaintexts are UTF-8 JSON with no whitespace.

### The manifest

```json
{"version":7,"ids":["0f3c9a0e5b7d4c21a8e6f1b2c3d4e5f6","8a1b2c3d4e5f60718293a4b5c6d7e8f9"]}
```

| Key | Type | Meaning |
|---|---|---|
| `version` | integer >= 0 | The store version this manifest belongs to: the version the write that carries it produces. |
| `ids` | array of strings | Every live record id, as 32 lowercase hex characters. Writers sort them ascending. |

A reader MUST refuse a manifest whose `version` differs from the version
`ReadStore` returned. This stops a server from replaying an older manifest
under a newer version.

A reader MUST also keep a **floor**: the highest version it has read or written
under an account key, stored with its cached store. It MUST refuse a
`ReadStore` answer whose version is below the floor, version 0 included: it
keeps the store it holds, writes nothing, and does not start an empty store.
A device that has never read the store has no floor.
A reader MUST refuse a manifest whose `ids` are not all
32 lowercase hex characters.

The floor is kept **per account key**, and a reader MUST NOT forget one:
not when it drops the key, not when the person starts over, not on a
sign-out, and not when the install starts over as a new device. A device that
takes a key again (from disk, or from a new approval's box) takes back that
key's floor. Only a key the device never held starts at 0. The reference
clients file each floor under the first 16 bytes of
`SHA-256("peachy store floor v1" || 0x00 || account_key)`, in hex. Otherwise
a server could have the same key approved again and serve an old store from a
floor of 0.

### A complete answer

The floor checks the version, not that the records came with it: a server
could leave out one record, such as a block or a verified security code.
So a reader MUST treat a read as all or nothing:

1. **Unreadable** is every returned value, under an id the manifest lists,
   that does not open under its own id: random bytes, another id's value, a
   version byte other than `0x01`, a bad tag, length or padding. An
   unreadable value is never another client's record (every writer seals
   `0x01`), so a reader MUST NOT take it as one, and MUST NOT let it replace
   a record it holds: the held copy stays as it was.
2. **Missing** is every id the manifest lists that the answer did not return
   in a form that opens and that the reader does not already hold, decoded,
   from an earlier read, plus every unreadable id, held or not. A record it
   held but could not decode counts as missing.
3. If anything is missing, the reader asks once more for exactly those ids:
   `ReadStore { since_version = 0, ids = missing }`.
4. If that answer is at another version, or any of those ids is still not
   returned in a form that opens, the reader refuses the read as it refuses
   one below the floor: it keeps the store, version and floor it holds, and
   writes nothing.
5. A returned record that the manifest does not list is ignored.

An honest server returns every record whenever the version moved, so the
second ask happens only in a race with another device's write. The cases are
published as `mls/fixtures/formats/store-read.json`.

### A record

```json
{"kind":"contact","key":"7b1f6a2e-4c3d-4e5f-8a9b-0c1d2e3f4a5b","at":1767225600000,"value":{"blocked":true}}
```

| Key | Type | Meaning |
|---|---|---|
| `kind` | string | `contact`, `chat` or `account`. Other kinds exist; see [Record values](#record-values). |
| `key` | string | The subject: an actor id for `contact`, a group id for `chat`, `""` for `account`. |
| `at` | number | Unix milliseconds of the write. The merge's clock. |
| `value` | object | The kind's fields. |

Writers emit the keys in this order. Readers MUST NOT depend on the order.

## ReadStore and WriteStore

Both require a session, and the session MUST be one that registered a live
device of the account whose install carries the account's signature
(`account_signature`, on either of its two rows; see
[Device identity](identity.md#one-install-two-rows)). Any other caller (a
login with no device, with only a pending device, or with a revoked one) gets
`permission_denied`. The server checks shapes, sizes and the version.

A client MUST certify its device (re-register with the account's
certificate, [Device identity](identity.md#the-account-identity-key)) with the
key in hand before its first `ReadStore` or `WriteStore` under that key, and
MUST treat a `permission_denied` from either as waiting for approval: keep
the key and what was read, write nothing, and run the lifecycle again on the
next store event.

### ReadStore

`ReadStore { since_version, ids }`:

- If no store exists, the response is `version = 0` and nothing else.
- If the store's version equals `since_version`, the response is just
  `version`. Nothing changed.
- Otherwise the response carries `version`, the sealed `manifest`, and the
  `records`: all of them when `ids` is empty, or only those named in `ids`.
  Each id in `ids` MUST be 16 bytes and not all zero (`invalid_argument`).

A read does not notify anyone.

### WriteStore

`WriteStore { expected_version, manifest, upserts, deletes, reset }` is a
compare-and-swap.

1. If the stored version (0 when none) differs from `expected_version`, the
   response is `conflict = true` with the current `version`, and nothing is
   written.
2. Otherwise, in one transaction: if `reset`, every record is deleted; then
   `deletes` are deleted (unknown ids are ignored); then `upserts` are stored,
   replacing a record with the same id; then the manifest is stored and the
   version becomes `expected_version + 1`.
3. The response is `conflict = false` with the new `version`.

A successful write sends a `state_changed` event for
`STATE_DOMAIN_ACCOUNT_STORE` on the account's `StreamEvents` streams, and each
device re-reads.

| Limit or check | Value | Code |
|---|---|---|
| `expected_version` | Not negative | `invalid_argument` |
| Record id | Exactly 16 bytes, not all zero | `invalid_argument` |
| Sealed value or manifest length | At least 285 bytes, and `(length - 29)` a multiple of 256 | `invalid_argument` |
| Record value | At most 8,192 bytes | `resource_exhausted` |
| Manifest | At most 524,288 bytes | `resource_exhausted` |
| Upserts per write | At most 500 | `resource_exhausted` |
| Same id twice in `upserts` | Refused | `invalid_argument` |
| Records in the store | At most 10,000 | `resource_exhausted` |
| Total stored bytes | At most 16 MiB | `resource_exhausted` |

`WriteStore` always needs a manifest. Because records are padded, a record
value is at most 7,965 bytes and its plaintext at most 7,935 bytes. A manifest
listing 10,000 ids is about 350,000 bytes of plaintext and seals to under the
524,288-byte limit.

What the server stores, and sees of each call, is in
[Security considerations](#security-considerations).

## Writing

### Subjects and the merge

There is one record per subject, (`kind`, `key`). Two devices writing at once
can leave two records for one subject. The rule that resolves it:

- Within a subject, the record with the greatest `at` wins. A tie goes to the
  lexicographically greater id (lowercase hex).
- Across subjects, the store is a union.
- Every losing id is deleted in the next write.

### A write

To change subjects, a client:

1. Computes the new value of each subject from the value it holds now (see
   [Patch writes](#patch-writes)).
2. For each changed subject, mints a **new** random 16-byte id (never all
   zero, never an id in use), and deletes every id the subject had. A
   subject whose new value is empty or null is only deleted.
3. Stamps `at = max(now_ms, greatest at of the subject's old records + 1)`.
4. Also deletes every merge loser it holds.
5. If the manifest would list more than 10,000 ids, deletes **key-only
   contacts** until it does not: `contact` records whose value holds nothing
   but `accessKey` and `profileKey`, the oldest `at` first, a tie to the
   lexicographically smaller id, never a subject this write changes. If too
   few exist, the
   client MUST NOT send the write and reports the store as full. It MUST NOT
   delete any other record to make room.
   `mls/fixtures/formats/store-room.json` pins which records a write at the
   bound deletes.
6. Writes a manifest listing every remaining id, including ids it cannot
   decode, with `version = expected_version + 1`.
7. Sends `WriteStore` with `expected_version` set to the version it last read.

On `conflict`, the client re-reads, recomputes its changes on top of what the
other device wrote, and retries. A client SHOULD give up after a few attempts
and report the failure.

On success the client's version and floor become `expected_version + 1`, the
version in the manifest it sealed. The `version` in the response is only
checked against it: a client MUST NOT take its version or floor from the
response, and MUST treat a `conflict = false` response whose `version` is not
`expected_version + 1` as a conflict and read again.

### Patch writes

Several features write fields of one record. A writer MUST change only its
own fields and keep every other field, including fields it does not know. On
a conflict it MUST re-apply its change to the freshly read value, not resend
the value it computed before. A change that leaves the value unchanged writes
nothing. A change that leaves the value empty removes the subject.

### Records a client cannot decode

A record whose value opens under its own id, but whose `kind` this client
does not know, belongs to another build. The client:

- MUST leave it out of what it shows;
- MUST list its id in every manifest it writes;
- MUST NOT delete it in a merge.

Only a value that opens counts; one that does not is missing
([A complete answer](#a-complete-answer)).

**The record format.** Every record is sealed as `0x01`, and a value with any
other first byte does not open, so it counts as unreadable. The manifest
names no format, and a writer keeps only `version` and `ids` when it rewrites
it.

## A device without the key

A device that writes a store it cannot read would replace a person's block
list with an empty one. So a device MUST NOT call `WriteStore` unless it holds
an account key that opens the current manifest.

On launch, after approval, and on every `STATE_DOMAIN_ACCOUNT_STORE` event, a
client runs this lifecycle. Every key is certified before the store is called
with it. Only a certificate the server refuses because it pins another
account identity is a definite answer; one that gets no answer, or that the
server registers without, is not.

1. **It holds a key.** Certify, then read the store.
   - If the certificate was refused for another identity, the key was minted
     here, and its floor is 0, another device minted first: drop the key and
     wait (step 3).
   - If the key does not open the manifest and its floor is above 0, this is
     a refused read: keep the store, version, floor and settings held, write
     nothing, and read again on the next store event or launch.
   - If the key does not open the manifest and its floor is 0, do not write
     with it and go on to step 2, but keep it for the next run.
   - If the store is at version 0 and the floor is 0, write an empty manifest
     (step 4's write) only when this device minted the key itself, that
     first write never landed, and the certificate was taken in this run. For
     a key from an approval's box or the PIN vault, version 0 is a refused
     read.
2. **A box is waiting.** Call `FetchAccountKey` for its own MLS device id. If
   a box comes back, open it as
   [Device identity](identity.md#fetching-and-opening-the-account-key)
   specifies, keep the key, certify the device, and then read the store. A
   box proves a store exists: if the read says version 0, it is a refused
   read, and the device MUST NOT write the empty manifest. If the key does
   not open the manifest, put back the key held before.
3. **The account has an identity key.** If `RegisterDevice` returned a
   non-empty `account_identity_key`, or step 1 or 2 saw a non-zero version,
   another device holds the key. Wait for an approval. A device without the
   key MUST NOT call `ReadStore` to find out: it cannot certify, so the store
   is not served to it.
4. **This device is the first.** Mint a key with a CSPRNG, keep it, certify
   the device with it, and only then write `{"version":1,"ids":[]}` with
   `expected_version = 0` and `reset = true`. If the certificate is refused
   for another identity, or the write answers `conflict`, another device
   minted first: drop this key and wait (step 3). If the certificate gets no
   answer, keep the key and write nothing; the next run certifies again at
   step 1 before it writes. A device that holds a key, even one that no
   longer opens the manifest, MUST NOT mint over it on the server's word; it
   waits at step 3.

The server's answers MUST NOT make a device drop a key it holds. A
`RegisterDevice` that pins an account identity key other than the one the
held key derives is logged, and the device asks to be let in again. A
`became_sole_device` sent to a device that holds a key is ignored
([Device identity](identity.md#registerdevice)). Only the person's own
`ClaimSoleDevice` drops the key, and the old key's floor stays filed.

A setting changed while the device waits MAY be kept locally and written as a
patch once the device holds the key. Changes a person would rely on at once,
such as a block, SHOULD be refused while waiting rather than queued.

## Carrying the key to a new device

The approving device seals the account key to the new device's MLS key and
sends it as `account_key_box` in `ApproveDevice`. The new device fetches it
with `FetchAccountKey` and opens a box only from an approver the person
picked on it or, under the server-approval switch, from any approver the
server lists. The box format and the checks are in
[Fetching and opening the account key](identity.md#fetching-and-opening-the-account-key).

After `ClaimSoleDevice` the server deletes the store and every box, and every
record is lost. The claiming device mints a fresh key and writes a fresh
store.

## Record values

Each value is a JSON object. Every field is optional, and a missing field
means its default. Times are unix milliseconds. An access key is standard
base64 of 16 bytes.

### `contact`

Keyed by the other person's actor id.

| Field | Type | Meaning |
|---|---|---|
| `blocked` | `true` | You block this person. |
| `acrossPeachy` | `false` | The block stays on your devices, and the server isn't told. Missing means the block is also across Peachy: the server was told, and keeps it ([The floor](metadata.md#the-floor)). |
| `accepted` | `true` | You let them in: you accepted or answered their message request, or you started a conversation with them. Without it, a conversation they start is a message request. |
| `accessKey` | string | Their access key, learned from the `ak` of a sealed message they wrote or of a hello they sent ([Hellos](sealed-messages.md#hellos)), only when it differs from the one held and never while `blocked`. A record holding nothing else may be deleted to make room ([A write](#a-write)). A client SHOULD also keep each key it learns in device-local storage that is never synced and never pruned for room, present the store's key while the store holds one and its local copy otherwise, and fill only its local gaps from the store's records (never from a `blocked` one), so a deleted record never costs the sessionless door. |
| `profileKey` | string | Their profile key, learned from the `pk` of a sealed message they wrote, by the rules `accessKey` follows ([Sharing the key](profiles.md#sharing-the-key)). With `accessKey` alone it is still a cache. |
| `contactName` | string | Their name in your phone contacts. |
| `nameChoice` | `"contact"` or `"peachy"` | `"contact"` shows them under `contactName`. Missing or `"peachy"` shows their own Peachy name. |
| `verifiedKey` | string | Standard base64 of their 32-byte account identity key when you marked their security code verified. See [Device identity](identity.md#verified). |

### `chat`

Keyed by the conversation's group id.

| Field | Type | Meaning |
|---|---|---|
| `mute` | string | `"hour1"`, `"hours8"`, `"day"`, `"week"` (timed), `"always"`, `"mentions"`, or `"peachy"`. Missing means not muted. `"peachy"` belongs to a feature out of scope; it is not muted for the archive rule below. |
| `mutedUntil` | number | When a timed mute ends. Set with the mute. |
| `muteAllMentions` | `true` | Mentions of everyone do not notify. |
| `hiddenAt` | number | The chat is hidden up to this moment. A later message shows it again. |
| `hiddenReason` | `"delete"` or `"block"` | Why it was hidden. Missing means `"delete"`. |
| `clearedAt` | number | Delete chat: every message at or before this moment is deleted on every device of this account, and nothing reaches the other people. Written with `hiddenAt` at the same moment. |
| `leftAt` | number | You left this group on one of your devices. |
| `pinnedAt` | number | Pinned since this moment. |
| `markedUnread` | `true` | Marked as unread. Opening the chat or Mark as read removes it. |
| `archivedAt` | number | Archived since this moment. |

Rules that every client applies when it reads these:

- **Leaving.** Leave writes `hiddenAt` and `clearedAt` at one moment with
  reason `"delete"`, removes `pinnedAt`, `markedUnread` and `archivedAt`, and
  sets `leftAt`. Every other device of the person that holds the group leaves
  it too when it reads the record, without writing. A device MUST NOT seat the
  person's other devices in a group whose record has `leftAt`.
- **Being added back.** A Welcome removes `leftAt` and the hide, and keeps
  `clearedAt`, only when all of these hold: it is stamped after `leftAt`; the
  member who signed it is another person, not one of your own devices; and
  this device did not itself ask for the seat in the last 60 days. Any other
  Welcome leaves `leftAt` in place, and the device leaves the group again.
- **Pins.** At most four chats are pinned, oldest pin first, a tie going to
  the smaller group id. A hidden chat is never in the pinned list.
- **Archive.** Archiving writes `archivedAt` and removes `pinnedAt`. A message
  newer than `archivedAt` brings the chat back, with no write, unless the chat
  is muted at that moment (`"always"`, or a timed mute still ahead) while
  `account.keepMutedArchived` is on. A `pinnedAt` newer than `archivedAt`
  wins over the archive.

### `account`

Key `""`.

| Field | Type | Meaning |
|---|---|---|
| `accessKey` | string | This account's own access key. Once `profileKey` is set, the one it derives. |
| `profileKey` | string | This account's profile key ([Profiles](profiles.md#format)): standard base64 of 32 bytes. |
| `sealedAvatar`, `sealedCover` | object | The sealed copies of this account's photo and cover its sealed profile points at, with the delete token (`x`) that removes a replaced one ([Writing a profile](profiles.md#writing-a-profile)). |
| `readReceipts` | `false` | Read receipts are off: send no read marks in sealed conversations and show nobody's. Missing means on. |
| `typingIndicators` | `false` | Typing indicators are off: send none and show none. Missing means on. |
| `linkPreviews` | `false` | Build no preview for links this person sends. Missing means on. |
| `notificationContent` | `"name"` or `"none"` | What a shown notification reveals. Missing means the name and the message. |
| `defaultTimer` | integer | Seconds, 1 to 2,419,200. The disappearing-message timer every chat this person founds starts with. Missing means off. |
| `notify` | object | Which kinds of notification are on. Keys include `dms`, `mentions`, `groups` and `calls`; other keys belong to features out of scope. `false` turns a kind off; a missing key, or any other value, is on. The field being present means the person has chosen. |
| `keepMutedArchived` | `true` | A muted archived chat stays archived when a message arrives. Missing means off. |
| `deviceNames` | object | From a device row id to that device's name, at most 120 characters each: the name a device gives itself, and the only one, since the server keeps no device name. Each device writes only its own entry, under both of its row ids (the plain row and its MLS twin), and drops entries for rows no longer on the account's device list. A device with no entry is shown by its platform; a value that is not a string is ignored. |
| `signedOutKeys` | array of strings | The device keys a PIN restore signed out, lowercase hex of 32 bytes each, at most 64, oldest first; none is removed to make room. A device approves none of them ([RevokeDevice](identity.md#revokedevice)). |

A device that has never held a key that opened the store MUST read
`readReceipts` and `typingIndicators` as on. A device whose read is refused
keeps reading them from the records it holds.

### Names reserved for features out of scope

Kinds and fields this document does not list belong to features out of scope,
and every unlisted name is reserved. A client MUST NOT invent
kinds or fields of its own, MUST NOT write a reserved one, and MUST keep every
field it does not know when it patches a record.

## Losing every device

A person who loses every device keeps the store only through a PIN backup
still in the PIN vault, restored with the PIN
([Who may certify](identity.md#who-may-certify), PIN restore). Otherwise
they lose the account key, and with it the store: `ClaimSoleDevice`
([Device identity](identity.md#claimsoledevice)) wipes the store and every
key box, and the claiming device starts a fresh store under a fresh key.

## Security considerations

- **What the server learns.** Record ids, padded sizes, the version, and
  which of the person's devices writes or reads and when; not what a record
  says or its kind ([Metadata](metadata.md#what-the-server-never-holds)).
- **The server chooses which version a device reads**, within the floor
  ([The manifest](#the-manifest)).
- **Approval is what hands out the key.** Any approved device receives the
  account key, so approving a device is the step to protect
  ([Letting a new device in](identity.md#letting-a-new-device-in)).
- **The key is a secret like the device seed**, kept under the same rules
  ([The key stores](identity.md#the-key-stores)).
- **Recovery rests on the PIN.** Without a PIN backup there is none
  ([Losing every device](#losing-every-device)). With one, the PIN vault,
  which Peachy runs, holds the account key sealed under a key derived from
  the PIN.
- **The store-review accounts are the server's.** A device the server runs
  holds their key, so the server reads their store
  ([Security considerations](identity.md#security-considerations)).

## IPR

This document is dedicated to the public domain under CC0 1.0.

## References

- [RFC 2119] "Key words for use in RFCs to Indicate Requirement Levels", BCP 14, RFC 2119, March 1997. <https://www.rfc-editor.org/rfc/rfc2119>
- [RFC 8174] "Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words", BCP 14, RFC 8174, May 2017. <https://www.rfc-editor.org/rfc/rfc8174>
- [RFC 5869] "HMAC-based Extract-and-Expand Key Derivation Function (HKDF)", RFC 5869, May 2010. <https://www.rfc-editor.org/rfc/rfc5869>
- [SP 800-38D] NIST, "Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC", SP 800-38D, November 2007. <https://doi.org/10.6028/NIST.SP.800-38D>
- [FIPS 180-4] NIST, "Secure Hash Standard (SHS)", FIPS 180-4, August 2015. <https://doi.org/10.6028/NIST.FIPS.180-4>
- [RFC 4648] "The Base16, Base32, and Base64 Data Encodings", RFC 4648, October 2006. <https://www.rfc-editor.org/rfc/rfc4648>
- [RFC 8259] "The JavaScript Object Notation (JSON) Data Interchange Format", STD 90, RFC 8259, December 2017. <https://www.rfc-editor.org/rfc/rfc8259>
