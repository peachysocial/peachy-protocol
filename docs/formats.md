<!-- SPDX-License-Identifier: CC0-1.0 -->
# Message formats

**Status:** describes the protocol as implemented by the `peachy-protocol`
0.2.0 release. **Revision:** 1, 2026-11-19. **Editor:** Peachy Social, Inc.

This page lists the golden tables that pin the message formats in these
specs. A golden table is a JSON file of cases: inputs and the exact output
every implementation must produce. The prose specs are normative. A table
shows what the prose means on real bytes, and the official clients replay
every table in their own tests.

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY" and
"OPTIONAL" in this document are to be interpreted as described in BCP 14
(RFC 2119, RFC 8174) when, and only when, they appear in all capitals, as
shown here.

## Two kinds of table

**Tables for the MLS core.** The files at the top of `mls/fixtures/`
(`rules.json`, `credentials.json`, `rosters.json`, `device-link.json`,
`account-store.json`, `join-request.json`, `welcome-frame.json`,
`carried-commit.json`, `calls.json`, `client-refusals.json`,
`device-seal.json` and `steward.json`) pin what the MLS core does. Each
language binding replays them through one function, the fixture door
([The fixture door](mls-core.md#the-fixture-door)). `keytrans.json` pins
`mls/keytrans`: its generator (`mls/keytrans/src/bin/gen_fixture.rs`) writes it
and checks the committed copy. Those files are described
in the specs that use them: [MLS core](mls-core.md), [Device identity](identity.md),
[Delivery](delivery.md), [The account store](account-store.md) and
[Calls](calls.md).

**Tables for the formats clients write.** The files in
`mls/fixtures/formats/` pin formats that live above the MLS core: the frames
inside application messages, the group's own state, self-notes, and a few
client decisions. The MLS core carries these as opaque bytes, so the fixture
door does not evaluate them. Each client replays them with its own code.
`formats/commit-refusal.json` is the exception: the core's recovery driver
replays it (`mls/core/tests/recovery.rs`). An
independent client SHOULD replay them the same way.

## Reading a table

Every file in `mls/fixtures/formats/` has the same outline:

- `_about` comes first. It says what the table pins, which section of the
  specs is normative, and what each field of a case means.
- Constants follow, such as limits and version numbers, where the table has
  them.
- Then one or more lists of cases. Most cases have an `id` (usually with a
  `why`) or a `name`; neither is input. They say which rule the case
  exercises. A few small tables (`chunkSize`, `paddedSize`,
  `forkRejoinDelays`, `spacing.cases`) are plain rows of input and expected
  output.
- Many lists hold several kinds of case. The `call` field names the question
  a case asks, such as `encode`, `parse` or `fold`.

To replay a table, run each case through your implementation and compare the
result with the case's expectation, field by field. A `null` expectation means
the input is not a valid instance of the format. A reader MUST ignore such an
input, and MUST NOT treat it as an error.

Inside a case, decoded values often use long names such as `messageId` or
`objectKey`. The wire uses the short keys that the specs define. `_about`
gives the mapping where it is not obvious.

Ids, handles, object keys and names in cases are test strings. They have no
meaning beyond the rules the case exercises.

## The tables

### payload.json

Pins the transcript frame: the bytes `0xFF 0x05` and a JSON object. Each case
gives a decrypted plaintext in base64 and its classification: `envelope` with
the decoded fields, `tooNew` or `unreadable`. It covers the frame's keys,
attachment pointers, places, replies, mentions, the access key and the
disappearing timer.

Normative: [The frame](sealed-messages.md#the-frame),
[Keys of a frame](sealed-messages.md#keys-of-a-frame) and
[Attachment pointers](sealed-messages.md#attachment-pointers).

### chunking.json

Pins sealed attachment objects byte for byte: the `PSA2` chunked format and
its padded version 3. It holds the chunk-size rule (`chunkSize`) and the
padding rule (`paddedSize`), round trips (`vectors`, `paddedVectors`), and
damaged objects a reader MUST refuse (`tamper`, `paddedTamper`). Plaintexts
are not written out. Each is built from a rule given in `_about`.

Normative: [Chunked objects (PSA2)](sealed-messages.md#chunked-objects-psa2)
and [Padded objects (version 3)](sealed-messages.md#padded-objects-version-3).

### mention.json

Pins how a sender turns `@handle` and `@all` in the words into the frame's
`m` and `ma`, given the conversation's members (`roster`, `resolve`).

Normative: [Keys of a frame](sealed-messages.md#keys-of-a-frame). The spec
only requires mentions to be resolved against the roster. The table pins how
the official clients match handles, and a sender SHOULD match them the same
way.

### disappearing.json

Pins when a disappearing message's countdown starts and when the message is
deleted (`expiry`). The timers themselves are pinned on the wire in
`payload.json` (`x`) and `group-meta.json` (`dis`).

Normative: [Disappearing messages](sealed-messages.md#disappearing-messages).

### content-hint.json

Pins what a device does with a message it cannot open (`fates`), the hint
values (`hints`), the `urgent` bit each hint sends with (`urgent`), the
transcript retry key (`retryKey`), how long the author's send log can answer
(`sendLog`), and the `resend-frame` answer (`resendFrames`).

Normative: [Content hints](sealed-messages.md#content-hints),
[Asking for a message again](sealed-messages.md#asking-for-a-message-again),
[The urgent bit](delivery.md#the-urgent-bit) and
[Idempotency](delivery.md#idempotency).

### reaction.json

Pins the reaction frame (`encode`, `parse`) and how a lane of reactions folds
into what a client shows (`fold`).

Normative: [Reactions](sealed-messages.md#reactions).

### receipt.json and receipt-route.json

`receipt.json` pins the receipt frame and how read and delivered marks fold
into what a client shows. `receipt-route.json` pins which marks a device
sends, every one to every device in the conversation, and the spacing
between batches.

Normative: [Receipts](sealed-messages.md#receipts).

### delete.json

Pins the delete frame, the author check (`honor`), and how deletes that
cannot be judged yet are kept and later judged (`pending`).

Normative: [Deletes](sealed-messages.md#deletes).

### edit.json

Pins the edit frame, whether a received edit applies, is dropped or waits
(`decide`), when a sender offers Edit (`canSend`), and how waiting edits are
kept (`pending`).

Normative: [Edits](sealed-messages.md#edits).

### resend.json

Pins the `resend` answer's wire format (`cases`) and whether a well-formed
answer may fill its seat on this device (`acceptCases`).

Normative: [Asking for a message again](sealed-messages.md#asking-for-a-message-again).

### history.json

Pins the history share frame (`parse`, `roundTrip`), the byte arithmetic that
splits a share into chunks (`cost`, `chunk`), and whether arriving words may
replace what a seat holds (`seat`).

Normative: [History shares](sealed-messages.md#history-shares).

### hello.json

Pins the hello frame (`encode`, `parse`), which hands its sender's access key
to the whole conversation. Every current build reads and sends it.

Normative: [Hellos](sealed-messages.md#hellos).

### typing.json

Pins the typing frame byte for byte: the JSON, the padding, and the sealed
bytes for a given key and nonce (`seal`, `open`).

Normative: [Typing inside the group](sealed-messages.md#typing-inside-the-group).

### group-meta.json

Pins the value of the group's own state, the `peachy_group_meta` extension:
the codec (`encode`, `parse`), the name and topic rules (`name`, `topic`), and
the invite tag (`inviteTag`). Who may change what is pinned in
`mls/fixtures/rosters.json`, not here.

Normative: [The group's own state](sealed-messages.md#the-groups-own-state),
[The value](sealed-messages.md#the-value),
[The name is in the group](sealed-messages.md#the-name-is-in-the-group),
[The group photo](sealed-messages.md#the-group-photo) and
[Invites](sealed-messages.md#invites).

### transfer.json

Pins the self-note bodies (`note`) and the history hand-off document a device
sends to its account's own new device (`parse`). How a self-note is sealed is
pinned in `mls/fixtures/account-store.json`. A `transfer` note's pointer is
passed through untouched, including a `kb` (the document's key sealed to the
device it went to, opened in place of `k`), whose box that fixture also pins.

Normative: [Self-notes](sealed-messages.md#self-notes) and
[Handing history to your own new device](sealed-messages.md#handing-history-to-your-own-new-device).

### self-note-trust.json

Pins which self-notes a device acts on: whose signature counts (`senders`),
which notes act (`verdicts`), and that a note acts once
while its id is remembered (`seen`). It also pins which siblings are handed
history, by the verdict `check_own_device_key` gives for each (`answers`). How
a note is signed and opened is pinned in `mls/fixtures/account-store.json`.

Normative: [Signed notes](sealed-messages.md#signed-notes) and
[Handing history to your own new device](sealed-messages.md#handing-history-to-your-own-new-device).

### store-read.json

Pins reading the account store as all or nothing: which of the manifest's
records a read is missing, counting a returned value that does not open as
missing even for a record the reader holds, and when the second ask refuses
the read (`withheld_records`).

Normative: [A complete answer](account-store.md#a-complete-answer).

### store-room.json

Pins a write at the account store's bound: which key-only contacts it deletes
to make room and when the store is full (`key_cache.cases`), and which
arriving access keys a device keeps (`key_cache.learn`).

Normative: [A write](account-store.md#a-write) and
[`contact`](account-store.md#contact).

### commit-refusal.json

Pins what a device does when `SubmitCommit` refuses its commit (`verdicts`),
whether a commit whose answer was lost was taken anyway (`commitsTaken`), when
being behind becomes stranded (`stuckBehind`), and how rejoins after a fork
are spaced out (`forkRejoinDelays`, `forkRejoins`).

Normative: [A commit the server refuses](delivery.md#a-commit-the-server-refuses)
and [SubmitCommit](delivery.md#submitcommit).

### security-code.json

Pins the security code: the 60 digits and the QR text for each pair
(`pairs`), the code after a key change (`changedKey`), what a scan reports
(`compare`), and the verified state of a contact (`verification`).

Normative: [Computing it](identity.md#computing-it) and
[Verified](identity.md#verified).

## Retiring a wire format

A format two devices exchange (an envelope version, a Welcome's framing, a
frame's signed or unsigned form, a commit a receiver would refuse) changes in
three steps: readers accept both forms, then writers send only the new one,
and only then do readers refuse the old one. A reader that refuses a commit
the rest of its group applied cannot follow the group past it, and leaves
and rejoins.

A reader drops a refused form silently: no head check, no count toward being
behind, no rejoin and no row in the transcript. An old commit that never
became the group's head is evidence of nothing.

## What is not here

Formats that belong to features outside this specification (Feed, events,
communities, group links and join inboxes, and stories) have no table here,
and cases that exercise their keys were left out of the tables above.

Two formats in the specs have no table. For these the prose is the
specification:

- link previews ([Link previews](sealed-messages.md#link-previews));
- when a device asks a sibling for a history hand-off, and when a sibling
  hands one over unasked ([Handing history to your own new device](sealed-messages.md#handing-history-to-your-own-new-device)).
  Whether a sibling answers an ask is pinned in `self-note-trust.json`
  (`answers`), and the `history` note's body in `transfer.json`.

## Security considerations

Matching a table is necessary, not sufficient. Every format here travels
inside an MLS application message, the account store or a self-note, and
takes its confidentiality and authenticity from there. What a table pins is
what a group member wrote, and a member may be hostile: a reader MUST treat
every decoded value as untrusted input and keep to the limits the specs set.

## IPR

This document is dedicated to the public domain under CC0 1.0.

## References

- [RFC 2119] "Key words for use in RFCs to Indicate Requirement Levels", BCP 14, RFC 2119, March 1997. <https://www.rfc-editor.org/rfc/rfc2119>
- [RFC 8174] "Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words", BCP 14, RFC 8174, May 2017. <https://www.rfc-editor.org/rfc/rfc8174>
- [RFC 8259] "The JavaScript Object Notation (JSON) Data Interchange Format", STD 90, RFC 8259, December 2017. <https://www.rfc-editor.org/rfc/rfc8259>
- [RFC 4648] "The Base16, Base32, and Base64 Data Encodings", RFC 4648, October 2006. <https://www.rfc-editor.org/rfc/rfc4648>
