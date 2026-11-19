<!-- SPDX-License-Identifier: CC0-1.0 -->
# Sealed messages

**Status:** describes the protocol as implemented by the `peachy-protocol`
0.2.0 release. **Revision:** 1, 2026-11-19. **Editor:** Peachy Social, Inc.

This document specifies what a Peachy device puts inside an MLS group: the
envelope every sealed byte travels in, the plaintext of an application
message, the control frames that share the group with it, typing, and the
group's own state carried in its GroupContext. It also covers how members
seat and remove devices, and what a device keeps when it signs out. With it,
the `mls/` workspace and the golden fixtures, an independent client can
produce bytes the official apps open, and open theirs.

## Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY" and
"OPTIONAL" in this document are to be interpreted as described in BCP 14
(RFC 2119, RFC 8174) when, and only when, they appear in all capitals, as
shown here.

| Term | Meaning |
|---|---|
| conversation id | A lowercase, hyphenated UUID string, for example `0f8e2a1c-5b7d-4e9a-8c3f-2d1b6a9e7c40`. |
| group id | The MLS `group_id`: the UTF-8 bytes of the conversation id (36 bytes). Every exporter context and envelope key below uses these bytes. |
| actor id | A person's stable account key, a lowercase UUID. It is what MLS credentials name. |
| device id | A device's UUID, as `RegisterDevice` returned it. |
| frame id | The UUID a sender mints for one transcript message (`i`, below). Members name a message to each other by it. |
| envelope id | `MailboxEnvelope.id`: the server's name for one send, the same for every recipient. |
| base64 | RFC 4648 section 4, with `=` padding. |
| base64url | RFC 4648 section 5, without padding. |
| `‖` | Byte concatenation. |
| BE*n* | An unsigned big-endian integer of *n* bits. |

All JSON is UTF-8 (RFC 8259). A writer MUST NOT emit a duplicate key anywhere
in an object. Where this document says a parser is **strict**, the reader
MUST refuse the whole value when any object in it, at any depth, names a key
twice, compared after unescaping. A reader MUST ignore keys it does not know,
unless a section says otherwise. Key order is not significant, except in the
typing frame, whose bytes are pinned.

The ciphersuite is `MLS_128_MLKEM768X25519_AES128GCM_SHA256_Ed25519`. Every
handshake and application message is a `PrivateMessage`; the core refuses
`PublicMessage`. Credentials, key packages, commits and the group's lifecycle
are specified with the core (`mls/core`) and in
[Device identity](identity.md#the-mls-leaf).

## The layers

One sealed message passes through four layers. From the outside in:

| Layer | What it is | Who can read it |
|---|---|---|
| `SendSealed` request | Recipients, access keys, an `urgent` bit, the payload. | The server. |
| Envelope | `version ‖ nonce ‖ tag ‖ AES-256-GCM(...)`, keyed by the epoch it was sealed at (version 3), or by the group id (version 2). | Members of that epoch; for version 2, anyone who knows the group id. |
| MLS `PrivateMessage` | The application message, its content hint in `authenticated_data`. | Members of that epoch. |
| Plaintext | A transcript frame, a lane frame or a resend ask. | Members of that epoch. |

A typing frame replaces the MLS layer with a frame of its own
([Typing inside the group](#typing-inside-the-group)). A Welcome is never
wrapped in an envelope.

## The envelope

Every sealed byte a conversation sends (application message, commit, seat
ask, typing frame, call signal) is wrapped in an envelope before it reaches
the server. A member MUST seal version 3, keyed by the epoch it was sealed
at, and seals version 2, keyed by the group id, only for a seat ask and a
link preview; a receiver still opens a version 2 envelope of the other kinds
([The wrapped envelope](delivery.md#the-wrapped-envelope) says why). The
envelope hides the group id, the epoch and the MLS framing. Its layout,
versions and kinds, and the `handle` that is the server's only name for a
conversation, are specified in
[The wrapped envelope](delivery.md#the-wrapped-envelope) and
[Handles and sender-addressed delivery](delivery.md#handles-and-sender-addressed-delivery).
A receiver MUST drop and acknowledge an envelope of a kind it does not
implement.

### Recipients and your own envelopes

A send names every leaf of the sender's current tree, its own device
included, and no other device, so every send in a conversation at one
epoch names the same set ([Who to address](delivery.md#sending)). This holds
for every frame, receipts included, except a group ring's `*_elsewhere`
reply ([The ring is a message](calls.md#the-ring-is-a-message)) and
typing, which leaves out the devices of a blocked account
([Typing inside the group](#typing-inside-the-group)). A device gets its own
envelopes back, recognizes them by nonce and acknowledges them unopened
([Own sends come back](delivery.md#own-sends-come-back)); MLS cannot decrypt
a member's own application message, so the sender records its own message,
and its own authorship, at send time.

## The anonymous door

`SendSealed` and `SubmitCommit` need no session. A sessionless call proves
instead that it may reach the recipients, with each recipient account's
access key ([Access keys](delivery.md#access-keys)), and, for a commit, that
it is a member of the epoch, with the epoch's send key
([SubmitCommit](delivery.md#submitcommit)). Access keys travel only inside
sealed messages (`ak`, [Keys of a frame](#keys-of-a-frame), and
[hellos](#hellos)).

## Size-hiding padding

**Application messages** are padded inside the AEAD with RFC 9420's
`PrivateMessageContent` padding, to a multiple of 256 bytes
(`APPLICATION_PADDING_BLOCK` in `mls/core/src/group.rs`;
`mls/core/tests/padding.rs`): transcript frames, lane frames and resend
answers alike.

**Commits** are padded the same way to a target no member's commit could
exceed, so that a commit's length depends on the tree's width, its member
count and what the commit carries, never on which member made it or where
any member sits (`mls/core/src/commit_padding.rs`;
`mls/core/tests/commit_sizes.rs`). The target is computed from what every
member holds alike, the public tree as the commit's proposals leave it and
the proposals themselves:

1. The largest leaf node of the members that survive the commit, other than
   this commit's joiners, as it would be re-signed as a commit's leaf; plus
   one public key for each level of the tree (the base-2 logarithm of its
   width); plus one HPKE ciphertext for each of those members but one. An
   UpdatePath has at most one node per level and at most one ciphertext per
   other non-joining member, so no real commit is longer.
2. That, plus the commit's proposals, its signature, its confirmation tag and
   the AEAD tag. The proposals are counted as at least one inline
   GroupContextExtensions proposal holding the group's current extensions
   plus 64 bytes, so a rotation, a renewal and a change of the group state
   that grows it by 64 bytes or less are one length.
3. Rounded up to a multiple of 256 bytes.

A sender MUST pad every commit this way, its `PrivateMessageContent` to
exactly that target; a receiver needs nothing new, since the padding is
zeros. The target does not depend on where the tree's blanks and filled
parents are, where the founder's device sits
([Founding a conversation](delivery.md#founding-a-conversation)), or which
leaves a commit last re-signed. A renewal that brings the sender a credential
or capability list larger than its leaf now holds is the one input not from
the tree: a sender MUST add that growth to every surviving leaf's figure,
not only to its own, the growth measured against its own leaf (what it still
shows is in [The floor](metadata.md#the-floor)). A credential's length is fixed by
its fields ([Format](identity.md#format)). A leave, the one standalone
proposal the protocol takes ([Leaving](#leaving)), is padded to the 256-byte
block like a message. A commit of leaves counts each leave by reference (34
bytes) toward its proposals, within the floor of step 2.

**Typing frames** are padded to 128 bytes
([Typing inside the group](#typing-inside-the-group)), **link previews** with
spaces to 256 bytes ([The preview](#the-preview)), and **account-store values
and self-notes** by their own rule ([Self-notes](#self-notes)).
**Attachments** are padded to a size bucket before they are sealed
([Padded objects](#padded-objects-version-3)).

**Envelopes.** Every envelope, version 2 or 3, whatever it carries, is padded
to at least 512 bytes and above that to a Padmé bucket of its length
([The wrapped envelope](delivery.md#the-wrapped-envelope)), so a short
message, a reaction, a receipt, a seat ask, a typing frame and a call frame
are one length on the wire.

Padding does not hide that a message was sent, when, to which devices, or
the bucket an attachment falls in.

## Content hints

Every application message a device seals, except a call signal, carries a
**content hint** in its MLS `authenticated_data`, readable when the message
itself will not open (`mls/core/src/hint.rs`):

```text
authenticated_data = 0x70 ‖ 0x01 ‖ hint ‖ commitment (16)
```

`commitment` is the author's commitment
([Asking for a message again](#asking-for-a-message-again)): 16 bytes for a
message that may be asked for again, zeros for every other.

| Hint | Name | Sent on | What a receiver does when it cannot open the message |
|---|---|---|---|
| 0 | default | Call records. | Show a "couldn't be opened" placeholder now. Ask for nothing. |
| 1 | resendable | Transcript messages. | Hold a hidden placeholder, send a resend ask, and show the placeholder only if no answer arrives within 1 hour (3,600,000 ms). |
| 2 | implicit | Receipts, resend asks, resend answers, history shares, hellos, group events. | Count it and show nothing. |
| 3 | resendable lane | Reactions, edits, deletes. | As for 1. |

Rules:

- A sender MUST set the hint as in the table. Commits carry none.
- A call signal on the MLS lane carries no hint: its `authenticated_data`
  MUST be `0x63 0x01` followed by 16 zero bytes
  ([The two lanes](calls.md#the-two-lanes)), which a receiver reads as no
  hint.
- `peek_message` in the core reads a message's epoch, hint and commitment
  without any key.
- A receiver MUST treat AAD that does not start with `0x70 0x01`, or a hint
  value it does not know, as "no hint", and a message with no hint as
  implicit. Nothing the server says stands in for a hint.
- The hint also sets the send's `urgent` bit: set for hints 1 and 3, clear
  for 0 and 2 ([The urgent bit](delivery.md#the-urgent-bit)).
- A receiver SHOULD hold at most 200 hidden placeholders. Holding a 201st
  shows the one due soonest. A held loss is always shown in the end, never
  dropped unseen.
- An answer to a resend ask clears a hidden placeholder only if it is of the
  same class: a transcript answer clears one held for hint 1, a resent lane
  frame one held for hint 3.

The hint is authenticated once the message opens, and is not confidential
from members; the envelope hides it from the server.

Fixture: `mls/fixtures/formats/content-hint.json`.

## What an application message holds

A receiver classifies the decrypted plaintext of an application message:

1. First byte `0xFF`: a **transcript frame**.
2. Otherwise, UTF-8 JSON object with a non-empty string `peachy`:
   - `"resend-ask"`: a [resend ask](#asking-for-a-message-again).
   - any other value: a **lane frame**, dispatched on that value.
3. Anything else MUST be dropped.

The author of any of these is the MLS sender: the actor id in the decrypted
leaf credential. No frame names its own author, except typing, which is not
an MLS message.

## Transcript messages

A transcript message is something a person wrote. It is sent with
`urgent = true`, content hint 1, and a `client_message_id` derived from the
frame's `i` under a secret only the sending install holds, never `i` itself
([Idempotency](delivery.md#idempotency)). It names the objects it points at
only inside the ciphertext.

### The frame

```text
byte 0    0xFF   (never a UTF-8 lead byte)
byte 1    0x05   (the frame version)
byte 2..  UTF-8 JSON object
```

A reader MUST classify the frame as:

| Condition | Result |
|---|---|
| byte 1 greater than 5 | too new: the client SHOULD say that an update is needed to read it. |
| byte 1 less than 5, no `0xFF` lead, invalid UTF-8 (fatal decoding), not a JSON object, or `i` missing or not a UUID | unreadable. |
| otherwise | a message. |

Fixture: `mls/fixtures/formats/payload.json`.

### Keys of a frame

| Key | Type | Required | Meaning and rules |
|---|---|---|---|
| `i` | string | yes | The frame id, a UUID minted by the sender. Read case-insensitively, then lowercased. |
| `t` | string | yes | The words. A non-string reads as `""`. |
| `a` | array | yes | Attachment pointers, possibly empty ([Attachment pointers](#attachment-pointers)). |
| `p` | object | no | A place: `{"n":name,"c":context,"la":lat,"lo":lng,"r":radius_km}`. `n` is trimmed and MUST be non-empty, `|la|` ≤ 90, `|lo|` ≤ 180, `r` > 0 or read as 0. Otherwise `p` is dropped. |
| `r` | string | no | The parent's frame id, for a reply. Ignored when equal to `i`. Threads are one level deep: a sender replying to a reply MUST name the top-level parent. |
| `b` | `true` | no | Only with `r`: the reply is also shown in the main transcript. |
| `m` | array | no | Mentions: `[{"u":actor id,"h":handle}]`, at most 10, resolved by the sender against the roster. An entry without a string `u` is dropped. `h` is lowercased; `""` when absent. |
| `ma` | `true` | no | The message mentions everyone in a group. |
| `ak` | string | no | The sender's access key: base64 of exactly 16 bytes (22 characters and `==`). Anything else reads as absent, and the rest of the frame survives. |
| `pk` | string | no | The sender's profile key: base64 of exactly 32 bytes (43 characters and `=`), read by the rule `ak` is. A sender includes it only once the server holds the access key it derives ([Sharing the key](profiles.md#sharing-the-key)). |
| `x` | integer | no | The disappearing timer in seconds, 1 to 2,419,200. **Fails closed**: an `x` present with any other value makes the whole frame unreadable. |
| `lp` | object | no | A link preview ([Link previews](#link-previews)). |
| `ev`, `st`, `ge`, `c` | object | no | Keys of features outside this specification (`ge` is a group-link event, `c` a call record). A client that does not implement them MUST NOT draw a frame carrying `ge` or `c` as a person's message. |

Rules for writers and readers:

- A malformed optional key is dropped and the rest of the frame decodes,
  except `x`.
- A sender MUST write `x` equal to the conversation's current timer (`dis`,
  [The group's own state](#the-groups-own-state)) and omit it when the timer
  is off.
- A sender SHOULD include `ak` so recipients can reach it through the
  anonymous door. Whether it does MUST NOT depend on whom it has blocked
  ([Blocked accounts](#blocked-accounts)). `ak` and a [hello](#hellos) are
  the only ways a key travels.

### Attachment pointers

Each element of `a` is a pointer to a sealed object:

| Key | Type | Meaning |
|---|---|---|
| `o` | string | Object key, `sealed/<uuid>.bin`. |
| `k` | string | base64 of the 32-byte AES-256 key. |
| `n` | string | base64 nonce: 12 bytes for version 1, the 4-byte nonce prefix for versions 2 and 3. |
| `d` | string | base64 SHA-256 of the true plaintext (its first `s` bytes). |
| `s` | number | True plaintext size in bytes. |
| `m` | string | MIME type. |
| `w`, `h` | number | Width and height in pixels; 0 when unknown. |
| `ms` | number | Duration in milliseconds; 0 when none. |
| `c` | string | Average color as `#rrggbb`, or `""`. |
| `f` | string | File name, or `""`. |
| `v` | number | Pointer version. Absent means 1. Written only when 2 or more. |
| `cs` | number | Chunk size. Written only when `v` ≥ 2. |

A numeric field that is not a finite number greater than 0 reads as 0, and
every number is floored. A reader MUST choose the decryption by `v`, never by
looking at the object:

| `v` | Object format |
|---|---|
| 1 | One-shot AES-256-GCM: `ciphertext ‖ tag(16)`, the 12-byte nonce from `n`, no AAD. Read only. |
| 2 | A `PSA2` object ([Chunked objects](#chunked-objects-psa2)). Read only. |
| 3 | A padded `PSA2` object ([Padded objects](#padded-objects-version-3)). Every sender MUST write version 3. |

**Upload.** A sender calls `CreateUpload` with `UPLOAD_KIND_FILE`,
`SEALED_CLASS_ATTACHMENT`, content type `application/octet-stream` and the
exact ciphertext length, and PUTs the ciphertext to `upload_url` with header
`content-disposition: attachment`, or, for an object larger than one part,
asks for `resumable` and sends it in parts
([Resumable upload](delivery.md#resumable-upload)). The returned `object_key`
goes in `o`. The send that carries the pointer MUST NOT name the object
outside the ciphertext: the server records no account against a sealed
upload, and a key named beside the send would tie the two together.

**Download.** The object is at `<media_base_url>/<o>`, where
`media_base_url` comes from `GetMeResponse`. A reader MUST compose the URL
itself and MUST NOT follow a URL found in a message. The object is public to
anyone who holds its key name and is deleted 30 days after upload, so a
recipient SHOULD download it when the envelope arrives. A 403, 404 or 410
means it is gone. A reader of version 1 MUST check `d` before showing
anything. A reader of version 2 or 3 MAY open each chunk as it arrives
([Reading as it arrives](#reading-as-it-arrives)), but MUST NOT show any of it
before `d` has been checked over the whole file.

**Limits.** A file is at most 90 MiB of plaintext. An object is at most
100,000,000 bytes; the largest padded object is 94,461,405 bytes.

### Chunked objects (PSA2)

```text
header (32 bytes, big-endian):
  "PSA2" (4) ‖ version 0x02 (1) ‖ 0x000000 (3)
  ‖ chunk_size BE32 ‖ plaintext_size BE64 ‖ chunk_count BE32
  ‖ nonce_prefix (4) ‖ 0x00000000 (4)

object = header ‖ chunk_0 ‖ … ‖ chunk_{count-1}
chunk_i = AES-256-GCM(key, nonce = nonce_prefix ‖ BE64(i),
                      aad = header ‖ BE32(i), plaintext slice i)   (ciphertext ‖ tag16)
```

- `chunk_count` = ceil(`plaintext_size` / `chunk_size`), and 1 for an empty
  plaintext. Chunk *i* starts at byte 32 + *i* · (`chunk_size` + 16).
- The object is exactly 32 + `plaintext_size` + 16 · `chunk_count` bytes.
- A reader MUST refuse non-zero reserved bytes, a `chunk_size` of 0, a
  `chunk_count` that does not match, and an object of any other length. A
  header version other than 2 is "too new".
- Chunk size: 64 KiB for a plaintext up to 16 MiB; 2 MiB for 512 MiB or
  more; otherwise ceil(size / 256) rounded up to a multiple of 64 KiB.
- The chunk key and nonce prefix MUST be fresh per object.

### Padded objects (version 3)

Before sealing, the sender pads the plaintext with zero bytes to a bucket:

```text
bucket = 541
while bucket < size: bucket = bucket + ceil(bucket / 20)
```

The `PSA2` header states the padded size, and the chunk size is chosen from
the padded size. The pointer's `s` is the true size. A reader MUST require
the header's size to be at least `s` and every byte past `s` to be zero, and
MUST check `d` over the first `s` bytes. A reader MUST accept any zero tail,
whatever bucket it reaches.

Fixture: `mls/fixtures/formats/chunking.json`.

### Reading as it arrives

A chunk's tag covers the header and the chunk's index, so chunk *i* is
authenticated at its position as soon as its last byte has arrived. A reader
of version 2 or 3 opens the object incrementally:

1. Once 32 bytes are in, read the header with every refusal of
   [Chunked objects](#chunked-objects-psa2); for version 3 the header's size
   MUST be at least `s`. A header whose object would be longer than
   100,000,000 bytes is a refusal, made before anything is allocated for it.
2. Whenever the whole of chunk *i* is in (its plaintext length plus 16 bytes),
   open it, check that every byte at or past `s` is zero, and only then keep
   its bytes below `s`. A reader MUST NOT keep any byte of a chunk whose tag
   has not verified.
3. A byte beyond the object's exact length is a refusal.
4. When every chunk is open and nothing is left over, check `d` over the
   first `s` bytes. On any refusal, at any step, the reader MUST discard what
   it kept for this object and show the attachment as unreadable.

A reader MUST NOT show, play, store or pass on any of the kept bytes before
step 4 has passed: the tags prove the bytes were sealed under the pointer's
key, but only `d` proves they are the one file the pointer describes. A
download that breaks off resumes at the start of the first chunk that has not
verified, discarding any bytes of it already received
([Download](delivery.md#download)). The vectors of
`mls/fixtures/formats/chunking.json` are fed to openers in arbitrary slices.

### Link previews

`lp` is a preview the sender built: `{"u":url,"t":title,"d":description,
"dt":published_ms,"im":pointer}`.

- `u` MUST start with `https://` (case-insensitive), be at most 4096
  characters, and appear in `t` of the frame as a whole link: followed only
  by closing punctuation and then whitespace or the end.
- `t` and `d` are clipped to 500 UTF-16 code units, never splitting a
  surrogate pair. `dt` greater than 0 is floored, else 0.
- `im` is an attachment pointer, read by the rules of `a`.
- A preview with neither a title nor a readable image is dropped. A
  malformed `lp` is dropped and the words survive.

### Disappearing messages

When a frame carries `x`, every device deletes the message `x` seconds after
its countdown starts:

- For the author's own devices, the countdown starts at send.
- For anyone else, it starts when the device first shows the message in an
  open, attended transcript, or at the time of a read note from another of
  that person's devices, whichever is earlier. A note stamped in the future
  counts as now.

Expiry deletes the words, attachments and local records. It sends nothing.
Timed messages MUST NOT be included in history shares or own-device
history hand-offs. Fixture: `mls/fixtures/formats/disappearing.json`.

## Lane frames

Lane frames are JSON application messages with a `peachy` tag. Each is sent
with the hint its section names, `urgent` as that hint sets it, and its own
retry key, the same on every retry of one send, never derived from the
message it names or from its content ([Idempotency](delivery.md#idempotency)).
A reaction, an edit and a delete are retried as a message is, in order per
conversation, so a retried reaction never lands after the unreact that
followed it. Every frame parser in this section is strict. A frame with an
unknown `v` MUST be dropped. The MLS sender is the frame's author.

### Reactions

```json
{"peachy":"react","v":1,"m":"<frame id>","e":"👍"}
{"peachy":"react","v":1,"m":"<frame id>","x":true}
```

- `e` MUST be exactly one emoji: one extended grapheme cluster, at most 32
  bytes of UTF-8, made only of `Extended_Pictographic` and
  `Emoji_Component` code points and U+200D, with at least one
  `Extended_Pictographic`, Regional Indicator or U+20E3.
- `"x":true` (a JSON boolean) clears the sender's reaction.
- Each person has at most one reaction per message. Per sender, the latest
  valid frame in mailbox order wins. An invalid frame does not clear an
  earlier one.
- Sent to the whole group, hint 3. Never a notification.

Fixture: `mls/fixtures/formats/reaction.json`.

### Receipts

```json
{"peachy":"receipt","v":1,"k":"read","m":"<frame id>"}
{"peachy":"receipt","v":1,"k":"lane","m":"<envelope id>"}
```

- `k` is `"read"`, `"delivered"` or `"lane"`; a receiver ignores any other
  value. A read or delivered mark is a high-water mark: it covers every
  earlier message by that author. The latest mark by transcript position
  wins, so an older mark never moves the line back. Read implies delivered.
- `"k":"lane"` is a **lane mark**: `m` is the `MailboxEnvelope.id` of a
  reaction, an edit or a delete, never a message. A receiver MUST NOT keep
  or draw it, even when `m` matches a frame id it holds.
- A receiver MUST also take a `delivered` mark carrying `"l":true` (the JSON
  boolean; any other value is ignored) as a lane mark. A device MUST NOT send
  one.
- A device MUST NOT send read marks while the person's read-receipts setting
  is off. Delivered marks still go.
- **When a delivered mark is due.** A device owes a delivered mark when it
  opens an urgent frame from somebody else, not when it shows it: a
  transcript message (hint 1), and a reaction, an edit or a delete (hint 3),
  whether or not it applies the frame. A frame that arrives in an answer to a
  resend ask is not owed one. Marks are batched per conversation: a device
  SHOULD wait about 1.5 seconds after the first mark falls due and then send
  one mark of each kind, naming the last message opened (delivered) or read
  (read). A device MUST NOT send a mark for a frame from its own account or
  from an account it has blocked ([Blocked accounts](#blocked-accounts)), and
  SHOULD NOT send a mark it has already sent for the same message. It SHOULD
  NOT send a delivered mark that a read mark it sends in the same batch, or
  has already sent, covers.
- **A lane frame is owed the same follow-up as a message.** When a batch
  opened a reaction, an edit or a delete from somebody else and would
  otherwise send nothing, the device MUST send one lane mark, naming the
  newest such frame's envelope id. Neither "nothing new" rule above applies
  to it, and it moves neither line those rules keep. When the batch sends any
  other mark, that mark is the follow-up. So the server sees the same quiet
  send about 1.5 seconds after every urgent send a device opened.
- **Read marks are about messages only.** A device sends a read mark when a
  person reads a transcript message, never for a reaction, an edit or a
  delete ([G2](metadata.md#what-the-server-never-holds)).
- Hint 2. A receipt is never `urgent`.

**Routing.** A receipt is addressed like every other send: to every leaf in
the sender's current tree, its own device included
([Recipients and your own envelopes](#recipients-and-your-own-envelopes)). A
device MUST NOT address a receipt to only the authors it covers. A receipt
that is owed goes to every leaf, a blocked account's included.

**Spacing.** After a batch that sent anything, a device SHOULD send the next
batch into that conversation no sooner than min(300 s, max(1.5 s, 250 ms ×
devices)) later, where devices is the number of leaves in its tree; a read
made from a notification action MAY go at once.

Fixtures: `mls/fixtures/formats/receipt.json`, `mls/fixtures/formats/receipt-route.json`.

### Deletes

```json
{"peachy":"del","v":1,"m":"<frame id>"}
```

- Only the author may withdraw a message: the delete's MLS sender MUST equal
  the target's MLS sender, as this device recorded it. With no record, the
  author the device knows for the row is used. With neither, the delete
  waits.
- A receiver keeps waiting deletes per (frame id, sender), at most 512 frame
  ids per group, oldest forgotten first. When the target can be judged, every
  sender that fails the check is dropped, so a forged delete never blocks the
  real one.
- There is no time limit.
- Honoring a delete removes the words and attachments and leaves a
  tombstone ("This message was deleted"). Hint 3.

Fixture: `mls/fixtures/formats/delete.json`.

### Edits

```json
{"peachy":"edit","v":1,"m":"<frame id>","n":1,"b":"the whole new text"}
```

- `n` is the revision, an integer 1 to 10. `b` is the whole new text and MUST
  NOT be blank after trimming.
- Only the author may edit, judged as for deletes.
- A sender offers Edit for 24 hours after the original and for at most 10
  revisions. A receiver applies an edit received at most 48 hours after the
  target, only when `n` is greater than the revision it has applied, and
  never to a withdrawn message.
- Edits wait like deletes (512 ids per group; the highest revision per
  sender is kept). An edit never notifies. Hint 3.

Fixture: `mls/fixtures/formats/edit.json`.

### Asking for a message again

A device that cannot open a resendable message asks the group for it:

```json
{"peachy":"resend-ask","v":1,"m":"<envelope id>"}
```

`m` is the `MailboxEnvelope.id` of the message that would not open. The ask
is an application message to the whole group, hint 2. A device SHOULD send
at most 10 automatic asks per mailbox drain. A device whose own epoch is
behind the group's MUST rejoin instead of asking ([Rejoining](#rejoining)).

**Who answers.** Each of the author's devices that still holds the words
answers. It MUST answer only when the asking device is a current leaf, and
only when every person in the group now was also in it when the message was
sent. Answers are idempotent.

A transcript message is answered with:

```json
{"peachy":"resend","v":1,"m":"<envelope id>","d":"<asking device id>",
 "t":"…","a":[…],"p":{…},"i":"…","r":"…","b":true,"x":3600,"lp":{…},"st":{…}}
```

`t`, `a`, `p`, `i`, `r`, `b`, `x`, `lp` and `st` have the frame's meanings
and rules, `x` failing closed. A receiver places the words in the seat of
envelope `m`.

A lane frame is answered from the author's send log (frames kept for 14 days,
or the conversation's timer if shorter, at most 500):

```json
{"peachy":"resend-frame","v":1,"m":"<envelope id>","d":"<asking device id>","f":"<the lane frame, as sent>"}
```

`f` is the original frame's JSON text. A receiver MUST refuse an `f` that is
itself a `resend-frame` or a `resend-ask`. Both answers are hint 2.

**The author's commitment.** Every member can decrypt every answer, so the
lost message itself names its author, in the 16 bytes after its hint
([Content hints](#content-hints)), readable without opening it:

```text
commitment = SHA-256("peachy resend author v1"
                     ‖ u32be(len) ‖ group_id ‖ u32be(len) ‖ actor_id
                     ‖ u32be(len) ‖ secret)[0..16]
```

- `actor_id` is the sender's own. `secret` is the transcript frame's `i`,
  lowercased (a random UUID, which the answer carries back as its `i`), or,
  for a lane frame, its whole JSON text, which the answer carries back as
  `f`. A message with no such secret carries zeros and commits to nobody
  (`resend_secret_of` in the core).
- A resendable lane frame MUST carry `z`, standard base64 of 16 bytes a
  receiver ignores, so its text cannot be guessed and tested against each
  member's commitment. A stored send's salt SHOULD be the same on every retry
  of that send, since the server answers a repeated `client_message_id` with
  the first copy ([Sending](delivery.md#sending)).
- A receiver that cannot open a message keeps its commitment beside the
  hidden placeholder, and takes an answer only if the commitment computed from
  the answer's MLS sender and the secret the answer carries equals it. A
  mismatch is refused as `not_the_author`, and an answer for a message that
  carried no commitment as `no_commitment`. A refused answer moves nothing on
  screen.

- The order of refusals is `not_for_this_device`, `no_such_row`,
  `wrong_group`, `not_sealed`, `not_the_author`, `no_commitment`,
  `not_asked`, `already_held`. An accepted answer replaces a quotation
  ([History shares](#history-shares)).

Fixture: `mls/fixtures/formats/resend.json` (`acceptCases`,
`commitmentCases`).

### History shares

A member who adds somebody MAY share recent history with them. The share is
one or more lane frames, each at most 131,072 bytes of JSON before
encryption, hint 2:

```json
{"peachy":"history","v":2,"share":"<uuid>","chunk":0,"chunks":1,
 "window":"days:30","for":"<actor id>","with":["<actor id>", …],"to":"person",
 "messages":[{"id":"…","by":"<actor id>","at":1790000000000,"text":"…","i":"…","r":"…","b":true}]}
```

- `window` is `"nothing"`, `"days:<n>"` or `"everything"`. `for` is the first
  person the share is for and `with` lists all of them when there is more
  than one.
- A reader MUST refuse a `v` other than 2 or a `to` other than `"person"`,
  and a `chunk` outside 0 to `chunks` − 1.
- A shared message is a **quotation**: the sharer vouches for it. The
  original author's signature is not carried, so a member could put words in
  anyone's mouth with one. A reader therefore MUST file a quotation only:
  - for a message from before its device joined the group: an `at` in a
    whole second strictly earlier than the second of the join. The join is
    the server's time of the latest Welcome that seated the device, since a
    re-add or a rejoin seats it again, else a lower bound such as its first
    join or its own registration. Both times are the server's to the second;
    the millisecond of `at` is only the sharer's delivery order. With no join
    time known, a reader MUST NOT drop the share: it leaves the envelope
    unacknowledged and reads it again later;
  - and only from a gap the device really missed: an `at` in a whole second
    later than the newest message it holds in the conversation from before
    the join that is not itself a quotation (one it was sent, opened or not,
    its own, words its author resent, or one handed over by another of the
    account's own devices). A re-added or rejoined device keeps
    its earlier stint, and a linked device may hold history from before its
    own join; a share never writes in among that;
  - into a seat that holds nothing: no words, and no message the device was
    sent itself, a placeholder it could not open included. Those words come
    back only from their author
    ([Asking for a message again](#asking-for-a-message-again)).

  Any other entry is dropped, and the rest of the share still files.
- After a reader imports a history transfer from another of its account's
  devices ([Handing history to your own new device](#handing-history-to-your-own-new-device))
  into a conversation, it MUST check every quotation in that conversation
  again against the messages it now holds there from before the join that
  are not quotations, and delete each whose `at` is in a whole second from
  the oldest such message's second to the newest's, both included. A
  quotation below every such message stays: it sits in a stretch the reader
  holds nothing of (a share it was given as a newcomer, before an earlier
  stint), and a transfer carries no quotations, so it is the reader's only
  copy. A quotation of a message the transfer carries is replaced by the
  transfer's copy. The reader MUST write the transfer's messages before the
  check, and MUST NOT let a share's look at what it holds and its filing
  interleave with the check in the same conversation: a share that looked
  before the messages landed has filed by the time the check reads, and one
  that looks after finds them held, so a share filed before, during or after
  a transfer never stays in among the messages the reader then holds.
  The cost is accepted: an honest share of a stretch the reader missed
  between two it holds (a gap between an earlier stint and the history a
  later transfer brings) is deleted too, and that stretch then reads as
  missing. A reader that files two direct chats with the same people as one
  (Peachy keeps the one with the lower handle) checks the kept one the same
  way, under the same exclusion, once the other's messages are filed under
  it, against the latest of their joins: a share admitted into the other
  was judged against that chat's history alone, and may be dated among
  messages the reader holds in the kept one after its own join. A reader
  that cannot run that check yet (no join known) runs it again on its next
  pass. A transfer's copy of a message whose id a share filed in
  another conversation takes the message back into the conversation the
  transfer names. A reader that cannot finish the check, or whose write of
  the messages fails (the check still runs), imports the transfer again
  before it counts it as imported.
- So a quotation only ever sits in a stretch of the conversation the reader
  never held, where every message is a sharer's copy. The author's own words,
  the original or a resend, always replace a quotation, and a second
  quotation never rewrites the first.
- A reader MUST name the sharer where the message is explained (Peachy's
  clients: "Shared by <sharer>" in the message's Info), and MUST keep it when
  the words leave the app (Copy).

Fixture: `mls/fixtures/formats/history.json`.

### Hellos

A hello hands its sender's access key to everyone in the conversation, so
that a member who never sees the sender write can still reach them through
the anonymous door ([Access keys](delivery.md#access-keys)).

```json
{"peachy":"hello","v":1,"ak":"<access key>"}
```

- `ak` is read exactly as a transcript frame's `ak`
  ([Keys of a frame](#keys-of-a-frame)): base64 of exactly 16 bytes, 22
  characters and `==`. A hello without a valid `ak` MUST be dropped.
- A receiver keeps `ak` under the MLS sender's actor id, exactly as it keeps
  the `ak` of a transcript frame, and never for its own account. Nothing in
  the frame names an account.
- Parsing is strict: a duplicate key or a trailing comma makes the payload
  not a hello, and so does a `v` other than the number 1. An unknown extra
  key is ignored.
- Hint 2, never `urgent`, its own retry key, the same on every retry of one
  send ([Idempotency](delivery.md#idempotency)), addressed like every send
  ([Recipients and your own envelopes](#recipients-and-your-own-envelopes)).
  A hello is never shown, never notifies, and is owed no delivered mark.

Every client sends hellos, and every reader MUST accept one. A client MUST:

1. send one hello to the whole tree after it has applied a Welcome;
2. send one hello to the whole tree after it has applied a commit, anybody's
   and its own included, that brings into the tree an account that was not
   in it before. A new device of an account already in the tree does not
   count, and neither does its own account: its own devices hold every key
   it has learned, in the account store;
3. wait a random time of up to 30 seconds before either, so that the hellos
   of one add, and those of one account's devices, do not leave together;
4. send it through the anonymous door when it holds the key of every
   account in its tree, and with its session otherwise, like any send;
5. include `ak` in every transcript frame;
6. not let whether it sends a hello, or to whom, depend on whom it has
   blocked ([Blocked accounts](#blocked-accounts)).

A hello owed is written down, so a relaunch inside the wait still sends it.
A second reason before the first hello has gone keeps the earlier time and
sends one hello under a fresh retry key, since a send under the old key may
have reached the server before the newcomer was in the tree. A hello that
cannot go yet (no access key the server holds, no seat, a failed send) is
tried again a minute later and given up a day after its latest reason. A
tree that holds only the sender's own account is owed nothing.

Fixture: `mls/fixtures/formats/hello.json`.

## Typing inside the group

A typing indicator is not an MLS application message. It is a frame keyed
from the epoch, wrapped in an envelope of kind 4 and relayed without being
stored ([Typing](delivery.md#typing)).

```text
unsigned  = {"peachy":"typing","s":<ms>,"t":<true|false>,"u":"<actor id>","v":1}
statement = "peachy typing signature v1" ‖ 0x00 ‖ u32be(len) ‖ group_id
            ‖ u64be(epoch) ‖ unsigned
plaintext = {"g":"<base64 signature>","peachy":"typing","s":<ms>,"t":…,"u":…,"v":1}
padded    = plaintext ‖ 0x00 …   (to a multiple of 128 bytes, at least 128)
key       = MLS-Exporter("peachy typing v1", context = group_id, length = 32)
frame     = nonce (12) ‖ AES-256-GCM(key, nonce, padded)   (no AAD)
```

- The JSON keys MUST be written in exactly this order (alphabetical), with
  no whitespace. `t` true means "still composing", false is an explicit
  stop; `u` is the composer's actor id; `s` is the sender's clock in
  milliseconds, strictly increasing per sender; `g` is standard base64 of the
  Ed25519 signature by the sender's own leaf signature key over `statement`.
  A real frame is two blocks, 284 bytes.
- The nonce MUST be fresh and random per frame.
- A receiver strips trailing `0x00` bytes and parses strictly: a duplicate
  key, another `v`, an empty `u`, a non-boolean `t`, an `s` that is not a
  whole number, a `g` that is not 64 bytes, or a frame missing `g` or `s` is
  ignored. It drops a frame whose
  `u` is its own actor, and any frame that does not open.

- A receiver MUST drop a signed frame unless the signature verifies, with
  `verify_strict`, under the leaf key of a current leaf whose credential names
  `u`, at the receiver's own epoch. It MUST drop a frame whose `s` is more
  than 120 seconds from its own agreed clock (its wall clock corrected by the
  server's, [The live lane's replay window](calls.md#the-live-lanes-replay-window);
  a sender stamps `s` on its own), and one whose `s` it has already taken
  from that leaf in that epoch. There is no high-water mark: an older stamp
  still inside the window that was never taken is accepted.
- `t: true` is a heartbeat. A sender sends it on the first keystroke and
  every 10 seconds while composing. It sends `t: false` after 3 seconds
  idle, when the field is emptied, or when the conversation closes. A
  receiver expires an indicator 15 seconds after the last `true`, and clears
  it when a message from that person arrives.
- A device MUST NOT address typing to the devices of an account it has
  blocked, and sends none at all into a conversation where no other account
  is left once they are taken out, such as a 1:1 with a blocked account
  ([Blocked accounts](#blocked-accounts)).

Fixture: `mls/fixtures/formats/typing.json`.

### The key is the epoch's exporter secret, not the application ratchet

Heartbeats on the application ratchet would spend a generation for every
receiver and could push a sleeping device past the 1000-generation limit;
the exporter secret is stateless and per epoch, and a frame from an earlier
epoch does not open. Since every member derives the key, the leaf signature
is what names the sender.

## The group's own state

A private group's state is the GroupContext extension `peachy_group_meta`,
type `0xF1A9` (RFC 9420 private-use range). Its value is UTF-8 JSON, at least
1 byte and at most 16 384 bytes (`mls/core/src/group_meta.rs`). It is changed
by a `GroupContextExtensions` proposal in a commit. A joiner reads it from the
Welcome.

Rules for the proposal:

- It MUST change this extension and nothing else, and MUST add `0xF1A9` to
  `required_capabilities` (keeping what is there). The core checks this
  (`group_meta_change`).
- Every leaf MUST advertise `0xF1A9` in its capabilities.
- External joins, PSK proposals, ReInit and SelfRemove are refused. A member
  cannot commit a Remove of its own leaf; how it leaves is in
  [Leaving](#leaving).
- The proposal travels inline in its sender's own commit. A proposal by
  reference is refused ([The proposal rules](mls-core.md#the-proposal-rules)).

### The value

```json
{"v":1,"n":"Sunday climbers","adm":["<actor id>"],"pol":{"add":"any"},"dis":86400}
```

| Key | Type | Meaning |
|---|---|---|
| `v` | 1 | Format. A reader MUST refuse any other value. It stays 1: new keys are added, existing keys never change meaning. |
| `n` | string | The name ([The name is in the group](#the-name-is-in-the-group)). May be empty. |
| `t` | string | The topic. Same character rules as `n`, at most 500 scalars and 1000 bytes. Written only when non-empty. |
| `a` | object | The group photo ([The group photo](#the-group-photo)). |
| `adm` | array | Admins: 1 to 64 distinct actor ids. A group whose `adm`, `pol`, `lk` and `ban` all read is a policy group ([The group's policy](mls-core.md#the-groups-policy)). |
| `pol` | object | The policy ([Policy](#policy)). |
| `dm` | `true` | A direct chat: a 1:1, a note to self, or an unnamed chat of several people. Every member is an admin and the name is empty. See [A direct chat](delivery.md#founding-a-conversation). |
| `dis` | integer | The disappearing timer in seconds, 1 to 2,419,200. Absent means off. |
| `ban` | array | Banned actor ids ([Bans](#bans)). |
| `lk` | object | The group link, `{"k":…,"r":…,"a":"any"|"adm"|"off"}`. Group links are out of scope; see [Bans](#bans) for the one rule that touches policy. |
| `inv` | object | Marks an invite ([Invites](#invites)). |
| `pnd` | object | The group's pending invites, invitee to inviter ([Invites](#invites)). |
| `acp` | any | Advanced Chat Privacy: while it is on, no member's app sends the conversation's messages to Peachy's AI notification feature, which is outside this specification. |
| `cg`, `cm`, `dir`, `jk`, `ev` | any | State of features outside this specification. |

The parser is strict. A value that does not parse is unreadable, and an
unreadable value is not a rename: the reader keeps what it showed before.

A writer MUST carry through, unchanged, every key it does not mean to change.
That includes `adm`, `pol`, `dm`, `dis`, `acp`, `lk`, `ban`, `inv`, the
out-of-scope keys and any key it does not know. A commit that dropped `lk`
or `ban` would also be refused by every honest member.

Fixtures: `mls/fixtures/formats/group-meta.json` for the value;
`mls/fixtures/rosters.json` for the policy.

### The name is in the group

The name lives only in the group's state. The server never holds it, except
in the store-review login's demo conversations, whose other members it runs
([Security considerations](identity.md#security-considerations)).

- `n` is at most 100 Unicode scalar values.
- It MUST NOT contain C0 or C1 controls, U+007F, bidi controls (U+200E,
  U+200F, U+202A to U+202E, U+2066 to U+2069), U+00AD, U+180E, U+200B,
  U+200C, U+2060 to U+2064, U+FEFF, U+115F, U+1160, U+3164, U+2800, or tag
  characters U+E0000 to U+E007F. U+200D is allowed.
- A name that breaks a rule is refused, never repaired. A writer MUST NOT
  commit one. A reader MUST treat a value carrying one as unreadable.
- An empty name is allowed. The client then titles the conversation from
  its roster.

### The group photo

`a` has exactly these nine keys:

| Key | Value |
|---|---|
| `v` | 3 |
| `o` | `sealed-meta/<lowercase uuid>.bin` |
| `k` | base64 32-byte key |
| `n` | base64 4-byte nonce prefix |
| `d` | base64 SHA-256 of the plaintext |
| `s` | plaintext size, 1 to 5,000,000 |
| `m` | `image/jpeg`, `image/png` or `image/webp` |
| `cs` | chunk size, at least 1 |
| `x` | the delete token: 43 base64url characters |

The object is a version 3 sealed object, uploaded with no session through
`CreateSealedMetaUpload` ([Upload](delivery.md#upload)), never
`CreateUpload`. It stays pending until an accepted commit lists it in
`SubmitCommitRequest.meta_object_keys`, and is deleted 7 days after upload if
none does; once kept, it lasts until a member deletes it. A client that
cannot use that door MUST NOT set a group photo. The member
who replaces the photo SHOULD delete the old object with
`DeleteSealedObject{object_key, delete_token}`. A reader composes the URL from
its own `media_base_url`, never from the value.

### Policy

`pol` is `{"add":…,"meta":…,"acp":…,"rm":…}`, each `"any"` or `"adm"`.
Absent keys take defaults: `add` any, `meta` any, `acp` adm (any in a DM),
`rm` adm.

Every member's device judges every commit before merging it (`judge_commit`
in `mls/core/src/policy.rs`), by the rules and deny codes in
[The group's policy](mls-core.md#the-groups-policy); a group whose state
names no readable policy is judged as one with no admin, and a receiver
refuses what that rule refuses.

A device that founds a group MUST write `adm`. The server does not enforce
the policy: it accepts a commit that breaks it into the order, every honest
member refuses to merge it, and the group cannot advance until that is
resolved.

### Bans

`ban` lists actor ids that may not be added: lowercase UUIDs, no duplicates,
oldest first, at most 100. An empty list is the same state as no list, and a
writer MUST omit it rather than write `[]`. A writer adding a 101st entry
drops the oldest.

- An Add of a banned actor is refused by every member, whoever commits it
  (deny code 22).
- Only an admin may change `ban`.
- To let a banned person back, an admin first commits a meta that removes
  them from `ban`, then adds them in a second commit.

An implementation that never writes `lk` MUST still carry `lk` and `ban`
through and honor them when judging commits: an `lk` whose `a` is `any` lets
any member add, whatever `pol.add` says.

### Invites

`inv` marks a two-person conversation that is an invitation into another
group: `{"t":tag}` while unanswered, then `{"t":tag,"r":"join"|"no"|"void"}`.

```text
t = base64url(SHA-256("peachy invite v1" ‖ 0x00 ‖ group_id ‖ 0x00 ‖ invitee_actor_id)[0..16])
```

The tag names the target group only to a device that already holds it.
`inv` is never written on a direct chat.

The inviter's device founds the invitation with the invitee's devices and its
own. Besides `t` and `r`, `inv` MAY carry `c`, the target group's member count,
an integer from 1 to 500, and `p: true`, meaning the inviter listed the invitee
in the target group's `pnd`. A reader treats each that does not read as
absent, and ignores any other key inside `inv`. The invitation's `n` is the
target group's name. It carries no `a` and names no member: who is in the
group, and its photo, reach the invitee only when they are seated. A writer of
`r` MUST carry `c` and `p` through.

The invitee answers by a commit to the invitation's own state: `r: join` to
accept, `r: no` to decline. A client that accepts every invitation (a bot)
writes `r: join` on each it receives. The device that sees `r: join` seats
the invitee in the target group by an ordinary add; one that can no longer do
so writes `r: void`.

`pnd`, on the target group, is an object from each invited actor id to the
actor id of who invited them, at most 500 entries. A reader that cannot read
it treats it as absent and MUST still carry it through unchanged, and MUST NOT
write a `pnd` over it. A writer builds every change from the value on its own
tree, and MUST NOT add an entry to a list of 500. The inviter writes the
entry when it sends the invitation, where its own rule allows the meta change,
and sends the `added` group event then; the device that seats the invitee
removes the entry and sends `added` again. An `added` event is backed when its
subject is in the tree or is in `pnd` under the event's sender; one only `pnd`
backs is drawn without the invitee's name except on the inviter's own devices.

Any member the meta rule allows can write `pnd`, so a reader counts an entry
only while the inviter's own backed `added` for it is the newest of that
inviter's `added` events and the `revoked` events about that invitee.
Cancelling is a `revoked` group event about the invitee, sent before the
commit that removes the entry. It is backed when its subject is not in the
tree and its sender is an admin, or sent an `added` about that invitee that
this device kept while only `pnd` backed it (its invited row); `pnd` never
backs it. A reader keeps, with the row, whether
its sender was an admin when it arrived, and counts a `revoked` against an
inviter's invitation only when the sender is that inviter or was an admin.
Rows are ordered by the server's time, a device's own rows included. A device
of the inviter's that holds a counted `revoked` for an invitation marked `p`,
newer than its own `added`, writes `r: void`, answered or not; an entry that
is gone without one cancels nothing. A cancel whose `revoked` was not sent
MUST NOT remove the entry.

An invitation that closes without the inviter's device seating the invitee
ends the entry that inviter listed, on the inviter's device that sees it.
After `r: no`, that device removes the entry and sends no group event: a
`revoked` reads as the invitation withdrawn, so a decline MUST NOT send one.
After `r: void`, while the invitee is not in the tree, it sends `revoked`
first, as a cancel. For an invitee already in the tree it only removes the
entry, since a `revoked` about a member is not backed.

A device that declines an invitation as a block keeps its tag: it answers
`r: no` to every later invitation carrying that tag, whoever sends it, and
leaves the target group if it is seated in it directly.

## Membership

Every change of membership is a commit, built in one epoch, submitted with
`SubmitCommit`, and merged only after the server accepts it. A device MUST
clear a staged commit the server refused. An Add carries one Welcome per
added device in `SubmitCommitRequest.welcomes`. A device added later reads
nothing sent before its Welcome.

### Removal

A removed member reads nothing sealed at an epoch after its removal: the removal is a
Remove commit signed by a member's device, and every later epoch derives from
secrets the removed leaf never held (`mls/core/tests/removal.rs`). A Welcome
that would move a group back to an epoch the removed leaf held is refused as
[Welcome semantics](delivery.md#welcome-semantics) describes
(`mls/core/tests/stale_welcome.rs`).

- A device MUST remove the leaves the server names in `stale_device_ids`
  (revoked devices) that the core's `stale_leaf_removable` allows: on the
  account's signed revocation, a lapsed credential (a person's last leaf
  only past the grace), or, while signed revocations are not enforced and
  the person keeps another unlapsed leaf in the group, the server's word
  alone
  ([Revocation reaches a seated leaf through the roster](identity.md#revocation-reaches-a-seated-leaf-through-the-roster)).
  This only ever removes; it never seats anyone.
- A removal names the leaf by its index and its leaf key from one roster
  read, so a leaf that another commit emptied and refilled since that read
  is not removed ([The commit lifecycle](mls-core.md#the-commit-lifecycle)).
- Messages a removed member already opened stay on its devices.
- A removal is not a device revocation.

### Leaving

A member cannot commit its own removal (RFC 9420 §12.2), so another member's
device commits it (`begin_leave`, `follow_leave` and `commit_proposed_leaves`
in `mls/core/src/group.rs`; `mls/core/tests/leave.rs`,
`mls/core/tests/leave_lands.rs`):

1. The leaving device proposes the removal of each leaf of its own person,
   its own included (`begin_leave`): one Remove proposal per leaf, each sent
   alone to the group's leaves as a message (envelope kind 1, not urgent).
   It forgets the conversation at once, but keeps the group as a **leaving
   stub** with a leaving record beside it (step 5), and writes the person's
   leave record, on which the person's other devices forget the group
   (`forget_group`, then `forget_remembered_roster`;
   [Record values](account-store.md#record-values)). A person who is alone in
   the group, with no leaf of anybody else's, has nobody to commit the leave:
   the device forgets the group and sends nothing.
2. Every member's device takes each proposal through the message door, which
   takes a leave and no other proposal, and keeps it in the proposal store,
   together with the bytes it arrived as.
3. After the drain, each device that kept a leave waits a random 0 to 3
   seconds, catches up, and commits the leaves still kept: one commit naming
   each by reference and carrying nothing else, submitted and merged like
   any other ([Membership](#membership)). The commit **carries the proposal
   messages it names**, in the same entry, ahead of the commit
   ([The carried commit](delivery.md#the-carried-commit)). A device never
   commits a leave of its own person. The server takes one commit for the
   epoch; the other devices clear theirs.
4. Every device that applies the commit, its maker included, takes the
   carried proposals through the message door first, so a device the leave
   never reached still holds them, and then the commit. It learns who left:
   each person every one of whose leaves the commit removed by that
   person's own proposals (`CommitOutcome::left`). It draws "{name} left"
   for each, whoever made the commit. A device the commit removes because
   its own person left asks for no seat back.
5. **The leave is sent again until it takes.** A different commit that takes
   the proposals' epoch first drops them. So the leaving device follows the
   group's commits through the stub (`follow_leave`): a commit that moves the
   group on with this device still seated gets the leave proposed again at
   the new epoch, once per epoch, sent as in step 1 to the stub's leaves
   (`leave_recipients`); the commit that removes this device ends the leave,
   and the group, its kept roster and the leaving record are forgotten. The
   stub is in no list, opens no message, and makes no commit or send of its
   own; only its commit entries are read, and every other entry of it is
   dropped unread. It survives a restart. A Welcome into the group's id ends
   the leave, and so does forgetting the group. A commit this device cannot
   apply gives the leave up: the stub is forgotten, and the person's leaves
   stay in the others' trees until an admin removes them or they lapse past
   their grace ([Refreshing a seated leaf](identity.md#refreshing-a-seated-leaf)).

A Remove by reference is taken only when the leaf it removes belongs to the
person who proposed it, and is judged as theirs; the group's policy lets
anyone remove their own leaves
([The proposal rules](mls-core.md#the-proposal-rules)).

### Seating a person's second device

A group seats devices, not people, so a person's device added after the
group was made is in nothing until a member adds it. A device that knows a
group but holds no leaf in it, while the member list still names its actor,
sends a **seat ask** (envelope kind 3) to the group's leaves. The ask, its
proof and the member's steps, with both checks against the tree, are
specified in [Rejoin with a sealed seat ask](delivery.md#rejoin-with-a-sealed-seat-ask)
and [Seat asks are taken in once](delivery.md#seat-asks-are-taken-in-once).

**The member's answer.** A signed ask proves who is asking, not that they
belong. A member's device seats the asker only when the asker's person holds
a leaf in its own tree, is its own person (but not a device the account
removed), or is someone it is itself still adding (`pending_actors`); any
other asker, and a person whose last leaf it saw leave and who holds none
again, is `NotAMember` (verdict 7) and seated by nobody (step 5 of
[Rejoin with a sealed seat ask](delivery.md#rejoin-with-a-sealed-seat-ask)).
Seeing a person leave also drops them from the roster a device keeps for a
group it forgot
([A Welcome into a group this device knew](delivery.md#a-welcome-into-a-group-this-device-knew)).

### Seating your own new devices

A brand-new device knows no group id, and the server knows none to tell it,
so **every device seats its own account's other devices in every group it is
in.** After an approval, at start and on every sessions change, a device
lists its account's devices (`ListDevices`), keeps those that are live,
approved and account-certified, and adds each one that has no leaf. An Add of
the committer's own actor is always allowed by the policy.

### Rejoining

A device whose tree no longer matches the group (it missed a commit, the
mailbox reported `lost`, or its verifier disagrees with the head) forgets the
group and sends a seat ask addressed to the leaves it last saw. The core
paces it (`recovery_judge`, [Group recovery](mls-core.md#group-recovery)): a
fork or stranded rejoin of one group waits nothing the first time, then 10
minutes, doubling to at most 6 hours; a rejoin after a lost mailbox is not
paced. It keeps the
envelopes it could not open; the reseat hands it the envelope secrets of the
epochs it missed, and each message then becomes a placeholder and a resend
ask to its author by its content hint
([Rejoin with a sealed seat ask](delivery.md#rejoin-with-a-sealed-seat-ask)).

Forgetting a group forgets its MLS state, not the device's history: what it
read stays, and so does every placeholder it held. A rejoin is not a join for
"sent before this device joined". The re-seated leaf keeps its device id, and
an author MUST NOT refuse its ask because it answered that device id for the
same message before the rejoin.

An ask the device sent before it forgot the group MUST NOT count as asked
once the device forgets the group or is re-seated. Each placeholder of that
group the device had asked for goes back to unasked, and the device asks for
it again, without a tap, once the Welcome lands (within the 10 automatic asks
of that drain). The 14 days an ask may stand still run from the message's
arrival (its first ask when its arrival is not known): a re-armed ask past
them is not sent, and the placeholder says it cannot be recovered. A
placeholder the device never asked for keeps waiting for a tap.

Forgetting a copy keeps its roster, and the Welcome that brings the device
back is drawn against it
([A Welcome into a group this device knew](delivery.md#a-welcome-into-a-group-this-device-knew)).

### Blocked accounts

A block is a `contact` record in the person's account store
([Account store](account-store.md)), and only the blocker's devices enforce
it: a blocked person with a session can still fetch the blocker's
KeyPackages, add the blocker to a group and send to the blocker's devices.

- A device MUST identify the sender of anything it opens by the sender's leaf
  credential, never by a payload field.
- A device MUST NOT show a message, reaction, edit or typing indicator from a
  blocked account, and MUST NOT draw a notification for one.
- **A blocked account does not put the blocker in a group.** A device MUST
  answer an unanswered invitation from a blocked account `no` at once,
  whether or not the account is otherwise known, and MUST NOT draw it or
  notify about it. A device seated directly in an ordinary group (no link,
  not a DM, room, community group or event chat) by a blocked account's
  signed Welcome MUST leave it as soon as it reads the tree
  ([Leaving](#leaving), with no leave record, since each of the person's
  devices leaves on its own Welcome), and MUST NOT draw it or notify about
  it, unless this device already drew that group before: a later block, or a
  rejoin's Welcome, never makes it leave.
- **A device MUST NOT send a blocked account anything in answer to it:**
  - no delivered mark for its messages, reactions, edits or deletes, and no
    read mark naming its messages;
  - no typing frame: its devices are left out of every typing frame's
    recipients, and a conversation with no other account left, such as a
    1:1 with it, gets none
    ([Typing inside the group](#typing-inside-the-group));
  - no reply to its call, in any conversation, a request included: the
    device does not ring and sends nothing back, not the `Direct` a ringing
    device sends a caller before anyone answers
    ([Direct 1:1 calls](calls.md#direct-11-calls)), not `busy` and not
    `need_permission`;
  - no answer to its resend ask
    ([Asking for a message again](#asking-for-a-message-again)).
- **Everything else goes as before.** The device's own messages, its
  reactions and its keys (`ak`, `pk`) go into a conversation that seats a
  blocked account exactly as into any other, to every leaf. A block mints a
  new profile key and access key ([Rotation](profiles.md#rotation)), which a
  blocked person who shares a conversation with the blocker still receives
  there, so they can still reach the blocker's devices without a session;
  the devices discard what arrives.
  A mark the device owes somebody else in a group goes to every leaf, the
  blocked account's included.
- Blocking across Peachy, which the person chooses separately, is told to
  the server, which keeps it while it lasts, and is outside this rule
  ([The floor](metadata.md#the-floor)).

## Self-notes

A device writes to its account's other devices with `SendSelfNote`. The
payload is at most 1 MiB. `device_id` empty sends to every own device;
otherwise to one. Notes arrive as `MAILBOX_KIND_SELF_NOTE`. Every note is
signed by the sending device's own Ed25519 key (the one its MLS leaf
carries):

```text
payload = id (16 random bytes) ‖ note
k2(id)  = HKDF-SHA256(ikm = account_key, salt = empty,
                      info = "peachy self note v2" ‖ 0x00 ‖ id, L = 32)
body    = u8(len(sender)) ‖ sender ‖ BE64(issued_at_ms) ‖ json
sig     = Ed25519(sender's device key, "peachy-self-note-v2" ‖ 0x00 ‖ id ‖ body)
note    = 0x02 ‖ nonce (12) ‖ AES-256-GCM(k2(id), nonce, pad(body ‖ sig), aad = id)
pad(p)  = p ‖ 0x80 ‖ 0x00 …   (to a multiple of 256 bytes, always at least one byte added)
```

`sender` is the sending device's device id (1 to 255 bytes). The JSON is at
most 65,463 bytes, less the sender id's length. The signature is inside the
seal, so the server gains no signed statement. The key domain differs from
the account store's, so a note can never be read as a store record or the
reverse. This is `note_seal_signed`, `note_sender` and `note_open_signed` in
`mls/core/src/account_store.rs`; fixture: `mls/fixtures/account-store.json`.
A note of any other version, the unsigned `0x01` included, is refused.

A receiver:

1. Reads the claimed sender (`note_sender`) and looks it up in its own
   account's device list. The device MUST be another of the account's devices,
   not revoked, approved, and certified by the account identity key; otherwise
   the note is dropped.
2. Opens it against that device's signing key (`note_open_signed`), which
   refuses a note issued more than 7 days ago or more than 10 minutes ahead of
   the receiver's clock.
3. Drops a note whose id it has acted on in the last 7 days and 10 minutes
   (the longest a note stays fresh), so a note acts once.
4. Acts on a `transfer` note only while it is waiting for its own hand-off,
   and on a `history` note only when the asking device `d` is the sender.

`mls/fixtures/formats/self-note-trust.json` pins these rules. They trust the
device list; the account's history goes only to a device on the approval
chain
([Handing history to your own new device](#handing-history-to-your-own-new-device)).

A device MUST NOT send a `read` note while its account has no other live
device that could open it: a person's device that is approved, not revoked
and holding the account key, as `ListDevices` last told it. When it cannot
tell, it sends none. A device that arrives later loses nothing, because the
hand-off sets its read position.

| `peachy` | Body | Meaning |
|---|---|---|
| `read` | `{"v":1,"g":conversation id,"m":envelope id,"at":ms}` | The read position moved. Debounced to one per conversation per 2 seconds. Never for a message not yet sent. |
| `receipts` | `{"v":1,"g":…,"rc":{actor:{"r":[frame ids],"d":[frame ids]}},"re":{frame id:[reaction]}}` | Receipt marks for a conversation, to a device just seated in it. At most 16 of each per reader, oldest first. `re` carries the reactions that stand, clears included. |
| `transfer` | `{"v":1,"f":3,"ptr":pointer}` or `{"v":1,"f":3,"none":true}` | A history hand-off, or none to hand off. The pointer's key is sealed to the recipient device (`kb`, [Handing history to your own new device](#handing-history-to-your-own-new-device)). |
| `history` | `{"v":1,"d":device id,"f":held format}` | A device asks a sibling for a hand-off. |
| `calls` | — | Not specified here. A device that does not implement it drops it. |

### Signed notes

Every note is signed (above): anyone who holds the account key could seal an
unsigned note, and nothing in it would say which device sent it or when.

### Handing history to your own new device

The device that approves a new device of the same account uploads a transfer
document as a sealed attachment and sends a `transfer` note to that device
only. The document is JSON:

```json
{"peachy":"transfer","v":1,"f":3,"conversations":[
  {"g":"<conversation id>","read":"<envelope id>","p":["<actor id>"],"q":true,
   "rc":{…},
   "messages":[{"id":"<envelope id>","i":"<frame id>","by":"<actor id>","at":1790000000000,
                "text":"…","r":"","b":false,"a":[pointer, …],"re":[reaction, …]}]}]}
```

- Messages are oldest first. `text` is omitted for a message with
  attachments and no words. A message with neither is dropped.
- `p` lists the members as the approver holds them; `q` is written only when
  the conversation is an unanswered message request. `rc` is always written.
- A **reaction** is `{"by":actor,"e":emoji,"s":mailbox position,"at":ms}`; in
  a `receipts` note `"x":true` takes the place of `e` for a clear. One with no
  reactor, or not exactly one emoji and no clear, is dropped, and a reactor
  repeated on one message keeps the first.
- An attachment whose object the approver could not re-upload goes without
  `o` and `k`, and the new device shows it as not available.
- For a conversation the device did not hold, the importer puts its read
  position at the newest message carried, so everything handed over counts
  as read. `read` is the approver's own position. For a conversation the
  device holds, the importer adds what it lacks and never moves its read
  position.
- Format `f` is 3: 1 is words only, 2 adds attachments and receipts, 3 adds
  reactions. A device that holds an older format MAY ask a sibling
  with a `history` note.

A device hands its history to a sibling that asked, or that its own record
says is due one, only when it can vouch for that sibling.
`check_own_device_key`, run on the sibling's id, signing key,
`approved_by_device_id` and `approval_signature` from the device list, MUST
answer `known` or `approved`: the sibling is on this device's approval chain,
or its approval verifies under a key that is, the evidence the adder checks
([What the adder checks](identity.md#what-the-adder-checks)). The check
records nothing. Any other answer gets the `none` note. Neither the list's
`account_certified` flag (any holder of the account key can certify a row)
nor a leaf in a group's tree is that evidence. The hand-off the approver
sends as it approves skips the check: it has just signed that approval.
`answers` in `mls/fixtures/formats/self-note-trust.json` pins it.

**The document's key, sealed to the device it goes to.** A `transfer` note's
pointer carries `kb` in place of `k`: the document's 32-byte key sealed to
the recipient device's own Ed25519 signing key, as its X25519 point, and
bound to that device's id, so the account key alone does not open it:

```text
R    = the recipient's signing key, as listed for the device id it is sent to
e, E = a fresh X25519 key pair; E = X25519(e, base point)
k    = HKDF-SHA256(ikm = X25519(e, Montgomery(R)), salt = empty,
                   info = "peachy transfer key v1" ‖ 0x00 ‖ E ‖ R ‖ device id (ASCII), L = 32)
kb   = base64(0x01 ‖ E (32) ‖ nonce (12) ‖ AES-256-GCM(k, nonce, key (32), aad = 0x01 ‖ E))
```

The box is 93 bytes. This is `transfer_key_seal` and `transfer_key_open` in
`mls/core/src/account_store.rs`; `mls/fixtures/account-store.json` pins the
opening (`transferKeyOpen`), refusals included. Its key domain is its own, so
an account-key box never opens as a transfer-key box, nor the reverse. The
sender's own key is not in the box: the signed note says who sent it.

- A sender seals to the signing key it has just vouched for: the key the
  approval it signs names, or the listed key on which `check_own_device_key`
  answered `known` or `approved`. It writes no `k` in the note's pointer.
- A reader opens `kb` with its own signing seed and its own device id and
  reads the result as `k`, ignoring any `k` beside it. A `kb` that does not
  open, or a pointer with no `kb`, is nothing to import.

The box is sealed to the signing key, not to the one-pairing link key
([Fetching and opening the account key](identity.md#fetching-and-opening-the-account-key)),
because a sibling answering a later `history` ask never saw that pairing.

Fixture: `mls/fixtures/formats/transfer.json`.

## Sign-out

- **Sign-out** (`SignOut`) MUST NOT delete the device's MLS state or its
  plaintext archive. It closes the MLS client and drops stream cursors. A
  device that signs in again as the same account resumes its seats.
- **A device another device removed** (`RevokeDevice`) MUST erase its archive,
  MLS state, account key and install ids when it next signs in, and register
  as a new device.
- **Deleting the account** MUST close the MLS client first and then delete its
  storage and seed, so no open handle keeps the files alive.
- A device SHOULD reset its read-note debounce on sign-out.

## The preview

Envelope kind 5 carries a group link's preview. It is sealed as version 2,
under the group id, so only someone who knows the group id (a link holder)
can open it. It is published at the conversation's head and is never
placed in a mailbox. Its inner bytes are JSON padded with trailing spaces to
a multiple of 256 bytes:

```json
{"v":1,"n":"<name>","c":<member count>,"ap":<approval required>,"a":{<photo pointer without "x">}}
```

A reader ignores unknown keys and refuses the preview when `v` is not 1, `n`
is not a string, `c` is not a non-negative integer, or `ap` is not a boolean.
A photo pointer that does not read is dropped. A client MUST drop and acknowledge a
kind 5 envelope found in a mailbox. Group links are otherwise out of scope.

## Out of scope

Group links and join inboxes, the call rpcs, and the keys and kinds marked
above as outside this specification are not specified here. They are named only so
a reader can skip them safely. Call signaling is in [Calls](calls.md).

## Golden fixtures

Every format above is pinned by a golden table under `mls/fixtures/formats/`
that the official clients replay, named in each section; the other
`mls/fixtures/` files are replayed through the fixture door
([The fixture door](mls-core.md#the-fixture-door)). [Message formats](formats.md)
says how to read the tables, and which formats have none, for which the prose
above is the specification ([What is not here](formats.md#what-is-not-here)).

## Security considerations

- **Members enforce membership.** The server cannot read the group's policy
  ([Policy](#policy)), except in the store-review login's demo conversations,
  whose other members it runs. Every member's device checks a commit before
  merging it, and a group whose admin list cannot be read has no admin and
  never gains one.
- **A content hint is read before the message is authenticated**
  ([Content hints](#content-hints)). A receiver MUST treat it as a hint.
- **Padding hides length only to a block or bucket**
  ([Size-hiding padding](#size-hiding-padding)).
- **Blocking is enforced on the blocker's devices**
  ([Blocked accounts](#blocked-accounts)). Blocking across Peachy, a
  separate step, is held by the server.
- **Receipts and typing tell co-members when a person reads and types.** That
  is their purpose. The server relays them sealed, so it sees when they are
  sent, not what they say.

## IPR

This document is dedicated to the public domain under CC0 1.0.

## References

- [RFC 2119] "Key words for use in RFCs to Indicate Requirement Levels", BCP 14, RFC 2119, March 1997. <https://www.rfc-editor.org/rfc/rfc2119>
- [RFC 8174] "Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words", BCP 14, RFC 8174, May 2017. <https://www.rfc-editor.org/rfc/rfc8174>
- [RFC 9420] "The Messaging Layer Security (MLS) Protocol", RFC 9420, July 2023. <https://www.rfc-editor.org/rfc/rfc9420>
- [RFC 8032] "Edwards-Curve Digital Signature Algorithm (EdDSA)", RFC 8032, January 2017. <https://www.rfc-editor.org/rfc/rfc8032>
- [RFC 5869] "HMAC-based Extract-and-Expand Key Derivation Function (HKDF)", RFC 5869, May 2010. <https://www.rfc-editor.org/rfc/rfc5869>
- [SP 800-38D] NIST, "Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC", SP 800-38D, November 2007. <https://doi.org/10.6028/NIST.SP.800-38D>
- [FIPS 180-4] NIST, "Secure Hash Standard (SHS)", FIPS 180-4, August 2015. <https://doi.org/10.6028/NIST.FIPS.180-4>
- [RFC 4648] "The Base16, Base32, and Base64 Data Encodings", RFC 4648, October 2006. <https://www.rfc-editor.org/rfc/rfc4648>
- [RFC 8259] "The JavaScript Object Notation (JSON) Data Interchange Format", STD 90, RFC 8259, December 2017. <https://www.rfc-editor.org/rfc/rfc8259>
- [RFC 9562] "Universally Unique IDentifiers (UUIDs)", RFC 9562, May 2024. <https://www.rfc-editor.org/rfc/rfc9562>
