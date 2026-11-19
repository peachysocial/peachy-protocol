<!-- SPDX-License-Identifier: CC0-1.0 -->
# Profiles

**Status:** describes the protocol as implemented by the `peachy-protocol`
0.2.0 release. **Revision:** 1, 2026-11-19. **Editor:** Peachy Social, Inc.

The server keeps a person's name, photo and About you in plaintext, and
shows them where a profile is public
([What stays public](#what-stays-public)). Beside that copy, the person's
device seals the profile (name, About you, photo and cover) under a
**profile key** the server never holds (except for Peachy's own store-review
accounts, whose account store it can read:
[Security considerations](identity.md#security-considerations)), and hands
the key to the people it talks to inside its sealed messages. The server
stores that copy as ciphertext it cannot open, and answers it only to a
caller presenting the person's access key. A device that holds the key draws
the sealed name, so what the person's contacts see of them is what the
person's own device wrote whenever the server serves it.

## Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY" and
"OPTIONAL" in this document are to be interpreted as described in BCP 14
(RFC 2119, RFC 8174) when, and only when, they appear in all capitals, as
shown here.

## Format

- The **profile key** is 32 random bytes, kept in the account store's
  `account` record as `profileKey` (standard, padded base64), so every device
  of the account holds the same one and a linked device receives it with the
  store ([Account store](account-store.md#record-values)).
- **access key** = HKDF-SHA256(ikm = profile key, salt = empty,
  info = `"peachy profile v1 access"`, L = 16). Whoever can open the
  profile can use the sessionless doors, and nobody else.
- **seal key** = HKDF-SHA256(ikm = profile key, salt = empty,
  info = `"peachy profile v1 seal"`, L = 32).
- **sealed profile** = `0x01` ‖ nonce (12 random bytes) ‖ AES-256-GCM(seal key,
  nonce, padded plaintext, AAD = the person's actor id, lowercase, UTF-8),
  tag included, so a sealed profile opens on nobody else's row.
- **plaintext** = UTF-8 JSON `{"n": name, "a"?: about, "p"?: photo, "c"?: cover}`,
  followed by `0x00` bytes up to the smallest of 256, 512, 1,024 or 2,048
  bytes. A plaintext longer than 2,048 bytes MUST NOT be sealed.
- A **photo** (`p`, `c`) is a pointer to a padded sealed attachment under
  `sealed-meta/`, the shape a private group's photo has:
  `{"v": 3, "o": object key, "k": key, "n": nonce prefix, "d": digest, "s": size, "m": type, "cs": chunk size}`.
  It carries an object key and never a URL; a reader composes the URL from
  the media base its own server stated.

A reader MUST treat as no profile at all: a version byte other than `0x01`,
fewer than 29 bytes, a tag that does not verify, bytes that are not UTF-8, or
JSON that is not an object with a string `n`. It cuts `n` to 100 code points
and `a` to 500, reads a missing `a` as empty, and reads a photo that breaks
any rule of the group photo's pointer as no photo. Unknown keys are ignored.

## Sharing the key

A sender puts its profile key in every sealed message it sends, as `pk` beside
`ak` ([Sealed messages](sealed-messages.md)), but only once the server holds
the access key it derives. A receiver keeps a `pk` that is exactly 32 bytes in
the sender's `contact` record as `profileKey`, against the actor of the
credential that signed the message, never against a name inside it, and never
while the sender is blocked. A `contact` record holding only `accessKey` and
`profileKey` is a cache a write at the store's bound may drop.

## Reading a profile

A device asks for the sealed profiles of the people it holds beside their
public rows: each `GetUsers` page carries one `ProfileAsk` per person on it
whose profile key the device holds, presenting the access key that profile key
derives. `GetUsers` takes no session. The server answers a sealed profile only
where the presented key's SHA-256 matches the one it holds, comparing every
ask in constant time, and leaves out a wrong key, an unknown id and a person
with no sealed profile alike. `GetUser`, which is not in the published proto
subset, takes an `access_key` too, and without a session answers the public
row and the sealed profile for a matching key and nothing viewer-relative.
A deleted account's key is not checked: it has no sealed profile, and
`GetUser` answers its tombstone's public row.

A device opens each answer under the profile key it holds now and draws the
sealed name as the person's own name, wherever the public name would be drawn.
The viewer's own label for the person still wins, exactly as it wins over the
public name. A person asked for and not answered (no sealed profile, or a key
that no longer matches) falls back to the public row.

## Writing a profile

After every change to the name, photo or cover, a device seals the whole
profile again and stores it with `SetSealedProfile`, naming the `sealed-meta/`
objects its photos point at so the sweep of unclaimed objects keeps them.
`SetSealedProfile`, `UpdateProfile`, `SetProfileAvatar`, `SetProfileCover`
and `SearchPeople` are not in the published proto subset; this section says
what they do to the sealed profile.

A photo goes up with `CreateUpload` and the session, so the object is
the account's own; the server keeps at most four for a profile, ordered by when a
write last named each, and deletes the oldest past that and every one at the
account's deletion ([Abandon, delete](delivery.md#abandon-delete)).

The pointers and their delete tokens are kept in the `account` record
(`sealedAvatar`, `sealedCover`), so every device seals the same profile, and a
replaced photo is deleted with its token. About you is sealed too (`a`), and
also kept in plaintext, because the server cuts its audiences.

A profile write that carries no sealed profile (`UpdateProfile`,
`SetProfileAvatar`, `SetProfileCover`) makes the server delete the stored
one, which holds the old values.

## Rotation

A device mints a new profile key when its account blocks somebody: it writes
the new key and the access key it derives into the `account` record, tells
the server the new access key, and seals the profile again under the new key.
The people the account still writes to learn the new keys from its next
message, and so does a blocked person who shares a conversation with it. A
blocked person who shares none opens nothing new and no longer opens the
sessionless doors.

A sessionless door refusing an access key marks the `permission_denied` with
the header `peachy-refusal: access-key`. A device holding a key its owner has
replaced MUST then send the same request once more through the identified
door, as it would for somebody whose key it never held. The mark says only
that some presented key was wrong, never whose.

The server sees that an access key changed
([G5](metadata.md#what-the-server-never-holds)).

## What stays public

The handle, the public id, the name and photo in plaintext
(`User.display_name` and the avatar) beside the sealed copy, and, when the
person chooses one, a **public name** (`User.public_name`): an explicit field
for the surfaces that are public by design, such as an event page, never a
copy of the sealed name.

## Handles

A handle's hash is SHA-256 of the UTF-8 of `"peachy username v1:"`
followed by the normalized handle (trimmed, leading `@` removed, lowercase),
kept by the server beside the handle.

`GetUserByHandle` takes only
`handle_hash` (32 bytes) and matches it exactly. A hash of any other length
answers what an unknown handle answers. `SearchPeople` takes the text the
person types.

## Security considerations

- **The sealed profile is about integrity, not secrecy from the server.** The
  server keeps the name, photo and About you in plaintext too
  ([What stays public](#what-stays-public)).
- **The profile key is the access key** ([Format](#format)): whoever holds it
  can reach the person on the sessionless doors.
- **A handle's hash is not secret.** Handles are short and public, so anybody
  can hash a guess; the hash only keeps the lookup exact
  ([Handles](#handles)).

## IPR

This document is dedicated to the public domain under CC0 1.0.
