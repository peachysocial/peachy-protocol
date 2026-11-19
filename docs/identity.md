<!-- SPDX-License-Identifier: CC0-1.0 -->
# Device identity

**Status:** describes the protocol as implemented by the `peachy-protocol`
0.2.0 release. **Revision:** 1, 2026-11-19. **Editor:** Peachy Social, Inc.

This document specifies who a Peachy client is: how a person signs in, how
each install registers a device key, the server-signed `pdc1` credential an
MLS leaf carries, and the account identity key that lets a person's own
devices, and never the server, decide which devices belong to them. It covers
letting a new device in, the MLS leaf rules every member enforces, and the
security code two people compare. The encrypted settings that the same
account key unlocks are specified in [Account store](account-store.md).


## Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY" and
"OPTIONAL" in this document are to be interpreted as described in BCP 14
(RFC 2119, RFC 8174) when, and only when, they appear in all capitals, as
shown here.

## Accounts, sessions and devices

Peachy keeps three things apart. A client MUST NOT use one in place of another.

| Thing | What it is | Created by | Ended by |
|---|---|---|---|
| Account | One person. Its key is the **actor id**, a UUID (`User.id`). The actor id is never shown to people. | `VerifyPhone` on a new phone number | Not in the published rpc set |
| Session | One login: an opaque bearer token. | `VerifyPhone` | `SignOut`, `RevokeSession`, `RevokeDevice`, `ClaimSoleDevice`, a PIN restore, [Idle linked devices](#idle-linked-devices) |
| Device | One install's Ed25519 key pair. The private half never leaves the install. | `RegisterDevice` | `RevokeDevice`, `ClaimSoleDevice`, a PIN restore, [Idle linked devices](#idle-linked-devices) |

Four keys are involved:

| Key | Size | Who holds it | Purpose |
|---|---|---|---|
| Device signing key | Ed25519, 32-byte seed | One install | Signs the device's MLS leaf, approvals and the two-digit exchange. |
| Account key | 32 random bytes | Every approved device of the account; for a person who sets a PIN, the PIN vault, sealed under a key derived from the PIN | Unlocks the [account store](account-store.md) and derives the account identity key. The server never holds it, except for Peachy's own store-review accounts ([Security considerations](#security-considerations)). |
| Account identity key | Ed25519, derived from the account key | Every approved device of the account; the vault's copy of the account key derives it | Certifies each device of the account. Its public half is what the security code is computed from. |
| Server credential key | Ed25519 | The Peachy server | Signs `pdc1` credentials. Its public half is published. |

## Signing in

Sign-in is by phone number and a one-time code.

1. `StartPhoneVerification { phone }` sends a code by SMS. `phone` is E.164.
   The server canonicalizes it and returns the number the code went to in
   `StartPhoneVerificationResponse.phone`. A client MUST show and send back
   that canonical number.
2. `VerifyPhone { phone, code }` checks the code.
   - A valid code for an existing account returns `session_token` and `user`.
   - A valid code for a number with no account returns
     `needs_display_name = true` and no token. The client resends with
     `display_name` set to create the account. The code stays valid until it
     expires.
   - A wrong code is `permission_denied`. Too many attempts or too many codes
     are `resource_exhausted`.
   - `registration_lock` is set when the account's registration lock is on
     and has not lapsed. No session is minted, and the code is spent; the
     sign-in finishes with [UnlockRegistration](#unlockregistration).

Every other rpc carries the token as an HTTP header:

```
authorization: Bearer <session_token>
```

The token is opaque. A client MUST store it only on the device that received
it, and MUST NOT log it or send it anywhere else. A missing, unknown or ended
session is `unauthenticated`.

`ListSessions` lists the account's logins. `RevokeSession { session_id }` ends
one. `SignOut` ends the caller's own. Ending a session does not revoke any
device key.

### UnlockRegistration

The registration lock is a switch a certified device turns on, with a PIN.
While it stands, a sign-in must also prove it holds the account key, which
the person's PIN recovers from a PIN vault. Setting the PIN, the vault and
unlocking are not specified here: their rpcs are not in the published
proto, and `RegistrationLockChallenge` carries only:

| Field | Meaning |
|---|---|
| `ticket` | Stands in for the spent code for 30 minutes. A new challenge for the account deletes every older ticket. |
| `time_remaining_ms` | How long until the lock lapses on its own (below). |

A person whose lock stands signs in on an official app, or waits for the
lock to lapse. A login that unlocks the lock is marked as a PIN restore, so
a certified registration that follows signs the account's other devices
out, unless a relaunch or an approval admits it first
([Who may certify](#who-may-certify), PIN restore).

**The lapse.** The lock lapses seven days after the account was last active:
the server keeps a UTC day on the lock, moved forward by any session's first
authenticated call of a day, by a new session and by setting the PIN, never by
signing out or removing devices. The count runs from the start of that UTC
day, so the lock can lapse a little over six days after the last call. Once
lapsed, the next `VerifyPhone` switches the lock off and mints a session; the
PIN and its vault backup stay, and only the PIN opens them.

## Registering a device

### One install, two rows

Every signed-in install registers two device rows:

| Row | `mls` | Key | Use |
|---|---|---|---|
| Plain row | `false` | The install's device key. A browser SHOULD keep it as a non-extractable WebCrypto key. | Lists the install on the Devices screen. |
| MLS row | `true` | The install's MLS seed (raw Ed25519 seed). | Holds the MLS leaf in every sealed conversation. |

The MLS row names the plain row in `twin_of`. The server links the two only
when `twin_of` names a live plain row still linked to the caller's login, on
the same platform, that no live MLS row of another login names; otherwise it
ignores the claim and still registers the row. An empty `twin_of` never
erases a link already on record.
Revoking either row of a linked pair revokes both. A client showing devices
to a person SHOULD show one entry per install: drop an MLS row whose
`twin_of` is on the same list.

`Device.current` is always `false`: a bearer token names a login, not an
install. A client finds its own rows by its plain install id and by the
device id `RegisterDevice` returned for its MLS row. `ListDevices` and
`ApproveDevice` send `install_id` and `session_id` only for rows registered
under the caller's own login, and empty for every other row, so a client MUST
NOT match on an empty install id.

### RegisterDevice

`RegisterDevice` requires a session. It is idempotent on (account,
`install_id`): an app that registers on every launch updates one row.

| Field | Rule |
|---|---|
| `install_id` | 1 to 128 characters after trimming. Client-generated, stable for the life of one install. |
| `platform` | `ios`, `mac`, `android` or `web`. Anything else is `invalid_argument`. |
| `signing_key` | The raw 32-byte Ed25519 public key. |
| `twin_of` | See [One install, two rows](#one-install-two-rows). |
| `account_identity_key`, `account_signature` | 32 and 64 bytes, both or neither. See [The account identity key](#the-account-identity-key). |
| `mls` | `true` on the MLS row only. |
| `key_proof` | 64 bytes or empty. See [Taking over a row](#taking-over-a-row). A client SHOULD send it on every registration. |

The response carries:

| Field | Meaning |
|---|---|
| `device` | The row. |
| `credential` | The `pdc1` credential for this key, as ASCII bytes. See [The credential](#the-credential). Never empty. |
| `account_identity_key` | The account identity key the server has pinned for this account, or empty when none is pinned. |
| `became_sole_device` | This registration made this device the account's only one. A client that holds no account key then does what it does after [ClaimSoleDevice](#claimsoledevice). A client that holds one MUST ignore it: the server sets it only for a registration without an account signature, and acting on it would drop the key and its store floor on the server's word ([Account store](account-store.md#a-device-without-the-key)). |

Server behavior:

- A new `signing_key` for a known `install_id` rotates the key in place. The
  device id stays the same. The old credential is withdrawn, and any account
  signature on the row is dropped until the device certifies the new key.
  See [Taking over a row](#taking-over-a-row).
- Every registration links the caller's login to the row. A linked login acts
  as that device (its mailbox and key packages), and, when the row carries an
  account signature, for the account ([RevokeDevice](#revokedevice)). A
  registration that changes the key, or carries a valid `key_proof`, unlinks
  every other login from the row.
- When the server holds no credential signing key, the call fails with
  `failed_precondition`.
- A bad account signature, or wrong sizes, is `invalid_argument`. An account
  identity key different from the pinned one is `failed_precondition`: the
  device holds a stale account key. The client MUST NOT drop the key or its
  store on that answer. It registers without the signature, so the row
  becomes `pending`, and waits to be let in: if the account really started
  over, the new key arrives in a box.
- An MLS row registering **without** an account signature, on an account that
  already has a pinned identity key, becomes `pending`. See
  [Letting a new device in](#letting-a-new-device-in).
- An account signature on an account whose identity key is already pinned
  is admitted only under [Who may certify](#who-may-certify).

**Which platform to send.** `ios`, `mac` and `android` turn on the
[copied-install rule](#a-copied-install). Any other client MUST send one of
the four values, and SHOULD send `web` unless it implements that rule.
`GetMinSupportedVersion` answers for Peachy's own apps; another client SHOULD
NOT act on it.

### Taking over a row

An install id is a selector, not a secret, and a device's public key is
public. A login that is not yet linked to the install's live row (for
example the same install signing in again after a sign-out) proves it holds
the row's key with a `key_proof`: the 64-byte Ed25519 signature, by the key
the row holds, over

```
"peachy-device-key-proof-v1" || 0x00 || install_id (UTF-8) || 0x00
  || signing_key (32 bytes) || 0x00 || SHA-256(bearer token) (32 bytes)
```

`signing_key` is the key in the request, and the bearer token is the one the
request carries, so a proof belongs to one login. The install's own login
(one still linked to the row) needs no proof, a re-key included.
Any other login without a valid proof is refused with `permission_denied`,
and the client starts over as a new device, as for
[A removed install](#a-removed-install).

Test vector: the Ed25519 seed `0102…1f20` (the bytes 1 to 32), install id
`3f0c2a9e-7b41-4d5e-9a80-1c2d3e4f5a6b` and bearer token
`pst_example-bearer-token-0123456789` give the public key
`79b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664` and the
deterministic (RFC 8032) proof
`c35e6f48702cc464c7e1d1cd9b21181c473ff7b331df0f40bff691aa206158d7c01b15e17ebbe199e3f0c1a5d5425a309a9da42f1329aadde4af2d29a5204109`.

### A removed install

The server never brings a revoked row back.

- If the caller's login belongs to the removed install, or is older than the
  removal, `RegisterDevice` is `unauthenticated`: the login has ended.
- If the login was minted after the removal, it is `permission_denied`. The
  client MUST then start over as a new device: erase the account key first,
  then its sealed state and both install ids, then register again with new
  install ids.

### A copied install

An install copied to new hardware by a backup or a device transfer MUST NOT
reuse the original's keys, ids or session. On a native platform, the server
treats an MLS registration as a copy when its `twin_of` names a live plain
row that already has an older live MLS row from another install with another
key. If the request sets `starts_over_if_copied`, or the copy's own row is
already revoked, the server revokes the copy's row and answers
`already_exists`; the original keeps working. The client MUST then start over
at sign-in as a new device, and a client MUST send
`starts_over_if_copied = true`. See also [The key stores](#the-key-stores).

## The credential

The server signs one short statement per device, binding the account's actor
id to the device id and its public key. A member checks it **offline**
against a published server key.

### Format

```
pdc1.<base64url(payload JSON)>.<base64url(64-byte Ed25519 signature)>
```

- The three segments are separated by `.`, and both are base64url without
  padding.
- The whole token is at most 8,192 bytes.
- The signed bytes are the **decoded middle segment exactly as it arrived**.
  A verifier MUST NOT re-serialize the payload before checking the signature.
- **One spelling.** The token MUST be the canonical encoding of its fields:
  the payload JSON as described below, with no whitespace, no escapes and
  integers in plain decimal; the key fields in padded standard base64; both
  segments unpadded. A verifier rebuilds the token from the fields it read
  and refuses one that differs by a byte as `malformed`, so a credential's
  length is a function of its fields.
- The prefix `pdc1` is the version. There is no header and no algorithm
  field: the algorithm is Ed25519, always.

The payload is a JSON object with exactly these keys, written by the issuer
in this order with no whitespace. A verifier MUST refuse an unknown key.

| Key | Type | Meaning |
|---|---|---|
| `v` | integer | `1`. Any other value is `unsupported_version`, checked before the other keys are read. |
| `kid` | string | The issuing server key: the first 8 lowercase hex characters of SHA-256 over its raw 32-byte public key. Any other shape is `malformed`. |
| `actor_id` | string | The account. An [id](#ids). |
| `device_id` | string | The MLS device row. An [id](#ids). |
| `device_key` | string | Standard base64 (padded) of the device's 32-byte Ed25519 public key. |
| `account_key` | string | Standard base64 (padded) of the 32-byte account identity public key, or `""`. |
| `account_sig` | string | Standard base64 (padded) of the 64-byte account signature, or `""`. Empty exactly when `account_key` is empty; one empty and one set is `malformed`. |
| `iat` | integer | Issued at, unix seconds: the UTC midnight at or before issue. |
| `exp` | integer | Expires, unix seconds: the UTC midnight at or after issue plus 30 days. |

So `exp - iat` is between 30 and 31 days. The issuer gives a device at most
one new credential per UTC day: a second registration on the same day, with
the same key and account signature, returns the same token.

In MLS the token is the `identity` of a `BasicCredential`. The leaf's
signature key is the raw 32-byte `device_key`. Any other credential type is
`wrong_credential_type`. The ciphersuite is `PEACHY_CIPHERSUITE` in
`mls/core/src/group.rs`.

The fixture `mls/fixtures/credentials.json` pins the encoding, every check
below and every rejection, with fixed seeds.

### Ids

An actor id or device id is 1 to 64 bytes, each one of `A-Z`, `a-z`, `0-9`,
`.`, `_` or `-`. Peachy's server issues only lowercase UUIDs and refuses to
sign a credential naming anything else. A verifier MUST refuse any other id
as `malformed`, and the core refuses one as an argument wherever a client
names a device to it (`is_valid_id` in `mls/core/src/credential.rs`). An id
never carries a separator such as a newline or the `#` of the
[new-device notice](#what-the-adder-checks)'s long form. Lists of ids cross
the native boundary length-prefixed, never joined by a character
([The C ABI contract](mls-core.md#the-c-abi-contract)).

### Verifying a credential

A verifier runs these checks in this order and stops at the first failure.

| Step | Check | Rejection |
|---|---|---|
| 1 | The prefix is `pdc1`, three segments, valid base64, JSON whose `v` reads as an integer | `malformed` (1) |
| 2 | `v` is 1; then known keys only, a `kid` of 8 lowercase hex characters, both [ids](#ids) well-formed and the [one spelling](#format), else `malformed` (1) | `unsupported_version` (7) |
| 3 | `kid` is in the trusted key set | `unknown_kid` (2) |
| 4 | Ed25519 `verify_strict` of the signature over the signed bytes | `bad_signature` (3) |
| 5 | Not past `exp` plus the allowed grace (see below) | `expired` (4) |
| 6 | Not before `iat`: `now + 60 < iat` is refused. Skipped where noted below. | `not_yet_valid` (5) |
| 7 | `iat <= exp` and `exp - iat <= 31 days` | `implausible_lifetime` (10) |
| 8 | The MLS leaf's signature key equals `device_key` | `leaf_key_mismatch` (6) |
| 9 | If `account_key` is set: the account signature verifies | `account_signature` (11) |
| 10 | Wherever a peer's leaf is believed: `account_key` is set | `not_approved` (12) |

The number in parentheses is the stable code of `CredentialRejection` in
`mls/core/src/error.rs`. Code 9 is unused.

"Expired" has two levels. A credential is **lapsed** once `now >= exp`. It is
refused only once `now >= exp + grace`. The grace is 0 for a key package and
for a device's own fresh credential, and 56 days for a leaf already in a group
(see [Refreshing a seated leaf](#refreshing-a-seated-leaf)).

A device's own client accepts its own uncertified credential, so a device
waiting to be let in can still run. Every door through which a peer's leaf
arrives (a fetched key package, an Add, a Welcome, a received commit) refuses
a credential without the account certificate.

The server writes `account_key` into the device's own credential too, so a
device that holds the account key MUST NOT take it as given. Whenever it
opens a client on its own credential, and before it installs a new one (the
answer to `RegisterDevice`, a renewal), it MUST refuse, as
`not_own_account_key` (13), a credential whose `account_key` is set and is
not the identity key it derives from the account key it holds, and keep the
credential it had. A device holding no account key MUST refuse any certified
credential, as `not_own_account_key`, and runs uncertified until it holds the
key; a device that kept its signing key but lost the account key is let in
again like a new device.

### The trusted server keys

The server publishes its credential keys at an unauthenticated endpoint. It
is part of the protocol even though it is not an rpc in `proto/`: every
client MUST fetch it before it can verify any credential.

```
GET https://api.pchy.app/healthz/device-credential-keys
```

The answer is `200` with a JSON body, for any caller, with no session:

```json
{"enabled":true,"keys":[{"kid":"1a2b3c4d","publicKey":"<base64 of 32 bytes>","current":true,"use":"device"}]}
```

| Field | Meaning |
|---|---|
| `enabled` | `false` when the server holds no signing key. |
| `kid` | The key's id, as in the payload. |
| `publicKey` | Standard base64 of the raw 32-byte Ed25519 public key. |
| `current` | The key new credentials are signed with. |
| `use` | `device`. A key with no `use` is a device key. A verifier MUST drop a key of any other `use`. |

A client fetches it each time it opens its core and hands it, narrowed to
the keys its build carries (`server_keys_pinned_json`, below), to
`Client::new` (`peachy_mls_client_open`'s `trusted_keys_json`); the set is
fixed for that open. A client that hands over the list as fetched trusts any
key the server adds. `TrustedServerKeys::from_published_json` in `mls/core/src/identity.rs`
reads it as-is. A verifier looks keys up by `kid`; it does not recompute the
`kid`. On `unknown_kid` a client SHOULD fetch the list again once and, if it
changed, reopen its core with it; no door replaces the set in a running
client.

Every client build carries the keys, current and retired, for the production
server (`mls/core/pinned-server-keys.json`, compiled into the core). The core
trusts exactly the list a client hands `Client::new`; a client MUST hand it
`server_keys_pinned_json`'s output, the published keys it carries
(`mls/core/src/server_key_pins.rs`), so a key the server adds vouches for
nothing until a build carries it. `server_keys_pinned_json` returns the
published list narrowed to the carried keys, in the same shape;
`server_key_pin_report` returns the difference as one log line, empty on a
match, which a client writes to its own device log and nowhere else. The
file records each newer key's first carrying release per platform, and the
production server refuses to start while it publishes a key that the
minimum supported build of each platform does not carry. A key without
`carriedFrom` counts as carried by no release, except `8730c349`, the first
key, which every build carries. The production set may
also carry a standby key, published only if the current key is compromised.

The core holds two sets: `production`, for `api.pchy.app`, and
`development`, for local test servers, whose signing seed is public in the
tests and so vouches for nothing. A shipped build carries only `production`:
the `development` set is empty unless the core is built with the
`development-keys` feature ([Core features](mls-core.md#core-features)). A
client picks the set from the host it is built for, never from anything a
server says.

The account certificate, which the server cannot make under an identity key
it does not hold, is what keeps a stranger's device out of an account a peer
already knows.

### Rotating the server key

The server rotates its credential key by making a new key current and keeping
the old public key published, with `current: false`, for at least 31 days,
after which no valid credential names the old key and it is dropped. A new
key goes into `mls/core/pinned-server-keys.json`, and builds that carry it
reach installs, before it becomes current. No answer from the server adds a
key to what a build carries.

- A verifier MUST trust every published `device` key, current or not, that
  its build also carries with the same bytes.
- Rotation is not revocation. To withdraw one credential, revoke its device.
- A leaf whose `kid` is no longer published reads as unidentified. It is
  removed, never replaced. See [What the adder checks](#what-the-adder-checks).
  It still counts as its person when a Welcome replaces the copy that holds
  it: a Welcome that leaves it out draws that person as gone
  ([A Welcome into a group this device knew](delivery.md#a-welcome-into-a-group-this-device-knew)).

## The account identity key

Each account has one Ed25519 identity key. Every holder of the account key
derives it, so no second secret exists:

```
seed = HKDF-SHA256(ikm = account_key (32 bytes), salt = empty,
                   info = "peachy account identity v1", L = 32)
identity key = Ed25519 key pair from seed
```

It signs one statement per device, the **account certificate**:

```
"peachy-account-device-v1" || 0x00 || device_signing_key (32 bytes)
```

The signature is 64 bytes. Verifiers MUST use Ed25519 `verify_strict`.
`account_identity_public_key` and `verify_account_device` in
`mls/core/src/account_identity.rs` implement it; `mls/fixtures/device-link.json`
pins it.

A device that holds the account key certifies itself: it sends
`account_identity_key` and `account_signature` in `RegisterDevice` for its MLS
row. The server:

1. verifies the signature, and refuses a bad one with `invalid_argument`;
2. pins the first identity key it sees for the account, and refuses any other
   with `failed_precondition`;
3. admits it ([Who may certify](#who-may-certify));
4. sets `Device.account_certified`;
5. copies both values into the credential as `account_key` and `account_sig`.

The device MUST check the credential it gets back against the key it sent,
before installing it ([Verifying a credential](#verifying-a-credential)).

### Who may certify

A certificate alone does not decide who joins. On an account
whose identity key is already pinned, the server admits a certificate only
when one of these holds:

- **Relaunch.** The same install, under the same signing key, is already
  certified.
- **Approved.** An approval ([ApproveDevice](#approvedevice)) exists for this
  row, made at most 7 days ago by a device of the account that is not
  revoked, is approved and is certified, and it verifies under that device's
  key over this row's id and this signing key.
- **Only device.** No other install of the account is live, approved and
  certified.
- **PIN restore.** The account has a PIN, and in the last hour this same
  login, holding no certified device, asked the PIN vault for a restore or
  unlocked the registration lock. The server first signs out every other
  install and session of the account (revoked as by
  [RevokeDevice](#revokedevice), their approvals voided), which leaves this
  install the only device. The identity key does not change. A restore signs
  out once: the login's mark is spent. It is read only when neither Relaunch
  nor Approved admits the certificate.

A certificate that none of these admits is dropped, not refused: the row
registers uncertified and becomes `pending`. A client MUST be ready for that:
a device that holds the account key and finds itself `pending` and not
`account_certified` waits to be let in like any new device.
[RevokeDevice](#revokedevice) deletes every approval the revoked install made
for a device that has not certified yet, and that device becomes `pending`
again.

The server's pin is a convenience; the protection is that the server cannot
forge a signature under an identity key it does not hold. A peer pins the key
on first sight and warns when a later one differs
([Security code changed](#security-code-changed)).

A device MUST NOT publish key packages or found a group until its credential
carries the account certificate. After a device first certifies itself, its
client MUST install the new credential before it publishes key packages. A
device that holds the key but was handed an uncertified credential publishes
no key packages and founds no group until it is certified again; meanwhile it
judges only the second half of the rule in
[One account key per person](#one-account-key-per-person).

### The first device

The first device of an account finds no box and no pinned identity key. It
mints a fresh 32-byte account key, keeps it, certifies itself with it, and
only then writes the account store's first manifest (see
[Account store](account-store.md#a-device-without-the-key)): the store serves
only a certified device. A device MUST NOT mint an account key when
`RegisterDeviceResponse.account_identity_key` is non-empty. If its
certificate is refused with `failed_precondition` (another device minted and
certified first), it drops the key it minted, which sealed nothing, and waits
to be let in.

## Letting a new device in

A device joins an account only from a device the account already has. The
approving device checks the new device's key through the person, signs an
approval, and seals the account key to it. The new device then certifies
itself.

### Pending devices

An MLS row that registers without an account signature, on an account with a
pinned identity key, has `approval_state = "pending"`. The account's other
devices see it in `ListDevices`.

| `approval_state` | Meaning |
|---|---|
| `approved` | Not asking. This is the prompt's state, not the seat. The seat is `account_certified`. |
| `pending` | Asking to be let in. `approval_requested_at` is set. |
| `expired` | Was pending, and has not asked for 7 days or its login has ended. Computed, never stored. |
| `denied` | Revoked while pending. It cannot be approved later. |

A device can approve when it is not revoked, is `approved`, and is
`account_certified`. Rows whose `platform` is not one of the four listed
values MUST be ignored.

### The QR code

Devices are approved by number only ([The two-digit number](#the-two-digit-number)).
`mls/core` defines a device-link QR text, which this specification reserves
and no client uses:

```
"peachy-link:" || device_id || "/" || lowercase hex(signing_key) || "/" || lowercase hex(link_secret)
```

`device_link_qr` and `device_link_qr_secret` in `mls/core/src/device_link.rs`
implement it, and `mls/fixtures/device-link.json` pins it.

### The two-digit number

The two devices derive a two-digit number from a commit-then-reveal exchange
the server relays but cannot steer. It is the only way a device is approved.

1. The approver draws a 32-byte nonce `nA` and posts only its commitment,
   signed for the waiting device:

   ```
   C = SHA-256("peachy-device-link-commit-v1" || 0x00 || nA)
   S = Ed25519 signature by the approver's device key over
       "peachy-device-link-commit-v2" || 0x00 || device_id (ASCII) || 0x00 ||
       new_device_key || C
   ```

   `device_id` and `new_device_key` are the waiting row's, as the approver
   read them when it drew `nA`. An approver MUST sign its commitment.

2. The waiting device, having seen `C`, draws and posts its own 32-byte nonce
   `nN`. It MUST answer only an exchange from a device that is `approved`,
   not revoked and `account_certified`, and whose `S` verifies (strict
   Ed25519) under that device's listed key over the waiting device's OWN id
   and its OWN public key as it holds them, never as its row lists them. Any
   other exchange, one with no `S` included, is not answered and does not end
   the pairing.

   With `nN` it posts its link key `L` and a signature `T` over it (see
   [The link key](#the-link-key)).
3. The approver, having seen `nN`, reveals `nA`. The waiting device MUST
   refuse an `nA` that does not open `C`.
4. Both compute:

   ```
   h = SHA-256("peachy-device-link-v2" || 0x00 || new_device_key || approver_key || C || nN || nA)
   number = (first 8 bytes of h, as a big-endian u64) mod 100
   ```

   shown as two digits, zero-padded. All five inputs are 32 bytes. The two
   keys MUST differ.

The waiting device shows the number. The approving device offers it among two
decoys drawn from a CSPRNG, all three distinct. **Tapping the right one is the
approval.** The approving device MAY first ask the person whether the sign-in
is theirs, but that answer approves nothing. A wrong tap MUST close approval
for that device on that approving device until the app restarts.

Beside the three numbers the approving device MUST offer "None of these",
which is what a substituted key, or a pairing bound to another approver,
looks like. It MUST approve nothing and MUST be treated exactly as a wrong
tap. The approving device SHOULD then tell the person not to approve the
device, and that a new attempt starts with a restart on both devices.

The approving device MUST approve (sign and seal the account key to) only the
waiting device's key it derived the number over. If the row carries a
different key by the time the right number is tapped, the tap approves
nothing and closes approval like a wrong one.

A server in the middle learns the waiting device's number as soon as it
posts `nN`, and an approver's `nA` once revealed; the two rules below keep it
to one try per pairing.

**One exchange per pairing.** A pairing begins when the waiting device starts
waiting (a sign-in, a launch, or Start again). The waiting device MUST post at
most one `nN` per pairing:

1. The first exchange it answers BINDS the pairing to that approver's device
   id, that approver's public key as listed at that moment, and that
   commitment `C`.
2. An exchange from the bound approver with the same key and the same `C`
   continues the pairing. If its `device_nonce` is empty, the device posts the
   SAME `nN` again, never a fresh one.
3. An exchange from the bound approver with a different `C`, or the bound
   approver listed under a different key, ENDS the pairing. The device MUST
   show no number, MUST say the pairing was interrupted, and MUST NOT answer
   again until the person starts a new pairing by hand.
4. An exchange from any other approver is never answered.
5. The number is computed over the BOUND approver key, never one read after
   the reveal.

A relaunch or reload of the waiting client is a new pairing.

**One commitment per prompt.** When the approving device first shows the
question for a waiting device, it fixes `nA`, `C`, `S` and the waiting
device's key as listed at that moment, and stores them BEFORE posting `C`.
Each read of the exchange then takes one step, decided in this order:

1. The row lists another key for the waiting device: **interrupted**.
2. The row lists another commitment: with no `nN` fixed yet, post the same
   `C` and `S` again (never fresh ones); with an `nN` fixed, **interrupted**.
3. The row lists an `nA` that does not open `C`: **interrupted**.
4. No `nN` fixed yet: a listed `nA` (a reveal this device never made over a
   fixed `nN`) is **interrupted**; a listed 32-byte `nN` is FIXED, and only
   then is `nA` posted; otherwise wait.
5. An `nN` fixed: a listed `nN` that differs is **interrupted**; with `nA`
   listed, show the number; otherwise post `nA` again.

A reveal whose post fails is retried only over exactly the inputs it was first
sent over. The number is computed over the fixed key and the fixed `nN`, never
over values read later, and MAY be shown as soon as the reveal's post
succeeds. **Interrupted** MUST show no number and MUST close approval for that
device on that approving device exactly as "None of these" does, until the
person starts again on the approving device (a relaunch or reload). A new
commitment is drawn only then: one per prompt the person opened, drawn when
they tap Approve and the number step opens.

**The approver's number.** After an approval by number the approving device
shows a second number over the same exchange:

```
SHA-256("peachy-device-link-approver-v1" || 0x00 || new device key ||
        approver key || C || nN || nA), first 8 bytes big-endian, mod 100
```

The waiting device computes it over the bound approver key and offers it among
two decoys and "None of these". The right pick confirms that approver key; a
wrong pick, or None, ends the pairing without confirming anything. The waiting
device MUST keep the revealed numbers itself, because the server deletes the
exchange on approval.

`device_link_commitment`, `device_link_number`, `device_link_approver_number`,
`sign_device_link_commitment`, `verify_device_link_commitment`,
`device_link_waiter_step` and `device_link_approver_step` in
`mls/core/src/device_link.rs` implement it; `mls/fixtures/device-link.json`
pins the domains and cases (`signCommitment`, `verifyCommitment`, `waiterStep`,
`approverStep`).

#### The link key

The waiting device posts a post-quantum key with `nN`, and the approver seals
the account key to it. The waiting device draws a 32-byte seed for each
pairing, kept until its account key opens or the pairing ends, and derives an
X-Wing key pair from it (`DeriveKeyPair` of HPKE KEM X-Wing, draft 6). With
`nN` it posts the 1216-byte public key `L` and:

```
T = Ed25519 signature by the waiting device's own device key over
    "peachy-device-link-kem-v1" || 0x00 || device_id (ASCII) || 0x00 ||
    C || nN || L
```

A retry of `nN` posts the same `L`. The approver MUST take `L` only when it
fixes `nN` before revealing (step 3), and only when `T` verifies (strict
Ed25519) under the waiting device key the prompt was opened over, with the
commitment it posted and that `nN`. An `L` listed later is never taken. With
no `L` taken, the approver seals no box, and the link fails.

`generate_device_link_kem_seed`, `device_link_kem_public_key`,
`sign_device_link_kem` and `verify_device_link_kem` in
`mls/core/src/device_link.rs` implement it; `mls/fixtures/device-link.json`
pins them (`linkKey`, `signLinkKey`, `verifyLinkKey`).

#### StepDeviceLink

`StepDeviceLink { device_id, approver_device_id, step,
approver_commitment_signature, device_link_key, device_link_key_signature }`
carries one step. `step` is exactly one of `approver_commitment`,
`device_nonce` or `approver_nonce`, each exactly 32 bytes.
`approver_commitment_signature` is `S`: with `approver_commitment` it is empty
or exactly 64 bytes, is stored with the commitment and replaced with it; with
any other step it is ignored. `device_link_key` and
`device_link_key_signature` are `L` (1216 bytes) and `T` (64 bytes): with
`device_nonce` both or neither, stored with the nonce, replaced with it and
cleared with it; with any other step they are ignored. The server verifies
neither signature. `DeviceLinkExchange.approver_signature`, `device_link_key`
and `device_link_key_signature` relay them.

| Step | Sent by | Accepted when | Effect |
|---|---|---|---|
| `approver_commitment` | Approver | Always | Starts or restarts the exchange and clears both nonces and the link key. The same commitment again changes nothing. |
| `device_nonce` | Waiting device | A commitment exists and `approver_nonce` is empty | Sets or replaces `device_nonce` and the link key with its signature. |
| `approver_nonce` | Approver | `device_nonce` is set and `approver_nonce` is empty | Sets `approver_nonce`, once. |

Each step is accepted only from a session that its sender registered under:
the approver's steps from the approver's, the nonce from the waiting device's.

| Refusal | Code |
|---|---|
| Same id twice, no step, wrong length (of a step, a signature or the link key), a link key without its signature or one without the other | `invalid_argument` |
| Either device is not the caller's | `not_found` |
| The sender is another device of the account, or revoked | `permission_denied` |
| Approver revoked or not certified; subject not pending; a step out of order | `failed_precondition` |

Each device reads the exchange from `ListDevices`: a pending row carries one
`DeviceLinkExchange` per approver in `Device.link_exchanges`. The server
deletes the exchange when the device is approved. The server does not refuse
a restart.

### ApproveDevice

`ApproveDeviceRequest`:

| Field | Value |
|---|---|
| `device_id` | The pending device. |
| `approver_device_id` | The caller's own approving device. |
| `signature` | The approval signature, below. |
| `account_key_box` | The account key sealed to the pending device: a version-3 box (1213 bytes). The server also accepts a 93-byte version-1 box, and refuses any other size or none. |
| `signed_out_box` | The approver's signed-out list, `{"v":1,"keys":[…]}` (at most 64 lowercase-hex keys), sealed under the account key to the pending device's id ([Key derivation domains](account-store.md#key-derivation-domains)); returned by `FetchAccountKey`. Optional, at most 8 KiB. |

The approval signature is made with the approver's device signing key over:

```
"peachy-device-approval-v1" || 0x00 || device_id (ASCII) || 0x00 || signing_key (32 bytes)
```

`device_id` and `signing_key` are the pending row's. `sign_device_approval`
and `verify_device_approval` in `mls/core/src/device_link.rs` implement it.

| Refusal | Code |
|---|---|
| Same id twice; box neither 93 nor 1213 bytes; bad signature | `invalid_argument` |
| Either device is not the caller's | `not_found` |
| The calling login is not the approver's; approver revoked | `permission_denied` |
| Approver not certified; subject revoked or not pending | `failed_precondition` |

`ApproveDevice` is accepted only from a session the approver registered
under, as with the approver's steps of [StepDeviceLink](#stepdevicelink): the
approver row must be linked to the calling login by registering under it
([Taking over a row](#taking-over-a-row)). This keeps another login of the
account, which is not sent the approver's install id, from replaying an
approval signature it has seen (`ListDevices` returns them) with a box of its
choosing. A client
sends `ApproveDevice` from the approving install, naming the MLS row it
registered under the login it calls with.

On success the row becomes `approved`, and `approved_by_device_id` names the
approver. The approval seats nothing by itself: the new device must open the
box and certify itself. It is what the server admits that certificate on
([Who may certify](#who-may-certify)), and what the person's other devices
check before they seat the new one ([What the adder checks](#what-the-adder-checks)).
`ListDevices` returns it on each row as `approved_by_device_id` and
`approval_signature` (64 bytes, empty for none).

### ReapproveDevice

A removed device's approvals stop counting on every device that learns of
the removal ([RevokeDevice](#revokedevice)), so a device it linked, and any
device linked through that one, drops off the approval chain while staying
signed in. `ReapproveDevice` puts it back: a device still on the chain signs
a fresh approval for it, and that approval replaces the row's old one.

`ReapproveDeviceRequest`:

| Field | Value |
|---|---|
| `device_id` | The device to approve again. |
| `approver_device_id` | The caller's own approving device. |
| `signature` | The approval signature of [ApproveDevice](#approvedevice), over the subject row's id and signing key. |

No account key rides it: the subject is already certified and holds the key.

**Rooted.** Both sides are judged by one walk over the device list, the same
on the server and on every client: follow `approved_by_device_id` up from a
row. The row is *rooted* when every approver on the way is an unrevoked row
of the account and the walk ends at a row with no approval. It is not rooted
when the walk reaches a revoked row, a row that is not listed, or a loop.

| Refusal | Code |
|---|---|
| Ids not UUIDs; same id twice; signature not 64 bytes; bad signature | `invalid_argument` |
| The calling login holds no certified device; the approver row is not linked to the calling login | `permission_denied` |
| Either device is not the caller's | `not_found` |
| Approver revoked | `permission_denied` |
| Approver not certified, or not rooted | `failed_precondition` |
| Subject revoked, not certified, not approved (pending, expired or denied), or rooted | `failed_precondition` |

The session rule is [ApproveDevice](#approvedevice)'s. On success the row's
approval is replaced (`approved_by_device_id`, `approval_signature`), and the
account's other sessions get a `state_changed` poke for `SESSIONS`.

A client offers it from a rooted device, deepest orphan first, and only for
a sibling it saw hold the listed key in a group it is active in. Each device
judges the new approval with the
[What the adder checks](#what-the-adder-checks) rule: it verifies only where
the approver is on that device's own chain.

[ClaimSoleDevice](#claimsoledevice) and a PIN restore leave the remaining
device as the account's root: they delete the approvals of the rows they
keep that a revoked device made.

### Fetching and opening the account key

`FetchAccountKey { device_id }` returns `{ box, approver_device_id,
signed_out_box }` for the caller's own MLS device that registered under the
session it calls with. `device_id` MUST be a 36-character UUID
(`invalid_argument` otherwise). A device with no box, a stranger's device, a
revoked device and a device of the account that did not register under that
session all return an empty response.

A person's approving device seals a version-3 box. A version-1 box is for a
device the server itself runs: on a test server, and on Peachy's service for
its store-review login (below).

The version-1 box is built from two X25519 agreements. Ed25519 keys are
mapped to X25519 as in RFC 7748 and RFC 8032:

- a secret: `SHA-512(seed)[0..32]`, clamped;
- a public key: the Montgomery form of the Ed25519 point. A key that is not
  on the curve, or is of small order, MUST be refused.

To seal, with `a` the approver's X25519 secret, `A` its Ed25519 public key,
`R` the recipient's X25519 public key, `B` its Ed25519 public key, and `id`
the recipient's MLS device id:

```
e   = 32 random bytes;  E = X25519(e, 9)
ikm = X25519(e, R) || X25519(a, R)          (refuse an all-zero output)
key = HKDF-SHA256(ikm, salt = empty,
                  info = "peachy account key v1" || 0x00 || A || B || id (ASCII), L = 32)
box = 0x01 || E (32) || nonce (12) || AES-256-GCM(key, nonce, account_key (32), aad = E)
```

The box is 1 + 32 + 12 + 32 + 16 = 93 bytes. To open, the recipient computes
`X25519(r, E) || X25519(r, A_x)` with its own secret `r` and the approver's
mapped key `A_x`.

A version-3 box is sealed when the approver took the recipient's link key `L`
([The link key](#the-link-key)). It adds a secret exported from HPKE (RFC 9180,
base mode) to `L`, with KEM X-Wing (draft 6), HKDF-SHA256 and AES-256-GCM:

```
info       = "peachy account key v3" || 0x00 || A || B || SHA-256(L) || id (ASCII)
enc, k_pq  = HPKE SetupBaseS(L, info) then Export(exporter_context = empty, L = 32)
ikm        = X25519(e, R) || X25519(a, R) || k_pq      (refuse an all-zero X25519 output)
key        = HKDF-SHA256(ikm, salt = empty, info, L = 32)
box        = 0x03 || E (32) || enc (1120) || nonce (12) ||
             AES-256-GCM(key, nonce, account_key (32), aad = 0x03 || E || enc)
```

The box is 1 + 32 + 1120 + 12 + 32 + 16 = 1213 bytes. To open, the recipient
derives its X-Wing private key from the seed of the `L` it posted, runs
`SetupBaseR(enc, info)` and the same export, and computes the two X25519
agreements as for version 1. A recipient that posted no `L` MUST refuse a
version-3 box.

A version-2 box adds the reserved QR code's link secret to the input keying
material. No client seals or opens one:

```
ikm = X25519(e, R) || X25519(a, R) || link_secret
key = HKDF-SHA256(ikm, salt = empty,
                  info = "peachy account key v2" || 0x00 || A || B || id (ASCII), L = 32)
box = 0x02 || E (32) || nonce (12) || AES-256-GCM(key, nonce, account_key (32), aad = E)
```

**Which approver to believe.** The recipient MUST open:

- a version-3 box, only when the approver's key is the one whose number the
  person picked on this device
  ([The two-digit number](#the-two-digit-number)), with the switch below
  on or off;
- a version-1 box, only under a local switch, and then from any listed
  approver. A client
  sets the switch only for a test server it was built or launched to talk
  to, or for a sign-in with a number from the fictional
  555-01xx block, which Peachy's service refuses for everyone but its own
  store-review login. The switch MUST be set only by the client itself,
  never from anything the server says. Under it a device trusts the
  server's list of the person's devices;
- a version-2 box, never.

The recipient MUST take the approver's signing key from its own `ListDevices`
answer: a row of its own account that is approved, not revoked and
`account_certified`. It MUST NOT trust a key carried in the same response as
the box. A box from another approver, for another device id, or altered in
transit does not open, and all three look the same.

`account_key_seal` (the version-1 box, for a server-run approver: a test
server or the store-review login's anchor),
`account_key_seal_hybrid` and `account_key_accept_hybrid`, the new device's
only door, in `mls/core/src/account_store.rs` implement it;
`mls/fixtures/account-store.json` pins it (`boxAccept`, `boxAcceptHybrid`).
No door seals a version-2 box: its sealer, `account_key_seal_linked`, is public
only in builds with the core's `fixture` feature, for the fixture and tests.
`account_key_open`, which opens a version-1 box from whatever approver key it
is handed, is not a client's door:
whoever lists the approver, the server included, picks the key it opens to.
It is public only in builds with the core's `fixture` feature, for tests and
tools; the C symbol refuses in every other build, and the shipped wasm bundle
does not export it.

#### Pairing a device with no screen

A bot, a relay or another headless device that joins an existing account as a
second device follows the same link, with its operator standing in for the
person:

1. It draws a link-key seed and posts `nN` with `L` and `T`
   ([The link key](#the-link-key)). On every read of the exchange it first
   drops one whose approver is not approved, unrevoked and certified, or
   whose `S` fails `verify_device_link_commitment` over its own id and key,
   and only then runs `device_link_waiter_step`, which checks neither,
   exactly as a phone does.
2. When the approving device shows the approver's number, the operator reads
   it there and types it into the headless device (a command-line prompt, a
   one-time config value). The device computes the approver's number over the
   bound approver key ([The two-digit number](#the-two-digit-number)), as a
   phone does before offering it among decoys; a number that differs ends the
   pairing, and a match confirms that key.
3. It opens the version-3 box with `account_key_accept_hybrid`, passing that
   key as `confirmed_approver_key` and `server_approval_allowed` false.

It opens a box only with `account_key_accept_hybrid`, never with
`account_key_open`, and never sets `server_approval_allowed`: either lets the
server choose the approver, and so the account key the device then certifies
under.

After opening the box, the device keeps the account key, certifies itself
with `RegisterDevice`, and only then reads the store, which serves only a
certified device. A restore from the PIN vault takes the same order. A key
that does not open the store's manifest is not treated as no key: the device
MUST NOT write the store with it, and MUST keep it and its floor and MUST NOT
mint a key over it. A held key whose floor is above 0 has opened the store
before, so a manifest it does not open is a refused read: the device keeps
what it holds and reads again on the next store event or launch. Only a key
whose floor is 0 makes the device wait for an approval. A key from a box or
the PIN vault MUST NOT start a store: a "no store" answer for it is a refused
read too ([A device without the key](account-store.md#a-device-without-the-key)).

### RevokeDevice

`RevokeDevice { device_id }` revokes the whole install: both rows, their
credentials, any account key box addressed to them, every mailbox entry still
owed to them, and every session the install registered under, including the
caller's own. A pending row becomes `denied`. The call is idempotent. A device
of another account is `not_found`. `was_let_in` is true when the device had
already been approved or had certified itself. Approvals the revoked install
made for devices that have not certified yet are deleted, and those devices
become `pending`.

Only an approved device may revoke: the calling session must be linked to an
unrevoked row that carries an account signature itself, or to a plain row
whose own MLS twin does. Another install's certificate never counts, even
through a `twin_of` link. A session with no device, or only a pending one, is
`permission_denied`.

**The signed revocation.** `revocations` carries the account's signature
revoking rows of the install: one `DeviceRevocation { device_id, signature }`
per row the core lets it sign, over that row's signing key, with the account
identity key:

```
"peachy-device-revocation-v1" || 0x00 || device_key
```

The statement covers the key only and carries no time: a revocation is
permanent, and the device comes back only as a new key. The server keeps a
signature only for a row of the install being revoked that verifies under the
account's pinned identity key, and the first one a row receives stays; it
drops any other and never refuses the revoke for it. The kept signature is
`Device.revocation` on the revoked row in `ListDevices`, and travels beside
the stale ids
([Revocation reaches a seated leaf through the roster](#revocation-reaches-a-seated-leaf-through-the-roster)).
A client MUST sign when it holds the account key. Which keys it signs is the
core's rule, never the list's (`install_revocation_targets` in
`mls/core/src/revocation.rs`), because the server writes the list:

- nothing for a denial: a pending device has no leaf;
- never a row of the revoking install itself;
- only a key the device's own approval chain vouches for, under the id it
  vouched for;
- the row the person named, and a row linked to it by `twin_of` only when the
  confirmation named that row too (`named_with`) and the device noted the
  link itself from its own earlier `ListDevices` reads
  (`note_own_install_links`, first sight wins). A confirmation calls a linked
  row the entry's own second key ("both of its keys") only when both carry
  the same sealed name this account wrote under each row's id in the account
  store ([`account`](account-store.md#account), `deviceNames`), and
  otherwise names it as "linked to it". When two rows carry this device's
  pin to the named one, nothing is signed, the named row included;
- never an id the list names twice, for a removal or a restore;
- over the list the confirmation drew when it opened, never a list redrawn
  under it or fetched again for the signature. A removal made from anywhere
  else (the new-device notice) signs the named row alone, following no link.

**A PIN restore signs the others.** The registration that restores signs
every other install out unsigned
([Who may certify](#who-may-certify), PIN restore), and none of them is on
the restoring device's approval chain. That registration's answer says so
(`RegisterDeviceResponse.pin_restored`) and names, from the same transaction,
the keys of the rows it signed out (`pin_restore_signed_out_keys`), leaving
out a plain row an MLS row names as its twin, each with the account
certificate its row registered with (`pin_restore_signed_out_certificates`,
in the same order).

The restoring device closes each restore with at most one answer:

- It marks the restore before it registers, the mark and "answer pending"
  being one write. Before the first registration after the mark that carries
  its account certificate (an enrollment or a certification, never a
  renewal), it writes the mark as asked by that request, under a fresh token,
  and only that request's own response answers it: its keys, or an empty list
  when it says nothing was restored.
- If that request fails, or its answer is not kept (a crash, a relaunch, a
  reload, another tab asking first), the restore closes unanswered and signs
  nothing; the next certified registration finds the mark already asked and
  closes it. So does an answer that arrives more than two minutes after the
  ask, timed on a monotonic clock, and an answer naming more than 64 keys.
- A mark that does not decode is moved aside, its keys joining the device's
  list. A mark the device cannot read is never written over, and a restore
  noted at or before a certified registration sent while it could not be read
  closes unanswered. In a browser each step on the mark runs under a lock
  shared by the account's tabs, taken for at most 20 seconds.
- The device keeps only the keys whose certificate verifies under the account
  identity key it derives, and never its own key (`note_restore_signed_out`,
  which checks each certificate again; the first answer kept for a restore
  wins). It then spends the mark and ignores every later answer.
- Any approval this device makes closes the restore: with no answer kept yet,
  an empty one is kept (`sign_own_device_approval`), so no answer that
  arrives after the person linked a device can name it, and the core takes
  no key for the list once an approval closed it.

For a day after it took the account key back from its PIN, the device signs
the kept keys on its reads of `ListDevices`, before a read forgets the list's
revoked rows, and sends each signature in a `RevokeDevice` for that row,
which keeps it. The core's rule (`restored_since`):

- only keys that answer named, on rows the list shows revoked from an hour
  before the restore, on the device's own clock, to two hours after it; none
  of this install's ids or keys, no key on its approval chain under any id,
  and no key a live row still carries. A read of the list adds no key;
- nothing when no answer was kept;
- a key the answer named, or one this device signed a revocation of or
  forgot, is never approved by this device again
  (`sign_own_device_approval` refuses it).

**The signed-out list.** The keys the answers named and the account certified
reach the account's other devices:

- The restoring device keeps them beside its mark, a later restore keeping
  every earlier one, and before any approval it makes it writes them into
  the sealed account record (`signedOutKeys`, at most 64, oldest first). No
  key is pushed out of the record to make room: when its list does not fit,
  the approval is still made, with nothing added to the record and the
  approver's own list alone handed over, and the device still refuses every
  key of its own list. Nothing clears the list.
- Every device, before it signs an approval, refuses while its account store
  is not ready (the person tries again) and refuses to approve a key the
  record or its own list names, removing that device instead
  (`RevokeDevice`, a denial), so its next registration is refused and it
  starts over under a new MLS seed and a new key.
- An approval (`ApproveDevice`, not a reapproval) hands the device it lets in
  the approver's list (the record's keys with its own) in `signed_out_box`,
  sealed under the account key and bound to that device's id. The device
  keeps it as its own list, refuses those keys, and writes them into the
  record, whichever store version it is served.

The server cannot forge or edit the record.

**Unsigned revocations.** These stay the server's word alone. Their leaves
go at once while signed revocations are not enforced and the person keeps
another unlapsed leaf in the group, and
otherwise by the lapse rule or a reseat:

- a denial, including one the server answers with `was_let_in`;
- [ClaimSoleDevice](#claimsoledevice);
- an account's deletion, which deletes the rows a revocation is kept on;
- a [copied install](#a-copied-install), refused at its registration;
- an [idle linked device](#idle-linked-devices), unlinked by the hourly sweep.

**Forgetting.** Each device of the account MUST forget a device it learns was
removed (`forget_own_device` in `mls/core/src/own_devices.rs`): it is no
longer the remembered approver, and the check below never again calls it
`known` or accepts an approval it signed. The device forgets the id, every
key it saw that id hold, and the key the device list gives for the row,
because the account certificate covers a key, not an id. Forgetting is
permanent. A device on this device's approval chain only through the
forgotten device, directly or through devices on the chain only through it,
leaves the chain until a device still on it approves it again
([ReapproveDevice](#reapprovedevice)). A device that another device on the
chain also approved stays.

### ClaimSoleDevice

`ClaimSoleDevice { device_id, keep_device_ids }` is for a person who has lost
every other device. `keep_device_ids` names the caller's other rows on the
same machine. The server:

- revokes every other install and ends its sessions;
- deletes the account store and every account key box;
- clears the pinned account identity key and every account signature, and
  never pins that key again: a later certificate under it is
  `failed_precondition`;
- turns the PIN and the registration lock off, deleting its unlock tickets;
- deletes the approvals of the kept rows that a revoked device made, so the
  remaining device is the root of the chain ([ReapproveDevice](#reapprovedevice));
- returns the device and `revoked_device_ids`.

It is `failed_precondition` while the account's registration lock is on
([UnlockRegistration](#unlockregistration)), `not_found` for a device that
is not the caller's, and `permission_denied` when the kept device did not
register under the calling login, or when `keep_device_ids` names a row that
is neither that device's twin nor a row the same login registered.

The client then mints a fresh account key, writes a fresh store and certifies
itself under it.

**Seating the device that started over.** Its new account key is refused
beside the person's old leaves ([One account key per person](#one-account-key-per-person)),
and those leaves were revoked without a signature. A member's device that
seats the new device in a group where the server named every one of the
person's leaves stale removes them all and adds the new device in one commit
(`reseat_person` in `mls/core/src/group.rs`). The core builds it only from a
key package carrying an account certificate, only when the named leaves are
all of that person's leaves, never for the committer's own person, and never
for the same device or device key. The key package's account key MUST be
new: when every named leaf carries the same account key, the device is an
ordinary add, which removes nobody (a PIN restore keeps the key, and its old
leaves go by their revocations); named leaves under different account keys
are refused; and a key the device saw the person move away from
(`account_retired` in `mls/core/src/storage.rs`) is refused for good. So a
reseat is always a [security-code change](#security-code-changed) for every
member, drawn as the change row, the badge and, for a verified person, the
send block. The group's policy judges both halves, so the removal needs
`pol.rm`.

### Idle linked devices

The server unlinks a **linked** install, one a live device approved (a row
of it has an approval, `Device.approved_by_device_id`, naming a device that
is not revoked), once it has gone more than 30 whole UTC days without
connecting: no `RegisterDevice` from either of its rows, and no
authenticated call from a login linked to either. Idleness counts from no
earlier than the day the install's live approval was made and the day the
last device it approved was removed; and an install goes no sooner than 7 UTC
days after the server first dated it. It revokes it exactly as
`RevokeDevice` does, unsigned (`revocations` is empty), so peers learn of it
the same way. It never unlinks:

- an install no live device approved: the account's first device, one that
  became its only device ([ClaimSoleDevice](#claimsoledevice), a PIN
  restore), or one whose approver has been removed;
- an install that approved a live device; a chain unwinds from its end, one
  install per sweep;
- any install while the account has no other live, certified install that
  connected within the 30 days.

`ListDevices` sets `Device.unlinks_at` on each live row of such an install
from the 24th day after the day it counts from: the UTC midnight after its
30th day, or 7 days after the day it was first dated if that is later, when
the server's hourly sweep unlinks it unless it connects first. A row that
connects again loses it. The removed device sees what any removed device sees
([A removed install](#a-removed-install)).

## The MLS leaf

A leaf carries exactly one credential: the device's `pdc1`, with the account
certificate inside, as a `BasicCredential`. Its signature key is the device
key.

### What the adder checks

Every leaf a member is asked to believe MUST carry its account's certificate.
The MLS core checks this at the key package, the Add, the Welcome and every
received commit. A server filter on `FetchKeyPackages` is not the check.

An adder:

- MUST read the identity (actor, device, device key) out of the key package
  bytes, never from the `FetchedKeyPackage` fields around them
  (`Client::key_package_identity`);
- MUST verify the key package's credential strictly: no grace, not-before
  checked, account certificate present;
- MUST refuse a key package whose lifetime no honest device mints, or that
  lapses inside the mailbox horizon, on its own clock
  ([A KeyPackage's lifetime is checked by its adder](#a-keypackages-lifetime-is-checked-by-its-adder));
- MUST refuse to commit while its own leaf has lapsed, on its own clock or on
  the [tree clock](#a-received-commit-is-judged-on-the-tree-clock);
- MUST NOT replace a leaf except with `replace_member`, which hands the seat
  back only to the same actor, the same device id, the same account identity
  key and the same device key. Receivers hold every commit to the same rule:
  a remove and an add in one commit count as a reseat only for the same seat
  ([The group's policy](mls-core.md#the-groups-policy)). A device that lost
  its key comes back by an ordinary add, once its old leaf is gone;
- MUST NOT add a key package whose device id already holds a leaf in the
  group, under any key (`add_member` refuses it);
- MUST NOT add a device of its own account that it forgot as removed, by
  its id or any key it was seen holding (`add_member`, `replace_member`,
  `founding_refusals` and `seat_founding` refuse it);
- MUST remove, never replace, a leaf whose owner cannot be identified (an
  unknown `kid`, a malformed credential).

Group policy (`mls/core/src/policy.rs`) also applies. Anyone may remove leaves
of their own account, and anyone may remove an unidentified leaf.

**Adding a device of your own account.** Before adding a key package whose
actor is its own, a device checks the device's approval from `ListDevices`
with `check_own_device_approval` (`mls/core/src/own_devices.rs`).
The check believes an approver's key only if it is on the device's
**approval chain**, recorded as the device learns each link:

- its own signing key;
- the device whose box it opened when it took the account key
  (`remember_own_approver`);
- a device whose approval verified under a key already on the chain when this
  device checked it for seating (`check_own_device_approval` answering
  `approved`).

`check_own_device_key` reads the chain and adds nothing to it, so the chain
grows only through the device's own seat checks. A sibling that another device
seats first in every group they share is never checked here and never joins it.
Nor is a sibling a founding commit seats: the founder judges her other devices
by `founding_refusals` alone, as anybody else's, with no call to the server
([Founding a conversation](delivery.md#founding-a-conversation)).

Nothing joins the chain from a tree or from a seat the device watched: a leaf
of its own actor already in the tree at its Welcome, or seated by a sibling,
is seen, not trusted, and counts only for the new-device notice; a Welcome it
signs into a group this device knew is drawn as a device that isn't one of
the person's own
([A Welcome into a group this device knew](delivery.md#a-welcome-into-a-group-this-device-knew)).
None of the chain counts once forgotten as removed, under its id or any key
it was seen holding. A leaf naming the device's OWN id counts only under the
device's own key. A leaf of its own actor added by a member the device has
not seen as its own, such as a contact answering a seat ask, is not even seen
until an approval for it verifies.

**A call link's group has its own core.** A call placed through a call link
runs in a group held by a second core on the device, in memory, which starts
with none of these records. The main core hands it the chain and every id and
key it forgot (`own_device_trust`, taken by `adopt_own_device_trust`), so every
rule above holds there too, and `own_device_standing` tells the call's screen
whether a leaf of the person's own account is on the chain: one that is not
is never shown as the person
([Call links on participant keys](calls.md#call-links-on-participant-keys)).

**The new-device notice is keyed on the device and its key.** Its input,
`own_sibling_leaves`, names each of the account's other devices seated in a
group the device holds. A device id comes back bare while its leaf carries
the first key the device saw that id hold, and otherwise (including the
device's own id under a key not its own) as
`<device id>#<device key, 64 hex characters>`, a name no device list carries,
so the notice fires for it as for a device it has not seen. The first key is
kept for good, even after a removal takes it out of the tree, and is taken
only from evidence: a `known` or `approved` verdict, the device's own add, or
a leaf it did not see added by a member it has not seen as its own. A key from
a verdict or an own add replaces one taken from a tree, never the reverse.

A client splits the long form at its `#` only when the rest is 64 lowercase
hex characters and the id before it is [well-formed](#ids). Any other entry
is a device it has not seen, every time it appears, and is never offered for
removal by id. The notice names a device by its platform and when it was
linked, never by any name the server supplies.

The notice is for a device no device of the account approved, and trust is
account-wide: a listed device is taken as seen without a notice, under its
bare id and its long form, when every leaf under its id holds the listed key
and either `check_own_device_key` answers `known` or `approved` for it, or its
approval (by another listed device) verifies under the listed key of a device
of the account. A device of the account is one of those, or one the device
saw seated under the account key (its id bare in `own_sibling_leaves`, a leaf
holding the listed key), which vouches for others but is not silent itself
without an approval. An open notice for a silent device closes. A device seen
for the first time that is not silent waits one look before it is announced,
since the leaves a device reads can be newer than its list.

The apps apply this rule. The core provides its inputs: `own_sibling_leaves`,
`check_own_device_key`, and `verify_device_approval` for an approval under a
listed key. `own_sibling_leaves` names a device this device forgot as
removed while its leaf is still seated.

| Verdict | Code | Meaning | Core `seats()` |
|---|---|---|---|
| `known` | 0 | The same device id and key is already on the chain. | Yes |
| `approved` | 1 | The approval verifies under a key on the chain. | Yes |
| `unanchored` | 2 | No approval, one by a device not on this device's chain, or a device it forgot as removed (which `add_member` refuses). | No |
| `bad_approval` | 3 | The approver is known and the signature does not verify. | No |
| `not_own_device` | 4 | Another actor's device, or this one. | No |
| `credential_rejected` | 5 | The package does not verify. | No |

The device id and key are read from the package. A peer of another account
cannot run this check, so it adds the devices the server lists for a person
on their certificates alone.

### One account key per person

The server issues every device credential, so it can make an account identity
key of its own and certify a device of its own under that key and a person's
actor id; it cannot make a certificate under the person's real key. A device
pins no key for its own actor, so the rule below is what keeps such a device
out of the person's own groups.

Every member MUST refuse, as `account_key_conflict`, a commit that adds a leaf
when:

- the leaf's actor is the reader's own and its account identity key is not
  the reader's own; or
- another leaf of the same actor, either still in the tree after the commit
  or added by the same commit, carries a different account identity key.

The committer runs the same check on its own commit before sending it. A
device joining by Welcome, into a new group or one it knew, MUST refuse the
same way a tree that holds a leaf of its own actor under another key, or one
actor under two keys: every leaf of a Welcome is new to its reader. Each leaf
is read with every credential check except expiry, so all members reach the
same verdict. Leaves a commit does not add are not judged against each
other, so a tree that already holds two keys for one person does not freeze;
nobody joins it by Welcome until the old leaves are gone.

A person whose account [started over](#claimsoledevice) has a new key. Their
new devices are seated in a group only after the leaves of their old devices
have left it ([Revocation reaches a seated leaf through the roster](#revocation-reaches-a-seated-leaf-through-the-roster)),
and peers then see [Security code changed](#security-code-changed). The first
time a device sees an actor, it takes that actor's key on the server's word.

### Refreshing a seated leaf

Every member refuses a sender whose credential is past its grace. A device
renews its leaf with a self-update commit carrying a fresh credential
(`refresh_credential`).

- **Only the dates may change.** Actor id, device id, device key and leaf
  signature key MUST stay the same, and the account identity key too.
  Receivers MUST require the renewed credential to come from a trusted issuer
  and to expire no earlier than the one it replaces (`check_renewed_leaf`).
  A new key is a rejoin, not a renewal.
- **When.** A device SHOULD renew a group's leaf when 10 days or fewer remain
  before `exp`, or when the leaf is due its
  [periodic rotation](mls-core.md#periodic-leaf-rotation). It renews at two
  moments only: before anything it seals into that conversation (a message,
  a reaction, an edit or delete, a read mark, a resend ask or answer, a
  history share, a group event, a call record), and in one pass over every
  group it holds when the app starts or returns to the foreground. It removes
  a leaf it cannot identify before its next message send and in that pass.
  It MUST NOT do either because a conversation was opened with nothing sent:
  the commit would show the server, at that conversation's handle, that
  someone looked at it. It gets the fresh credential by calling
  `RegisterDevice`.
- **Sealing past `exp`.** A device whose leaf is past `exp` seals only once
  that renewal has landed. If the renewal lost an epoch race to another
  member's commit, a device that has followed the winner before sealing plans
  once more and, if a renewal is still due, renews once more at the winner's
  epoch. Never a third time: if that one loses too, or the device seals
  before following the winner, the seal is refused with `expired`
  ([A lapsed leaf's new messages](#a-lapsed-leafs-new-messages)) and the
  next seal renews.
- **Before key packages.** A device SHOULD renew before publishing key packages
  when 6 days or fewer remain. The server stops serving a key package within
  5 days of its credential's `exp`.
- **The grace is 56 days past `exp`.** A lapsed leaf inside the grace may
  renew itself, and members read what it sent while it was live
  ([A lapsed leaf's new messages](#a-lapsed-leafs-new-messages)). It still
  counts as an existing member in a Welcome and still reads as identified in
  the roster. It MUST NOT add, remove, replace or rename, and its standalone
  proposals are refused.
- **Carrying the tree clock.** A device SHOULD also renew when it holds a
  credential issued after another leaf's `exp` that the group's tree clock
  has not reached yet (`lapsed_leaf_awaits_tree_clock`): the renewal moves the
  tree clock past that `exp`, once per lapsed leaf.
- **Stopping.** A device MUST stop renewing one day before its grace ends, so
  no member is between accepting and refusing it. Past the grace it stops
  sealing and asks to be seated again with a sealed seat ask.

The constants are in `mls/core/src/identity.rs`:

| Constant | Value |
|---|---|
| `CLOCK_SKEW_SECONDS` | 60 |
| `MAX_CREDENTIAL_LIFETIME_SECONDS` | 31 days |
| `CREDENTIAL_REFRESH_WINDOW_SECONDS` | 10 days |
| `EXPIRED_LEAF_GRACE_SECONDS` | 56 days |
| `RENEWAL_CUTOFF_MARGIN_SECONDS` | 1 day |
| `MAX_TREE_CLOCK_JUMP_SECONDS` | 85 days |

Expiry is not revocation. See
[Revocation reaches a seated leaf through the roster](#revocation-reaches-a-seated-leaf-through-the-roster).

### A received commit is judged on the tree clock

A verdict that depends on the reader's wall clock would fork the group, so
every verdict on another member's commit uses the group's **tree clock**:

```
tree_clock = max(iat) over every person leaf in the current tree
             and every leaf the commit brings in
             (its update path leaf, swept-up Update leaves, added key packages)
```

Every member at an epoch computes the same number. The rules
(`tree_clock`, `refuse_tree_clock_jump` and `refuse_lapsed_committer` in
`mls/core/src/group.rs`):

- A committer whose credential has `exp <= tree_clock` has lapsed. Its commit
  is accepted only if it carries no proposals and has an update path, that is,
  a renewal. Anything else is refused as `expired`.
- Leaves in the commit are judged with the 56-day grace measured from the
  tree clock, not from the reader's wall.
- The not-before check is skipped for a leaf arriving in a commit. It runs
  where a credential is first believed.
- No commit may bring in a leaf whose `iat` is at or past
  `tree_clock_before + 85 days`. Such a commit is refused as `expired`.
- The committer runs these same checks on its own staged commit before
  sending it.

The tree clock is not monotonic: removing the leaf with the newest `iat`
moves it back, to the same smaller value for every member.

### The joiner reads its Welcome on its own wall

A device joining by Welcome validates every leaf's credential against its own
wall clock, with the 56-day grace. This is the one credential verdict on group
state not made on the tree clock; it can only refuse the joiner itself. It
does not judge the leaves' key package lifetimes, which were judged when each
was added.

### A KeyPackage's lifetime is checked by its adder

Every key package carries a lifetime (RFC 9420 §7.2), which every member that
processes an Add judges on its own clock. So that no honest member refuses an
Add the rest merged (`mls/core/src/key_package_lifetime.rs`):

- **A device mints** every key package with a window from one hour before its
  now to 84 days after it.
- **An adder MUST refuse**, on its own clock, a key package whose window is
  longer than 84 days and one hour (the maximum RFC 9420 §7.2 requires),
  started less than 50 minutes before its now (so a minter whose clock runs
  up to 10 minutes ahead still passes, and every member whose clock lags the
  adder's by up to 50 minutes has the package started), or ends less than 31
  days after its now, which outlasts the 30 days a commit waits in a mailbox
  ([Retention](delivery.md#retention)). Every honestly minted package passes:
  it was minted under a credential at most 31 days old and has at least 53
  days left. The founding checks, `add_member`, `replace_member` and
  `key_package_identity` all apply this.
- **A joiner does not judge** the lifetimes in its Welcome's tree
  ([The joiner reads its Welcome on its own wall](#the-joiner-reads-its-welcome-on-its-own-wall)).

The window protects nobody from a lapsed leaf: a credential's `exp` does
that, judged on the [tree clock](#a-received-commit-is-judged-on-the-tree-clock).

### Revocation reaches a seated leaf through the roster

A credential carries no revocation, and the server does not know which
conversations a device is in. Two paths name a revoked device's leaf.

1. **The delivery service names stale recipients.** `SendSealed` and
   `SubmitCommit` return `stale_device_ids`: named
   recipients that are revoked or do not exist. `SendSealed` and
   `SubmitCommit` also return `stale_revocations`: the account's signature
   ([RevokeDevice](#revokedevice)) for each of them that has one, and only
   when the row is the account the sender named.
2. **The owner's other devices sweep.** After `RevokeDevice` or
   `ClaimSoleDevice`, and on every `state_changed` event for
   `STATE_DOMAIN_SESSIONS`, each of the owner's devices reads `ListDevices`
   and sweeps every group it is in for the revoked rows, with each row's
   `revocation`. Policy lets anyone remove their own account's leaves. Where
   policy refuses a non-admin, admins and the owner carry out the removal.

The server's list names a leaf; it does not decide that the leaf goes. A
device MUST remove a named leaf at once when `stale_leaf_removable`
(`mls/core/src/revocation.rs`) allows it, and MUST NOT remove it otherwise.

The core enforces this only through its own door: `remove_stale_leaf`
(`peachy_mls_group_remove_stale_leaf` in C, `removeStaleLeaf` in wasm)
judges the leaf and stages its removal in one call, stages nothing for a leaf
the judge keeps, and never removes the device's own leaf. The plain removal
(`remove_member`) is the door for a removal a person decided on and checks
group policy only, so a client that removes a server-named leaf through it
has skipped the rule.

`stale_leaf_removable` judges on two clocks, never the server-corrected one:
its own, and the group's
[tree clock](#a-received-commit-is-judged-on-the-tree-clock). The judged leaf
has lapsed only once it has on both; another leaf of the person counts as
unlapsed only while it is unlapsed on both. It allows the removal when any of
these holds:

1. **The account revoked it.** The revocation verifies under the leaf's own
   account identity key, over the leaf's own device key.
2. **Its credential has lapsed** (`exp` plus the 60-second skew is past),
   and either the same person keeps an unlapsed leaf in the group and the
   lapsed credential ran the issuer's full 30 days (`has_issuer_lifetime` in
   `mls/core/src/identity.rs`), or `exp` plus the 56-day grace is past. For
   the first, a leaf still seated from its key package counts only if its
   credential had the 10-day refresh window left when the device minted the
   package (the package's `not_before` plus the hour it is backdated).
3. **The person keeps another unlapsed leaf there**, while signed
   revocations are not enforced: the core's `SIGNED_REVOCATIONS_ENFORCED` is
   off, as it is in 0.2.0, and the device has not adopted the
   `signed_revocations` client refusal
   ([The protocol floor](delivery.md#the-protocol-floor),
   [Client refusals](CHANGELOG.md#client-refusals)). The server's word
   alone, with no signed revocation, removes one of a person's several
   devices, at once; the person stays a member. A lapsed leaf does not count
   as another.

Another leaf of the same person carries the same actor id and the same
account identity key. A person's last leaf in a group otherwise goes only in
the commit that seats their new device under a new account key
([ClaimSoleDevice](#claimsoledevice)). The list can only cause a removal,
never a seat. These are the committer's rules; a receiver does not re-judge a
removal.

A revoked device's sessions end with the revocation.

### A revoked leaf's messages

A member that holds the account's signed revocation of a device refuses the
application messages the delivery service received from it once the
revocation took effect, and reads the ones it received before
(`judge_message_sender` in `mls/core/src/identity.rs`, applied to every
application message by `process_message`):

- **Holding a revocation.** When `stale_leaf_removable` is handed a revocation
  that verifies under the leaf's own account identity key, over the leaf's own
  device key, the device keeps it by device key, with `revoked_at`: the second
  the delivery service says the revocation took effect
  (`DeviceRevocation.revoked_at` in `stale_revocations`, `Device.revoked_at` on
  `ListDevices`), or 0 when it did not say. Offered the same key again with
  another time, it keeps the earlier one it knows. Before it refuses a
  message, it verifies the kept signature again against the sender's
  credential.
- **Refused.** An application message from that key, in any group, whether or
  not the leaf has been removed yet, that the delivery service received at or
  after `revoked_at`, or whose receive time or `revoked_at` the device does not
  know. It is refused as `NotFromAMember`, like a removed device's message,
  and rolled back, so it spends nothing.
- **Still read.** A message the delivery service received before `revoked_at`.

The receive time is the mailbox envelope's `received_at`, which the client
hands the core with the message (`process_message_received_at`). Both times
are whole seconds on the delivery service's clock, so a message received in
the second the revocation took effect is refused.

A member holds a signed revocation once the delivery service returned it in
`stale_revocations`, or once it is one of the owner's devices that read it on
`ListDevices`; until then it reads the revoked device's messages like any
member's. A revocation nobody signed is never held. Both times are the
delivery service's word.

### A lapsed leaf's new messages

A lapsed leaf inside the grace is still heard, so that what it sent while
live reaches a member that reads late. A message from it is NEW when it was
not sent while the leaf was live (`judge_message_sender`):

- **Received after `exp`.** The delivery service received it at or after the
  sender's `exp`, whatever epoch it was sealed in. With no receive time, the
  reader's own wall stands in for it.
- **Sealed past the tree clock.** It was sealed in the epoch the reader's
  group is in now, and that epoch's tree clock is at or past the sender's
  `exp`. This holds whatever receive time the delivery service gives the
  message. A message from an epoch the group has left is judged on its
  receive time alone.

Every leaf in an epoch's tree was issued before the epoch began, so a message
sealed and received while its sender was live is never new.

A member MUST
refuse a new message as `expired`, rolled back like any refusal
(`judge_message_sender` in `mls/core/src/identity.rs`).

- **A device does not seal on a lapsed leaf**: one whose `exp` is at or
  before the tree clock, or that its own clock puts within 60 seconds of
  `exp` or past it (`CLOCK_SKEW_SECONDS`, how far ahead the delivery
  service's clock may run). `encrypt` refuses with `expired`, so the send
  fails rather than going out to be refused, and the device renews before it
  sends again.
- **A member renews to carry the tree clock** past a lapsed leaf's `exp` when
  it holds a credential issued after it
  ([Refreshing a seated leaf](#refreshing-a-seated-leaf)).

## The security code

Two people compare a 60-digit code to check that each holds the other's real
account identity key. It changes only when a person's account identity key
changes, which is after [ClaimSoleDevice](#claimsoledevice) or
`became_sole_device`. Adding or removing a device never changes it.

### Computing it

The inputs per person are:

- `key`: the 32-byte account identity public key. The other person's is read
  from their leaves in a sealed conversation the device has verified, never
  from a server answer. The device's own MUST be derived from the account key
  it holds ([The account identity key](#the-account-identity-key)), never read
  from its own credential, which the server writes. A device that holds no
  account key MUST NOT show a code;
- `id`: the 16 bytes of the actor id UUID.

Each side's fingerprint:

```
h = SHA-512(0x00 0x00 || key || id || key)
repeat 5,199 times:  h = SHA-512(h || key)
```

That is 5,200 SHA-512 calls. Each side's 30 digits come from the first 30
bytes of `h`: six chunks of 5 bytes, each read as a big-endian 40-bit integer,
taken mod 100,000 and zero-padded to 5 digits. The code is the two 30-digit
strings joined with the smaller one first, shown as 12 groups of 5.

The QR code carries this side's view:

```
"peachy-sc:" || base64url-no-padding(SecurityCodeQr)
```

`SecurityCodeQr` is protobuf:

| Field | Type | Value |
|---|---|---|
| 1 | varint | Version: 1 |
| 2 | message | Local fingerprint: `{ 1: bytes }` holding the first 32 bytes of this side's `h` |
| 3 | message | Remote fingerprint: `{ 1: bytes }` holding the first 32 bytes of the other side's `h` |

A scan matches when the scanned local half equals this side's remote half and
the scanned remote half equals this side's local half. Compare in constant
time. A different version is a version mismatch, not a match or mismatch.
Trim whitespace around the scanned text first. Text without the prefix, or
whose payload is not base64url of this protobuf, is invalid.

### Security code changed

Each device pins each other actor's account identity key on first use, in its
own MLS core store (`observe_account_keys` in `mls/core/src/group.rs`). Call it
after anything that can change a tree: a merged commit, a processed commit, a
joined Welcome; and for every conversation held, in the client's foreground
pass, so a change seen elsewhere reaches a tree that has not changed.

- The first sight of an actor accepts silently every key that tree shows for
  them and pins the key of their newest leaf (highest `iat`, among the leaves
  no more than a day past this device's clock when any is) as current.
- After that, every leaf of theirs not under the current key is reported,
  once per conversation, unless that conversation already reported it (or
  accepted it at a first sight). A leaf it settled while that leaf's key was
  current, one it reported when that key was new included, is reported once
  the person moves off the key: the conversation still encrypts to it. A
  report settles a leaf only while its key is not current: whenever the pin
  moves, every conversation the device holds drops its reports of that
  person's leaves under the key it moved to or off, whichever conversations
  it read in between, and so does a conversation it forgot for a rejoin, at
  its first read after the rejoin. A conversation keeps no leaf as both
  settled and reported: a leaf a store holds as both is kept as settled, so
  that conversation names the person once if they are, or later are, off
  that leaf's key. A leaf under a key they moved away from is reported in any
  tree, one this device joined by Welcome included. The client shows
  "{name}'s security code changed" there. A conversation knows a leaf by its
  signature key, its HPKE key and its credential together, so a leaf seated
  on the keys of one it settled, under another person's credential or
  another account key, is judged afresh.
- The pin moves to a reported leaf only when its `iat` is later than that of
  the leaf that made the current key current (for a key never accepted, not
  earlier: the issuer floors `iat` to the day) and no more than a day past
  this device's clock; the pin is dated no later than that clock. An older or
  future-dated one is recorded as a key they moved away from and the current
  key stays.
- Each conversation keeps the key it last showed as current; the first
  current key it shows after showing the person only under another is
  reported there once.
- A pin with no time recorded takes its time only from leaves under the
  pinned key (or a key accepted in that conversation, never a retired one);
  the keys such a conversation showed count as accepted there, never as
  current.
- It is a notice, never a refusal.
- A change of devices (added, removed, re-added, the viewer's own included)
  MUST NOT draw a row: every leaf carries the account's signature, so a device
  change moves nobody's code.

### Verified

A person may mark a contact as verified after comparing codes. The client
stores the checked key as `verifiedKey` on that contact's
[account store record](account-store.md#record-values). The state is derived:

| `verifiedKey` | Their key now | State |
|---|---|---|
| absent | anything | not verified |
| equal | equal | verified |
| present | not seen yet | verified |
| present | different | changed since verified |

While a direct conversation is "changed since verified", a client MUST NOT
send in it until the person acknowledges the change. Acknowledging removes
`verifiedKey`.

A client SHOULD NOT seat a device of a verified person under an account key
other than `verifiedKey` until the person reviews the change. That covers an
add, a replace, or a reseat of all their leaves. Until the review, it SHOULD
treat the held key as theirs in that conversation, so the conversation reads
"changed since verified" and its sends are held, and SHOULD keep the held key
across restarts. Once the change is
acknowledged or the verification cleared, it SHOULD seat them. Whether a
seat is held SHOULD be derived from the store as it stands on every read (a
`verifiedKey` that the held key is not), never stored, so any device's
acknowledgment or clear ends it, and a device SHOULD judge by the newest copy
of the store it holds. Until it has
read the account store, it SHOULD seat nobody else.

## The key stores

**A device key copied onto a second device is a second device holding the
first one's identity**: two installs would sign as one member, and neither
could be removed without the other.

A client:

- MUST keep the device seeds and the account key in storage that is bound to
  this device and excluded from every platform backup, sync and
  device-transfer path (the PIN vault's copy, sealed under a key derived
  from the PIN, is the one exception);
- MUST NOT fall back to an exportable key where the platform cannot hold one.
  A browser SHOULD hold the plain device key as a non-extractable WebCrypto
  key;
- MUST NOT delete the device key at sign-out: it is the install's identity,
  not the login's;
- MUST detect that it was copied onto new hardware, where its platform allows,
  and start over at sign-in as a new device.

Peachy's own web client holds the plain device key as a non-extractable
WebCrypto key and keeps the MLS seed and the account key sealed at rest under
a non-extractable key. Any script that runs in its page can use them
([Security considerations](delivery.md#security-considerations)).

## Fixtures

| Fixture | Pins |
|---|---|
| `mls/fixtures/credentials.json` | `pdc1` encoding, every verification check, a device's check of its own credential against the key it holds, every rejection code |
| `mls/fixtures/device-link.json` | The account certificate, the device revocation, the approval signature, the QR text, the commitment and the two-digit number |
| `mls/fixtures/account-store.json` | The account key box, record and manifest sealing |
| `mls/fixtures/formats/security-code.json` | The security code, its QR text, comparing a scan, and the verified state |

## Security considerations

What this document trusts:

- **The server vouches for devices.** It issues every credential and
  vouches for the first sight of an account's identity key. Comparing
  security codes ([The security code](#the-security-code)) is the check that
  does not rest on it.
- **The account certificate does not name its account.** Which account a
  certified device belongs to is the server's word
  ([The account identity key](#the-account-identity-key)).
- **Keys are only as safe as the client keeps them.** The device key is a raw
  Ed25519 seed in the client's key store
  ([The key stores](#the-key-stores)). Code that reads the app's memory, or
  the store and the key that seals it, acts as the device until it is
  removed.
- **The store-review login is the operator's.** The login Peachy gives app
  stores for review, and the fictional people in its demo conversations, are
  accounts whose devices the server runs, so it holds their account keys and
  reads their store and demo conversations. Sign-in refuses every other
  555-01xx number, so no other account is affected.
- **Signatures are classical.** Ed25519 resists no quantum computer, though
  forging one takes a quantum computer at the time of the attack.

## IPR

This document is dedicated to the public domain under CC0 1.0.

## References

- [RFC 2119] "Key words for use in RFCs to Indicate Requirement Levels", BCP 14, RFC 2119, March 1997. <https://www.rfc-editor.org/rfc/rfc2119>
- [RFC 8174] "Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words", BCP 14, RFC 8174, May 2017. <https://www.rfc-editor.org/rfc/rfc8174>
- [RFC 8032] "Edwards-Curve Digital Signature Algorithm (EdDSA)", RFC 8032, January 2017. <https://www.rfc-editor.org/rfc/rfc8032>
- [RFC 7748] "Elliptic Curves for Security", RFC 7748, January 2016. <https://www.rfc-editor.org/rfc/rfc7748>
- [RFC 5869] "HMAC-based Extract-and-Expand Key Derivation Function (HKDF)", RFC 5869, May 2010. <https://www.rfc-editor.org/rfc/rfc5869>
