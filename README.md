# Peachy protocol

Specifications and the MLS library behind Peachy's end-to-end encrypted
conversations.

Peachy is a chat app. Every private conversation in it (direct messages and
private groups) is end-to-end encrypted with MLS (RFC 9420). The server holds
ciphertext, a mailbox per device and each conversation's order of changes, and
never message plaintext (the store-review login's demo conversations aside:
[Metadata](docs/metadata.md#what-the-server-never-holds); and a reported
message's words when the reporter chooses to include them:
[the floor](docs/metadata.md#the-floor)). It sees which
devices each message goes to and, at each change to a group, every device in
it. Until every device has collected a change (at most 30 days), the rows it
stored for that change tie the conversation to the devices still waiting for
it and to their accounts ([Metadata](docs/metadata.md#the-verifier-log)).

The apps are not here, so nothing in this repository proves that an installed
app is built from this code, and the web client is sent by the server each
time it opens, so a web user trusts the server for content too
([Security considerations](docs/delivery.md#security-considerations)).

## Specifications

The index is [docs/README.md](docs/README.md).

### [Device identity](docs/identity.md) (Revision 1, 2026-11-19)

This document describes how a Peachy device is identified: signing in, the
device key, the server-signed `pdc1` credential an MLS leaf carries, the
account identity key, letting a new device in, and the security code two
people compare.

### [Delivery](docs/delivery.md) (Revision 1, 2026-11-19)

This document describes how a client moves sealed bytes through the Peachy
server: conversation handles, the wrapped envelope, per-device mailboxes,
commits and Welcomes, the KeyPackage directory, sealed media, and which
builds the server serves.

### [Sealed messages](docs/sealed-messages.md) (Revision 1, 2026-11-19)

This document describes what a Peachy device puts inside an MLS group: the
envelope, message frames, control frames, typing, the group's own state, and
seating and removing devices.

### [Message formats](docs/formats.md) (Revision 1, 2026-11-19)

This document describes the golden tables that pin message frames,
reactions, receipts, edits, deletes, the group's state and the security code
on real bytes.

### [Account store](docs/account-store.md) (Revision 1, 2026-11-19)

This document describes how a person's settings and lists are sealed under
an account key the server never holds (Peachy's own store-review accounts
excepted), and kept the same on all their devices.

### [Profiles](docs/profiles.md) (Revision 1, 2026-11-19)

This document describes how a person's name and photos are sealed under a
profile key and handed to the people they talk to, and what the server keeps
in plaintext.

### [Calls](docs/calls.md) (Revision 1, 2026-11-19)

This document describes how a call's media keys come from the conversation's
MLS epoch, how call signals are encoded and sealed, and the ringing every
client runs.

### [MLS core](docs/mls-core.md) (Revision 1, 2026-11-19)

This document describes the MLS profile every Peachy client speaks
(ciphersuite 0x004F, extensions, group policy, key packages) and the `mls/`
workspace that implements it.

### [Metadata](docs/metadata.md) (Revision 1, 2026-11-19)

This document describes what the Peachy server holds about private
conversations, for how long, and what it never holds.

What changed on the wire, and what a client of your own must do about it, is
in the [changelog](docs/CHANGELOG.md).

## Library

`mls/` is the Rust MLS core every Peachy client is built from, with C,
JavaScript/WebAssembly and Swift bindings, golden test tables, fuzz targets
and a ProVerif model of the call keys. Building and testing it is
[below](#building-and-testing).

| Path | What it is |
|---|---|
| `proto/peachy/v1/` | The client protocol: the subset of Peachy's ConnectRPC/protobuf API that messaging uses, as the official apps speak it to `https://api.pchy.app`. |
| `mls/core` | The MLS engine every official client is built from (Rust, on OpenMLS): groups, the Peachy device credential, group policy, the sealed envelope, the account store primitives. |
| `mls/cabi` | Its C ABI, with a committed header (`mls/cabi/include/peachy_mls.h`). |
| `mls/wasm` | The JavaScript/WebAssembly binding. |
| `mls/swift` | The Swift package over the C ABI. |
| `mls/keytrans` | Key transparency (draft-ietf-keytrans-protocol-05): the wire format, the log tree and Peachy's labels and values. No client or server uses it. |
| `mls/fixtures` | Golden tables: credentials, policy, rosters and envelopes, device linking, the account store, seat asks, the padded Welcome frame, call keys, signals and ringing, and more. The core and its bindings replay the tables for the core's own rules. |
| `mls/fixtures/formats` | Golden tables for the formats clients write above the MLS core: message frames, reactions, receipts, edits and deletes, the group's own state, the security code. See [docs/formats.md](docs/formats.md). |
| `mls/fuzz`, `mls/formal` | Fuzz targets and a ProVerif model of the call keys. |
| `docs/` | The specifications above. |

The repository is at https://github.com/peachysocial/peachy-protocol; see
[CONTRIBUTING.md](CONTRIBUTING.md) before sending a change.

## Stability and support

This code is published to be read, built and audited. Use outside Peachy is
unsupported: the API, the wire format and the file formats may change without
notice, and nothing here promises compatibility from one version to the next.
Peachy's official apps are the only clients Peachy supports.

## Audit status

This code has not been independently audited. Peachy is a small company and
has not paid for an outside audit; we intend to ask for independent audits at
prices we can afford, and to say here when one is done. Reports are welcome
under [SECURITY.md](SECURITY.md).

## What is not here

- Peachy's server, its apps (iOS, macOS, Android, web) and its other services.
  They are not open source.
- Features outside private messaging: the Feed, events, communities, group
  links and join inboxes, the call signaling rpcs (not the call-token doors),
  the media server and push, stories, contact discovery, the PIN and
  registration lock unlock, and anything for operators. Their rpcs are not
  in the proto subset.
- The Android binding of the MLS core.
- Golden tables for link previews and history hand-off requests; the prose is
  the reference ([docs/formats.md](docs/formats.md#what-is-not-here)).

## Building and testing

The MLS workspace needs Rust (the version in `mls/rust-toolchain.toml`) and a
C compiler. Every release of this tree passes these, run from `mls/`:

```sh
cd mls
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo test -p peachy-mls-core --features test-issuer,fixture,sqlite --test server_key_pins
cargo test -p peachy-mls-cabi --test shipped_store
cargo deny check          # cargo-deny 0.18 or later; the policy is mls/deny.toml
```

and, from the repository root, `buf lint` (buf 1.x). Why the two narrower
runs exist, and the `cargo tree` checks that keep test features out of the
shipped graphs, are in
[docs/mls-core.md](docs/mls-core.md#building-and-testing-locally).

Two tests in `mls/core/tests/rfc9420_vectors.rs` check the core against RFC
9420 test vectors that are not distributed here; without them each test prints
`SKIPPED` and passes. How to fetch and verify them is in
[mls/core/tests/vectors/README.md](mls/core/tests/vectors/README.md).

The X-Wing KEM of ciphersuite 0x004F has its own known-answer test,
`mls/core/tests/xwing_vectors.rs`, over the draft-connolly-cfrg-xwing-kem-06
vectors, which ship here.

The wasm binding's Node tests need the `wasm32-unknown-unknown` target,
`wasm-pack` (0.13.1 is what the official build uses) and Node 22 or later.
Every release of this tree passes them too, run from the repository root:

```sh
(cd mls && rustup target add wasm32-unknown-unknown)
wasm-pack build mls/wasm --target nodejs --dev --out-dir pkg-node -- --features test-issuer,fixture
node --test 'mls/wasm/tests/node/*.test.mjs'
```

The Swift package needs Xcode and builds its own archives first:

```sh
cd mls/swift
./build-xcframework.sh --host
swift test
```

The proto files compile with any protobuf toolchain; with buf:

```sh
buf build
```

Cross-compiling and fuzzing are in
[docs/mls-core.md](docs/mls-core.md#building-and-testing-locally) and
[§Fuzzing](docs/mls-core.md#fuzzing).

## License

Two licenses, split by what a file is:

- **Code and the protocol definition** (`mls/`, `proto/`) are licensed under
  the MIT License ([LICENSE](LICENSE), `SPDX-License-Identifier: MIT`).
  Copyright (c) 2026 Peachy Social, Inc.
- **The specifications** (`docs/`) are dedicated to the public domain under
  CC0 1.0 ([LICENSES/CC0-1.0.txt](LICENSES/CC0-1.0.txt)). Implement them in
  anything, under any license.

Every file says which applies, in an SPDX line or in `REUSE.toml`.

Dependencies are under permissive licenses, except `hpke-rs` (MPL-2.0,
compiled into every binding unmodified) and `cbindgen` (MPL-2.0, a build tool
only). The core's `sqlite` feature, which the C ABI always enables, compiles in
SQLCipher (BSD-3-Clause) and, off Apple platforms, OpenSSL (Apache-2.0); this
repository distributes neither library's source, and whoever ships a binary
built from it carries their license notices.

The RFC 9420 test vectors are not included: their upstream repository states
no license for them.

`mls/core/tests/vectors/xwing-draft-06.json`, the X-Wing test vectors, is the
`x-wing` crate's (version 0.1.0) `tests/test-vectors.json`, unmodified, under
the MIT License, Copyright (c) 2024-2026 RustCrypto Developers.

## Contributing

Contributions are welcome under the same licenses as the files they change;
see [CONTRIBUTING.md](CONTRIBUTING.md). Security reports:
[SECURITY.md](SECURITY.md).
