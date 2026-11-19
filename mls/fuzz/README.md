<!-- SPDX-License-Identifier: MIT -->

# Fuzz targets for mls/core

The targets the specification's docs/mls-core.md §Fuzzing promises.

From the repository root, write a starting corpus from the golden fixtures, then run a target:

```sh
cargo run --manifest-path mls/Cargo.toml -p peachy-mls-core --features fixture \
  --example fuzz_seeds -- mls/fuzz/corpus
cargo +nightly fuzz run --fuzz-dir mls/fuzz envelope_open -- -max_total_time=60
```

`mls/fuzz` is its own workspace, outside `mls/Cargo.toml`, because libFuzzer needs a nightly toolchain and sanitizer flags. Peachy smoke-runs each target for 30 seconds from an empty corpus on every change, and runs each for ten minutes every day from the previous run's corpus. `fuzz_seeds` (`mls/core/examples/fuzz_seeds.rs`) seeds every target but `call_ring_step` and `string_list` from the fixtures. A crash leaves its input under `mls/fuzz/artifacts/<target>/`, and `cargo +nightly fuzz run --fuzz-dir mls/fuzz <target> <file>` replays it. Where a target needs a valid signature or MAC to get past the first check, the first input byte selects a mode in which the target signs or seals the fuzzer's bytes itself. Each target's header gives its input layout and what it asserts. Inputs are arbitrary unless the table says how they are built.

| Target | Input |
|---|---|
| `envelope_open` | Bytes opened as a mailbox envelope |
| `envelope_roundtrip` | A payload sealed then opened |
| `call_envelope_open` | Bytes through a call signal's whole receive path |
| `call_live_frame_open` | Bytes as a call's live-lane frame |
| `call_signal_decode` | Bytes into the call signal codec |
| `call_signal_json` | Text into the call signal JSON door |
| `call_ring_step` | Event sequences into the ring reducer |
| `credential_parse` | Tokens, and payloads the test issuer signs |
| `join_request_check` | Proofs, and honest proofs signed at a chosen time, optionally with one bit flipped |
| `account_store_open` | Store records and self-notes, and plaintexts sealed then opened |
| `account_key_box_open` | Account-key boxes, and boxes sealed from the fuzzer's keys |
| `device_link` | The QR code, the number, the waiting device's step and the approval signature |
| `group_meta` | A group context's extensions in wire form, and a new name |
| `content_hint_peek` | Authenticated data read for its hint and the author's commitment; plaintexts read for a resend secret; bytes as a whole group message read without a key |
| `welcome_frame` | Bytes read as a join reads them, and Welcomes framed then read |
| `string_list` | Bytes read as the C door's string list, and lists written then read |
| `mls_message_process` | Bytes through `process_message` and `process_commit` on a real two-member group; plaintexts a member really seals; a member's real message with the fuzzer's mask XORed in, handed over before the real one |
| `welcome_join` | Bytes, and the real Welcome XOR a mask, through `welcome_group` and `join_from_welcome` |
| `key_package_check` | Bytes, and a real key package XOR a mask, through `key_package_identity` and `add_member` |
| `call_grant_payload` | Bytes into the call media grant's plaintext codec |
| `call_grant_open` | Sealed grants into `open_call_media_grant` under both suites' keys, checked against their call, leaves and recipient |
| `call_grant_sealed` | Real grants sealed under either suite, and chosen plaintexts sealed as a sealer seals them, with one field changed |
| `typing_open` | Typing frames, JSON sealed under a real group's typing key, and frames its member signs, through `open_typing_wire`, `parse_typing` and `Client::open_typing` |
| `epoch_envelope` | Version 3 envelopes under a chosen secret, and payloads sealed under an epoch secret, then changed |
| `device_seal_open` | Device seals, and seals between real device keys with the seal, the envelope or the recipient changed |
| `commit_entry` | Commit entries split as the commit door splits them, and entries built from carried proposals under a signed veto |
| `steward_frames` | Stamps and head-log copies, sealed ones changed, repair notices, and the steward key and admins a group meta names |
| `welcome_gap_block` | Welcome gap blocks, sealed gaps changed, and plaintexts no sealer writes, sealed as a sealer seals |
| `account_signatures` | Device certificates and revocations, and ones an account key signs, then changed |
| `account_store_signed` | Signed self-notes, transfer-key boxes and post-quantum account-key boxes, and ones sealed from the fuzzer's bytes, then changed |
| `device_link_exchange` | The device link's commitment and link-key signatures, arbitrary and honest, and the approver's step checked against its stated rule |
| `server_key_list` | Server key lists through `from_published_json`, both pin modes, the pin report and the narrowed list, against both carried sets |
| `own_devices` | A sibling's key package, row and approval, arbitrary or real with bits changed, through the seat check, the row check and the standing; the device list, a restore's answer and a revocation request as JSON |

Every function in `mls/core` that parses or opens bytes a peer or the server chose is one of these targets' doors, or reaches those bytes only through one:

- `Client::check_repair_notice` through `RepairNotice::parse`, and `Client::open_fetched_commit` through `open_log_copy` (`steward_frames`);
- `Client::verify_join_request`, `Client::verify_admitted_join_request` and `Client::first_sight_of_join_request` through the proof reader `check_join_request` uses (`join_request_check`);
- the live lane's `split_live_signature` and `Client::open_call_signal_json` through `call_envelope_open`, and `Client::open_typing_json` through `Client::open_typing` (`typing_open`);
- every `Client::process_message_*` variant through the path `process_message` takes, `Client::follow_leave` through `process_commit` (`mls_message_process`), and `Client::commit_strands` and `Client::judge_veto` through `split_carried` (`commit_entry`) and the message reader `process_message` uses;
- `Client::hold_envelope` and `Client::hold_envelope_sealed` through the envelope and device-seal openers (`envelope_open`, `epoch_envelope`, `device_seal_open`);
- `Client::join_from_welcome_at_head` and its variants through the Welcome frame reader and `join_from_welcome` (`welcome_frame`, `welcome_join`);
- `Client::update_credential` through `validate_token` (`credential_parse`), and `Client::stale_leaf_removable` through `verify_device_revocation` (`account_signatures`);
- `Client::replace_member`, `Client::reseat_person`, `Client::founding_refusals` and `Client::seat_founding` through the key-package reader `add_member` and `key_package_identity` use (`key_package_check`).

A function that only compares such bytes with what the device holds has no target: a head's epoch and verifier (`Client::confirm_head`, `Client::head_rolled_back`, `Client::settle_saved_commit`) and a leaf's expected key (`Client::remove_member`); tests pin those (`mls/core/tests/head_history.rs`, `head_lapse.rs` and `head_rollback.rs`). Nor does JSON a client writes for its own core (`Client::call_media_json`, `Client::adopt_own_device_trust`, the fixture doors).

The targets that drive a real group (`mls_message_process`, `welcome_join`, `key_package_check`, `typing_open`) share their devices through `mls/fuzz/fuzz_targets/common/mod.rs` and keep one group across inputs, as `call_envelope_open` does (`own_devices` builds a fresh phone for each input).
