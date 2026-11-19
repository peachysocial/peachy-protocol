// SPDX-License-Identifier: MIT
//! Typing frames through their whole receive path: `open_typing_wire` (the
//! exporter-keyed AEAD and the padding), `parse_typing` (the strict JSON
//! reader) and `Client::open_typing` (the leaf signature and the replay
//! window), on a real one-member group. docs/mls-core.md §Fuzzing.
//!
//! The first input byte picks how far in the fuzzer's bytes are placed, since
//! no fuzzer forges an AEAD tag or a signature:
//! - 0: the bytes are a whole frame, opened by the group and, under the fixed
//!   key of `mls/fixtures/formats/typing.json`, by `open_typing_wire`;
//! - 1: they are a frame's JSON, sealed under the group's real typing key;
//! - 2: they describe a frame the member's own leaf signs, `typing (1) ‖
//!   actor (1) ‖ epoch delta (1) ‖ spec`: `typing`'s bit 0 is `t`, `actor`'s
//!   bit 0 names another actor than the signer's, a nonzero `epoch delta`
//!   signs it for another epoch, and `spec` (`common::mutate`) changes the
//!   JSON after signing;
//! - 3: they are text for `parse_typing` alone.
//!
//! Asserted:
//! - No input panics, and no frame moves the group's epoch.
//! - `parse_typing` reads canonically: what it reads, written by
//!   `encode_typing`, reads back the same.
//! - A frame opens only if its JSON parses, names the member's own actor and
//!   carries a signature its leaf made: an unsigned frame never opens.
//! - The frame the member signs, unchanged, for its own actor and epoch,
//!   opens with its words; signed for another epoch or another actor, it does
//!   not open.

#![no_main]

mod common;

use std::cell::{Cell, RefCell};

use libfuzzer_sys::fuzz_target;
use peachy_mls_core::call::CALL_LIVE_MAX_SKEW_MS;
use peachy_mls_core::issuer::device_key_pair;
use peachy_mls_core::steward::sign_statement;
use peachy_mls_core::typing::{
    encode_typing, open_typing_wire, parse_typing, seal_typing_wire, typing_signature_holds,
    typing_statement, TypingFrame, TYPING_EXPORTER_LABEL, TYPING_KEY_BYTES,
};
use peachy_mls_core::Client;

const ACTOR: &str = "actor-ada";
/// The member's leaf seed, `common::device`'s for `n = 1`.
const SEED: [u8; 32] = {
    let mut seed = [0u8; 32];
    seed[0] = 1;
    seed
};
const NONCE: [u8; 12] = [0x0b; 12];
/// `seal/start`'s key in `mls/fixtures/formats/typing.json`.
const FIXTURE_KEY: [u8; 32] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
    26, 27, 28, 29, 30, 31,
];

struct Member {
    client: Client,
    key: Vec<u8>,
}

fn member() -> Member {
    let mut client = common::device(&common::issuer(), 1, ACTOR, "device-ada");
    client.create_group(common::GROUP).expect("a group");
    let key = client
        .export_secret(
            common::GROUP,
            TYPING_EXPORTER_LABEL,
            common::GROUP,
            TYPING_KEY_BYTES,
        )
        .expect("the typing key");
    Member { client, key }
}

thread_local! {
    static MEMBER: RefCell<Member> = RefCell::new(member());
    static SENT: Cell<u64> = const { Cell::new(0) };
}

/// A fresh stamp: the stamps walk the whole clock bound and wrap, as
/// `call_envelope_open`'s do, so none is one the window still holds.
fn next_stamp() -> u64 {
    let n = SENT.with(|sent| {
        let n = sent.get();
        sent.set(n + 1);
        n
    });
    let now_ms = u64::try_from(common::NOW).expect("positive") * 1000;
    now_ms - CALL_LIVE_MAX_SKEW_MS + n % (2 * CALL_LIVE_MAX_SKEW_MS + 1)
}

fn parses_canonically(wire: &str) -> Option<TypingFrame> {
    let frame = parse_typing(wire)?;
    assert_eq!(
        parse_typing(&encode_typing(&frame)).as_ref(),
        Some(&frame),
        "a parsed frame did not read back the same"
    );
    Some(frame)
}

fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };
    MEMBER.with(|cell| {
        let member = &mut *cell.borrow_mut();
        let epoch = member.client.epoch(common::GROUP).expect("epoch");
        let (_, leaf_key) = device_key_pair(&SEED);

        // The frame, the JSON sealed in it when the target sealed it, and the
        // words a frame the member signed must open to.
        let (frame, wire, honest): (Vec<u8>, Option<String>, Option<TypingFrame>) = match mode % 4 {
            0 => {
                if let Some(text) = open_typing_wire(&FIXTURE_KEY, rest) {
                    let _ = parses_canonically(&text);
                }
                (rest.to_vec(), None, None)
            }
            1 => {
                let text = String::from_utf8_lossy(rest).into_owned();
                let Ok(frame) = seal_typing_wire(&member.key, &NONCE, &text) else {
                    return;
                };
                (frame, Some(text), None)
            }
            2 => {
                let [typing, actor, epoch_delta, spec @ ..] = rest else {
                    return;
                };
                let mut words = TypingFrame {
                    actor_id: if actor & 1 == 0 {
                        ACTOR.to_owned()
                    } else {
                        "actor-bob".to_owned()
                    },
                    typing: typing & 1 == 1,
                    stamp_ms: Some(next_stamp()),
                    signature: None,
                };
                let signed_epoch = epoch.wrapping_add(u64::from(*epoch_delta));
                let statement = typing_statement(common::GROUP, signed_epoch, &words);
                words.signature = Some(sign_statement(&SEED, &statement));
                let text = encode_typing(&words);
                let changed = common::mutate(text.as_bytes(), spec);
                let unchanged = changed == text.as_bytes();
                let text = String::from_utf8_lossy(&changed).into_owned();
                let Ok(frame) = seal_typing_wire(&member.key, &NONCE, &text) else {
                    return;
                };
                let honest = (unchanged && *epoch_delta == 0 && actor & 1 == 0).then_some(words);
                if unchanged && honest.is_none() {
                    let opened = member
                        .client
                        .open_typing(common::GROUP, &frame)
                        .expect("the group is held");
                    assert!(
                        opened.is_none(),
                        "a frame signed for another epoch or actor opened: {opened:?}"
                    );
                    return;
                }
                (frame, Some(text), honest)
            }
            _ => {
                let _ = parses_canonically(&String::from_utf8_lossy(rest));
                return;
            }
        };

        let opened = member
            .client
            .open_typing(common::GROUP, &frame)
            .expect("the group is held");
        assert_eq!(
            member.client.epoch(common::GROUP).expect("epoch"),
            epoch,
            "a typing frame moved the group"
        );
        if let Some(words) = &honest {
            let opened = opened
                .as_ref()
                .expect("the member's own signed frame opened");
            assert_eq!(opened.actor_id, words.actor_id);
            assert_eq!(opened.typing, words.typing);
        }
        let Some(opened) = opened else {
            return;
        };
        let parsed = match &wire {
            Some(text) => parse_typing(text),
            None => open_typing_wire(&member.key, &frame).and_then(|text| parse_typing(&text)),
        }
        .expect("a frame opened whose JSON does not parse");
        assert_eq!(opened.actor_id, parsed.actor_id);
        assert_eq!(opened.typing, parsed.typing);
        assert_eq!(opened.actor_id, ACTOR, "a frame opened for another actor");
        assert!(
            typing_signature_holds(&leaf_key, common::GROUP, epoch, &parsed),
            "a frame opened that the leaf did not sign"
        );
    });
});
