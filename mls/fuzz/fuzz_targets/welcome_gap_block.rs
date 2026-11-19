// SPDX-License-Identifier: MIT
//! The gap block of a version 2 Welcome frame, through `open_gap_block`: the
//! envelope secrets of the epochs a returning device's seat was held
//! through, sealed by the member who reseated it. `welcome_frame` covers the
//! frame around it. docs/mls-core.md §Fuzzing.
//!
//! The first input byte picks the layout (`mode % 3`), since no fuzzer forges
//! an AEAD tag; the key is `mls/fixtures/welcome-frame.json`'s:
//! - 0: the rest is a block;
//! - 1: `count (1) ‖ spec_len (1) ‖ spec ‖ entries`: `count` epochs, each
//!   `epoch (8, BE) ‖ secret (32)`, sealed with `seal_gap_block_with_nonce`,
//!   then `common::mutate`d by `spec`;
//! - 2: `nonce (12) ‖ plaintext`: the plaintext, cut or zero-filled to the
//!   block's one length, sealed with AES-256-GCM exactly as a sealer seals
//!   (the exporter label as associated data), so the count and fill checks
//!   after the AEAD see bytes no sealer writes.
//!
//! Asserted:
//! - No input panics.
//! - What opens is canonical: at most `WELCOME_GAP_EPOCHS` epochs, and
//!   sealed again under the block's own nonce it is the same block.
//! - A gap of at most `WELCOME_GAP_EPOCHS` seals; unchanged, it opens to
//!   exactly that gap; with any byte changed, it does not open.
//! - A raw plaintext opens exactly when its count is at most
//!   `WELCOME_GAP_EPOCHS` and every byte past its entries is zero.

#![no_main]

mod common;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use libfuzzer_sys::fuzz_target;
use peachy_mls_core::welcome_frame::{
    open_gap_block, seal_gap_block_with_nonce, WELCOME_GAP_BLOCK_BYTES, WELCOME_GAP_EPOCHS,
    WELCOME_GAP_EXPORTER_LABEL,
};

/// `seal-gap-two`'s key.
const KEY: [u8; 32] = [
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
    0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
];
const NONCE_BYTES: usize = 12;
const TAG_BYTES: usize = 16;
const ENTRY_BYTES: usize = 8 + 32;
const PLAINTEXT_BYTES: usize = WELCOME_GAP_BLOCK_BYTES - NONCE_BYTES - TAG_BYTES;

fn check_opened(block: &[u8]) -> Option<Vec<(u64, [u8; 32])>> {
    let gap = open_gap_block(&KEY, block).ok()?;
    assert!(gap.len() <= WELCOME_GAP_EPOCHS);
    assert_eq!(
        seal_gap_block_with_nonce(&KEY, &gap, &block[..NONCE_BYTES]).expect("an opened gap seals"),
        block,
        "an opened gap block did not seal back the same"
    );
    Some(gap.to_vec())
}

fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };
    match mode % 3 {
        0 => {
            let _ = check_opened(rest);
        }
        1 => {
            let [count, spec_len, rest @ ..] = rest else {
                return;
            };
            let Some((spec, entries)) = rest.split_at_checked(usize::from(*spec_len)) else {
                return;
            };
            let gap: Vec<(u64, [u8; 32])> = entries
                .chunks_exact(ENTRY_BYTES)
                .take(usize::from(*count))
                .map(|entry| {
                    (
                        u64::from_be_bytes(entry[..8].try_into().expect("8 bytes")),
                        entry[8..].try_into().expect("32 bytes"),
                    )
                })
                .collect();
            let sealed = seal_gap_block_with_nonce(&KEY, &gap, &[0x60; NONCE_BYTES]);
            assert_eq!(sealed.is_ok(), gap.len() <= WELCOME_GAP_EPOCHS);
            let Ok(block) = sealed else {
                return;
            };
            assert_eq!(block.len(), WELCOME_GAP_BLOCK_BYTES);
            let changed = common::mutate(&block, spec);
            let opened = check_opened(&changed);
            if changed == block {
                assert_eq!(opened.expect("a sealed gap block opens"), gap);
            } else {
                assert!(opened.is_none(), "a changed gap block opened");
            }
        }
        _ => {
            let Some((nonce, plaintext)) = rest.split_at_checked(NONCE_BYTES) else {
                return;
            };
            let mut plaintext = plaintext.to_vec();
            plaintext.resize(PLAINTEXT_BYTES, 0);
            let sealed = Aes256Gcm::new_from_slice(&KEY)
                .expect("a 32-byte key")
                .encrypt(
                    Nonce::from_slice(nonce),
                    Payload {
                        msg: &plaintext,
                        aad: WELCOME_GAP_EXPORTER_LABEL.as_bytes(),
                    },
                )
                .expect("AES-GCM seals");
            let block = [nonce, &sealed].concat();
            let count = usize::from(plaintext[0]);
            let canonical = count <= WELCOME_GAP_EPOCHS
                && plaintext[1 + count * ENTRY_BYTES..].iter().all(|&b| b == 0);
            let opened = check_opened(&block);
            assert_eq!(
                opened.is_some(),
                canonical,
                "a gap block's count {count} and fill were judged wrongly"
            );
            if let Some(gap) = opened {
                assert_eq!(gap.len(), count);
            }
        }
    }
});
