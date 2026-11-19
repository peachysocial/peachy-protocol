// SPDX-License-Identifier: MIT
//! The C door's string list: a u32 big-endian count, then each item as a
//! u32 big-endian length and its UTF-8 bytes (`mls/cabi/src/lib.rs`,
//! `decode_string_list`). A caller's list crosses into the core through it,
//! and its lengths are the caller's. docs/mls-core.md §Fuzzing.
//!
//! Input layout: `mode (1) ‖ rest`.
//!
//! - Mode 0: `rest` is read as a list.
//! - Any other mode: `rest` is cut into items at every 0x00 byte, the items
//!   that are UTF-8 are written as a list, and the list is read back.
//!
//! - No input panics, and no count allocates past what the input can hold.
//! - A list is read exactly when an independent reading of the layout
//!   consumes every byte and every item is UTF-8; the empty input is the
//!   empty list. What is read writes back to the same bytes.
//! - A list written and read back is the same list, and so is no prefix of
//!   its bytes but the empty one, nor its bytes with one byte added.

#![no_main]

use libfuzzer_sys::fuzz_target;
use peachy_mls_cabi::fuzzing::{decode_string_list, encode_string_list};

fn expected(bytes: &[u8]) -> Option<Vec<String>> {
    if bytes.is_empty() {
        return Some(Vec::new());
    }
    let mut at = 0usize;
    let take = |at: &mut usize| -> Option<usize> {
        let end = at.checked_add(4)?;
        let head = bytes.get(*at..end)?;
        *at = end;
        Some(u32::from_be_bytes([head[0], head[1], head[2], head[3]]) as usize)
    };
    let count = take(&mut at)?;
    let mut items = Vec::new();
    for _ in 0..count {
        let len = take(&mut at)?;
        let end = at.checked_add(len)?;
        let item = bytes.get(at..end)?;
        at = end;
        items.push(String::from_utf8(item.to_vec()).ok()?);
    }
    (at == bytes.len()).then_some(items)
}

fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };
    if mode == 0 {
        let read = decode_string_list(rest);
        assert_eq!(read, expected(rest));
        if let Some(items) = read {
            if !rest.is_empty() {
                assert_eq!(encode_string_list(&items), rest);
            }
        }
        return;
    }
    let items: Vec<String> = rest
        .split(|&b| b == 0)
        .filter_map(|item| String::from_utf8(item.to_vec()).ok())
        .collect();
    let bytes = encode_string_list(&items);
    assert_eq!(decode_string_list(&bytes), Some(items));
    let cut = usize::from(mode) % bytes.len();
    if cut > 0 {
        assert_eq!(decode_string_list(&bytes[..cut]), None, "a prefix was read");
    }
    let mut longer = bytes.clone();
    longer.push(mode);
    assert_eq!(
        decode_string_list(&longer),
        None,
        "a trailing byte was read"
    );
});
