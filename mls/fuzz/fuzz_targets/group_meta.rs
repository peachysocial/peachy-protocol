// SPDX-License-Identifier: MIT
//! The group's own state: a group context's extensions as a commit carries
//! them, read and rebuilt by `crate::group_meta`, the module the policy asks
//! whether a `GroupContextExtensions` proposal is a rename and nothing else.
//! docs/mls-core.md §Fuzzing.
//!
//! Input layout: `current length (2, big-endian) ‖ current ‖ rest`. `current`
//! is the group's extensions in TLS wire form (empty extensions when it does
//! not parse); `rest` is used twice, as a proposed extension set in wire form
//! and as a new meta value.
//!
//! - No input panics.
//! - A value is accepted exactly when it is 1 to `MAX_GROUP_META_BYTES` bytes.
//! - The set an honest rename builds carries that value, everything `current`
//!   carried besides, survives its own wire form unchanged, and is judged a
//!   rename of `current` and nothing else.

#![no_main]

use libfuzzer_sys::fuzz_target;
use openmls::prelude::{Extensions, GroupContext};
use peachy_mls_core::group_meta::{
    check_group_meta_value, group_context_extensions_with_meta, group_meta_change,
    group_meta_extension_type, group_meta_from_context,
};
use peachy_mls_core::MAX_GROUP_META_BYTES;
use tls_codec::{DeserializeBytes, Serialize};

fuzz_target!(|data: &[u8]| {
    let Some((len, rest)) = data.split_first_chunk::<2>() else {
        return;
    };
    let Some((current, rest)) = rest.split_at_checked(usize::from(u16::from_be_bytes(*len))) else {
        return;
    };
    let current =
        Extensions::<GroupContext>::tls_deserialize_exact_bytes(current).unwrap_or_default();

    // `rest` as a proposal someone else built.
    if let Ok(proposed) = Extensions::<GroupContext>::tls_deserialize_exact_bytes(rest) {
        if group_meta_change(&current, &proposed) {
            let value = group_meta_from_context(&proposed).expect("a rename carries a value");
            assert!(
                check_group_meta_value(&value).is_ok(),
                "a rename to a value the check refuses"
            );
        }
    }

    // `rest` as the new value.
    let value = rest;
    assert_eq!(
        check_group_meta_value(value).is_ok(),
        !value.is_empty() && value.len() <= MAX_GROUP_META_BYTES
    );
    let Ok(next) = group_context_extensions_with_meta(&current, value) else {
        return;
    };
    assert_eq!(group_meta_from_context(&next).as_deref(), Some(value));
    for extension in current.iter() {
        let kind = extension.extension_type();
        if kind != group_meta_extension_type()
            && kind != openmls::prelude::ExtensionType::RequiredCapabilities
        {
            assert!(
                next.iter().any(|e| e == extension),
                "a rename dropped an extension"
            );
        }
    }
    let wire = next
        .tls_serialize_detached()
        .expect("an extension set serializes");
    let back =
        Extensions::<GroupContext>::tls_deserialize_exact_bytes(&wire).expect("and parses back");
    assert_eq!(back, next);
    assert!(
        group_meta_change(&current, &next),
        "an honest rename was judged something else"
    );
    assert!(
        group_meta_change(&current, &back),
        "an honest rename, through the wire, was judged something else"
    );
});
