// SPDX-License-Identifier: MIT
//! A Welcome through the doors a joining device calls: `Client::welcome_group`
//! (the peek that finds the group's head first) and then
//! `Client::join_from_welcome`, which read the padded frame and hand the rest
//! to OpenMLS. docs/mls-core.md §Fuzzing.
//!
//! The joiner published a last-resort key package, which a Welcome does not
//! use up, and a member added it once, so a real Welcome for it exists. The
//! first input byte picks what the rest is:
//! - even: a Welcome, as the fuzzer wrote it;
//! - odd: `offset (2) ‖ mask`, XORed into that real Welcome.
//!
//! - No input panics.
//! - Whatever joins, joins the one group a member really welcomed this device
//!   to, and at the epoch the peek read off the same bytes.
//! - Nothing refused before it keeps the device from taking the real
//!   Welcome: the real bytes, the first time they come, join.

#![no_main]

mod common;

use std::cell::RefCell;

use common::{device, issuer, mutate, GROUP};
use libfuzzer_sys::fuzz_target;
use peachy_mls_core::Client;

struct World {
    joiner: Client,
    welcome: Vec<u8>,
    joined: bool,
}

fn world() -> World {
    let issuer = issuer();
    let mut ada = device(&issuer, 1, "actor-ada", "device-ada");
    let joiner = device(&issuer, 2, "actor-bo", "device-bo");
    ada.create_group(GROUP).expect("a group");
    let (key_package, _) = joiner
        .generate_last_resort_key_package_with_ref()
        .expect("a last-resort key package");
    let added = ada.add_member(GROUP, &key_package).expect("an add");
    ada.merge_pending_commit(GROUP).expect("merged");
    World {
        joiner,
        welcome: added.welcome.expect("a Welcome"),
        joined: false,
    }
}

thread_local! {
    static WORLD: RefCell<World> = RefCell::new(world());
}

fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };
    WORLD.with(|cell| {
        let world = &mut *cell.borrow_mut();
        let bytes = if mode % 2 == 0 {
            rest.to_vec()
        } else {
            mutate(&world.welcome, rest)
        };
        let peeked = world.joiner.welcome_group(&bytes);
        let real_first = bytes == world.welcome && !world.joined;
        let result = world.joiner.join_from_welcome(&bytes);
        if real_first {
            assert!(result.is_ok(), "the real Welcome did not join: {result:?}");
        }
        let Ok(joined) = result else {
            return;
        };
        world.joined = true;
        assert_eq!(joined, GROUP, "a Welcome joined a group no member welcomed");
        if let Ok((group, epoch)) = peeked {
            assert_eq!(group, joined, "the peek and the join read different groups");
            assert_eq!(
                world.joiner.epoch(&joined).expect("epoch"),
                epoch,
                "the join seated the device at another epoch than the peek read"
            );
        }
    });
});
