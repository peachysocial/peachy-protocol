// SPDX-License-Identifier: MIT
//! An incoming MLS message through the doors every client calls for one:
//! `Client::process_message` (the application door) and
//! `Client::process_commit` (the commit door), on a real two-member group.
//! docs/mls-core.md §Fuzzing.
//!
//! The first input byte picks what the rest is:
//! - 0: a message for the application door, as the fuzzer wrote it;
//! - 1: a message for the commit door, as the fuzzer wrote it;
//! - 2: a plaintext the other member really seals and sends;
//! - 3: `offset (2) ‖ mask`, XORed into a message the other member really
//!   sealed (no fuzzer forges an AEAD tag, so this is how bytes reach the
//!   ratchet), handed over before the real one.
//!
//! - No input panics, and none moves the group: no one signs a commit here.
//! - A message the other member sealed opens to its plaintext, and the same
//!   bytes again are `Duplicate` (docs/mls-core.md §Receiving).
//! - A changed copy of a real message never opens, and leaves the real one
//!   its key: the real one still opens after it.

#![no_main]

mod common;

use std::cell::RefCell;

use common::{device, issuer, mutate, GROUP};
use libfuzzer_sys::fuzz_target;
use peachy_mls_core::{Client, Error, Incoming};

struct World {
    ada: Client,
    bo: Client,
    sent: u64,
}

fn world() -> World {
    let issuer = issuer();
    let mut ada = device(&issuer, 1, "actor-ada", "device-ada");
    let mut bo = device(&issuer, 2, "actor-bo", "device-bo");
    ada.create_group(GROUP).expect("a group");
    let key_package = bo.generate_key_package().expect("a key package");
    let added = ada.add_member(GROUP, &key_package).expect("an add");
    ada.merge_pending_commit(GROUP).expect("merged");
    bo.join_from_welcome(&added.welcome.expect("a Welcome"))
        .expect("joined");
    World { ada, bo, sent: 0 }
}

thread_local! {
    static WORLD: RefCell<World> = RefCell::new(world());
}

/// `message` opens on `bo` to `words`, and is a duplicate the second time.
fn opens_once(bo: &mut Client, message: &[u8], words: &[u8]) {
    match bo.process_message(GROUP, message) {
        Ok(Incoming::Application { plaintext, .. }) => {
            assert_eq!(plaintext, words, "a real message opened to other words")
        }
        other => panic!("a real message did not open: {other:?}"),
    }
    assert!(
        matches!(bo.process_message(GROUP, message), Err(Error::Duplicate(_))),
        "a message opened twice was not a duplicate"
    );
}

fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };
    WORLD.with(|cell| {
        let world = &mut *cell.borrow_mut();
        let epoch = world.bo.epoch(GROUP).expect("epoch");
        match mode % 4 {
            0 => {
                let result = world.bo.process_message(GROUP, rest);
                assert!(
                    !matches!(result, Ok(Incoming::Commit(_))),
                    "the application door merged a commit"
                );
            }
            1 => {
                let _ = world.bo.process_commit(GROUP, rest);
            }
            2 => {
                let Ok(real) = world.ada.encrypt(GROUP, rest) else {
                    return;
                };
                opens_once(&mut world.bo, &real, rest);
            }
            _ => {
                world.sent += 1;
                let words = format!("message {}", world.sent);
                let real = world
                    .ada
                    .encrypt(GROUP, words.as_bytes())
                    .expect("a member seals");
                let copy = mutate(&real, rest);
                if copy != real {
                    let result = world.bo.process_message(GROUP, &copy);
                    assert!(
                        !matches!(result, Ok(Incoming::Application { .. })),
                        "a changed copy of a message opened"
                    );
                    assert!(
                        !matches!(result, Err(Error::Duplicate(_))),
                        "a changed copy of a message read as a duplicate"
                    );
                }
                opens_once(&mut world.bo, &real, words.as_bytes());
            }
        }
        assert_eq!(
            world.bo.epoch(GROUP).expect("epoch"),
            epoch,
            "a message moved the group"
        );
    });
});
