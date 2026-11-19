// SPDX-License-Identifier: MIT
//! A key package through the doors a client calls on one it fetched from the
//! directory: `Client::key_package_identity` (whose credential is it) and
//! `Client::add_member` (add it to a group). docs/mls-core.md
//! §Fuzzing.
//!
//! The first input byte picks what the rest is:
//! - even: a key package, as the fuzzer wrote it;
//! - odd: `offset (2) ‖ mask`, XORed into a real key package another device
//!   published.
//!
//! - No input panics.
//! - What `add_member` accepts, `key_package_identity` accepts too: the two
//!   parse alike (its doc's promise).
//! - A changed copy of the real key package, if accepted at all, names the
//!   real one's actor, device and device key: the signature binds them.
//! - An add is staged, never merged, and cleared here, so the group stays at
//!   its epoch with its one member.

#![no_main]

mod common;

use std::cell::RefCell;

use common::{device, issuer, mutate, GROUP};
use libfuzzer_sys::fuzz_target;
use peachy_mls_core::{Client, PeachyIdentity};

struct World {
    ada: Client,
    key_package: Vec<u8>,
    identity: PeachyIdentity,
}

fn world() -> World {
    let issuer = issuer();
    let mut ada = device(&issuer, 1, "actor-ada", "device-ada");
    let cy = device(&issuer, 3, "actor-cy", "device-cy");
    ada.create_group(GROUP).expect("a group");
    let key_package = cy.generate_key_package().expect("a key package");
    let identity = ada
        .key_package_identity(&key_package)
        .expect("a key package")
        .expect("a credential the issuer signed");
    World {
        ada,
        key_package,
        identity,
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
            mutate(&world.key_package, rest)
        };
        let epoch = world.ada.epoch(GROUP).expect("epoch");
        let identity = world.ada.key_package_identity(&bytes);
        if mode % 2 == 1 {
            if let Ok(Ok(named)) = &identity {
                assert_eq!(named.actor_id, world.identity.actor_id);
                assert_eq!(named.device_id, world.identity.device_id);
                assert_eq!(
                    named.device_key, world.identity.device_key,
                    "a changed key package named another device key"
                );
            }
        }
        if world.ada.add_member(GROUP, &bytes).is_ok() {
            assert!(
                matches!(identity, Ok(Ok(_))),
                "add_member took a key package key_package_identity refused: {identity:?}"
            );
            world
                .ada
                .clear_pending_commit(GROUP)
                .expect("a staged add clears");
        }
        assert_eq!(world.ada.epoch(GROUP).expect("epoch"), epoch);
        assert!(
            !world.ada.has_pending_commit(GROUP).expect("pending"),
            "an add was left staged"
        );
    });
});
