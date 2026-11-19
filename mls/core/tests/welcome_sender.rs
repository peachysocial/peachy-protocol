// SPDX-License-Identifier: MIT
//! WHO SEATED THIS DEVICE (`Client::welcome_sender`): the actor whose commit
//! a Welcome came from, read from the Welcome's verified GroupInfo signer and
//! kept with the group's state.
//!
//! What clients ask it (docs/account-store.md §Record values, **Leaving a
//! group**): a Welcome into a group this person LEFT re-adds them only when
//! somebody ELSE added them. A Welcome from one of their own devices is a
//! linked device being seated by a device that had not yet heard of the
//! leave, and must not undo it.

mod support;

use peachy_mls_core::{MemoryKv, PeachyStorage};
use support::{client, client_on, issuer};

const GROUP: &[u8] = b"peachy-group-welcome-sender";

#[test]
fn a_welcome_names_the_actor_whose_commit_seated_this_device() {
    let server = issuer();
    let mut phone = client(&server, 1, "actor-ada", "device-ada-phone");
    let mut laptop = client(&server, 2, "actor-ada", "device-ada-laptop");
    let mut bo = client(&server, 3, "actor-bo", "device-bo-phone");

    // The founder holds no Welcome sender: nobody seated it.
    phone.create_group(GROUP).expect("create");
    assert_eq!(phone.welcome_sender(GROUP).expect("founder"), None);

    // Somebody else adds bo: bo's Welcome names ada.
    let kp = bo.generate_key_package().expect("bo kp");
    let add = phone.add_member(GROUP, &kp).expect("add bo");
    phone.merge_pending_commit(GROUP).expect("merge");
    bo.join_from_welcome(&add.welcome.expect("welcome"))
        .expect("bo joins");
    assert_eq!(
        bo.welcome_sender(GROUP).expect("bo").as_deref(),
        Some("actor-ada")
    );

    // bo seats ada's laptop: the laptop's Welcome names bo, not ada.
    let kp = laptop.generate_key_package().expect("laptop kp");
    let add = bo.add_member(GROUP, &kp).expect("add laptop");
    bo.merge_pending_commit(GROUP).expect("merge");
    laptop
        .join_from_welcome(&add.welcome.expect("welcome"))
        .expect("laptop joins");
    assert_eq!(
        laptop.welcome_sender(GROUP).expect("laptop").as_deref(),
        Some("actor-bo")
    );

    // A group this device does not hold has no Welcome sender.
    assert_eq!(
        laptop.welcome_sender(b"no-such-group").expect("unknown"),
        None
    );

    // Forgetting the group forgets who seated it.
    laptop.forget_group(GROUP).expect("forget");
    assert_eq!(laptop.welcome_sender(GROUP).expect("forgotten"), None);
}

#[test]
fn a_linked_device_seated_by_its_own_person_names_that_person_after_a_restart() {
    let server = issuer();
    let mut phone = client(&server, 1, "actor-ada", "device-ada-phone");
    let kv = MemoryKv::new();
    let open = || PeachyStorage::open(Box::new(kv.clone())).expect("open");
    let mut laptop = client_on(&server, 2, "actor-ada", "device-ada-laptop", open());

    phone.create_group(GROUP).expect("create");
    let kp = laptop.generate_key_package().expect("laptop kp");
    let add = phone.add_member(GROUP, &kp).expect("seat laptop");
    phone.merge_pending_commit(GROUP).expect("merge");
    laptop
        .join_from_welcome(&add.welcome.expect("welcome"))
        .expect("laptop joins");
    // Its own actor: one of its person's own devices seated it.
    assert_eq!(
        laptop.welcome_sender(GROUP).expect("laptop").as_deref(),
        Some("actor-ada")
    );
    drop(laptop);

    // Kept with the group's state: a reopened client still knows.
    let reopened = client_on(&server, 2, "actor-ada", "device-ada-laptop", open());
    assert_eq!(
        reopened.welcome_sender(GROUP).expect("reopened").as_deref(),
        Some("actor-ada")
    );
}
