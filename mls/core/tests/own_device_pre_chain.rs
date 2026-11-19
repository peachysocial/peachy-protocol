// SPDX-License-Identifier: MIT
//! Why the apps' own-seat switch is still off
//! (docs/identity.md §Who may certify a new install).
//!
//! The approval chain (`own_devices.rs` §Which keys this device trusts) only
//! knows what was recorded while it existed. Approvals are kept since
//! 2026-09-18, and a device remembers the device that let it in only since
//! 2026-10-28. A pair linked before that, the account's first device and the
//! second it approved, holds nothing about each other, so with the switch on
//! each would leave the other out of every group it starts. These pin that
//! gap, so whatever closes it (and lets the switch flip) changes them on
//! purpose.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

mod support;

use peachy_mls_core::issuer::device_key_pair;
use peachy_mls_core::{sign_device_approval, OwnDeviceVerdict};
use support::{client, device_seed, issuer};

const G: &[u8] = b"66666666-6666-4666-8666-666666666666";

fn public(tag: u8) -> [u8; 32] {
    device_key_pair(&device_seed(tag)).1
}

/// A phone and the laptop it linked, seated together the way builds before
/// the check seated a sibling: no verdict, no remembered approver.
fn linked_before_the_chain() -> (peachy_mls_core::Client, peachy_mls_core::Client) {
    let server = issuer();
    let mut phone = client(&server, 1, "actor-ada", "device-ada-phone");
    let mut laptop = client(&server, 2, "actor-ada", "device-ada-laptop");
    phone.create_group(G).unwrap();
    let key_package = laptop.generate_key_package().unwrap();
    let bundle = phone.add_member(G, &key_package).unwrap();
    phone.merge_pending_commit(G).unwrap();
    support::join_at_head(
        &mut laptop,
        &bundle.welcome.unwrap(),
        support::head_of(&phone, G),
    )
    .unwrap();
    (phone, laptop)
}

/// The laptop cannot vouch for the phone: the account's first device has no
/// approval, and the laptop never recorded it as its approver. Sharing a
/// group vouches for nothing.
#[test]
fn a_laptop_linked_before_the_chain_cannot_vouch_for_the_first_device() {
    let (phone, mut laptop) = linked_before_the_chain();
    let phone_package = phone.generate_key_package().unwrap();
    assert_eq!(
        laptop.check_own_device_approval(&phone_package, "", &[]),
        OwnDeviceVerdict::Unanchored
    );
}

/// The phone vouches for the laptop only through the approval it signed,
/// which the server keeps since 2026-09-18. A laptop linked earlier has none.
#[test]
fn the_first_device_vouches_only_through_a_kept_approval() {
    let (mut phone, laptop) = linked_before_the_chain();
    let laptop_package = laptop.generate_key_package().unwrap();
    assert_eq!(
        phone.check_own_device_approval(&laptop_package, "", &[]),
        OwnDeviceVerdict::Unanchored
    );
    let approval = sign_device_approval(&device_seed(1), "device-ada-laptop", &public(2)).unwrap();
    assert_eq!(
        phone.check_own_device_approval(&laptop_package, "device-ada-phone", &approval),
        OwnDeviceVerdict::Approved
    );
}
