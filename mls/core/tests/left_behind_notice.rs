// SPDX-License-Identifier: MIT
//! A leaf a conversation still seats under a key its person moved off is
//! named there once, whichever conversations this device read in between
//! (docs/identity.md §Security code changed).
//!
//! A report settles a leaf only while its key is not the person's current
//! one. These states could keep such a report past that, and so silence the
//! notice for good:
//! - a store holding the leaf in both of a conversation's records (settled
//!   and reported);
//! - a conversation that reported a leaf whose key then became current and
//!   was left again while it was not read, held or forgotten for a rejoin;
//! - a report under the current key that a core with no pin-move prune left
//!   in the store.
//!
//! A read drops the first. A pin moving drops the others: it drops the
//! reports under the key it moved to and the key it moved off, and for a
//! copy forgotten for a rejoin records those keys for its read after the
//! rejoin.

#![cfg(feature = "test-forgery")]
#![allow(clippy::expect_used, clippy::unwrap_used)]

mod support;

use peachy_mls_core::issuer::{device_key_pair, TestIssuer};
use peachy_mls_core::{account_identity_public_key, Client, ClientConfig, MemoryKv, PeachyStorage};
use support::{client, client_on, device_seed, issuer, DAY, HOUR, NOW};

const G0: &[u8] = b"left-behind-ada-meets-bo";
const G: &[u8] = b"left-behind-shows-k2";
const G2: &[u8] = b"left-behind-k2-current";
const G3: &[u8] = b"left-behind-bo-moves-to-k3";

const K2: [u8; 32] = [0x61; 32];
const K3: [u8; 32] = [0x66; 32];

fn client_under(
    server: &TestIssuer,
    tag: u8,
    actor: &str,
    device: &str,
    account: &[u8],
    issued_at: i64,
) -> Client {
    let (_, public) = device_key_pair(&device_seed(tag));
    let token = server
        .issue_for_account(
            actor,
            device,
            &public,
            Some(account),
            issued_at,
            issued_at + 30 * DAY,
        )
        .expect("mint");
    let held = account_identity_public_key(account).expect("derive");
    let mut config = ClientConfig::new(token, device_seed(tag), server.trusted_keys().unwrap())
        .with_storage(PeachyStorage::in_memory())
        .with_own_account_identity(Some(held));
    config.clock = Some(Box::new(support::TestClock));
    Client::new(config).expect("client")
}

fn add(adder: &mut Client, joiner: &mut Client, group: &[u8]) {
    let kp = joiner.generate_key_package().expect("kp");
    let bundle = adder.add_member(group, &kp).expect("add");
    adder.merge_pending_commit(group).expect("merge");
    joiner
        .join_from_welcome(&bundle.welcome.expect("welcome"))
        .expect("join");
}

/// Ada knows Bo under K1 (G0). G is the first conversation to show Bo's new
/// key K2 (device bo-2): it reports him and the pin moves to K2 there.
///
/// `both_records`: G's records then hold bo-2's leaf as settled AND as
/// reported, as a core that kept a report under the key it made current
/// leaves them.
///
/// Ada's app then opens the store again. `read_g_first`: the foreground pass
/// reads G before anything else. Then Bo starts over under K3 (he lost the
/// phone bo-2 runs on), shown to Ada first in G3, while G still seats
/// bo-2's leaf under K2. Returns what G then says, asserting it says it once.
fn g_after_bo_moves(both_records: bool, read_g_first: bool) -> Vec<String> {
    let server = issuer();
    let kv = MemoryKv::new();
    let open = || PeachyStorage::open(Box::new(kv.clone())).expect("open");
    let mut ada = client_on(&server, 1, "actor-ada", "device-ada-phone", open());
    let mut bo1 = client(&server, 2, "actor-bo", "device-bo-1");
    ada.create_group(G0).unwrap();
    add(&mut ada, &mut bo1, G0);
    assert!(ada.observe_account_keys(G0).unwrap().is_empty());

    let mut bo2 = client_under(&server, 6, "actor-bo", "device-bo-2", &K2, NOW - 120);
    ada.create_group(G).unwrap();
    add(&mut ada, &mut bo2, G);
    assert_eq!(ada.observe_account_keys(G).unwrap(), vec!["actor-bo"]);
    assert!(ada.observe_account_keys(G).unwrap().is_empty());
    ada.flush().expect("flush");
    drop(ada);

    let k2 = account_identity_public_key(&K2).unwrap();
    {
        let store = open();
        assert_eq!(
            store.account_pins("actor-bo").unwrap(),
            vec![k2],
            "K2 is current"
        );
        let known = store
            .account_known_leaves(G)
            .unwrap()
            .expect("known record");
        assert_eq!(known.len(), 1, "G settled bo-2's leaf under K2");
        let reported = store
            .account_reported_leaves(G)
            .unwrap()
            .unwrap_or_default();
        assert!(
            !reported.contains(&known[0]),
            "a read drops a report under the key current then"
        );
        if both_records {
            let mut both = reported.clone();
            both.push(known[0]);
            store.set_account_reported_leaves(G, &both).unwrap();
            store.flush().expect("flush");
        }
    }

    let mut ada = client_on(&server, 1, "actor-ada", "device-ada-phone", open());
    if read_g_first {
        assert!(ada.observe_account_keys(G).unwrap().is_empty());
    }

    let mut bo3 = client_under(&server, 7, "actor-bo", "device-bo-3", &K3, NOW - 60);
    ada.create_group(G3).unwrap();
    add(&mut ada, &mut bo3, G3);
    assert_eq!(ada.observe_account_keys(G3).unwrap(), vec!["actor-bo"]);
    assert!(
        ada.leaf_of_device(G, "device-bo-2").is_ok(),
        "G still encrypts to bo-2's leaf under K2, the key Bo moved off"
    );
    let after = ada.observe_account_keys(G).unwrap();
    assert!(ada.observe_account_keys(G).unwrap().is_empty(), "once");
    after
}

/// A leaf both settled and reported in one conversation is named once the
/// person moves off its key, whether that conversation is read before the
/// move or the move is learned in another conversation first. A store
/// whose records this core wrote is the control.
#[test]
fn a_leaf_both_settled_and_reported_is_named_once_its_person_moves_off_its_key() {
    assert_eq!(g_after_bo_moves(false, false), vec!["actor-bo"], "control");
    assert_eq!(
        g_after_bo_moves(true, true),
        vec!["actor-bo"],
        "both records, G read before the move"
    );
    assert_eq!(
        g_after_bo_moves(true, false),
        vec!["actor-bo"],
        "both records, the move learned in G3 first"
    );
}

/// A leaf left behind under a key its person moved off is named once, and
/// then held as reported only, so neither a later read nor a reopened store
/// names it again.
#[test]
fn a_leaf_left_behind_is_named_once_and_then_held_as_reported_only() {
    let server = issuer();
    let kv = MemoryKv::new();
    let open = || PeachyStorage::open(Box::new(kv.clone())).expect("open");
    let mut ada = client_on(&server, 1, "actor-ada", "device-ada-phone", open());
    let mut bo1 = client(&server, 2, "actor-bo", "device-bo-1");
    ada.create_group(G0).unwrap();
    add(&mut ada, &mut bo1, G0);
    assert!(ada.observe_account_keys(G0).unwrap().is_empty());
    let mut bo3 = client_under(&server, 7, "actor-bo", "device-bo-3", &K3, NOW - 60);
    ada.create_group(G3).unwrap();
    add(&mut ada, &mut bo3, G3);
    assert_eq!(ada.observe_account_keys(G3).unwrap(), vec!["actor-bo"]);
    assert_eq!(
        ada.observe_account_keys(G0).unwrap(),
        vec!["actor-bo"],
        "G0 still seats bo-1 under the key Bo moved off"
    );
    ada.flush().expect("flush");
    drop(ada);
    {
        let store = open();
        let known = store
            .account_known_leaves(G0)
            .unwrap()
            .expect("known record");
        let reported = store
            .account_reported_leaves(G0)
            .unwrap()
            .expect("reported record");
        assert_eq!(reported.len(), 1, "G0 holds bo-1's leaf as reported");
        assert!(
            !known.contains(&reported[0]),
            "and no longer as settled under a current key"
        );
    }

    let mut ada = client_on(&server, 1, "actor-ada", "device-ada-phone", open());
    assert!(ada.observe_account_keys(G0).unwrap().is_empty());
    assert!(ada.observe_account_keys(G3).unwrap().is_empty());
}

/// Ada pins Bo's K1 in G0. Bo's device under K2, dated before that pin's
/// leaf, joins G: G reports it at arrival, and the pin stays K1 (an older
/// leaf never moves it). Then G2 shows Bo under K2 on a later leaf: the pin
/// moves to K2. When `read_g_while_k2_current`, G is read now. Then G3 shows
/// Bo under K3, and the pin moves off K2. Returns what G said in between and
/// after that, asserting it says the latter once.
fn g_after_k2_comes_and_goes(read_g_while_k2_current: bool) -> (Vec<String>, Vec<String>) {
    let server = issuer();
    let kv = MemoryKv::new();
    let open = || PeachyStorage::open(Box::new(kv.clone())).expect("open");
    let mut ada = client_on(&server, 1, "actor-ada", "device-ada-phone", open());
    let mut bo1 = client(&server, 2, "actor-bo", "device-bo-1");
    ada.create_group(G0).unwrap();
    add(&mut ada, &mut bo1, G0);
    assert!(ada.observe_account_keys(G0).unwrap().is_empty());
    let k1 = account_identity_public_key(&TestIssuer::test_account_key("actor-bo")).unwrap();
    let k2 = account_identity_public_key(&K2).unwrap();
    let k3 = account_identity_public_key(&K3).unwrap();
    assert_eq!(open().account_pins("actor-bo").unwrap(), vec![k1]);

    let mut bo2 = client_under(&server, 6, "actor-bo", "device-bo-2", &K2, NOW - 2 * HOUR);
    ada.create_group(G).unwrap();
    add(&mut ada, &mut bo2, G);
    assert_eq!(
        ada.observe_account_keys(G).unwrap(),
        vec!["actor-bo"],
        "G reports the K2 leaf when it arrives"
    );
    assert_eq!(
        open().account_pins("actor-bo").unwrap(),
        vec![k1],
        "pin stays K1"
    );
    assert!(ada.observe_account_keys(G).unwrap().is_empty());

    let mut bo2b = client_under(&server, 8, "actor-bo", "device-bo-2b", &K2, NOW - 120);
    ada.create_group(G2).unwrap();
    add(&mut ada, &mut bo2b, G2);
    assert_eq!(ada.observe_account_keys(G2).unwrap(), vec!["actor-bo"]);
    assert_eq!(
        open().account_pins("actor-bo").unwrap(),
        vec![k2],
        "K2 is current"
    );

    let mut between = Vec::new();
    if read_g_while_k2_current {
        between = ada.observe_account_keys(G).unwrap();
    }

    let mut bo3 = client_under(&server, 7, "actor-bo", "device-bo-3", &K3, NOW - 60);
    ada.create_group(G3).unwrap();
    add(&mut ada, &mut bo3, G3);
    assert_eq!(ada.observe_account_keys(G3).unwrap(), vec!["actor-bo"]);
    assert_eq!(
        open().account_pins("actor-bo").unwrap(),
        vec![k3],
        "K3 is current"
    );
    assert!(
        ada.leaf_of_device(G, "device-bo-2").is_ok(),
        "G still seats (and encrypts to) the K2 leaf"
    );
    let after = ada.observe_account_keys(G).unwrap();
    assert!(ada.observe_account_keys(G).unwrap().is_empty(), "once");
    (between, after)
}

/// A leaf a conversation reported at its arrival, whose key then became the
/// person's current one elsewhere and was left again, is named once there
/// after the move, whether or not that conversation was read while the key
/// was current.
#[test]
fn a_leaf_reported_while_its_key_came_and_went_unread_is_named_after_the_move() {
    let (between, after) = g_after_k2_comes_and_goes(true);
    assert_eq!(
        between,
        vec!["actor-bo"],
        "G catches up while K2 is current"
    );
    assert_eq!(
        after,
        vec!["actor-bo"],
        "and names Bo after he moves off K2"
    );
    let (between, after) = g_after_k2_comes_and_goes(false);
    assert!(between.is_empty());
    assert_eq!(after, vec!["actor-bo"], "G not read while K2 was current");
}

/// Ada pins Bo's K1 (G0). Cy's conversation G seats Bo's device under K2,
/// dated before the K1 pin's leaf: Ada's G reports it at arrival, and the pin
/// stays K1. Cy reseats Ada (a replace), and Ada forgets her copy for the
/// rejoin, either before (`forgotten_during_k2`) or after Bo's K2 tenure: G2
/// shows Bo under a later K2 leaf (the pin moves to K2), then G3 under K3
/// (the pin moves to K3). Ada rejoins G from the Welcome, whose tree still
/// seats bo-2 under K2. Returns what G says at its first read after the
/// rejoin, asserting it says it once and keeps no record of the moves.
fn rejoined_g(forgotten_during_k2: bool) -> Vec<String> {
    let server = issuer();
    let kv = MemoryKv::new();
    let open = || PeachyStorage::open(Box::new(kv.clone())).expect("open");
    let mut ada = client_on(&server, 1, "actor-ada", "device-ada-phone", open());
    let mut bo1 = client(&server, 2, "actor-bo", "device-bo-1");
    ada.create_group(G0).unwrap();
    add(&mut ada, &mut bo1, G0);
    assert!(ada.observe_account_keys(G0).unwrap().is_empty());
    let k1 = account_identity_public_key(&TestIssuer::test_account_key("actor-bo")).unwrap();
    let k2 = account_identity_public_key(&K2).unwrap();
    let k3 = account_identity_public_key(&K3).unwrap();
    assert_eq!(open().account_pins("actor-bo").unwrap(), vec![k1]);

    let mut cy = client(&server, 9, "actor-cy", "device-cy-phone");
    let mut bo2 = client_under(&server, 6, "actor-bo", "device-bo-2", &K2, NOW - 2 * HOUR);
    cy.create_group(G).unwrap();
    add(&mut cy, &mut bo2, G);
    add(&mut cy, &mut ada, G);
    assert_eq!(
        ada.observe_account_keys(G).unwrap(),
        vec!["actor-bo"],
        "G reports the K2 leaf when it arrives"
    );
    assert_eq!(
        open().account_pins("actor-bo").unwrap(),
        vec![k1],
        "pin stays K1"
    );
    assert!(ada.observe_account_keys(G).unwrap().is_empty());

    let ada_leaf = cy
        .leaf_of_device(G, "device-ada-phone")
        .expect("ada's leaf");
    let fresh = ada.generate_key_package().expect("kp");
    let replaced = cy.replace_member(G, ada_leaf, &fresh).expect("replace");
    cy.merge_pending_commit(G).expect("merge");
    if forgotten_during_k2 {
        ada.forget_group(G).expect("forget for the rejoin");
    }

    let mut bo2b = client_under(&server, 8, "actor-bo", "device-bo-2b", &K2, NOW - 120);
    ada.create_group(G2).unwrap();
    add(&mut ada, &mut bo2b, G2);
    assert_eq!(ada.observe_account_keys(G2).unwrap(), vec!["actor-bo"]);
    assert_eq!(
        open().account_pins("actor-bo").unwrap(),
        vec![k2],
        "K2 is current"
    );

    let mut bo3 = client_under(&server, 7, "actor-bo", "device-bo-3", &K3, NOW - 60);
    ada.create_group(G3).unwrap();
    add(&mut ada, &mut bo3, G3);
    assert_eq!(ada.observe_account_keys(G3).unwrap(), vec!["actor-bo"]);
    assert_eq!(
        open().account_pins("actor-bo").unwrap(),
        vec![k3],
        "K3 is current"
    );

    if !forgotten_during_k2 {
        ada.forget_group(G).expect("forget for the rejoin");
    }
    assert_eq!(
        !open().account_moved_while_forgotten(G).unwrap().is_empty(),
        forgotten_during_k2,
        "the moves made while the copy was forgotten are recorded for it"
    );
    ada.join_from_welcome(&replaced.welcome.expect("welcome"))
        .expect("rejoin");
    assert!(
        ada.leaf_of_device(G, "device-bo-2").is_ok(),
        "G still seats (and encrypts to) bo-2 under K2, the key Bo moved off"
    );
    let after = ada.observe_account_keys(G).unwrap();
    assert!(ada.observe_account_keys(G).unwrap().is_empty(), "once");
    assert!(
        open().account_moved_while_forgotten(G).unwrap().is_empty(),
        "the read after the rejoin drops the record of the moves"
    );
    after
}

/// A copy forgotten for a rejoin while a key its report named came and went
/// names that leaf at its first read after the rejoin, as a copy held
/// through those moves does.
#[test]
fn a_copy_forgotten_while_a_reported_key_came_and_went_names_the_leaf_after_the_rejoin() {
    assert_eq!(
        rejoined_g(false),
        vec!["actor-bo"],
        "control: the copy was held while K2 was current"
    );
    assert_eq!(
        rejoined_g(true),
        vec!["actor-bo"],
        "the copy was forgotten while K2 came and went"
    );
}

/// How the store holds a report of a leaf under the person's current key
/// when this core opens it.
#[derive(Clone, Copy, Debug)]
enum Written {
    /// As this core writes it: no report under the current key.
    ThisCore,
    /// As a core with no pin-move prune writes it: G reported bo-2's K2 leaf
    /// at arrival, and keeps the report after K2 became current in G2.
    ArrivalReportKept,
    /// As a core whose carry of the version-1 records carried their reports
    /// of leaves under the current key writes it: G0 holds bo-1's K1 leaf as
    /// reported, not as settled.
    CarriedReport,
}

/// Ada knows Bo under K1 (G0, bo-1). Unless `written` is `CarriedReport`, G
/// shows Bo's device bo-2 under K2, dated before the K1 pin's leaf, and
/// reports it at arrival; G2 then shows a later K2 leaf, and the pin moves
/// to K2. The store is written as `written` says and opened again. When
/// `read_first`, the conversation holding the report is read now (G, which
/// last showed Bo under K1, catches up to K2 there). Then Bo moves to K3,
/// shown first in G3. Returns what the conversation holding the report says
/// after that, asserting it says it once.
fn after_upgrade(written: Written, read_first: bool) -> Vec<String> {
    let server = issuer();
    let kv = MemoryKv::new();
    let open = || PeachyStorage::open(Box::new(kv.clone())).expect("open");
    let mut ada = client_on(&server, 1, "actor-ada", "device-ada-phone", open());
    let mut bo1 = client(&server, 2, "actor-bo", "device-bo-1");
    ada.create_group(G0).unwrap();
    add(&mut ada, &mut bo1, G0);
    assert!(ada.observe_account_keys(G0).unwrap().is_empty());
    let k1 = account_identity_public_key(&TestIssuer::test_account_key("actor-bo")).unwrap();
    let k2 = account_identity_public_key(&K2).unwrap();
    let k3 = account_identity_public_key(&K3).unwrap();

    let mut arrival_report = Vec::new();
    let (holder, device, current) = if let Written::CarriedReport = written {
        (G0, "device-bo-1", k1)
    } else {
        let mut bo2 = client_under(&server, 6, "actor-bo", "device-bo-2", &K2, NOW - 2 * HOUR);
        ada.create_group(G).unwrap();
        add(&mut ada, &mut bo2, G);
        assert_eq!(ada.observe_account_keys(G).unwrap(), vec!["actor-bo"]);
        ada.flush().expect("flush");
        arrival_report = open()
            .account_reported_leaves(G)
            .unwrap()
            .expect("reported record");
        assert_eq!(arrival_report.len(), 1, "G reported bo-2's leaf");
        let mut bo2b = client_under(&server, 8, "actor-bo", "device-bo-2b", &K2, NOW - 120);
        ada.create_group(G2).unwrap();
        add(&mut ada, &mut bo2b, G2);
        assert_eq!(ada.observe_account_keys(G2).unwrap(), vec!["actor-bo"]);
        (G, "device-bo-2", k2)
    };
    ada.flush().expect("flush");
    drop(ada);
    {
        let store = open();
        assert_eq!(store.account_pins("actor-bo").unwrap(), vec![current]);
        let reported = store
            .account_reported_leaves(holder)
            .unwrap()
            .unwrap_or_default();
        assert!(
            reported.is_empty(),
            "this core keeps no report under the current key"
        );
        match written {
            Written::ThisCore => {}
            Written::ArrivalReportKept => {
                store
                    .set_account_reported_leaves(G, &arrival_report)
                    .unwrap();
            }
            Written::CarriedReport => {
                let known = store
                    .account_known_leaves(G0)
                    .unwrap()
                    .expect("known record");
                assert_eq!(known.len(), 1, "G0 settled bo-1's leaf under K1");
                store.set_account_known_leaves(G0, &[]).unwrap();
                store.set_account_reported_leaves(G0, &known).unwrap();
            }
        }
        store.flush().expect("flush");
    }

    let mut ada = client_on(&server, 1, "actor-ada", "device-ada-phone", open());
    if read_first {
        let catches_up = holder == G;
        assert_eq!(
            !ada.observe_account_keys(holder).unwrap().is_empty(),
            catches_up
        );
        assert!(ada.observe_account_keys(holder).unwrap().is_empty());
    }
    let mut bo3 = client_under(&server, 7, "actor-bo", "device-bo-3", &K3, NOW - 60);
    ada.create_group(G3).unwrap();
    add(&mut ada, &mut bo3, G3);
    assert_eq!(ada.observe_account_keys(G3).unwrap(), vec!["actor-bo"]);
    assert_eq!(open().account_pins("actor-bo").unwrap(), vec![k3]);
    assert!(
        ada.leaf_of_device(holder, device).is_ok(),
        "the conversation still encrypts to the leaf under the key Bo moved off"
    );
    let after = ada.observe_account_keys(holder).unwrap();
    assert!(ada.observe_account_keys(holder).unwrap().is_empty(), "once");
    after
}

/// A report under the person's current key that a store holds from a core
/// with no pin-move prune (one kept after its key became current, or one its
/// carry of the version-1 records carried) settles nothing: once this core
/// opens the store, the conversation names the person once they move off
/// that key, whether it is read before the move or the move is learned
/// elsewhere first.
#[test]
fn a_report_under_the_current_key_another_core_left_is_named_once_the_person_moves_off_it() {
    for read_first in [false, true] {
        for written in [
            Written::ThisCore,
            Written::ArrivalReportKept,
            Written::CarriedReport,
        ] {
            assert_eq!(
                after_upgrade(written, read_first),
                vec!["actor-bo"],
                "{written:?}, read first: {read_first}"
            );
        }
    }
}
