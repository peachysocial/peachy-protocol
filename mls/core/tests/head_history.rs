// SPDX-License-Identifier: MIT
//! A copy no head has matched yet is judged against its own history
//! (`Client::confirm_head`, docs/delivery.md §Two seats under one
//! group id).
//!
//! The server decides at a join whether a Welcome's seat counts as below
//! the head: one head above the Welcome files an honest seat as unconfirmed.
//! So the device keeps the head it joined against and the verifier of each
//! epoch its copy held: an honest head, even one that trails the copy,
//! confirms it, and a head that contradicts it is reported before any
//! Welcome can replace it. A Welcome that does replace a copy is drawn
//! against it, confirmed or not.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

mod support;
#[allow(unused_imports)]
use support::RemoveLeaf;

use peachy_mls_core::{Client, Error, Incoming};
use support::{client, head_of, issuer};

const G: &[u8] = b"9a1f0c3e-2b4d-4e6f-8a7b-0c1d2e3f4a5b";
const JUNK: [u8; 32] = [0x5a; 32];

fn take(c: &mut Client, welcome: &[u8], head: (u64, [u8; 32])) -> Result<Vec<u8>, Error> {
    let (group, _epoch) = c.welcome_group(welcome)?;
    assert_eq!(group, G);
    c.join_from_welcome_at_head(welcome, head.0, &head.1)
}

fn opens(reader: &mut Client, wire: &[u8], text: &[u8]) -> bool {
    matches!(
        reader.process_message(G, wire),
        Ok(Incoming::Application { plaintext, .. }) if plaintext == text
    )
}

/// Ada founds G with Mal, then removes Mal, who keeps the id. Only then is
/// Bo added, so Mal is in no roster Bo ever sees. Answers Bo's Welcome and
/// the head the honest server holds for it.
fn group_with_removed_mal(
    ada: &mut Client,
    mal: &mut Client,
    bo: &Client,
) -> (Vec<u8>, (u64, [u8; 32])) {
    ada.create_group(G).unwrap();
    let add_mal = ada
        .add_member(G, &mal.generate_key_package().unwrap())
        .unwrap();
    ada.merge_pending_commit(G).unwrap();
    take(mal, &add_mal.welcome.unwrap(), head_of(ada, G)).unwrap();
    let mal_leaf = ada.leaf_of_device(G, "device-mal").unwrap();
    ada.remove_leaf(G, mal_leaf).unwrap();
    ada.merge_pending_commit(G).unwrap();
    let add_bo = ada
        .add_member(G, &bo.generate_key_package().unwrap())
        .unwrap();
    ada.merge_pending_commit(G).unwrap();
    (add_bo.welcome.unwrap(), head_of(ada, G))
}

/// Mal founds a group of her own under G, well past Bo's epoch, and adds
/// Bo: its head is what a lying server names as G's. Bo takes it either way,
/// and draws it as Mal's, with Ada gone ([`assert_drawn_as_mals`]).
fn mals_group(
    server: &peachy_mls_core::issuer::TestIssuer,
    bo: &Client,
) -> (Vec<u8>, (u64, [u8; 32])) {
    let mut mal2 = client(server, 33, "actor-mal", "device-mal-2");
    mal2.create_group(G).unwrap();
    for _ in 0..20 {
        mal2.self_update(G).unwrap();
        mal2.merge_pending_commit(G).unwrap();
    }
    let add = mal2
        .add_member(G, &bo.generate_key_package().unwrap())
        .unwrap();
    mal2.merge_pending_commit(G).unwrap();
    (add.welcome.unwrap(), head_of(&mal2, G))
}

/// Bo took Mal's group, and its report says so: re-added by Mal, by name,
/// with Mal added and Ada gone.
fn assert_drawn_as_mals(bo: &mut Client, taken: Result<Vec<u8>, Error>) {
    assert_eq!(taken.unwrap(), G);
    let report = bo.take_rejoin_report(G).unwrap().expect("a report");
    assert_eq!(report.readded_by, "actor-mal");
    assert!(!report.readded_by_untrusted, "{report:?}");
    assert_eq!(report.added_actors, vec!["actor-mal"]);
    assert_eq!(report.departed_actors, vec!["actor-ada"]);
}

/// Ada and Bo talk in the real group for `rounds` epochs, Bo following
/// Ada's commits. After each, the server answers Bo's sweep with the head
/// one epoch behind his copy: `honest` gives that epoch's real verifier,
/// otherwise junk. Answers what each `confirm_head` said.
fn live_in_the_real_group(
    ada: &mut Client,
    bo: &mut Client,
    rounds: usize,
    honest: bool,
) -> Vec<bool> {
    let mut answers = Vec::new();
    for i in 0..rounds {
        let before = head_of(ada, G);
        let c = ada.self_update(G).unwrap();
        ada.merge_pending_commit(G).unwrap();
        bo.process_commit(G, &c.commit).unwrap();
        let text = format!("round {i}");
        let wire = ada.encrypt(G, text.as_bytes()).unwrap();
        assert!(opens(bo, &wire, text.as_bytes()), "bo reads ada");
        let back = bo.encrypt(G, b"ack").unwrap();
        assert!(opens(ada, &back, b"ack"), "ada reads bo");
        let trailing = if honest { before } else { (before.0, JUNK) };
        answers.push(bo.confirm_head(G, trailing.0, &trailing.1).unwrap());
    }
    answers
}

/// An honest server whose sweeps trail the copy confirms it, even after a
/// lie at join; the ex-member's group is then drawn as hers.
#[test]
fn an_honest_trailing_head_confirms_a_seat() {
    let server = issuer();
    let mut ada = client(&server, 1, "actor-ada", "device-ada");
    let mut mal = client(&server, 3, "actor-mal", "device-mal");
    let mut bo = client(&server, 2, "actor-bo", "device-bo");
    let (welcome, real_head) = group_with_removed_mal(&mut ada, &mut mal, &bo);
    // The head given at join names an epoch far beyond the Welcome.
    assert_eq!(
        take(&mut bo, &welcome, (real_head.0 + 100, JUNK)).unwrap(),
        G
    );

    let answers = live_in_the_real_group(&mut ada, &mut bo, 3, true);
    assert_eq!(
        answers,
        vec![true, true, true],
        "the trailing head confirms"
    );
    assert_eq!(bo.take_rejoin_report(G).unwrap(), None, "nothing to tell");

    let (imp_welcome, imp_head) = mals_group(&server, &bo);
    let taken = take(&mut bo, &imp_welcome, imp_head);
    assert_drawn_as_mals(&mut bo, taken);
}

/// A seat taken below an honest head is confirmed when the copy reaches the
/// head it was taken against.
#[test]
fn a_seat_below_the_head_is_confirmed_on_reaching_it() {
    let server = issuer();
    let mut ada = client(&server, 1, "actor-ada", "device-ada");
    let mut mal = client(&server, 3, "actor-mal", "device-mal");
    let mut bo = client(&server, 2, "actor-bo", "device-bo");
    let (welcome, _) = group_with_removed_mal(&mut ada, &mut mal, &bo);
    // Ada moves on before Bo takes his Welcome: it is honestly below.
    let update = ada.self_update(G).unwrap();
    ada.merge_pending_commit(G).unwrap();
    assert_eq!(take(&mut bo, &welcome, head_of(&ada, G)).unwrap(), G);
    bo.process_commit(G, &update.commit).unwrap();

    let (imp_welcome, imp_head) = mals_group(&server, &bo);
    let taken = take(&mut bo, &imp_welcome, imp_head);
    assert_drawn_as_mals(&mut bo, taken);
}

/// A lie at join followed by junk trailing heads: the copy is contested,
/// and the client is told so BEFORE the ex-member's group replaces it. The
/// replacement is then drawn as its own report.
#[test]
fn a_contradicting_head_is_reported_before_any_swap() {
    let server = issuer();
    let mut ada = client(&server, 1, "actor-ada", "device-ada");
    let mut mal = client(&server, 3, "actor-mal", "device-mal");
    let mut bo = client(&server, 2, "actor-bo", "device-bo");
    let (welcome, real_head) = group_with_removed_mal(&mut ada, &mut mal, &bo);
    let lie = (real_head.0 + 1, JUNK);
    assert_eq!(take(&mut bo, &welcome, lie).unwrap(), G);

    let answers = live_in_the_real_group(&mut ada, &mut bo, 10, false);
    assert!(answers.iter().all(|confirmed| !confirmed));
    let report = bo
        .take_rejoin_report(G)
        .unwrap()
        .expect("told before the swap");
    assert!(report.contested);
    assert!(report.readded_by.is_empty(), "nobody re-added this device");

    let (imp_welcome, imp_head) = mals_group(&server, &bo);
    let taken = take(&mut bo, &imp_welcome, imp_head);
    assert_drawn_as_mals(&mut bo, taken);
}

/// A head that names the copy's own epoch under another send key contests a
/// copy no head has matched, at once.
#[test]
fn a_head_at_the_copys_epoch_under_another_key_contests_it() {
    let server = issuer();
    let mut ada = client(&server, 1, "actor-ada", "device-ada");
    let mut mal = client(&server, 3, "actor-mal", "device-mal");
    let mut bo = client(&server, 2, "actor-bo", "device-bo");
    let (welcome, real_head) = group_with_removed_mal(&mut ada, &mut mal, &bo);
    assert_eq!(
        take(&mut bo, &welcome, (real_head.0 + 100, JUNK)).unwrap(),
        G
    );
    assert!(!bo.confirm_head(G, real_head.0, &JUNK).unwrap());
    assert!(
        bo.take_rejoin_report(G)
            .unwrap()
            .expect("a report")
            .contested
    );
    // A later head that matches confirms it after all.
    assert!(bo.confirm_head(G, real_head.0, &real_head.1).unwrap());
}

/// A server that refuses every commit of this device's own keeps a copy
/// unconfirmed (and its leaf unrotated); after enough refusals in a row the
/// client is told.
#[test]
fn own_commits_refused_in_a_row_are_told() {
    let server = issuer();
    let mut ada = client(&server, 1, "actor-ada", "device-ada");
    let mut mal = client(&server, 3, "actor-mal", "device-mal");
    let mut bo = client(&server, 2, "actor-bo", "device-bo");
    let (welcome, real_head) = group_with_removed_mal(&mut ada, &mut mal, &bo);
    assert_eq!(
        take(&mut bo, &welcome, (real_head.0 + 100, JUNK)).unwrap(),
        G
    );
    for _ in 0..15 {
        bo.self_update(G).unwrap();
        bo.clear_pending_commit(G).unwrap();
    }
    assert_eq!(bo.take_rejoin_report(G).unwrap(), None);
    bo.self_update(G).unwrap();
    bo.clear_pending_commit(G).unwrap();
    assert!(
        bo.take_rejoin_report(G)
            .unwrap()
            .expect("a report")
            .contested
    );
}
