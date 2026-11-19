// SPDX-License-Identifier: MIT
//! A catch-up reads the LANE before the ROWS, and must still open the rows.
//!
//! The shape this pins (`OUT_OF_ORDER_TOLERANCE` in crate::group): one of
//! Alice's devices is offline for a night in a sealed DM. Meanwhile her phone
//! sends messages AND, on the group's own lane, the sealed read and delivery
//! marks it sends for every message it reads. On return the offline device
//! replays the lane first, in delivery order, and only then decrypts the
//! messages. With OpenMLS's default window of five, every message more than
//! five generations behind the phone's last mark would be "too distant in the
//! past" and draw as unreadable. These tests replay that interleaving, prove it
//! fails at a window of five, and prove the open-time upgrade widens a group
//! stored with the narrow window.

mod support;

use peachy_mls_core::{
    Client, Incoming, MemoryKv, PeachyStorage, MAXIMUM_FORWARD_DISTANCE, OUT_OF_ORDER_TOLERANCE,
};
use support::{client, client_on, issuer};

const GROUP: &[u8] = b"00000000-0000-4000-8000-00000000d0d0";

/// What one member sent, in the order it sent it: `Row` is a message,
/// `Lane` a read or delivery mark on the group's lane.
#[derive(Clone, Copy)]
enum Sent {
    Row(&'static str),
    Lane,
}

/// Alice's phone in one epoch of the DM: four marks, a message twelve
/// generations behind the last mark, another nine behind, and one a single
/// generation behind.
const PHONE_EPOCH: &[Sent] = &[
    Sent::Lane,
    Sent::Lane,
    Sent::Lane,
    Sent::Lane,
    Sent::Row("first"),
    Sent::Lane,
    Sent::Lane,
    Sent::Row("second"),
    Sent::Lane,
    Sent::Lane,
    Sent::Lane,
    Sent::Lane,
    Sent::Lane,
    Sent::Lane,
    Sent::Lane,
    Sent::Row("third"),
    Sent::Lane,
];

fn dm(kv: Option<MemoryKv>) -> (Client, Client) {
    let server = issuer();
    let mut phone = client(&server, 1, "actor-alice", "device-alice-phone");
    let mut browser = match kv {
        Some(kv) => client_on(
            &server,
            2,
            "actor-alice",
            "device-alice-browser",
            PeachyStorage::open(Box::new(kv)).expect("store"),
        ),
        None => client(&server, 2, "actor-alice", "device-alice-browser"),
    };
    phone.create_group(GROUP).expect("create");
    let kp = browser.generate_key_package().expect("key package");
    let added = phone.add_member(GROUP, &kp).expect("add browser");
    phone.merge_pending_commit(GROUP).expect("merge");
    browser
        .join_from_welcome(&added.welcome.expect("welcome"))
        .expect("browser joins");
    (phone, browser)
}

/// A message row: the words it was sent with, and its ciphertext.
type Row = (&'static str, Vec<u8>);

/// Encrypt the script; answer (lane ciphertexts in order, rows with words).
fn send(phone: &mut Client, script: &[Sent]) -> (Vec<Vec<u8>>, Vec<Row>) {
    let mut lane = Vec::new();
    let mut rows = Vec::new();
    for (i, item) in script.iter().enumerate() {
        match item {
            Sent::Lane => lane.push(
                phone
                    .encrypt(
                        GROUP,
                        format!("{{\"peachy\":\"receipt\",\"n\":{i}}}").as_bytes(),
                    )
                    .expect("encrypt mark"),
            ),
            Sent::Row(words) => rows.push((
                *words,
                phone.encrypt(GROUP, words.as_bytes()).expect("encrypt row"),
            )),
        }
    }
    (lane, rows)
}

/// The browser's catch-up: the whole lane first, then every row.
fn catch_up(
    browser: &mut Client,
    lane: &[Vec<u8>],
    rows: &[(&str, Vec<u8>)],
) -> Vec<Result<String, String>> {
    for mark in lane {
        match browser
            .process_message(GROUP, mark)
            .expect("a lane mark opens")
        {
            Incoming::Application { .. } => {}
            other => panic!("expected an application message, got {other:?}"),
        }
    }
    rows.iter()
        .map(|(_, ct)| match browser.process_message(GROUP, ct) {
            Ok(Incoming::Application { plaintext, .. }) => {
                Ok(String::from_utf8(plaintext).expect("utf8"))
            }
            Ok(other) => Err(format!("{other:?}")),
            Err(err) => Err(err.to_string()),
        })
        .collect()
}

#[test]
fn the_window_covers_what_the_lane_can_move_past() {
    const { assert!(OUT_OF_ORDER_TOLERANCE >= 1000) };
    assert_eq!(OUT_OF_ORDER_TOLERANCE, MAXIMUM_FORWARD_DISTANCE);
}

#[test]
fn rows_opened_after_the_lane_all_read_the_way_they_were_sent() {
    let (mut phone, mut browser) = dm(None);
    let (lane, rows) = send(&mut phone, PHONE_EPOCH);
    let opened = catch_up(&mut browser, &lane, &rows);
    let words: Vec<&str> = rows.iter().map(|(w, _)| *w).collect();
    assert_eq!(
        opened,
        words.iter().map(|w| Ok(w.to_string())).collect::<Vec<_>>(),
        "every row must open after the lane replay, not only the last few"
    );
}

#[test]
fn a_week_of_marks_ahead_of_a_row_still_leaves_it_readable() {
    let (mut phone, mut browser) = dm(None);
    let mut script = vec![Sent::Row("from a week ago")];
    script.extend(std::iter::repeat_n(Sent::Lane, 900));
    let (lane, rows) = send(&mut phone, &script);
    assert_eq!(
        catch_up(&mut browser, &lane, &rows),
        vec![Ok("from a week ago".to_string())]
    );
}

#[cfg(feature = "test-forgery")]
#[test]
fn a_window_of_five_loses_the_rows_more_than_five_behind() {
    let (mut phone, mut browser) = dm(None);
    browser
        .forge_stored_out_of_order_tolerance(GROUP, 5)
        .expect("forge");
    let (lane, rows) = send(&mut phone, PHONE_EPOCH);
    let opened = catch_up(&mut browser, &lane, &rows);
    assert!(opened[0].is_err(), "first: 12 behind, lost at five");
    assert!(opened[1].is_err(), "second: 9 behind, lost at five");
    assert_eq!(
        opened[2],
        Ok("third".to_string()),
        "third: 1 behind, inside the window"
    );
}

#[cfg(feature = "test-forgery")]
#[test]
fn a_group_stored_with_the_old_window_is_widened_when_it_is_opened() {
    let kv = MemoryKv::new();
    let (mut phone, mut browser) = dm(Some(kv.clone()));
    browser
        .forge_stored_out_of_order_tolerance(GROUP, 5)
        .expect("forge");
    drop(browser);
    // The next build opens the same store.
    let server = issuer();
    let mut browser = client_on(
        &server,
        2,
        "actor-alice",
        "device-alice-browser",
        PeachyStorage::open(Box::new(kv)).expect("store"),
    );
    let (lane, rows) = send(&mut phone, PHONE_EPOCH);
    let opened = catch_up(&mut browser, &lane, &rows);
    assert!(
        opened.iter().all(|r| r.is_ok()),
        "the reopened group must read at the new window: {opened:?}"
    );
}
