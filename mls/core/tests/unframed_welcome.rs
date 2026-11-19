// SPDX-License-Identifier: MIT
//! A Welcome without its frame is refused, and spends its key package first.
//!
//! Every Welcome travels in a padded frame (`welcome_frame`), and a raw one
//! is refused. The refusal used to come before the Welcome was opened, so the
//! one-time key package it was sealed to stayed in the store with its private
//! keys, while the add that made the Welcome had already seated this device
//! in every other member's tree. Both `welcome_group`, which every app calls
//! first, and the join doors now spend that package before refusing, as they
//! do for every other refused Welcome.

#![allow(clippy::expect_used, clippy::unwrap_used)]

mod support;

use peachy_mls_core::welcome_frame::{frame_welcome, unframe_welcome};
use peachy_mls_core::Client;
use support::{client, head_of, issuer, join_at_head};

const GROUP: &[u8] = b"99999999-9999-4999-8999-999999999999";

/// Ada founds the group and adds Bo through a one-time key package. Returns
/// Ada, Bo and the framed Welcome.
fn added() -> (Client, Client, Vec<u8>) {
    let server = issuer();
    let mut ada = client(&server, 1, "actor-ada", "device-ada");
    let bo = client(&server, 2, "actor-bo", "device-bo");
    ada.create_group(GROUP).unwrap();
    let kp = bo.generate_key_package().unwrap();
    let add = ada.add_member(GROUP, &kp).unwrap();
    ada.merge_pending_commit(GROUP).unwrap();
    (ada, bo, add.welcome.unwrap())
}

fn assert_frame_refusal(err: peachy_mls_core::Error) {
    assert!(err.to_string().contains("frame"), "{err}");
}

/// Control: the framed Welcome reads without spending, then joins.
#[test]
fn a_framed_welcome_reads_and_then_joins() {
    let (ada, mut bo, welcome) = added();
    let (group, _) = bo.welcome_group(&welcome).unwrap();
    assert_eq!(group, GROUP);
    join_at_head(&mut bo, &welcome, head_of(&ada, GROUP)).unwrap();
    assert_eq!(bo.epoch(GROUP).unwrap(), ada.epoch(GROUP).unwrap());
}

#[test]
fn reading_a_raw_welcome_spends_its_key_package() {
    let (ada, mut bo, welcome) = added();
    let raw = unframe_welcome(&welcome).unwrap().to_vec();
    assert_frame_refusal(bo.welcome_group(&raw).expect_err("a raw Welcome"));
    // The package is gone: the same Welcome, framed, no longer opens.
    assert!(bo.welcome_group(&welcome).is_err());
    assert!(join_at_head(&mut bo, &welcome, head_of(&ada, GROUP)).is_err());
    assert!(bo.epoch(GROUP).is_err());
}

#[test]
fn joining_from_a_raw_welcome_spends_its_key_package() {
    let (ada, mut bo, welcome) = added();
    let raw = unframe_welcome(&welcome).unwrap().to_vec();
    assert_frame_refusal(bo.join_from_welcome(&raw).expect_err("a raw Welcome"));
    assert!(join_at_head(&mut bo, &welcome, head_of(&ada, GROUP)).is_err());
    assert!(bo.epoch(GROUP).is_err());
}

#[test]
fn a_frame_with_a_dirty_fill_spends_its_key_package() {
    let (ada, mut bo, welcome) = added();
    let raw = unframe_welcome(&welcome).unwrap().to_vec();
    let mut dirty = frame_welcome(&raw, welcome.len() + 256).unwrap();
    *dirty.last_mut().unwrap() = 1;
    assert_frame_refusal(
        bo.join_from_welcome_at_head(&dirty, head_of(&ada, GROUP).0, &head_of(&ada, GROUP).1)
            .expect_err("a dirty fill"),
    );
    assert!(join_at_head(&mut bo, &welcome, head_of(&ada, GROUP)).is_err());
}

/// Bytes that are not a Welcome spend nothing.
#[test]
fn bytes_that_are_no_welcome_spend_nothing() {
    let (ada, mut bo, welcome) = added();
    assert_frame_refusal(bo.welcome_group(b"not a welcome").expect_err("refused"));
    assert_frame_refusal(bo.join_from_welcome(b"not a welcome").expect_err("refused"));
    join_at_head(&mut bo, &welcome, head_of(&ada, GROUP)).unwrap();
}
