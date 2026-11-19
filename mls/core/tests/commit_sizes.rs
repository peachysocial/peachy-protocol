// SPDX-License-Identifier: MIT
//! A commit's length depends on the tree and on what it carries, never on
//! which member made it (docs/sealed-messages.md §Size-hiding padding).
//!
//! An UpdatePath is one HPKE public key per node of the committer's filtered
//! direct path and one HPKE ciphertext per member of each copath resolution,
//! each over a kilobyte with X-Wing, so unpadded its size names the
//! committer's position in the tree, and the server knows every position.
//! Every test here builds the SAME commit from every member, from the same
//! epoch, and asserts the server would see one length.

#![allow(clippy::expect_used, clippy::unwrap_used)]

mod support;
#[allow(unused_imports)]
use support::RemoveLeaf;

use peachy_mls_core::envelope::{seal_group_id_envelope, ENVELOPE_KIND_COMMIT};
use peachy_mls_core::Client;
use support::{client, issuer};

const G: &[u8] = b"0f8e2a1c-5b7d-4e9a-8c3f-2d1b6a9e7c40";

fn actor(i: usize) -> String {
    format!("{:08x}-0000-4000-8000-{:012x}", i, i)
}

fn device(i: usize) -> String {
    format!("{:08x}-1111-4111-8111-{:012x}", i, i)
}

/// What the server stores and forwards for a commit: the wrapped envelope.
fn wire_len(commit: &[u8]) -> usize {
    seal_group_id_envelope(G, ENVELOPE_KIND_COMMIT, commit)
        .unwrap()
        .len()
}

/// `n` members on their own accounts, added one device per commit by member 0
/// (docs/delivery.md §Founding a conversation), every one at the
/// same epoch.
fn group_of(n: usize) -> Vec<Client> {
    let s = issuer();
    let mut members: Vec<Client> = (0..n)
        .map(|i| client(&s, (i + 1) as u8, &actor(i), &device(i)))
        .collect();
    members[0].create_group(G).unwrap();
    for i in 1..n {
        let kp = members[i].generate_key_package().unwrap();
        let bundle = members[0].add_member(G, &kp).unwrap();
        members[0].merge_pending_commit(G).unwrap();
        for m in members.iter_mut().take(i).skip(1) {
            m.process_commit(G, &bundle.commit).unwrap();
        }
        members[i]
            .join_from_welcome(&bundle.welcome.unwrap())
            .unwrap();
    }
    members
}

/// Member `by` commits; everybody else (still in the group) applies it.
fn commit_everywhere(
    members: &mut [Option<Client>],
    by: usize,
    build: impl FnOnce(&mut Client) -> Vec<u8>,
) {
    let commit = {
        let m = members[by].as_mut().unwrap();
        let commit = build(m);
        m.merge_pending_commit(G).unwrap();
        commit
    };
    for (i, m) in members.iter_mut().enumerate() {
        if i == by {
            continue;
        }
        if let Some(m) = m {
            m.process_commit(G, &commit).unwrap();
        }
    }
}

/// The wire length of the commit `build` makes, built by each member in
/// `who` from the same epoch (each staged, measured and cleared).
fn lengths_by(
    members: &mut [Option<Client>],
    who: &[usize],
    build: impl Fn(&mut Client) -> Vec<u8>,
) -> Vec<usize> {
    who.iter()
        .map(|&i| {
            let m = members[i].as_mut().unwrap();
            let commit = build(m);
            m.clear_pending_commit(G).unwrap();
            wire_len(&commit)
        })
        .collect()
}

fn one_length(what: &str, lens: &[usize]) -> usize {
    eprintln!("{what}: {lens:?}");
    assert!(
        lens.windows(2).all(|w| w[0] == w[1]),
        "{what}: every member's commit must be one length, got {lens:?}"
    );
    lens[0]
}

fn rotation(m: &mut Client) -> Vec<u8> {
    m.self_update(G).unwrap().commit
}

/// Unpadded, rotations in 3- to 7-leaf trees fall into 2 to 4 length
/// classes, and leaf 2 of a 3-leaf tree (one person on two devices in a DM,
/// with the other person's device beside them) is named outright.
#[test]
fn every_member_rotation_is_one_length() {
    let mut sizes = Vec::new();
    for n in 2..=9 {
        let mut members: Vec<Option<Client>> = group_of(n).into_iter().map(Some).collect();
        let all: Vec<usize> = (0..n).collect();
        let lens = lengths_by(&mut members, &all, rotation);
        sizes.push((n, one_length(&format!("{n} leaves, rotation"), &lens)));
    }
    eprintln!("rotation commit on the wire, by group size: {sizes:?}");
    // Growing the group grows the commit; the padding never doubles one.
    assert!(sizes.windows(2).all(|w| w[1].1 >= w[0].1));
    assert!(
        sizes.iter().all(|&(n, len)| len < 2_000 + n * 2_000),
        "{sizes:?}"
    );
}

#[test]
fn every_member_remove_is_one_length() {
    for (n, target) in [(5usize, 3u32), (7, 0), (7, 6), (6, 5), (3, 2)] {
        let mut members: Vec<Option<Client>> = group_of(n).into_iter().map(Some).collect();
        let who: Vec<usize> = (0..n).filter(|&i| i != target as usize).collect();
        let lens = lengths_by(&mut members, &who, |m| {
            m.remove_leaf(G, target).unwrap().commit
        });
        one_length(&format!("{n} leaves, Remove(leaf {target})"), &lens);
    }
}

#[test]
fn every_member_rename_is_one_length() {
    let mut members: Vec<Option<Client>> = group_of(5).into_iter().map(Some).collect();
    let all: Vec<usize> = (0..5).collect();
    let lens = lengths_by(&mut members, &all, |m| {
        m.set_group_meta(G, br#"{"v":1,"n":"Trip"}"#)
            .unwrap()
            .commit
    });
    one_length("5 leaves, rename", &lens);
}

/// A blank leaf in the middle, unmerged leaves on parents, and a tree that
/// grows and shrinks: the target is computed from the tree every member
/// holds, so it holds through all of it.
#[test]
fn every_member_commit_is_one_length_through_blanks_and_unmerged_leaves() {
    let s = issuer();
    let mut members: Vec<Option<Client>> = group_of(6).into_iter().map(Some).collect();

    // Leaf 2 leaves: a blank in the middle of the tree.
    commit_everywhere(&mut members, 0, |m| m.remove_leaf(G, 2).unwrap().commit);
    members[2] = None;
    let live: Vec<usize> = (0..6).filter(|&i| members[i].is_some()).collect();
    let lens = lengths_by(&mut members, &live, rotation);
    one_length("6 leaves, blank at 2, rotation", &lens);

    // Adding somebody fills the blank, whoever adds them.
    let joiner = client(&s, 40, &actor(40), &device(40));
    let lens = lengths_by(&mut members, &live, |m| {
        let kp = joiner.generate_key_package().unwrap();
        m.add_member(G, &kp).unwrap().commit
    });
    one_length("6 leaves, blank at 2, add", &lens);

    // Leaf 5 adds them for real, so the joiner is unmerged on the parents
    // of its path that leaf 5's path does not cross.
    let mut joiner = joiner;
    let kp = joiner.generate_key_package().unwrap();
    let added = {
        let m = members[5].as_mut().unwrap();
        let added = m.add_member(G, &kp).unwrap();
        m.merge_pending_commit(G).unwrap();
        added
    };
    for &i in &live {
        if i != 5 {
            members[i]
                .as_mut()
                .unwrap()
                .process_commit(G, &added.commit)
                .unwrap();
        }
    }
    joiner.join_from_welcome(&added.welcome.unwrap()).unwrap();
    members[2] = Some(joiner);
    let all: Vec<usize> = (0..6).collect();
    let lens = lengths_by(&mut members, &all, rotation);
    one_length("6 leaves, unmerged joiner at 2, rotation", &lens);
    let lens = lengths_by(&mut members, &[0, 1, 3, 4, 5], |m| {
        m.remove_leaf(G, 2).unwrap().commit
    });
    one_length("6 leaves, unmerged joiner at 2, Remove(leaf 2)", &lens);

    // Two leave from the right: the tree shrinks from 8 leaves to 4.
    commit_everywhere(&mut members, 0, |m| m.remove_leaf(G, 5).unwrap().commit);
    members[5] = None;
    commit_everywhere(&mut members, 0, |m| m.remove_leaf(G, 4).unwrap().commit);
    members[4] = None;
    let live: Vec<usize> = (0..6).filter(|&i| members[i].is_some()).collect();
    let lens = lengths_by(&mut members, &live, rotation);
    one_length("shrunk to 4 leaves, rotation", &lens);
    // And growing it again (the add takes leaf 4, past the 4-leaf tree).
    let grower = client(&s, 41, &actor(41), &device(41));
    let lens = lengths_by(&mut members, &live, |m| {
        let kp = grower.generate_key_package().unwrap();
        m.add_member(G, &kp).unwrap().commit
    });
    one_length("4 leaves, add that grows the tree", &lens);
}

/// A renewal is a rotation's length, from any leaf. A credential's length
/// is a function of its fields (docs/identity.md §Format),
/// and a renewal changes only its dates, ten digits each, so the new leaf is
/// the size of the one it replaces and the renewal carries no growth.
///
/// Growth is still counted for every candidate and not for the renewer
/// alone, but no credential supplies it any more: a device's account
/// certificate is in its leaf before any group seats it (no founder, adder
/// or member accepts a leaf without one), so the one-time step from no
/// certificate to one never reaches a seated leaf. What can still grow one
/// is a capability list a newer build brings.
#[test]
fn a_renewal_is_one_length_from_any_leaf_and_a_rotations_length() {
    for n in [3usize, 5] {
        let mut members: Vec<Option<Client>> = group_of(n).into_iter().map(Some).collect();
        let all: Vec<usize> = (0..n).collect();
        let plain = one_length(
            &format!("{n} leaves, rotation"),
            &lengths_by(&mut members, &all, rotation),
        );
        for (i, m) in members.iter_mut().enumerate() {
            m.as_mut()
                .unwrap()
                .update_credential(&respelled_token(i, 0), None)
                .unwrap();
        }
        let renewal = one_length(
            &format!("{n} leaves, a renewal"),
            &lengths_by(&mut members, &all, |m| {
                m.refresh_credential(G).unwrap().commit
            }),
        );
        assert_eq!(renewal, plain, "a renewal is a rotation's length");
    }
}

/// Member `i`'s next credential (later-expiring than the one [`group_of`]
/// gave it) as an issuer could spell it: the canonical token's fields,
/// signed by the same key, with `pad` bytes of JSON whitespace after the
/// payload's opening brace. `pad` 0 is the canonical token.
fn respelled_token(i: usize, pad: usize) -> Vec<u8> {
    use base64::Engine as _;
    let s = issuer();
    let (_, public) =
        peachy_mls_core::issuer::device_key_pair(&support::device_seed((i + 1) as u8));
    let token = s
        .issue(
            &actor(i),
            &device(i),
            &public,
            support::NOW,
            support::NOW + 31 * support::DAY,
        )
        .unwrap();
    let text = String::from_utf8(token).unwrap();
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(text.split('.').nth(1).unwrap())
        .unwrap();
    let mut spaced = vec![b'{'];
    spaced.extend(std::iter::repeat_n(b' ', pad));
    spaced.extend_from_slice(&payload[1..]);
    s.issue_raw(peachy_mls_core::credential::TOKEN_PREFIX, &spaced)
}

/// The issuer mints every credential, so were any spelling of a payload
/// accepted, it could hand each device a next credential of its own length,
/// and every renewal and periodic rotation that device made would name it
/// by its growth. A credential is read only in its one canonical spelling,
/// so its length is a function of its fields, which a renewal does not
/// change: the respelled token is refused and the device keeps its own.
#[test]
fn a_credential_the_issuer_respelled_is_refused_so_its_length_names_nobody() {
    let mut members: Vec<Option<Client>> = group_of(4).into_iter().map(Some).collect();
    for (i, m) in members.iter_mut().enumerate() {
        let m = m.as_mut().unwrap();
        for pad in [1, 300 * (i + 1)] {
            match m.update_credential(&respelled_token(i, pad), None) {
                Err(peachy_mls_core::Error::CredentialRejected(
                    peachy_mls_core::CredentialRejection::Malformed,
                )) => {}
                other => panic!("member {i}, {pad} bytes of whitespace: {other:?}"),
            }
        }
        m.update_credential(&respelled_token(i, 0), None)
            .expect("the canonical spelling is taken");
    }
    let lens = lengths_by(&mut members, &[0, 1, 2, 3], |m| {
        m.refresh_credential(G).unwrap().commit
    });
    one_length("4 leaves, a renewal after a respelled credential", &lens);
}

/// Every member's commit is still read by every other member: the padding
/// is the zeros MLS receivers already strip.
#[test]
fn a_padded_commit_is_applied_by_every_member() {
    let mut members: Vec<Option<Client>> = group_of(5).into_iter().map(Some).collect();
    for by in 0..5 {
        commit_everywhere(&mut members, by, rotation);
    }
    let epochs: Vec<u64> = members
        .iter()
        .map(|m| m.as_ref().unwrap().epoch(G).unwrap())
        .collect();
    assert!(epochs.windows(2).all(|w| w[0] == w[1]), "{epochs:?}");
    // And messages still pad to the message block after a commit.
    let m = members[0].as_mut().unwrap();
    let a = m.encrypt(G, b"ok").unwrap();
    let b = m.encrypt(G, b"okay").unwrap();
    assert_eq!(a.len(), b.len());
    let opened = members[1].as_mut().unwrap().process_message(G, &a).unwrap();
    assert!(matches!(
        opened,
        peachy_mls_core::Incoming::Application { .. }
    ));
}

/// A group founded as docs/delivery.md §Founding a conversation
/// writes it: the founder commits the initial state at epoch 0, then adds
/// one device per commit. `owners[i]` is the account of leaf i, so one
/// person may hold two leaves.
fn founded_with(owners: &[usize], meta: &[u8]) -> Vec<Option<Client>> {
    let s = issuer();
    let mut members: Vec<Client> = owners
        .iter()
        .enumerate()
        .map(|(i, &o)| client(&s, (i + 1) as u8, &actor(o), &device(i)))
        .collect();
    members[0].create_group(G).unwrap();
    members[0].set_group_meta(G, meta).unwrap();
    members[0].merge_pending_commit(G).unwrap();
    for i in 1..members.len() {
        let kp = members[i].generate_key_package().unwrap();
        let bundle = members[0].add_member(G, &kp).unwrap();
        members[0].merge_pending_commit(G).unwrap();
        for m in members.iter_mut().take(i).skip(1) {
            m.process_commit(G, &bundle.commit).unwrap();
        }
        members[i]
            .join_from_welcome(&bundle.welcome.unwrap())
            .unwrap();
    }
    members.into_iter().map(Some).collect()
}

/// A group's state with `extra` keys after the founding ones: a direct
/// chat's (no name, both people admins, `dm`) or a named group's.
fn state(owners: &[usize], dm: bool, extra: &str) -> Vec<u8> {
    let mut actors: Vec<String> = owners
        .iter()
        .map(|&o| format!("\"{}\"", actor(o)))
        .collect();
    actors.dedup();
    let head = if dm { r#""n":"""# } else { r#""n":"Trip""# };
    let dm = if dm { r#","dm":true"# } else { "" };
    format!(
        r#"{{"v":1,{head},"adm":[{}]{dm}{extra}}}"#,
        actors.join(",")
    )
    .into_bytes()
}

/// A small change to the group's own state (the disappearing timer, Advanced
/// Chat Privacy) is the same length as a key rotation, whoever builds either:
/// every commit is padded as if it carried the group's state plus fixed room
/// (docs/metadata.md §Encrypted handshakes). In a direct chat, whose
/// name and admins never change, a state commit the server could tell apart
/// would say the timer or Advanced Chat Privacy had just been switched.
#[test]
fn a_small_state_change_is_one_length_with_a_rotation() {
    let cases: [(&str, &[usize], bool, &str, &str); 5] = [
        ("DM, timer on", &[0, 1], true, "", r#","dis":86400"#),
        ("DM, timer off", &[0, 1], true, r#","dis":604800"#, ""),
        (
            "DM, Advanced Chat Privacy on",
            &[0, 1],
            true,
            "",
            r#","acp":true"#,
        ),
        (
            "DM, one side on two devices, timer on",
            &[0, 1, 1],
            true,
            "",
            r#","dis":3600"#,
        ),
        (
            "5-person group, timer on",
            &[0, 1, 2, 3, 4],
            false,
            "",
            r#","dis":2419200"#,
        ),
    ];
    for (what, owners, dm, before, after) in cases {
        let mut members = founded_with(owners, &state(owners, dm, before));
        let next = state(owners, dm, after);
        let all: Vec<usize> = (0..owners.len()).collect();
        let rotated = one_length(
            &format!("{what}: rotation"),
            &lengths_by(&mut members, &all, rotation),
        );
        let switched = one_length(
            &format!("{what}: state change"),
            &lengths_by(&mut members, &all, |m| {
                m.set_group_meta(G, &next).unwrap().commit
            }),
        );
        assert_eq!(
            rotated, switched,
            "{what}: a state change must not be told from a rotation"
        );
    }
}
