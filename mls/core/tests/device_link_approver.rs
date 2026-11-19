// SPDX-License-Identifier: MIT
//! The approving device's half of the two-digit number, driven through
//! `device_link_approver_step` exactly as the three apps drive it.
//!
//! THE REGRESSION. An approver that revealed its nonce, saw the post fail, and
//! then took the number over whatever device nonce the next read listed, gave
//! a server its nonce first and the choice of the other afterwards. One dropped
//! response, about ten thousand offline hashes, and both two-digit numbers
//! matched the new device's by construction, with one commitment and nothing on
//! either screen. The approver then sealed the account key to the server's key.
//!
//! The test below runs that attack against the rule. The server still learns
//! the nonce and still finds a device nonce that would match both numbers; the
//! approver answers `Interrupted` to it and derives no number at all.

#![allow(clippy::expect_used, clippy::unwrap_used)]

mod support;

use peachy_mls_core::issuer::device_key_pair;
use peachy_mls_core::{
    device_link_approver_number, device_link_approver_step, device_link_commitment,
    device_link_number, device_link_waiter_step, sign_device_link_commitment,
    verify_device_link_commitment, DeviceLinkApproverStep, DeviceLinkWaiterStep,
};
use sha2::{Digest, Sha256};
use support::device_seed;

fn nonce(tag: &[u8], i: u64) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(tag);
    h.update(i.to_be_bytes());
    h.finalize().into()
}

/// What the server lists for this approver's exchange on one read.
struct Listed {
    key: [u8; 32],
    commitment: Vec<u8>,
    device_nonce: Vec<u8>,
    approver_nonce: Vec<u8>,
}

/// The approving device's state for one waiting device and one prompt, as the
/// apps keep it, advanced only through the core's rule.
struct Approver {
    nonce: [u8; 32],
    commitment: [u8; 32],
    pending_key: [u8; 32],
    bound_device_nonce: Vec<u8>,
    interrupted: bool,
    number: Option<String>,
    approver_number: Option<String>,
    commitments_posted: Vec<[u8; 32]>,
}

impl Approver {
    fn open_prompt(pending_key: [u8; 32], n: [u8; 32]) -> Self {
        Approver {
            nonce: n,
            commitment: device_link_commitment(&n).unwrap(),
            pending_key,
            bound_device_nonce: Vec::new(),
            interrupted: false,
            number: None,
            approver_number: None,
            commitments_posted: Vec::new(),
        }
    }

    /// One read. `post_reveal` is the server's answer to the reveal: Err = the
    /// post failed (the apps log it and read again).
    fn step(
        &mut self,
        my_key: &[u8],
        listed: &Listed,
        post_reveal: &mut dyn FnMut([u8; 32]) -> Result<(), ()>,
    ) -> DeviceLinkApproverStep {
        if self.interrupted || self.number.is_some() {
            return DeviceLinkApproverStep::Wait;
        }
        let step = device_link_approver_step(
            &self.pending_key,
            &self.commitment,
            &self.bound_device_nonce,
            &listed.key,
            &listed.commitment,
            &listed.device_nonce,
            &listed.approver_nonce,
        )
        .unwrap();
        match step {
            DeviceLinkApproverStep::Commit => self.commitments_posted.push(self.commitment),
            DeviceLinkApproverStep::Wait => {}
            DeviceLinkApproverStep::Reveal => {
                if self.bound_device_nonce.is_empty() {
                    // Fixed BEFORE the reveal leaves this device.
                    self.bound_device_nonce = listed.device_nonce.clone();
                }
                let _ = post_reveal(self.nonce);
            }
            DeviceLinkApproverStep::Show => {
                self.number = Some(
                    device_link_number(
                        &self.pending_key,
                        my_key,
                        &self.commitment,
                        &self.bound_device_nonce,
                        &self.nonce,
                    )
                    .unwrap(),
                );
                self.approver_number = Some(
                    device_link_approver_number(
                        &self.pending_key,
                        my_key,
                        &self.commitment,
                        &self.bound_device_nonce,
                        &self.nonce,
                    )
                    .unwrap(),
                );
            }
            DeviceLinkApproverStep::Interrupted => {
                self.interrupted = true;
                self.number = None;
            }
        }
        step
    }
}

#[test]
fn a_failed_reveal_followed_by_a_changed_device_nonce_is_interrupted_never_a_match() {
    let waiter_seed = device_seed(10);
    let (_, waiter_key) = device_key_pair(&waiter_seed);
    let server_seed = device_seed(11);
    let (_, server_key) = device_key_pair(&server_seed);
    let approver_seed = device_seed(12);
    let (_, approver_key) = device_key_pair(&approver_seed);
    let sk: [u8; 32] = server_key.as_slice().try_into().unwrap();

    // Toward the waiting device the server plays the real approver with a
    // commitment of its own; the waiting device's number and the approver
    // number it expects are fixed from here.
    let fake_na = nonce(b"server-na", 0);
    let fake_c = device_link_commitment(&fake_na).unwrap();
    let waiter_nn = nonce(b"waiter-nn", 0);
    let shown =
        device_link_number(&waiter_key, &approver_key, &fake_c, &waiter_nn, &fake_na).unwrap();
    let expect_second =
        device_link_approver_number(&waiter_key, &approver_key, &fake_c, &waiter_nn, &fake_na)
            .unwrap();

    // Toward the real approver it lists the waiting row under its own key.
    let mut approver = Approver::open_prompt(sk, nonce(b"approver-na", 1));
    let c = approver.commitment;
    let none = Vec::new();

    // Read 0: nothing on the row yet: the one commitment goes out.
    assert_eq!(
        approver.step(
            &approver_key,
            &Listed {
                key: sk,
                commitment: none.clone(),
                device_nonce: none.clone(),
                approver_nonce: none.clone()
            },
            &mut |_| panic!("nothing to reveal"),
        ),
        DeviceLinkApproverStep::Commit
    );

    // Read 1: a throwaway device nonce. The approver fixes it, reveals, and
    // the server keeps nA and answers with an error.
    let junk = nonce(b"junk", 0);
    let mut learned: Option<[u8; 32]> = None;
    assert_eq!(
        approver.step(
            &approver_key,
            &Listed {
                key: sk,
                commitment: c.to_vec(),
                device_nonce: junk.to_vec(),
                approver_nonce: none.clone()
            },
            &mut |na| {
                learned = Some(na);
                Err(())
            },
        ),
        DeviceLinkApproverStep::Reveal
    );
    assert!(approver.number.is_none());
    let na = learned.expect("the server saw nA");

    // Offline, the server still finds a device nonce that would make BOTH
    // numbers match the waiting device's: the grind itself is unchanged.
    let mut tries = 0u64;
    let chosen = loop {
        tries += 1;
        assert!(tries < 1_000_000, "no match");
        let nn = nonce(b"server-nn", tries);
        if device_link_number(&sk, &approver_key, &c, &nn, &na).unwrap() == shown
            && device_link_approver_number(&sk, &approver_key, &c, &nn, &na).unwrap()
                == expect_second
        {
            break nn;
        }
    };

    // Read 2: the chosen nonce, with nA listed as stored. THE ASSERTION: the
    // approver answers Interrupted and shows nothing, so nothing is tapped and
    // no account key is sealed.
    assert_eq!(
        approver.step(
            &approver_key,
            &Listed {
                key: sk,
                commitment: c.to_vec(),
                device_nonce: chosen.to_vec(),
                approver_nonce: na.to_vec()
            },
            &mut |_| panic!("no second reveal"),
        ),
        DeviceLinkApproverStep::Interrupted
    );
    assert!(approver.interrupted);
    assert_eq!(
        approver.number, None,
        "an interrupted approver offers no number"
    );
    assert_eq!(approver.approver_number, None);
    assert_eq!(
        approver.commitments_posted.len(),
        1,
        "one commitment per prompt"
    );

    // The same without the reveal stored (the server re-lists before taking
    // the post): a different device nonce after the fix is still the end.
    let mut again = Approver::open_prompt(sk, nonce(b"approver-na", 2));
    let c2 = again.commitment;
    again.step(
        &approver_key,
        &Listed {
            key: sk,
            commitment: c2.to_vec(),
            device_nonce: junk.to_vec(),
            approver_nonce: none.clone(),
        },
        &mut |_| Err(()),
    );
    assert_eq!(
        again.step(
            &approver_key,
            &Listed {
                key: sk,
                commitment: c2.to_vec(),
                device_nonce: chosen.to_vec(),
                approver_nonce: none.clone()
            },
            &mut |_| panic!("no reveal over another nonce"),
        ),
        DeviceLinkApproverStep::Interrupted
    );

    // And every other listing after a failed reveal is either the identical
    // retry or the end: never a number over anything but the fixed nonce.
    for i in 0..256u64 {
        let mut a = Approver::open_prompt(sk, nonce(b"approver-na", 100 + i));
        let ci = a.commitment;
        a.step(
            &approver_key,
            &Listed {
                key: sk,
                commitment: ci.to_vec(),
                device_nonce: junk.to_vec(),
                approver_nonce: none.clone(),
            },
            &mut |_| Err(()),
        );
        let other = nonce(b"other-nn", i);
        let step = a.step(
            &approver_key,
            &Listed {
                key: sk,
                commitment: ci.to_vec(),
                device_nonce: other.to_vec(),
                approver_nonce: a.nonce.to_vec(),
            },
            &mut |_| Ok(()),
        );
        assert_eq!(step, DeviceLinkApproverStep::Interrupted, "listing {i}");
        assert!(a.number.is_none());
    }

    // THE OTHER HALF: the server cannot stand in as this approver toward the
    // waiting device. Its own commitment carries no signature of the
    // approver's, and the approver's real signature names the key the approver
    // was shown (the server's), not the waiting device's.
    let server_sig =
        sign_device_link_commitment(&server_seed, "device-new", &waiter_key, &fake_c).unwrap();
    assert!(!verify_device_link_commitment(
        &approver_key,
        "device-new",
        &waiter_key,
        &fake_c,
        &server_sig
    ));
    let real_sig = sign_device_link_commitment(&approver_seed, "device-new", &sk, &c).unwrap();
    assert!(verify_device_link_commitment(
        &approver_key,
        "device-new",
        &sk,
        &c,
        &real_sig
    ));
    assert!(!verify_device_link_commitment(
        &approver_key,
        "device-new",
        &waiter_key,
        &c,
        &real_sig
    ));
    eprintln!("device-link approver: the grind still finds a match ({tries} hashes); the approver interrupts");
}

#[test]
fn an_honest_failed_reveal_is_retried_over_the_same_inputs_and_both_screens_agree() {
    let waiter_seed = device_seed(20);
    let (_, waiter_key) = device_key_pair(&waiter_seed);
    let approver_seed = device_seed(21);
    let (_, approver_key) = device_key_pair(&approver_seed);
    let wk: [u8; 32] = waiter_key.as_slice().try_into().unwrap();

    let mut approver = Approver::open_prompt(wk, nonce(b"honest-na", 0));
    let c = approver.commitment;
    let sig = sign_device_link_commitment(&approver_seed, "device-new", &wk, &c).unwrap();

    // The waiting device checks the signature, then binds and answers.
    assert!(verify_device_link_commitment(
        &approver_key,
        "device-new",
        &wk,
        &c,
        &sig
    ));
    assert_eq!(
        device_link_waiter_step("", &[], &[], "approver", &approver_key, &c).unwrap(),
        DeviceLinkWaiterStep::Answer
    );
    let nn = nonce(b"honest-nn", 0);
    let none = Vec::new();

    // Nothing answered yet: wait.
    assert_eq!(
        approver.step(
            &approver_key,
            &Listed {
                key: wk,
                commitment: c.to_vec(),
                device_nonce: none.clone(),
                approver_nonce: none.clone()
            },
            &mut |_| panic!("too early"),
        ),
        DeviceLinkApproverStep::Wait
    );
    // The reveal post fails twice; each retry is over the identical inputs.
    let mut posts = 0;
    for _ in 0..2 {
        assert_eq!(
            approver.step(
                &approver_key,
                &Listed {
                    key: wk,
                    commitment: c.to_vec(),
                    device_nonce: nn.to_vec(),
                    approver_nonce: none.clone()
                },
                &mut |_| {
                    posts += 1;
                    Err(())
                },
            ),
            DeviceLinkApproverStep::Reveal
        );
    }
    assert_eq!(posts, 2);
    // It lands; the next read shows it.
    assert_eq!(
        approver.step(
            &approver_key,
            &Listed {
                key: wk,
                commitment: c.to_vec(),
                device_nonce: nn.to_vec(),
                approver_nonce: approver.nonce.to_vec()
            },
            &mut |_| panic!("already revealed"),
        ),
        DeviceLinkApproverStep::Show
    );
    let na = approver.nonce;
    assert_eq!(
        approver.number.as_deref(),
        Some(
            device_link_number(&waiter_key, &approver_key, &c, &nn, &na)
                .unwrap()
                .as_str()
        )
    );
    assert_eq!(
        approver.approver_number.as_deref(),
        Some(
            device_link_approver_number(&waiter_key, &approver_key, &c, &nn, &na)
                .unwrap()
                .as_str()
        )
    );
    assert!(
        approver.commitments_posted.is_empty(),
        "the commitment was on the row all along"
    );
}

#[test]
fn a_changed_key_or_commitment_ends_the_prompt_and_nothing_restarts_it() {
    let approver_seed = device_seed(30);
    let (_, approver_key) = device_key_pair(&approver_seed);
    let pending = [0x22u8; 32];
    let mut approver = Approver::open_prompt(pending, nonce(b"na", 0));
    let c = approver.commitment;
    let none = Vec::new();

    // Before anything is fixed, someone else's commitment on our row is put
    // right by posting OURS again, never a fresh one.
    let foreign = device_link_commitment(&nonce(b"foreign", 0)).unwrap();
    for _ in 0..3 {
        assert_eq!(
            approver.step(
                &approver_key,
                &Listed {
                    key: pending,
                    commitment: foreign.to_vec(),
                    device_nonce: none.clone(),
                    approver_nonce: none.clone()
                },
                &mut |_| panic!("nothing to reveal"),
            ),
            DeviceLinkApproverStep::Commit
        );
    }
    assert!(approver
        .commitments_posted
        .iter()
        .all(|posted| *posted == c));

    // The row's key changes under the prompt: the end, fixed or not.
    assert_eq!(
        approver.step(
            &approver_key,
            &Listed {
                key: [0x33; 32],
                commitment: c.to_vec(),
                device_nonce: none.clone(),
                approver_nonce: none.clone()
            },
            &mut |_| panic!("nothing to reveal"),
        ),
        DeviceLinkApproverStep::Interrupted
    );

    // Fixed, then the exchange vanishes or is replaced: the end.
    for listed_commitment in [Vec::new(), foreign.to_vec()] {
        let mut a = Approver::open_prompt(pending, nonce(b"na", 1));
        let ca = a.commitment;
        a.step(
            &approver_key,
            &Listed {
                key: pending,
                commitment: ca.to_vec(),
                device_nonce: vec![0x55; 32],
                approver_nonce: none.clone(),
            },
            &mut |_| Err(()),
        );
        assert_eq!(
            a.step(
                &approver_key,
                &Listed {
                    key: pending,
                    commitment: listed_commitment,
                    device_nonce: none.clone(),
                    approver_nonce: none.clone()
                },
                &mut |_| panic!("no reveal"),
            ),
            DeviceLinkApproverStep::Interrupted
        );
    }
}
