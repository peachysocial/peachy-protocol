// SPDX-License-Identifier: MIT
//! Two devices race a commit, and the loser has to end up in the winner's
//! epoch.
//!
//! This is the failure `mls/core/src/group.rs` §The commit lifecycle exists to
//! make unrepresentable: a commit-producing method that merges its own commit
//! before anybody has agreed to it sends the loser of a race off onto a
//! private branch that nothing can ever bring back. The symptom is the
//! quietest kind: `is_active` still true, `encrypt` still returning bytes, and
//! every one of those bytes unreadable by every other member for ever.
//!
//! The delivery service is stubbed by a rule rather than mocked
//! (docs/delivery.md §The ordering rule): a commit is accepted only
//! when it was built at the group's current epoch, and the first one to arrive
//! at a given epoch wins.

mod support;

use peachy_mls_core::{Error, Incoming};
use support::{client, issuer};

const GROUP: &[u8] = b"peachy-race";

/// The delivery service, in as much detail as this test needs: one epoch
/// counter per group, and a refusal for anything not built against it.
struct Ds {
    epoch: u64,
    stream: Vec<Vec<u8>>,
}

impl Ds {
    fn new() -> Self {
        Self {
            epoch: 0,
            stream: Vec::new(),
        }
    }

    /// `Ok(seq)` when the commit is taken, `Err(())` on the epoch check —
    /// which is what the server answers as `failed_precondition`.
    fn submit(&mut self, built_at: u64, commit: Vec<u8>) -> Result<usize, ()> {
        if built_at != self.epoch {
            return Err(());
        }
        self.epoch += 1;
        self.stream.push(commit);
        Ok(self.stream.len())
    }
}

#[test]
fn the_loser_of_a_commit_race_ends_up_in_the_winners_epoch() {
    let server = issuer();
    let mut ada = client(&server, 1, "actor-ada", "device-ada-phone");
    let mut bo = client(&server, 2, "actor-bo", "device-bo-phone");
    let mut ds = Ds::new();

    // A two-member group, built the way a client should build one.
    ada.create_group(GROUP).expect("create");
    let bo_kp = bo.generate_key_package().expect("bo key package");
    let add = ada.add_member(GROUP, &bo_kp).expect("add bo");
    ds.submit(ada.epoch(GROUP).expect("epoch"), add.commit.clone())
        .expect("the first commit on an empty group is taken");
    ada.merge_pending_commit(GROUP).expect("merge the add");
    bo.join_from_welcome(&add.welcome.clone().expect("welcome"))
        .expect("bo joins");
    assert_eq!(ada.epoch(GROUP).expect("epoch"), 1);
    assert_eq!(bo.epoch(GROUP).expect("epoch"), 1);

    // --- the race ---------------------------------------------------------
    // Both build a commit against epoch 1, neither knowing about the other.
    let ada_built_at = ada.epoch(GROUP).expect("epoch");
    let ada_commit = ada.self_update(GROUP).expect("ada stages a self-update");
    let bo_built_at = bo.epoch(GROUP).expect("epoch");
    let bo_commit = bo.self_update(GROUP).expect("bo stages a self-update");

    // Neither has moved: a staged commit is not an epoch.
    assert_eq!(ada.epoch(GROUP).expect("epoch"), 1);
    assert_eq!(bo.epoch(GROUP).expect("epoch"), 1);
    assert!(ada.has_pending_commit(GROUP).expect("pending"));
    assert!(bo.has_pending_commit(GROUP).expect("pending"));

    // Ada reaches the delivery service first.
    ds.submit(ada_built_at, ada_commit.commit.clone())
        .expect("ada wins");
    ada.merge_pending_commit(GROUP).expect("ada merges");

    // Bo loses on the epoch check.
    assert!(
        ds.submit(bo_built_at, bo_commit.commit.clone()).is_err(),
        "the delivery service must refuse a commit built at a superseded epoch",
    );

    // THE FIX, in one line: Bo drops the branch the server never took.
    bo.clear_pending_commit(GROUP).expect("bo clears");
    assert!(!bo.has_pending_commit(GROUP).expect("pending"));
    assert_eq!(
        bo.epoch(GROUP).expect("epoch"),
        1,
        "clearing leaves the group exactly where the server left it",
    );

    // ...and then replays the server's order, which is the only way forward.
    match bo
        .process_commit(GROUP, &ada_commit.commit)
        .expect("bo applies ada's commit")
    {
        Incoming::Commit(_) => {}
        other => panic!("expected a commit, got {other:?}"),
    }

    // --- the property -----------------------------------------------------
    assert_eq!(
        bo.epoch(GROUP).expect("epoch"),
        ada.epoch(GROUP).expect("epoch"),
        "the loser must end up in the winner's epoch, not beside it",
    );

    // And the group still works in BOTH directions, which is the assertion
    // that would have failed before the fix: Bo's message would have been
    // sealed at a private epoch 2 that Ada never entered.
    let from_bo = bo.encrypt(GROUP, b"still in the room").expect("encrypt");
    match ada.process_message(GROUP, &from_bo).expect("ada reads it") {
        Incoming::Application {
            plaintext, sender, ..
        } => {
            assert_eq!(plaintext, b"still in the room");
            assert_eq!(sender.actor_id, "actor-bo");
        }
        other => panic!("expected an application message, got {other:?}"),
    }
    let from_ada = ada.encrypt(GROUP, b"heard you").expect("encrypt");
    match bo.process_message(GROUP, &from_ada).expect("bo reads it") {
        Incoming::Application { plaintext, .. } => assert_eq!(plaintext, b"heard you"),
        other => panic!("expected an application message, got {other:?}"),
    }

    // Bo can commit again, at the epoch the group is really in.
    let retry_built_at = bo.epoch(GROUP).expect("epoch");
    let retry = bo.self_update(GROUP).expect("bo tries again");
    ds.submit(retry_built_at, retry.commit.clone())
        .expect("the retry is built at the current epoch and is taken");
    bo.merge_pending_commit(GROUP).expect("bo merges");
    ada.process_commit(GROUP, &retry.commit)
        .expect("ada applies");
    assert_eq!(
        ada.epoch(GROUP).expect("epoch"),
        bo.epoch(GROUP).expect("epoch")
    );
}

/// A staged commit blocks a second one, rather than silently stacking.
///
/// OpenMLS refuses, and it should: two commits from one device against one
/// epoch is the same fork by another route. The caller's job is to resolve the
/// first, and the error is how it finds out it has not.
#[test]
fn a_second_commit_is_refused_while_one_is_still_staged() {
    let server = issuer();
    let mut ada = client(&server, 3, "actor-ada", "device-ada-mac");
    let bo = client(&server, 4, "actor-bo", "device-bo-mac");

    ada.create_group(GROUP).expect("create");
    let bo_kp = bo.generate_key_package().expect("bo key package");
    ada.add_member(GROUP, &bo_kp).expect("stage an add");

    assert!(
        ada.self_update(GROUP).is_err(),
        "a device holding a staged commit must not build a second one",
    );

    // Resolving the first unblocks the group either way round.
    ada.clear_pending_commit(GROUP).expect("clear");
    ada.self_update(GROUP).expect("now it builds");
    ada.merge_pending_commit(GROUP).expect("merge");
}

/// `clear` is a one-way door once the server has TAKEN the commit, and this is
/// the test that says so out loud.
///
/// `a_second_commit_is_refused_while_one_is_still_staged` and the race above
/// both clear a commit the delivery service REFUSED, which is what
/// `clear_pending_commit` is documented for and which costs nothing: the group
/// never moved, so replaying the server's order catches up. The case here is
/// the other one — the server ACCEPTED the commit and this device failed to
/// merge it — and it is not symmetrical with that at all.
///
/// The reason is `Incoming::Echo`, and since handshakes went out as
/// `PrivateMessage` ([`PEACHY_WIRE_FORMAT_POLICY`] in `mls/core/src/group.rs`)
/// it is the reason on BOTH sides of the door. A staged own commit comes back
/// as `OwnPendingCommit`; a cleared one comes back as `OwnPrivateMessage`,
/// because a sender holds no key that opens its own `PrivateMessage` and no
/// signature it could verify against itself. Either way OpenMLS hands back an
/// echo and the group does not move — so a recovery that clears and then
/// "replays the stream" is replaying something it can never apply, and the
/// device is left below the group for ever with `is_active` still true.
///
/// That is a change of REGISTER and not of outcome. Under the old plaintext
/// framing a cleared own commit came back as a stranger's commit against an
/// epoch this device had left, which was an `Err`; now it is a silent no-op.
/// Nothing was relying on the error — no client reads it, and the cure was a
/// rejoin either way — but the wedge is quieter than it was, which the last
/// assertion of this test names.
///
/// Both halves are asserted here, because the contrast IS the property.
/// A client that assumes the replay would work loops on it; it must take the
/// rejoin door instead (`docs/delivery.md` §The client contract on
/// `behind_retention`), and this test is why it has to.
#[test]
fn an_accepted_commit_is_replayable_while_staged_and_never_after_it_is_cleared() {
    let server = issuer();

    // --- while staged: the device knows its own commit --------------------
    {
        let mut ada = client(&server, 9, "actor-ada", "device-ada-phone");
        let bo = client(&server, 10, "actor-bo", "device-bo-phone");
        let mut ds = Ds::new();

        ada.create_group(GROUP).expect("create");
        let bo_kp = bo.generate_key_package().expect("bo key package");
        let add = ada.add_member(GROUP, &bo_kp).expect("add bo");
        ds.submit(ada.epoch(GROUP).expect("epoch"), add.commit.clone())
            .expect("taken");
        ada.merge_pending_commit(GROUP).expect("merge the add");

        let built_at = ada.epoch(GROUP).expect("epoch");
        let mine = ada.self_update(GROUP).expect("stage a self-update");
        ds.submit(built_at, mine.commit.clone())
            .expect("the server takes it");
        assert!(ada.has_pending_commit(GROUP).expect("pending"));

        // The same bytes off the stream, still staged: recognised as its own.
        match ada
            .process_commit(GROUP, &mine.commit)
            .expect("a staged commit coming back is not an error")
        {
            Incoming::Echo => {}
            other => panic!("expected Echo while staged, got {other:?}"),
        }
        assert_eq!(
            ada.epoch(GROUP).expect("epoch"),
            built_at,
            "an echo is not an epoch: only the merge moves the group",
        );
        ada.merge_pending_commit(GROUP)
            .expect("and it still merges");
        assert_eq!(ada.epoch(GROUP).expect("epoch"), built_at + 1);
    }

    // --- once cleared: the road is closed ---------------------------------
    let mut ada = client(&server, 11, "actor-ada", "device-ada-mac");
    let mut bo = client(&server, 12, "actor-bo", "device-bo-mac");
    let mut ds = Ds::new();

    ada.create_group(GROUP).expect("create");
    let bo_kp = bo.generate_key_package().expect("bo key package");
    let add = ada.add_member(GROUP, &bo_kp).expect("add bo");
    ds.submit(ada.epoch(GROUP).expect("epoch"), add.commit.clone())
        .expect("taken");
    ada.merge_pending_commit(GROUP).expect("merge the add");
    bo.join_from_welcome(&add.welcome.clone().expect("welcome"))
        .expect("bo joins");

    let built_at = ada.epoch(GROUP).expect("epoch");
    let mine = ada.self_update(GROUP).expect("stage a self-update");
    ds.submit(built_at, mine.commit.clone())
        .expect("the server takes it — this is the accepted case");

    // The merge is where the old recovery went wrong, so stand in its place:
    // the commit is thrown away instead of merged.
    ada.clear_pending_commit(GROUP).expect("clear it");
    assert!(!ada.has_pending_commit(GROUP).expect("pending"));

    // Everyone else applies it, because the server took it.
    bo.process_commit(GROUP, &mine.commit)
        .expect("bo applies it");
    assert_eq!(bo.epoch(GROUP).expect("epoch"), built_at + 1);

    // THE PROPERTY. Replaying the stream cannot put Ada back: her own commit is
    // no longer hers as far as the state machine is concerned.
    match ada
        .process_commit(GROUP, &mine.commit)
        .expect("an own PrivateMessage is an echo, cleared or not")
    {
        Incoming::Echo => {}
        other => panic!("a cleared own commit must not be applicable — got {other:?}"),
    }
    assert!(
        ada.is_active(GROUP).expect("active"),
        "the group is still here; it is the commit that cannot land",
    );
    assert_eq!(
        ada.epoch(GROUP).expect("epoch"),
        built_at,
        "and she is left below the group, not beside it",
    );

    // Which is not a slow recovery — it is none. Nothing the group does after
    // this reaches her, so every later entry fails the same way.
    let next = bo.self_update(GROUP).expect("bo rotates");
    ds.submit(bo.epoch(GROUP).expect("epoch"), next.commit.clone())
        .expect("taken");
    bo.merge_pending_commit(GROUP).expect("bo merges");
    assert!(
        ada.process_commit(GROUP, &next.commit).is_err(),
        "a device below the group cannot apply what comes after, either",
    );
    let from_bo = bo.encrypt(GROUP, b"can you hear me").expect("encrypt");
    assert!(
        ada.process_message(GROUP, &from_bo).is_err(),
        "nor read the room it still believes it is in",
    );
    assert_eq!(
        ada.epoch(GROUP).expect("epoch"),
        built_at,
        "stuck, and stuck quietly — which is why the cure has to be a rejoin",
    );
}

/// `merge` is for a commit that exists; `clear` is safe on nothing.
#[test]
fn merging_nothing_is_an_error_and_clearing_nothing_is_not() {
    let server = issuer();
    let mut ada = client(&server, 5, "actor-ada", "device-ada-ipad");
    ada.create_group(GROUP).expect("create");

    let err = ada
        .merge_pending_commit(GROUP)
        .expect_err("there is nothing staged");
    assert!(matches!(err, Error::InvalidArgument(_)), "got {err:?}");

    // The error path must not itself have an error path.
    ada.clear_pending_commit(GROUP).expect("clearing nothing");
    ada.clear_pending_commit(GROUP).expect("and again");

    assert!(matches!(
        ada.clear_pending_commit(b"no-such-group"),
        Err(Error::NoSuchGroup)
    ));
    assert!(matches!(
        ada.merge_pending_commit(b"no-such-group"),
        Err(Error::NoSuchGroup)
    ));
    assert!(matches!(
        ada.has_pending_commit(b"no-such-group"),
        Err(Error::NoSuchGroup)
    ));
}

/// A second Welcome for a group this device is already in must not replace it.
///
/// Two members racing an ADD is where the second Welcome comes from
/// (the web client's session code, `claimWelcomes`: "a second Welcome
/// from a racing commit"). Ada and Cy both add Bo against the same epoch, each
/// against a different one of Bo's published key packages. Only one commit can
/// be taken — but both Welcomes are real, well-formed and openable, and the
/// loser's can reach Bo late.
///
/// Joining on it would overwrite the live group at whatever epoch the stale
/// Welcome sealed, losing every epoch in between; the device would then fail
/// to read its own conversation and look corrupt rather than stale.
#[test]
fn a_duplicate_welcome_is_refused_and_the_live_group_survives() {
    let server = issuer();
    let mut ada = client(&server, 6, "actor-ada", "device-ada-phone");
    let mut bo = client(&server, 7, "actor-bo", "device-bo-phone");
    let mut cy = client(&server, 8, "actor-cy", "device-cy-phone");
    let mut ds = Ds::new();

    // Ada and Cy are in the group; Bo is not, yet.
    ada.create_group(GROUP).expect("create");
    let cy_kp = cy.generate_key_package().expect("cy key package");
    let add_cy = ada.add_member(GROUP, &cy_kp).expect("add cy");
    ds.submit(ada.epoch(GROUP).expect("epoch"), add_cy.commit.clone())
        .expect("taken");
    ada.merge_pending_commit(GROUP).expect("merge");
    cy.join_from_welcome(&add_cy.welcome.clone().expect("welcome"))
        .expect("cy joins");

    // Bo has two one-time key packages published, which is the ordinary state
    // of a device's pool.
    let bo_kp_one = bo.generate_key_package().expect("bo key package");
    let bo_kp_two = bo.generate_key_package().expect("bo key package");

    // --- both add Bo, against the same epoch ------------------------------
    let ada_at = ada.epoch(GROUP).expect("epoch");
    let ada_add = ada.add_member(GROUP, &bo_kp_one).expect("ada adds bo");
    let cy_at = cy.epoch(GROUP).expect("epoch");
    let cy_add = cy.add_member(GROUP, &bo_kp_two).expect("cy adds bo");

    ds.submit(ada_at, ada_add.commit.clone()).expect("ada wins");
    ada.merge_pending_commit(GROUP).expect("ada merges");
    assert!(ds.submit(cy_at, cy_add.commit.clone()).is_err(), "cy loses");
    cy.clear_pending_commit(GROUP).expect("cy clears");
    cy.process_commit(GROUP, &ada_add.commit)
        .expect("cy replays");

    // Bo joins on the WINNER's Welcome, and the group moves on.
    bo.join_from_welcome(&ada_add.welcome.clone().expect("welcome"))
        .expect("bo joins");
    assert_eq!(bo.epoch(GROUP).expect("epoch"), 2);
    let moved_on = ada.self_update(GROUP).expect("ada rotates");
    ds.submit(ada.epoch(GROUP).expect("epoch"), moved_on.commit.clone())
        .expect("taken");
    ada.merge_pending_commit(GROUP).expect("merge");
    bo.process_commit(GROUP, &moved_on.commit)
        .expect("bo applies");
    cy.process_commit(GROUP, &moved_on.commit)
        .expect("cy applies");
    assert_eq!(bo.epoch(GROUP).expect("epoch"), 3);

    // --- and now the loser's Welcome arrives ------------------------------
    let stale_welcome = cy_add.welcome.clone().expect("welcome");
    let err = bo
        .join_from_welcome(&stale_welcome)
        .expect_err("a Welcome into a group we are in must be refused");
    assert!(matches!(err, Error::AlreadyAMember), "got {err:?}");

    // The live group is untouched — same epoch, and still readable.
    assert_eq!(
        bo.epoch(GROUP).expect("epoch"),
        3,
        "the refusal must not have moved the group Bo was in",
    );
    let hello = ada.encrypt(GROUP, b"still working").expect("encrypt");
    match bo.process_message(GROUP, &hello).expect("bo reads it") {
        Incoming::Application { plaintext, .. } => assert_eq!(plaintext, b"still working"),
        other => panic!("expected an application message, got {other:?}"),
    }
}

/// TWO MEMBERS FOUND THE SAME GROUP AT ONCE, and the loser keeps a copy of a
/// group the delivery service never took.
///
/// A conversation's MLS group has a FIXED id (the conversation's), so a group
/// chat opened by two members before either one's first commit lands is built
/// twice: each creates the group locally at epoch 0 and stages an Add. The
/// server takes the first Add at epoch 0 and refuses the other, and the loser
/// clears its staged commit — correctly — but clearing a commit does not
/// unmake the group. What is left is an epoch-0 group under the real id, keyed
/// by secrets nobody else holds, and it blocks both ways in:
///
/// - the winner's commit off the stream cannot apply to it (it never opens,
///   so `commit_strands` says no and the client asks the group's head, which
///   is ahead of the loser's copy); and
/// - a Welcome into the group is refused as `AlreadyAMember`. It is kept as
///   a contested seat, which the head can still choose over the copy
///   (`group_membership_attacks.rs`), but the key package is spent.
///
/// Four- and five-member web groups showed both in about three runs of four.
/// The fix is the clients' (`abandonUnfoundedGroup`): a founding commit the
/// server refused leaves nothing behind. This pins the core half — that the
/// stale copy is exactly what blocks the Welcome, and that forgetting it is all
/// it takes for the winner's Welcome to open.
#[test]
fn a_founding_race_loser_must_forget_its_group_before_the_winners_welcome_opens() {
    let server = issuer();
    let mut ada = client(&server, 9, "actor-ada", "device-ada-phone");
    let mut bo = client(&server, 10, "actor-bo", "device-bo-phone");
    let cy = client(&server, 11, "actor-cy", "device-cy-phone");
    let mut ds = Ds::new();

    // Both open the conversation before either has committed anything.
    ada.create_group(GROUP).expect("ada creates");
    bo.create_group(GROUP).expect("bo creates");
    let bo_kp = bo.generate_key_package().expect("bo key package");
    let ada_kp = ada.generate_key_package().expect("ada key package");
    let ada_add = ada.add_member(GROUP, &bo_kp).expect("ada adds bo");
    let bo_add = bo.add_member(GROUP, &ada_kp).expect("bo adds ada");

    ds.submit(ada.epoch(GROUP).expect("epoch"), ada_add.commit.clone())
        .expect("ada founds the group");
    ada.merge_pending_commit(GROUP).expect("ada merges");
    assert!(
        ds.submit(bo.epoch(GROUP).expect("epoch"), bo_add.commit.clone())
            .is_err(),
        "bo's founding commit loses",
    );
    bo.clear_pending_commit(GROUP).expect("bo clears");

    // What clearing leaves: a live epoch-0 group nobody else is in.
    assert_eq!(bo.epoch(GROUP).expect("epoch"), 0);
    assert!(bo.is_active(GROUP).expect("active"));

    // The group moves on without Bo's copy knowing: Ada adds Cy.
    let cy_kp = cy.generate_key_package().expect("cy key package");
    let add_cy = ada.add_member(GROUP, &cy_kp).expect("ada adds cy");
    ds.submit(ada.epoch(GROUP).expect("epoch"), add_cy.commit.clone())
        .expect("taken");
    ada.merge_pending_commit(GROUP).expect("merge");

    assert!(
        bo.process_commit(GROUP, &ada_add.commit).is_err(),
        "the winner's commit cannot apply to the loser's private copy",
    );
    assert!(
        !bo.commit_strands(GROUP, &ada_add.commit).expect("framing"),
        "a commit that never opened is the head's to judge, not its framing's",
    );
    // The winner's Welcome for Bo is refused while the copy stands, and the
    // key package with it is spent. It is kept as a contested seat, but the
    // group has moved past the Welcome's epoch (Cy's add), so the head names
    // neither Bo's copy nor the Welcome: only a re-add by a live member (the
    // rejoin) gets Bo in.
    let err = bo
        .join_from_welcome(&ada_add.welcome.clone().expect("welcome"))
        .expect_err("an active copy refuses the Welcome");
    assert!(matches!(err, Error::AlreadyAMember), "got {err:?}");
    assert_eq!(bo.epoch(GROUP).expect("epoch"), 0, "still the private copy");
    let send_key = ada
        .export_secret(GROUP, peachy_mls_core::SEND_KEY_LABEL, GROUP, 32)
        .expect("send key");
    let verifier = <sha2::Sha256 as sha2::Digest>::digest(send_key);
    assert!(matches!(
        bo.join_contested_welcome(ada.epoch(GROUP).expect("epoch"), &verifier),
        Err(Error::AlreadyAMember)
    ));
    assert_eq!(bo.epoch(GROUP).expect("epoch"), 0, "still the private copy");
}

/// And the client's fix, at the core: a loser that forgets its copy the moment
/// its founding commit is refused joins on the winner's FIRST Welcome, with no
/// re-add and no key package spent on a refusal.
#[test]
fn a_founding_race_loser_that_forgets_at_once_joins_on_the_first_welcome() {
    let server = issuer();
    let mut ada = client(&server, 12, "actor-ada", "device-ada-phone");
    let mut bo = client(&server, 13, "actor-bo", "device-bo-phone");
    let mut ds = Ds::new();

    ada.create_group(GROUP).expect("ada creates");
    bo.create_group(GROUP).expect("bo creates");
    let bo_kp = bo.generate_key_package().expect("bo key package");
    let ada_kp = ada.generate_key_package().expect("ada key package");
    let ada_add = ada.add_member(GROUP, &bo_kp).expect("ada adds bo");
    let bo_add = bo.add_member(GROUP, &ada_kp).expect("bo adds ada");
    ds.submit(0, ada_add.commit.clone())
        .expect("ada founds the group");
    ada.merge_pending_commit(GROUP).expect("ada merges");
    assert!(ds.submit(0, bo_add.commit.clone()).is_err(), "bo loses");
    bo.clear_pending_commit(GROUP).expect("bo clears");
    bo.forget_group(GROUP)
        .expect("and forgets the copy the server never took");

    bo.join_from_welcome(&ada_add.welcome.clone().expect("welcome"))
        .expect("the winner's Welcome opens");
    assert_eq!(bo.epoch(GROUP).expect("epoch"), 1);
    let hello = ada.encrypt(GROUP, b"ride at nine").expect("encrypt");
    match bo.process_message(GROUP, &hello).expect("bo reads it") {
        Incoming::Application { plaintext, .. } => assert_eq!(plaintext, b"ride at nine"),
        other => panic!("expected an application message, got {other:?}"),
    }
}
