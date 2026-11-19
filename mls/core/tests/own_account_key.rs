// SPDX-License-Identifier: MIT
//! A device runs only on a credential certified under the account identity key
//! it derives from the account key it holds (docs/identity.md §The
//! account identity key, `ClientConfig::own_account_identity`).
//!
//! The server writes `account_key` into every credential it mints, and it can
//! make an identity key of its own and sign for any device under it. Before
//! this check, a device took that field as its own key: the one-account-key
//! rule judged "the reader's own key" from it, so the person's own device
//! merged the add of a server-made device certified under the same key, and
//! both halves of the security code were read from it, so a comparison
//! passed. The attack here worked and now stops at the first step: the device
//! will not open on, or be handed, that credential. A device that holds no
//! account key yet refuses every certified credential, for the same reason.

#![cfg(feature = "test-forgery")]
#![allow(clippy::expect_used, clippy::unwrap_used)]

mod support;

use peachy_mls_core::issuer::{device_key_pair, TestIssuer};
use peachy_mls_core::{
    account_identity_public_key, Client, ClientConfig, CredentialRejection, DenyReason, Error,
    FixedClock, MemoryKv, PeachyStorage,
};
use support::{client, device_seed, issuer, DAY, HOUR, NOW};

const DM: &[u8] = b"33333333-3333-4333-8333-333333333333";
/// An account key the SERVER made: it holds the private half of the identity
/// key derived from it, so it can certify any device under that key.
const SERVERS_ACCOUNT_KEY: [u8; 32] = [0x99; 32];
const ADA: &str = "5b0f5a52-8a55-4a5b-9d59-1b9a7a3f0c11";
const BO: &str = "0f3c6d2e-1111-4222-8333-944455556666";

/// The account key Ada's first device minted and holds.
fn adas_account_key() -> [u8; 32] {
    TestIssuer::test_account_key(ADA)
}

fn adas_identity() -> [u8; 32] {
    account_identity_public_key(&adas_account_key()).unwrap()
}

/// A `pdc1` for Ada's phone carrying whatever account certificate the server
/// chose to write into it (none for `None`).
fn token_under(server: &TestIssuer, account: Option<&[u8]>, exp: i64) -> Vec<u8> {
    let (_, public) = device_key_pair(&device_seed(1));
    server
        .issue_for_account(ADA, "device-ada-phone", &public, account, NOW - HOUR, exp)
        .expect("mint")
}

/// Ada's phone opened on `token`, holding the account identity key `held`.
fn open(server: &TestIssuer, token: Vec<u8>, held: Option<[u8; 32]>) -> Result<Client, Error> {
    let mut config = ClientConfig::new(token, device_seed(1), server.trusted_keys().unwrap())
        .with_storage(PeachyStorage::in_memory())
        .with_own_account_identity(held);
    config.clock = Some(Box::new(FixedClock(NOW)));
    Client::new(config)
}

fn rejection<T>(result: Result<T, Error>) -> CredentialRejection {
    match result {
        Err(Error::CredentialRejected(reason)) => reason,
        Err(other) => panic!("expected a credential rejection, got {other:?}"),
        Ok(_) => panic!("expected a credential rejection, got a client"),
    }
}

/// The attack's first step, refused. Ada's first device minted her account
/// key and certified itself under it; the server answered with a credential
/// certified under its own key. The device will not run on it, so there is no
/// "own key" for the server's device to share, and no security code computed
/// from the server's key.
#[test]
fn a_device_will_not_open_on_a_credential_under_an_account_key_it_does_not_hold() {
    let server = issuer();
    let token = token_under(&server, Some(&SERVERS_ACCOUNT_KEY), NOW + 30 * DAY);
    assert_eq!(
        rejection(open(&server, token, Some(adas_identity()))),
        CredentialRejection::NotOwnAccountKey
    );
}

/// The honest credential opens, and its key is the held one.
#[test]
fn a_device_opens_on_a_credential_under_the_key_it_holds() {
    let server = issuer();
    let token = token_under(&server, Some(&adas_account_key()), NOW + 30 * DAY);
    let ada = open(&server, token, Some(adas_identity())).expect("opens");
    assert_eq!(ada.identity().account_key, Some(adas_identity()));
}

/// A credential with no certificate is still the device's own while it waits
/// to be let in (a stale key's uncertified fallback, an approval not yet
/// made): it carries no key that could be another's.
#[test]
fn an_uncertified_credential_still_opens_with_a_key_held() {
    let server = issuer();
    let token = token_under(&server, None, NOW + 30 * DAY);
    let ada = open(&server, token, Some(adas_identity())).expect("opens");
    assert_eq!(ada.identity().account_key, None);
}

/// The certificate arriving later, at a device that opened holding no key
/// (it was waiting to be approved): handed the key it now holds with the
/// re-registered credential, it refuses one under the server's key and keeps
/// the credential it had; the honest one installs.
#[test]
fn a_certificate_under_another_key_is_refused_when_it_arrives() {
    let server = issuer();
    let mut ada =
        open(&server, token_under(&server, None, NOW + 20 * DAY), None).expect("waiting device");

    let forged = token_under(&server, Some(&SERVERS_ACCOUNT_KEY), NOW + 30 * DAY);
    assert_eq!(
        rejection(ada.update_credential(&forged, Some(adas_identity()))),
        CredentialRejection::NotOwnAccountKey
    );
    assert_eq!(ada.identity().account_key, None, "the old credential stays");

    let honest = token_under(&server, Some(&adas_account_key()), NOW + 30 * DAY);
    ada.update_credential(&honest, Some(adas_identity()))
        .expect("the honest certificate installs");
    assert_eq!(ada.identity().account_key, Some(adas_identity()));
}

/// A renewal at a device that opened holding its key checks the renewed
/// credential against that key when the call names none.
#[test]
fn a_renewal_is_held_to_the_key_the_client_opened_with() {
    let server = issuer();
    let mut ada = open(
        &server,
        token_under(&server, None, NOW + 20 * DAY),
        Some(adas_identity()),
    )
    .expect("opens");
    let forged = token_under(&server, Some(&SERVERS_ACCOUNT_KEY), NOW + 30 * DAY);
    assert_eq!(
        rejection(ada.update_credential(&forged, None)),
        CredentialRejection::NotOwnAccountKey
    );
}

/// A device that holds no account key has nothing to check a certificate
/// against, and a certificate is something it can make only once it holds the
/// key. So it refuses ANY certified credential and runs uncertified until the
/// key arrives.
///
/// The attack this closes: the server certified a waiting device under a key
/// of its own. The device took it as given, and once approved it could not
/// leave it: the honest credential was refused because "the certificate never
/// changes", the device kept the server's certificate and no held key, and
/// plain renewals under the server's key kept installing. Here the waiting
/// device refuses at the first step, and the approval installs the honest
/// credential through the "none to one" step.
#[test]
fn a_waiting_device_will_not_open_on_a_certified_credential() {
    let server = issuer();

    // Under the server's key, and even under Ada's real key: either way it is
    // a certificate the waiting device did not make and cannot check.
    for account in [SERVERS_ACCOUNT_KEY, adas_account_key()] {
        let token = token_under(&server, Some(&account), NOW + 20 * DAY);
        assert_eq!(
            rejection(open(&server, token, None)),
            CredentialRejection::NotOwnAccountKey
        );
    }

    // It runs uncertified while it waits.
    let mut ada =
        open(&server, token_under(&server, None, NOW + 20 * DAY), None).expect("waiting device");
    // Handed a certified renewal while it still holds nothing: refused, and
    // it keeps the credential it had.
    let forged = token_under(&server, Some(&SERVERS_ACCOUNT_KEY), NOW + 30 * DAY);
    assert_eq!(
        rejection(ada.update_credential(&forged, None)),
        CredentialRejection::NotOwnAccountKey
    );
    assert_eq!(ada.identity().account_key, None);

    // Approved: the key arrives and the honest credential installs.
    let honest = token_under(&server, Some(&adas_account_key()), NOW + 30 * DAY);
    ada.update_credential(&honest, Some(adas_identity()))
        .expect("the approval installs");
    assert_eq!(ada.identity().account_key, Some(adas_identity()));
    // And from here every renewal is held to that key.
    assert_eq!(
        rejection(ada.update_credential(&forged, None)),
        CredentialRejection::NotOwnAccountKey
    );
    assert_eq!(ada.identity().account_key, Some(adas_identity()));
}

/// The window leaves nothing behind. The attack's second half: groups a
/// waiting device joined under the server's key kept its leaf under that key,
/// and the server's own device beside it, across a restart on the held key.
/// Now the waiting device never opens on the server's certificate, so it
/// writes nothing to its store; uncertified, it mints no key package, so no
/// group seats it in the window; and the restart on the held key finds no
/// group at all.
#[test]
fn a_waiting_device_is_seated_nowhere_before_it_holds_the_key() {
    let server = issuer();
    let kv = MemoryKv::new();
    let open_on = |token: Vec<u8>, held: Option<[u8; 32]>| {
        let mut config = ClientConfig::new(token, device_seed(1), server.trusted_keys().unwrap())
            .with_storage(PeachyStorage::open(Box::new(kv.clone())).unwrap())
            .with_own_account_identity(held);
        config.clock = Some(Box::new(FixedClock(NOW)));
        Client::new(config)
    };

    assert_eq!(
        rejection(open_on(
            token_under(&server, Some(&SERVERS_ACCOUNT_KEY), NOW + 20 * DAY),
            None
        )),
        CredentialRejection::NotOwnAccountKey
    );
    {
        let waiting = open_on(token_under(&server, None, NOW + 20 * DAY), None)
            .expect("the uncertified credential opens");
        assert!(matches!(
            waiting.generate_key_package(),
            Err(Error::CredentialRejected(CredentialRejection::NotApproved))
        ));
    }

    let ada = open_on(
        token_under(&server, Some(&adas_account_key()), NOW + 30 * DAY),
        Some(adas_identity()),
    )
    .expect("the honest restart opens");
    assert_eq!(ada.identity().account_key, Some(adas_identity()));
    assert!(ada.roster(DM).is_err(), "no group from the window");
}

/// The control the attack relied on, kept: with Ada's own credential honest,
/// a server-made device under the server's key is refused by Bo's adder.
#[test]
fn with_an_honest_own_credential_the_servers_device_is_refused() {
    let server = issuer();
    let token = token_under(&server, Some(&adas_account_key()), NOW + 30 * DAY);
    let mut ada = open(&server, token, Some(adas_identity())).unwrap();
    let mut bo = client(&server, 2, BO, "device-bo-phone");
    bo.create_group(DM).unwrap();
    let key_package = ada.generate_key_package().unwrap();
    let bundle = bo.add_member(DM, &key_package).unwrap();
    bo.merge_pending_commit(DM).unwrap();
    ada.join_from_welcome(&bundle.welcome.unwrap()).unwrap();

    let seed = device_seed(9);
    let (_, public) = device_key_pair(&seed);
    let ghost_token = server
        .issue_for_account(
            ADA,
            "device-server-ghost",
            &public,
            Some(&SERVERS_ACCOUNT_KEY),
            NOW - HOUR,
            NOW + 30 * DAY,
        )
        .unwrap();
    // The server runs its device, so it holds the key the server made.
    let mut config = ClientConfig::new(ghost_token, seed, server.trusted_keys().unwrap())
        .with_own_account_identity(Some(
            account_identity_public_key(&SERVERS_ACCOUNT_KEY).unwrap(),
        ));
    config.clock = Some(Box::new(FixedClock(NOW)));
    let ghost = Client::new(config).unwrap();
    match bo.add_member(DM, &ghost.generate_key_package().unwrap()) {
        Err(Error::PolicyRefused(DenyReason::AccountKeyConflict)) => {}
        other => panic!("expected a refusal, got {other:?}"),
    }
}
