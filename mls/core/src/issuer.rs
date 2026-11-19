// SPDX-License-Identifier: MIT
//! A `pdc1` issuer, for tests and fixtures. **Not the server.**
//!
//! Behind the `test-issuer` feature, off by default, so a release build of
//! `peachy-mls-core` contains no code that can mint a credential. The real
//! issuer is the server's credential issuer and there is exactly one of it: only
//! the server holds the key, the server signs, and a client verifies. This
//! module exists so that the tests in this crate — and the golden fixture the
//! four clients share — can produce a credential without a running server and
//! its signing key.
//!
//! It is also the other half of a claim: the round-trip test in
//! `tests/identity.rs` mints here and verifies through
//! [`crate::identity::PeachyIdentityProvider`], which is what holds this
//! crate's reading of the token format against the server's. If the server's
//! `canonicalPayload` ever gains a field or changes an order, that test is
//! where the two stop agreeing.

use ed25519_dalek::{Signer as _, SigningKey};

use crate::account_identity::{account_identity_public_key, sign_account_device};
use crate::credential::{
    encode_base64url, encode_standard, CredentialPayload, CREDENTIAL_VERSION,
    ED25519_PUBLIC_KEY_BYTES, TOKEN_PREFIX,
};
use crate::error::{Error, Result};
use crate::identity::TrustedServerKeys;

/// A stand-in for the server's device-credential signing key.
#[derive(Debug, Clone)]
pub struct TestIssuer {
    signing: SigningKey,
    kid: String,
}

impl TestIssuer {
    /// An issuer from a fixed 32-byte seed. Fixed, not random, so a fixture
    /// mints the same bytes on every machine.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let signing = SigningKey::from_bytes(seed);
        let kid = key_id_for(&signing.verifying_key().to_bytes());
        Self { signing, kid }
    }

    /// The `kid` this issuer signs with: the first 8 hex of sha256 over the
    /// raw public key, exactly as `keyIdFor` in the server's credential issuer.
    pub fn kid(&self) -> &str {
        &self.kid
    }

    pub fn public_key(&self) -> [u8; ED25519_PUBLIC_KEY_BYTES] {
        self.signing.verifying_key().to_bytes()
    }

    /// A trusted-key set holding this issuer's key — the set a client fetching
    /// `/healthz/device-credential-keys` from this server would end up with.
    pub fn trusted_keys(&self) -> Result<TrustedServerKeys> {
        let mut keys = TrustedServerKeys::new();
        keys.insert(self.kid.clone(), &self.public_key())?;
        Ok(keys)
    }

    /// The JSON `GET /healthz/device-credential-keys` would return for this
    /// issuer. Used to test [`TrustedServerKeys::from_published_json`] against
    /// the shape the server actually serves.
    pub fn published_json(&self) -> String {
        self.published_json_with_use("device")
    }

    /// The same list, with this issuer's key published under `key_use`. A use
    /// other than `device` must leave a reader trusting nothing.
    pub fn published_json_with_use(&self, key_use: &str) -> String {
        format!(
            "{{\"enabled\":true,\"keys\":[{{\"kid\":\"{}\",\"publicKey\":\"{}\",\"current\":true,\"use\":\"{}\"}}]}}",
            self.kid,
            encode_standard(&self.public_key()),
            key_use,
        )
    }

    /// Mint a `pdc1` device credential for a device its account has let in.
    ///
    /// The account certificate is signed with [`Self::test_account_key`] of
    /// `actor_id`, so every device a test mints for one actor shares one
    /// account identity key, exactly as a real account's devices do, and a
    /// test that is not about approval never has to think about it.
    pub fn issue(
        &self,
        actor_id: &str,
        device_id: &str,
        device_key: &[u8; ED25519_PUBLIC_KEY_BYTES],
        issued_at: i64,
        expires_at: i64,
    ) -> Result<Vec<u8>> {
        self.issue_for_account(
            actor_id,
            device_id,
            device_key,
            Some(&Self::test_account_key(actor_id)),
            issued_at,
            expires_at,
        )
    }

    /// Mint a credential under the account key you name, or with no account
    /// certificate at all (`None`): a device nobody on the account has let in.
    pub fn issue_for_account(
        &self,
        actor_id: &str,
        device_id: &str,
        device_key: &[u8; ED25519_PUBLIC_KEY_BYTES],
        account_key: Option<&[u8]>,
        issued_at: i64,
        expires_at: i64,
    ) -> Result<Vec<u8>> {
        let (account_key, account_sig) = match account_key {
            Some(account) => (
                encode_standard(&account_identity_public_key(account)?),
                encode_standard(&sign_account_device(account, device_key)?),
            ),
            None => (String::new(), String::new()),
        };
        let payload = CredentialPayload {
            v: CREDENTIAL_VERSION,
            kid: self.kid.clone(),
            actor_id: actor_id.to_string(),
            device_id: device_id.to_string(),
            device_key: encode_standard(device_key),
            account_key,
            account_sig,
            iat: issued_at,
            exp: expires_at,
        };
        self.issue_payload(&payload)
    }

    /// The account key [`Self::issue`] signs `actor_id`'s devices under:
    /// `SHA-256("peachy-test-account" || 0x00 || actor_id)`. A test stand-in
    /// for the key a real account mints at random.
    pub fn test_account_key(actor_id: &str) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"peachy-test-account");
        hasher.update([0u8]);
        hasher.update(actor_id.as_bytes());
        hasher.finalize().into()
    }

    /// Mint a credential over a payload you built yourself — the door for a
    /// fixture that needs a wrong `kid` or an impossible clock.
    pub fn issue_payload(&self, payload: &CredentialPayload) -> Result<Vec<u8>> {
        self.issue_payload_with_prefix(TOKEN_PREFIX, payload)
    }

    /// The same, over a prefix you chose.
    pub fn issue_payload_with_prefix(
        &self,
        prefix: &str,
        payload: &CredentialPayload,
    ) -> Result<Vec<u8>> {
        let encoded = serde_json::to_vec(payload)
            .map_err(|err| Error::invalid(format!("could not encode a payload: {err}")))?;
        Ok(self.issue_raw(prefix, &encoded))
    }

    /// Sign payload BYTES you wrote yourself, under the prefix you chose.
    ///
    /// **The forgery door.** It exists so a test can mint what this crate's
    /// own types cannot express — a payload with a field the format does not
    /// have, or a prefix it does not read, signed by the trusted key — and prove every client refuses it. Nothing that ships can reach
    /// it: the whole module is behind `test-issuer`.
    pub fn issue_raw(&self, prefix: &str, payload_bytes: &[u8]) -> Vec<u8> {
        let signature = self.signing.sign(payload_bytes);
        format!(
            "{prefix}.{}.{}",
            encode_base64url(payload_bytes),
            encode_base64url(&signature.to_bytes())
        )
        .into_bytes()
    }
}

/// A device key pair, for a test client.
pub fn device_key_pair(seed: &[u8; 32]) -> (SigningKey, [u8; ED25519_PUBLIC_KEY_BYTES]) {
    let signing = SigningKey::from_bytes(seed);
    let public = signing.verifying_key().to_bytes();
    (signing, public)
}

fn key_id_for(public_key: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(public_key);
    let hex: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    hex[..8].to_string()
}
