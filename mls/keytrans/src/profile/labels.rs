// SPDX-License-Identifier: MIT
//! The profile's four label kinds (spec §4.1, §4.3, §4.4, §6.4). Each label
//! starts with a one-byte kind, so the spaces cannot collide.

use crate::error::{Error, Result};

/// The account label's kind, `a`.
pub const KIND_ACCOUNT: u8 = 0x61;
/// The handle label's kind, `h`.
pub const KIND_HANDLE: u8 = 0x68;
/// The phone label's kind, `p`.
pub const KIND_PHONE: u8 = 0x70;
/// The auditor instance label's kind, `k`.
pub const KIND_AUDITOR_INSTANCE: u8 = 0x6B;

/// The longest handle a label can carry: a label is `opaque label<0..2^8-1>`
/// and the kind takes one byte.
pub const MAX_HANDLE_BYTES: usize = 254;

/// A label of the profile.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Label {
    /// `0x61 || actor_id`: the account's keys (spec §4.1).
    Account {
        /// `users.actor_id`, the UUID's 16 raw bytes.
        actor_id: [u8; 16],
    },
    /// `0x68 || handle`: who holds a handle (spec §4.3).
    Handle {
        /// The handle as `SetHandle` stores it: lowercase UTF-8, no `@`.
        handle: String,
    },
    /// `0x70 || phone_lookup`: who holds a phone number, under its blind
    /// index (spec §4.4).
    Phone {
        /// The 32-byte keyed blind index of the E.164 number.
        lookup: [u8; 32],
    },
    /// `0x6B || instance_key`: one of the auditor's instances (spec §6.4).
    AuditorInstance {
        /// The instance's Ed25519 public key.
        instance_key: [u8; 32],
    },
}

fn check_handle(handle: &str) -> Result<()> {
    if handle.is_empty() || handle.len() > MAX_HANDLE_BYTES {
        return Err(Error::InvalidArgument("handle length"));
    }
    if handle.chars().any(char::is_uppercase) {
        return Err(Error::InvalidArgument("handle is not lowercase"));
    }
    Ok(())
}

impl Label {
    /// The label for `actor_id`'s account.
    pub fn account(actor_id: [u8; 16]) -> Self {
        Label::Account { actor_id }
    }

    /// The label for a handle, which must already be lowercase.
    pub fn handle(handle: &str) -> Result<Self> {
        check_handle(handle)?;
        Ok(Label::Handle {
            handle: handle.to_owned(),
        })
    }

    /// The label for a phone number's blind index.
    pub fn phone(lookup: [u8; 32]) -> Self {
        Label::Phone { lookup }
    }

    /// The label for an auditor instance's key.
    pub fn auditor_instance(instance_key: [u8; 32]) -> Self {
        Label::AuditorInstance { instance_key }
    }

    /// The label's kind byte.
    pub fn kind(&self) -> u8 {
        match self {
            Label::Account { .. } => KIND_ACCOUNT,
            Label::Handle { .. } => KIND_HANDLE,
            Label::Phone { .. } => KIND_PHONE,
            Label::AuditorInstance { .. } => KIND_AUDITOR_INSTANCE,
        }
    }

    /// The label's bytes, as the draft's `label` fields carry them.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut out = vec![self.kind()];
        match self {
            Label::Account { actor_id } => out.extend_from_slice(actor_id),
            Label::Handle { handle } => {
                check_handle(handle)?;
                out.extend_from_slice(handle.as_bytes());
            }
            Label::Phone { lookup } => out.extend_from_slice(lookup),
            Label::AuditorInstance { instance_key } => out.extend_from_slice(instance_key),
        }
        Ok(out)
    }

    /// Parses a label, refusing an unknown kind or a body of the wrong shape.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let (&kind, body) = bytes
            .split_first()
            .ok_or_else(|| Error::Decode("empty label".into()))?;
        let fixed = |what: &str| Error::Decode(format!("{what} label of the wrong length"));
        match kind {
            KIND_ACCOUNT => Ok(Label::Account {
                actor_id: body.try_into().map_err(|_| fixed("account"))?,
            }),
            KIND_HANDLE => {
                let handle = core::str::from_utf8(body)
                    .map_err(|_| Error::Decode("handle label is not UTF-8".into()))?;
                check_handle(handle)
                    .map_err(|_| Error::Decode("handle label of the wrong shape".into()))?;
                Ok(Label::Handle {
                    handle: handle.to_owned(),
                })
            }
            KIND_PHONE => Ok(Label::Phone {
                lookup: body.try_into().map_err(|_| fixed("phone"))?,
            }),
            KIND_AUDITOR_INSTANCE => Ok(Label::AuditorInstance {
                instance_key: body.try_into().map_err(|_| fixed("auditor instance"))?,
            }),
            _ => Err(Error::Decode("unknown label kind".into())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn label_vectors() {
        let actor: [u8; 16] = hex::decode("0123456789abcdef0123456789abcdef")
            .unwrap()
            .try_into()
            .unwrap();
        let cases = [
            (
                Label::account(actor),
                "610123456789abcdef0123456789abcdef".to_string(),
            ),
            (
                Label::handle("ada_lovelace").unwrap(),
                "686164615f6c6f76656c616365".to_string(),
            ),
            (Label::phone([0x11; 32]), format!("70{}", "11".repeat(32))),
            (
                Label::auditor_instance([0x22; 32]),
                format!("6b{}", "22".repeat(32)),
            ),
        ];
        for (label, expected) in cases {
            let bytes = label.to_bytes().unwrap();
            assert_eq!(hex::encode(&bytes), expected);
            assert_eq!(Label::from_bytes(&bytes).unwrap(), label);
            assert_eq!(bytes[0], label.kind());
        }
    }

    #[test]
    fn handles() {
        // Non-ASCII lowercase is allowed: the label carries what is stored.
        let label = Label::handle("café").unwrap();
        assert_eq!(
            Label::from_bytes(&label.to_bytes().unwrap()).unwrap(),
            label
        );
        assert!(Label::handle("Ada").is_err());
        assert!(Label::handle("").is_err());
        assert!(Label::handle(&"a".repeat(254)).is_ok());
        assert!(Label::handle(&"a".repeat(255)).is_err());
        // A full-length handle label still fits `label<0..2^8-1>`.
        assert_eq!(
            Label::handle(&"a".repeat(254))
                .unwrap()
                .to_bytes()
                .unwrap()
                .len(),
            255
        );
    }

    #[test]
    fn malformed_labels_are_refused() {
        assert!(Label::from_bytes(&[]).is_err());
        assert!(Label::from_bytes(&[KIND_ACCOUNT; 16]).is_err());
        assert!(Label::from_bytes(&[KIND_ACCOUNT; 18]).is_err());
        assert!(Label::from_bytes(&[KIND_PHONE; 32]).is_err());
        assert!(Label::from_bytes(&[KIND_AUDITOR_INSTANCE; 34]).is_err());
        assert!(Label::from_bytes(&[KIND_HANDLE]).is_err());
        assert!(Label::from_bytes(&[KIND_HANDLE, 0xff]).is_err());
        assert!(Label::from_bytes(b"hABC").is_err());
        assert!(Label::from_bytes(b"zanything").is_err());
    }
}
