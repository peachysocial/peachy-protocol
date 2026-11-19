// SPDX-License-Identifier: MIT
//! The profile's values (spec §4.1, §4.3, §6.4): what an `UpdateValue`'s
//! bytes hold for each label kind.
//!
//! Each type encodes in the TLS presentation language and decodes exactly:
//! trailing bytes, an unknown kind or a field of a length the spec does not
//! allow is refused.

use crate::codec::{Reader, Writer};
use crate::error::{Error, Result};
use crate::suite::{Hash, PUBLIC_KEY_LEN, SIGNATURE_LEN};

/// The account label's value (spec §4.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountValue {
    /// `kind = 1`: a live account.
    Live {
        /// `account_identity_key[32]`: the account's Ed25519 public key.
        account_identity_key: [u8; PUBLIC_KEY_LEN],
        /// `device_set_root[32]`: [`super::DeviceSet::root`].
        device_set_root: Hash,
    },
    /// `kind = 0`: the account was deleted.
    Closed,
}

impl AccountValue {
    /// The value's bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            AccountValue::Live {
                account_identity_key,
                device_set_root,
            } => {
                let mut out = Vec::with_capacity(65);
                out.push(1);
                out.extend_from_slice(account_identity_key);
                out.extend_from_slice(device_set_root);
                out
            }
            AccountValue::Closed => vec![0],
        }
    }

    /// Parses a value.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        let value = match r.u8()? {
            1 => AccountValue::Live {
                account_identity_key: r.array()?,
                device_set_root: r.array()?,
            },
            0 => AccountValue::Closed,
            _ => return Err(Error::Decode("unknown account value kind".into())),
        };
        r.finish()?;
        Ok(value)
    }
}

/// The handle and phone labels' value (spec §4.3, §4.4):
/// `struct { opaque actor_id<0..16>; }`, empty when the address was released.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MappingValue {
    /// Who holds the address, or `None` once released.
    pub actor_id: Option<[u8; 16]>,
}

impl MappingValue {
    /// The value's bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        match &self.actor_id {
            Some(id) => {
                let mut out = Vec::with_capacity(17);
                out.push(16);
                out.extend_from_slice(id);
                out
            }
            None => vec![0],
        }
    }

    /// Parses a value. Only lengths 0 and 16 are actor ids.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        let id = r.bytes(0, 16, "actor id longer than 16 bytes")?;
        r.finish()?;
        let actor_id = match id.len() {
            0 => None,
            16 => Some(
                id.try_into()
                    .map_err(|_| Error::Decode("actor id".into()))?,
            ),
            _ => return Err(Error::Decode("actor id of neither 0 nor 16 bytes".into())),
        };
        Ok(MappingValue { actor_id })
    }
}

/// The auditor instance label's value (spec §6.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditorInstance {
    /// `uint64 boot_time`, milliseconds since the Unix epoch.
    pub boot_time: u64,
    /// `uint64 start_position`: the log entry the instance resumes after.
    pub start_position: u64,
    /// `opaque predecessor_key<0..32>`: empty only for the first instance.
    pub predecessor_key: Option<[u8; PUBLIC_KEY_LEN]>,
    /// `opaque handoff_sig<0..64>`: the predecessor's signature over the
    /// handoff, empty for the first instance and after a cold start.
    pub handoff_sig: Option<[u8; SIGNATURE_LEN]>,
}

impl AuditorInstance {
    fn check(&self) -> Result<()> {
        if self.handoff_sig.is_some() && self.predecessor_key.is_none() {
            return Err(Error::InvalidArgument(
                "a handoff signature without a predecessor",
            ));
        }
        Ok(())
    }

    /// The value's bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        self.check()?;
        let mut w = Writer::new();
        w.u64(self.boot_time).u64(self.start_position);
        w.bytes(
            self.predecessor_key.as_ref().map_or(&[][..], |k| &k[..]),
            0,
            32,
            "predecessor key",
        );
        w.bytes(
            self.handoff_sig.as_ref().map_or(&[][..], |s| &s[..]),
            0,
            64,
            "handoff signature",
        );
        w.finish()
    }

    /// Parses a value. The key is 0 or 32 bytes, the signature 0 or 64, and
    /// a signature needs a key.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        let boot_time = r.u64()?;
        let start_position = r.u64()?;
        let key = r.bytes(0, 32, "predecessor key longer than 32 bytes")?;
        let sig = r.bytes(0, 64, "handoff signature longer than 64 bytes")?;
        r.finish()?;
        let predecessor_key =
            match key.len() {
                0 => None,
                _ => Some(key.try_into().map_err(|_| {
                    Error::Decode("predecessor key of neither 0 nor 32 bytes".into())
                })?),
            };
        let handoff_sig = match sig.len() {
            0 => None,
            _ => Some(sig.try_into().map_err(|_| {
                Error::Decode("handoff signature of neither 0 nor 64 bytes".into())
            })?),
        };
        let value = AuditorInstance {
            boot_time,
            start_position,
            predecessor_key,
            handoff_sig,
        };
        value
            .check()
            .map_err(|_| Error::Decode("a handoff signature without a predecessor".into()))?;
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn account_value_vectors() {
        let live = AccountValue::Live {
            account_identity_key: [0xaa; 32],
            device_set_root: [0xbb; 32],
        };
        let bytes = live.to_bytes();
        assert_eq!(
            hex::encode(&bytes),
            format!("01{}{}", "aa".repeat(32), "bb".repeat(32))
        );
        assert_eq!(AccountValue::from_bytes(&bytes).unwrap(), live);
        assert_eq!(AccountValue::Closed.to_bytes(), vec![0]);
        assert_eq!(
            AccountValue::from_bytes(&[0]).unwrap(),
            AccountValue::Closed
        );
        assert!(AccountValue::from_bytes(&[]).is_err());
        assert!(AccountValue::from_bytes(&[2]).is_err());
        assert!(AccountValue::from_bytes(&[0, 0]).is_err());
        assert!(AccountValue::from_bytes(&bytes[..64]).is_err());
        let mut long = bytes.clone();
        long.push(0);
        assert!(AccountValue::from_bytes(&long).is_err());
    }

    #[test]
    fn mapping_value_vectors() {
        let held = MappingValue {
            actor_id: Some([0x01; 16]),
        };
        assert_eq!(
            hex::encode(held.to_bytes()),
            format!("10{}", "01".repeat(16))
        );
        assert_eq!(MappingValue::from_bytes(&held.to_bytes()).unwrap(), held);
        let released = MappingValue { actor_id: None };
        assert_eq!(released.to_bytes(), vec![0]);
        assert_eq!(MappingValue::from_bytes(&[0]).unwrap(), released);
        assert!(MappingValue::from_bytes(&[]).is_err());
        assert!(MappingValue::from_bytes(&[1, 7]).is_err());
        assert!(MappingValue::from_bytes(&[17; 18]).is_err());
        assert!(MappingValue::from_bytes(&[0, 0]).is_err());
    }

    #[test]
    fn auditor_instance_vectors() {
        let first = AuditorInstance {
            boot_time: 0x0102,
            start_position: 0,
            predecessor_key: None,
            handoff_sig: None,
        };
        assert_eq!(
            hex::encode(first.to_bytes().unwrap()),
            concat!("0000000000000102", "0000000000000000", "00", "00")
        );
        let handoff = AuditorInstance {
            boot_time: 5,
            start_position: 9,
            predecessor_key: Some([0x33; 32]),
            handoff_sig: Some([0x44; 64]),
        };
        let bytes = handoff.to_bytes().unwrap();
        assert_eq!(
            hex::encode(&bytes),
            format!(
                "{}{}20{}40{}",
                "0000000000000005",
                "0000000000000009",
                "33".repeat(32),
                "44".repeat(64)
            )
        );
        assert_eq!(AuditorInstance::from_bytes(&bytes).unwrap(), handoff);
        let cold = AuditorInstance {
            handoff_sig: None,
            ..handoff
        };
        assert_eq!(
            AuditorInstance::from_bytes(&cold.to_bytes().unwrap()).unwrap(),
            cold
        );
        // A signature with no predecessor, a short key, a short signature.
        let orphan = AuditorInstance {
            predecessor_key: None,
            ..handoff
        };
        assert!(orphan.to_bytes().is_err());
        let mut orphan_bytes = first.to_bytes().unwrap();
        orphan_bytes.pop();
        orphan_bytes.push(64);
        orphan_bytes.extend([0x44; 64]);
        assert!(AuditorInstance::from_bytes(&orphan_bytes).is_err());
        let mut short_key = vec![0u8; 16];
        short_key.push(31);
        short_key.extend([0x33; 31]);
        short_key.push(0);
        assert!(AuditorInstance::from_bytes(&short_key).is_err());
        let mut short_sig = vec![0u8; 16];
        short_sig.push(32);
        short_sig.extend([0x33; 32]);
        short_sig.push(63);
        short_sig.extend([0x44; 63]);
        assert!(AuditorInstance::from_bytes(&short_sig).is_err());
    }
}
