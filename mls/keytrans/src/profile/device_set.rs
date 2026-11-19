// SPDX-License-Identifier: MIT
//! The device set (spec §4.2): an account's certified devices, committed to
//! by one Merkle root in its account value.
//!
//! Entries are sorted by `device_key` and hashed as an RFC 6962-shaped tree:
//!
//! - leaf = SHA-256(0x00 || "peachy-kt-device-v1" || 0x00 || encoded entry)
//! - node = SHA-256(0x01 || left || right), the left subtree holding the
//!   largest power of two of entries below the count
//! - the empty set's root = SHA-256("peachy-kt-device-v1" || 0x00 || "empty")
//!
//! A device proves membership with an inclusion path: its position, the
//! set's size, and the sibling values from the leaf up.
//!
//! Checking an entry's `account_sig` against the account identity key is the
//! MLS core's job (it owns the account certificate's format), not this
//! module's.

use crate::codec::{Reader, Writer};
use crate::error::{Error, Result};
use crate::suite::{hash, Hash, PUBLIC_KEY_LEN, SIGNATURE_LEN};

/// The domain string of every device-set hash.
pub const DOMAIN: &[u8] = b"peachy-kt-device-v1";
/// The longest `device_id`.
pub const MAX_DEVICE_ID_LEN: usize = 64;

/// One certified device (spec §4.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceEntry {
    /// `opaque device_id<1..64>`: the MLS row's id, ASCII.
    pub device_id: Vec<u8>,
    /// `device_key[32]`: the MLS row's Ed25519 key.
    pub device_key: [u8; PUBLIC_KEY_LEN],
    /// `account_sig[64]`: the account certificate over the device key.
    pub account_sig: [u8; SIGNATURE_LEN],
}

fn check_device_id(id: &[u8]) -> Result<()> {
    if id.is_empty() || id.len() > MAX_DEVICE_ID_LEN {
        return Err(Error::InvalidArgument("device id length"));
    }
    if !id.is_ascii() {
        return Err(Error::InvalidArgument("device id is not ASCII"));
    }
    Ok(())
}

impl DeviceEntry {
    /// The entry's encoding.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        check_device_id(&self.device_id)?;
        Writer::new()
            .bytes(&self.device_id, 1, MAX_DEVICE_ID_LEN, "device id")
            .raw(&self.device_key)
            .raw(&self.account_sig)
            .finish()
    }

    /// Parses an entry.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        let device_id = r.bytes(1, MAX_DEVICE_ID_LEN, "device id length")?.to_vec();
        check_device_id(&device_id).map_err(|_| Error::Decode("device id is not ASCII".into()))?;
        let entry = DeviceEntry {
            device_id,
            device_key: r.array()?,
            account_sig: r.array()?,
        };
        r.finish()?;
        Ok(entry)
    }

    /// The entry's leaf value.
    pub fn leaf_hash(&self) -> Result<Hash> {
        Ok(hash(&[&[0x00], DOMAIN, &[0x00], &self.to_bytes()?]))
    }
}

/// An inner node's value.
pub fn node_hash(left: &Hash, right: &Hash) -> Hash {
    hash(&[&[0x01], left, right])
}

/// The empty set's root.
pub fn empty_root() -> Hash {
    hash(&[DOMAIN, &[0x00], b"empty"])
}

/// The largest power of two strictly below `n` (for `n >= 2`).
fn split(n: usize) -> usize {
    let mut k = 1;
    while k * 2 < n {
        k *= 2;
    }
    k
}

/// A device's inclusion path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceInclusion {
    /// The entry's position in the sorted set.
    pub index: u64,
    /// The number of entries in the set.
    pub size: u64,
    /// Sibling values from the leaf's up to the root's children.
    pub path: Vec<Hash>,
}

impl DeviceInclusion {
    /// The root this path and `entry` compute.
    pub fn root(&self, entry: &DeviceEntry) -> Result<Hash> {
        if self.index >= self.size {
            return Err(Error::MalformedProof("device index outside the set"));
        }
        let index =
            usize::try_from(self.index).map_err(|_| Error::MalformedProof("device index"))?;
        let size =
            usize::try_from(self.size).map_err(|_| Error::MalformedProof("device set size"))?;
        root_from_path(index, size, entry.leaf_hash()?, &self.path)
    }

    /// Checks that `entry` is in the set whose root is `root`.
    pub fn verify(&self, entry: &DeviceEntry, root: &Hash) -> Result<()> {
        if self.root(entry)? == *root {
            Ok(())
        } else {
            Err(Error::ProofMismatch("device is not in the set"))
        }
    }
}

fn root_from_path(index: usize, size: usize, leaf: Hash, path: &[Hash]) -> Result<Hash> {
    if size == 1 {
        return if path.is_empty() {
            Ok(leaf)
        } else {
            Err(Error::MalformedProof("device path too long"))
        };
    }
    let (top, rest) = path
        .split_last()
        .ok_or(Error::MalformedProof("device path too short"))?;
    let k = split(size);
    if index < k {
        Ok(node_hash(&root_from_path(index, k, leaf, rest)?, top))
    } else {
        Ok(node_hash(
            top,
            &root_from_path(index - k, size - k, leaf, rest)?,
        ))
    }
}

/// An account's device set: entries sorted by key, no key or id twice.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DeviceSet {
    entries: Vec<DeviceEntry>,
    leaves: Vec<Hash>,
}

impl DeviceSet {
    /// The set of `entries`, in any order. Refuses a malformed entry, two
    /// entries with one device key, or two with one device id.
    pub fn new(mut entries: Vec<DeviceEntry>) -> Result<Self> {
        entries.sort_by_key(|e| e.device_key);
        if entries
            .windows(2)
            .any(|w| matches!(w, [a, b] if a.device_key == b.device_key))
        {
            return Err(Error::InvalidArgument("two devices with one key"));
        }
        let mut ids: Vec<&[u8]> = entries.iter().map(|e| e.device_id.as_slice()).collect();
        ids.sort_unstable();
        if ids.windows(2).any(|w| matches!(w, [a, b] if a == b)) {
            return Err(Error::InvalidArgument("two devices with one id"));
        }
        let leaves = entries
            .iter()
            .map(DeviceEntry::leaf_hash)
            .collect::<Result<Vec<_>>>()?;
        Ok(DeviceSet { entries, leaves })
    }

    /// The entries, sorted by device key.
    pub fn entries(&self) -> &[DeviceEntry] {
        &self.entries
    }

    /// The set's root, for [`super::AccountValue::Live`].
    pub fn root(&self) -> Hash {
        if self.leaves.is_empty() {
            return empty_root();
        }
        subtree_root(&self.leaves)
    }

    /// The position of the device with `device_key`, if it is in the set.
    pub fn position(&self, device_key: &[u8; PUBLIC_KEY_LEN]) -> Option<usize> {
        self.entries
            .binary_search_by(|e| e.device_key.cmp(device_key))
            .ok()
    }

    /// The inclusion path of the entry at `index`.
    pub fn inclusion(&self, index: usize) -> Result<DeviceInclusion> {
        if index >= self.leaves.len() {
            return Err(Error::InvalidArgument("device index outside the set"));
        }
        let mut path = Vec::new();
        collect_path(index, &self.leaves, &mut path);
        Ok(DeviceInclusion {
            index: index as u64,
            size: self.leaves.len() as u64,
            path,
        })
    }
}

fn subtree_root(leaves: &[Hash]) -> Hash {
    match leaves {
        [] => empty_root(),
        [one] => *one,
        _ => {
            let k = split(leaves.len());
            let (l, r) = leaves.split_at(k);
            node_hash(&subtree_root(l), &subtree_root(r))
        }
    }
}

/// Siblings from the leaf up: the deepest is pushed first.
fn collect_path(index: usize, leaves: &[Hash], out: &mut Vec<Hash>) {
    if leaves.len() <= 1 {
        return;
    }
    let k = split(leaves.len());
    let (l, r) = leaves.split_at(k);
    if index < k {
        collect_path(index, l, out);
        out.push(subtree_root(r));
    } else {
        collect_path(index - k, r, out);
        out.push(subtree_root(l));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(i: u8) -> DeviceEntry {
        DeviceEntry {
            device_id: format!("device-{i}").into_bytes(),
            // Keys in reverse order of i, so sorting has work to do.
            device_key: [255 - i; 32],
            account_sig: [i; 64],
        }
    }

    #[test]
    fn entry_encoding() {
        let e = DeviceEntry {
            device_id: b"ab".to_vec(),
            device_key: [0x11; 32],
            account_sig: [0x22; 64],
        };
        let bytes = e.to_bytes().unwrap();
        assert_eq!(
            hex::encode(&bytes),
            format!("026162{}{}", "11".repeat(32), "22".repeat(64))
        );
        assert_eq!(DeviceEntry::from_bytes(&bytes).unwrap(), e);
        let mut leaf_input = vec![0x00];
        leaf_input.extend(b"peachy-kt-device-v1");
        leaf_input.push(0x00);
        leaf_input.extend(&bytes);
        assert_eq!(e.leaf_hash().unwrap(), hash(&[&leaf_input]));

        for bad in [vec![], vec![b'x'; 65], vec![0xc3, 0xa9]] {
            let mut e2 = e.clone();
            e2.device_id = bad;
            assert!(e2.to_bytes().is_err());
        }
        assert!(DeviceEntry::from_bytes(&bytes[..bytes.len() - 1]).is_err());
        let mut zero_id = vec![0u8];
        zero_id.extend(&bytes[3..]);
        assert!(DeviceEntry::from_bytes(&zero_id).is_err());
    }

    #[test]
    fn roots_for_0_1_2_3_and_64_devices() {
        assert_eq!(DeviceSet::new(vec![]).unwrap().root(), empty_root());
        assert_eq!(empty_root(), hash(&[b"peachy-kt-device-v1\x00empty"]));

        let one = DeviceSet::new(vec![entry(1)]).unwrap();
        assert_eq!(one.root(), entry(1).leaf_hash().unwrap());

        // Sorted by key: entry(2) has the smaller key.
        let two = DeviceSet::new(vec![entry(1), entry(2)]).unwrap();
        assert_eq!(two.entries()[0], entry(2));
        let (l1, l2) = (entry(1).leaf_hash().unwrap(), entry(2).leaf_hash().unwrap());
        assert_eq!(two.root(), node_hash(&l2, &l1));

        // Three: (a b) c.
        let three = DeviceSet::new(vec![entry(1), entry(2), entry(3)]).unwrap();
        let l3 = entry(3).leaf_hash().unwrap();
        assert_eq!(three.root(), node_hash(&node_hash(&l3, &l2), &l1));

        let all: Vec<DeviceEntry> = (0..64).map(entry).collect();
        let set = DeviceSet::new(all.clone()).unwrap();
        // Order does not matter.
        let mut reversed = all.clone();
        reversed.reverse();
        assert_eq!(DeviceSet::new(reversed).unwrap().root(), set.root());
        // Every path verifies and is log-sized.
        for i in 0..64 {
            let path = set.inclusion(i).unwrap();
            assert_eq!(path.path.len(), 6);
            path.verify(&set.entries()[i], &set.root()).unwrap();
        }
    }

    #[test]
    fn paths_for_every_size_to_40() {
        for n in 1..=40u8 {
            let set = DeviceSet::new((0..n).map(entry).collect()).unwrap();
            for i in 0..usize::from(n) {
                let path = set.inclusion(i).unwrap();
                path.verify(&set.entries()[i], &set.root()).unwrap();
                assert_eq!(set.position(&set.entries()[i].device_key), Some(i));
            }
            assert!(set.inclusion(usize::from(n)).is_err());
        }
    }

    #[test]
    fn inclusion_negatives() {
        let set = DeviceSet::new((0..5).map(entry).collect()).unwrap();
        let root = set.root();
        let path = set.inclusion(2).unwrap();
        let e = set.entries()[2].clone();
        path.verify(&e, &root).unwrap();
        // Another entry, a changed signature, a wrong index or size, a
        // tampered, short or long path, another root.
        assert!(path.verify(&set.entries()[3], &root).is_err());
        let mut forged = e.clone();
        forged.account_sig[0] ^= 1;
        assert!(path.verify(&forged, &root).is_err());
        // (A size whose tree gives the index the same path shape, such as 6
        // here, is not caught: the size is a hint, as in RFC 6962, and the
        // root is what binds the set.)
        for (index, size) in [(3, 5), (2, 4), (2, 3), (5, 5)] {
            let p = DeviceInclusion {
                index,
                size,
                path: path.path.clone(),
            };
            assert!(p.verify(&e, &root).is_err(), "index {index} size {size}");
        }
        let mut p = path.clone();
        p.path[0][0] ^= 1;
        assert!(p.verify(&e, &root).is_err());
        let mut p = path.clone();
        p.path.pop();
        assert!(p.verify(&e, &root).is_err());
        let mut p = path.clone();
        p.path.push([0; 32]);
        assert!(p.verify(&e, &root).is_err());
        assert!(path.verify(&e, &empty_root()).is_err());
        // A device absent from the set has no position.
        assert_eq!(set.position(&[0x42; 32]), None);
    }

    #[test]
    fn duplicates_are_refused() {
        let mut same_key = entry(2);
        same_key.device_id = b"other".to_vec();
        assert!(DeviceSet::new(vec![entry(1), entry(2), same_key]).is_err());
        let mut same_id = entry(3);
        same_id.device_id = entry(1).device_id;
        assert!(DeviceSet::new(vec![entry(1), same_id]).is_err());
        let mut bad = entry(1);
        bad.device_id = vec![];
        assert!(DeviceSet::new(vec![bad]).is_err());
    }
}
