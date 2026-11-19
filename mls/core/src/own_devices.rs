// SPDX-License-Identifier: MIT
//! Seating a sibling: the check a device runs before it adds another device
//! of its OWN account to a group (docs/identity.md §What the adder checks).
//!
//! ## Why holding the account key is not enough
//!
//! Every device of an account holds the account key, and the account key's
//! certificate on a device key is what every peer's core checks at an add
//! ([`crate::account_identity`]). So the certificate says "this device key
//! belongs to whoever holds the account key", and nothing more. A device that
//! was removed keeps the key it was given. With it, it can certify any number
//! of new device keys, and each one would be seated by the person's own
//! devices in every group they hold, with no change any peer can see.
//!
//! What separates a device the person let in from one minted with a retained
//! key is the APPROVAL: the signature a live device of the account makes over
//! the new device's id and key when the person approves it
//! ([`crate::device_link::sign_device_approval`]). The server keeps it and
//! hands it back with the device list. This module decides whether that
//! approval was made by a device THIS device already trusts.
//!
//! ## Which keys this device trusts
//!
//! Only keys it learned on the APPROVAL CHAIN, never from the device list
//! and never from a tree alone ([`Client::own_device_anchors`]):
//!
//! - its own signing key;
//! - the device that let it in, remembered when it took the account key
//!   ([`Client::remember_own_approver`]): the account-key box opened under
//!   that device's key, so the key is the one the person paired with;
//! - a device whose approval verified here under a key already on the chain
//!   ([`Client::check_own_device_approval`] answering
//!   [`OwnDeviceVerdict::Approved`]), so the chain grows one approval at a
//!   time from this device and its approver.
//!
//! Each is recorded as it happens and kept; none is read back out of a tree.
//! A leaf naming THIS device's id under another key is never on the chain:
//! this device is only ever its own key.
//!
//! A leaf of its own account that is merely in a tree (one already there
//! when this device joined by a Welcome, or one a sibling it only saw in a
//! tree seated) is SEEN, not trusted: the notice counts it as a device it
//! has seen, and it vouches for nothing here. A Welcome tells a joiner
//! nothing about who seated each leaf, and a removed device that kept the
//! account key can certify a fresh key, have it seated in a new group, and
//! found that group itself. A device the server invents is on no chain.
//!
//! ## Forgetting a removed device
//!
//! When the account removes one of its devices, every remaining device
//! forgets it ([`Client::forget_own_device`]): the client calls it for the id
//! it just revoked and for every revoked row the device list shows, with the
//! key that row lists ([`Client::forget_own_device_with_key`]). From then
//! on that device is neither trusted as an approver nor seated by this
//! device, whatever the server lists later and whoever seats it elsewhere,
//! and its approvals vouch for nobody. That includes the approvals this
//! device already verified: each chain record keeps which device vouched for
//! it, and a device on the chain only by the forgotten device's approvals
//! (directly, or through devices on it only by those) comes off the chain
//! here. Any unlocked device can approve a new one, so a device a thief linked
//! from a stolen laptop goes when the laptop is removed; so does an honest
//! device the removed one linked, until a device still on the chain approves
//! it again. A removed device's id never comes
//! back, so the record is kept for good. Forgetting is what stops the device
//! that let this one in (most often the phone, the device most likely to be
//! lost) from staying trusted after its removal.
//!
//! It is by key as well as by id. The account's certificate covers a device
//! key, never the id the server files it under, so a server could list a
//! removed device's key again under a fresh id. Every key this device has
//! seen a forgotten id hold (the key it first saw it with, its leaves in any
//! group, a record that one was unvouched, the approver key, the device
//! list's key) is forgotten with it, and so is any key a leaf under a
//! forgotten id holds later. A forgotten key counts for nothing under any id,
//! at every check here and at the Welcome gate: it is never an anchor, never
//! `Known` or `Approved`, its seat is outside the gate whoever commits it,
//! and its Welcome never seats this device in any group, known or new, with
//! the Welcome roster switch on or off. A removed device
//! comes back only as a new key, under an approval a trusted device makes.
//!
//! ## A seat this device made on no verdict
//!
//! This device's own add is evidence of a sibling only when
//! [`Client::check_own_device_approval`] answered a verdict that seats for
//! the same id and key, or the device was already trusted here. Any other
//! own add is recorded unvouched, like a contact's seat. A sibling that
//! watched this device's commit cannot tell which verdict was
//! behind it, so a watched seat is never chain evidence (§What it cannot
//! judge).
//!
//! ## A leaf this device did not see vouched for
//!
//! A contact seats a person's devices on their certificates alone: the
//! contact cannot check another account's approvals. A leaf of this account
//! that a contact seated is therefore no evidence that the person let that
//! device in. When this device applies a commit that adds a leaf of its own
//! account, and the committer is not one of its own devices it has seen, it
//! records that leaf as unvouched; an unvouched leaf counts for nothing here,
//! not even as seen, until an approval that verifies under a key on the chain
//! vouches for the same device and key. So one seat a contact gave a retained-key device cannot turn into
//! a seat in every group this device holds. A leaf naming this very device's
//! id under any other key is recorded the same way whoever seats it, a
//! device of this account or not.
//!
//! ## What the new-device notice is told
//!
//! [`Client::own_sibling_leaves`] is the notice's input, and it is keyed on
//! the device AND its key, not the id alone: a device under an id this device
//! has seen, with a key it has not seen that id hold, is a device it has not
//! seen. Such a leaf (and any leaf naming this device's own id under another
//! key) is reported as `<device id>#<device key, hex>`, a name no device list
//! carries, so every client's id-keyed notice fires on it and shows it as a
//! device that is not on the list. The key first seen for each id is kept for
//! good, including the key a commit's removal takes out of a seat, so a
//! replace that swaps a sibling's key under its id is reported even when the
//! new key is the only one left.
//!
//! That first key is taken only from evidence: an approval that verifies, or
//! a leaf this device already trusts ([`OwnDeviceVerdict::Approved`] or
//! [`OwnDeviceVerdict::Known`]), this device's own add of the device, or a
//! leaf this device did not see seated from outside the gate. Never from a
//! leaf it did see seated that way, so a device a contact seated under a
//! sibling's id cannot take that id's bare name: until an approval vouches
//! for it, it is reported in the long form beside the bare id. A key taken
//! from an approval or an own add replaces one taken from a tree, never the
//! reverse.
//!
//! ## What it cannot judge
//!
//! A device with no approval at all (the account's first device, one let in
//! by "I don't have my other devices", or one that took the key back with the
//! PIN while no other device was left) is on the chain only of a device it
//! let in. Elsewhere the answer is [`OwnDeviceVerdict::Unanchored`], which is
//! "not by me, not now": a device that holds it on its chain seats it
//! instead, and a history ask from it here is answered with nothing. So is
//! an approved device whose approver is on no chain here yet.
//!
//! A seat this device watches puts nobody on the chain, even one a device on
//! the chain commits.
//!
//! ## A call link's core
//!
//! A call placed through a call link runs in a group of its own, held by a
//! second core on the device: in memory, with the device's own credential
//! and key, so the chat's store never sees the call's group
//! (docs/calls.md §Call links on participant keys). That core
//! starts with none of the records above: no approver, no chain, nothing
//! forgotten. So the main core hands it what it holds
//! ([`Client::own_device_trust`], a JSON form that never leaves the device),
//! and the link's core adopts it ([`Client::adopt_own_device_trust`]): the
//! approval chain as the main core computes it, every device id it forgot
//! and every key it forgot with them. From then on every check above runs in
//! the link's core on those records too: its adds refuse a forgotten device
//! of the account, a Welcome signed by one seats this device in no call,
//! a commit seating one records it as seated from outside the gate, and an
//! approval by one vouches for nobody. The client adopts again before it
//! joins from a Welcome and as the call goes on, so a removal heard during
//! the call reaches the call's core. Forgotten ids and keys accumulate
//! across adoptions; the chain is replaced by the latest.
//!
//! [`Client::own_device_standing`] is what the call's screen asks of a leaf
//! of the person's own account there: a device on the chain counts as one of
//! theirs, and any other (on no chain here, forgotten, or wearing this
//! device's id or key) does not, so the call never names it as the person.

use crate::device_link::verify_device_approval;
use crate::error::Result;
use crate::group::Client;
use crate::identity::PeachyIdentity;

/// Own devices a commit seats, each as (device id, signing key).
type OwnSeats = Vec<(String, Vec<u8>)>;

/// The version of [`Client::own_device_trust`]'s JSON form this build writes
/// and reads. Both cores are the same build on the same device, so a version
/// it does not read is a caller bug, refused.
pub const OWN_DEVICE_TRUST_VERSION: u64 = 1;

/// At most this many entries in each list of an adopted trust: far beyond
/// any account's devices, so a malformed form cannot grow a core without
/// bound.
const MAX_ADOPTED_ENTRIES: usize = 4096;

/// What a core took from the device's main core
/// ([`Client::adopt_own_device_trust`], §A call link's core). In memory.
#[derive(Debug, Clone, Default)]
pub(crate) struct AdoptedOwnTrust {
    /// The main core's approval chain, less this device.
    anchors: Vec<(String, Vec<u8>)>,
    /// Every device id the main core forgot, and every key it forgot.
    forgotten_ids: Vec<String>,
    forgotten_keys: Vec<Vec<u8>>,
}

/// What [`Client::own_device_standing`] makes of one device. Only
/// [`Self::ThisDevice`] and [`Self::OnChain`] count as the person's own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum OwnDeviceStanding {
    /// Another person's device.
    NotOwn = 0,
    /// This very device: its id under its own key.
    ThisDevice = 1,
    /// A device of this account on this device's approval chain (its own, or
    /// the one it adopted from the main core).
    OnChain = 2,
    /// A device of this account on no chain here, one this device saw seated
    /// from outside the gate, or one wearing this device's id or key. Not one
    /// of the person's devices as far as this device can tell.
    OffChain = 3,
    /// A device this account forgot as removed, by its id or any key it was
    /// seen holding.
    Forgotten = 4,
}

impl OwnDeviceStanding {
    /// Every standing, in code order.
    pub const ALL: [OwnDeviceStanding; 5] = [
        OwnDeviceStanding::NotOwn,
        OwnDeviceStanding::ThisDevice,
        OwnDeviceStanding::OnChain,
        OwnDeviceStanding::OffChain,
        OwnDeviceStanding::Forgotten,
    ];

    /// The number every binding carries.
    pub fn code(self) -> u32 {
        self as u32
    }

    /// A stable name, for logs.
    pub fn name(self) -> &'static str {
        match self {
            OwnDeviceStanding::NotOwn => "not_own",
            OwnDeviceStanding::ThisDevice => "this_device",
            OwnDeviceStanding::OnChain => "on_chain",
            OwnDeviceStanding::OffChain => "off_chain",
            OwnDeviceStanding::Forgotten => "forgotten",
        }
    }

    /// Whether the device counts as one of the person's own.
    pub fn counts_as_own(self) -> bool {
        matches!(
            self,
            OwnDeviceStanding::ThisDevice | OwnDeviceStanding::OnChain
        )
    }
}

/// What [`Client::check_own_device_approval`] makes of one key package from
/// this account's own device list. Only [`Self::Known`] and
/// [`Self::Approved`] may be seated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum OwnDeviceVerdict {
    /// The same device, under the same key, is already a leaf of this
    /// account in a group this device holds (and was not seen seated by a
    /// committer this device does not trust), or is the device that let this
    /// one in. Never a device this device forgot. Seat it.
    Known = 0,
    /// Its approval verifies under the key of a device this device already
    /// trusts. Seat it.
    Approved = 1,
    /// No approval, or one by a device this device cannot vouch for. Do not
    /// seat it from here; a device that knows the approver will, and this
    /// device asks again once its own view grows.
    Unanchored = 2,
    /// An approval that names a device this device trusts and does not verify
    /// over this package's device id and key. Refuse it.
    BadApproval = 3,
    /// The package is another person's device, or this very device.
    NotOwnDevice = 4,
    /// The package is not one this build accepts, or its credential does not
    /// verify ([`Client::key_package_identity`]).
    CredentialRejected = 5,
}

impl OwnDeviceVerdict {
    /// Every verdict, in code order.
    pub const ALL: [OwnDeviceVerdict; 6] = [
        OwnDeviceVerdict::Known,
        OwnDeviceVerdict::Approved,
        OwnDeviceVerdict::Unanchored,
        OwnDeviceVerdict::BadApproval,
        OwnDeviceVerdict::NotOwnDevice,
        OwnDeviceVerdict::CredentialRejected,
    ];

    /// The number every binding carries.
    pub fn code(self) -> u32 {
        self as u32
    }

    /// A stable name, for logs.
    pub fn name(self) -> &'static str {
        match self {
            OwnDeviceVerdict::Known => "known",
            OwnDeviceVerdict::Approved => "approved",
            OwnDeviceVerdict::Unanchored => "unanchored",
            OwnDeviceVerdict::BadApproval => "bad_approval",
            OwnDeviceVerdict::NotOwnDevice => "not_own_device",
            OwnDeviceVerdict::CredentialRejected => "credential_rejected",
        }
    }

    /// Whether this verdict lets the device be seated.
    pub fn seats(self) -> bool {
        matches!(self, OwnDeviceVerdict::Known | OwnDeviceVerdict::Approved)
    }
}

impl Client {
    /// Remember the device that let this one in: `device_id` and its raw
    /// 32-byte signing key, as this device learned them while taking the
    /// account key (the box opened under that key). Call it once, right after
    /// the account key is accepted from an approval. Idempotent. One step
    /// against the store, under its write lock, like every write door.
    pub fn remember_own_approver(&mut self, device_id: &str, signing_key: &[u8]) -> Result<()> {
        crate::credential::require_valid_id(device_id, "a device_id")?;
        if signing_key.len() != 32 {
            return Err(crate::error::Error::invalid(format!(
                "a signing_key must be exactly 32 bytes, got {}",
                signing_key.len()
            )));
        }
        self.synced(|client| {
            client
                .peachy_storage()
                .set_own_approver(device_id, signing_key)?;
            Ok(())
        })
    }

    /// Forget `device_id`, a device of this account that the account removed
    /// (`RevokeDevice`, or a device list row that is revoked). It stops being
    /// the remembered approver if it was one, its leaves stop counting as
    /// known, its approvals vouch for nobody, and
    /// [`Self::check_own_device_approval`] never seats it again. Idempotent;
    /// answers whether the device was not forgotten already. Refuses this
    /// device's own id.
    ///
    /// The list it comes from is the server's, believed in one direction
    /// only: a server that names a live device as removed can make this
    /// device stop seating it, which it could already do by dropping its mail.
    pub fn forget_own_device(&mut self, device_id: &str) -> Result<bool> {
        self.forget_own_device_with_key(device_id, &[])
    }

    /// [`Self::forget_own_device`], with the raw 32-byte `signing_key` the
    /// device list shows for that device (empty when the caller has none).
    ///
    /// Forgetting is by id AND by key (§Forgetting a removed device): every
    /// key this device has seen the id hold (the key it first saw, any leaf
    /// under the id in any group it holds, a record that a leaf under it was
    /// unvouched, the approver key it remembered) and `signing_key` are
    /// recorded as forgotten, and none of them counts again under any id.
    /// This device's own key is never recorded, whoever lists it. Answers
    /// whether the device was not forgotten already.
    ///
    /// What the forgotten device vouched for goes with it: a device on the
    /// chain only by its approvals (or by approvals of devices on the chain
    /// only by its approvals) is no longer an anchor
    /// ([`Self::own_device_anchors`]). It stays seated where it is; this
    /// device asks again, and it counts once an approval by a device still on
    /// the chain verifies.
    ///
    /// One step against the store, under its write lock: a write that fails
    /// rolls the whole forget back, for the caller to repeat.
    pub fn forget_own_device_with_key(
        &mut self,
        device_id: &str,
        signing_key: &[u8],
    ) -> Result<bool> {
        self.synced(|client| client.forget_own_device_now(device_id, signing_key))
    }

    fn forget_own_device_now(&self, device_id: &str, signing_key: &[u8]) -> Result<bool> {
        crate::credential::require_valid_id(device_id, "a device_id")?;
        let me = self.identity();
        if device_id == me.device_id {
            return Err(crate::error::Error::invalid(
                "a device does not forget itself",
            ));
        }
        if !signing_key.is_empty() && signing_key.len() != 32 {
            return Err(crate::error::Error::invalid(format!(
                "a signing_key must be empty or exactly 32 bytes, got {}",
                signing_key.len()
            )));
        }
        let store = self.peachy_storage();
        let already = store.own_device_forgotten(device_id)?;
        let approvers = store.own_approvers()?;
        let approver = approvers.iter().any(|(id, _)| id == device_id);
        let mut keys: Vec<Vec<u8>> = Vec::new();
        if !signing_key.is_empty() {
            keys.push(signing_key.to_vec());
        }
        keys.extend(
            approvers
                .into_iter()
                .filter(|(id, _)| id == device_id)
                .map(|(_, key)| key),
        );
        keys.extend(store.own_sibling_key(device_id)?);
        keys.extend(
            store
                .own_unvouched()?
                .into_iter()
                .chain(store.own_vouched()?)
                .filter(|(id, _)| id == device_id)
                .map(|(_, key)| key),
        );
        for group_id in self.group_ids() {
            for entry in self.roster(&group_id)? {
                if let Ok(identity) = entry.identity {
                    if identity.actor_id == me.actor_id && identity.device_id == device_id {
                        keys.push(identity.device_key.to_vec());
                    }
                }
            }
        }
        let mut wrote_key = false;
        for key in keys {
            if key.as_slice() == me.device_key.as_slice() || key.len() != 32 {
                continue;
            }
            wrote_key |= store.note_own_key_forgotten(&key, device_id)?;
        }
        if already && !approver && !wrote_key {
            return Ok(false);
        }
        store.forget_own_approver(device_id)?;
        store.note_own_device_forgotten(device_id)?;
        Ok(true)
    }

    /// Every device key a forgotten device of this account counts for
    /// nothing under: the keys recorded when it was forgotten, and any key a
    /// leaf under a forgotten id holds now in a group this device holds.
    /// Never this device's own key.
    pub(crate) fn forgotten_own_keys(&self) -> Result<Vec<Vec<u8>>> {
        let me = self.identity();
        let store = self.peachy_storage();
        let mut keys = store.forgotten_own_keys()?;
        for key in &self.adopted_own_trust.forgotten_keys {
            if !keys.contains(key) {
                keys.push(key.clone());
            }
        }
        let forgotten = self.forgotten_own_device_ids()?;
        if !forgotten.is_empty() {
            for group_id in self.group_ids() {
                for entry in self.roster(&group_id)? {
                    let Ok(identity) = entry.identity else {
                        continue;
                    };
                    if identity.actor_id == me.actor_id && forgotten.contains(&identity.device_id) {
                        let key = identity.device_key.to_vec();
                        if !keys.contains(&key) {
                            keys.push(key);
                        }
                    }
                }
            }
        }
        keys.retain(|key| key.as_slice() != me.device_key.as_slice());
        Ok(keys)
    }

    /// Every device id this account forgot: the ones this core recorded, and
    /// the ones it adopted from the main core (§A call link's core).
    pub(crate) fn forgotten_own_device_ids(&self) -> Result<Vec<String>> {
        let mut ids = self.peachy_storage().forgotten_own_devices()?;
        for id in &self.adopted_own_trust.forgotten_ids {
            if !ids.contains(id) {
                ids.push(id.clone());
            }
        }
        Ok(ids)
    }

    /// Whether this account forgot `device_id`, here or in the trust this
    /// core adopted.
    pub(crate) fn own_device_id_forgotten(&self, device_id: &str) -> Result<bool> {
        Ok(self
            .adopted_own_trust
            .forgotten_ids
            .iter()
            .any(|id| id == device_id)
            || self.peachy_storage().own_device_forgotten(device_id)?)
    }

    /// Whether `(device_id, device_key)` is a device this account forgot,
    /// by its id or by its key. Fails closed: a store that cannot answer
    /// answers yes.
    pub(crate) fn is_forgotten_own_device(&self, device_id: &str, device_key: &[u8]) -> bool {
        let by_id = self.own_device_id_forgotten(device_id).unwrap_or(true);
        by_id
            || self
                .forgotten_own_keys()
                .map(|keys| keys.iter().any(|key| key.as_slice() == device_key))
                .unwrap_or(true)
    }

    /// The `(device_id, signing_key)` pairs this device holds on the
    /// approval chain, the only devices of its own account it vouches for
    /// (§Which keys this device trusts): itself, the device that let it in,
    /// and every device whose approval it verified under a device already on
    /// the chain, for as long as a device that approved it is on the chain
    /// itself. Never a leaf it learned from a tree, or saw seated. Less every
    /// device this device forgot ([`Self::forget_own_device`]), by id or by
    /// any key it was seen holding, and every leaf it saw seated by a
    /// committer it did not trust.
    ///
    /// Forgetting a device therefore takes off the chain, here, every device
    /// it vouched for and no device still on the chain did, and in turn what
    /// those vouched for alone. A record written before approvers were kept
    /// names none, and stays.
    pub fn own_device_anchors(&self) -> Result<Vec<(String, Vec<u8>)>> {
        let me = self.identity();
        let store = self.peachy_storage();
        let forgotten = self.forgotten_own_device_ids()?;
        let forgotten_keys = self.forgotten_own_keys()?;
        let unvouched = store.own_unvouched()?;
        let mut anchors = vec![(me.device_id.clone(), me.device_key.to_vec())];
        // The device that let this one in, and the main core's chain when
        // this core adopted it (§A call link's core).
        let adopted = self.adopted_own_trust.anchors.iter().cloned();
        for approver in store.own_approvers()?.into_iter().chain(adopted) {
            if !forgotten.contains(&approver.0)
                && !forgotten_keys.contains(&approver.1)
                && approver.0 != me.device_id
                && approver.1.as_slice() != me.device_key.as_slice()
                && !anchors.contains(&approver)
            {
                anchors.push(approver);
            }
        }
        let mut vouched: Vec<_> = store
            .own_vouched_by()?
            .into_iter()
            .filter(|(pair, _)| {
                !(pair.0 == me.device_id
                    || pair.1.as_slice() == me.device_key.as_slice()
                    || forgotten.contains(&pair.0)
                    || forgotten_keys.contains(&pair.1)
                    || unvouched.contains(pair))
            })
            .collect();
        // Grow the chain from this device and its approver, one approval at
        // a time, until no record left names an approver on it.
        loop {
            let (joining, waiting): (Vec<_>, Vec<_>) =
                vouched
                    .into_iter()
                    .partition(|(_, approvers)| match approvers {
                        None => true,
                        Some(keys) => keys
                            .iter()
                            .any(|key| anchors.iter().any(|(_, anchor)| anchor == key)),
                    });
            vouched = waiting;
            if joining.is_empty() {
                break;
            }
            for (pair, _) in joining {
                if !anchors.contains(&pair) {
                    anchors.push(pair);
                }
            }
        }
        Ok(anchors)
    }

    /// The pairs this device has SEEN as its own account's devices: the
    /// approval chain ([`Self::own_device_anchors`]) and every leaf of its
    /// own account in every group it is an active member of, less the same
    /// forgotten and unvouched pairs, and less any leaf naming this device's
    /// id. A pair seen only in a tree vouches for nothing; it decides only
    /// whether its own adds are recorded unvouched, so the new-device notice
    /// names an honest sibling's next device by its bare id.
    fn own_devices_seen(&self) -> Result<Vec<(String, Vec<u8>)>> {
        let me = self.identity();
        let store = self.peachy_storage();
        let forgotten = self.forgotten_own_device_ids()?;
        let forgotten_keys = self.forgotten_own_keys()?;
        let unvouched = store.own_unvouched()?;
        let mut seen = self.own_device_anchors()?;
        for group_id in self.group_ids() {
            if !self.is_active(&group_id).unwrap_or(false) {
                continue;
            }
            for entry in self.roster(&group_id)? {
                let Ok(identity) = entry.identity else {
                    continue;
                };
                // This device's own id is this device's own key, already
                // first in the list: a leaf naming it under any other key is
                // never trusted, however it got its seat.
                if identity.actor_id != me.actor_id
                    || identity.device_id == me.device_id
                    || forgotten.contains(&identity.device_id)
                {
                    continue;
                }
                let pair = (identity.device_id, identity.device_key.to_vec());
                if !seen.contains(&pair)
                    && !unvouched.contains(&pair)
                    && !forgotten_keys.contains(&pair.1)
                {
                    seen.push(pair);
                }
            }
        }
        Ok(seen)
    }

    /// The leaves of this account, other than this device, that a commit
    /// about to be applied adds while its `committer` is not a device this
    /// device has seen as its own ([`Self::own_devices_seen`]), and that
    /// this device has not seen either; plus, whoever the committer, every
    /// leaf it adds that names THIS device's id under another key, and every
    /// forgotten device. Read BEFORE the commit is merged, so the commit's
    /// own adds vouch for nothing. A watched seat puts nobody on the
    /// approval chain, whoever commits it (§What it cannot judge). Fails
    /// closed: a set that cannot be read trusts no committer.
    pub(crate) fn seats_outside_the_gate(
        &self,
        committer: &PeachyIdentity,
        added: &[PeachyIdentity],
    ) -> OwnSeats {
        let me = self.identity();
        let mine = (me.device_id.clone(), me.device_key.to_vec());
        let (wearing_my_id, siblings): (Vec<_>, Vec<_>) = added
            .iter()
            .filter(|leaf| leaf.actor_id == me.actor_id)
            .map(|leaf| (leaf.device_id.clone(), leaf.device_key.to_vec()))
            .filter(|pair| *pair != mine)
            .partition(|(id, _)| *id == me.device_id);
        if siblings.is_empty() {
            return wearing_my_id;
        }
        // A device this account forgot, under its id or under any key it was
        // seen holding, is outside the gate whoever seats it.
        let (mut outside, siblings): (Vec<_>, Vec<_>) = siblings
            .into_iter()
            .partition(|(id, key)| self.is_forgotten_own_device(id, key));
        outside.extend(wearing_my_id);
        if siblings.is_empty() {
            return outside;
        }
        let seen = self.own_devices_seen().unwrap_or_default();
        let committer_pair = (committer.device_id.clone(), committer.device_key.to_vec());
        if committer.actor_id == me.actor_id && seen.contains(&committer_pair) {
            return outside;
        }
        outside.extend(siblings.into_iter().filter(|pair| !seen.contains(pair)));
        outside
    }

    /// Record, for each `(device_id, device_key)` of this account's other
    /// devices, the key as the one that id was first seen holding, unless
    /// one is recorded already (§What the new-device notice is told). A
    /// pair this device saw seated from outside the gate is skipped: it is
    /// no evidence of that id's key. The caller flushes.
    pub(crate) fn note_own_sibling_keys(&self, siblings: &[(String, Vec<u8>)]) -> Result<()> {
        let store = self.peachy_storage();
        let unvouched = store.own_unvouched()?;
        for pair in siblings {
            if unvouched.contains(pair) {
                continue;
            }
            store.note_own_sibling_key(&pair.0, &pair.1)?;
        }
        Ok(())
    }

    /// Record, for each `(device_id, device_key)` of this account's other
    /// devices, the key as the one that id holds on evidence (an approval
    /// this device checked, or this device's own add), over any key taken
    /// from a tree. The caller flushes.
    pub(crate) fn note_own_sibling_keys_on_evidence(
        &self,
        siblings: &[(String, Vec<u8>)],
    ) -> Result<()> {
        let store = self.peachy_storage();
        for (device_id, device_key) in siblings {
            store.note_own_sibling_key_evidence(device_id, device_key)?;
        }
        Ok(())
    }

    /// Split this device's OWN adds of its account's other devices, read
    /// BEFORE the commit is merged, into the ones its add is evidence for
    /// (a device it already trusts, or one [`Self::check_own_device_approval`]
    /// answered with a verdict that seats) and the rest, which are recorded
    /// unvouched (§A seat this device made on no verdict). A forgotten device
    /// is never evidence. Fails closed: a store that cannot answer vouches for none.
    pub(crate) fn split_own_adds(&self, seated: OwnSeats) -> (OwnSeats, OwnSeats) {
        if seated.is_empty() {
            return (Vec::new(), Vec::new());
        }
        let anchors = self.own_device_anchors().unwrap_or_default();
        let store = self.peachy_storage();
        seated.into_iter().partition(|(id, key)| {
            !self.is_forgotten_own_device(id, key)
                && (anchors.iter().any(|(a, k)| a == id && k == key)
                    || store.own_seat_vouched(id, key).unwrap_or(false))
        })
    }

    /// Record what [`Self::seats_outside_the_gate`] found, once the commit
    /// is merged. The caller flushes.
    pub(crate) fn note_seats_outside_the_gate(&self, seats: &[(String, Vec<u8>)]) -> Result<()> {
        for (device_id, device_key) in seats {
            log::info!(
                "peachy-mls: a device of this account was seated by a committer this device \
                 does not trust; it counts for nothing here until an approval vouches for it"
            );
            self.peachy_storage()
                .note_own_unvouched(device_id, device_key)?;
        }
        Ok(())
    }

    /// This account's OTHER devices that are leaves of a group this device
    /// is an active member of, each once. This is what a device has SEEN of
    /// its own account, from commits it verified rather than from the device
    /// list: the "new device linked" notice is keyed on it, so a server that
    /// leaves a device off the list cannot also keep it out of the notice
    /// once it has a seat.
    ///
    /// Each entry is a device id, for a leaf under the key this device first
    /// saw that id hold; or `<device id>#<device key as 64 hex characters>`
    /// for one under any other key, and for any leaf naming this device's
    /// own id under a key that is not its own (§What the new-device notice is
    /// told). When no key is recorded for an id yet (an approval or this
    /// device's own add records one on evidence), it is recorded here when
    /// the id shows exactly one key this device did not see seated from
    /// outside the gate; until then the id is reported with every one of its
    /// keys in the long form beside it, a sole key seated from outside the
    /// gate included. One step against the store, under its write lock, since
    /// it may record a key.
    pub fn own_sibling_leaves(&mut self) -> Result<Vec<String>> {
        self.synced(|client| client.own_sibling_leaves_now())
    }

    fn own_sibling_leaves_now(&self) -> Result<Vec<String>> {
        let me = self.identity();
        let store = self.peachy_storage();
        let unvouched = store.own_unvouched()?;
        let mut pairs: Vec<(String, Vec<u8>)> = Vec::new();
        for group_id in self.group_ids() {
            if !self.is_active(&group_id).unwrap_or(false) {
                continue;
            }
            for entry in self.roster(&group_id)? {
                let Ok(identity) = entry.identity else {
                    continue;
                };
                if identity.actor_id != me.actor_id {
                    continue;
                }
                let pair = (identity.device_id, identity.device_key.to_vec());
                if (pair.0 == me.device_id && pair.1 == me.device_key) || pairs.contains(&pair) {
                    continue;
                }
                pairs.push(pair);
            }
        }
        let long_form = |id: &str, key: &[u8]| {
            let hex: String = key.iter().map(|b| format!("{b:02x}")).collect();
            format!("{id}#{hex}")
        };
        let mut ids: Vec<&String> = Vec::new();
        for (id, _) in &pairs {
            if !ids.contains(&id) {
                ids.push(id);
            }
        }
        let mut out: Vec<String> = Vec::new();
        for id in ids {
            let keys: Vec<&Vec<u8>> = pairs
                .iter()
                .filter(|(other, _)| other == id)
                .map(|(_, key)| key)
                .collect();
            if *id == me.device_id {
                out.extend(keys.iter().map(|key| long_form(id, key)));
                continue;
            }
            let mut first = store.own_sibling_key(id)?;
            if first.is_none() {
                let vouched: Vec<&Vec<u8>> = keys
                    .iter()
                    .copied()
                    .filter(|key| !unvouched.contains(&(id.clone(), key.to_vec())))
                    .collect();
                // Only a key this device did not see seated from outside the
                // gate is evidence of the id's key. A sole unvouched key is
                // reported in the long form beside the bare id, until an
                // approval that verifies records the key on evidence.
                let pick = match vouched.as_slice() {
                    [only] => Some(only.to_vec()),
                    _ => None,
                };
                if let Some(key) = pick {
                    store.note_own_sibling_key(id, &key)?;
                    first = Some(key);
                }
            }
            match &first {
                Some(first) => {
                    if keys.contains(&first) {
                        out.push(id.clone());
                    }
                    out.extend(
                        keys.iter()
                            .filter(|key| **key != first)
                            .map(|key| long_form(id, key)),
                    );
                }
                None => {
                    out.push(id.clone());
                    out.extend(keys.iter().map(|key| long_form(id, key)));
                }
            }
        }
        Ok(out)
    }

    /// May this device seat the device in `key_package`, one of its own
    /// account's, in a group? (docs/identity.md §What the adder checks.)
    ///
    /// `approver_device_id` and `approval_signature` are the device list's
    /// `approved_by_device_id` and `approval_signature` for that device, or
    /// empty. They are believed only as far as the signature verifies under a
    /// key from [`Self::own_device_anchors`]; the approver's KEY is never
    /// taken from the server. The new device's id and key are read out of the
    /// package itself ([`Self::key_package_identity`]), so the approval
    /// checked is for the leaf that would land.
    ///
    /// Never fails: a store that cannot be read answers
    /// [`OwnDeviceVerdict::Unanchored`], which seats nobody.
    ///
    /// A verdict that seats records its evidence (the device on the chain,
    /// its key, the seat vouched for), and is answered only once that record
    /// is durable: the check is one step against the store, under its write
    /// lock, and a write or a commit that fails rolls it back and answers
    /// [`OwnDeviceVerdict::Unanchored`].
    pub fn check_own_device_approval(
        &mut self,
        key_package: &[u8],
        approver_device_id: &str,
        approval_signature: &[u8],
    ) -> OwnDeviceVerdict {
        self.synced(|client| {
            client.judge_own_device_approval(key_package, approver_device_id, approval_signature)
        })
        .unwrap_or(OwnDeviceVerdict::Unanchored)
    }

    fn judge_own_device_approval(
        &self,
        key_package: &[u8],
        approver_device_id: &str,
        approval_signature: &[u8],
    ) -> Result<OwnDeviceVerdict> {
        let identity = match self.key_package_identity(key_package) {
            Ok(Ok(identity)) => identity,
            Ok(Err(_)) | Err(_) => return Ok(OwnDeviceVerdict::CredentialRejected),
        };
        let me = self.identity();
        if identity.actor_id != me.actor_id || identity.device_id == me.device_id {
            return Ok(OwnDeviceVerdict::NotOwnDevice);
        }
        // A device the account removed is never seated from here, under any
        // id and on anybody's approval: not under its own id (the device list
        // may still carry the approval a live sibling once made for it), and
        // not under any key it was seen holding, whatever id the server puts
        // that key under now. It comes back only as a new key, approved.
        if self.is_forgotten_own_device(&identity.device_id, &identity.device_key) {
            return Ok(OwnDeviceVerdict::Unanchored);
        }
        let Ok(anchors) = self.own_device_anchors() else {
            return Ok(OwnDeviceVerdict::Unanchored);
        };
        let key = identity.device_key.to_vec();
        let store = self.peachy_storage();
        // A verdict that seats is evidence of the id's key for the notice
        // (§What the new-device notice is told), and makes this device's own
        // add of it evidence too (§A seat this device made on no verdict).
        // Written before the verdict is answered: a write that fails fails
        // the check, and the door answers a verdict that seats nobody.
        let on_evidence = || -> Result<()> {
            store.note_own_sibling_key_evidence(&identity.device_id, &key)?;
            store.note_own_seat_vouched(&identity.device_id, &key)?;
            Ok(())
        };
        if anchors
            .iter()
            .any(|(id, k)| *id == identity.device_id && *k == key)
        {
            on_evidence()?;
            return Ok(OwnDeviceVerdict::Known);
        }
        if !crate::credential::is_valid_id(approver_device_id)
            || approval_signature.is_empty()
            || approver_device_id == identity.device_id
        {
            return Ok(OwnDeviceVerdict::Unanchored);
        }
        let approver_keys: Vec<&Vec<u8>> = anchors
            .iter()
            .filter(|(id, _)| id == approver_device_id)
            .map(|(_, k)| k)
            .collect();
        if approver_keys.is_empty() {
            return Ok(OwnDeviceVerdict::Unanchored);
        }
        let Some(approver) = approver_keys.into_iter().find(|approver| {
            verify_device_approval(approver, &identity.device_id, &key, approval_signature)
        }) else {
            return Ok(OwnDeviceVerdict::BadApproval);
        };
        // Vouched for now: a leaf of this device and key that a committer
        // this device did not trust seated counts again, and the device joins
        // the approval chain, so its own approvals vouch in turn, for as long
        // as the approver it was vouched for by stays on the chain
        // ([`Self::own_device_anchors`]).
        store.clear_own_unvouched(&identity.device_id, &key)?;
        store.note_own_vouched(&identity.device_id, &key, approver)?;
        on_evidence()?;
        Ok(OwnDeviceVerdict::Approved)
    }
}

/// Handing history to a sibling: the same evidence that seats it, read from
/// the device list's row instead of a key package.
impl Client {
    /// Is `(device_id, device_key)`, a row of this account's own device list,
    /// a device this device can vouch for? Judged on the evidence
    /// [`Self::check_own_device_approval`] uses for a key package carrying
    /// that id and key, without consuming one, and stricter only in that this
    /// device's own key under another id is never vouched for. Only
    /// [`OwnDeviceVerdict::Known`] and [`OwnDeviceVerdict::Approved`] say yes.
    ///
    /// A device hands its account's message history only to a sibling this
    /// answers yes for (docs/sealed-messages.md §Handing history to
    /// your own new device). The list's `account_certified` flag is not enough.
    ///
    /// `device_key` is the row's signing key, and `approver_device_id` and
    /// `approval_signature` the row's `approved_by_device_id` and
    /// `approval_signature`, or empty. The approval is believed only as far as
    /// it verifies under a key from [`Self::own_device_anchors`].
    ///
    /// Reads only: unlike the seat check it records no evidence. Never fails:
    /// a store that cannot be read answers [`OwnDeviceVerdict::Unanchored`],
    /// and an id or key that is not well formed answers
    /// [`OwnDeviceVerdict::CredentialRejected`].
    pub fn check_own_device_key(
        &self,
        device_id: &str,
        device_key: &[u8],
        approver_device_id: &str,
        approval_signature: &[u8],
    ) -> OwnDeviceVerdict {
        if !crate::credential::is_valid_id(device_id) || device_key.len() != 32 {
            return OwnDeviceVerdict::CredentialRejected;
        }
        let me = self.identity();
        if device_id == me.device_id {
            return OwnDeviceVerdict::NotOwnDevice;
        }
        // This device's key under any other id is another device wearing it.
        if device_key == me.device_key.as_slice() {
            return OwnDeviceVerdict::Unanchored;
        }
        if self.is_forgotten_own_device(device_id, device_key) {
            return OwnDeviceVerdict::Unanchored;
        }
        let Ok(anchors) = self.own_device_anchors() else {
            return OwnDeviceVerdict::Unanchored;
        };
        if anchors
            .iter()
            .any(|(id, key)| id == device_id && key.as_slice() == device_key)
        {
            return OwnDeviceVerdict::Known;
        }
        if !crate::credential::is_valid_id(approver_device_id)
            || approval_signature.is_empty()
            || approver_device_id == device_id
        {
            return OwnDeviceVerdict::Unanchored;
        }
        let approver_keys: Vec<&Vec<u8>> = anchors
            .iter()
            .filter(|(id, _)| id == approver_device_id)
            .map(|(_, key)| key)
            .collect();
        if approver_keys.is_empty() {
            return OwnDeviceVerdict::Unanchored;
        }
        if approver_keys.iter().any(|approver| {
            verify_device_approval(approver, device_id, device_key, approval_signature)
        }) {
            OwnDeviceVerdict::Approved
        } else {
            OwnDeviceVerdict::BadApproval
        }
    }
}

/// A call link's core: the trust it takes from the main core (§A call link's
/// core), and how the call's screen judges a leaf of its own account.
impl Client {
    /// This core's own-device trust, as the JSON form
    /// [`Self::adopt_own_device_trust`] reads: this device's identity, the
    /// approval chain ([`Self::own_device_anchors`]) less this device, and
    /// every device id and key this account forgot. Keys are 64 lowercase hex
    /// characters. Reads only. The form never leaves the device: it is handed
    /// from the main core to a call link's core on the same device.
    pub fn own_device_trust(&self) -> Result<String> {
        let me = self.identity();
        let anchors: Vec<serde_json::Value> = self
            .own_device_anchors()?
            .into_iter()
            .filter(|(id, key)| *id != me.device_id && key.as_slice() != me.device_key.as_slice())
            .map(|(id, key)| serde_json::json!({ "deviceId": id, "deviceKey": trust_hex(&key) }))
            .collect();
        let forgotten_keys: Vec<String> = self
            .forgotten_own_keys()?
            .iter()
            .map(|key| trust_hex(key))
            .collect();
        let form = serde_json::json!({
            "v": OWN_DEVICE_TRUST_VERSION,
            "actorId": me.actor_id,
            "deviceId": me.device_id,
            "deviceKey": trust_hex(&me.device_key),
            "anchors": anchors,
            "forgottenDevices": self.forgotten_own_device_ids()?,
            "forgottenKeys": forgotten_keys,
        });
        Ok(form.to_string())
    }

    /// Adopt `trust`, the [`Self::own_device_trust`] form of the device's
    /// main core, into this core (§A call link's core). Refused unless it is
    /// this very device's form (same actor id, device id and key) at
    /// [`OWN_DEVICE_TRUST_VERSION`], and nothing is adopted unless the whole
    /// form reads. The chain replaces the one adopted before; forgotten ids
    /// and keys are added to the ones adopted before, never dropped. In
    /// memory only: nothing is written to this core's store.
    pub fn adopt_own_device_trust(&mut self, trust: &str) -> Result<()> {
        use crate::error::Error;
        let form: serde_json::Value = serde_json::from_str(trust)
            .map_err(|e| Error::invalid(format!("own-device trust is not JSON: {e}")))?;
        if form.get("v").and_then(|v| v.as_u64()) != Some(OWN_DEVICE_TRUST_VERSION) {
            return Err(Error::invalid(
                "own-device trust is not at a version this build reads",
            ));
        }
        let me = self.identity();
        let text = |field: &str| -> Result<String> {
            form.get(field)
                .and_then(|v| v.as_str())
                .map(str::to_owned)
                .ok_or_else(|| Error::invalid(format!("own-device trust has no {field}")))
        };
        if text("actorId")? != me.actor_id
            || text("deviceId")? != me.device_id
            || trust_key(&text("deviceKey")?, "deviceKey")? != me.device_key.to_vec()
        {
            return Err(Error::invalid(
                "own-device trust is another device's; a core adopts only its own device's",
            ));
        }
        let list = |field: &str| -> Result<Vec<serde_json::Value>> {
            let items = form
                .get(field)
                .and_then(|v| v.as_array())
                .cloned()
                .ok_or_else(|| Error::invalid(format!("own-device trust has no {field} list")))?;
            if items.len() > MAX_ADOPTED_ENTRIES {
                return Err(Error::invalid(format!(
                    "own-device trust lists more than {MAX_ADOPTED_ENTRIES} {field}"
                )));
            }
            Ok(items)
        };
        let mut anchors: Vec<(String, Vec<u8>)> = Vec::new();
        for item in list("anchors")? {
            let id = item
                .get("deviceId")
                .and_then(|v| v.as_str())
                .ok_or_else(|| Error::invalid("an own-device trust anchor has no deviceId"))?;
            crate::credential::require_valid_id(id, "an anchor's deviceId")?;
            let key = trust_key(
                item.get("deviceKey").and_then(|v| v.as_str()).unwrap_or(""),
                "an anchor's deviceKey",
            )?;
            let pair = (id.to_owned(), key);
            if pair.0 == me.device_id || pair.1.as_slice() == me.device_key.as_slice() {
                continue;
            }
            if !anchors.contains(&pair) {
                anchors.push(pair);
            }
        }
        let mut forgotten_ids: Vec<String> = Vec::new();
        for item in list("forgottenDevices")? {
            let id = item
                .as_str()
                .ok_or_else(|| Error::invalid("a forgotten device is not a device id"))?;
            crate::credential::require_valid_id(id, "a forgotten device id")?;
            if id != me.device_id && !forgotten_ids.iter().any(|known| known == id) {
                forgotten_ids.push(id.to_owned());
            }
        }
        let mut forgotten_keys: Vec<Vec<u8>> = Vec::new();
        for item in list("forgottenKeys")? {
            let key = trust_key(item.as_str().unwrap_or(""), "a forgotten key")?;
            if key.as_slice() != me.device_key.as_slice() && !forgotten_keys.contains(&key) {
                forgotten_keys.push(key);
            }
        }
        let held = &mut self.adopted_own_trust;
        held.anchors = anchors;
        for id in forgotten_ids {
            if !held.forgotten_ids.contains(&id) && held.forgotten_ids.len() < MAX_ADOPTED_ENTRIES {
                held.forgotten_ids.push(id);
            }
        }
        for key in forgotten_keys {
            if !held.forgotten_keys.contains(&key)
                && held.forgotten_keys.len() < MAX_ADOPTED_ENTRIES
            {
                held.forgotten_keys.push(key);
            }
        }
        Ok(())
    }

    /// What this device makes of `(actor_id, device_id, device_key)`, a leaf
    /// in one of its groups ([`OwnDeviceStanding`]). Another person's device
    /// is [`OwnDeviceStanding::NotOwn`]; a device of this account counts as
    /// the person's only on this core's approval chain (its own, or the one
    /// it adopted). A device it forgot, by id or by any key it was seen
    /// holding, is [`OwnDeviceStanding::Forgotten`]; a leaf wearing this
    /// device's id or key that is not this device, and any device on no
    /// chain here, is [`OwnDeviceStanding::OffChain`]. Fails closed: a store
    /// that cannot answer counts nobody as the person's.
    pub fn own_device_standing(
        &self,
        actor_id: &str,
        device_id: &str,
        device_key: &[u8],
    ) -> OwnDeviceStanding {
        let me = self.identity();
        if actor_id != me.actor_id {
            return OwnDeviceStanding::NotOwn;
        }
        if device_id == me.device_id && device_key == me.device_key.as_slice() {
            return OwnDeviceStanding::ThisDevice;
        }
        if self.is_forgotten_own_device(device_id, device_key) {
            return OwnDeviceStanding::Forgotten;
        }
        if device_id == me.device_id || device_key == me.device_key.as_slice() {
            return OwnDeviceStanding::OffChain;
        }
        match self.own_device_anchors() {
            Ok(anchors)
                if anchors
                    .iter()
                    .any(|(id, key)| id == device_id && key.as_slice() == device_key) =>
            {
                OwnDeviceStanding::OnChain
            }
            _ => OwnDeviceStanding::OffChain,
        }
    }
}

/// A key as 64 lowercase hex characters, in the own-device trust form.
pub(crate) fn trust_hex(key: &[u8]) -> String {
    key.iter().map(|b| format!("{b:02x}")).collect()
}

/// A 32-byte key from its 64 hex characters in the own-device trust form.
pub(crate) fn trust_key(hex: &str, field: &str) -> Result<Vec<u8>> {
    let bytes = hex.as_bytes();
    if bytes.len() != 64 {
        return Err(crate::error::Error::invalid(format!(
            "{field} must be 64 hex characters"
        )));
    }
    let digit = |c: u8| -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    };
    bytes
        .chunks(2)
        .map(|pair| match (digit(pair[0]), digit(pair[1])) {
            (Some(hi), Some(lo)) => Ok((hi << 4) | lo),
            _ => Err(crate::error::Error::invalid(format!(
                "{field} must be 64 hex characters"
            ))),
        })
        .collect()
}
