<!-- SPDX-License-Identifier: CC0-1.0 -->
# Metadata

**Status:** describes the protocol as implemented by the `peachy-protocol`
0.2.0 release. **Revision:** 1, 2026-11-19. **Editor:** Peachy Social, Inc.

What the Peachy server holds about private conversations (every DM and
private group, all end-to-end encrypted with MLS), for how long, and what it
never holds. "The server" is its operator and anyone who obtains its data.
Every push about a private conversation is the same payload.

## The floor

| What the server holds | For how long |
|---|---|
| The account's phone number; its handle, name, photo, cover, profile link and About you in plaintext, with the photos' uncropped originals and crops, and a public name if it chose one ([What stays public](profiles.md#what-stays-public)); its sealed profile and the sealed photos it names; and when it was created | While the account exists. A deleted account leaves a tombstone holding its id, a public id, when it was created, a sync revision, and any moderation restriction placed on it |
| Each session's start time, its app family (such as "Chrome (macOS)"), its push token, and the last day it was used | While the session exists |
| The last day the account was used in the foreground | While the account exists |
| Each device's platform, install id, public key and KeyPackage pool size, when it was added, the day it was last used, and whether its build is below its platform's minimum; for a removed device, when, and the account's signed revocation. No device name | While the account exists |
| Every credential issued to each device: the device key and account key it vouches for, the day it was issued, when it expires, and the day it was revoked | While the account exists |
| For each approved device, which device approved it, when, and the approval's signature; and the account-key box sealed to it and the approver's sealed list of signed-out keys sent with it, also after they are fetched | While the account exists; the boxes until the device is removed or the store is wiped |
| A handed-out KeyPackage, with when it was handed out; the day of a device's latest one | About ten minutes; the day, 30 days |
| A hash of each account's access key ([Access keys](delivery.md#access-keys)) | While the account exists |
| The account's identity key, public, and the day it was set ([The account identity key](identity.md#the-account-identity-key)) | While the account exists, until the account starts over ([ClaimSoleDevice](identity.md#claimsoledevice)) |
| Each public identity key the account started over from, and the day | While the account exists |
| If the person set a PIN: the registration lock's salt and a hash of a token derived from the account key, whether the lock is on, the PIN vault's public key, the day's wrong tries and when they began, the day the PIN was set, the last day any of the account's logins made a request ([UnlockRegistration](identity.md#unlockregistration)), each unlock ticket, and how many times a PIN has been set | Until the PIN is turned off or ClaimSoleDevice, while the account exists; a ticket until it is used or the next sign-in replaces it; the count while the account exists |
| For an account that set a PIN and was deleted or started over ([ClaimSoleDevice](identity.md#claimsoledevice)), the ask that the PIN vault drop its backup: the account's id, when the ask was queued, how many times it was tried, and when it is next due | Until the vault confirms it, at most 30 days |
| Each conversation's opaque handle, its epoch, the time of its last commit (to the second), and its send-key verifier at each of its last 4096 epochs ([The verifier log](#the-verifier-log)) | While the handle exists |
| An undelivered envelope: ciphertext, its recipient accounts and devices, the receive time to the second, and one urgent bit | Until every device it is for collects it, or 30 days |
| An encrypted attachment, padded, under an opaque key | 30 days after upload |
| An encrypted group photo under an opaque key, with the hash of its delete token and, until a commit names it, when it was uploaded | Until a member deletes it, or 7 days after upload if no commit names it |
| For each anonymous token spent (a group photo's upload, a call or a call link): a hash of it beside its key's expiry; no account, and not when it was spent | Until its key expires (at most two weeks), then the next sweep (at most hourly, on a key fetch) |
| A group call's id under the conversation's handle and when it was created, and per join a random id, the hash of its secret, its media-server session, the tracks it published and the tracks it pulled from each other join, the epoch it last proved, and when it joined, was last heard from, was last given relays, and left; no account | While the call runs, and up to about an hour after |
| A call link ([Calls](calls.md#call-links-on-participant-keys)): an id derived from its secret, the admin's public key, the approval switch, its sealed name and approvals, hashes of approved devices' passes, and when it was made, expires and was deleted; per call, when it was opened and founded, its asks (sealed, each with the hash of the asker's secret, its outcome, when it was made and last polled, the Welcome that seated it and, on the admin's own ask, its signed join, which shows which joiner is the admin), its commits and signals in order, each with its epoch and time and a commit with the verifier of the epoch it makes, the first epoch's verifier, and the link state's revision and signature; no account | The link 90 days after it was made or last started a call, its row up to 90 days more (90 days once deleted); a call's asks and commits while the call runs, and up to about an hour after; its in-call signals two minutes, and a call's last ones up to about an hour |
| The sealed account store: record ids, padded sizes and the version | While the account exists |
| For each person recently seated, or whose KeyPackages were recently fetched: what is left of each allowance, its bucket ([Welcomes are metered per person](delivery.md#welcomes-are-metered-per-person)) or fetch door, and when it was last spent, to the millisecond; no committer ([The verifier log](#the-verifier-log)) | Until the allowance refills, at most about two hours |
| For each account recently issued anonymous tokens: what is left of each purpose's daily allowance, and when it was last spent | About a day after the last issue |
| Each block a person applies across Peachy: who blocked whom, and when | Until it is undone, or either account is deleted |
| A report a person files about someone, a message request's Report spam included: who reported whom, when, the reason, and, only if the reporter chose to include them, the reported message's words as their device showed them; no conversation or message id | Until it is ruled on, and 90 days after; kept if either account is deleted |
| For an install woken because it sat idle (with an urgent envelope waiting, or for 60 days or more), the person's local day it was last woken | Two days |
| At sign-in, the asking IP address beside the phone number; and, in rate buckets, the address alone, and the number alone (two buckets), each with the time of its last sign-in step | While the code is live, and an hour after a wrong code; the buckets up to about 70 minutes after any sign-in |
| A log of requests and server events, with no address | 14 days |
| Hourly message counts, and daily usage counts the apps send without a session, across all accounts and with no account, device or conversation | 180 days |

What it sees while it serves a request:

- **Who a send is for**: every device a send names, and at each commit every
  device in the tree and each device a Welcome seats.
- **Sizes**: envelopes are padded to at least 512 bytes and then a bucket,
  commits to the tree's shape.
- **Time and address** of every request, and when an account checks its
  conversations.
- **Requests made with a session** name their account: a send or commit
  naming somebody whose access key the sender lacks (a founding with somebody
  new, for one), an identified KeyPackage fetch, an attachment upload, and a
  profile read (`GetUser`, which the apps also make when a DM opens).
- **A 1:1 call's answer** shows whether the callee accepted the caller's
  message request, or blocked them.

## What the server never holds

These hold for every person's conversations, but not for the demo
conversations of Peachy's store-review login, whose other members are devices
the server runs: there it holds what any member holds, and it holds those
accounts' keys and can read their stores
([Security considerations](identity.md#security-considerations)).

- **G1. A conversation's name.** Its name, topic, photo, admins and policy
  are the group's own state, sealed in MLS.
- **G2. What a message is.** Ids, reply targets, and whether an envelope is a
  message, reaction, receipt, edit or delete. The urgent bit says only
  whether a person acted ([The urgent bit](delivery.md#the-urgent-bit)).
- **G4. Settings.** The account store is sealed record by record, type
  included, under an account key the server never holds (the store-review
  accounts excepted, above; [The model](account-store.md#the-model)). That
  covers the names a person gives contacts and devices.
- **G5. Choices.** Mutes, hidden chats, accepted requests and blocks are store
  records applied on the device. A block mints a new access key; the server
  sees the change, and why only when a report goes with it (Block and report
  spam files one). A block a person also applies across Peachy, and a
  report, are held by the server (the floor).
- **G6. History.** An envelope is deleted once collected
  ([Retention](delivery.md#retention)).
- **G7. Who sends.** A send, add or founding by somebody who holds the access
  key of every account it names carries no session
  ([Access keys](delivery.md#access-keys)).
- **G8. Member lists.** A conversation's group id never reaches the server;
  members' devices enforce roles and policy. A commit made with a session
  names the committer's account. While a commit or a Welcome waits in a
  mailbox, the stored rows tie its conversation to the devices it waits for
  ([The verifier log](#the-verifier-log)).
- **G10. Which conversation a package is for.** A KeyPackage fetch names no
  conversation.
- **G11. Attachment keys.** A key travels only inside the sealed message, and
  no record ties a stored attachment to its uploader
  ([Sealed media](delivery.md#sealed-media)).

## Encrypted handshakes

Every commit and proposal is an MLS `PrivateMessage`, a plaintext handshake
is refused, no `GroupInfo` is published, and there are no external joins.
Each envelope is wrapped so that its group id, epoch and framing are
ciphertext ([The wrapped envelope](delivery.md#the-wrapped-envelope)).

## The verifier log

For every handle the server keeps the verifier at each of its last 4096
epochs, so it shows how many commits a handle took. A commit's head and log
rows, its mailbox entries and the Welcome allowance it spends are written in
one database transaction and carry its id, which can be set against wall
time; the head's last-commit time is also the commit's receive time. So
while a commit or a Welcome waits in a mailbox, the server's data ties the
conversation's handle to the devices it waits for and their accounts.
`FetchVerifierAt` is sessionless ([FetchVerifierAt](delivery.md#fetchverifierat)).

## IPR

This document is dedicated to the public domain under CC0 1.0.
