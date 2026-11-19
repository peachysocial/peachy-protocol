<!-- SPDX-License-Identifier: CC0-1.0 -->
# Specifications

The specifications of the protocol Peachy's apps speak for private
conversations, and of the MLS core that implements it.

## [Device identity](identity.md)

Revision 1, 2026-11-19.

This document describes how a Peachy device is identified: signing in, the
device key, the server-signed `pdc1` credential an MLS leaf carries, the
account identity key, letting a new device in, and the security code two
people compare.

## [Delivery](delivery.md)

Revision 1, 2026-11-19.

This document describes how a client moves sealed bytes through the Peachy
server: conversation handles, the wrapped envelope, per-device mailboxes,
commits and Welcomes, the KeyPackage directory, sealed media, and which
builds the server serves.

## [Sealed messages](sealed-messages.md)

Revision 1, 2026-11-19.

This document describes what a Peachy device puts inside an MLS group: the
envelope, message frames, control frames, typing, the group's own state, and
seating and removing devices.

## [Message formats](formats.md)

Revision 1, 2026-11-19.

This document describes the golden tables that pin message frames,
reactions, receipts, edits, deletes, the group's state and the security code
on real bytes.

## [Account store](account-store.md)

Revision 1, 2026-11-19.

This document describes how a person's settings and lists are sealed under
an account key the server never holds (Peachy's own store-review accounts
excepted), and kept the same on all their devices.

## [Profiles](profiles.md)

Revision 1, 2026-11-19.

This document describes how a person's name and photos are sealed under a
profile key and handed to the people they talk to, and what the server keeps
in plaintext.

## [Calls](calls.md)

Revision 1, 2026-11-19.

This document describes how a call's media keys come from the conversation's
MLS epoch, how call signals are encoded and sealed, and the ringing every
client runs.

## [MLS core](mls-core.md)

Revision 1, 2026-11-19.

This document describes the MLS profile every Peachy client speaks
(ciphersuite 0x004F, extensions, group policy, key packages) and the `mls/`
workspace that implements it.

## [Metadata](metadata.md)

Revision 1, 2026-11-19.

This document describes what the Peachy server holds about private
conversations, for how long, and what it never holds.

## [Changelog](CHANGELOG.md)

What changed on the wire and in the core's API, and what a client of your own
must do about it.

## IPR

This document is dedicated to the public domain under CC0 1.0.
