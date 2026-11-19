<!-- SPDX-License-Identifier: CC0-1.0 -->
# Calls

**Status:** describes the protocol as implemented by the `peachy-protocol`
0.2.0 release. **Revision:** 1, 2026-11-19. **Editor:** Peachy Social, Inc.

This document specifies the cryptography of a Peachy call as the MLS core
implements it: how a call's media keys come out of the conversation's MLS
epoch, how call signals are encoded and sealed on their two lanes, the
ring-state reducer every client runs, and the signal that sets up a direct
1:1 call. It also states what the design protects against, and the tests and
formal model that hold it.

How a call's media and signals cross the network (the call rpcs, the media
server and relays, push, and hosting) is out of scope. This document
describes only what the core does and what a client MUST do with it.

A client that implements only messaging can ignore all of it. A sealed
envelope of kind 6 is a call signal; a client without calls SHOULD
acknowledge it and draw nothing.

## Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY" and
"OPTIONAL" in this document are to be interpreted as described in BCP 14
(RFC 2119, RFC 8174) when, and only when, they appear in all capitals, as
shown here.

- `‖` is byte concatenation. `u32be(x)`, `u64be(x)` and `u16be(x)` are
  big-endian unsigned integers of 4, 8 and 2 bytes.
- `MLS-Exporter(G, label, context, L)` is the RFC 9420 exporter of group `G`'s
  current epoch (`export_secret` in `mls/core`; see
  [Exporter secrets](mls-core.md#exporter-secrets)). `e` is the epoch number.
- A **leaf** is a device's leaf index in the conversation's MLS tree. A person
  with several devices has several leaves.
- A **participant** is a device that is in the call now. A **member** is a
  device in the MLS group, in the call or not.
- The names are those of `mls/core/src/call/`. The key-schedule, lane, codec
  and ring constants are in the `constants` case of `mls/fixtures/calls.json`,
  with two live-lane bounds; the per-field codec caps and the core's other
  in-memory bounds are not.

A call can start only in a conversation whose MLS group exists, which is every
private conversation.

## Keys

A call's frame keys come out of the conversation's MLS epoch, so every commit
rekeys the call. There are two schedules, and a call uses exactly one:

- **v1, the epoch alone. A direct 1:1 call uses v1.** Every member of epoch
  `e` derives every sender's key from the epoch's exporter secret, with no
  key-distribution message. In a 1:1 the members are the two people's
  devices, and DTLS-SRTP adds a device-to-device layer under it
  ([Direct 1:1 calls](#direct-11-calls)).
- **v2, the epoch and the participant. A group call uses v2**, a call link's
  included. Each sender key also mixes in a media secret that the sender
  grants to the call's participants only
  ([Participant media keys](#participant-media-keys)). A member not in the
  call derives nothing; a participant that leaves, or that a commit removes,
  derives nothing sent after the rotation its leaving causes; a participant
  that joins derives nothing sent before it joined.

```
call_root(e)    = MLS-Exporter(G, "peachy call v1", context = call_id (16 bytes), 32)
sender_key      = HKDF-Expand-SHA256(PRK = call_root(e), info = "peachy call sender" ‖ u32be(leaf), 16)
key_index       = e mod 256

call_root_v2(e) = MLS-Exporter(G, "peachy call v2", context = call_id, 32)
sender_key_v2   = HKDF-Expand-SHA256(PRK = HKDF-Extract(salt = call_root_v2(e), IKM = media_secret(leaf, g)),
                                     info = "peachy call sender v2" ‖ u32be(leaf), 16)
key_index_v2    = ((e mod 16) << 4) | (g mod 16)
advance(s)      = HKDF-Expand-SHA256(PRK = s, info = "peachy call media advance", 32)

frame_key       = HKDF-SHA256(salt = "peachy call frame v1", IKM = sender_key or sender_key_v2,
                              info = 128 zero bytes, 16)                                 // AES-128-GCM
live_key(e)     = MLS-Exporter(G, "peachy call live v1", context = empty, 32)          // the live lane
```

`g` is the generation of the sender's media secret. HKDF-SHA256 is Extract
then Expand (RFC 5869). `frame_key` is the same in both schedules.

- **`call_id` is 128 random bits** chosen by the device that places the call
  and carried in its sealed `Offer`. It is never the group id. A device MUST
  NOT reuse a call id (R-K5).
- **One key per sender.** Each leaf encrypts its media under its own key. In
  v2 a device computes a leaf's key only if that leaf granted it the media
  secret.
- **`key_index` names the key** in one byte: the epoch in v1, the low four
  bits of the epoch and of the generation in v2. It rides in every media
  frame's trailer, so a receiver picks the right key across a change. The
  receiver's key ring has 256 slots per sender.
- **An epoch change is the rekey.** Any commit advances `e`, and every
  participant re-derives (R-K1, R-K2). In v2, joining and leaving the call
  also change the keys within an epoch.
- **Removal from the group is cryptographic.** A member removed by the commit
  that makes `e+1` cannot derive `call_root(e+1)` or `call_root_v2(e+1)`;
  what it reads before that is bounded by R-K3.
- **Whoever can derive a sender's key can forge that sender's frames** within
  an epoch: in v1 every member, in v2 every participant the sender granted its
  secret to.
- **Post-compromise security during a long call** needs each device to
  update its own leaf (D2), so in a group call **every participant MUST
  commit its own self-update every 10 minutes**, staggered by its rank
  (R-K4; [Keys as built](#keys-as-built)). A direct 1:1 call runs none.
  Outside calls the core's own leaf rotation applies
  ([Periodic leaf rotation](mls-core.md#periodic-leaf-rotation)).
- **Several devices.** A call rings all of a person's devices, and whichever
  answers encrypts under its own leaf's key.

### Keys as built

`mls/core/src/call/keys.rs` and `mls/core/src/call/session.rs`.

| Constant | Value |
|---|---|
| `CALL_EXPORTER_LABEL` | `"peachy call v1"` |
| `CALL_ROOT_BYTES` | 32 |
| `CALL_ID_BYTES` | 16 |
| `CALL_SENDER_INFO` | `"peachy call sender"` |
| `CALL_SENDER_KEY_BYTES` | 16 |
| `CALL_FRAME_RATCHET_SALT` | `"peachy call frame v1"` |
| `CALL_FRAME_KEY_INFO_BYTES` | 128 |
| `CALL_FRAME_KEY_BYTES` | 16 |
| `CALL_KEY_RING_SIZE` | 256 |
| `CALL_KEY_GRACE_MS` | 10 000 |
| `CALL_LIVE_EXPORTER_LABEL` | `"peachy call live v1"` |
| `CALL_LIVE_KEY_BYTES` | 32 |
| `CALL_SELF_UPDATE_INTERVAL_MS` | 600 000 |
| `CALL_EXPORTER_LABEL_V2` | `"peachy call v2"` |
| `CALL_SENDER_INFO_V2` | `"peachy call sender v2"` |
| `CALL_MEDIA_SEED_BYTES` | 32 |
| `CALL_MEDIA_ADVANCE_INFO` | `"peachy call media advance"` |
| `CALL_MEDIA_KEY_INFO` | `"peachy call media key v2"` |
| `CALL_MEDIA_PUBLIC_KEY_BYTES` | 32 |
| `MAX_CALL_MEDIA_GRANTS` | 24 |
| `CALL_MEDIA_MAX_ADVANCE` | 64 |
| `CALL_MEDIA_ROTATE_DELAY_MS` | 5 000 |

- **`sender_key` is what a client hands its frame encryptor**, at slot
  `key_index`, for that sender; the encryptor's key provider derives
  `frame_key` from it. A client MUST configure the WebRTC frame-encryption
  layer so that it derives exactly `frame_key` and nothing else (R-K7):
  - key derivation HKDF-SHA256 (not PBKDF2), salt `"peachy call frame v1"`
    as UTF-8 bytes, info 128 zero bytes, a 128-bit AES-GCM key;
  - a key ring of 256 slots;
  - a ratchet window of 0, so a failed decrypt never ratchets a key forward;
  - one key per sender, never a shared key.
  A client that implements frame encryption itself applies `call_frame_key`
  to each `sender_key`. The fixture's `frameKeyHex` rows pin it.
- **The v1 doors.** `call_keys(group_id, call_id)` returns the current epoch,
  its `key_index`, `call_root` and one `sender_key` per leaf, in leaf order.
  `pending_call_keys` returns the same at the epoch the device's staged commit
  would make; a leaf the staged commit adds is not listed, and its key is
  `call_sender_key(call_root, leaf)`. The C and wasm doors pack the result as
  `u64be(epoch) ‖ key_index (1) ‖ call_root (32) ‖ u32be(count) ‖ (u32be(leaf) ‖ sender_key (16))*`.
  A call root of any length but 32, or a sender key of any length but 16, is
  refused.
- **Rekey.** On every epoch change a client calls `call_keys` again, installs
  the new keys, switches its sending slot, and keeps the previous epoch's
  **frame** keys for `CALL_KEY_GRACE_MS` (10 s); the live key has no grace
  window (R-K9). In a v2 call the door is `call_media_json`'s `keys` (R-K10).
- **The periodic self-update** (R-K4, D2). Every participant of a group call
  commits its own self-update at
  `joined + offset + k × CALL_SELF_UPDATE_INTERVAL_MS` for k = 1, 2, …, where
  `joined` is when it joined and

  ```
  offset = call_self_update_offset_ms(rank, participants)
         = (600 000 / max(participants, 1)) × min(rank, max(participants, 1) − 1)     // integer division first
  ```

  `rank` is the device's 0-based position among the participants by
  ascending leaf index, and `participants` their count
  (`callSelfUpdateOffsetMs` in the bindings). The fixture's
  `selfUpdateOffset` cases pin it (rank 1 of 4 is 150 000 ms, rank 15 of 16
  is 562 500 ms).

### Participant media keys

`mls/core/src/call/media.rs`, with the codec in `signal.rs` and the key
functions in `keys.rs`. These keep a group call's keys to the devices in it.

**What each participant holds.**
- **A media secret**: 32 random bytes per device and call
  (`CALL_MEDIA_SEED_BYTES`), at generation 0 when it joins. The next
  generation is `advance(s)`, which is one-way.
- **Two call key pairs**, fresh per device and join: an X25519 pair, whose
  32-byte public key, the **call key**, goes in the device's signed `Joined`
  (field 5, `media_key`), and an X-Wing pair (ML-KEM-768 with X25519,
  draft-connolly-cfrg-xwing-kem-06), whose 1216-byte public key, the
  **post-quantum call key**, goes beside it (field 7, `media_key_pq`). A
  `Joined` the core seals carries no media-server session and no tracks;
  those travel only inside grants, so a member outside the call never learns
  what to pull. A receiver refuses a signed `Joined` that names a session,
  and ignores any tracks one names: it binds a participant's tracks only
  from that participant's grant.
  Live heartbeats leave out the post-quantum call key, which would not fit
  the live frame.
- **A usable post-quantum call key.** A receiver refuses a signed `Joined`
  whose X-Wing key's ML-KEM-768 part fails the modulus check of FIPS 203
  §7.2 (no grant can be sealed to it). Each grant is sealed on its own: a key
  a grant cannot be sealed to costs that participant its grant, nobody else
  theirs.
- **What it was granted**: per bound participant, that participant's secret
  at the generation it last granted or announced, its session and its tracks.

**A grant** is one participant's secret, sealed with HPKE (RFC 9180) in base
mode to another participant's post-quantum call key, with the suite X-Wing,
HKDF-SHA256, AES-128-GCM (the HPKE of the group's MLS suite, 0x004F):

```
info      = "peachy call media key v2" ‖ call_id ‖ u32be(sender_leaf) ‖ u32be(to_leaf)
aad       = empty
plaintext = MediaGrantPayload { generation, secret (32), session_id, track_names }
```

Grants travel in a `MediaKey` signal (body 14), which the core seals signed
on the MLS lane and never `urgent`. One `MediaKey` carries at most 24 grants
(`MAX_CALL_MEDIA_GRANTS`), and fewer when more would take the grants past
10 KiB (`GRANT_BYTES_PER_SIGNAL`, so the sealed signal fits a call link's
16 KiB log entry); a participant granting more sends several. The `info`
binds a grant to its call and both leaves, so it does not open for another
recipient, another call, or as if from another sender (fixture rows
`open-media-grant-*-refused`).

**Joining.**
1. `call_media_start(call_id, participant_id, session_id, track_names)`
   draws the secret and the key pairs and keeps the session and tracks for
   grants. `participant_id` is the id the server's `JoinCall` answered (an
   rpc of the media server's room, outside this protocol's proto). The core
   refuses to seal a `Joined` naming any other id, and refuses a `start`
   naming an id this call's `remove` took out. The server MUST answer every
   join with a fresh random UUID that names no account and is never handed
   out again, so a rejoin gets a new one.
2. The device sends its `Joined` signed on the MLS lane. The core writes the
   call keys into it and empties its session and tracks, whatever the client
   passed.
3. `call_media_share` grants its secret to every participant it has bound.

Each participant already in the call that opens the newcomer's signed
`Joined` advances its own secret one generation, switches to it at once, and
grants it to the newcomer alone (`rotated = false`). The others see that
`MediaKey`, with its generation and no grant for them, and advance their copy
of the sender's secret to match.

**Leaving.** A participant is gone when its signed `Left` arrives, when its
heartbeat goes stale (the client calls `call_media_remove` with its leaf), or
when this device honors a `Remove` of it (`call_media_remove_participant`
with its participant id; the core then refuses any signed `Joined` under that
id for the rest of the call, and a `Remove` of this device's own id ends its
participation as `end` does). Each remaining participant forgets the leaver's
key, draws a **fresh random** secret at the next generation (an advance would
not do: the leaver could advance too), grants it to those that remain
(`rotated = true`), and switches its sending key to it
`CALL_MEDIA_ROTATE_DELAY_MS` (5 s) later, so the others hold the new key
before the first frame under it.

The core seals every `Left` signed, whichever door the client used. Sealing
one that names the participant id the last `start` named ends this device's
media keys; any other `Left` leaves them alone. A device that rejoins under a
new id sends each old participant's `Left` before its new `Joined`: once that
`Joined` binds its leaf under the new id, a `Left` naming the old one is
refused.

A signed `Left` speaks only for its sender's own participant: the core
refuses one that names this device's own id, one from a leaf bound under
another id, and one from a leaf it never bound while another leaf holds that
id. Opening one answers `unboundLeaf`, the sender's leaf it unbound (null when
none), and a client drops a tile for it only at that leaf (R-K10.7).

**A participant a commit removes is a leaver.** A commit that takes a bound
participant's leaf away (its device removed, or another device put at that
leaf) rekeys only `call_root_v2`, which the removed device's owner's other
devices still derive, and the removed device still holds every secret it was
granted, so it costs the same rotation as a `Left`. The core reads the roster
at every door that touches a call's media state, every open included, before
it changes anything, so it notices the removal even when the `Joined` of the
device now at that leaf is opened first, and binds that device as a newcomer
only after it. The rotation stays owed until `call_media_on_epoch`
(R-K10.3), which rotates once per removal, or a `call_media_remove` for that
leaf, pays it.

**What a lapsed leaf owes.** Opening a peer's signal can oblige this device
to seal for others: grants to a newcomer, a rotation's grants, or its own
`Joined` again for a returning device. When this device's own leaf credential
has lapsed, those seals are refused, and the open must still hand the peer's
signal back, since the credential renewal the client runs next cannot run
inside it. So inside an open, on either lane, and inside `epoch`, which runs
mid-drain after a commit, a seal refused for this device's lapsed leaf is not
an error: what it was is recorded as owed (the latest secret to every bound
participant, or this device's own `Joined`), and the answer's `send` leaves it
out. The next signal opened for the call, `epoch` or `apply` sends what is owed
first: the `Joined`, then the latest secret granted to every bound
participant. A seal still refused there stays owed; a rotation or `share`,
which grant to every bound participant, pays owed grants too, but not an
owed `Joined`; and nothing is owed once this device has left the call. Any other refusal fails the door as before.

**Participant ids.** A participant id binds at one leaf: the core refuses a
signed `Joined` naming an id another leaf holds, or this device's own, so the
first device to claim an id keeps it (a device whose id a held-back `Joined`
let another claim joins again under a new id). A participant keeps its id
while it is bound: a signed `Joined` from the same device naming another id
under the same call key is refused, so a `Remove` honored here reaches the
device whose tile showed it. Once this device's own `Joined` is sealed, the
core unbinds any peer it had bound under that id (which owes a rotation), and
never lists or grants a peer under its own id. A removed person comes back
only through a new join, under a new participant id.

**The core runs no group call on a key every member holds** (R-K11).
The core binds no signed `Joined` that lacks either call key or names a
session, takes no grant sealed to an X25519 key and seals none, and refuses
any op it does not list. The core seals a `Joined` only for a device that holds a
participation; from any other it refuses with `CALL_STATE_LOST`
("call state lost"): a device whose own `Left` ended its keys, one whose
`start` failed, one that asked `end`, one that honored a `Remove` of its own
id, and one whose core was rebuilt mid-call. `start` is the only way to seal
a `Joined` again.

**The core owns the switch.** It records when the pending secret is due and
switches to it at the first door call at or after that time: any signal it
seals or opens for the call (the 10-second heartbeat included), and `share`,
`remove`, `epoch`, `apply` and `keys`. Nothing a client does postpones it:
`apply` before it is a no-op. Only `share` brings it forward: a `share` made
while a rotation is owed (a commit took a bound participant away, or this
device's own `Joined` took the id a peer was bound under) pays it at once with
a fresh secret, which becomes the sending secret immediately and replaces a
pending one. The due time, and the grace a receiver keeps a peer's previous
secret for, run on the device's monotonic clock (`Clock::monotonic_ms`;
`performance.now()` in a browser). Live-lane stamps run on the agreed clock
([The live lane's replay window](#the-live-lanes-replay-window)), and
credential checks on the wall clock.

Every answer but `start`'s and `end`'s, an open's included, reports
`applyAfterMs` (the milliseconds left until the switch, null when nothing is
pending) and `applied` (the core switched since an answer last said so); the
frame encryptor sends under whatever `keys` last returned (R-K10.4, R-K10.5).

A second leaver while a rotation is pending neither draws a second secret nor
moves the due time, since the pending secret was granted to that leaver: the
core chains another rotation behind it, drawn and granted at the first door
after the switch that can hand over envelopes (an open, `remove`, `epoch` or
`apply`; not a seal and not `keys`), and due `CALL_MEDIA_ROTATE_DELAY_MS`
after that. A door that removes participants (`remove`, a `Remove` honored, a
signed `Left` opened) takes them out before it switches and draws, so a
rotation it chains grants them nothing. A `share` made after the switch and
before such a door pays the chained rotation at once, with no delay.

**Binding.** A key counts only from a participant this device has bound:
- A participant is bound by its signed `Joined`, to the leaf that signed it,
  the device behind that leaf, and the call keys it names. A live `Joined`
  binds nothing.
- A grant counts only from a bound leaf, from that same device. A grant that
  arrives before the `Joined` that binds its sender is held, at most 16 per
  call, and counts when that `Joined` binds the same device.
- A `Joined` from another device at the same leaf, or from the same device
  with a new call key (it joined again), starts that participant over:
  nothing granted before counts.
- One device's participations are ordered by a counter. Each participation
  carries a mark (`participation`, in its `Joined` and `MediaKey`): 16 random
  bytes the core draws at each `start`, then a counter the device keeps in
  its store (`call_participation`,
  [Storage layout](mls-core.md#storage-layout)), raised by one for each
  participation and written before the mark goes out. The core remembers,
  per leaf, the last signed `Joined` it bound there: the device, the MLS
  epoch it was sealed in, and its mark. A signed `Joined` from the same
  device naming another participation is refused when it is earlier: sealed
  at an earlier epoch, or at the same epoch with a lower counter. Two with
  the same mark are the same participation, at any epoch; two with the same
  counter and different ids (only a device that lost its store mints that)
  are neither earlier. `started_at_ms` orders nothing. The memory outlasts a
  `Left` and goes when the leaf changes hands. So a server that holds a
  device's `Joined` back past a rejoin cannot re-bind the leaf to the call
  key that died with the earlier participation or to the id it left.
- A signed `Joined` or `MediaKey` with no mark is refused.
- A grant counts only under the participation that sealed it: a `MediaKey`
  that names another participation than the bound one is held if it is later
  (its `Joined` is still to come) and dropped if it is earlier, and a binding
  takes only the held grants of its own participation.

**The keys a receiver installs.** For each bound sender, the receiver derives
`sender_key_v2` for each generation from one before the latest it was told of
to one after it, so frames in flight across an advance decrypt, including an
advance for a newcomer it has not heard of yet. An announced advance counts
only up to 64 generations past the last grant (`CALL_MEDIA_MAX_ADVANCE`).
After a rotation it keeps the sender's previous secret for the rotation delay
plus `CALL_KEY_GRACE_MS`. Each key goes in at its `key_index_v2` in that
sender's ring.

**The doors.** `call_media_json` takes `{"op", "callId", …}` with `op` one of
`start` (with `participantId`, `sessionId` and `trackNames`), `share`,
`remove`, `epoch`, `apply`, `end` and `keys`. It is
`peachy_mls_group_call_media` in C, `callMedia` in wasm, and
`callMedia(groupID:request:)` in Swift.
`open_call_signal` handles `Joined`, `Left` and `MediaKey` itself and returns,
beside the signal, `send` (the envelopes this device owes now: grants to a
newcomer, or a rotation), `media` (what a grant to this device carried), and
`applyAfterMs` and `applied`.
`keys` returns every sender key to install, this device's own sending
`key_index`, and each bound participant with its session and tracks once a
grant has given them.

**Lost state.** The state is in memory only. A core rebuilt mid-call holds no
participation, and answers `keys`, like sealing a `Joined`, with
`CALL_STATE_LOST`. A client MUST NOT answer that by declaring the call
shared or by sending the `Joined` some other way; it joins the keys again
under the same participant id, session and tracks, with no new media-server
session (R-K10.8). Each participant that bound it opens the new `Joined` as
the same device with a new call key, starts that participant over, and sends
its own signed `Joined` again, so the returning device binds it and is
granted its secret. The core keeps media state for
at most 16 calls, and past that forgets a call this device is not in before
one it is.

#### Call links on participant keys

A call link's call runs on participant media keys as a chat's group call
does, each joiner holding a leaf of its own. Its group lives in a core of its
own on each device, in memory, so the door is that core's `call_media_json`,
asked in the link's one serial lane, and the envelopes it owes (from a door
or from opening a signal) go onto the link's log as signals (tag 0x01), in
order, inside that lane, rather than through `SendSealed`.

**The server enforces an admin's removal.** The server opens and closes every
media-server session itself. The admin's device commits the MLS Remove, then
asks the server, through a call rpc out of scope here, to evict the removed
participants with an operation signed by the link's admin key
(`EvictCallParticipantsRequest.admin_op`, op 4): Ed25519 over
`"peachy call link op v1" ‖ 0x00 ‖ room_id ‖ u8(4) ‖ i64be(issued_at_ms) ‖ nonce`,
whose 16-byte nonce is the first 16 bytes of
`SHA-256("peachy call link remove v1" ‖ call_id ‖ (u16be(len) ‖ participant_id)…)`
over the ids in the order sent. The server checks it against the link's admin
key, within 5 minutes of its clock and not replayed, then closes each named
participant's whole session, whatever epoch it proved, and refuses every
later rpc on that participant's secret. A forged, misbound, stale or replayed
operation evicts nobody. The server also takes an eviction without the
operation, which closes only participants behind the link group's epoch.

**The person's own devices.** The link's core starts with none of the main
core's records of the person's own devices
([What the adder checks](identity.md#what-the-adder-checks)), so the main
core hands them over: `own_device_trust` writes its approval chain and every
device id and key the account forgot as a small JSON form that never leaves
the device, and the link's core takes it with `adopt_own_device_trust`, which
refuses any form but this very device's. The client adopts as it makes the
link's core, again just before it joins from a Welcome, and again at most
every five seconds of the call; forgotten ids and keys accumulate across
adoptions. The link's core then runs every own-device check on those records:
its adds refuse a forgotten device, a Welcome signed by one seats this device
in no call, a commit seating one counts as a seat from outside the gate, and
an approval by one vouches for nobody. The clients turn away a forgotten
device's ask at once. A leaf of the person's own account counts as them only
when `own_device_standing` puts it on this device's approval chain: any other
is shown as someone else, its signals carry no sender actor (so no admin
control is taken from it), and its roster note names nobody.

### The media frame

Each media frame is encrypted by the sender's frame encryptor, in the format
the WebRTC frame-encryption layer writes:

```
frame = header ‖ AES-128-GCM(frame_key, iv, aad = header, payload) ‖ iv (12) ‖ 0x0C ‖ key_index
```

- `header` is the codec bytes left clear for the media server to route by:
  1 byte of an Opus frame, 10 of a VP8 key frame, 3 of a VP8 delta frame,
  authenticated as AAD.
- `iv` is `ssrc ‖ rtp_timestamp ‖ (rtp_timestamp − send_count mod 0xFFFF)`
  with a random starting count (R-K6).
- `0x0C` is the IV length, and `key_index` the key's slot.

`mls/core/tests/calls_negative.rs` carries real frames through these keys in
this format.

## Signaling

Every call signal is a small protobuf written and read by hand in
`mls/core/src/call/signal.rs`. It is the plaintext of an MLS application
message or of an exporter-keyed live frame, and either is the inner bytes of
an envelope of kind 6 (`ENVELOPE_KIND_CALL`; see
[The envelope](sealed-messages.md#the-envelope) and
[The wrapped envelope](delivery.md#the-wrapped-envelope)). The server sees an
ordinary sealed envelope.

### The codec

```proto
message CallSignal {
  uint32 version = 1;            // 1; 0 or absent is not a call signal
  bytes  call_id = 2;            // 16 random bytes, chosen by the caller
  bytes  live_signature = 64;    // live lane only, the last field: the leaf's signature
  oneof body {
    Offer      offer       = 3;  // MLS lane, urgent
    Answer     answer      = 4;  // MLS lane, urgent
    Hangup     hangup      = 5;  // MLS lane, urgent
    Joined     joined      = 6;  // a participant's first per epoch on the MLS lane; heartbeats live
    Left       left        = 7;  // MLS lane, signed
    RaiseHand  raise_hand  = 8;  // MLS lane: an in-call control
    React      react       = 9;  // MLS lane: an in-call control
    RemoteMute remote_mute = 10; // MLS lane: an in-call control
    Remove     remove      = 11; // MLS lane: a group admin's act
    MediaState media       = 12; // MLS lane: an in-call control
    Direct     direct      = 13; // MLS lane: a direct 1:1 call's SDP
    MediaKey   media_key   = 14; // MLS lane: media secrets, granted to participants only
  }
}
enum CallMedia    { AUDIO = 0; VIDEO = 1; }
enum HangupReason { NORMAL = 0; DECLINED = 1; BUSY = 2; ACCEPTED_ELSEWHERE = 3;
                    DECLINED_ELSEWHERE = 4; BUSY_ELSEWHERE = 5; NEED_PERMISSION = 6; }
message Offer      { CallMedia media = 1; bool ring = 2; int64 created_at_ms = 3; }
message Answer     { }
message Hangup     { HangupReason reason = 1; }
message Joined     { string participant_id = 1; string session_id = 2;
                     repeated string track_names = 3; uint32 leaf_index = 4;
                     bytes media_key = 5;          // the call key (X25519, 32)
                     uint64 started_at_ms = 6;     // when this participation started
                     bytes media_key_pq = 7;       // the post-quantum call key (X-Wing, 1216);
                                                   // signed Joined only, and only beside media_key
                     bytes participation = 8; }    // the participation's mark: id (16) ‖ u64be(counter)
message Left       { string participant_id = 1; }
message RaiseHand  { bool up = 1; }
message React      { string emoji = 1; }
message RemoteMute { string target = 1; }   // a participant id
message Remove     { string target = 1; }   // a participant id
message MediaState { bool audio_on = 1; bool video_on = 2; bool presenting = 3; }
message Direct     { uint32 to_leaf = 1; string sdp = 2; bool offer = 3; }
message MediaKey   { uint32 generation = 1; bool rotated = 2; repeated MediaGrant grants = 3;
                     uint64 started_at_ms = 4;     // the granting participation's start
                     repeated MediaGrant pq_grants = 5;    // grants sealed with X-Wing
                     bytes participation = 6; }    // the granting participation's mark
message MediaGrant { uint32 to_leaf = 1; bytes enc = 2; bytes ciphertext = 3; }
                     // enc: 32 bytes in grants (X25519), 1120 in pq_grants (X-Wing)

// A grant's plaintext, sealed to one participant (never a CallSignal body):
message MediaGrantPayload { uint32 generation = 1; bytes secret = 2;   // 32 bytes
                            string session_id = 3; repeated string track_names = 4; }
```

- `Offer.ring = false` is a non-ringing notice that a group call started.
  `created_at_ms` MUST be in `0..=2^53−1`; anything else is refused.
- `Joined` says the device is in the call as `participant_id`, encrypting
  under the key of `leaf_index`. It is sent on joining and every 10 s as a
  heartbeat. The core sends `session_id` and `track_names` empty (they
  travel inside grants); a receiver refuses a signed `Joined` whose
  `session_id` is set and ignores its `track_names`. `media_key` carries the
  call key and, in the signed `Joined` only, `media_key_pq` the post-quantum
  call key.
- `MediaKey` grants the sender's media secret at `generation`: `rotated` is
  true for a fresh secret (a joiner's first share, or a rotation after a
  leaver) and false for an advance for a newcomer. Every grant goes in
  `pq_grants`; `grants` (X25519) is never taken (R-K11).
- `started_at_ms` (in `Joined` and `MediaKey`) is the sender's wall clock in
  milliseconds when its core began this participation, later than any
  earlier participation in that core; the core writes it, whatever the
  client passed. It MUST be in `0..=2^53−1`. A receiver orders nothing by it.
- `participation` (in `Joined` and `MediaKey`) is the participation's mark,
  24 bytes: its 16 random bytes, then the device's participation counter as a
  big-endian u64 in `1..=2^53−1`; the core writes it, whatever the client
  passed. Any other length or counter is refused. Its JSON form is
  `participationHex`, absent when empty.

  A signed `Joined` or `MediaKey` without it is refused.
- The `*_ELSEWHERE` reasons tell a person's own other devices to stop
  ringing. `NEED_PERMISSION` answers a caller the callee has not accepted.

**Tolerance.** Unknown fields are skipped at every level, whatever their wire
type. A body this build does not know decodes as `unknown`, which every
client ignores. An unknown media value reads as audio; an unknown hangup
reason as normal. The version is carried, not gated: a version above 1 still
decodes.

**Refused:** version 0 or absent, a field numbered 0, a malformed varint or
length, a known field with the wrong wire type, a call id that is absent or
not 16 bytes, a string that is not UTF-8, a group wire type, a `Direct` with
an empty SDP, a `Joined` whose `media_key` is neither empty nor 32 bytes, or
whose `media_key_pq` is neither empty nor 1216 bytes, or names one without a
`media_key`, a grant in `grants` whose `enc` is not 32 bytes or one in
`pq_grants` whose `enc` is not 1120 bytes, a grant whose ciphertext is empty,
and anything past the size caps.

**Encoding is canonical:** fields in number order, `version` and `call_id`
always written, proto3 defaults omitted inside a body. One signal has one
byte string, which lets the fixture pin bytes.

| Cap | Value |
|---|---|
| An encoded signal (`MAX_CALL_SIGNAL_BYTES`) | 16 384 bytes |
| A `Direct` SDP (`MAX_CALL_SDP_BYTES`) | 15 360 bytes |
| An id string: participant, session, target, track name | 256 bytes |
| A reaction | 64 bytes |
| Track names in one `Joined` or grant | 32 |
| Grants in one `MediaKey` (`MAX_CALL_MEDIA_GRANTS`) | 24 |

### The two lanes

The envelope's inner bytes start with a lane byte (`mls/core/src/call/frame.rs`):

```
lane 1, MLS:  0x01 ‖ MLSMessage      a PrivateMessage of content type application,
                                     authenticated_data = 0x63 0x01 ‖ 0x00 (16),
                                     whose plaintext is the encoded CallSignal
lane 2, live: 0x02 ‖ nonce (12) ‖ AES-256-GCM(live_key, nonce, aad = 0x02,
                    u32be(sender_leaf) ‖ u64be(sent_at_ms) ‖ u16be(len) ‖ CallSignal ‖ 0x00…)
```

**The MLS lane** is sender-authenticated by the group. Opening one names the
sender's identity and its `senderLeaf`.
- Its `authenticated_data` MUST be `0x63 0x01` followed by 16 zero bytes
  (`CALL_LANE_AAD`). It is not a content hint, and a receiver MUST ignore it.
  It is there for length: the lane byte plus these 18 bytes match a message's
  19 (its hint and the author's commitment), so a call signal is as long as a
  message whose plaintext falls in the same 256-byte padding block.
- It carries every signal but `Joined` heartbeats: `Offer`, `Answer`,
  `Hangup`, `Remove`, `Direct`, `MediaKey`, every `Left`, and the in-call
  controls `RaiseHand`, `React`, `RemoteMute` and `Media`
  ([In-call controls](#in-call-controls)), which `seal_call_signal` always
  puts there. A member therefore cannot ring as somebody else, forge
  "answered elsewhere", or forge a device's `Left`, and every control names
  its sender.
- `Joined` MAY be sent on it with `seal_call_signal_on_mls_lane`
  (`sealCallSignalSigned` in the bindings), and each participant's first
  `Joined` per epoch MUST go this way (D10). The core refuses a signed
  `Joined` whose `leaf_index` is not the sender's own leaf.
- On open, the MLS message MUST be an application message. A commit or
  proposal wrapped as a call signal is refused before the MLS library sees
  it, so a call envelope can never move the group's epoch. A device's own
  signal coming back is refused as an echo.
- These signals go through the mailbox, stored like messages
  ([The mailbox](delivery.md#the-mailbox)). `Offer`, `Answer` and `Hangup`
  are sent `urgent`; nothing else is (`call_signal_is_urgent_json`).

**The live lane** is keyed from the epoch's exporter, not the application
ratchet, as typing is
([The key is the epoch's exporter secret, not the application ratchet](sealed-messages.md#the-key-is-the-epochs-exporter-secret-not-the-application-ratchet)),
so a heartbeat every 10 s spends no ratchet generation.
- It carries `Joined` heartbeats only. It is sent like a typing frame:
  `SendSealed` with `ephemeral`, relayed to open streams, never stored and
  never pushed ([Typing](delivery.md#typing)). A sealed live frame MUST fit
  the ephemeral payload limit.
- The plaintext (leaf, stamp, length, signal) is zero-padded to a multiple of
  128 bytes (`CALL_LIVE_PADDING_BLOCK`). The nonce is 12 fresh random bytes.
  Opening refuses a wrong key, a flipped bit, a truncation, the MLS lane
  byte, a length that runs past the end, and nonzero padding.
- **The live lane's signature.** Every member holds the live key, so the key
  alone says only that a member wrote a frame; each live frame is therefore
  signed by the leaf it claims, as a typing frame is
  ([Typing inside the group](sealed-messages.md#typing-inside-the-group)).
  The sealing core signs with its leaf's signature key (Ed25519)
  `"peachy call live signature v1" ‖ 0x00 ‖ u32be(len(group_id)) ‖ group_id ‖ u64be(epoch) ‖ u32be(sender_leaf) ‖ u64be(sent_at_ms) ‖ CallSignal`
  (`live_signature_statement`, `mls/core/src/call/frame.rs`), where
  `CallSignal` is the encoded signal without its signature, and writes the
  64-byte signature as the signal's last field, number 64
  (`CALL_LIVE_SIGNATURE_FIELD`). The opening core splits the signature off
  (refusing one that is not 64 bytes, not the last field, or there twice) and
  verifies it, with `verify_strict`, under the leaf key of the claimed leaf at
  its own epoch, whose credential must check out. An unsigned live frame, or
  one that does not verify, is refused. The
  server cannot write a live frame at all.

- The core refuses every signal but `Joined` on the live lane, a live `Left`
  and a type this build does not know included: a live frame can never ring, stop a ring, hang up, remove anyone,
  drop a participant, or carry an in-call control (N6).
- The core also refuses a live frame whose claimed leaf is not in the tree,
  and a live `Joined` whose `leaf_index` is not the leaf its frame claims, or
  that names this device's own id or a participant bound at another leaf.
- A client MUST NOT bind a participant from a live `Joined`. A live `Joined`
  only refreshes a participant a signed one already bound, with the same
  participant id and leaf, and never changes its session or tracks. Its
  mark is not checked: a live `Joined` with no mark, or another
  participation's, opens like any heartbeat, and binds nothing.
- A receiver derives the live key at its own current epoch only. A frame from
  a sender one epoch away does not open and is dropped; the next heartbeat
  comes 10 s later.

### The live lane's replay window

Every live frame carries, inside its AEAD and its signature, the sender's
leaf and a stamp, and every receiver keeps a replay window over them
(`mls/core/src/call/replay.rs`; D3, N17).

- **The stamp** is the sender's agreed clock in milliseconds, made strictly
  increasing per device: `max(now_ms, last + 1)`. The sealing core fills in
  both the leaf (its own) and the stamp.
- **The agreed clock** is the device's wall clock plus the offset to the
  server's clock (`set_server_clock_offset_ms`, kept by the core for the
  process and bounded to a day either way, `SERVER_CLOCK_OFFSET_MAX_MS`).
  Each client sets the offset from the `server_time` every `FetchMailbox`
  answers with ([FetchMailbox and AckMailbox](delivery.md#fetchmailbox-and-ackmailbox)),
  against the midpoint of the request. Every stamp, check and typing stamp
  the core makes runs on it; until the client sets an offset it is 0.
- **The window.** The opening core keeps, per (group, sender leaf) and in
  memory, the leaf's epoch and the stamps it has accepted from it, each under
  the call it came in, and refuses, in this order:
  1. a stamp more than 120 s from its own agreed clock, either way
     (`CALL_LIVE_MAX_SKEW_MS`);
  2. a frame from an epoch older than the leaf's, while any stamp from that
     leaf is remembered. A newer epoch, or a leaf with no stamp remembered,
     starts the leaf afresh;
  3. a stamp it has already accepted from that leaf in the same call.

  Any other stamp is accepted once, in any order. The call id is sealed
  inside the frame, so a recording cannot be sent again as another call's.
- **It is bounded.** A stamp is kept with the receiver's monotonic time of
  arrival, and forgotten only once 240 s of monotonic time have passed
  (`CALL_LIVE_FORGET_MS`, twice the skew bound) and rule 1 refuses it, so
  stepping the wall clock forgets nothing early. A leaf keeps at most 256
  stamps (`MAX_SEEN`); past that the one accepted longest ago is forgotten,
  never the one just accepted, so a frame with a stamp below all 256 is still
  a duplicate. A window keeps at most 1 024 records, one per (group, leaf)
  (`CALL_LIVE_MAX_SENDERS`), and past that the one heard from least recently
  is forgotten. A frame claiming a leaf outside the tree is refused before
  the window.
- The check runs in `open_call_signal` once the frame's signature holds
  for its leaf, and before any check that reads the whole tree, so a
  replayed frame costs the receiver one credential check and one signature,
  whatever the group's size. A signed frame a later check refuses is
  remembered too. A refused frame is dropped like any frame that does not
  open.
- A receiver that restarts forgets the window.

### In-call controls

`RaiseHand`, `React`, `RemoteMute`, `Remove` and `Media` each name who sent
it, so they travel only on the MLS lane, through the mailbox, not urgent:
`seal_call_signal` seals them signed, and the core refuses one that arrives
live. A receiver attributes one to the participant that its authenticated
sender leaf's signed `Joined` bound, and drops one from a leaf nothing has
bound. Because they are stored, a device:

1. applies an in-call control only while it is in that call, and otherwise
   drops it;
2. takes, per sender, the latest `Media` and `RaiseHand` in MLS order.

`Remove` counts only from a group admin, and is always dropped in a 1:1. Each
client checks the sender is an admin itself, and once it honors a `Remove`
it never shows that participant id again, nor does its core bind it (R-K10).
MLS's own generation check protects the MLS lane from replay.

## Ringing

**The ring-state reducer** is a pure function in `mls/core/src/call/ring.rs`:
`ring_step(state, event) → (state, effects)`, with `ring_step_json` as the
door the bindings use. It holds no clock and no timer and sends nothing; the
client feeds it what happened and does what the effects say.
`mls/fixtures/calls.json` pins it case by case.

| Constant | Value |
|---|---|
| `CALL_RING_CAP` | 16 |
| `CALL_RING_TIMEOUT_MS` | 60 000 |
| `CALL_OFFER_MAX_AGE_MS` | 60 000 |
| `CALL_OFFER_MAX_SKEW_MS` | 120 000 |

- **States:** `idle`, `outgoing` (a 1:1 call this device placed, not yet
  answered), `ringing`, `inCall`.
- **Events:** `placeCall`, `offer` (with its age, the caller's `createdAtMs`
  and this device's agreed clock `nowMs`,
  [The live lane's replay window](#the-live-lanes-replay-window)), `answer`,
  `hangup` (signals that arrived, each with its sender's account, whether it
  is this account, and the conversation it arrived in), `accept`, `decline`,
  `hangUp { alone }` (the person's taps), `timeout` (a timer the reducer
  asked for).
- **Effects:** `ring`, `stopRinging`, `notice`, `send { to, signal }` with
  `to` either `conversation` or `ownDevices`, `join`, `leave`,
  `armTimeout { afterMs }`, `peerAnswered`, `ended { outcome }`, `refused` and
  `rememberHangup`.
- **Outcomes** recorded by `ended`: missed, declined, answeredElsewhere,
  declinedElsewhere, busyElsewhere, remoteBusy, remoteDeclined,
  needsPermission, noAnswer, cancelled, completed and glare.

**The behavior.**
- **The ring cap.** An offer rings when its conversation is a 1:1, or its
  `ring` bit is set and the group has at most 16 members (`should_ring`). A
  caller sets the bit by the same rule, and the receiver applies it again. A
  larger group, or `ring = false`, gets a notice.
- **Stale offers do not ring.** An offer rings only while it is fresh by
  every clock the device has (`offer_is_fresh`); otherwise it is recorded as
  missed:
  - its age is between −120 s and 60 s. A drained offer's age is
    `server_time − received_at` from `FetchMailbox`
    ([FetchMailbox and AckMailbox](delivery.md#fetchmailbox-and-ackmailbox));
    one that arrives on the stream is aged by the agreed clock against
    `created_at_ms`;
  - the caller's `created_at_ms` is no more than 120 s ahead of this device's
    agreed clock and no more than 180 s (60 s plus the skew) behind it. A
    caller stamps `created_at_ms` on its own agreed clock (the `placeCall`
    event's `nowMs`).
- **Ring and answer timeout.** A ringing device stops after 60 s and records
  missed. A 1:1 caller cancels with `normal` and records no answer. A group
  caller is already in the call and does not time out.
- **This account's own offers never ring** on its other devices.
- **One call at a time per device.** An offer for another call while
  ringing, calling or in a call is busy: a 1:1 caller is told `busy`, a group
  ring's `busy_elsewhere` goes to this account's other devices, and the offer
  is recorded as missed.
- **Gating.** The client decides from its own records whether a caller may
  ring (`allowed`, `blocked`, `needsPermission`), and the gate runs before the
  freshness check and asks the block first. A blocked caller rings nothing and
  hears nothing: no `Direct`, no `busy`, no hangup, no `need_permission`, no
  marks or typing ([Blocked accounts](sealed-messages.md#blocked-accounts)).
  A caller this person has not accepted is told `need_permission` in a 1:1,
  whatever the offer's age, and rings nothing.
- **Answered, declined or busy elsewhere.** A ringing device that hears this
  account's own answer, decline or busy stops and records which
  ([The ring is a message](#the-ring-is-a-message)).
- **A 1:1 call hears only its own conversation.** While calling or in a 1:1
  call, an `Answer` or another account's `Hangup` counts only from the call's
  own conversation.
- **The caller cancelling** (any hangup from the caller while it rings) stops
  the ring as missed. Another member's hangup leaves a group ring as it was. A
  group caller who hangs up while nobody else has ever joined
  (`hangUp { alone: true }`) sends that hangup to the conversation.
- **Glare.** When both people in a 1:1 call each other at once, the larger
  call id (compared as lowercase hex) keeps its call; the other side ends its
  own with `normal` and rings for the winner. Equal ids lose both.
- **Re-call.** An offer from the other person in a 1:1 this device is already
  in ends the stale call and rings the new one.
- **A call already over never rings again.** An offer whose call id the
  device's call history holds is stepped with `alreadyEnded`, and is ignored
  (R-K5). The same offer redelivered while the device is on that call is
  ignored too.
- **A hangup that beats its offer.** A hangup for a call this device is not
  on yields `rememberHangup`; the client keeps a bounded number of these by
  call id and passes one back as the offer's `earlyHangup`. A caller's hangup
  then ends the call as missed, and one from this account's own device ends
  it as answered, declined or busy elsewhere, before the age check and
  without ringing. Only hangups are kept.
- An event about a call this device is not on changes nothing. An unknown
  event, a missing field or an unknown state is refused.

A client MUST step arriving call signals strictly in the order they arrived,
one to its end before the next.

### The ring is a message

An `Offer`, `Answer` or `Hangup` is sent exactly as a message a person would
want to hear about is:

- **Addressed to the conversation**: exactly the devices of the leaves in the
  sender's tree, its own other seated devices included
  ([Sending](delivery.md#sending)). In a 1:1 the reducer sends one `answer`,
  `declined`, `busy` or `need_permission` to the whole conversation, and the
  replier's other devices read it as answered, declined or busy elsewhere. A
  group ring's `*_elsewhere` reply goes to the replier's own devices alone,
  sealed with `SendSealed`, the one exception to whole-tree addressing.
- **`urgent`**, and nothing else: no ring field, no shorter lifetime, no push
  class of its own.
- **With its own retry key** ([Idempotency](delivery.md#idempotency)).

So neither the server nor a push service can tell a ring from a message by
any field it sees (D1).

### Hanging up

A hang-up turns this device's microphone, camera and screen share off, and
closes every media connection of the call, before anything else, as local
work. A client MUST NOT wait for the `Hangup` or `Left` to be sealed or
sent, or for `LeaveCall`, before stopping capture: a seal waits in the
conversation's queue behind every call frame peers send, and a send waits on
the network. The same holds for a decline, a ring timeout, a failure and a
removal.

What tells the others follows, best effort: the `Hangup` (a 1:1, or a group
caller still alone), the `Left`, the end of this device's media keys, and
`LeaveCall`. A client SHOULD wait for these a bounded time or not at all; if
they never arrive, the others see this device's media stop, and the server
ends its session by the heartbeat timeout.

The ring timer is armed only when a ring starts, and no arriving signal
re-arms it, so the 60 s timeout and a decline always end it. A client SHOULD
queue live-lane frames for opening at most 32 at a time per conversation and
drop the rest; the lane is lossy by design. The bound is per conversation,
since a frame's leaf is known only once it is opened. A signed `Left` and
every `MediaKey` travel on the MLS lane, not in this queue.

## Direct 1:1 calls

A 1:1 call is one WebRTC peer connection between the caller's device and the
device that answers. Every byte of its setup rides sealed kind-6 envelopes on
the MLS lane; how the connection reaches the other device is out of scope.

**Which calls are direct.** A call is direct when the conversation is a 1:1
and the group's tree holds exactly two accounts, this one and the other
person's. A 1:1 whose tree is not exactly those two fails the call. There is
no fallback between a direct call and a group call in either direction.

**The signal.** `Direct { to_leaf, sdp, offer }` is body 13 of the codec:
- It carries one complete session description, not trickled: at most
  15 360 bytes, never empty. `offer` is true for an SDP offer and false for an
  SDP answer.
- It travels on the MLS lane only, signed, never `urgent`.
- It is addressed like every call signal, to all the conversation's devices.
  `to_leaf`, inside the sealed body, names the one device meant to act on it.
- Each ringing device of the callee sends its offer to the caller's leaf; the
  caller answers each, and keeps the one whose device answers.

**Who may speak.** A client MUST drop every other `Direct`:
- A caller takes a `Direct { offer: true }` only when `to_leaf` is its own
  leaf, the call is the one it placed, and the MLS sender is a device of the
  other person: before the `Answer`, one per device; after it, only from the
  device that answered.
- A callee takes a `Direct { offer: false }` only from the leaf it sent its
  offer to, naming its own leaf.
- Once bound, the DTLS certificate fingerprint MUST NOT change: a later SDP
  (an ICE restart) whose fingerprint differs from the bound one ends the call.
- The peer's leaf is bound by its signed `Answer` or `Direct`, so no `Joined`
  is sent in a direct call.

**Two layers of encryption, both authenticated by MLS.**
1. **DTLS-SRTP, device to device.** The certificate fingerprints travel only
   inside MLS-signed `Direct` signals from the expected leaf, so the handshake
   is authenticated to the two devices' leaves, whose credentials are bound to
   each account's identity ([The MLS leaf](identity.md#the-mls-leaf)). DTLS's
   ephemeral exchange gives each call fresh keys.
2. **Frame encryption**, on the v1 schedule. Its media never passes a media
   server, so the other members that derive its v1 keys, the two people's
   other devices, have no copy of its packets.

A device that cannot build either layer MUST end the call. There is no
unencrypted path.

**Rekey.** Every commit still rekeys the frame keys. A direct call runs no
in-call periodic self-update: a commit from both people every 10 minutes
would tell the server a call was running and for how long.

**IP addresses.** A client MUST restrict a direct call to relay candidates,
as caller and as callee, when the other person is one it has not accepted,
or when it cannot tell whether it has. A person MAY also choose to relay
every call.

A ringing device MUST restrict its connection to relay candidates until its
person answers, whatever its relay rule says. When its person answers and its
rule allows every candidate, it widens the same connection and restarts ICE
once (a new `Direct { offer: true }` to the bound leaf, the same DTLS
certificate). The caller's rule applies from its first answer.

So, unless a device relays by its rule: before the answer, each ringing callee
device can learn the caller's address and the caller learns none of theirs;
after it, the caller can learn the answering device's address and no other.
The relay service learns the address of every device that uses it.

A group call's connection to the media server is restricted to relay
candidates always, so no member learns another member's address there.

## Security considerations

The adversaries are: the server, which relays every envelope and live frame;
the media server and relays, which forward every encrypted frame; the
network; push services; a removed member with its whole device state,
colluding with all of those; a malicious current member; a device seized
after a call (forward secrecy); and a device whose group state was copied
mid-call (post-compromise security, the signature key not taken). Out of
scope: a member who records what it legitimately hears, a compromised
operating system or app, traffic analysis, and denial of service.

**The exporter labels in use per epoch**, all under one epoch secret:

| Label | Context | Holder of the output |
|---|---|---|
| `peachy call v1` | call id | members only |
| `peachy call v2` | call id | members only; alone it is no key (v2 needs a participant's media secret too) |
| `peachy call live v1` | empty | members only |
| `peachy typing v1` | group id | members only |
| `peachy sealed-sender v1` | group id | members, **and the server** |

The server holds each epoch's sealed-sender output
([The anonymous door](sealed-messages.md#the-anonymous-door)). Label
separation is all that keeps it from being a call key; N4 tests it and the
formal model checks it.

### Rekeying requirements

Requirements on the core and on every client, tested in
[Negative tests](#negative-tests).

- **R-K1. Every commit is a rekey.** On merging `e+1` a client derives
  `call_root(e+1)` and every sender key, installs them at slot
  `(e+1) mod 256`, and switches its own sending key at once. It MUST NOT
  encrypt a frame under `e` after merging `e+1`. A committer derives `e+1`
  from its staged commit (`pending_call_keys`) and switches on merge, not on
  submit. A client SHOULD fire the rekey from the merge itself; one that
  notices the new epoch on a poll extends R-K3's window by up to one poll.
- **R-K2. The previous epoch's keys are deleted after the grace window.** A
  receiver keeps epoch `e`'s frame keys for `CALL_KEY_GRACE_MS` after merging
  `e+1`, then MUST delete them from its key ring, with any cached
  `call_root`. Forward secrecy rests on this deletion
  (`forward_secrecy_control.pv`); a native WebRTC key ring does not drop an
  old epoch's keys on its own.
- **R-K3. Removal is a commit first.** The remover's Remove commit makes
  `e+1`. Until each sender processes it, that sender may still encrypt under
  `e`, and the removed member can read those frames: the commit's delivery
  latency plus R-K1's switch. Evicting the removed device from the media path
  is the server's, out of scope here.
- **R-K4. Each device updates its own leaf.** In a group call every
  participant MUST commit its own on the schedule in
  [Keys as built](#keys-as-built) (D2).
- **R-K5. A call id is used once.** `call_id` is 128 fresh random bits. An
  offer for a call this device already recorded as over never rings
  (`alreadyEnded`), so a member cannot restart a call under keys already used
  in that epoch.
- **R-K6. IVs never repeat under one frame key.** One SSRC repeats an IV only
  after the 32-bit RTP timestamp wraps, about 13 hours of 90 kHz video, far
  longer than any epoch under R-K4. Across SSRCs a repeat needs an SSRC
  collision, about 2⁻³² per pair. A rejoin within an epoch reuses the sender
  key with fresh random SSRCs. This is argued, not proved.
- **R-K7. The key provider derives only what the core did**: HKDF with the
  salt above, ratchet window 0, no shared key, a ring of 256
  ([Keys as built](#keys-as-built)).
- **R-K8. No clear frames, either way.** A track with no key installed MUST
  send nothing, and a client MUST NOT disable the encryptor on a call track.
  A receiver MUST NOT pass through any frame undecrypted: a frame encryptor's
  "unencrypted magic bytes" or similar trailer MUST be configured empty (D4),
  and a frame that arrives before its key is ready MUST be dropped.
- **R-K9. The live key does not outlive an epoch.** A client MUST NOT keep a
  live key past an epoch change; the core derives it at the current epoch
  only. The grace window is for frame keys alone (D7).
- **R-K10. In a group call, being in the call is the key boundary**
  ([Participant media keys](#participant-media-keys)). A client:
  1. joins with `start` (under the participant id `JoinCall` answered), then
     a signed `Joined`, then `share`, and sends every envelope a door returns
     in `send`, in order. A `start` that fails fails the join;
  2. on a participant's heartbeat going stale calls `remove` with its leaf,
     and on a `Remove` it honors calls `remove` with the participant id; for
     its own id, the core ends this device's participation as `end` does, and
     the client seals its own `Left` and leaves;
  3. on every epoch change it sees, calls `epoch`, at the latest after the
     rest of the mailbox page that carried the commit;
  4. whenever an answer (an open's included) reports `applyAfterMs`, calls
     `apply` once that much time has passed, and arms again from that
     answer's `applyAfterMs`; it never waits a delay of its own, and never
     moves a knock already armed to a later time;
  5. reloads `keys` after every open that granted or announced a key, every
     epoch change, every rotation, every `apply`, and every answer that
     reports `applied`, and installs exactly what it returns: no key from any
     other source;
  6. pulls a participant's media only with the session and tracks a grant
     gave it;
  7. takes its tiles from the core: drops a tile for a signed `Left` only when
     the open's `unboundLeaf` is the leaf that tile is at, and on every `keys`
     reload drops each tile that was up when it asked and that `participants`
     no longer lists at its leaf;
  8. on `CALL_STATE_LOST` from `keys` or from sealing its `Joined`, while it
     is in the call, joins the keys again under the same participant id and
     session ([Participant media keys](#participant-media-keys), lost state),
     and ends the call if that `start` fails.
- **R-K11. The core runs no group call on the shared key.** It refuses a
  `Joined` without both call keys or naming a session, and any op it does
  not list, and takes no grant sealed to an X25519 key. A direct
  1:1 call runs on v1 by design.

### Key confirmation

There is no explicit key confirmation message. A receiver that opens a frame
under epoch `e`'s key knows that some holder of `e`'s secret sent it; with a
malicious member present, that is not necessarily the claimed sender (D10). A
live `Joined` that fails to open while the same peer's MLS-lane signals do
open means the two devices disagree on the epoch, not packet loss.

### Disagreements

Points where the obvious design is unsafe, each with the rule that answers
it. Code and tests cite the numbers.

- **D1. A ring must not be told from a message at the push service.** A ring
  with its own push class, lifetime or collapse key would show the server and
  the push services which envelopes are calls. **Rule:** a ring is an
  ordinary urgent sealed envelope ([The ring is a message](#the-ring-is-a-message)).
- **D2. One participant's self-update heals nobody else.** A commit's path
  secret is sealed to every other leaf's current key, so a copied leaf keeps
  reading until that device updates (`pcs_update_by_other.pv`: attack;
  `pcs_update_by_compromised.pv`: the cure). **Rule:** every participant of a
  group call commits its own self-update every
  `CALL_SELF_UPDATE_INTERVAL_MS`, offset by
  `call_self_update_offset_ms(rank, participants)`, at a cost of N commits per
  period.
- **D3. Replay within an epoch.** A replayed frame or live signal carries
  no new content. **Rule for live signals:** the stamp and window of
  [The live lane's replay window](#the-live-lanes-replay-window) (N17).
- **D4. An encryptor's "unencrypted" passthrough is an injection door** for
  the media server. **Rule:** R-K8.
- **D5. A removed member must not classify later envelopes.** An outer key
  fixed for the group's life would let a removed member, with the server's
  help, read the kind byte (6) and the lane byte of later envelopes.
  **Rule:** a member MUST seal a call signal at its epoch as a version 3
  envelope ([The wrapped envelope](delivery.md#the-wrapped-envelope)), whose
  keys a member removed at a commit does not hold. Content is never readable
  (`post_removal.pv`).
- **D6. The grace window does not bound a removed member.** It is a
  receive-side allowance; R-K3 bounds a removed member.
- **D7. A previous epoch's live key would let a removed member inject live
  signals** during a grace window. **Rule:** R-K9.
- **D8. The ring cap and the offer's freshness are enforced in the
  reducer**, so every client applies them and the reducer's fuzz target
  checks them as invariants.
- **D9. The call id is public in the model.** Nothing proved depends on it
  staying secret; in `non_participant.pv` the member that never joins holds
  every call id.
- **D10. Member impersonation, narrowed by a signed `Joined`.** A member can
  put frames on another member's tile only if receivers map its track to the
  victim's leaf, and that mapping comes from `Joined`. **Rule:** each
  participant's first `Joined` per epoch goes signed on the MLS lane; the core
  refuses a signed `Joined` naming another leaf; a live `Joined` only
  refreshes a binding with the same participant and leaf.
- **D11. Under v1 every member could listen to a group call it never joined,
  and leaving would rekey nothing.** Rekeying the group on every join and
  leave fixes neither, since everybody stays a member. **Rule:** participant
  media keys ([Participant media keys](#participant-media-keys)), at the cost
  of a `MediaKey` per participant on every join and leave.

### The formal model

`mls/formal/calls/` is a ProVerif 2.05 model of the key schedule, rekeying
and participant media keys, with MLS reduced to its key-schedule steps and
every KDF and AEAD ideal. The attacker owns the network, standing for the
server, the media server, relays and push services at once. `run.sh` checks
all 53 verdicts against `expected.txt` (`mls/formal/calls/README.md` says how
to run it). It assumes MLS itself is sound, and an uncompromised signature
key in the post-compromise models.

| Model | Verdict |
|---|---|
| `server_sfu.pv` | Media and every call secret stay secret from the server, the media server and the network; frames are authenticated to the epoch's holders; replay within an epoch is an expected attack (D3) |
| `post_removal.pv` | A removed device learns and forges nothing in later epochs; a member can impersonate another (D10) |
| `forward_secrecy.pv`, `forward_secrecy_control.pv` | Seizing devices reveals no earlier epoch, unless the old frame key is kept (R-K2) |
| `pcs_update_by_compromised.pv`, `pcs_update_by_other.pv` | A copied state heals only when its own device self-updates (D2) |
| `non_participant.pv` | A member that never joins, a leaver and a newcomer read no media outside their window (D11) |

Not modeled: IV uniqueness (R-K6), the grace window's timing (R-K3),
multiple devices, the ring reducer, the live lane's replay window and
signature, and the server's authorization.

### Negative tests

`mls/core/tests/calls_*.rs` test each requirement on the real core, each
binding replays `mls/fixtures/calls.json`, and N1 is the formal model's
`run.sh`. Code and tests cite the numbers; numbers not listed test the
server, the apps and CI, outside this protocol.

| N | Property |
|---|---|
| N1 | Every formal verdict, expected attacks included |
| N2 | A removed device derives no `e+1` call or live key |
| N3 | Forward secrecy at `e+1`, on the SQLite store and from every cut of its log; not below the file ([MLS core](mls-core.md#security-considerations)) |
| N4 | Exporter label and context separation |
| N5 | Live-lane integrity |
| N6 | Lane authentication: only `Joined` opens live; a live frame's leaf is in the tree and matches its `Joined` |
| N7 | Cross-client agreement on refusals and keys |
| N15 | A call already over never rings (R-K5) |
| N16 | A removed member or a recording at the media server decodes no frame; a tampered frame does not decode |
| N17 | The live lane's replay window (D3) |
| N20 | An offer is fresh only by both clocks |
| N21 | Participant media keys (D11, R-K10) |

## IPR

This document is dedicated to the public domain under CC0 1.0.

## References

- [RFC 2119] "Key words for use in RFCs to Indicate Requirement Levels", BCP 14, RFC 2119, March 1997. <https://www.rfc-editor.org/rfc/rfc2119>
- [RFC 8174] "Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words", BCP 14, RFC 8174, May 2017. <https://www.rfc-editor.org/rfc/rfc8174>
- [RFC 9420] "The Messaging Layer Security (MLS) Protocol", RFC 9420, July 2023. <https://www.rfc-editor.org/rfc/rfc9420>
- [RFC 9180] "Hybrid Public Key Encryption", RFC 9180, February 2022. <https://www.rfc-editor.org/rfc/rfc9180>
- [RFC 5869] "HMAC-based Extract-and-Expand Key Derivation Function (HKDF)", RFC 5869, May 2010. <https://www.rfc-editor.org/rfc/rfc5869>
- [SP 800-38D] NIST, "Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC", SP 800-38D, November 2007. <https://doi.org/10.6028/NIST.SP.800-38D>
- [FIPS 180-4] NIST, "Secure Hash Standard (SHS)", FIPS 180-4, August 2015. <https://doi.org/10.6028/NIST.FIPS.180-4>
