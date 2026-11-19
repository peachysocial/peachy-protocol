<!-- SPDX-License-Identifier: MIT -->

# A symbolic model of the call key schedule

This is a ProVerif model of how a Peachy call derives its keys and rekeys. `docs/calls.md` §The formal model explains the abstractions, the assumptions and every verdict. This file covers how to run it.

| File | Scenario |
|---|---|
| `calls.pvl` | Primitives shared by every model: the MLS key-schedule steps, the call schedule, HPKE, signatures, AEAD. It also defines the events and the sender and receiver roles. |
| `server_sfu.pv` | The server, the media server (SFU), the network and the push providers all collude against three honest members. The call goes through one self-update rekey. |
| `post_removal.pv` | A removed device is fully compromised and colludes with the server and media server. |
| `forward_secrecy.pv` | Both devices are seized after the call has moved on to a later epoch. |
| `forward_secrecy_control.pv` | The same seizure, except the device never deleted the old epoch's key. This is the negative control. |
| `pcs_update_by_compromised.pv` | A copied device state, healed by that device's own self-update. |
| `pcs_update_by_other.pv` | The same copied state, with another device doing the update. It does not heal (D2 in `docs/calls.md` §Disagreements). |
| `non_participant.pv` | Participant media keys (v2). A member that never joins the call, a participant that left and keeps its state, and a newcomer all collude with the server and the media server. Each one reads only the media it was granted. |
| `expected.txt` | Every verdict, pinned. Some of them are attacks, and they are expected. |
| `run.sh` | Runs every model and diffs the verdicts against `expected.txt`. |

## Installing ProVerif

Use ProVerif 2.05. To build the command-line tool without the GTK simulator:

```
brew install ocaml opam
opam init --bare -n --disable-sandboxing
opam switch create proverif ocaml-system
opam source proverif            # unpacks proverif.2.05/ here
cd proverif.2.05 && ./build -nointeract
```

## Running it

```
PROVERIF=/path/to/proverif.2.05/proverif mls/formal/calls/run.sh
```

- It prints `53 verdicts, all as expected`, and on any drift it exits non-zero with a diff.
- Each model's full ProVerif output goes to `build/formal/calls/<model>.log`. Read the attack traces there.
- To run one model by hand: `proverif -lib mls/formal/calls/calls mls/formal/calls/post_removal.pv`.

## Reading a verdict

- `RESULT not attacker(x) is true`: `x` stays secret.
- `... is false`: ProVerif found an attack. It is expected only where `expected.txt` says so, and the model's header explains why.
- `event(A) ==> event(B) is true`: every `A` is preceded by a matching `B` (authentication). `inj-event` additionally requires one `B` per `A`, so it fails when a message can be replayed.
- `not event(E) is false`: `E` is reachable. Most models have one of these; `forward_secrecy`, its control and `pcs_update_by_other` show their runs are real by an expected attack instead, so that a "true" elsewhere cannot come from a run that never completes.

## Changing a model

After changing a model or `mls/core/src/call/keys.rs`, rerun; `run.sh --update` re-pins `expected.txt`.
