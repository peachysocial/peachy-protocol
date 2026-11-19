// SPDX-License-Identifier: MIT
// The same journey, driven from JavaScript through the BUILT package.
//
// This is the half the Rust tests cannot be. `wasm-pack test --node` compiles
// the test into the same module as the code and calls it across a boundary
// wasm-bindgen generated for itself; it proves the Rust is right. It cannot
// prove that the package a `import` statement gets is usable — that the class
// is exported under the name the doc promises, that a byte field arrives as a
// Uint8Array rather than an array of 32 numbers, that an epoch is a number and
// not a BigInt, or that a failure arrives as a thrown Error a `catch` can read.
// Every one of those is glue that compiles and then hands JS something nobody
// can use.
//
// Run it against a nodejs-target build:
//
//   wasm-pack build mls/wasm --target nodejs --dev --out-dir pkg-node -- --features test-issuer
//   node --test mls/wasm/tests/node/journey.test.mjs
//
// The file, not the directory: `node --test <dir>` on Node 22 tries to load the
// directory as a module and dies with MODULE_NOT_FOUND before a test runs.
//
// `pkg-node/` is gitignored and carries the test issuer, which `pkg/` (the
// --target web build the client would load) deliberately does not.

import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { createRequire } from 'node:module';
import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { testAccountKey } from './test-account.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const pkgDir = resolve(here, '../../pkg-node');
const entry = resolve(pkgDir, 'peachy_mls_wasm.js');

if (!existsSync(entry)) {
  throw new Error(
    `no build at ${pkgDir}. Run:\n` +
      '  wasm-pack build mls/wasm --target nodejs --dev --out-dir pkg-node -- --features test-issuer',
  );
}

// A --target nodejs build is CommonJS, so it comes in through createRequire
// rather than a bare import. That is the build's shape, not a workaround: the
// --target web build the browser loads is an ES module with an async init, and
// testing THAT under node would mean testing a polyfilled fetch instead of the
// binding.
const require = createRequire(import.meta.url);
const wasm = require(entry);

const {
  MlsClient,
  TestIssuer,
  foundingSeats,
  generateSigningKeySeed,
  signingKeyPublicKey,
  accountIdentityPublicKey,
  version,
} = wasm;

// Around today, since the binding reads the wall clock (as the Swift and

// Kotlin suites' TestIssuer.now does), and for the issuer's real thirty days:

// a credential claiming longer than thirty-one is refused as

// implausible_lifetime (mls/core/src/identity.rs, MAX_CREDENTIAL_LIFETIME_SECONDS).

const NOW = Math.floor(Date.now() / 1000) - 3_600;

const LIFETIME = 30 * 86_400;

const enc = new TextEncoder();
const dec = new TextDecoder();

function issuer() {
  return new TestIssuer(new Uint8Array(32).fill(7));
}

function device(iss, actorId, deviceId, seedByte) {
  const seed = new Uint8Array(32).fill(seedByte);
  const publicKey = signingKeyPublicKey(seed);
  const token = iss.issue(actorId, deviceId, publicKey, NOW, NOW + LIFETIME);
  return { seed, publicKey, token, held: heldKey(actorId) };
}

// The identity key a client opened on an `issue` credential for `actorId` holds.
function heldKey(actorId) {
  return accountIdentityPublicKey(testAccountKey(actorId));
}

function client(iss, dev) {
  return new MlsClient(iss.publishedJson(), dev.token, dev.seed, dev.held);
}

test('the package exports the surface the doc names', () => {
  assert.equal(typeof MlsClient, 'function');
  assert.equal(typeof generateSigningKeySeed, 'function');
  assert.equal(typeof signingKeyPublicKey, 'function');
  assert.equal(version(), '0.2.0');
  for (const method of [
    'generateKeyPackage',
    'generateKeyPackageWithRef',
    'createGroup',
    'joinFromWelcome',
    'addMember',
    'seatFounding',
    'foundingRefusals',
    'removeMember',
    'selfUpdate',
    'mergePendingCommit',
    'clearPendingCommit',
    'hasPendingCommit',
    'roster',
    'leafOfDevice',
    'epoch',
    'isActive',
    'encrypt',
    'processMessage',
    'processCommit',
    'exportSecret',
    'replaceMember',
    'isBehind',
    'commitStrands',
    'contestedWelcomeGroupId',
    'joinContestedWelcome',
    'welcomeGroup',
    'joinFromWelcomeAtHead',
    'confirmHead',
    'firstSightOfJoinRequest',
    'joinRequestSeen',
    'forgetGroup',
    'updateCredential',
    'ownLeafCredentialExpiresAt',
    'leafCredentialExpiring',
    'leafCredentialPastGrace',
    'credentialRefreshDue',
    'refreshCredential',
  ]) {
    assert.equal(
      typeof MlsClient.prototype[method],
      'function',
      `MlsClient.prototype.${method} is missing`,
    );
  }
  // No doorless way in: a message goes through `processMessage`, a commit
  // through `processCommit`, and each refuses the other kind unread.
  assert.equal(typeof MlsClient.prototype.process, 'undefined', 'the doorless process is exported');
});

test('two members: add, Welcome, a message each way, remove, and the removed member goes dark', () => {
  const iss = issuer();
  const ada = device(iss, 'actor-ada', 'device-ada', 1);
  const bo = device(iss, 'actor-bo', 'device-bo', 2);
  const adaClient = client(iss, ada);
  const boClient = client(iss, bo);

  const group = enc.encode('group-journey');
  adaClient.createGroup(group);
  assert.equal(adaClient.epoch(group), 0);
  assert.equal(typeof adaClient.epoch(group), 'number', 'an epoch is a number, not a BigInt');

  const keyPackage = boClient.generateKeyPackage();
  assert.ok(keyPackage instanceof Uint8Array, 'a key package is bytes');

  const added = adaClient.addMember(group, keyPackage);
  assert.equal(added.epoch, 1, 'the epoch this commit WOULD produce');
  assert.ok(added.commit instanceof Uint8Array);
  assert.ok(added.welcome instanceof Uint8Array, 'an add carries a Welcome');

  // Staged, not adopted: a commit is Ada's proposal until the delivery service
  // accepts it, and this stands in for that acceptance.
  assert.equal(adaClient.hasPendingCommit(group), true);
  assert.equal(adaClient.epoch(group), 0, 'still at the old epoch until it merges');
  assert.equal(adaClient.mergePendingCommit(group), 1);
  assert.equal(adaClient.hasPendingCommit(group), false);

  const joined = boClient.joinFromWelcome(added.welcome);
  assert.deepEqual(Array.from(joined), Array.from(group));

  // Ada speaks, Bo reads.
  const fromAda = adaClient.encrypt(group, enc.encode('hello from ada'));
  const heard = boClient.processMessage(group, fromAda);
  assert.equal(heard.kind, 'application');
  assert.equal(dec.decode(heard.plaintext), 'hello from ada');
  assert.equal(heard.sender.actorId, 'actor-ada');
  assert.equal(heard.sender.deviceId, 'device-ada');
  assert.ok(heard.sender.deviceKey instanceof Uint8Array, 'a device key crosses as bytes');
  assert.equal(heard.sender.expiresAt, NOW + LIFETIME);

  // Bo speaks, Ada reads.
  const fromBo = boClient.encrypt(group, enc.encode('hello from bo'));
  const back = adaClient.processMessage(group, fromBo);
  assert.equal(back.kind, 'application');
  assert.equal(dec.decode(back.plaintext), 'hello from bo');

  // The roster: two entries, both verified, neither rejected.
  const roster = adaClient.roster(group);
  assert.equal(roster.length, 2);
  assert.deepEqual(
    roster.map((entry) => entry.identity.actorId).sort(),
    ['actor-ada', 'actor-bo'],
  );
  assert.ok(roster.every((entry) => entry.rejection === null));

  // The exporter agrees across members and separates across labels.
  const adaSecret = adaClient.exportSecret(group, 'peachy/test', enc.encode('ctx'), 32);
  const boSecret = boClient.exportSecret(group, 'peachy/test', enc.encode('ctx'), 32);
  assert.deepEqual(Array.from(adaSecret), Array.from(boSecret));
  const otherLabel = adaClient.exportSecret(group, 'peachy/other', enc.encode('ctx'), 32);
  assert.notDeepEqual(Array.from(adaSecret), Array.from(otherLabel));

  // A self-update rotates Ada's leaf and moves the epoch on; Bo follows it.
  const rotated = adaClient.selfUpdate(group);
  assert.equal(rotated.epoch, 2);
  assert.equal(rotated.welcome, null, 'a bare self-update welcomes nobody');
  adaClient.mergePendingCommit(group);
  assert.equal(boClient.processCommit(group, rotated.commit).kind, 'commit');
  assert.equal(boClient.epoch(group), 2);

  // Ada removes Bo. Bo sees the commit, and then cannot read a word of it.
  const leaf = adaClient.leafOfDevice(group, 'device-bo');
  const removal = adaClient.removeMember(group, leaf, adaClient.roster(group).find((e) => e.leafIndex === leaf).leafKey);
  adaClient.mergePendingCommit(group);
  const seen = boClient.processCommit(group, removal.commit);
  assert.equal(seen.kind, 'commit');
  assert.equal(seen.removedSelf, true);
  assert.deepEqual(seen.removed, [leaf]);
  assert.equal(boClient.isActive(group), false);
  assert.equal(adaClient.roster(group).length, 1);

  const afterward = adaClient.encrypt(group, enc.encode('just us now'));
  assert.throws(
    () => boClient.processMessage(group, afterward),
    /not an active member of this group/,
    'the removed member cannot decrypt what comes after',
  );

  for (const c of [adaClient, boClient]) c.free();
});

// docs/delivery.md §Founding a conversation: one commit seats every
// device, the founder's own package rides in the same Welcome, and her copy
// opens nothing (mls/core/tests/founding_names_nobody.rs is the protocol half).
test('one founding commit seats everyone and the founder copy opens nothing', () => {
  assert.equal(typeof foundingSeats(), 'number');
  const iss = issuer();
  const adaClient = client(iss, device(iss, 'actor-ada', 'device-ada', 1));
  const boClient = client(iss, device(iss, 'actor-bo', 'device-bo', 2));
  const cyClient = client(iss, device(iss, 'actor-cy', 'device-cy', 3));

  const group = enc.encode('group-founding');
  adaClient.createGroup(group);
  const own = adaClient.generateKeyPackage();
  const bo = boClient.generateKeyPackage();
  const cy = cyClient.generateKeyPackage();
  // A second package for one device is left out, by index.
  assert.deepEqual([...adaClient.foundingRefusals(group, [bo, cy, bo])], [2]);
  const founding = adaClient.seatFounding(group, [bo, cy], own);
  assert.equal(founding.epoch, 1);
  adaClient.mergePendingCommit(group);
  assert.equal(adaClient.roster(group).length, 3);

  boClient.joinFromWelcome(founding.welcome);
  cyClient.joinFromWelcome(founding.welcome);
  const heard = boClient.processMessage(group, adaClient.encrypt(group, enc.encode('hi')));
  assert.equal(dec.decode(heard.plaintext), 'hi');
  assert.throws(() => adaClient.joinFromWelcome(founding.welcome));
});

// The verb a client publishing to a key-package DIRECTORY needs, as opposed to
// the one a test handing a package straight to `addMember` needs. Peachy's
// `PublishKeyPackages` files each package under its RFC 9420 KeyPackageRef and
// uses that as the idempotency key, and the server has no MLS implementation to
// check it with — so if this computed something plausible but wrong, nothing
// anywhere would say so and a device replenishing its pool would grow it
// without bound instead of writing zero rows.
test('a key package can be minted with the reference a directory files it under', () => {
  const iss = issuer();
  const ada = device(iss, 'actor-ada', 'device-ada', 1);
  const bo = device(iss, 'actor-bo', 'device-bo', 2);
  const adaClient = client(iss, ada);
  const boClient = client(iss, bo);

  const published = boClient.generateKeyPackageWithRef();
  assert.ok(published.keyPackage instanceof Uint8Array, 'a key package is bytes');
  assert.ok(published.keyPackageRef instanceof Uint8Array, 'a reference is bytes');
  // SHA-256 for MLS_128_MLKEM768X25519_AES128GCM_SHA256_Ed25519.
  assert.equal(published.keyPackageRef.length, 32);
  assert.equal(published.ciphersuite, 0x004f, 'the suite id rides along so a pool can be keyed on it');

  // The reference is NOT a hash of the bytes beside it — those carry an
  // MlsMessage header the reference is computed under. A client tempted to
  // hash what it was handed would get this instead, and nothing else in MLS
  // would recognize it.
  const naive = createHash('sha256').update(published.keyPackage).digest();
  assert.notDeepEqual(Array.from(published.keyPackageRef), Array.from(naive));

  // Single-use, so two calls are two different packages under two different
  // names: a pool of N is N rows, not one row published N times.
  const second = boClient.generateKeyPackageWithRef();
  assert.notDeepEqual(
    Array.from(published.keyPackageRef),
    Array.from(second.keyPackageRef),
    'each key package gets its own reference',
  );

  // And the package half is the same thing `generateKeyPackage` returns: it
  // still adds a member.
  const group = enc.encode('group-refs');
  adaClient.createGroup(group);
  const added = adaClient.addMember(group, published.keyPackage);
  adaClient.mergePendingCommit(group);
  assert.deepEqual(
    Array.from(boClient.joinFromWelcome(added.welcome)),
    Array.from(group),
    'a package minted with its reference is still a package',
  );

  for (const c of [adaClient, boClient]) c.free();
});

test('a core failure arrives as a thrown Error carrying the core message', () => {
  const iss = issuer();
  const ada = device(iss, 'actor-ada', 'device-ada', 1);

  assert.throws(
    () => new MlsClient(iss.publishedJson(), ada.token, new Uint8Array(32).fill(9), ada.held),
    (err) => {
      assert.ok(err instanceof Error, 'a failure is an Error, not a code');
      assert.equal(err.message, 'device credential rejected: leaf_key_mismatch');
      return true;
    },
  );

  assert.throws(
    () => new MlsClient(iss.publishedJson(), ada.token, new Uint8Array(3), ada.held),
    /a device signing key seed must be exactly 32 bytes, got 3/,
  );

  const adaClient = client(iss, ada);
  assert.throws(() => adaClient.encrypt(enc.encode('nope'), enc.encode('hi')), /no such group/);
  adaClient.free();
});

test('a generated seed enrolls, and an expired credential is refused', () => {
  const iss = issuer();

  const seed = generateSigningKeySeed();
  assert.ok(seed instanceof Uint8Array);
  assert.equal(seed.length, 32);
  assert.notDeepEqual(Array.from(seed), Array.from(generateSigningKeySeed()));

  const publicKey = signingKeyPublicKey(seed);
  const token = iss.issue('actor-new', 'device-new', publicKey, NOW, NOW + LIFETIME);
  const fresh = new MlsClient(iss.publishedJson(), token, seed, heldKey('actor-new'));
  assert.equal(fresh.identity.actorId, 'actor-new');
  assert.deepEqual(Array.from(fresh.identity.deviceKey), Array.from(publicKey));
  fresh.free();

  // `exp` in the past. The clock here is the real one, so the expiry is dated
  // against 1970 rather than against NOW — an absolute past, not a relative one.
  const stale = iss.issue('actor-old', 'device-old', publicKey, 1_000, 2_000);
  assert.throws(
    () => new MlsClient(iss.publishedJson(), stale, seed, heldKey('actor-old')),
    /device credential rejected: expired/,
  );
});

// Two members commit at the same epoch. The delivery service takes one and
// refuses the other (docs/delivery.md §The ordering rule), and the
// loser has to be able to come back — which is the whole reason the binding
// exposes `clearPendingCommit` rather than merging inside `addMember`.
//
// The failure this rules out is silent: a loser that merged anyway would go on
// encrypting happily, at an epoch no other member will ever reach, with
// `isActive` still true and nothing thrown anywhere.
test('a refused commit is cleared, and the loser lands in the winner epoch', () => {
  const iss = issuer();
  const ada = device(iss, 'actor-ada', 'device-ada', 1);
  const bo = device(iss, 'actor-bo', 'device-bo', 2);
  const cy = device(iss, 'actor-cy', 'device-cy', 3);
  const adaClient = client(iss, ada);
  const boClient = client(iss, bo);
  const cyClient = client(iss, cy);

  // Ada and Bo, both at epoch 1.
  const group = enc.encode('group-race');
  adaClient.createGroup(group);
  const seeded = adaClient.addMember(group, boClient.generateKeyPackage());
  adaClient.mergePendingCommit(group);
  boClient.joinFromWelcome(seeded.welcome);
  assert.equal(adaClient.epoch(group), 1);
  assert.equal(boClient.epoch(group), 1);

  // Both build a commit at epoch 1. Ada's reaches the server first.
  const adaCommit = adaClient.selfUpdate(group);
  const boCommit = boClient.addMember(group, cyClient.generateKeyPackage());
  assert.equal(adaCommit.epoch, 2);
  assert.equal(boCommit.epoch, 2, 'both were built to produce the same epoch');
  assert.equal(boClient.hasPendingCommit(group), true);

  adaClient.mergePendingCommit(group);

  // Bo is refused. Dropping the staged commit is what makes the next line
  // possible at all: OpenMLS will not process an incoming commit over a staged
  // one, and merging it would put Bo on a branch of his own forever.
  boClient.clearPendingCommit(group);
  assert.equal(boClient.hasPendingCommit(group), false);
  assert.equal(boClient.epoch(group), 1, 'still where he started');

  assert.equal(boClient.processCommit(group, adaCommit.commit).kind, 'commit');
  assert.equal(boClient.epoch(group), 2, 'and now in the epoch the group took');
  assert.equal(adaClient.epoch(group), 2);

  // The proof that the two are really one group again: they can still speak.
  const fromAda = adaClient.encrypt(group, enc.encode('after the race'));
  assert.equal(dec.decode(boClient.processMessage(group, fromAda).plaintext), 'after the race');

  // And Bo can try again, now built at epoch 2.
  const retry = boClient.addMember(group, cyClient.generateKeyPackage());
  assert.equal(retry.epoch, 3);
  boClient.mergePendingCommit(group);
  assert.equal(adaClient.processCommit(group, retry.commit).kind, 'commit');
  assert.deepEqual(Array.from(cyClient.joinFromWelcome(retry.welcome)), Array.from(group));
  assert.equal(cyClient.roster(group).length, 3);

  // Clearing nothing is not an error: an error path unwinding should not have
  // to know how far it got before it failed.
  boClient.clearPendingCommit(group);
  assert.throws(() => boClient.mergePendingCommit(group), /no staged commit/);

  for (const c of [adaClient, boClient, cyClient]) c.free();
});

// A MONTH ASLEEP, through the binding the browser actually loads
// (docs/delivery.md §The client contract on `behind_retention`).
//
// The Rust side of this is `mls/core/tests/rejoin.rs`; what cannot be proved
// there is that the three verbs a stale browser needs are reachable from
// JavaScript with the types the client passes them: an epoch as a `number` on
// the way IN (`isBehind` takes the server's `oldest_retained_epoch`, which
// arrives from protobuf as a BigInt the caller has to narrow), a plain boolean
// back, and a `replaceMember` bundle whose Welcome is a Uint8Array rather than
// null.
test('a device past the retention window forgets its group and is replaced back in', () => {
  const iss = issuer();
  const ada = device(iss, 'actor-ada', 'device-ada', 21);
  const bo = device(iss, 'actor-bo', 'device-bo', 22);
  const adaClient = client(iss, ada);
  const boClient = client(iss, bo);

  const group = enc.encode('group-rejoin');
  adaClient.createGroup(group);
  const added = adaClient.addMember(group, boClient.generateKeyPackage());
  adaClient.mergePendingCommit(group);
  boClient.joinFromWelcome(added.welcome);

  // Ada keeps talking for a while. Bo, asleep, misses every one of these.
  for (let i = 0; i < 4; i += 1) {
    const update = adaClient.selfUpdate(group);
    adaClient.mergePendingCommit(group);
    void update;
  }
  assert.equal(adaClient.epoch(group), 5);
  assert.equal(boClient.epoch(group), 1);

  // THE SECOND OPINION. The server says the oldest epoch it still holds is 4;
  // Bo is at 1 and agrees. Ada, at 5, does not — which is the case that stops a
  // delivery service being able to talk every client into forgetting.
  assert.equal(boClient.isBehind(group, 4), true);
  assert.equal(adaClient.isBehind(group, 4), false);
  // The boundary is exclusive: a device AT the oldest retained epoch can still
  // replay from there.
  assert.equal(boClient.isBehind(group, 1), false);
  // And a group this client has never heard of is not one it has fallen behind.
  assert.equal(boClient.isBehind(enc.encode('group-nobody'), 99), false);

  // Bo gives up locally. Nothing about Ada's group changes — this is the one
  // move in the protocol that touches only the device making it.
  boClient.forgetGroup(group);
  // Forgotten means GONE, not "present and inactive": the group has to be
  // absent for the Welcome to be able to create it fresh rather than collide
  // with a stale copy.
  assert.throws(() => boClient.epoch(group), /no such group/i);
  assert.equal(adaClient.roster(group).length, 2, "Bo's leaf is still in Ada's tree");

  // Ada puts Bo back: Remove and Add in ONE commit, which is what mints the
  // Welcome. A fresh key package, because the old leaf's secrets are gone.
  const leaf = adaClient.leafOfDevice(group, 'device-bo');
  const fresh = boClient.generateKeyPackage();
  const replaced = adaClient.replaceMember(group, leaf, fresh);
  assert.ok(replaced.commit instanceof Uint8Array);
  assert.ok(replaced.welcome instanceof Uint8Array, 'a replace ALWAYS carries a Welcome');
  adaClient.mergePendingCommit(group);
  assert.equal(adaClient.roster(group).length, 2, 'still two members, not three');

  const rejoined = boClient.joinFromWelcome(replaced.welcome);
  assert.deepEqual(Array.from(rejoined), Array.from(group));
  assert.equal(boClient.isActive(group), true);
  assert.equal(boClient.epoch(group), adaClient.epoch(group));

  // Sealing resumes in both directions.
  const hello = adaClient.encrypt(group, enc.encode('welcome back'));
  assert.equal(dec.decode(boClient.processMessage(group, hello).plaintext), 'welcome back');
  const reply = boClient.encrypt(group, enc.encode('what did I miss'));
  assert.equal(dec.decode(adaClient.processMessage(group, reply).plaintext), 'what did I miss');

  for (const c of [adaClient, boClient]) c.free();
});

// A COMMIT THIS DEVICE CANNOT APPLY (docs/delivery.md §A commit
// this device cannot apply). The protocol half is `mls/core/tests/stranded.rs`;
// this is the binding the browser loads answering the same question with a
// plain boolean. Only a commit that opened and verified and was then refused
// strands (core: `group_membership_attacks.rs`); everything else, a commit
// that never opened included, is the head check's to judge.
test('commitStrands says which refused entries strand a device and which it can skip', () => {
  const iss = issuer();
  const ada = device(iss, 'actor-ada', 'device-ada-s', 23);
  const bo = device(iss, 'actor-bo', 'device-bo-s', 24);
  const adaClient = client(iss, ada);
  const boClient = client(iss, bo);

  const group = enc.encode('group-stranded');
  adaClient.createGroup(group);
  const added = adaClient.addMember(group, boClient.generateKeyPackage());
  adaClient.mergePendingCommit(group);
  boClient.joinFromWelcome(added.welcome);

  const first = adaClient.selfUpdate(group);
  adaClient.mergePendingCommit(group);
  const second = adaClient.selfUpdate(group);
  adaClient.mergePendingCommit(group);

  // The commit at Bo's own epoch, and one above it: neither has been refused,
  // so neither strands him on its framing's say-so.
  assert.equal(boClient.commitStrands(group, first.commit), false);
  assert.equal(boClient.commitStrands(group, second.commit), false);
  // One that does not open (Bo has not applied `first`) is refused, and still
  // strands nobody: its framing is anyone's to write.
  assert.throws(() => boClient.processCommit(group, second.commit));
  assert.equal(boClient.commitStrands(group, second.commit), false);
  // The add he joined past is a duplicate from an epoch he has left.
  assert.equal(boClient.commitStrands(group, added.commit), false);
  // Once applied, a second delivery of the same commit is skippable.
  boClient.processCommit(group, first.commit);
  assert.equal(boClient.commitStrands(group, first.commit), false);
  // Not a commit, not a message, not a group this device holds.
  assert.equal(boClient.commitStrands(group, adaClient.encrypt(group, enc.encode('hi'))), false);
  assert.equal(boClient.commitStrands(group, enc.encode('garbage')), false);
  assert.equal(boClient.commitStrands(enc.encode('group-nobody'), second.commit), false);

  // A signed seat ask is taken in once; a fresh one is a fresh nonce.
  const proof = boClient.signJoinRequest(group);
  assert.equal(adaClient.joinRequestSeen(group, proof), false);
  assert.equal(adaClient.firstSightOfJoinRequest(group, proof), true);
  assert.equal(adaClient.joinRequestSeen(group, proof), true);
  assert.equal(adaClient.firstSightOfJoinRequest(group, proof), false);
  assert.equal(adaClient.firstSightOfJoinRequest(group, boClient.signJoinRequest(group)), true);
  // No Welcome has been contested.
  assert.equal(boClient.contestedWelcomeGroupId(), undefined);

  for (const c of [adaClient, boClient]) c.free();
});

// docs/identity.md §Refreshing a seated leaf. The client runs on the
// real clock, so this one mints against today rather than NOW.
test('a leaf near expiry renews its credential, and the other member follows', () => {
  const iss = issuer();
  const today = Math.floor(Date.now() / 1000);
  const DAY = 86_400;
  const seed = new Uint8Array(32).fill(21);
  const publicKey = signingKeyPublicKey(seed);
  const mint = (actorId, exp) => iss.issue(actorId, 'device-ada-r', publicKey, today - DAY, exp);

  const adaClient = new MlsClient(
    iss.publishedJson(),
    mint('actor-ada-r', today + 5 * DAY),
    seed,
    heldKey('actor-ada-r'),
  );
  const bo = device(iss, 'actor-bo-r', 'device-bo-r', 22);
  const boClient = client(iss, bo);

  const group = enc.encode('group-credential-refresh');
  adaClient.createGroup(group);
  const added = adaClient.addMember(group, boClient.generateKeyPackage());
  adaClient.mergePendingCommit(group);
  boClient.joinFromWelcome(added.welcome);

  // Expiring, nothing fresher in hand: the cue to call RegisterDevice.
  assert.equal(adaClient.leafCredentialExpiring(group), true);
  assert.equal(adaClient.credentialRefreshDue(group), false);
  assert.equal(adaClient.leafCredentialPastGrace(group), false);
  const before = adaClient.ownLeafCredentialExpiresAt(group);
  assert.equal(typeof before, 'number');
  assert.equal(before, today + 5 * DAY);

  // Somebody else's credential on the same key is refused as a thrown Error
  // naming the policy, not as a malformed token. Minted under Ada's account key,
  // so the seat check answers rather than the account check.
  const eves = iss.issueForAccount(
    'actor-eve-r',
    'device-ada-r',
    publicKey,
    testAccountKey('actor-ada-r'),
    today - DAY,
    today + 30 * DAY,
  );
  assert.throws(
    () => adaClient.updateCredential(eves),
    (err) => err instanceof Error && /update_of_another_leaf|another/i.test(err.message),
  );
  // And an older one is refused too.
  assert.throws(() => adaClient.updateCredential(mint('actor-ada-r', today + 2 * DAY)));
  assert.equal(adaClient.credentialRefreshDue(group), false, 'a refused credential changes nothing');

  adaClient.updateCredential(mint('actor-ada-r', today + 30 * DAY));
  assert.equal(adaClient.credentialRefreshDue(group), true);

  const renewal = adaClient.refreshCredential(group);
  assert.equal(renewal.welcome, null, 'a renewal welcomes nobody');
  assert.ok(renewal.commit instanceof Uint8Array);
  assert.equal(adaClient.mergePendingCommit(group), renewal.epoch);

  const seen = boClient.processCommit(group, renewal.commit);
  assert.equal(seen.kind, 'commit');
  assert.equal(boClient.epoch(group), renewal.epoch);
  assert.equal(adaClient.ownLeafCredentialExpiresAt(group), today + 30 * DAY);
  assert.equal(adaClient.leafCredentialExpiring(group), false);

  const said = adaClient.encrypt(group, enc.encode('renewed'));
  assert.equal(dec.decode(boClient.processMessage(group, said).plaintext), 'renewed');

  for (const c of [adaClient, boClient]) c.free();
});
