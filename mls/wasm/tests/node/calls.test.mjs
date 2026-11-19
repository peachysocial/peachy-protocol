// SPDX-License-Identifier: MIT
// The golden calls fixture, replayed through the BUILT wasm package, and a
// call carried between two real clients through the binding's own exports.
//
// `mls/fixtures/calls.json` pins the call key schedule off the MLS exporter,
// the frame key a frame encryptor's key provider derives, the signaling codec and its
// two lanes, ENVELOPE_KIND_CALL, and the ring-state reducer
// (docs/calls.md §Keys, §Signaling, §Ringing; mls/core/src/call/). An
// independent implementation wrote it (a separate Python generator, not in this repository);
// `mls/core/tests/calls_fixture.rs` replays it in Rust.
//
// Keep it in step with the three other replays:
// mls/core/tests/calls_fixture.rs,
// mls/swift/Tests/PeachyMLSTests/CallsFixtureTests.swift and
// the Android binding's `CallsFixtureTest` (not in this repository).
//
//   wasm-pack build mls/wasm --target nodejs --dev --out-dir pkg-node -- --features test-issuer,fixture
//   node --test mls/wasm/tests/node/calls.test.mjs

import test from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { existsSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { testAccountKey } from './test-account.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const pkgDir = resolve(here, '../../pkg-node');
const entry = resolve(pkgDir, 'peachy_mls_wasm.js');

if (!existsSync(entry)) {
  throw new Error(
    `no build at ${pkgDir}. Run:\n` +
      '  wasm-pack build mls/wasm --target nodejs --dev --out-dir pkg-node -- --features test-issuer,fixture',
  );
}

const require = createRequire(import.meta.url);
const {
  evaluateFixtureCase,
  encodeCallSignal,
  decodeCallSignal,
  callSignalIsUrgent,
  callSenderKey,
  callFrameKey,
  callRingStep,
  callSelfUpdateOffsetMs,
  MlsClient,
  TestIssuer,
  signingKeyPublicKey,
  accountIdentityPublicKey,
} = require(entry);

const fixture = JSON.parse(readFileSync(resolve(here, '../../../fixtures/calls.json'), 'utf8'));
const CALLS = ['constants', 'senderKey', 'encode', 'decode', 'sealLive', 'openLive', 'liveReplay', 'envelope', 'ring', 'selfUpdateOffset', 'senderKeyV2', 'mediaAdvance', 'mediaKeyPair', 'openMediaGrant'];

const hex = (bytes) => Buffer.from(bytes).toString('hex');
const unhex = (text) => new Uint8Array(Buffer.from(text, 'hex'));
const utf8 = (text) => new TextEncoder().encode(text);

test('every case gets the verdict it expects, through the fixture door', () => {
  assert.equal(fixture.version, 1);
  assert.ok(fixture.cases.length >= 100, `only ${fixture.cases.length} cases`);
  const ids = new Set();
  const failures = [];
  for (const testCase of fixture.cases) {
    const { id } = testCase;
    assert.ok(!ids.has(id), `two cases share the id ${id}`);
    ids.add(id);
    assert.equal(testCase.kind, 'call', `case ${id}`);
    assert.ok(('expect' in testCase) !== ('expectError' in testCase), `case ${id}: exactly one of expect / expectError`);
    let raw;
    try {
      raw = evaluateFixtureCase(JSON.stringify(testCase));
    } catch (err) {
      if (!('expectError' in testCase)) failures.push(`  ${id}: refused: ${err.message}`);
      else if (!err.message.includes(testCase.expectError)) {
        failures.push(`  ${id}: expected an error with ${JSON.stringify(testCase.expectError)}, got ${err.message}`);
      }
      continue;
    }
    if ('expectError' in testCase) {
      failures.push(`  ${id}: expected an error with ${JSON.stringify(testCase.expectError)}, got ${raw}`);
      continue;
    }
    try {
      assert.deepStrictEqual(JSON.parse(raw), testCase.expect);
    } catch {
      failures.push(`  ${id}\n    expected ${JSON.stringify(testCase.expect)}\n    actual   ${raw}`);
    }
  }
  assert.deepEqual(failures, [], `${failures.length} cases disagree:\n${failures.join('\n')}`);
  const reached = new Set(fixture.cases.map((testCase) => testCase.call));
  assert.deepEqual(CALLS.filter((call) => !reached.has(call)), []);
});

test("the key, codec and ring cases agree through the binding's own exports", () => {
  const failures = [];
  let reached = 0;
  for (const testCase of fixture.cases) {
    const { id, expect, expectError } = testCase;
    let actual;
    try {
      if (testCase.call === 'senderKey') {
        const sender = callSenderKey(unhex(testCase.callRootHex), testCase.leafIndex);
        actual = {
          senderKeyHex: hex(sender),
          keyIndex: testCase.epoch % 256,
          frameKeyHex: hex(callFrameKey(sender)),
        };
      } else if (testCase.call === 'encode') {
        actual = { bytesHex: hex(encodeCallSignal(utf8(JSON.stringify(testCase.signal)))) };
      } else if (testCase.call === 'decode') {
        actual = { signal: JSON.parse(decodeCallSignal(unhex(testCase.bytesHex))) };
      } else if (testCase.call === 'ring') {
        actual = JSON.parse(callRingStep(testCase.state === null ? undefined : JSON.stringify(testCase.state), JSON.stringify(testCase.event)));
      } else {
        continue;
      }
    } catch (err) {
      reached += 1;
      if (expectError === undefined || !err.message.includes(expectError)) {
        failures.push(`  ${id}: threw ${err.message}`);
      }
      continue;
    }
    reached += 1;
    try {
      assert.equal(expectError, undefined, `expected an error with ${expectError}`);
      assert.deepStrictEqual(actual, expect);
    } catch (err) {
      failures.push(`  ${id}: ${err.message}\n    actual ${JSON.stringify(actual)}`);
    }
  }
  assert.ok(reached >= 100, `only ${reached} cases reached the product exports`);
  assert.deepEqual(failures, [], failures.join('\n'));
});

// ---- Two real clients -----------------------------------------------------------

const NOW = Math.floor(Date.now() / 1000) - 3_600;
const LIFETIME = 30 * 86_400;
const GROUP = utf8('peachy-call-group');
const CALL_ID = '00112233445566778899aabbccddeeff';

function member(issuer, tag, actor) {
  const seed = new Uint8Array(32).fill(tag);
  const token = issuer.issue(actor, `${actor}-phone`, signingKeyPublicKey(seed), NOW, NOW + LIFETIME);
  return new MlsClient(issuer.publishedJson(), token, seed, accountIdentityPublicKey(testAccountKey(actor)));
}

function openCall(receiver, envelope) {
  const opened = receiver.openEnvelope(envelope);
  assert.ok(opened, 'the envelope opens');
  assert.equal(opened.kind, 6);
  return JSON.parse(receiver.openCallSignal(GROUP, opened.inner));
}

test('two members derive the same keys and a call round-trips', () => {
  const issuer = new TestIssuer(new Uint8Array(32).fill(97));
  const ada = member(issuer, 81, 'actor-ada');
  const bo = member(issuer, 82, 'actor-bo');
  ada.createGroup(GROUP);
  const bundle = ada.addMember(GROUP, bo.generateKeyPackage());
  ada.mergePendingCommit(GROUP);
  bo.joinFromWelcome(bundle.welcome);

  const a = ada.callKeys(GROUP, unhex(CALL_ID));
  const b = bo.callKeys(GROUP, unhex(CALL_ID));
  assert.deepStrictEqual(a, b);
  assert.equal(a.senders.length, 2);
  assert.equal(a.keyIndex, a.epoch % 256);
  assert.equal(hex(a.callRoot), hex(ada.exportSecret(GROUP, 'peachy call v1', unhex(CALL_ID), 32)));
  for (const sender of a.senders) {
    assert.equal(hex(sender.key), hex(callSenderKey(a.callRoot, sender.leafIndex)));
  }

  const offer = { version: 1, callId: CALL_ID, type: 'offer', media: 'video', ring: true, createdAtMs: 1789516800000 };
  assert.equal(callSignalIsUrgent(utf8(JSON.stringify(offer))), true);
  // A signal is handed over as its JSON's UTF-8 bytes; bytes that are not
  // text are refused by name.
  assert.throws(() => ada.sealCallSignal(GROUP, new Uint8Array([0x7b, 0xff, 0x7d])), /a call signal is not UTF-8/);
  const opened = openCall(bo, ada.sealCallSignal(GROUP, utf8(JSON.stringify(offer))));
  assert.equal(opened.lane, 'mls');
  assert.equal(opened.urgent, true);
  assert.equal(opened.sender.actorId, 'actor-ada');
  assert.deepStrictEqual(opened.signal, offer);

  const media = { version: 1, callId: CALL_ID, type: 'media', audioOn: true, videoOn: false, presenting: false };
  assert.equal(callSignalIsUrgent(utf8(JSON.stringify(media))), false);
  // An in-call control names its sender: it rides the MLS lane, never the live one.
  const control = openCall(ada, bo.sealCallSignal(GROUP, utf8(JSON.stringify(media))));
  assert.equal(control.lane, 'mls');
  assert.equal(control.urgent, false);
  assert.equal(control.sender.actorId, 'actor-bo');
  assert.deepStrictEqual(control.signal, media);

  // A device's own Left goes signed through either door, so every
  // participant that bound it rotates past it.
  const left = { version: 1, callId: CALL_ID, type: 'left', participantId: 'p-bo' };
  const signedLeft = openCall(ada, bo.sealCallSignal(GROUP, utf8(JSON.stringify(left))));
  assert.equal(signedLeft.lane, 'mls');
  assert.equal(signedLeft.sender.actorId, 'actor-bo');
  assert.deepStrictEqual(signedLeft.signal, left);

  // A participant's first Joined goes signed and must name its own leaf (D10).
  const adaLeaf = opened.senderLeaf;
  assert.equal(typeof adaLeaf, 'number');
  const joined = (leafIndex) => ({ version: 1, callId: CALL_ID, type: 'joined', participantId: 'p', sessionId: '', trackNames: [], leafIndex });
  // A keyless Joined from a device that is not a participant is refused:
  // only `start` gives it the call keys a Joined carries.
  assert.throws(() => ada.sealCallSignalSigned(GROUP, utf8(JSON.stringify(joined(adaLeaf)))), /call state lost/);
  assert.throws(() => ada.sealCallSignal(GROUP, utf8(JSON.stringify(joined(adaLeaf)))), /call state lost/);
  assert.throws(() => ada.callMedia(GROUP, JSON.stringify({ op: 'shared', callId: CALL_ID })), /unknown call media op/);
  ada.callMedia(GROUP, JSON.stringify({ op: 'start', callId: CALL_ID, participantId: 'p', sessionId: 's', trackNames: [] }));
  const signed = openCall(bo, ada.sealCallSignalSigned(GROUP, utf8(JSON.stringify(joined(adaLeaf)))));
  assert.equal(signed.lane, 'mls');
  assert.equal(signed.senderLeaf, adaLeaf);
  const forged = bo.openEnvelope(ada.sealCallSignalSigned(GROUP, utf8(JSON.stringify(joined(adaLeaf + 1)))));
  assert.throws(() => bo.openCallSignal(GROUP, forged.inner), /names leaf/);
  assert.equal(callSelfUpdateOffsetMs(1, 4), 150000);

  // A new epoch is a new key ring, and the committer can load it first.
  const update = ada.selfUpdate(GROUP);
  const pending = ada.pendingCallKeys(GROUP, unhex(CALL_ID));
  ada.mergePendingCommit(GROUP);
  bo.processCommit(GROUP, update.commit);
  const next = bo.callKeys(GROUP, unhex(CALL_ID));
  assert.equal(next.epoch, a.epoch + 1);
  assert.equal(hex(next.callRoot), hex(pending.callRoot));
  assert.notEqual(hex(next.callRoot), hex(a.callRoot));
});

test("v2: only participants get each other's media keys, through callMedia", (t) => {
  // The binding times the rotation on the monotonic clock, read through
  // `performance.now()` at each call (the wall clock, `Date.now()`, is left
  // alone: setting it must move nothing), so the rotation delay can pass
  // without waiting for it.
  const realNow = performance.now;
  let ahead = 0;
  performance.now = () => realNow.call(performance) + ahead;
  t.after(() => {
    performance.now = realNow;
  });
  const issuer = new TestIssuer(new Uint8Array(32).fill(98));
  const ada = member(issuer, 83, 'actor-ada');
  const bo = member(issuer, 84, 'actor-bo');
  const cy = member(issuer, 85, 'actor-cy');
  ada.createGroup(GROUP);
  let bundle = ada.addMember(GROUP, bo.generateKeyPackage());
  ada.mergePendingCommit(GROUP);
  bo.joinFromWelcome(bundle.welcome);
  bundle = ada.addMember(GROUP, cy.generateKeyPackage());
  ada.mergePendingCommit(GROUP);
  bo.processCommit(GROUP, bundle.commit);
  cy.joinFromWelcome(bundle.welcome);

  const media = (client, request) => JSON.parse(client.callMedia(GROUP, JSON.stringify({ callId: CALL_ID, ...request })));
  const leafOf = (client) => media(client, { op: 'keys' }).ownLeaf;
  const joined = (participantId, leafIndex, sessionId) => JSON.stringify({ version: 1, callId: CALL_ID, type: 'joined', participantId, sessionId, trackNames: [`${sessionId}-audio`], leafIndex });

  // `start` names the participant id the server's JoinCall answered.
  assert.throws(() => media(ada, { op: 'start', sessionId: 'sess-ada', trackNames: [] }), /participantId/);
  media(ada, { op: 'start', participantId: 'p-ada', sessionId: 'sess-ada', trackNames: ['sess-ada-audio'] });
  const adaLeaf = leafOf(ada);
  const adaJoined = ada.sealCallSignalSigned(GROUP, utf8(joined('p-ada', adaLeaf, 'sess-ada')));
  const seenByCy = openCall(cy, adaJoined);
  assert.equal(seenByCy.signal.sessionId, '', 'the pull capability stays out of a Joined');
  assert.equal(seenByCy.signal.mediaKeyHex.length, 64);
  openCall(bo, adaJoined);

  media(bo, { op: 'start', participantId: 'p-bo', sessionId: 'sess-bo', trackNames: [] });
  const boLeaf = leafOf(bo);
  const boJoined = bo.sealCallSignalSigned(GROUP, utf8(joined('p-bo', boLeaf, 'sess-bo')));
  openCall(cy, boJoined);
  const atAda = openCall(ada, boJoined);
  assert.equal(atAda.send.length, 1, 'Ada grants the newcomer her advanced key');
  for (const envelope of atAda.send) {
    const atBo = openCall(bo, unhex(envelope));
    assert.equal(atBo.media.senderLeaf, adaLeaf);
    assert.equal(atBo.media.sessionId, 'sess-ada');
    assert.equal(openCall(cy, unhex(envelope)).media, null);
  }
  for (const envelope of media(bo, { op: 'share' }).send) {
    assert.equal(openCall(ada, unhex(envelope)).media.sessionId, 'sess-bo');
    assert.equal(openCall(cy, unhex(envelope)).media, null);
  }

  const adaKeys = media(ada, { op: 'keys' });
  const boKeys = media(bo, { op: 'keys' });
  const adaSends = adaKeys.senders.find((k) => k.leafIndex === adaLeaf && k.keyIndex === adaKeys.sendKeyIndex);
  assert.ok(boKeys.senders.some((k) => k.leafIndex === adaLeaf && k.senderKeyHex === adaSends.senderKeyHex));
  assert.ok(adaKeys.participants.some((p) => p.leafIndex === boLeaf && p.keyed));
  assert.throws(() => media(cy, { op: 'keys' }), /call state lost: this device is not in that call/);
  const v1 = cy.callKeys(GROUP, unhex(CALL_ID));
  assert.ok(v1.senders.every((k) => hex(k.key) !== adaSends.senderKeyHex));

  // Bo leaves: his Left goes signed, naming his own participant (the id his
  // Joined bound to his leaf), and Ada rotates.
  const left = openCall(ada, bo.sealCallSignal(GROUP, utf8(JSON.stringify({ version: 1, callId: CALL_ID, type: 'left', participantId: 'p-bo' }))));
  assert.equal(left.lane, 'mls');
  assert.equal(left.unboundLeaf, boLeaf, "the core unbound Bo's own leaf");
  assert.ok(left.applyAfterMs > 0 && left.applyAfterMs <= 5000, 'the open says when the core switches');
  assert.equal(left.applied, false);
  // Asking to apply before the due time changes nothing.
  const early = media(ada, { op: 'apply' });
  assert.equal(early.applied, false);
  assert.ok(early.applyAfterMs > 0 && early.applyAfterMs <= 5000);
  assert.equal(media(ada, { op: 'keys' }).sendKeyIndex, adaKeys.sendKeyIndex);
  // Once it is due, the next door switches by itself and says so, once.
  ahead += 5000;
  const due = media(ada, { op: 'apply' });
  assert.equal(due.applied, true);
  assert.equal(due.applyAfterMs, null);
  assert.equal(media(ada, { op: 'apply' }).applied, false);
  const after = media(ada, { op: 'keys' });
  const rotated = after.senders.find((k) => k.leafIndex === adaLeaf && k.keyIndex === after.sendKeyIndex);
  assert.notEqual(rotated.senderKeyHex, adaSends.senderKeyHex);
  assert.ok(boKeys.senders.every((k) => k.senderKeyHex !== rotated.senderKeyHex));
  assert.ok(after.participants.every((p) => p.leafIndex !== boLeaf));

});

test('v2: a participant a commit removes is rotated past, through callMedia epoch', () => {
  const issuer = new TestIssuer(new Uint8Array(32).fill(97));
  const ada = member(issuer, 86, 'actor-ada');
  const bo = member(issuer, 87, 'actor-bo');
  const cy = member(issuer, 88, 'actor-cy');
  ada.createGroup(GROUP);
  let bundle = ada.addMember(GROUP, bo.generateKeyPackage());
  ada.mergePendingCommit(GROUP);
  bo.joinFromWelcome(bundle.welcome);
  bundle = ada.addMember(GROUP, cy.generateKeyPackage());
  ada.mergePendingCommit(GROUP);
  bo.processCommit(GROUP, bundle.commit);
  cy.joinFromWelcome(bundle.welcome);

  const everyone = [ada, bo, cy];
  const media = (client, request) => JSON.parse(client.callMedia(GROUP, JSON.stringify({ callId: CALL_ID, ...request })));
  const leafOf = (client) => media(client, { op: 'keys' }).ownLeaf;
  const joined = (participantId, leafIndex, sessionId) =>
    JSON.stringify({ version: 1, callId: CALL_ID, type: 'joined', participantId, sessionId, trackNames: [], leafIndex });
  // Every envelope a door or an open owes goes to everyone else, in turn.
  const deliver = (from, envelopes) => {
    for (const envelope of envelopes) {
      for (const client of everyone) {
        if (client !== from) deliver(client, openCall(client, typeof envelope === 'string' ? unhex(envelope) : envelope).send);
      }
    }
  };
  everyone.forEach((client, i) => {
    media(client, { op: 'start', participantId: `p-${i}`, sessionId: `sess-${i}`, trackNames: [] });
    deliver(client, [client.sealCallSignalSigned(GROUP, utf8(joined(`p-${i}`, leafOf(client), `sess-${i}`)))]);
    deliver(client, media(client, { op: 'share' }).send);
  });
  const adaLeaf = leafOf(ada);
  const cyLeaf = leafOf(cy);
  assert.equal(media(ada, { op: 'epoch' }).applyAfterMs, null, 'nobody was removed, so nothing rotates');

  // A commit removes Cy; nobody hears a Left.
  const removal = ada.removeMember(GROUP, cyLeaf, ada.roster(GROUP).find((e) => e.leafIndex === cyLeaf).leafKey);
  ada.mergePendingCommit(GROUP);
  bo.processCommit(GROUP, removal.commit);

  const rotation = media(ada, { op: 'epoch' });
  assert.ok(rotation.applyAfterMs > 0 && rotation.applyAfterMs <= 5000, `${rotation.applyAfterMs}`);
  assert.equal(rotation.send.length, 1, 'one grant, to Bo');
  const atBo = openCall(bo, unhex(rotation.send[0]));
  assert.equal(atBo.media.senderLeaf, adaLeaf);
  assert.equal(atBo.signal.rotated, true);
  const again = media(ada, { op: 'epoch' });
  assert.equal(again.send.length, 0, 'one rotation per removal');
  assert.ok(again.applyAfterMs !== null && again.applyAfterMs <= rotation.applyAfterMs, 'the due time stands');
  assert.ok(media(ada, { op: 'keys' }).participants.every((p) => p.leafIndex !== cyLeaf));
});
