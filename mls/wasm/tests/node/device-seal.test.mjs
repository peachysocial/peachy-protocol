// SPDX-License-Identifier: MIT
// The golden device-seal fixture, replayed through the BUILT wasm package.
//
// `mls/fixtures/device-seal.json` pins the device seal
// (mls/core/src/device_seal.rs): its bytes for given inputs, what opens and
// what is refused, and that no build SENDS it (`DEVICE_SEAL_SENDS` is false).
// `mls/core/tests/device_seal_fixture.rs` replays it in Rust; this is the same
// file through `evaluateFixtureCase`, told apart by each case's `kind`.
//
// It also drives the binding's OWN door, which the web client calls and the
// fixture door does not reach: `MlsClient.holdEnvelope` takes a seal beside an
// envelope that opens for no group here, keeps it, and hands it out once the
// copy is past the message's epoch, opening on the secret the seal carried.
//
// Keep it in step with the three other replays:
// mls/core/tests/device_seal_fixture.rs,
// mls/swift/Tests/PeachyMLSTests/DeviceSealFixtureTests.swift and
// the Android binding's `DeviceSealFixtureTest` (not in this repository).
//
//   wasm-pack build mls/wasm --target nodejs --dev --out-dir pkg-node -- --features test-issuer,fixture
//   node --test mls/wasm/tests/node/device-seal.test.mjs

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
const { evaluateFixtureCase, signingKeyPublicKey, accountIdentityPublicKey, MlsClient, TestIssuer } =
  require(entry);

const fixture = JSON.parse(readFileSync(resolve(here, '../../../fixtures/device-seal.json'), 'utf8'));

const FORMAT_VERSION = 1;
const CALLS = ['constants', 'seal', 'open'];
const hex = (bytes) => Buffer.from(bytes).toString('hex');
const unhex = (text) => new Uint8Array(Buffer.from(text, 'hex'));
const door = (testCase) => JSON.parse(evaluateFixtureCase(JSON.stringify(testCase)));

test('the fixture declares its format and every case its kind', () => {
  assert.equal(fixture.version, FORMAT_VERSION);
  assert.ok(fixture.cases.length >= 20, `only ${fixture.cases.length} cases`);
  for (const testCase of fixture.cases) {
    assert.equal(testCase.kind, 'device_seal', `case ${testCase.id} has no kind: "device_seal"`);
    assert.equal(typeof testCase.expect, 'object', `case ${testCase.id} has no \`expect\``);
  }
  const calls = new Set(fixture.cases.map((c) => c.call));
  for (const call of CALLS) assert.ok(calls.has(call), `no case calls ${call}`);
});

test('every case gets the verdict it expects, through the wasm door', () => {
  const failures = [];
  const ids = new Set();
  for (const testCase of fixture.cases) {
    const id = testCase.id;
    assert.ok(!ids.has(id), `two cases share the id ${id}`);
    ids.add(id);
    let raw;
    try {
      raw = evaluateFixtureCase(JSON.stringify(testCase));
    } catch (err) {
      failures.push(`  ${id}\n    refused: ${err.message}`);
      continue;
    }
    assert.equal(typeof raw, 'string');
    try {
      assert.deepStrictEqual(JSON.parse(raw), testCase.expect);
    } catch {
      failures.push(`  ${id}\n    expected ${JSON.stringify(testCase.expect)}\n    actual   ${raw}`);
    }
  }
  assert.deepEqual(failures, [], `${failures.length} device-seal cases disagree:\n${failures.join('\n')}`);
});

test('the client door keeps a sealed envelope and opens it once the copy is past its epoch', () => {
  const NOW = Math.floor(Date.now() / 1000) - 3_600;
  const issuer = new TestIssuer(new Uint8Array(32).fill(7));
  const adaSeed = new Uint8Array(32).fill(0x11);
  const boSeed = new Uint8Array(32).fill(0x22);
  const device = (actorId, deviceId, seed) => {
    const token = issuer.issue(actorId, deviceId, signingKeyPublicKey(seed), NOW, NOW + 30 * 86_400);
    return new MlsClient(issuer.publishedJson(), token, seed, accountIdentityPublicKey(testAccountKey(actorId)));
  };
  const ada = device('actor-ada', 'device-ada', adaSeed);
  const bo = device('actor-bo', 'device-bo', boSeed);
  const group = new TextEncoder().encode('device-seal-room');
  ada.createGroup(group);
  const added = ada.addMember(group, bo.generateKeyPackage());
  ada.mergePendingCommit(group);
  bo.joinFromWelcome(added.welcome);

  // Ada's message, in an envelope keyed by a secret Bo's copy never held,
  // with Ada's seal for Bo carrying it.
  const message = ada.encrypt(group, new TextEncoder().encode('missed'));
  const secret = new Uint8Array(32).fill(0x5a);
  const envelope = unhex(
    door({
      kind: 'roster',
      call: 'seal',
      epochSecretHex: hex(secret),
      envelopeKind: 1,
      innerHex: hex(message),
      nonceHex: '000102030405060708090a0b',
    }).envelopeHex,
  );
  const seal = unhex(
    door({
      kind: 'device_seal',
      call: 'seal',
      senderSeedHex: hex(adaSeed),
      recipientKeyHex: hex(signingKeyPublicKey(boSeed)),
      groupIdHex: hex(group),
      epochSecretHex: hex(secret),
      envelopeHex: hex(envelope),
      ephemeralHex: hex(new Uint8Array(32).fill(0x42)),
    }).sealHex,
  );
  assert.equal(seal.length, 226);
  assert.equal(bo.openEnvelope(envelope), undefined, 'opens for nothing Bo holds');
  assert.equal(bo.holdEnvelope(1, 'env-sealed', Date.now(), envelope, seal), 1, 'kept');
  assert.equal(bo.nextReopenable(), undefined, "Bo's copy is at the message's epoch: it waits");

  const update = ada.selfUpdate(group);
  ada.mergePendingCommit(group);
  bo.processCommit(group, update.commit);
  const held = bo.nextReopenable();
  assert.ok(held, "handed out once Bo's copy is past the message's epoch");
  assert.equal(held.id, 'env-sealed');
  const opened = bo.openEnvelope(held.envelope);
  assert.ok(opened, 'opens on the secret the seal carried');
  assert.deepEqual(Array.from(opened.groupId), Array.from(group));
  assert.equal(opened.kind, 1);
  assert.deepEqual(Array.from(opened.inner), Array.from(message));
  assert.equal(bo.nextReopenable(), undefined, 'handed out once a pass');
  // From a leaf of Bo's copy: taken through as any envelope, naming nobody.
  assert.deepEqual(bo.heldDisposition('env-sealed'), { fate: 0 });
  // Kept, and still granted, until released; released, the grant is spent.
  assert.ok(bo.openEnvelope(held.envelope), 'still granted before the release');
  assert.equal(bo.releaseHeld('env-sealed'), true);
  assert.equal(bo.openEnvelope(held.envelope), undefined, 'the release spends the grant');
  assert.equal(bo.nextReopenable(), undefined);

  // No seal, or one that does not open: held as before, and never granted.
  const other = unhex(
    door({
      kind: 'roster',
      call: 'seal',
      epochSecretHex: hex(new Uint8Array(32).fill(0x6b)),
      envelopeKind: 1,
      innerHex: hex(ada.encrypt(group, new TextEncoder().encode('unsealed'))),
      nonceHex: '0c0d0e0f1011121314151617',
    }).envelopeHex,
  );
  assert.equal(bo.holdEnvelope(1, 'env-plain', Date.now(), other), 1, 'kept');
  // The same bytes again, under a new id and a seal that does not open: held
  // once.
  assert.equal(bo.holdEnvelope(1, 'env-garbled', Date.now(), other, new Uint8Array(226).fill(1)), 0, 'not kept');
  assert.equal(bo.nextReopenable(), undefined);
  assert.equal(bo.heldDisposition('env-plain'), undefined, 'handed out on no seal');
  ada.free();
  bo.free();
});
