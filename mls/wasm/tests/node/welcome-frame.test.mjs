// SPDX-License-Identifier: MIT
// The golden Welcome-frame fixture, replayed through the BUILT wasm package.
//
// `mls/fixtures/welcome-frame.json` pins the padded Welcome frame
// (mls/core/src/welcome_frame.rs): its bytes, its target's rounding, what a
// reader accepts and refuses: every add and reseat is sent framed. `mls/core/tests/welcome_frame_fixture.rs` replays it in
// Rust; this is the same file through `evaluateFixtureCase`, told apart by each
// case's `kind`.
//
// It also drives the binding's OWN door, which the web client calls and the
// fixture door does not reach: `MlsClient.joinFromWelcome` takes a framed
// real Welcome and seats its joiner, and refuses a frame with stray fill.
//
// Keep it in step with the three other replays:
// mls/core/tests/welcome_frame_fixture.rs,
// mls/swift/Tests/PeachyMLSTests/WelcomeFrameFixtureTests.swift and
// the Android binding's `WelcomeFrameFixtureTest` (not in this repository).
//
//   wasm-pack build mls/wasm --target nodejs --dev --out-dir pkg-node -- --features test-issuer,fixture
//   node --test mls/wasm/tests/node/welcome-frame.test.mjs

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

const fixture = JSON.parse(readFileSync(resolve(here, '../../../fixtures/welcome-frame.json'), 'utf8'));

const FORMAT_VERSION = 1;
const CALLS = ['constants', 'frame', 'paddedLen', 'unframe', 'sealGap', 'openGap'];

test('the fixture declares its format and every case its kind', () => {
  assert.equal(fixture.version, FORMAT_VERSION);
  assert.ok(fixture.cases.length >= 20, `only ${fixture.cases.length} cases`);
  for (const testCase of fixture.cases) {
    assert.equal(testCase.kind, 'welcome_frame', `case ${testCase.id} has no kind: "welcome_frame"`);
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
  assert.deepEqual(failures, [], `${failures.length} welcome-frame cases disagree:\n${failures.join('\n')}`);
});

test('the client door seats a joiner from a framed real Welcome', () => {
  const NOW = Math.floor(Date.now() / 1000) - 3_600;
  const issuer = new TestIssuer(new Uint8Array(32).fill(7));
  const device = (actorId, deviceId, seedByte) => {
    const seed = new Uint8Array(32).fill(seedByte);
    const token = issuer.issue(actorId, deviceId, signingKeyPublicKey(seed), NOW, NOW + 30 * 86_400);
    return new MlsClient(issuer.publishedJson(), token, seed, accountIdentityPublicKey(testAccountKey(actorId)));
  };
  const ada = device('actor-ada', 'device-ada', 0x11);
  const bo = device('actor-bo', 'device-bo', 0x22);
  const group = new TextEncoder().encode('welcome-frame-room');
  ada.createGroup(group);
  const added = ada.addMember(group, bo.generateKeyPackage());
  ada.mergePendingCommit(group);
  assert.ok(added.welcome instanceof Uint8Array);
  // Bo's package reads the frame, so the Welcome comes framed; take the raw
  // Welcome out of it and frame it again with fill of our own.
  assert.deepEqual(Array.from(added.welcome.slice(0, 4)), [0xff, 0x50, 0x57, 0x01]);
  const opened = JSON.parse(
    evaluateFixtureCase(
      JSON.stringify({
        kind: 'welcome_frame',
        call: 'unframe',
        bytesHex: Buffer.from(added.welcome).toString('hex'),
      }),
    ),
  );
  assert.equal(opened.accepted, true);
  const raw = new Uint8Array(Buffer.from(opened.welcomeHex, 'hex'));

  const answer = JSON.parse(
    evaluateFixtureCase(
      JSON.stringify({
        kind: 'welcome_frame',
        call: 'frame',
        welcomeHex: Buffer.from(raw).toString('hex'),
        paddedLen: raw.length + 1024,
      }),
    ),
  );
  const framed = new Uint8Array(Buffer.from(answer.framedHex, 'hex'));
  assert.equal(framed.length, raw.length + 1024);

  assert.deepEqual(Array.from(bo.joinFromWelcome(framed)), Array.from(group));
  const heard = bo.processMessage(group, ada.encrypt(group, new TextEncoder().encode('hello')));
  assert.equal(new TextDecoder().decode(heard.plaintext), 'hello');

  // A refused frame spends its key package, so the stray one goes last.
  const stray = framed.slice();
  stray[stray.length - 1] = 1;
  assert.throws(() => bo.joinFromWelcome(stray));
});
