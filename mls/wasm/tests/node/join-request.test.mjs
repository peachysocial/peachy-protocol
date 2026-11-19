// SPDX-License-Identifier: MIT
// The golden join-request fixture, replayed through the BUILT wasm package.
//
// `mls/fixtures/join-request.json` pins what a device signs to ask for a seat
// in a group, and what an admitting device decides about it
// (mls/core/src/join_request.rs). `mls/core/tests/join_request_fixture.rs`
// replays it in Rust; this is the same file through `evaluateFixtureCase`, the
// door the other tables use, told apart by each case's `kind`.
//
// It also drives the binding's OWN exports, which the web client calls and the
// fixture door does not reach: `MlsClient.signJoinRequest` and
// `MlsClient.verifyJoinRequest`.
//
// Keep it in step with the three other replays:
// mls/core/tests/join_request_fixture.rs,
// mls/swift/Tests/PeachyMLSTests/JoinRequestFixtureTests.swift and
// the Android binding's `JoinRequestFixtureTest` (not in this repository).
//
//   wasm-pack build mls/wasm --target nodejs --dev --out-dir pkg-node -- --features test-issuer,fixture
//   node --test mls/wasm/tests/node/join-request.test.mjs

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

const fixture = JSON.parse(readFileSync(resolve(here, '../../../fixtures/join-request.json'), 'utf8'));

const FORMAT_VERSION = 1;
const CALLS = ['statement', 'sign', 'verify', 'roundTrip'];
const VERDICTS = [
  'accepted',
  'malformed',
  'credential_rejected',
  'identity_mismatch',
  'bad_signature',
  'stale',
  'from_the_future',
  'not_a_member',
];

test('the fixture declares its format and every case its kind', () => {
  assert.equal(fixture.version, FORMAT_VERSION);
  assert.ok(fixture.cases.length >= 28, `only ${fixture.cases.length} cases`);
  for (const testCase of fixture.cases) {
    assert.equal(testCase.kind, 'join_request', `case ${testCase.id} has no kind: "join_request"`);
    assert.notEqual(
      testCase.expect === undefined,
      testCase.expectError === undefined,
      `case ${testCase.id} needs exactly one of \`expect\` and \`expectError\``,
    );
  }
});

test('every case gets the verdict it expects, through the wasm door', () => {
  const failures = [];
  const ids = new Set();
  for (const testCase of fixture.cases) {
    const id = testCase.id;
    assert.ok(!ids.has(id), `two cases share the id ${id}`);
    ids.add(id);
    const json = JSON.stringify(testCase);
    if (testCase.expectError !== undefined) {
      try {
        failures.push(`  ${id}\n    expected a refusal, got ${evaluateFixtureCase(json)}`);
      } catch (err) {
        if (!(err instanceof Error) || !err.message.includes(testCase.expectError)) {
          failures.push(`  ${id}\n    expected a refusal naming ${testCase.expectError}, got ${err}`);
        }
      }
      continue;
    }
    let raw;
    try {
      raw = evaluateFixtureCase(json);
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
  assert.deepEqual(failures, [], `${failures.length} join-request cases disagree:\n${failures.join('\n')}`);
});

test('every call and every verdict is reached, with its true number', () => {
  const calls = new Set(fixture.cases.map((c) => c.call));
  for (const call of CALLS) assert.ok(calls.has(call), `no case calls ${call}`);
  const reached = new Set();
  for (const testCase of fixture.cases) {
    const verdict = testCase.expect?.verdict;
    if (verdict === undefined) continue;
    assert.equal(VERDICTS[testCase.expect.verdictCode], verdict, `case ${testCase.id} names the wrong number`);
    reached.add(verdict);
  }
  for (const verdict of VERDICTS) assert.ok(reached.has(verdict), `no case reaches ${verdict}`);
});

test('the client doors sign and verify, and a member cannot sign for somebody else', () => {
  const NOW = Math.floor(Date.now() / 1000) - 3_600;
  const issuer = new TestIssuer(new Uint8Array(32).fill(7));
  const device = (actorId, deviceId, seedByte) => {
    const seed = new Uint8Array(32).fill(seedByte);
    const token = issuer.issue(actorId, deviceId, signingKeyPublicKey(seed), NOW, NOW + 30 * 86_400);
    return new MlsClient(issuer.publishedJson(), token, seed, accountIdentityPublicKey(testAccountKey(actorId)));
  };
  const ada = device('actor-ada', 'device-ada-phone', 0x11);
  const mallory = device('actor-mallory', 'device-mallory-phone', 0x22);
  const bob = device('actor-bob', 'device-bob-phone', 0x33);
  const room = new TextEncoder().encode('room-1');
  const adaPackage = ada.generateKeyPackage();

  // Bob holds no copy of the room: Ada is somebody he is adding.
  const pending = ['actor-ada'];
  const honest = ada.signJoinRequest(room);
  assert.ok(honest instanceof Uint8Array);
  assert.equal(honest.length, 89);
  assert.deepEqual(bob.verifyJoinRequest(room, 'actor-ada', 'device-ada-phone', honest, adaPackage, pending), {
    code: 0,
    name: 'accepted',
  });
  const forged = mallory.signJoinRequest(room);
  assert.deepEqual(bob.verifyJoinRequest(room, 'actor-ada', 'device-ada-phone', forged, adaPackage, pending), {
    code: 4,
    name: 'bad_signature',
  });
  const otherRoom = new TextEncoder().encode('room-2');
  assert.equal(bob.verifyJoinRequest(otherRoom, 'actor-ada', 'device-ada-phone', honest, adaPackage, pending).code, 4);
  assert.equal(bob.verifyJoinRequest(room, 'actor-ada', 'device-ada-phone', new Uint8Array(0), adaPackage, pending).code, 1);
  assert.equal(bob.verifyJoinRequest(room, 'actor-ada', 'device-ada-phone', honest, new Uint8Array([1, 2]), pending).code, 2);
  // A signed ask proves who is asking, never that they belong.
  assert.deepEqual(bob.verifyJoinRequest(room, 'actor-ada', 'device-ada-phone', honest, adaPackage, []), {
    code: 7,
    name: 'not_a_member',
  });
  // A person Bob admits by his own rule (a link, an open group's join inbox):
  // every check but membership.
  assert.deepEqual(bob.verifyAdmittedJoinRequest(room, 'actor-ada', 'device-ada-phone', honest, adaPackage), {
    code: 0,
    name: 'accepted',
  });
  assert.equal(bob.verifyAdmittedJoinRequest(room, 'actor-ada', 'device-ada-phone', forged, adaPackage).code, 4);
  assert.equal(bob.verifyAdmittedJoinRequest(otherRoom, 'actor-ada', 'device-ada-phone', honest, adaPackage).code, 4);
});
