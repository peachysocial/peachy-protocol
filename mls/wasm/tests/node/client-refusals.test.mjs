// SPDX-License-Identifier: MIT
// The golden client-refusals fixture, replayed through the BUILT wasm package.
//
// `mls/fixtures/client-refusals.json` lists every refusal the delivery service
// can switch on, with this build's compiled default, and pins the one-way rule
// (mls/core/src/client_refusals.rs). `mls/core/tests/client_refusals_fixture.rs`
// replays it in Rust; this is the same file through `evaluateFixtureCase`.
//
// It also drives the binding's OWN door, which the web client calls:
// `MlsClient.adoptClientRefusals` switches `signed_revocations` on for a
// client, which then keeps a sibling leaf the server named, and keeps it after
// a list that leaves the name out.
//
// Keep it in step with the three other replays:
// mls/core/tests/client_refusals_fixture.rs,
// mls/swift/Tests/PeachyMLSTests/ClientRefusalsFixtureTests.swift and
// the Android binding's `ClientRefusalsFixtureTest` (not in this repository).
//
//   wasm-pack build mls/wasm --target nodejs --dev --out-dir pkg-node -- --features test-issuer,fixture
//   node --test mls/wasm/tests/node/client-refusals.test.mjs

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

const fixture = JSON.parse(readFileSync(resolve(here, '../../../fixtures/client-refusals.json'), 'utf8'));

test('every case gets the verdict it expects, through the wasm door', () => {
  assert.equal(fixture.version, 1);
  const calls = new Set(fixture.cases.map((c) => c.call));
  for (const call of ['table', 'ratchet', 'on']) assert.ok(calls.has(call), `no case calls ${call}`);
  const failures = [];
  for (const testCase of fixture.cases) {
    assert.equal(testCase.kind, 'client_refusals', `case ${testCase.id}`);
    const raw = evaluateFixtureCase(JSON.stringify(testCase));
    try {
      assert.deepStrictEqual(JSON.parse(raw), testCase.expect);
    } catch {
      failures.push(`  ${testCase.id}\n    expected ${JSON.stringify(testCase.expect)}\n    actual   ${raw}`);
    }
  }
  assert.deepEqual(failures, [], `${failures.length} client-refusals cases disagree:\n${failures.join('\n')}`);
});

test('a switched-on signed_revocations keeps a sibling leaf, and stays on', () => {
  const NOW = Math.floor(Date.now() / 1000) - 3_600;
  const issuer = new TestIssuer(new Uint8Array(32).fill(7));
  const device = (actorId, deviceId, tag) => {
    const seed = new Uint8Array(32).fill(tag);
    const token = issuer.issue(actorId, deviceId, signingKeyPublicKey(seed), NOW, NOW + 30 * 86_400);
    return new MlsClient(issuer.publishedJson(), token, seed, accountIdentityPublicKey(testAccountKey(actorId)));
  };
  const bo = device('actor-bo', 'device-bo', 0x22);
  const laptop = device('actor-ada', 'device-ada-laptop', 0x11);
  const phone = device('actor-ada', 'device-ada-phone', 0x12);
  const group = new TextEncoder().encode('client-refusals-room');
  bo.createGroup(group);
  for (const joiner of [laptop, phone]) {
    const added = bo.addMember(group, joiner.generateKeyPackage());
    bo.mergePendingCommit(group);
    joiner.joinFromWelcome(added.welcome);
  }
  const phoneLeaf = 2;
  const compiled = fixture.refusals.find((r) => r.name === 'signed_revocations').compiledDefault;
  assert.equal(bo.staleLeafRemovable(group, phoneLeaf, new Uint8Array()), !compiled, 'the sibling rule');
  bo.adoptClientRefusals('no_such_refusal');
  assert.equal(bo.staleLeafRemovable(group, phoneLeaf, new Uint8Array()), !compiled, 'unknown: ignored');
  bo.adoptClientRefusals('own_seat_check, signed_revocations');
  assert.equal(bo.staleLeafRemovable(group, phoneLeaf, new Uint8Array()), false, 'on at once');
  bo.adoptClientRefusals('');
  assert.equal(bo.staleLeafRemovable(group, phoneLeaf, new Uint8Array()), false, 'a list without it changes nothing');
  bo.free();
  laptop.free();
  phone.free();
});
