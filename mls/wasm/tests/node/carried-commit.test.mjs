// SPDX-License-Identifier: MIT
// The golden carried-commit fixture, replayed through the BUILT wasm package.
//
// `mls/fixtures/carried-commit.json` pins the carried commit
// (mls/core/src/carried_commit.rs): its bytes, what a reader accepts and
// refuses, and the frame's constants.
// `mls/core/tests/carried_commit_fixture.rs` replays it in Rust; this is the
// same file through `evaluateFixtureCase`, told apart by each case's `kind`.
//
// It also drives the binding's OWN leave doors, which the web client calls:
// `beginLeave` proposes and keeps a stub, `followLeave` proposes again after
// a commit that took the epoch, and the commit that lands ends the leave.
//
// Keep it in step with the three other replays:
// mls/core/tests/carried_commit_fixture.rs,
// mls/swift/Tests/PeachyMLSTests/CarriedCommitFixtureTests.swift and
// the Android binding's `CarriedCommitFixtureTest` (not in this repository).
//
//   wasm-pack build mls/wasm --target nodejs --dev --out-dir pkg-node -- --features test-issuer,fixture
//   node --test mls/wasm/tests/node/carried-commit.test.mjs

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

const fixture = JSON.parse(readFileSync(resolve(here, '../../../fixtures/carried-commit.json'), 'utf8'));

const FORMAT_VERSION = 1;
const CALLS = ['constants', 'carry', 'split'];

test('the fixture declares its format and every case its kind', () => {
  assert.equal(fixture.version, FORMAT_VERSION);
  assert.ok(fixture.cases.length >= 20, `only ${fixture.cases.length} cases`);
  for (const testCase of fixture.cases) {
    assert.equal(testCase.kind, 'carried_commit', `case ${testCase.id} has no kind: "carried_commit"`);
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
  assert.deepEqual(failures, [], `${failures.length} carried-commit cases disagree:\n${failures.join('\n')}`);
});

test('the client doors keep a leave proposing until it takes', () => {
  const NOW = Math.floor(Date.now() / 1000) - 3_600;
  const issuer = new TestIssuer(new Uint8Array(32).fill(7));
  const device = (actorId, deviceId, seedByte) => {
    const seed = new Uint8Array(32).fill(seedByte);
    const token = issuer.issue(actorId, deviceId, signingKeyPublicKey(seed), NOW, NOW + 30 * 86_400);
    return new MlsClient(issuer.publishedJson(), token, seed, accountIdentityPublicKey(testAccountKey(actorId)));
  };
  const ada = device('actor-ada', 'device-ada', 0x11);
  const bo = device('actor-bo', 'device-bo', 0x22);
  const cy = device('actor-cy', 'device-cy', 0x33);
  const group = new TextEncoder().encode('carried-commit-room');
  ada.createGroup(group);
  for (const [joiner, followers] of [
    [bo, []],
    [cy, [bo]],
  ]) {
    const added = ada.addMember(group, joiner.generateKeyPackage());
    ada.mergePendingCommit(group);
    for (const follower of followers) follower.processCommit(group, added.commit);
    joiner.joinFromWelcome(added.welcome);
  }

  const first = bo.beginLeave(group);
  assert.equal(first.length, 1, "one proposal for Bo's one leaf");
  assert.ok(first[0] instanceof Uint8Array);
  assert.equal(bo.isLeaving(group), true);
  assert.equal(bo.groupIds().length, 0, 'the stub is in no listing');
  assert.equal(bo.beginLeave(group).length, 0, 'a second call proposes nothing');
  assert.deepEqual(
    bo
      .leaveRecipients(group)
      .map((r) => r.deviceId)
      .sort(),
    ['device-ada', 'device-bo', 'device-cy'],
    'the leave is still addressed to every leaf',
  );

  // Ada's update takes the epoch first; Bo's stub proposes again.
  const update = ada.selfUpdate(group);
  ada.mergePendingCommit(group);
  cy.processCommit(group, update.commit);
  const again = bo.followLeave(group, update.commit);
  assert.equal(again.length, 1, 'proposed again at the new epoch');

  // Every member queues the proposal itself as well; the carried commit
  // brings it to any member it never reached.
  const queued = cy.processMessage(group, again[0]);
  assert.equal(queued.kind, 'proposal');
  assert.equal(ada.processMessage(group, again[0]).kind, 'proposal');
  const leave = cy.commitProposedLeaves(group);
  assert.ok(leave);
  cy.mergePendingCommit(group);
  const seen = ada.processCommit(group, leave.commit);
  assert.deepEqual(seen.left, ['actor-bo']);

  assert.equal(bo.followLeave(group, leave.commit).length, 0);
  assert.equal(bo.isLeaving(group), false, 'the leave took');
});
