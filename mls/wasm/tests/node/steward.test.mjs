// SPDX-License-Identifier: MIT
// The golden steward fixture, replayed through the BUILT wasm package.
//
// `mls/fixtures/steward.json` pins the steward key's statements, the veto
// frame and how it nests around a carried frame, the commit MAC, the sealed
// stamp, the head log copy, the repair notice and the meta's `stw.k`
// (mls/core/src/steward.rs). `mls/core/tests/steward_fixture.rs` replays it in
// Rust; this is the same file through `evaluateFixtureCase`, told apart by
// each case's `kind`.
//
// It also drives the binding's own steward doors, which the web client
// calls: the stamp handed in before a commit and the check taken after it,
// and the hold, inert in a group whose meta names no steward key.
//
// Keep it in step with the three other replays:
// mls/core/tests/steward_fixture.rs,
// mls/swift/Tests/PeachyMLSTests/StewardFixtureTests.swift and
// the Android binding's `StewardFixtureTest` (not in this repository).
//
//   wasm-pack build mls/wasm --target nodejs --dev --out-dir pkg-node -- --features test-issuer,fixture
//   node --test mls/wasm/tests/node/steward.test.mjs

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

const fixture = JSON.parse(readFileSync(resolve(here, '../../../fixtures/steward.json'), 'utf8'));

const FORMAT_VERSION = 1;
const CALLS = [
  'constants',
  'public_key',
  'statement',
  'wrap_veto',
  'split',
  'verify_veto',
  'mac',
  'seal_stamp',
  'open_stamp',
  'seal_log_copy',
  'open_log_copy',
  'repair_notice',
  'meta_key',
];

test('the fixture declares its format and every case its kind', () => {
  assert.equal(fixture.version, FORMAT_VERSION);
  assert.ok(fixture.cases.length >= 30, `only ${fixture.cases.length} cases`);
  for (const testCase of fixture.cases) {
    assert.equal(testCase.kind, 'steward', `case ${testCase.id} has no kind: "steward"`);
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
  assert.deepEqual(failures, [], `${failures.length} steward cases disagree:\n${failures.join('\n')}`);
});

test('the client doors check a stamp, read a veto, and hold nothing unenrolled', () => {
  const NOW = Math.floor(Date.now() / 1000) - 3_600;
  const issuer = new TestIssuer(new Uint8Array(32).fill(7));
  const device = (actorId, deviceId, seedByte) => {
    const seed = new Uint8Array(32).fill(seedByte);
    const token = issuer.issue(actorId, deviceId, signingKeyPublicKey(seed), NOW, NOW + 30 * 86_400);
    return new MlsClient(issuer.publishedJson(), token, seed, accountIdentityPublicKey(testAccountKey(actorId)));
  };
  const ada = device('actor-ada', 'device-ada', 0x11);
  const bo = device('actor-bo', 'device-bo', 0x22);
  const group = new TextEncoder().encode('steward-room');
  ada.createGroup(group);
  const added = ada.addMember(group, bo.generateKeyPackage());
  ada.mergePendingCommit(group);
  bo.joinFromWelcome(added.welcome);

  // No stamp: the check is only absent.
  const update = ada.selfUpdate(group);
  ada.mergePendingCommit(group);
  bo.processCommit(group, update.commit);
  assert.deepEqual(JSON.parse(bo.takeCommitCheck(group)), {
    epoch: 1,
    stamp: 'absent',
    mac: 'unread',
    steward: 'unread',
  });
  assert.equal(bo.takeCommitCheck(group), undefined, 'taken once');

  // A stamp that is not this epoch's: unopened, an alert, and the commit
  // still merges (this build refuses nothing for it).
  const next = ada.selfUpdate(group);
  ada.mergePendingCommit(group);
  bo.noteCommitStamp(group, new Uint8Array(125).fill(1));
  bo.processCommit(group, next.commit);
  assert.equal(JSON.parse(bo.takeCommitCheck(group)).stamp, 'unopened');
  assert.equal(bo.epoch(group), ada.epoch(group));

  // The hold is inert: the meta names no steward key.
  assert.equal(bo.enterHold(group, 1), false);
  assert.equal(bo.groupHold(group), undefined);
  assert.throws(() => bo.enterHold(group, 9));
  bo.releaseHold(group);

  // A plain commit is no veto; a repair notice of an epoch with no verifier
  // kept, or another frame, is nothing to judge.
  assert.equal(bo.judgeVeto(group, next.commit), 0);
  const other = new TextEncoder().encode('{"peachy":"hello","v":1}');
  assert.equal(bo.checkRepairNotice(group, 'actor-ada', other), 2);
  assert.throws(() => bo.openFetchedCommit(group, new Uint8Array(40)));
});
