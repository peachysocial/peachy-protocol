// SPDX-License-Identifier: MIT
// The golden rosters fixture, replayed through the BUILT wasm package.
//
// `mls/fixtures/rosters.json` pins a member-rostered conversation's handle,
// the envelope that hides which conversation a sealed byte belongs to, and the
// group policy every member's device enforces (mls/core/src/envelope.rs and
// mls/core/src/policy.rs are the reading guide). An independent implementation
// wrote it; `mls/core/tests/rosters_fixture.rs` replays it in Rust. This is
// the same file through the wasm binding, twice over:
//
//  1. through `evaluateFixtureCase`, the door every fixture replay shares, told
//     by `kind: "roster"` which table it is reading; and
//  2. through the binding's OWN exports — `groupHandle`, `sealEnvelope` and
//     `MlsClient.openEnvelope` — which are what the web client calls, and
//     which the fixture door does not reach. The product seal draws a random
//     nonce, so a seal case is checked there by opening what it sealed; the
//     fixture door's deterministic bytes are (1)'s job. A case keyed by an
//     epoch secret (`epochSecretHex`, `epochSecretsHex`: version 3) names a
//     secret only a group's epoch derives, which no product export takes: the
//     product seal skips it, and the product open, holding the case's group
//     ids alone, must open nothing.
//
// Keep it in step with the three other replays:
// mls/core/tests/rosters_fixture.rs,
// mls/swift/Tests/PeachyMLSTests/RostersFixtureTests.swift and
// the Android binding's `RostersFixtureTest` (not in this repository).
//
// Run it against a nodejs-target build with both test features on:
//
//   wasm-pack build mls/wasm --target nodejs --dev --out-dir pkg-node -- --features test-issuer,fixture
//   node --test mls/wasm/tests/node/rosters.test.mjs

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
  groupHandle,
  sealEnvelope,
  MlsClient,
  TestIssuer,
  signingKeyPublicKey,
  accountIdentityPublicKey,
} = require(entry);

const fixturePath = resolve(here, '../../../fixtures/rosters.json');
const fixture = JSON.parse(readFileSync(fixturePath, 'utf8'));

const FORMAT_VERSION = 1;
const CALLS = ['handle', 'seal', 'open', 'judge'];

const hex = (bytes) => Buffer.from(bytes).toString('hex');
const unhex = (text) => new Uint8Array(Buffer.from(text, 'hex'));
const utf8 = (text) => new TextEncoder().encode(text);

// As journey.test.mjs: around today, since the binding reads the wall clock,
// and for the issuer's real thirty days.
const NOW = Math.floor(Date.now() / 1000) - 3_600;
const LIFETIME = 30 * 86_400;

let nextTag = 60;

/** A client holding exactly `groupIds` (strings), each as a group of one. */
function clientHolding(groupIds) {
  const issuer = new TestIssuer(new Uint8Array(32).fill(97));
  const tag = nextTag++;
  const seed = new Uint8Array(32).fill(tag);
  const token = issuer.issue('actor-rosters', `rosters-${tag}`, signingKeyPublicKey(seed), NOW, NOW + LIFETIME);
  const held = accountIdentityPublicKey(testAccountKey('actor-rosters'));
  const client = new MlsClient(issuer.publishedJson(), token, seed, held);
  for (const groupId of groupIds) client.createGroup(utf8(groupId));
  return client;
}

/** `openEnvelope`'s answer in the fixture's `expect` shape. */
function asVerdict(opened) {
  if (opened === undefined) return { opened: false };
  return {
    opened: true,
    groupId: new TextDecoder().decode(opened.groupId),
    envelopeKind: opened.kind,
    innerHex: hex(opened.inner),
  };
}

test('the package exports the fixture door and the three envelope functions', () => {
  assert.equal(typeof evaluateFixtureCase, 'function');
  assert.equal(typeof groupHandle, 'function');
  assert.equal(typeof sealEnvelope, 'function');
  assert.equal(typeof MlsClient.prototype.openEnvelope, 'function');
  assert.equal(fixture.version, FORMAT_VERSION);
  assert.ok(fixture.cases.length >= 30, `only ${fixture.cases.length} cases`);
  for (const testCase of fixture.cases) {
    assert.equal(testCase.kind, 'roster', `case ${testCase.id}`);
    assert.equal(typeof testCase.expect, 'object', `case ${testCase.id} has no \`expect\``);
  }
});

test('every case gets the verdict it expects, through the fixture door', () => {
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
      failures.push(`  ${id}\n    expected ${JSON.stringify(testCase.expect)}\n    actual   refused: ${err.message}`);
      continue;
    }
    assert.equal(typeof raw, 'string', `case ${id}: a verdict crosses as a string`);
    try {
      assert.deepStrictEqual(JSON.parse(raw), testCase.expect);
    } catch {
      failures.push(`  ${id}\n    expected ${JSON.stringify(testCase.expect)}\n    actual   ${raw}`);
    }
  }
  assert.deepEqual(failures, [], `${failures.length} cases disagree:\n${failures.join('\n')}`);
});

test("every handle, seal and open case agrees through the binding's own exports", () => {
  const failures = [];
  let reached = 0;
  for (const testCase of fixture.cases) {
    const { id, expect } = testCase;
    try {
      if (testCase.call === 'handle') {
        const handle = groupHandle(utf8(testCase.groupId));
        assert.ok(handle instanceof Uint8Array, `case ${id}: a handle crosses as bytes`);
        if (handle.length !== 32 || hex(handle) !== expect.handleHex) {
          failures.push(`  ${id}: expected ${expect.handleHex}, got ${hex(handle)}`);
        }
      } else if (testCase.call === 'seal' && testCase.epochSecretHex !== undefined) {
        continue;
      } else if (testCase.call === 'open' && testCase.epochSecretsHex !== undefined) {
        const opened = asVerdict(clientHolding(testCase.groupIds).openEnvelope(unhex(testCase.envelopeHex)));
        if (opened.opened) failures.push(`  ${id}: opened by the group id alone, as ${JSON.stringify(opened)}`);
      } else if (testCase.call === 'seal' && testCase.envelopeKind !== 3 && testCase.envelopeKind !== 5) {
        // The clientless door seals a seat ask and a link preview only; every
        // other kind is the client's, by the epoch.
        try {
          sealEnvelope(utf8(testCase.groupId), testCase.envelopeKind, unhex(testCase.innerHex));
          failures.push(`  ${id}: kind ${testCase.envelopeKind} sealed at the clientless door`);
        } catch {
          // refused, as it should be
        }
      } else if (testCase.call === 'seal') {
        const sealed = sealEnvelope(utf8(testCase.groupId), testCase.envelopeKind, unhex(testCase.innerHex));
        // A case naming no `envelopeVersion` pins what this build SENDS
        // (version 2): same version byte, same nonce width,
        // so the same length; the bytes differ by the nonce. A case naming one
        // pins bytes only the fixture door seals: here, only its round trip.
        if (testCase.envelopeVersion === undefined) {
          if (sealed.length !== expect.envelopeHex.length / 2) {
            failures.push(`  ${id}: ${sealed.length} bytes, the golden envelope has ${expect.envelopeHex.length / 2}`);
          }
          if (hex(sealed.subarray(0, 1)) !== expect.envelopeHex.slice(0, 2)) {
            failures.push(`  ${id}: sealed as version ${sealed[0]}, the golden envelope is ${expect.envelopeHex.slice(0, 2)}`);
          }
        }
        const opened = asVerdict(clientHolding([testCase.groupId]).openEnvelope(sealed));
        const want = { opened: true, groupId: testCase.groupId, envelopeKind: testCase.envelopeKind, innerHex: testCase.innerHex };
        try {
          assert.deepStrictEqual(opened, want);
        } catch {
          failures.push(`  ${id}: sealed, then opened as ${JSON.stringify(opened)}`);
        }
      } else if (testCase.call === 'open') {
        const opened = asVerdict(clientHolding(testCase.groupIds).openEnvelope(unhex(testCase.envelopeHex)));
        try {
          assert.deepStrictEqual(opened, expect);
        } catch {
          failures.push(`  ${id}: expected ${JSON.stringify(expect)}, got ${JSON.stringify(opened)}`);
        }
      } else {
        continue;
      }
      reached += 1;
    } catch (err) {
      failures.push(`  ${id}: threw ${err.message}`);
    }
  }
  assert.ok(reached >= 11, `only ${reached} handle, seal and open cases reached the product exports`);
  assert.deepEqual(failures, [], failures.join('\n'));
});

test("a client's own seal is keyed by the epoch", () => {
  const groupId = '33333333-3333-4333-8333-333333333333';
  const client = clientHolding([groupId]);
  assert.equal(typeof client.sealEnvelope, 'function');
  const sealed = client.sealEnvelope(utf8(groupId), 1, utf8('hello'));
  assert.equal(sealed[0], 3, 'sealed by the epoch');
  assert.deepStrictEqual(asVerdict(client.openEnvelope(sealed)), {
    opened: true,
    groupId,
    envelopeKind: 1,
    innerHex: hex(utf8('hello')),
  });
  // Not by the group id: another device holding only the id opens nothing.
  assert.equal(clientHolding([groupId]).openEnvelope(sealed), undefined);
  // A seat ask stays keyed by the group id, for an asker that holds no epoch.
  const ask = client.sealEnvelope(utf8(groupId), 3, utf8('{}'));
  assert.equal(ask[0], 2);
  assert.equal(asVerdict(clientHolding([groupId]).openEnvelope(ask)).envelopeKind, 3);
});

test('every call is reached', () => {
  const reached = new Set(fixture.cases.map((testCase) => testCase.call));
  assert.deepEqual(CALLS.filter((call) => !reached.has(call)), []);
  for (const testCase of fixture.cases) {
    assert.ok(CALLS.includes(testCase.call), `case ${testCase.id}: no such call ${testCase.call}`);
  }
});

test('the product exports refuse what the core refuses', () => {
  assert.throws(() => groupHandle(new Uint8Array(0)), /must not be empty/);
  assert.throws(() => sealEnvelope(utf8('g'), 0, new Uint8Array(0)), /not an envelope kind/);
  // 6 is a call signal (ENVELOPE_KIND_CALL), the last kind; 7 is the first one refused.
  assert.throws(() => sealEnvelope(utf8('g'), 7, new Uint8Array(0)), /not an envelope kind/);
  // A seat ask (3) and a link preview (5) only: a message, commit, typing
  // frame or call signal is sealed by the client holding the group.
  for (const kind of [1, 2, 4, 6]) {
    assert.throws(() => sealEnvelope(utf8('g'), kind, new Uint8Array(0)), /sealed by the client holding the group/);
  }
  assert.ok(sealEnvelope(utf8('g'), 5, new Uint8Array(0)).length > 0);
  // Two seals of the same bytes differ: the nonce is fresh each time.
  const group = utf8('11111111-1111-4111-8111-111111111111');
  assert.notEqual(hex(sealEnvelope(group, 3, new Uint8Array(0))), hex(sealEnvelope(group, 3, new Uint8Array(0))));
  // A client holding no group opens nothing, and says so without throwing.
  assert.equal(clientHolding([]).openEnvelope(new Uint8Array([2, 3])), undefined);
});
