// SPDX-License-Identifier: MIT
// The golden credential fixture, replayed through the BUILT wasm package.
//
// `mls/fixtures/credentials.json` is the table of every way a `pdc1` device
// credential can fail to make a leaf into somebody;
// `mls/core/tests/credentials_fixture.rs` replays it in Rust. This is the same
// table, same file, through `evaluateFixtureCase` in the wasm binding — the
// same door `rules.test.mjs` uses, told by each case's `kind` which question it
// is being asked.
//
// Two replays and not one, for the reason the rules fixture has two: the Rust
// one proves the VERIFIER, this one proves the DOOR. What can only go wrong
// here is the crossing — a verdict that came back as a wasm-bindgen object
// instead of a string, a `reasonCode` that arrived as text, an `expiresAt` that
// turned into a BigInt on the way across, a throw that reaches `catch` as
// something it cannot read. None of that is visible from Rust.
//
// Keep it in step with the three other replays of this file:
// mls/core/tests/credentials_fixture.rs,
// mls/swift/Tests/PeachyMLSTests/CredentialsFixtureTests.swift and
// the Android binding's `CredentialsFixtureTest` (not in this repository). A check
// added here and nowhere else is a check three clients are not held to.
//
// Run it against a nodejs-target build with both test features on:
//
//   wasm-pack build mls/wasm --target nodejs --dev --out-dir pkg-node -- --features test-issuer,fixture
//   node --test mls/wasm/tests/node/credentials.test.mjs

import test from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { existsSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

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
const { evaluateFixtureCase } = require(entry);

// Read, never bundled. The fixture is data three other languages read too, and
// a copy inside this directory would be a second fixture pretending to be the
// first one.
const fixturePath = resolve(here, '../../../fixtures/credentials.json');
const fixture = JSON.parse(readFileSync(fixturePath, 'utf8'));

// The format version this replay understands. Must equal
// `peachy_mls_core::fixture::FORMAT_VERSION`, and the Rust replay checks the
// other end of the same equality.
const FORMAT_VERSION = 1;

// Every `CredentialRejection`, spelled out here rather than read from the file,
// so a fixture that quietly stopped covering one of them still fails. The
// numbers are half the contract: a rename that left the discriminant alone and
// a renumbering that left the name alone are the two ways it breaks.
const REJECTIONS = {
  malformed: 1,
  unknown_kid: 2,
  bad_signature: 3,
  expired: 4,
  not_yet_valid: 5,
  leaf_key_mismatch: 6,
  unsupported_version: 7,
  wrong_credential_type: 8,
  // 9 was wrong_key_use, retired.
  implausible_lifetime: 10,
  account_signature: 11,
  not_approved: 12,
  not_own_account_key: 13,
};

test('the package exports the fixture door', () => {
  assert.equal(typeof evaluateFixtureCase, 'function');
  assert.equal(fixture.version, FORMAT_VERSION);
  // A floor, under today's count, so a replay that stopped finding cases
  // cannot read as a clean pass over nothing.
  assert.ok(
    fixture.cases.length >= 35,
    `only ${fixture.cases.length} cases — the fixture shrank or stopped parsing`,
  );
  for (const testCase of fixture.cases) {
    assert.equal(testCase.kind, 'credential', `case ${testCase.id} has no kind: "credential"`);
  }
});

test('every case gets the verdict it expects, through the wasm door', () => {
  const failures = [];
  const ids = new Set();

  for (const testCase of fixture.cases) {
    const id = testCase.id ?? '<no id>';
    assert.ok(!ids.has(id), `two cases share the id ${JSON.stringify(id)}`);
    ids.add(id);

    // The whole case object, verbatim — `expect`, `why` and all. Exactly what
    // the Rust replay hands over, so a difference between the two is a
    // difference in the BINDING and can never be a difference in what was
    // asked.
    const raw = evaluateFixtureCase(JSON.stringify(testCase));
    assert.equal(typeof raw, 'string', `case ${id}: a verdict crosses as a string`);
    const actual = JSON.parse(raw);

    // deepStrictEqual and not a field-by-field check: an EXTRA key in the
    // verdict — a `reason` on an acceptance, say — is a disagreement too, and
    // the kind a per-field check reads straight past.
    try {
      assert.deepStrictEqual(actual, testCase.expect);
    } catch {
      failures.push(
        `  ${id}\n    expected ${JSON.stringify(testCase.expect)}\n` +
          `    actual   ${JSON.stringify(actual)}`,
      );
    }
  }

  assert.deepEqual(
    failures,
    [],
    `${failures.length} of ${fixture.cases.length} fixture cases disagree with the identity ` +
      `layer as the wasm binding reports it.\n${failures.join('\n')}`,
  );
});

test('all ten rejection codes are reached, and every name a case uses is one of them', () => {
  const reached = new Set(fixture.cases.map((testCase) => testCase.expect.reason).filter(Boolean));
  const missing = Object.keys(REJECTIONS).filter((name) => !reached.has(name));
  assert.deepEqual(
    missing,
    [],
    `no case produces ${missing.join(', ')}. A rejection nothing reaches is a branch this ` +
      'fixture cannot protect, and it can go wrong in one client with nothing going red.',
  );

  for (const testCase of fixture.cases) {
    const { reason, reasonCode } = testCase.expect;
    if (reason === undefined) continue;
    assert.ok(reason in REJECTIONS, `case ${testCase.id}: no such rejection ${reason}`);
    assert.equal(reasonCode, REJECTIONS[reason], `case ${testCase.id}: ${reason} is a different code`);
  }
});

test('an acceptance names who it accepted, and a rejection carries name and number', () => {
  // Spot checks written out in JavaScript rather than read from the file, so
  // that a fixture which somehow round-trips its own mistakes still fails here.
  const good = {
    kind: 'credential',
    call: 'validateToken',
    nowUnix: 1789516800,
    trust: ['0707070707070707070707070707070707070707070707070707070707070707'],
    mint: {
      signerSeed: '0707070707070707070707070707070707070707070707070707070707070707',
      actorId: 'actor-ada',
      deviceId: 'device-ada-phone',
      deviceSeed: '1111111111111111111111111111111111111111111111111111111111111111',
      issuedAt: 1789513200,
      expiresAt: 1792108800,
    },
  };
  assert.deepStrictEqual(JSON.parse(evaluateFixtureCase(JSON.stringify(good))), {
    decision: 'accepted',
    actorId: 'actor-ada',
    deviceId: 'device-ada-phone',
    kid: 'fe812c12',
    expiresAt: 1792108800,
  });

  // `expiresAt` is a NUMBER after the crossing, not a string and not a BigInt.
  // A unix second is exactly the kind of field a binding turns into something
  // JSON.parse cannot compare.
  const accepted = JSON.parse(evaluateFixtureCase(JSON.stringify(good)));
  assert.equal(typeof accepted.expiresAt, 'number');

  // The same credential replayed onto somebody else's leaf. This is the check
  // that gives the whole credential its meaning, so it is the one worth
  // asserting twice.
  const replayed = {
    ...good,
    leafSeed: '2222222222222222222222222222222222222222222222222222222222222222',
  };
  const verdict = JSON.parse(evaluateFixtureCase(JSON.stringify(replayed)));
  assert.deepStrictEqual(verdict, {
    decision: 'rejected',
    reason: 'leaf_key_mismatch',
    reasonCode: 6,
  });
  assert.equal(typeof verdict.reasonCode, 'number');
});

test('a case that addresses nothing real throws, rather than returning a verdict', () => {
  // The distinction the whole replay rests on. A case naming something that no
  // longer exists must fail loudly — the alternative is a fixture that goes on
  // passing while it tests nothing.
  assert.throws(
    () =>
      evaluateFixtureCase(
        JSON.stringify({
          kind: 'credential',
          call: 'validateEverything',
          nowUnix: 0,
          trust: [],
          token: 'pdc1',
          leafSeed: '1111111111111111111111111111111111111111111111111111111111111111',
        }),
      ),
    (err) => {
      assert.ok(err instanceof Error, 'a failure is an Error, not a code');
      assert.match(err.message, /unknown call "validateEverything"/);
      // And it lists what IS known, so repointing the case is a read rather
      // than a search.
      assert.match(err.message, /validateCredential/);
      return true;
    },
  );

  assert.throws(
    () => evaluateFixtureCase(JSON.stringify({ kind: 'teleport' })),
    /unknown case kind "teleport"/,
  );
  assert.throws(
    () =>
      evaluateFixtureCase(
        JSON.stringify({ kind: 'credential', call: 'validateToken', nowUnix: 0, trust: ['07'] }),
      ),
    /64 hex characters/,
  );
});

test('a case with no kind is still a rules case', () => {
  // The dispatch defaults the way `mls/fixtures/rules.json` needs it to, and
  // this is the assertion that catches it defaulting the other way — which
  // would leave both fixtures green here and red in a client built from an
  // older commit.
  assert.deepStrictEqual(
    JSON.parse(
      evaluateFixtureCase(
        JSON.stringify({ call: 'evaluate', proposal: { kind: 'add', sender: 'member' } }),
      ),
    ),
    { decision: 'allow' },
  );
});
