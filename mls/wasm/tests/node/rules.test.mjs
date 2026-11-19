// SPDX-License-Identifier: MIT
// The golden rules fixture, replayed through the BUILT wasm package.
//
// `mls/fixtures/rules.json` is the table of every decision Peachy's group
// policy makes; `mls/core/tests/rules_fixture.rs` replays it in Rust. This is
// the same table, same file, through `evaluateFixtureCase` in the wasm binding
// — which is the door a browser would reach the policy through, and the same
// one `credentials.test.mjs` feeds the credential table to.
//
// Two replays and not one, for the reason the journey has two
// (tests/journey.rs and tests/node/journey.test.mjs): the Rust one proves the
// policy, this one proves the DOOR. A JSON contract is exactly the kind of
// thing that compiles and then hands JavaScript something it cannot read — a
// verdict that came back as a wasm-bindgen object instead of a string, a throw
// that arrives as a code, an epoch-shaped field that turned into a BigInt on
// the way across. None of that is visible from Rust.
//
// It is also the worked example the Swift and Kotlin replays were copied from:
// mls/swift/Tests/PeachyMLSTests/RulesFixtureTests.swift and
// the Android binding's `RulesFixtureTest` (not in this repository) make the same five
// assertions through the C door. Keep the four in step — a check added here and
// nowhere else is a check three clients are not held to.
//
// Run it against a nodejs-target build with both test features on:
//
//   wasm-pack build mls/wasm --target nodejs --dev --out-dir pkg-node -- --features test-issuer,fixture
//   node --test mls/wasm/tests/node/rules.test.mjs

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
const fixturePath = resolve(here, '../../../fixtures/rules.json');
const fixture = JSON.parse(readFileSync(fixturePath, 'utf8'));

// The format version this replay understands. Must equal
// `peachy_mls_core::fixture::FORMAT_VERSION`, and the Rust replay checks the
// other end of the same equality — a case whose SHAPE changed is not something
// to read past in either language.
const FORMAT_VERSION = 1;

test('the package exports the fixture door', () => {
  assert.equal(typeof evaluateFixtureCase, 'function');
  assert.equal(fixture.version, FORMAT_VERSION);
  // A floor, under today's count, so a replay that stopped finding cases
  // cannot read as a clean pass over nothing.
  assert.ok(
    fixture.cases.length >= 50,
    `only ${fixture.cases.length} cases — the fixture shrank or stopped parsing`,
  );
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
    // verdict — a `reason` on an allow, say — is a disagreement too, and the
    // kind a per-field check reads straight past.
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
    `${failures.length} of ${fixture.cases.length} fixture cases disagree with the policy ` +
      `as the wasm binding reports it.\n${failures.join('\n')}`,
  );
});

test('an allow carries no reason, and a denial carries both the name and the number', () => {
  // Spot checks written out in JavaScript rather than read from the file, so
  // that a fixture which somehow round-trips its own mistakes still fails here.
  assert.deepStrictEqual(
    JSON.parse(evaluateFixtureCase(JSON.stringify({ call: 'evaluate', proposal: { kind: 'add', sender: 'member' } }))),
    { decision: 'allow' },
  );
  assert.deepStrictEqual(
    JSON.parse(
      evaluateFixtureCase(
        JSON.stringify({ call: 'evaluate', proposal: { kind: 'external_init', sender: 'member' } }),
      ),
    ),
    { decision: 'deny', reason: 'external_join', reasonCode: 1 },
  );
  assert.deepStrictEqual(
    JSON.parse(
      evaluateFixtureCase(
        JSON.stringify({ call: 'evaluateCommitSender', sender: 'new_member_commit' }),
      ),
    ),
    { decision: 'deny', reason: 'external_join', reasonCode: 1 },
  );
});

test('a case that addresses nothing real throws, rather than returning a verdict', () => {
  // The distinction the whole replay rests on. A case naming a proposal kind
  // that no longer exists must fail loudly — the alternative is a fixture that
  // goes on passing while it tests nothing, which is the failure
  // the clients' identifier checks exist to catch on their side.
  assert.throws(
    () =>
      evaluateFixtureCase(
        JSON.stringify({ call: 'evaluate', proposal: { kind: 'teleport', sender: 'member' } }),
      ),
    (err) => {
      assert.ok(err instanceof Error, 'a failure is an Error, not a code');
      assert.match(err.message, /unknown proposal kind "teleport"/);
      // And it lists what IS known, so repointing the case is a read rather
      // than a search.
      assert.match(err.message, /external_init/);
      return true;
    },
  );

  assert.throws(
    () => evaluateFixtureCase(JSON.stringify({ call: 'evaluateNothing' })),
    /unknown call "evaluateNothing"/,
  );
  assert.throws(() => evaluateFixtureCase('{not json'), /could not read the fixture case/);
});

test('the rules block travels with the case', () => {
  // allowRemoveByAnyMember is the one knob of the proposal rules, so
  // the fixture has to be able to describe both settings — and the binding has
  // to carry the block across, which is a place a hand-written JSON mapping
  // can silently drop a field.
  const strict = {
    call: 'evaluate',
    rules: { allowRemoveByAnyMember: false },
    proposal: { kind: 'remove', sender: 'member' },
  };
  assert.deepStrictEqual(JSON.parse(evaluateFixtureCase(JSON.stringify(strict))), {
    decision: 'deny',
    reason: 'non_member_proposal',
    reasonCode: 3,
  });

  delete strict.rules;
  assert.deepStrictEqual(JSON.parse(evaluateFixtureCase(JSON.stringify(strict))), {
    decision: 'allow',
  });
});
