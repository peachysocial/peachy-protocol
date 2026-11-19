// SPDX-License-Identifier: MIT
// The golden account-store fixture, replayed through the BUILT wasm package.
//
// `mls/fixtures/account-store.json` pins what four clients must each get when
// they open a sealed store record or an account-key box, and every refusal a
// wrong input meets (mls/core/src/account_store.rs is the reading guide).
// `mls/core/tests/account_store_fixture.rs` generates and replays it in Rust;
// this is the same file through the wasm binding, twice over:
//
//  1. through `evaluateFixtureCase`, the door every fixture replay shares, told
//     by `kind: "account_store"` which table it is reading; and
//  2. through the binding's OWN exports — `storeOpen` and `accountKeyOpen` —
//     which are what the web client calls, and which the fixture door does not
//     reach. A replay that only went through (1) would leave the product
//     surface compiled and unexercised.
//
// Plus a round trip through the random doors (`generateAccountKey`,
// `storeSeal`, `accountKeySeal`), which the fixture cannot pin.
//
// Keep it in step with the three other replays:
// mls/core/tests/account_store_fixture.rs,
// mls/swift/Tests/PeachyMLSTests/AccountStoreFixtureTests.swift and
// the Android binding's `AccountStoreFixtureTest` (not in this repository).
//
// Run it against a nodejs-target build with both test features on:
//
//   wasm-pack build mls/wasm --target nodejs --dev --out-dir pkg-node -- --features test-issuer,fixture
//   node --test mls/wasm/tests/node/account-store.test.mjs

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
const {
  evaluateFixtureCase,
  generateAccountKey,
  accountKeySeal,
  accountKeyOpen,
  accountKeyAcceptHybrid,
  storeSeal,
  storeOpen,
  noteSealSigned,
  noteSender,
  noteOpenSigned,
  signingKeyPublicKey,
  transferKeySeal,
  transferKeyOpen,
} = require(entry);

const fixturePath = resolve(here, '../../../fixtures/account-store.json');
const fixture = JSON.parse(readFileSync(fixturePath, 'utf8'));

const FORMAT_VERSION = 1;
const CALLS = [
  'recordKey',
  'storeOpen',
  'boxOpen',
  'boxAccept',
  'boxAcceptHybrid',
  'noteSender',
  'noteOpenSigned',
  'transferKeyOpen',
];

const hex = (bytes) => Buffer.from(bytes).toString('hex');
const unhex = (text) => new Uint8Array(Buffer.from(text, 'hex'));

test('the package exports the fixture door and the five account-store functions', () => {
  assert.equal(typeof evaluateFixtureCase, 'function');
  for (const fn of [
    generateAccountKey,
    accountKeySeal,
    accountKeyOpen,
    accountKeyAcceptHybrid,
    storeSeal,
    storeOpen,
    noteSealSigned,
    noteSender,
    noteOpenSigned,
    transferKeySeal,
    transferKeyOpen,
  ]) {
    assert.equal(typeof fn, 'function');
  }
  assert.equal(fixture.version, FORMAT_VERSION);
  assert.ok(fixture.cases.length >= 30, `only ${fixture.cases.length} cases`);
  for (const testCase of fixture.cases) {
    assert.equal(testCase.kind, 'account_store', `case ${testCase.id}`);
    assert.notEqual(
      testCase.expect === undefined,
      testCase.expectError === undefined,
      `case ${testCase.id} needs exactly one of \`expect\` and \`expectError\``,
    );
  }
});

test('every case gets the verdict it expects, through the fixture door', () => {
  const failures = [];
  const ids = new Set();
  for (const testCase of fixture.cases) {
    const id = testCase.id;
    assert.ok(!ids.has(id), `two cases share the id ${id}`);
    ids.add(id);
    const json = JSON.stringify(testCase);
    if (testCase.expectError !== undefined) {
      try {
        const answered = evaluateFixtureCase(json);
        failures.push(`  ${id}\n    expected a refusal naming ${testCase.expectError}\n    actual   ${answered}`);
      } catch (err) {
        if (!(err instanceof Error) || !err.message.includes(testCase.expectError)) {
          failures.push(`  ${id}\n    expected a refusal naming ${testCase.expectError}\n    actual   ${err?.message ?? err}`);
        }
      }
      continue;
    }
    let raw;
    try {
      raw = evaluateFixtureCase(json);
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

test('every open case agrees through the binding\'s own storeOpen, accountKeyOpen and accountKeyAcceptHybrid', () => {
  const failures = [];
  let reached = 0;
  for (const testCase of fixture.cases) {
    let run;
    let key;
    if (testCase.call === 'storeOpen') {
      run = () => storeOpen(unhex(testCase.accountKeyHex), unhex(testCase.idHex), unhex(testCase.valueHex));
      key = 'plaintextHex';
    } else if (testCase.call === 'noteOpenSigned') {
      run = () =>
        noteOpenSigned(
          unhex(testCase.accountKeyHex),
          unhex(testCase.idHex),
          unhex(testCase.valueHex),
          testCase.deviceId,
          unhex(testCase.senderKeyHex),
          testCase.nowMs,
        );
      key = 'plaintextHex';
    } else if (testCase.call === 'noteSender') {
      run = () => noteSender(unhex(testCase.accountKeyHex), unhex(testCase.idHex), unhex(testCase.valueHex));
      key = 'senderDeviceId';
    } else if (testCase.call === 'transferKeyOpen') {
      run = () => transferKeyOpen(unhex(testCase.recipientSeedHex), testCase.deviceId, unhex(testCase.boxHex));
      key = 'transferKeyHex';
    } else if (testCase.call === 'boxOpen') {
      run = () =>
        accountKeyOpen(
          unhex(testCase.recipientSeedHex),
          unhex(testCase.approverKeyHex),
          testCase.deviceId,
          unhex(testCase.boxHex),
        );
      key = 'accountKeyHex';
    } else if (testCase.call === 'boxAcceptHybrid') {
      const empty = new Uint8Array(0);
      run = () =>
        accountKeyAcceptHybrid(
          unhex(testCase.recipientSeedHex),
          unhex(testCase.approverKeyHex),
          testCase.deviceId,
          unhex(testCase.boxHex),
          testCase.linkKeySeedHex ? unhex(testCase.linkKeySeedHex) : empty,
          testCase.confirmedApproverKeyHex ? unhex(testCase.confirmedApproverKeyHex) : empty,
          testCase.serverApprovalAllowed === true,
        );
      key = 'accountKeyHex';
    } else {
      continue;
    }
    reached += 1;
    let out;
    try {
      out = run();
    } catch (err) {
      if (testCase.expectError === undefined || !err.message.includes(testCase.expectError)) {
        failures.push(`  ${testCase.id}: threw ${err.message}`);
      }
      continue;
    }
    if (testCase.expectError !== undefined) {
      failures.push(`  ${testCase.id}: expected a refusal, got ${out}`);
    } else if (typeof out === 'string') {
      if (out !== testCase.expect[key]) failures.push(`  ${testCase.id}: expected ${testCase.expect[key]}, got ${out}`);
    } else if (!(out instanceof Uint8Array) || hex(out) !== testCase.expect[key]) {
      failures.push(`  ${testCase.id}: expected ${testCase.expect[key]}, got ${out}`);
    }
  }
  assert.ok(reached >= 20, `only ${reached} open cases reached the product doors`);
  assert.deepEqual(failures, [], failures.join('\n'));
});

test('every call is reached', () => {
  const reached = new Set(fixture.cases.map((testCase) => testCase.call));
  assert.deepEqual(CALLS.filter((call) => !reached.has(call)), []);
  for (const testCase of fixture.cases) {
    assert.ok(CALLS.includes(testCase.call), `case ${testCase.id}: no such call ${testCase.call}`);
  }
});

test('the random doors round-trip, including an empty plaintext', () => {
  const key = generateAccountKey();
  assert.ok(key instanceof Uint8Array);
  assert.equal(key.length, 32);
  assert.notEqual(hex(key), hex(generateAccountKey()));

  const id = new Uint8Array(16).fill(0x11);
  for (const plaintext of [new Uint8Array(0), new TextEncoder().encode('{"kind":"account"}')]) {
    const value = storeSeal(key, id, plaintext);
    assert.equal((value.length - 29) % 256, 0);
    assert.equal(hex(storeOpen(key, id, value)), hex(plaintext));
  }
  const manifestId = new Uint8Array(16);
  const manifest = storeSeal(key, manifestId, new TextEncoder().encode('{"version":1,"ids":[]}'));
  assert.throws(() => storeOpen(key, id, manifest), /does not open/);

  // A signed note: who sent it, then opened under that device's key.
  const phoneSeed = new Uint8Array(32).fill(0x11);
  const now = Date.now();
  const signed = noteSealSigned(key, id, new TextEncoder().encode('{}'), 'device-ada-phone', now, phoneSeed);
  assert.equal(noteSender(key, id, signed), 'device-ada-phone');
  assert.throws(() => storeOpen(key, id, signed), /format version 0x02/);
  assert.equal(
    new TextDecoder().decode(noteOpenSigned(key, id, signed, 'device-ada-phone', signingKeyPublicKey(phoneSeed), now)),
    '{}',
  );
  assert.throws(
    () => noteOpenSigned(key, id, signed, 'device-ada-phone', signingKeyPublicKey(phoneSeed), now + 0.5),
    /whole number/,
  );

  const approverSeed = new Uint8Array(32).fill(0x11);
  const recipientSeed = new Uint8Array(32).fill(0x33);
  const deviceId = '0f8e2b1c-6a4d-4e3f-9b2a-7c5d1e0f3a9b';
  const box = accountKeySeal(approverSeed, signingKeyPublicKey(recipientSeed), deviceId, key);
  assert.equal(box.length, 93);
  assert.equal(hex(accountKeyOpen(recipientSeed, signingKeyPublicKey(approverSeed), deviceId, box)), hex(key));
  assert.throws(
    () => accountKeyOpen(recipientSeed, signingKeyPublicKey(new Uint8Array(32).fill(0x44)), deviceId, box),
    /does not open/,
  );
  // The new device's door never opens a version-2 box (the removed QR code's,
  // which no door seals any more), and opens a version-1 box only under its
  // own switch for server approvals.
  const linked = Uint8Array.from(box);
  linked[0] = 0x02;
  const none = new Uint8Array(0);
  const approverKey = signingKeyPublicKey(approverSeed);
  assert.throws(
    () => accountKeyAcceptHybrid(recipientSeed, approverKey, deviceId, linked, none, approverKey, true),
    /showed no QR code/,
  );
  assert.throws(
    () => accountKeyAcceptHybrid(recipientSeed, approverKey, deviceId, box, none, approverKey, false),
    /post-quantum box/,
  );
  assert.equal(hex(accountKeyAcceptHybrid(recipientSeed, approverKey, deviceId, box, none, none, true)), hex(key));
  // A hand-off's key, sealed to the device it goes to: no other seed opens it.
  const transfer = transferKeySeal(signingKeyPublicKey(recipientSeed), deviceId, key);
  assert.equal(transfer.length, 93);
  assert.equal(hex(transferKeyOpen(recipientSeed, deviceId, transfer)), hex(key));
  assert.throws(() => transferKeyOpen(approverSeed, deviceId, transfer), /does not open/);
  assert.throws(() => transferKeySeal(signingKeyPublicKey(recipientSeed), deviceId, key.subarray(0, 16)), /exactly 32 bytes, got 16/);
  assert.throws(() => storeSeal(key, id.subarray(0, 15), new Uint8Array(1)), /exactly 16 bytes, got 15/);
});
