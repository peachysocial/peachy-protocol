// SPDX-License-Identifier: MIT
// The golden device-link fixture, replayed through the BUILT wasm package.
//
// `mls/fixtures/device-link.json` is the table of what four clients must each
// compute when a person approves a new device from one they already have: the
// exact bytes an approving device signs, the signature over them, whether an
// approval holds, the QR code a new device shows, and the two-digit number
// both devices show when neither can scan.
// `mls/core/tests/device_link_fixture.rs` replays it in Rust. This is the same
// table, same file, through `evaluateFixtureCase` in the wasm binding — the
// same door `rules.test.mjs` and `credentials.test.mjs` use, told by each case's
// `kind` which question it is being asked.
//
// Two replays and not one, for the reason the other two tables have two: the
// Rust one proves the DERIVATION, this one proves the DOOR. What can only go
// wrong here is the crossing — a verdict that came back as a wasm-bindgen
// object instead of a string, a `valid` that arrived as the string "false", a
// throw that reaches `catch` as something it cannot read, a `Uint8Array` that
// lost its last byte. None of that is visible from Rust.
//
// It also drives the binding's OWN exports, which the fixture door does not
// reach: `deviceApprovalStatement`, `signDeviceApproval`,
// `verifyDeviceApproval`, the `deviceLink…` calls and `MlsClient.keyPackageIdentity`
// are what the web client will call, and a replay that only ever went through
// `evaluateFixtureCase` would leave them compiled and unexercised.
//
// Keep it in step with the three other replays of this file:
// mls/core/tests/device_link_fixture.rs,
// mls/swift/Tests/PeachyMLSTests/DeviceLinkFixtureTests.swift and
// the Android binding's `DeviceLinkFixtureTest` (not in this repository). A check
// added here and nowhere else is a check three clients are not held to.
//
// Run it against a nodejs-target build with both test features on:
//
//   wasm-pack build mls/wasm --target nodejs --dev --out-dir pkg-node -- --features test-issuer,fixture
//   node --test mls/wasm/tests/node/device-link.test.mjs

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
// The QR doors take what was scanned as its UTF-8 bytes (it carries a secret).
const utf8 = (text) => new TextEncoder().encode(text);
const {
  evaluateFixtureCase,
  deviceApprovalStatement,
  signDeviceApproval,
  verifyDeviceApproval,
  deviceLinkCommitment,
  deviceLinkNumber,
  deviceLinkApproverNumber,
  deviceLinkQr,
  deviceLinkQrMatches,
  deviceLinkQrSecret,
  deviceLinkWaiterStep,
  signDeviceLinkCommitment,
  verifyDeviceLinkCommitment,
  deviceLinkApproverStep,
  generateDeviceLinkKemSeed,
  deviceLinkKemPublicKey,
  signDeviceLinkKem,
  verifyDeviceLinkKem,
  accountKeySealHybrid,
  accountKeyAcceptHybrid,
  signingKeyPublicKey,
  accountIdentityPublicKey,
  MlsClient,
  TestIssuer,
} = require(entry);

// Read, never bundled. The fixture is data three other languages read too, and
// a copy inside this directory would be a second fixture pretending to be the
// first one.
const fixturePath = resolve(here, '../../../fixtures/device-link.json');
const fixture = JSON.parse(readFileSync(fixturePath, 'utf8'));

// The format version this replay understands. Must equal
// `peachy_mls_core::fixture::FORMAT_VERSION`, and the Rust replay checks the
// other end of the same equality.
const FORMAT_VERSION = 1;

// Every `call` the table has to reach, spelled out here rather than derived
// from the file: a derivation from the same source cannot notice that a call
// stopped being exercised.
const CALLS = [
  'statement',
  'sign',
  'verify',
  'commitment',
  'number',
  'approverNumber',
  'qr',
  'qrMatches',
  'accountIdentity',
  'signAccountDevice',
  'verifyAccountDevice',
  'keyPackageIdentity',
  'waiterStep',
  'signCommitment',
  'verifyCommitment',
  'approverStep',
  'linkKey',
  'signLinkKey',
  'verifyLinkKey',
  'signDeviceRevocation',
  'verifyDeviceRevocation',
  'installRevocationTargets',
];

const hex = (bytes) => Buffer.from(bytes).toString('hex');
const unhex = (text) => new Uint8Array(Buffer.from(text, 'hex'));

test('the package exports the fixture door and the four device-link functions', () => {
  assert.equal(typeof evaluateFixtureCase, 'function');
  for (const fn of [
    deviceApprovalStatement,
    signDeviceApproval,
    verifyDeviceApproval,
    deviceLinkCommitment,
    deviceLinkNumber,
    deviceLinkApproverNumber,
    deviceLinkQr,
    deviceLinkQrMatches,
    deviceLinkQrSecret,
    deviceLinkWaiterStep,
    signDeviceLinkCommitment,
    verifyDeviceLinkCommitment,
    deviceLinkApproverStep,
  ]) {
    assert.equal(typeof fn, 'function');
  }
  // The fifth call lives on the client rather than free, because it needs the
  // reader's trusted keys and clock.
  assert.equal(typeof MlsClient.prototype.keyPackageIdentity, 'function');
  assert.equal(fixture.version, FORMAT_VERSION);
  // A floor, under today's count, so a replay that stopped finding cases
  // cannot read as a clean pass over nothing.
  assert.ok(
    fixture.cases.length >= 34,
    `only ${fixture.cases.length} cases — the fixture shrank or stopped parsing`,
  );
  for (const testCase of fixture.cases) {
    assert.equal(testCase.kind, 'device_link', `case ${testCase.id} has no kind: "device_link"`);
    // Exactly one of the two, never both and never neither: a case with an
    // `expect` AND an `expectError` would be read differently by the four
    // replays, and one with neither asserts nothing at all.
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
    const id = testCase.id ?? '<no id>';
    assert.ok(!ids.has(id), `two cases share the id ${JSON.stringify(id)}`);
    ids.add(id);

    // The whole case object, verbatim — `expect`, `expectError`, `why` and all.
    // Exactly what the Rust replay hands over, so a difference between the two
    // is a difference in the BINDING and can never be a difference in what was
    // asked.
    const json = JSON.stringify(testCase);

    if (testCase.expectError !== undefined) {
      // A refusal is NOT a verdict, and blurring the two is the one thing this
      // replay must not do: a signing key of the wrong length handed to
      // `statement` is a caller mistake, not a `valid: false`.
      let thrown;
      try {
        const answered = evaluateFixtureCase(json);
        failures.push(`  ${id}\n    expected a refusal naming ${testCase.expectError}\n    actual   ${answered}`);
        continue;
      } catch (err) {
        thrown = err;
      }
      if (!(thrown instanceof Error)) {
        failures.push(`  ${id}\n    a refusal is an Error, not a ${typeof thrown}`);
      } else if (!thrown.message.includes(testCase.expectError)) {
        failures.push(
          `  ${id}\n    expected a refusal naming ${testCase.expectError}\n` +
            `    actual   ${thrown.message}`,
        );
      }
      continue;
    }

    let raw;
    try {
      raw = evaluateFixtureCase(json);
    } catch (err) {
      failures.push(
        `  ${id}\n    expected ${JSON.stringify(testCase.expect)}\n    actual   refused: ${err.message}`,
      );
      continue;
    }
    assert.equal(typeof raw, 'string', `case ${id}: a verdict crosses as a string`);
    const actual = JSON.parse(raw);

    // deepStrictEqual and not a field-by-field check: an EXTRA key in the
    // verdict is a disagreement too, and the kind a per-field check reads
    // straight past.
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
    `${failures.length} of ${fixture.cases.length} fixture cases disagree with ` +
      `mls/core/src/device_link.rs as the wasm binding reports it.\n${failures.join('\n')}`,
  );
});

test('every call is reached, and every call a case names is one the door has', () => {
  const reached = new Set(fixture.cases.map((testCase) => testCase.call));
  const missing = CALLS.filter((call) => !reached.has(call));
  assert.deepEqual(
    missing,
    [],
    `no fixture case calls ${missing.join(', ')}. A call nothing reaches is a function three ` +
      'clients are not held to, and it can go wrong in one of them with nothing going red.',
  );

  for (const testCase of fixture.cases) {
    assert.ok(CALLS.includes(testCase.call), `case ${testCase.id}: no such call ${testCase.call}`);
  }

  const refusals = fixture.cases.filter((testCase) => testCase.expectError !== undefined).length;
  assert.ok(
    refusals >= 6,
    `only ${refusals} refusal cases — the refusals ARE the contract for three of the four ` +
      'calls, and a table with one of them says nothing about the rest',
  );
});

test('a verify verdict is a boolean after the crossing, not a string', () => {
  // JSON through a wasm string is exactly where a boolean quietly becomes text,
  // and `valid` is the one field in this table a truthiness check would read
  // past: the string "false" is true.
  const holds = JSON.parse(
    evaluateFixtureCase(
      JSON.stringify(fixture.cases.find((testCase) => testCase.id === 'verify/round-trip')),
    ),
  );
  assert.equal(typeof holds.valid, 'boolean');
  assert.equal(holds.valid, true);

  const doesNot = JSON.parse(
    evaluateFixtureCase(
      JSON.stringify(
        fixture.cases.find((testCase) => testCase.id === 'verify/one-flipped-signature-bit'),
      ),
    ),
  );
  assert.equal(typeof doesNot.valid, 'boolean');
  assert.equal(doesNot.valid, false);
});

test("the binding's own exports agree with the fixture door", () => {
  // The four functions a web client will actually call, checked against the
  // same golden values. The fixture door reaches `peachy_mls_core::device_link`
  // by another path, so a disagreement here is a bug in this crate's glue and
  // nowhere else.
  const statementCase = fixture.cases.find((testCase) => testCase.id === 'statement/ada-laptop');
  assert.equal(
    hex(deviceApprovalStatement(statementCase.deviceId, unhex(statementCase.signingKeyHex))),
    statementCase.expect.statementHex,
  );

  const signCase = fixture.cases.find(
    (testCase) => testCase.id === 'sign/ada-approves-the-laptop',
  );
  const signature = signDeviceApproval(
    unhex(signCase.seedHex),
    signCase.deviceId,
    unhex(signCase.signingKeyHex),
  );
  assert.equal(signature.length, 64);
  assert.equal(hex(signature), signCase.expect.signatureHex);

  const approver = signingKeyPublicKey(unhex(signCase.seedHex));
  assert.equal(
    verifyDeviceApproval(approver, signCase.deviceId, unhex(signCase.signingKeyHex), signature),
    true,
  );

  // The number, at the binding's own door: commit, then compute.
  const n = fixture.cases.find((testCase) => testCase.id === 'number/ordinary');
  const commitment = deviceLinkCommitment(unhex(n.approverNonceHex));
  assert.equal(hex(commitment), n.commitmentHex);
  assert.equal(
    deviceLinkNumber(
      unhex(n.newDeviceKeyHex),
      unhex(n.approverKeyHex),
      commitment,
      unhex(n.deviceNonceHex),
      unhex(n.approverNonceHex),
    ),
    n.expect.number,
  );
  assert.throws(
    () =>
      deviceLinkNumber(
        unhex(n.newDeviceKeyHex),
        unhex(n.approverKeyHex),
        commitment,
        unhex(n.deviceNonceHex),
        unhex(n.deviceNonceHex),
      ),
    /does not open its commitment/,
  );

  // The approver's number, at its own door too.
  const an = fixture.cases.find((testCase) => testCase.id === 'approverNumber/ordinary');
  assert.equal(
    deviceLinkApproverNumber(
      unhex(an.newDeviceKeyHex),
      unhex(an.approverKeyHex),
      unhex(an.commitmentHex),
      unhex(an.deviceNonceHex),
      unhex(an.approverNonceHex),
    ),
    an.expect.number,
  );

  // And the QR code, matched only by itself, carrying its secret.
  const q = fixture.cases.find((testCase) => testCase.id === 'qr/the-new-laptop');
  const qr = deviceLinkQr(q.deviceId, unhex(q.signingKeyHex), unhex(q.linkSecretHex));
  assert.equal(qr, q.expect.qr);
  assert.equal(deviceLinkQrMatches(utf8(qr), q.deviceId, unhex(q.signingKeyHex)), true);
  assert.equal(deviceLinkQrMatches(utf8(qr), q.deviceId, unhex('33'.repeat(32))), false);
  assert.equal(hex(deviceLinkQrSecret(utf8(qr), q.deviceId, unhex(q.signingKeyHex))), q.linkSecretHex);
  assert.equal(deviceLinkQrSecret(utf8(qr), q.deviceId, unhex('33'.repeat(32))), undefined);
  // Bytes that are not text are no QR code of ours.
  assert.equal(deviceLinkQrMatches(new Uint8Array([0xff, 0xfe]), q.deviceId, unhex(q.signingKeyHex)), false);
  assert.equal(deviceLinkQrSecret(new Uint8Array([0xff, 0xfe]), q.deviceId, unhex(q.signingKeyHex)), undefined);

  // And the waiting device's rule, every row of it, at the binding's own door.
  const empty = new Uint8Array(0);
  for (const w of fixture.cases.filter((testCase) => testCase.call === 'waiterStep')) {
    const step = () =>
      deviceLinkWaiterStep(
        w.boundApproverDeviceId ?? '',
        w.boundApproverKeyHex ? unhex(w.boundApproverKeyHex) : empty,
        w.boundCommitmentHex ? unhex(w.boundCommitmentHex) : empty,
        w.approverDeviceId,
        unhex(w.approverKeyHex),
        unhex(w.commitmentHex),
      );
    if (w.expectError) {
      assert.throws(step, (err) => err.message.includes(w.expectError), w.id);
    } else {
      assert.equal(step(), w.expect.waiterStep, w.id);
    }
  }

  // The approving device's rule and the commitment signature, every row, at
  // the binding's own doors.
  const bytes = (text) => (text ? unhex(text) : empty);
  for (const a of fixture.cases.filter((testCase) => testCase.call === 'approverStep')) {
    const step = () =>
      deviceLinkApproverStep(
        bytes(a.pendingKeyHex),
        bytes(a.commitmentHex),
        bytes(a.boundDeviceNonceHex),
        bytes(a.listedKeyHex),
        bytes(a.listedCommitmentHex),
        bytes(a.listedDeviceNonceHex),
        bytes(a.listedApproverNonceHex),
      );
    if (a.expectError) {
      assert.throws(step, (err) => err.message.includes(a.expectError), a.id);
    } else {
      assert.equal(step(), a.expect.approverStep, a.id);
    }
  }
  for (const s of fixture.cases.filter((testCase) => testCase.call === 'signCommitment')) {
    const sign = () =>
      signDeviceLinkCommitment(bytes(s.seedHex), s.deviceId, bytes(s.signingKeyHex), bytes(s.commitmentHex));
    if (s.expectError) {
      assert.throws(sign, (err) => err.message.includes(s.expectError), s.id);
    } else {
      assert.equal(hex(sign()), s.expect.signatureHex, s.id);
    }
  }
  for (const v of fixture.cases.filter((testCase) => testCase.call === 'verifyCommitment')) {
    assert.equal(
      verifyDeviceLinkCommitment(
        bytes(v.approverKeyHex),
        v.deviceId,
        bytes(v.signingKeyHex),
        bytes(v.commitmentHex),
        bytes(v.signatureHex),
      ),
      v.expect.valid,
      v.id,
    );
  }
});

test('verifyDeviceApproval returns false rather than throwing, and deviceLinkNumber throws', () => {
  // The asymmetry is the design. A malformed key, a wrong length and a bad
  // signature all mean "this approval does not hold" — a caller able to tell
  // them apart would be holding an oracle. Building a number over one key in
  // both roles, on the other hand, is a caller mistake with no safe answer: it
  // would render as a MATCH on the screen that is asking whether these are two
  // different machines.
  const signCase = fixture.cases.find(
    (testCase) => testCase.id === 'sign/ada-approves-the-laptop',
  );
  const signature = signDeviceApproval(
    unhex(signCase.seedHex),
    signCase.deviceId,
    unhex(signCase.signingKeyHex),
  );
  const approver = signingKeyPublicKey(unhex(signCase.seedHex));

  assert.equal(
    verifyDeviceApproval(new Uint8Array(0), signCase.deviceId, unhex(signCase.signingKeyHex), signature),
    false,
  );
  assert.equal(
    verifyDeviceApproval(approver, signCase.deviceId, unhex(signCase.signingKeyHex), signature.slice(0, 63)),
    false,
  );
  assert.equal(verifyDeviceApproval(approver, '', unhex(signCase.signingKeyHex), signature), false);

  const key = unhex('aa'.repeat(32));
  const nonce = unhex('66'.repeat(32));
  const commitment = deviceLinkCommitment(nonce);
  assert.throws(
    () => deviceLinkNumber(key, key, commitment, nonce, nonce),
    /a device cannot be compared with itself/,
  );
  assert.throws(
    () => deviceLinkNumber(key.slice(0, 31), unhex('bb'.repeat(32)), commitment, nonce, nonce),
    /new_device_key/,
  );
  assert.throws(
    () => deviceApprovalStatement('device-ada-laptop', key.slice(0, 31)),
    /signing_key must be exactly 32 bytes/,
  );
  assert.throws(() => deviceApprovalStatement('', key), /device_id must not be empty/);
});

test("a key package's identity comes out of its own bytes", () => {
  // The fifth call, through the binding's OWN door rather than the fixture's.
  // A real client produces a key package, a different client reads it, and the
  // signing key that comes back is the one the producer actually holds — which
  // is what lets an adder check a device approval without taking the server's
  // word for which key it is checking.
  // Around today, since the binding reads the wall clock (as the Swift and
  // Kotlin suites' TestIssuer.now does), and for the issuer's real thirty days:
  // a credential claiming longer than thirty-one is refused as
  // implausible_lifetime (mls/core/src/identity.rs, MAX_CREDENTIAL_LIFETIME_SECONDS).
  const NOW = Math.floor(Date.now() / 1000) - 3_600;
  const LIFETIME = 30 * 86_400;
  const issuer = new TestIssuer(new Uint8Array(32).fill(7));
  const device = (actorId, deviceId, seedByte) => {
    const seed = new Uint8Array(32).fill(seedByte);
    const publicKey = signingKeyPublicKey(seed);
    return {
      seed,
      publicKey,
      token: issuer.issue(actorId, deviceId, publicKey, NOW, NOW + LIFETIME),
      held: accountIdentityPublicKey(testAccountKey(actorId)),
    };
  };

  const laptop = device('actor-ada', 'device-ada-laptop', 0x33);
  const reader = device('actor-bo', 'device-bo-phone', 0x44);
  const producing = new MlsClient(issuer.publishedJson(), laptop.token, laptop.seed, laptop.held);
  const reading = new MlsClient(issuer.publishedJson(), reader.token, reader.seed, reader.held);
  const keyPackage = producing.generateKeyPackage();

  const read = reading.keyPackageIdentity(keyPackage);
  assert.equal(read.rejection, null);
  assert.equal(read.identity.actorId, 'actor-ada');
  assert.equal(read.identity.deviceId, 'device-ada-laptop');
  // THE assertion. The key handed to `verifyDeviceApproval` is the producer's
  // own, taken out of the package, and nobody in between got to name it.
  assert.equal(hex(read.identity.deviceKey), hex(laptop.publicKey));
  assert.ok(read.identity.deviceKey instanceof Uint8Array);

  // And an approval over that key, checked the way an adder would.
  const approverSeed = new Uint8Array(32).fill(0x11);
  const approval = signDeviceApproval(
    approverSeed,
    read.identity.deviceId,
    read.identity.deviceKey,
  );
  assert.equal(
    verifyDeviceApproval(
      signingKeyPublicKey(approverSeed),
      read.identity.deviceId,
      read.identity.deviceKey,
      approval,
    ),
    true,
  );
  // The same approval against the key a lying directory might have named
  // instead does NOT hold, which is the whole reason the key is read here.
  assert.equal(
    verifyDeviceApproval(
      signingKeyPublicKey(approverSeed),
      read.identity.deviceId,
      signingKeyPublicKey(new Uint8Array(32).fill(0x55)),
      approval,
    ),
    false,
  );

  // Bytes that are not a key package THROW — a refusal, not a rejection. A
  // caller must not be able to report "that device's credential is bad" about
  // something that was never a credential.
  assert.throws(() => reading.keyPackageIdentity(new Uint8Array([0xde, 0xad, 0xbe, 0xef])));
  assert.throws(() => reading.keyPackageIdentity(new Uint8Array(0)));
});

test('a case that addresses nothing real throws, rather than returning a verdict', () => {
  // The distinction the whole replay rests on. A case naming something that no
  // longer exists must fail loudly — the alternative is a fixture that goes on
  // passing while it tests nothing.
  assert.throws(
    () =>
      evaluateFixtureCase(
        JSON.stringify({
          kind: 'device_link',
          call: 'compareEverything',
          deviceId: 'device-ada-laptop',
          signingKeyHex: '22',
        }),
      ),
    (err) => {
      assert.ok(err instanceof Error, 'a failure is an Error, not a code');
      assert.match(err.message, /unknown call "compareEverything"/);
      // And it lists what IS known, so repointing the case is a read rather
      // than a search.
      assert.match(err.message, /statement, sign, verify, commitment, number, approverNumber, qr, qrMatches, accountIdentity, signAccountDevice, verifyAccountDevice, signDeviceRevocation, verifyDeviceRevocation, keyPackageIdentity/);
      return true;
    },
  );

  assert.throws(
    () => evaluateFixtureCase(JSON.stringify({ kind: 'teleport' })),
    /unknown case kind "teleport"/,
  );
  assert.throws(
    () => evaluateFixtureCase(JSON.stringify({ kind: 'device_link', call: 'number' })),
    /`newDeviceKeyHex`/,
  );
  assert.throws(
    () =>
      evaluateFixtureCase(
        JSON.stringify({ kind: 'device_link', call: 'commitment', approverNonceHex: 'zz' }),
      ),
    /is not hex/,
  );
});

test('the other two tables are untouched by the new kind', () => {
  // `rules.json` carries no `kind` and must go on meaning the policy table.
  // This is the assertion that would catch the new arm swallowing it — which
  // would leave all three fixtures green here and red in a client built from an
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

test('the link key crosses the wasm door: drawn, signed, checked, and sealed to', () => {
  const seed = generateDeviceLinkKemSeed();
  assert.ok(seed instanceof Uint8Array);
  assert.equal(seed.length, 32);
  const linkKey = deviceLinkKemPublicKey(seed);
  assert.equal(linkKey.length, 1216);

  const laptopSeed = new Uint8Array(32).fill(0x33);
  const laptopKey = signingKeyPublicKey(laptopSeed);
  const phoneSeed = new Uint8Array(32).fill(0x11);
  const phoneKey = signingKeyPublicKey(phoneSeed);
  const commitment = new Uint8Array(32).fill(0x44);
  const nonce = new Uint8Array(32).fill(0x55);
  const id = '0f8e2b1c-6a4d-4e3f-9b2a-7c5d1e0f3a9b';
  const signature = signDeviceLinkKem(laptopSeed, id, commitment, nonce, linkKey);
  assert.equal(verifyDeviceLinkKem(laptopKey, id, commitment, nonce, linkKey, signature), true);
  assert.equal(verifyDeviceLinkKem(phoneKey, id, commitment, nonce, linkKey, signature), false);
  assert.equal(verifyDeviceLinkKem(laptopKey, id, commitment, nonce, new Uint8Array(0), signature), false);

  const accountKey = new Uint8Array(32).fill(0xa1);
  const box = accountKeySealHybrid(phoneSeed, laptopKey, linkKey, id, accountKey);
  assert.equal(box.length, 1213);
  assert.equal(box[0], 0x03);
  const opened = accountKeyAcceptHybrid(laptopSeed, phoneKey, id, box, seed, phoneKey, false);
  assert.equal(hex(opened), hex(accountKey));
  assert.throws(
    () => accountKeyAcceptHybrid(laptopSeed, phoneKey, id, box, new Uint8Array(0), phoneKey, false),
    (err) => err instanceof Error && err.message.includes('posted none'),
  );
});
