// SPDX-License-Identifier: MIT
// A device's own approval and a PIN restore's answer, through the BUILT
// package (docs/identity.md §RevokeDevice). The protocol half is
// mls/core/tests/signed_revocation.rs; this holds that the two doors reach
// JavaScript as the web client calls them: the approval is the 64 bytes the
// seed makes, a key the restore's answer named is refused with words the web
// client matches, and the answer is kept once.
//
//   wasm-pack build mls/wasm --target nodejs --dev --out-dir pkg-node -- --features test-issuer
//   node --test mls/wasm/tests/node/own-approval.test.mjs

import test from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { testAccountKey } from './test-account.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const entry = resolve(here, '../../pkg-node/peachy_mls_wasm.js');
if (!existsSync(entry)) {
  throw new Error(
    'no build at mls/wasm/pkg-node. Run:\n' +
      '  wasm-pack build mls/wasm --target nodejs --dev --out-dir pkg-node -- --features test-issuer',
  );
}
const {
  MlsClient,
  TestIssuer,
  signingKeyPublicKey,
  signDeviceApproval,
  accountIdentityPublicKey,
  signAccountDevice,
} = createRequire(import.meta.url)(entry);

const NOW = Math.floor(Date.now() / 1000) - 3_600;
const LIFETIME = 30 * 86_400;
const hex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');

function open(iss, actorId, deviceId, seedByte) {
  const seed = new Uint8Array(32).fill(seedByte);
  const publicKey = signingKeyPublicKey(seed);
  const token = iss.issue(actorId, deviceId, publicKey, NOW, NOW + LIFETIME);
  const client = new MlsClient(iss.publishedJson(), token, seed, accountIdentityPublicKey(testAccountKey(actorId)));
  return { client, publicKey, seed };
}

test("a device's own approval is the one its seed makes", () => {
  const iss = new TestIssuer(new Uint8Array(32).fill(9));
  const phone = open(iss, 'actor-ada', 'device-ada-phone', 41);
  const laptop = signingKeyPublicKey(new Uint8Array(32).fill(42));
  const made = phone.client.signOwnDeviceApproval('device-ada-laptop', laptop, 0);
  assert.ok(made instanceof Uint8Array);
  assert.deepEqual(made, signDeviceApproval(phone.seed, 'device-ada-laptop', laptop));
  assert.throws(() => phone.client.signOwnDeviceApproval('device-ada-laptop', laptop, 1.5), /whole number of seconds/);
});

test("a key a restore's answer named is never approved, and the answer is kept once", () => {
  const iss = new TestIssuer(new Uint8Array(32).fill(9));
  const phone = open(iss, 'actor-ada', 'device-ada-phone', 51);
  const laptop = signingKeyPublicKey(new Uint8Array(32).fill(52));
  const tablet = signingKeyPublicKey(new Uint8Array(32).fill(53));
  const stranger = signingKeyPublicKey(new Uint8Array(32).fill(54));
  // The answer carries the account's certificate of each key and the identity
  // key the phone holds, as the web client sends them; the core keeps only a
  // key whose certificate verifies under it.
  const ada = testAccountKey('actor-ada');
  const certified = (key, account = ada) =>
    key.length === 32 ? signAccountDevice(account, key) : new Uint8Array(64);
  const answer = (keys, certificates = keys.map((k) => certified(k))) =>
    JSON.stringify({
      restoredSince: NOW,
      keys: keys.map(hex),
      certificates: certificates.map(hex),
      accountIdentityKey: hex(accountIdentityPublicKey(ada)),
    });

  // Its own key, a key that is no key, and a key another account certified
  // are dropped.
  const named = [laptop, phone.publicKey, new Uint8Array(3), stranger];
  const certificates = named.map((k) => certified(k, k === stranger ? testAccountKey('actor-bo') : ada));
  assert.equal(phone.client.noteRestoreSignedOut(answer(named, certificates)), 1);
  // A second answer for the same restore keeps nothing.
  assert.equal(phone.client.noteRestoreSignedOut(answer([tablet])), 0);
  assert.throws(() => phone.client.noteRestoreSignedOut(JSON.stringify({ restoredSince: 0, keys: [] })));

  assert.throws(
    () => phone.client.signOwnDeviceApproval('device-ada-laptop', laptop, NOW),
    /signed out of the account/,
  );
  // The tablet was not in the kept answer, nor the key the account never
  // certified: either may be approved.
  assert.equal(phone.client.signOwnDeviceApproval('device-ada-tablet', tablet, NOW).length, 64);
  assert.equal(phone.client.signOwnDeviceApproval('device-ada-stranger', stranger, NOW).length, 64);
});
