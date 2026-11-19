// SPDX-License-Identifier: MIT
// A call link's client adopts the main client's own-device trust through the
// BUILT package (docs/calls.md §Call links on participant keys). The
// protocol half is mls/core/tests/call_link_own_devices.rs; this holds that
// the three bindings reach JavaScript as the web client calls them: the trust
// is a string, adopting another device's throws, and a standing is a number.
//
//   wasm-pack build mls/wasm --target nodejs --dev --out-dir pkg-node -- --features test-issuer
//   node --test mls/wasm/tests/node/call-link-trust.test.mjs

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
const { MlsClient, TestIssuer, signingKeyPublicKey, accountIdentityPublicKey } = createRequire(import.meta.url)(entry);

const NOW = Math.floor(Date.now() / 1000) - 3_600;
const LIFETIME = 30 * 86_400;

function open(iss, actorId, deviceId, seedByte) {
  const seed = new Uint8Array(32).fill(seedByte);
  const publicKey = signingKeyPublicKey(seed);
  const token = iss.issue(actorId, deviceId, publicKey, NOW, NOW + LIFETIME);
  const client = new MlsClient(iss.publishedJson(), token, seed, accountIdentityPublicKey(testAccountKey(actorId)));
  return { client, publicKey };
}

test("a link client adopts the main client's forgotten devices", () => {
  const iss = new TestIssuer(new Uint8Array(32).fill(9));
  const main = open(iss, 'actor-ada', 'device-ada-laptop', 31);
  const link = open(iss, 'actor-ada', 'device-ada-laptop', 31);
  const phone = open(iss, 'actor-ada', 'device-ada-phone', 32);
  const tablet = open(iss, 'actor-ada', 'device-ada-tablet', 33);

  assert.equal(main.client.forgetOwnDevice('device-ada-phone', phone.publicKey), true);
  const trust = main.client.ownDeviceTrust();
  assert.equal(typeof trust, 'string');
  assert.equal(JSON.parse(trust).v, 1);

  assert.throws(() => link.client.adoptOwnDeviceTrust(tablet.client.ownDeviceTrust()));
  assert.equal(link.client.ownDeviceStanding('actor-ada', 'device-ada-phone', phone.publicKey), 3);
  link.client.adoptOwnDeviceTrust(trust);

  assert.equal(link.client.ownDeviceStanding('actor-ada', 'device-ada-phone', phone.publicKey), 4);
  assert.equal(link.client.ownDeviceStanding('actor-ada', 'device-ada-tablet', tablet.publicKey), 3);
  assert.equal(link.client.ownDeviceStanding('actor-ada', 'device-ada-laptop', link.publicKey), 1);
  assert.equal(link.client.ownDeviceStanding('actor-bo', 'device-bo', tablet.publicKey), 0);

  const group = new TextEncoder().encode('88888888-8888-4888-8888-888888888888');
  link.client.createGroup(group);
  assert.throws(() => link.client.addMember(group, phone.client.generateKeyPackage()));
});
