// SPDX-License-Identifier: MIT
// A panic poisons the module instance, through the BUILT wasm package
// (mls/wasm/src/lib.rs §After a panic, docs/mls-core.md §wasm
// binding).
//
// `wasm32-unknown-unknown` cannot unwind, so a panic is a trap that leaves the
// instance mid-operation. The binding's panic hook marks the instance poisoned
// before the trap, and every export refuses from then on: a call throws
// `poisoned: …`, and `flush()` rejects before a byte reaches the store, so the
// interrupted state is never written. `panicForTest` (behind `fixture`) is the
// panic; no shipped bundle carries it.
//
// Its own file, and so its own process under `node --test`: the poison is the
// whole module instance's, and nothing after it in the file could run.
//
//   wasm-pack build mls/wasm --target nodejs --dev --out-dir pkg-node -- --features test-issuer,fixture
//   node --test mls/wasm/tests/node/poison.test.mjs

import test from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { existsSync } from 'node:fs';
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
  MlsClient,
  TestIssuer,
  signingKeyPublicKey,
  accountIdentityPublicKey,
  isPoisoned,
  panicForTest,
  messageEpoch,
} = require(entry);

const NOW = Math.floor(Date.now() / 1000) - 3_600;
const LIFETIME = 30 * 86_400;
const enc = new TextEncoder();

/** An `MlsKvStore` over a `Map` that counts its batches. */
class CountingStore {
  constructor() {
    this.rows = new Map();
    this.batches = 0;
  }
  static hex(key) {
    return Buffer.from(key).toString('hex');
  }
  async get(key) {
    return this.rows.get(CountingStore.hex(key)) ?? null;
  }
  async writeBatch(entries) {
    this.batches += 1;
    for (const [key, value] of entries) {
      if (value === null) this.rows.delete(CountingStore.hex(key));
      else this.rows.set(CountingStore.hex(key), value);
    }
  }
  async iterate(prefix) {
    const wanted = CountingStore.hex(prefix);
    return [...this.rows.entries()]
      .filter(([key]) => key.startsWith(wanted))
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
      .map(([key, value]) => [Uint8Array.from(Buffer.from(key, 'hex')), value]);
  }
}

const isPoisonedError = (err) => err instanceof Error && err.message.startsWith('poisoned:');

test('after a panic, every export refuses and nothing more reaches the store', async () => {
  const iss = new TestIssuer(new Uint8Array(32).fill(7));
  const seed = new Uint8Array(32).fill(1);
  const token = iss.issue('actor-ada', 'device-ada', signingKeyPublicKey(seed), NOW, NOW + LIFETIME);
  const held = accountIdentityPublicKey(testAccountKey('actor-ada'));
  const published = iss.publishedJson();
  const store = new CountingStore();
  const client = await MlsClient.open(published, token, seed, store, held);

  const group = enc.encode('group-poisoned');
  client.createGroup(group);
  await client.flush();
  assert.equal(isPoisoned(), false, 'a healthy instance is not poisoned');
  const message = client.encrypt(group, enc.encode('before the panic'));
  const batchesBefore = store.batches;
  assert.ok(client.pendingWrites > 0, 'the encrypt is owed to the store');

  // The panic: a trap, not an ordinary error.
  assert.throws(() => panicForTest(), (err) => err instanceof WebAssembly.RuntimeError);
  assert.equal(isPoisoned(), true, 'the hook marked the instance before the trap');

  // The flush the host would have made next writes nothing.
  await assert.rejects(client.flush(), isPoisonedError);
  assert.equal(store.batches, batchesBefore, 'a poisoned instance wrote to the store');

  // Methods that answer a Result, getters, and free functions all refuse.
  assert.throws(() => client.epoch(group), isPoisonedError);
  assert.throws(() => client.encrypt(group, enc.encode('after')), isPoisonedError);
  assert.throws(() => client.groupIds(), isPoisonedError);
  assert.throws(() => client.pendingWrites, isPoisonedError);
  assert.throws(() => messageEpoch(message), isPoisonedError);
  assert.throws(() => new MlsClient(published, token, seed, held), isPoisonedError);
  await assert.rejects(MlsClient.open(published, token, seed, store, held), isPoisonedError);
  assert.throws(() => iss.publishedJson(), isPoisonedError);
  assert.equal(store.batches, batchesBefore, 'a refused open wrote to the store');
  assert.equal(isPoisoned(), true, 'and it stays poisoned');
});
