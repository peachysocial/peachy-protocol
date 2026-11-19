// SPDX-License-Identifier: MIT
// Persistence, through the BUILT package, against a store that outlives the
// client — the JavaScript half of `mls/core/tests/persistence.rs`.
//
// The Rust test proves the storage provider and the SQLite backend keep a
// group across a process restart. It cannot prove the thing this file is for:
// that the SYNCHRONOUS OpenMLS trait and an ASYNCHRONOUS host store were joined
// honestly. The join is a write-through cache plus an awaited `flush()`
// (mls/wasm/src/kv.rs), and every way it can be got wrong is invisible to Rust:
//
//   - `open()` could hydrate the wrong prefix and come back with an empty
//     client that cheerfully creates a second group under the same id;
//   - `flush()` could resolve before the host actually wrote;
//   - a key could cross as an array of numbers rather than a `Uint8Array`, and
//     `Map` would happily key on the wrong thing;
//   - the dirty set could be cleared on a REJECTED write, losing an epoch.
//
// So the store here is a deliberately dumb fake: a `Map`, async, counting its
// calls, with a switch to make it fail. What it is NOT is IndexedDB — that
// implementation is the web client's IndexedDB store and it is held to
// the same interface by the web client's type check. A fake is the right thing at this
// layer: `fake-indexeddb` would test somebody's shim of a browser API, when
// what is under test is our three-method contract.
//
// Run it against a nodejs-target build:
//
//   wasm-pack build mls/wasm --target nodejs --dev --out-dir pkg-node -- --features test-issuer,fixture
//   node --test mls/wasm/tests/node/storage.test.mjs

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
const wasm = require(entry);

const { MlsClient, TestIssuer, signingKeyPublicKey, accountIdentityPublicKey } = wasm;

// Around today, since the binding reads the wall clock (as the Swift and

// Kotlin suites' TestIssuer.now does), and for the issuer's real thirty days:

// a credential claiming longer than thirty-one is refused as

// implausible_lifetime (mls/core/src/identity.rs, MAX_CREDENTIAL_LIFETIME_SECONDS).

const NOW = Math.floor(Date.now() / 1000) - 3_600;

const LIFETIME = 30 * 86_400;

const enc = new TextEncoder();
const dec = new TextDecoder();

// ---- The fake store ---------------------------------------------------------

/**
 * An `MlsKvStore` over a `Map`, async, counting what it was asked to do.
 *
 * Keyed by the key's bytes rendered as hex, because a `Uint8Array` is keyed by
 * identity in a `Map` and two arrays holding the same bytes are two keys. That
 * is exactly the trap a real implementation has to avoid too — IndexedDB avoids
 * it by keying on the underlying `ArrayBuffer`, which it compares by value.
 */
class FakeStore {
  constructor(rows = new Map()) {
    this.rows = rows;
    this.calls = { get: 0, writeBatch: 0, iterate: 0 };
    /** The size of every batch it was handed, newest last. */
    this.batchSizes = [];
    /** Set to a message to make the next `writeBatch` reject. */
    this.failWriteWith = null;
    /** Awaited inside `writeBatch` before anything lands, if set. */
    this.duringWrite = null;
  }

  static hex(key) {
    assert.ok(key instanceof Uint8Array, 'a key must cross as a Uint8Array');
    return Buffer.from(key).toString('hex');
  }

  async get(key) {
    this.calls.get += 1;
    const found = this.rows.get(FakeStore.hex(key));
    return found === undefined ? null : found;
  }

  /**
   * The whole batch or none of it — the same promise a real IndexedDB
   * transaction makes. Nothing is applied until every entry has been checked,
   * so a rejection cannot leave a half-written store behind to be mistaken for
   * a working one.
   */
  async writeBatch(entries) {
    this.calls.writeBatch += 1;
    assert.ok(Array.isArray(entries), 'a batch must cross as an Array');
    this.batchSizes.push(entries.length);
    if (this.duringWrite) await this.duringWrite();
    if (this.failWriteWith) throw new Error(this.failWriteWith);

    const staged = [];
    for (const entry of entries) {
      assert.ok(Array.isArray(entry) && entry.length === 2, 'an entry is [key, value|null]');
      const [key, value] = entry;
      assert.ok(
        value === null || value instanceof Uint8Array,
        'a value must cross as a Uint8Array or null for a delete',
      );
      staged.push([FakeStore.hex(key), value]);
    }
    for (const [key, value] of staged) {
      if (value === null) this.rows.delete(key);
      else this.rows.set(key, value);
    }
  }

  async iterate(prefix) {
    this.calls.iterate += 1;
    const wanted = FakeStore.hex(prefix);
    return [...this.rows.entries()]
      .filter(([key]) => key.startsWith(wanted))
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
      .map(([key, value]) => [Uint8Array.from(Buffer.from(key, 'hex')), value]);
  }

  /** A second store object over the same rows — a restart, not a copy. */
  reopen() {
    return new FakeStore(this.rows);
  }
}

// ---- Identities -------------------------------------------------------------

function issuer() {
  return new TestIssuer(new Uint8Array(32).fill(7));
}

function device(iss, actorId, deviceId, seedByte) {
  const seed = new Uint8Array(32).fill(seedByte);
  const token = iss.issue(actorId, deviceId, signingKeyPublicKey(seed), NOW, NOW + LIFETIME);
  return { seed, token, held: accountIdentityPublicKey(testAccountKey(actorId)) };
}

function openOn(store, iss, dev) {
  return MlsClient.open(iss.publishedJson(), dev.token, dev.seed, store, dev.held);
}

// ---- The tests --------------------------------------------------------------

test('the package exports the persistent door', () => {
  assert.equal(typeof MlsClient.open, 'function', 'MlsClient.open is a static');
  assert.equal(typeof MlsClient.prototype.flush, 'function');
  assert.ok(
    Object.getOwnPropertyDescriptor(MlsClient.prototype, 'pendingWrites')?.get,
    'pendingWrites is a getter',
  );
});

test('a group survives dropping the client and reopening on the same store', async () => {
  const iss = issuer();
  const ada = device(iss, 'actor-ada', 'device-ada', 1);
  const bo = device(iss, 'actor-bo', 'device-bo', 2);

  const store = new FakeStore();
  const first = await openOn(store, iss, ada);

  // Bo is ephemeral: one durable side is enough to prove the point, and it
  // keeps the assertion about what came back off the disk unambiguous.
  const boClient = new MlsClient(iss.publishedJson(), bo.token, bo.seed, bo.held);

  const group = enc.encode('group-persistent');
  first.createGroup(group);
  const added = first.addMember(group, boClient.generateKeyPackage());
  assert.equal(added.epoch, 1);
  first.mergePendingCommit(group); // standing in for the delivery service's yes
  boClient.joinFromWelcome(added.welcome);

  assert.ok(first.pendingWrites > 0, 'a created group is owed to the store');
  await first.flush();
  assert.equal(first.pendingWrites, 0, 'a flush clears what it wrote');
  assert.ok(store.rows.size > 0, 'and the store really has rows');

  // The tab closes.
  first.free();

  // A new tab, a new store object, the same rows.
  const restarted = store.reopen();
  const second = await openOn(restarted, iss, ada);

  assert.deepEqual(
    second.groupIds().map((id) => dec.decode(id)),
    ['group-persistent'],
    'the reopened client knows which groups it is in',
  );
  assert.equal(second.epoch(group), 1, 'at the epoch it left off at');
  assert.equal(second.roster(group).length, 2);

  // The real proof: the ratchet came back, not just the metadata.
  const fromBo = boClient.encrypt(group, enc.encode('still here?'));
  const heard = second.processMessage(group, fromBo);
  assert.equal(heard.kind, 'application');
  assert.equal(dec.decode(heard.plaintext), 'still here?');
  assert.equal(heard.sender.deviceId, 'device-bo');

  // And it can still speak, which needs its own signature key back.
  await second.flush();
  const reply = second.encrypt(group, enc.encode('still here.'));
  const back = boClient.processMessage(group, reply);
  assert.equal(dec.decode(back.plaintext), 'still here.');

  second.free();
  boClient.free();
});

test('open reads the schema stamp before it downloads the store', async () => {
  const iss = issuer();
  const ada = device(iss, 'actor-ada', 'device-ada', 1);

  const store = new FakeStore();
  const client = await openOn(store, iss, ada);
  await client.flush();
  client.free();

  const rowsBefore = store.rows.size;
  const reopened = store.reopen();
  const second = await openOn(reopened, iss, ada);
  const owed = second.pendingWrites;
  second.free();

  assert.equal(reopened.calls.get, 1, 'exactly one get: the stamp');
  assert.equal(reopened.calls.iterate, 1, 'exactly one iterate: everything else');

  // Reopening an unchanged store writes nothing. `Client::new` checks the
  // signature key on every open (so a store holding another key cannot leave
  // OpenMLS unable to find this device's key) but writes it only when what is
  // stored differs (mls/core/src/group.rs). A rewrite of the identical key is
  // what held SQLite's write lock across every group load on iOS
  // (docs/mls-core.md §Storage layout); the Rust half of this
  // is `reopening_a_store_writes_nothing` in mls/core/tests/persistence.rs.
  assert.equal(owed, 0, 'nothing owed after a reopen');
  assert.equal(reopened.calls.writeBatch, 0, 'no batch');
  assert.equal(store.rows.size, rowsBefore, 'and no row was added by reopening');
});

// The reason `writeBatch` exists instead of a `put` per key. A commit's worth
// of MLS state is a dozen keys that are ONE state — tree, context, epoch
// secrets, group state — and a host that writes them in separate transactions
// can be interrupted between two of them into a group that loads as absent.
// Nothing in Rust can see how many transactions the host opened, so the thing
// to assert is the only thing visible from here: it was handed over as one
// call.
test('everything a commit writes crosses in a single batch', async () => {
  const iss = issuer();
  const ada = device(iss, 'actor-ada', 'device-ada', 1);
  const bo = device(iss, 'actor-bo', 'device-bo', 2);

  const store = new FakeStore();
  const client = await openOn(store, iss, ada);
  const boClient = new MlsClient(iss.publishedJson(), bo.token, bo.seed, bo.held);
  await client.flush();

  const group = enc.encode('group-atomic');
  client.createGroup(group);
  client.addMember(group, boClient.generateKeyPackage());
  client.mergePendingCommit(group);

  const owed = client.pendingWrites;
  assert.ok(owed > 1, 'a group plus a commit is more than one key');

  const batchesBefore = store.calls.writeBatch;
  await client.flush();
  assert.equal(store.calls.writeBatch - batchesBefore, 1, 'one call, not one per key');
  assert.equal(store.batchSizes.at(-1), owed, 'carrying every owed key');

  client.free();
  boClient.free();
});

// `pendingWrites` is what a caller reads to decide whether it is safe to let
// the tab go, so it has to stay non-zero for the whole duration of the write.
// Dropping the moment the drain picks the work up would make it read "safe"
// during precisely the window it exists to warn about.
test('pendingWrites stays truthful until the store says the batch landed', async () => {
  const iss = issuer();
  const ada = device(iss, 'actor-ada', 'device-ada', 1);

  const store = new FakeStore();
  const client = await openOn(store, iss, ada);
  await client.flush();

  client.createGroup(enc.encode('group-inflight'));
  const owed = client.pendingWrites;
  assert.ok(owed > 0);

  let duringWrite = null;
  store.duringWrite = async () => {
    duringWrite = client.pendingWrites;
  };
  await client.flush();

  assert.equal(duringWrite, owed, 'mid-write, every key is still owed');
  assert.equal(client.pendingWrites, 0, 'and zero only once the store answered');

  client.free();
});

test('a store written by a newer schema is refused, not guessed at', async () => {
  const iss = issuer();
  const ada = device(iss, 'actor-ada', 'device-ada', 1);

  const store = new FakeStore();
  const client = await openOn(store, iss, ada);
  await client.flush();
  client.free();

  // Forge a stamp from the future. The stamp is the ONLY key whose bytes this
  // test knows, and it knows them because the layout is a published contract:
  // version byte, namespace, 0x1f, key (docs/mls-core.md §Storage layout).
  const stampKey = FakeStore.hex(enc.encode('\x01meta\x1fschema'));
  assert.ok(store.rows.has(stampKey), 'the stamp is where the layout says');
  store.rows.set(stampKey, new Uint8Array([2]));

  const refused = store.reopen();
  await assert.rejects(
    () => openOn(refused, iss, ada),
    /schema version 2/,
    'it says which version it found',
  );
  assert.equal(refused.calls.iterate, 0, 'and it never downloaded the store');
});

test('a store that refuses a write leaves the work owed, not lost', async () => {
  const iss = issuer();
  const ada = device(iss, 'actor-ada', 'device-ada', 1);

  const store = new FakeStore();
  const client = await openOn(store, iss, ada);
  await client.flush();

  client.createGroup(enc.encode('group-unwritable'));
  const owed = client.pendingWrites;
  assert.ok(owed > 0);

  store.failWriteWith = 'QuotaExceededError';
  await assert.rejects(() => client.flush(), /QuotaExceededError/);
  assert.equal(client.pendingWrites, owed, 'every key is still owed');
  assert.equal(store.rows.has(FakeStore.hex(enc.encode('\x01meta\x1fschema'))), true);

  // The disk frees up.
  store.failWriteWith = null;
  await client.flush();
  assert.equal(client.pendingWrites, 0);

  const reopened = store.reopen();
  const second = await openOn(reopened, iss, ada);
  assert.deepEqual(
    second.groupIds().map((id) => dec.decode(id)),
    ['group-unwritable'],
    'and the group that nearly did not persist, did',
  );

  client.free();
  second.free();
});

test('an ephemeral client owes nothing and flushing it is not an error', async () => {
  const iss = issuer();
  const ada = device(iss, 'actor-ada', 'device-ada', 1);
  const client = new MlsClient(iss.publishedJson(), ada.token, ada.seed, ada.held);

  client.createGroup(enc.encode('group-ephemeral'));
  assert.equal(client.pendingWrites, 0);
  await client.flush();

  client.free();
});

test('a store object missing a method is named, not silently tolerated', async () => {
  const iss = issuer();
  const ada = device(iss, 'actor-ada', 'device-ada', 1);

  await assert.rejects(
    () => MlsClient.open(iss.publishedJson(), ada.token, ada.seed, { get: async () => null }, ada.held),
    /`iterate` method/,
    'the missing method is named',
  );
});

test('a store row read before a refused one is wiped from the module memory', async () => {
  const iss = issuer();
  const ada = device(iss, 'actor-ada', 'device-ada', 1);
  const memory = wasm.__wasm?.memory;
  assert.ok(memory instanceof WebAssembly.Memory, 'the nodejs build exports its memory');

  // A value as a store holds an epoch's secrets: the needle sits well inside
  // it, past where the allocator writes its own bookkeeping into a freed block.
  const needle = enc.encode('store-row-needle-0123456789abcdef');
  const value = new Uint8Array(4096);
  for (let at = 0; at + needle.length <= value.length; at += needle.length) value.set(needle, at);
  const found = () => {
    const bytes = Buffer.from(memory.buffer);
    let n = 0;
    for (let at = bytes.indexOf(needle); at !== -1; at = bytes.indexOf(needle, at + 1)) n++;
    return n;
  };
  assert.equal(found(), 0, 'the needle is not in the module before the read');

  const store = {
    get: async () => null,
    writeBatch: async () => {},
    // The first row is read into the module; the second is refused.
    iterate: async () => [
      [enc.encode('\x01kv\x1frow'), value],
      [enc.encode('\x01kv\x1fnext'), 'not bytes'],
    ],
  };
  await assert.rejects(
    () => MlsClient.open(iss.publishedJson(), ada.token, ada.seed, store, ada.held),
    /a value from `iterate` must be a Uint8Array/,
  );
  assert.equal(found(), 0, 'a block the refused read freed still holds the row it read');
});
