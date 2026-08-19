import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPair } from '../src/crypto.js';
import { verifyChain, type AttestationEntry, type LedgerStore } from '../src/ledger.js';
import { attested } from '../src/wrap.js';

class MemoryLedgerStore implements LedgerStore {
  entries: AttestationEntry[] = [];
  async getLast(actorId: string) {
    return this.entries.filter((e) => e.actorId === actorId).at(-1);
  }
  async append(entry: AttestationEntry) {
    this.entries.push(entry);
  }
  async list(actorId: string) {
    return this.entries.filter((e) => e.actorId === actorId).sort((a, b) => a.seq - b.seq);
  }
}

test('a successful wrapped call is attested with its real result', async () => {
  const store = new MemoryLedgerStore();
  const keyPair = generateKeyPair();

  const addTwo = attested(async (a: number, b: number) => a + b, {
    store,
    actorId: 'calc-agent',
    keyPair,
    actionType: 'add',
  });

  const result = await addTwo(2, 3);
  assert.equal(result, 5);

  const entries = await store.list('calc-agent');
  assert.equal(entries.length, 1);
  assert.equal(entries[0]!.actionType, 'add');
  // payloadHash commits to the real args/result, but only its hash is stored
  // by design — assert the chain still verifies rather than peeking inside it.
  assert.equal(verifyChain(entries).valid, true);
});

test('a throwing wrapped call is still attested, and still throws', async () => {
  const store = new MemoryLedgerStore();
  const keyPair = generateKeyPair();

  const alwaysFails = attested(
    async () => {
      throw new Error('boom');
    },
    { store, actorId: 'flaky-agent', keyPair, actionType: 'risky_call' },
  );

  await assert.rejects(() => alwaysFails(), /boom/);

  const entries = await store.list('flaky-agent');
  assert.equal(entries.length, 1, 'the attempt is attested even though it failed');
  assert.equal(verifyChain(entries).valid, true, 'the ledger entry itself is still a valid, well-formed attestation');
});

test('consecutive calls chain correctly through the wrapper', async () => {
  const store = new MemoryLedgerStore();
  const keyPair = generateKeyPair();
  const echo = attested(async (msg: string) => msg, { store, actorId: 'echo-agent', keyPair, actionType: 'echo' });

  await echo('one');
  await echo('two');
  await echo('three');

  const entries = await store.list('echo-agent');
  assert.deepEqual(entries.map((e) => e.seq), [1, 2, 3]);
  assert.equal(verifyChain(entries).valid, true);
});

test('a custom describe() function is used for the summary', async () => {
  const store = new MemoryLedgerStore();
  const keyPair = generateKeyPair();
  const fn = attested(async (userId: string) => `deleted ${userId}`, {
    store,
    actorId: 'admin-agent',
    keyPair,
    actionType: 'delete_user',
    describe: (userId: string) => `delete user ${userId}`,
  });

  await fn('user-42');
  const entries = await store.list('admin-agent');
  assert.equal(entries[0]!.summary, 'delete user user-42');
});
