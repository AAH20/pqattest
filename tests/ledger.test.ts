import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPair } from '../src/crypto.js';
import { GENESIS_HASH, recordAction, verifyChain, type AttestationEntry, type LedgerStore } from '../src/ledger.js';

class MemoryLedgerStore implements LedgerStore {
  private entries: AttestationEntry[] = [];

  async getLast(actorId: string): Promise<AttestationEntry | undefined> {
    return this.entries.filter((e) => e.actorId === actorId).at(-1);
  }

  async append(entry: AttestationEntry): Promise<void> {
    this.entries.push(entry);
  }

  async list(actorId: string): Promise<AttestationEntry[]> {
    return this.entries.filter((e) => e.actorId === actorId).sort((a, b) => a.seq - b.seq);
  }
}

test('a chain of genuine entries verifies as valid', async () => {
  const store = new MemoryLedgerStore();
  const keyPair = generateKeyPair();

  for (let i = 0; i < 5; i++) {
    await recordAction({
      store,
      actorId: 'agent-1',
      actionType: 'tool_call',
      summary: `step ${i}`,
      payload: { i },
      keyPair,
    });
  }

  const entries = await store.list('agent-1');
  assert.equal(entries.length, 5);
  assert.equal(entries[0]!.prevHash, GENESIS_HASH);

  const result = verifyChain(entries);
  assert.equal(result.valid, true);
  assert.equal(result.totalEntries, 5);
  assert.equal(result.brokenAtSeq, undefined);
  assert.equal(result.invalidSignatureAtSeq, undefined);
});

test('mutating a middle entry\'s content breaks the chain from that point on', async () => {
  const store = new MemoryLedgerStore();
  const keyPair = generateKeyPair();

  for (let i = 0; i < 4; i++) {
    await recordAction({ store, actorId: 'agent-2', actionType: 'tool_call', summary: `step ${i}`, payload: { i }, keyPair });
  }

  const entries = await store.list('agent-2');
  // Tamper with entry 2's summary without recomputing its hashes or signature —
  // exactly what an attacker editing a stored log after the fact would do.
  const tampered = entries.map((e, i) => (i === 1 ? { ...e, summary: 'forged summary' } : e));

  const result = verifyChain(tampered);
  assert.equal(result.valid, false);
  assert.equal(result.brokenAtSeq, tampered[1]!.seq);
});

test('a valid chain hash with a forged signature is caught independently', async () => {
  const store = new MemoryLedgerStore();
  const keyPair = generateKeyPair();
  const impostor = generateKeyPair();

  await recordAction({ store, actorId: 'agent-3', actionType: 'tool_call', summary: 'step 0', payload: {}, keyPair });
  const entries = await store.list('agent-3');

  // Chain hash itself is untouched and internally consistent; only the claimed
  // signer is swapped for a different real key pair's public key.
  const forged = [{ ...entries[0]!, publicKey: Buffer.from(impostor.publicKey).toString('hex') }];

  const result = verifyChain(forged);
  assert.equal(result.valid, false);
  assert.equal(result.invalidSignatureAtSeq, forged[0]!.seq);
  assert.equal(result.brokenAtSeq, undefined, 'chain-hash linkage itself was not touched');
});

test('an empty chain is trivially valid', () => {
  const result = verifyChain([]);
  assert.equal(result.valid, true);
  assert.equal(result.totalEntries, 0);
});

test('reordering two entries breaks the chain', async () => {
  const store = new MemoryLedgerStore();
  const keyPair = generateKeyPair();

  for (let i = 0; i < 3; i++) {
    await recordAction({ store, actorId: 'agent-4', actionType: 'tool_call', summary: `step ${i}`, payload: { i }, keyPair });
  }
  const entries = await store.list('agent-4');
  const reordered = [entries[1]!, entries[0]!, entries[2]!];

  const result = verifyChain(reordered);
  assert.equal(result.valid, false);
});
