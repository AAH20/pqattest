import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { generateKeyPair } from '../src/crypto.js';
import { recordAction, verifyChain } from '../src/ledger.js';
import { FileLedgerStore } from '../src/store.js';

async function withTempDir<T>(fn: (dir: string) => Promise<T>): Promise<T> {
  const dir = await mkdtemp(join(tmpdir(), 'pqattest-test-'));
  try {
    return await fn(dir);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

test('FileLedgerStore persists entries across separate instances', async () => {
  await withTempDir(async (dir) => {
    const path = join(dir, 'nested', 'ledger.jsonl');
    const keyPair = generateKeyPair();

    const writer = new FileLedgerStore(path);
    for (let i = 0; i < 3; i++) {
      await recordAction({ store: writer, actorId: 'agent-x', actionType: 'tool_call', summary: `step ${i}`, payload: { i }, keyPair });
    }

    // A fresh instance reading the same path sees exactly what was written —
    // the store is genuinely on disk, not just in the first instance's memory.
    const reader = new FileLedgerStore(path);
    const entries = await reader.list('agent-x');
    assert.equal(entries.length, 3);
    assert.equal(entries[2]!.seq, 3);

    const result = verifyChain(entries);
    assert.equal(result.valid, true);
  });
});

test('reading a nonexistent ledger file returns an empty list, not an error', async () => {
  await withTempDir(async (dir) => {
    const store = new FileLedgerStore(join(dir, 'does-not-exist.jsonl'));
    assert.deepEqual(await store.list('anyone'), []);
    assert.equal(await store.getLast('anyone'), undefined);
  });
});

test('multiple actors interleaved in one file are kept separate', async () => {
  await withTempDir(async (dir) => {
    const store = new FileLedgerStore(join(dir, 'ledger.jsonl'));
    const keyA = generateKeyPair();
    const keyB = generateKeyPair();

    await recordAction({ store, actorId: 'alice', actionType: 't', summary: 'a1', payload: {}, keyPair: keyA });
    await recordAction({ store, actorId: 'bob', actionType: 't', summary: 'b1', payload: {}, keyPair: keyB });
    await recordAction({ store, actorId: 'alice', actionType: 't', summary: 'a2', payload: {}, keyPair: keyA });

    const aliceEntries = await store.list('alice');
    const bobEntries = await store.list('bob');
    assert.equal(aliceEntries.length, 2);
    assert.equal(bobEntries.length, 1);
    // Each actor's own sequence starts at 1 independently.
    assert.deepEqual(aliceEntries.map((e) => e.seq), [1, 2]);
    assert.deepEqual(bobEntries.map((e) => e.seq), [1]);
  });
});
