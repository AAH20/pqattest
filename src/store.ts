/**
 * Default `LedgerStore`: an append-only JSONL file, one entry per line.
 *
 * Zero external dependencies on purpose — the whole point of shipping a
 * default store is that `npm install pqattest` works standalone, with
 * nothing to provision. Anything with a database (Postgres, Supabase, a
 * cloud KV store) can implement `LedgerStore` directly; this one is for
 * everyone else, and for verifying the format itself.
 */
import { appendFile, readFile, mkdir } from 'node:fs/promises';
import { dirname } from 'node:path';
import type { AttestationEntry, LedgerStore } from './ledger.js';

export class FileLedgerStore implements LedgerStore {
  constructor(private readonly path: string) {}

  async getLast(actorId: string): Promise<AttestationEntry | undefined> {
    const entries = await this.list(actorId);
    return entries.at(-1);
  }

  async append(entry: AttestationEntry): Promise<void> {
    await mkdir(dirname(this.path), { recursive: true });
    await appendFile(this.path, `${JSON.stringify(entry)}\n`, 'utf8');
  }

  async list(actorId: string): Promise<AttestationEntry[]> {
    const all = await this.readAll();
    return all.filter((entry) => entry.actorId === actorId).sort((a, b) => a.seq - b.seq);
  }

  /** All entries in the file, every actor, in file order. Useful for `pqattest verify` on a whole log. */
  async readAll(): Promise<AttestationEntry[]> {
    let raw: string;
    try {
      raw = await readFile(this.path, 'utf8');
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === 'ENOENT') return [];
      throw err;
    }
    return raw
      .split('\n')
      .filter((line) => line.trim().length > 0)
      .map((line) => JSON.parse(line) as AttestationEntry);
  }
}
