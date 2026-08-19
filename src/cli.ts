#!/usr/bin/env node
/**
 * pqattest CLI.
 *
 *   pqattest keygen [--out <file>]     Generate an ML-DSA-65 key pair.
 *   pqattest verify <ledger-file>      Independently verify every actor's
 *                                      chain in a JSONL ledger file. Exits
 *                                      non-zero if any chain is broken or
 *                                      any signature fails — safe to wire
 *                                      into CI.
 */
import { writeFile } from 'node:fs/promises';
import { generateKeyPair, toHex } from './crypto.js';
import { verifyChain, type AttestationEntry } from './ledger.js';
import { FileLedgerStore } from './store.js';

function usage(): never {
  console.error('Usage:\n  pqattest keygen [--out <file>]\n  pqattest verify <ledger-file>');
  process.exit(2);
}

async function runKeygen(args: string[]): Promise<void> {
  const outIdx = args.indexOf('--out');
  const outPath = outIdx !== -1 ? args[outIdx + 1] : undefined;

  const keyPair = generateKeyPair();
  const output = {
    algorithm: 'ml-dsa-65',
    publicKey: toHex(keyPair.publicKey),
    secretKey: toHex(keyPair.secretKey),
  };

  if (outPath) {
    await writeFile(outPath, `${JSON.stringify(output, null, 2)}\n`, { mode: 0o600 });
    console.error(`Key pair written to ${outPath} (mode 0600). Keep the secret key private — never commit it.`);
  } else {
    console.log(JSON.stringify(output, null, 2));
    console.error('\nKeep secretKey private — never commit it or send it to a verifier.');
  }
}

async function runVerify(args: string[]): Promise<void> {
  const filePath = args[0];
  if (!filePath) usage();

  const store = new FileLedgerStore(filePath);
  const allEntries = await store.readAll();
  if (allEntries.length === 0) {
    console.error(`No entries found in ${filePath}`);
    process.exit(1);
  }

  const byActor = new Map<string, AttestationEntry[]>();
  for (const entry of allEntries) {
    const bucket = byActor.get(entry.actorId) ?? [];
    bucket.push(entry);
    byActor.set(entry.actorId, bucket);
  }

  let allValid = true;
  for (const [actorId, entries] of byActor) {
    entries.sort((a, b) => a.seq - b.seq);
    const result = verifyChain(entries);
    allValid &&= result.valid;

    const status = result.valid ? 'VALID' : 'INVALID';
    console.log(`${actorId}: ${status} (${result.totalEntries} entries)`);
    if (result.brokenAtSeq !== undefined) {
      console.log(`  chain broken at seq ${result.brokenAtSeq}`);
    }
    if (result.invalidSignatureAtSeq !== undefined) {
      console.log(`  invalid signature at seq ${result.invalidSignatureAtSeq}`);
    }
  }

  process.exit(allValid ? 0 : 1);
}

async function main(): Promise<void> {
  const [command, ...args] = process.argv.slice(2);
  switch (command) {
    case 'keygen':
      await runKeygen(args);
      break;
    case 'verify':
      await runVerify(args);
      break;
    default:
      usage();
  }
}

main().catch((err: unknown) => {
  console.error(err instanceof Error ? err.message : err);
  process.exit(1);
});
