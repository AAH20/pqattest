/**
 * Hash-chained, PQ-signed attestation ledger.
 *
 * Each entry commits to the previous entry's chain hash, so reordering or
 * altering any entry breaks every chain hash after it (tamper-evidence).
 * Each entry is also individually signed with the actor's ML-DSA-65 key, so
 * a verifier can confirm *who* produced it, independent of chain integrity
 * (tamper-evidence proves the log wasn't altered after the fact; the
 * signature proves a specific key holder produced each entry in the first
 * place).
 *
 * SHA-256 chains the entries. That's a deliberate, different choice from the
 * ML-DSA signatures: chain-hashing only needs collision resistance to do its
 * job (detect reordering/tampering), and SHA-256's 128-bit security margin
 * against Grover's algorithm is still solid for that. The part that actually
 * needs to resist a future quantum adversary — proving a specific key
 * produced a specific entry, potentially verified years later — is the
 * signature, which is why that part, and only that part, is post-quantum.
 */
import { createHash } from 'node:crypto';
import { sign, verify, toHex, fromHex, ALGORITHM, type KeyPair } from './crypto.js';

export const GENESIS_HASH = '0'.repeat(64);

export interface AttestationEntry {
  seq: number;
  actorId: string;
  actionType: string;
  summary: string;
  /** SHA-256 of the full payload, not the payload itself — keeps the ledger
   * itself free of potentially sensitive action content while still binding
   * the entry to it. Store the real payload wherever your app already does;
   * this is what lets a verifier confirm a specific payload was the one
   * attested, without the ledger being a copy of your data. */
  payloadHash: string;
  actionHash: string;
  prevHash: string;
  chainHash: string;
  signature: string;
  publicKey: string;
  algorithm: string;
  timestamp: string;
}

export interface LedgerStore {
  getLast(actorId: string): Promise<AttestationEntry | undefined>;
  append(entry: AttestationEntry): Promise<void>;
  list(actorId: string): Promise<AttestationEntry[]>;
}

function sha256Hex(input: string): string {
  return createHash('sha256').update(input).digest('hex');
}

export interface RecordActionInput {
  store: LedgerStore;
  actorId: string;
  actionType: string;
  summary: string;
  /** Arbitrary JSON-serializable payload; only its hash is stored. */
  payload: unknown;
  keyPair: KeyPair;
}

/** Compute and sign the next entry for `actorId`, and append it to `store`. */
export async function recordAction(input: RecordActionInput): Promise<AttestationEntry> {
  const last = await input.store.getLast(input.actorId);
  const seq = (last?.seq ?? 0) + 1;
  const prevHash = last?.chainHash ?? GENESIS_HASH;
  const payloadHash = sha256Hex(JSON.stringify(input.payload));
  const actionHash = sha256Hex(
    JSON.stringify({ actionType: input.actionType, summary: input.summary, payloadHash, seq }),
  );
  const chainHash = sha256Hex(`${prevHash}:${actionHash}`);
  const signature = toHex(sign(new TextEncoder().encode(chainHash), input.keyPair.secretKey));

  const entry: AttestationEntry = {
    seq,
    actorId: input.actorId,
    actionType: input.actionType,
    summary: input.summary,
    payloadHash,
    actionHash,
    prevHash,
    chainHash,
    signature,
    publicKey: toHex(input.keyPair.publicKey),
    algorithm: ALGORITHM,
    timestamp: new Date().toISOString(),
  };

  await input.store.append(entry);
  return entry;
}

export interface VerifyResult {
  valid: boolean;
  totalEntries: number;
  /** `seq` of the first entry whose chain hash doesn't match, if any. */
  brokenAtSeq: number | undefined;
  /** `seq` of the first entry whose signature doesn't verify, if any. */
  invalidSignatureAtSeq: number | undefined;
}

/**
 * Independently verify a chain of entries: no store, no network, no trust in
 * whoever produced the log required. Entries must be in ascending `seq`
 * order for the actor being verified (callers building from a `LedgerStore`
 * should already have this from `list`).
 */
export function verifyChain(entries: readonly AttestationEntry[]): VerifyResult {
  let brokenAtSeq: number | undefined;
  let invalidSignatureAtSeq: number | undefined;

  for (const [i, entry] of entries.entries()) {
    // Recompute actionHash from the entry's own claimed fields first. Without
    // this, chainHash only proves *some* action_hash was chained in at this
    // position — not that action_hash genuinely corresponds to this entry's
    // actionType/summary/payloadHash/seq. An editor who leaves actionHash
    // untouched could otherwise rewrite the human-readable summary in place
    // and still pass the chain-hash and signature checks below.
    const recomputedActionHash = sha256Hex(
      JSON.stringify({ actionType: entry.actionType, summary: entry.summary, payloadHash: entry.payloadHash, seq: entry.seq }),
    );
    const expectedPrev = i === 0 ? GENESIS_HASH : entries[i - 1]!.chainHash;
    const recomputedChainHash = sha256Hex(`${expectedPrev}:${recomputedActionHash}`);

    if (
      recomputedActionHash !== entry.actionHash ||
      entry.prevHash !== expectedPrev ||
      recomputedChainHash !== entry.chainHash
    ) {
      brokenAtSeq = entry.seq;
      break;
    }
    const signatureValid = verify(
      fromHex(entry.signature),
      new TextEncoder().encode(entry.chainHash),
      fromHex(entry.publicKey),
    );
    if (!signatureValid) {
      invalidSignatureAtSeq = entry.seq;
      break;
    }
  }

  return {
    valid: brokenAtSeq === undefined && invalidSignatureAtSeq === undefined,
    totalEntries: entries.length,
    brokenAtSeq,
    invalidSignatureAtSeq,
  };
}
