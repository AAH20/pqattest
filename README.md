# pqattest

Post-quantum-signed, hash-chained provenance for AI agent actions.

Agentic AI is now writing code, calling tools, moving money, and touching production infrastructure with less human review at every step. The audit trail for what an agent actually did is usually a database row with a timestamp — trusted because you trust the database, not because anyone can independently prove it wasn't altered after the fact. And the signatures most logging/provenance tools use today (Ed25519, ECDSA) are vulnerable to harvest-now-decrypt-later: record a signed log today, forge a signature retroactively once a cryptographically relevant quantum computer exists. An audit trail is exactly the kind of artifact that has to stay verifiable for years, not just "soon after" it was written.

`pqattest` gives every agent action a hash-chained, ML-DSA-65 (FIPS 204 / CRYSTALS-Dilithium) signed entry — independently verifiable by anyone, with no need to trust the party that logged it.

## What this actually is

Two things, honestly scoped:

**A real, working core (this release):**
- ML-DSA-65 signing and verification via [`@noble/post-quantum`](https://github.com/paulmillr/noble-post-quantum) — a real, audited implementation of the NIST-standardized algorithm (FIPS 204), not a custom scheme.
- A hash-chained ledger format: each entry commits to the previous entry's chain hash (tamper-evident — altering or reordering any entry breaks every chain hash after it) and is individually PQ-signed (proves *which key holder* produced it, independent of chain integrity).
- A transport-agnostic wrapper (`attested()`) that turns any async function into an attested one — works with any agent framework, since every one of them comes down to "call a function, get a result."
- A zero-dependency default store (append-only JSONL file) and a `LedgerStore` interface anyone can implement against Postgres, Supabase, or anything else.
- A `verify` CLI that checks a whole ledger file's chain and signature integrity with no trust in whoever wrote it — safe to run in CI.

**Roadmap (not yet shipped — don't assume these exist):**
- An official MCP adapter (tool-call interception at the protocol level, not just the function-call level `attested()` already covers).
- A LangChain / LangGraph adapter.
- Threshold/multi-signer attestation for actions requiring more than one agent's sign-off.

If you need the second list today, it isn't here yet — open an issue or a PR.

## Why this exists, and where it comes from

This isn't a from-scratch cryptographic experiment. The signing primitive is the same NIST-standardized ML-DSA-65 used in:
- [`GRC_Claw`'s `quantum-resistant-crypto` package](https://github.com/AAH20/GRC_Claw/tree/main/packages/quantum-resistant-crypto) (same `@noble/post-quantum` dependency)
- [`AAH_PostQuantum_Cryptography`](https://github.com/AAH20/AAH_PostQuantum_Cryptography) (the OQS/liboqs path — same NIST standard, independent implementation, cross-verifiable signatures)
- The agent attestation ledger already running in production on [a2zsoc.com](https://a2zsoc.com)

`pqattest` is a generalized, standalone extraction of that same pattern — with one deliberate improvement over the production version it's descended from: **the signing key stays with whoever performs the action, never with whoever verifies it.** A server that both holds the signing key and logs the actions only proves "the server says this happened" — the server is the same party you'd need to trust anyway. Real non-repudiation requires the key to live with the actor, not the verifier.

## Install

```bash
npm install pqattest
```

## Quick start

```typescript
import { generateKeyPair, FileLedgerStore, attested, verifyChain } from 'pqattest';

// Generate once per agent, keep the secret key with the agent process.
// Never send it to whatever verifies the log later.
const keyPair = generateKeyPair();

const store = new FileLedgerStore('./agent-ledger.jsonl');

const deleteRecord = attested(
  async (recordId: string) => {
    // ... your actual tool logic ...
    return { deleted: recordId };
  },
  {
    store,
    actorId: 'agent-42',
    keyPair,
    actionType: 'delete_record',
    describe: (recordId) => `delete record ${recordId}`,
  },
);

await deleteRecord('rec_123'); // recorded, hash-chained, and signed automatically

// Independent verification — no trust in the agent or the store required:
const entries = await store.list('agent-42');
const result = verifyChain(entries);
console.log(result.valid); // true
```

Or from the command line:

```bash
npx pqattest keygen --out agent-key.json
npx pqattest verify ./agent-ledger.jsonl
```

`verify` exits `0` if every actor's chain is fully valid, `1` otherwise — wire it into CI to catch a tampered or corrupted ledger before it's trusted anywhere downstream.

## Design notes

**Why SHA-256 for chaining, but ML-DSA for signing?** Different jobs. Chain-hashing only needs collision resistance to detect reordering or tampering — SHA-256's 128-bit security margin against Grover's algorithm is still solid for that. The part that needs to resist a *future* quantum adversary is the signature: proving a specific key produced a specific entry, potentially checked years after the fact. That's why only the signature, not the hash chain, is post-quantum — using ML-DSA everywhere would cost more without buying anything the threat model needs.

**Why is the payload hashed, not stored?** The ledger entry commits to `sha256(payload)`, not the payload itself. That keeps the ledger free of potentially sensitive action content while still binding each entry to exactly one payload — store the real payload wherever your application already does, and use the hash to prove a specific stored payload is the one that was attested.

**Why does a thrown error still get attested?** A failed or refused action is still part of an agent's provenance trail — arguably the part an auditor cares about most. `attested()` records the outcome either way, then re-throws so your own error handling is unaffected.

## API

```typescript
generateKeyPair(): KeyPair
sign(message: Uint8Array, secretKey: Uint8Array): Uint8Array
verify(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): boolean

recordAction(input: RecordActionInput): Promise<AttestationEntry>
verifyChain(entries: readonly AttestationEntry[]): VerifyResult

class FileLedgerStore implements LedgerStore   // default, zero-dependency
interface LedgerStore { getLast, append, list } // implement your own backend

attested(fn, options): wrapped function          // transport-agnostic action wrapper
```

Full types in [`src/`](./src).

## Contributing

PRs welcome, especially toward the roadmap above — an MCP adapter is the most valuable near-term contribution. Please open an issue describing the change before a large PR.

```bash
npm install
npm run build
npm test
```

## License

Apache 2.0 — see [LICENSE](LICENSE).

---

Author: Ahmed Hassan ([A2Z SOC](https://a2zsoc.com))
