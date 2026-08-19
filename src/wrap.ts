/**
 * Transport-agnostic attestation wrapper.
 *
 * `pqattest` doesn't assume MCP, LangChain, or any other agent framework —
 * every one of them ultimately comes down to "call an async function with
 * some arguments, get a result." `attested` wraps that function so every
 * call is hash-chained and PQ-signed automatically, regardless of what's
 * driving it. A thin MCP-specific adapter (or LangChain, or anything else)
 * is just this wrapper called from that framework's tool-call site — see
 * the roadmap in the README.
 */
import type { KeyPair } from './crypto.js';
import { recordAction, type LedgerStore } from './ledger.js';

export interface AttestOptions<Args extends unknown[]> {
  store: LedgerStore;
  actorId: string;
  keyPair: KeyPair;
  actionType: string;
  /** Human-readable summary of a call. Defaults to a truncated JSON dump of the arguments. */
  describe?: (...args: Args) => string;
}

function defaultDescribe(args: unknown[]): string {
  const dump = JSON.stringify(args);
  return dump.length > 200 ? `${dump.slice(0, 200)}…` : dump;
}

/**
 * Wrap `fn` so every call is recorded to `options.store` as a signed,
 * chained attestation entry — including the outcome (result or error), not
 * just the attempt. A thrown error is still attested, then re-thrown, so a
 * failed action is as much a part of the provenance trail as a successful
 * one.
 */
export function attested<Args extends unknown[], Result>(
  fn: (...args: Args) => Promise<Result>,
  options: AttestOptions<Args>,
): (...args: Args) => Promise<Result> {
  return async (...args: Args): Promise<Result> => {
    const summary = (options.describe ?? ((...a: Args) => defaultDescribe(a)))(...args);
    try {
      const result = await fn(...args);
      await recordAction({
        store: options.store,
        actorId: options.actorId,
        actionType: options.actionType,
        summary,
        payload: { args, result, ok: true },
        keyPair: options.keyPair,
      });
      return result;
    } catch (error) {
      await recordAction({
        store: options.store,
        actorId: options.actorId,
        actionType: options.actionType,
        summary,
        payload: { args, error: error instanceof Error ? error.message : String(error), ok: false },
        keyPair: options.keyPair,
      });
      throw error;
    }
  };
}
