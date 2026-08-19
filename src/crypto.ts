/**
 * Post-quantum signing primitives.
 *
 * ML-DSA-65 (FIPS 204 / CRYSTALS-Dilithium), via @noble/post-quantum — a real,
 * audited, pure-JS implementation of the NIST-standardized algorithm, not a
 * custom scheme. Same standard, same interoperable signatures, as the OQS
 * (liboqs) path in https://github.com/AAH20/AAH_PostQuantum_Cryptography and
 * the wrapper in https://github.com/AAH20/GRC_Claw/tree/main/packages/quantum-resistant-crypto.
 *
 * Classical schemes (Ed25519, ECDSA) are vulnerable to "harvest now, decrypt
 * later": an adversary can record a signed log today and forge signatures
 * retroactively once a cryptographically relevant quantum computer exists.
 * An agent-action provenance log is exactly the kind of artifact that needs
 * to remain independently verifiable for years — audit trails, compliance
 * evidence, and incident forensics don't get to assume the verifier runs
 * "soon after" the signature was made.
 */
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';

export const ALGORITHM = 'ml-dsa-65' as const;

export interface KeyPair {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
}

/**
 * Generate a new ML-DSA-65 key pair.
 *
 * The secret key is meant to live with whatever process performs actions on
 * an agent's behalf — it should never be transmitted to, or stored by, the
 * party that verifies the log. That's what makes a signature here evidence
 * of *what a specific key holder did*, not just *what a server claims
 * happened*. (Contrast a server-custodied signing key: that only proves the
 * server produced a signature, not that it faithfully represents the agent's
 * actions — the server is the same party you'd need to trust anyway.)
 */
export function generateKeyPair(): KeyPair {
  const keys = ml_dsa65.keygen();
  return { publicKey: keys.publicKey, secretKey: keys.secretKey };
}

/** Sign an arbitrary message with an ML-DSA-65 secret key. */
export function sign(message: Uint8Array, secretKey: Uint8Array): Uint8Array {
  return ml_dsa65.sign(message, secretKey);
}

/**
 * Verify an ML-DSA-65 signature. Never throws — a malformed signature or key
 * is simply invalid, the same as one that doesn't match.
 */
export function verify(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): boolean {
  try {
    return ml_dsa65.verify(signature, message, publicKey);
  } catch {
    return false;
  }
}

export function toHex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('hex');
}

export function fromHex(hex: string): Uint8Array {
  return new Uint8Array(Buffer.from(hex, 'hex'));
}
