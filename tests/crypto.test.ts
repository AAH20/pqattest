import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPair, sign, verify } from '../src/crypto.js';

test('a genuine signature verifies', () => {
  const keyPair = generateKeyPair();
  const message = new TextEncoder().encode('hello quantum-resistant world');
  const signature = sign(message, keyPair.secretKey);
  assert.equal(verify(signature, message, keyPair.publicKey), true);
});

test('verification fails against a tampered message', () => {
  const keyPair = generateKeyPair();
  const message = new TextEncoder().encode('original message');
  const signature = sign(message, keyPair.secretKey);
  const tampered = new TextEncoder().encode('original massage');
  assert.equal(verify(signature, tampered, keyPair.publicKey), false);
});

test('verification fails against the wrong public key', () => {
  const keyPair = generateKeyPair();
  const impostor = generateKeyPair();
  const message = new TextEncoder().encode('who signed this');
  const signature = sign(message, keyPair.secretKey);
  assert.equal(verify(signature, message, impostor.publicKey), false);
});

test('verification fails gracefully on garbage input instead of throwing', () => {
  const garbageSignature = new Uint8Array([1, 2, 3]);
  const garbageKey = new Uint8Array([4, 5, 6]);
  const message = new TextEncoder().encode('anything');
  assert.equal(verify(garbageSignature, message, garbageKey), false);
});
