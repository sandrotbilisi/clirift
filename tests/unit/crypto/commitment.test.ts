import { describe, it, expect } from 'vitest';
import {
  pedersenCommit,
  pedersenVerify,
  schnorrProve,
  schnorrVerify,
  generateBlindingFactor,
} from '../../../src/crypto/commitment';
import { generateScalar, scalarMulG } from '../../../src/crypto/secp256k1';

describe('Pedersen Commitment', () => {
  it('commitment verifies correctly with correct blinding factor', () => {
    const secret = generateScalar();
    const point = scalarMulG(secret);
    const blinding = generateBlindingFactor();

    const { commitment, blindingFactor } = pedersenCommit([point], blinding);
    const valid = pedersenVerify(commitment, [point], blindingFactor);

    expect(valid).toBe(true);
  });

  it('commitment does not verify with wrong blinding factor', () => {
    const secret = generateScalar();
    const point = scalarMulG(secret);
    const blinding = generateBlindingFactor();
    const wrongBlinding = generateBlindingFactor();

    const { commitment } = pedersenCommit([point], blinding);
    const valid = pedersenVerify(commitment, [point], wrongBlinding.toString(16).padStart(64, '0'));

    expect(valid).toBe(false);
  });

  it('commitment changes when points change', () => {
    const p1 = scalarMulG(generateScalar());
    const p2 = scalarMulG(generateScalar());
    const blinding = generateBlindingFactor();

    const { commitment: c1 } = pedersenCommit([p1], blinding);
    const { commitment: c2 } = pedersenCommit([p2], blinding);

    expect(c1).not.toBe(c2);
  });
});

describe('Schnorr ZK Proof', () => {
  it('proves and verifies knowledge of discrete log', () => {
    const secret = generateScalar();
    const publicPoint = scalarMulG(secret);

    const proof = schnorrProve(secret, publicPoint, 'test-context');
    const valid = schnorrVerify(publicPoint, proof, 'test-context');

    expect(valid).toBe(true);
  });

  it('proof fails verification with wrong public point', () => {
    const secret = generateScalar();
    const publicPoint = scalarMulG(secret);
    const wrongPoint = scalarMulG(generateScalar());

    const proof = schnorrProve(secret, publicPoint, 'test-context');
    const valid = schnorrVerify(wrongPoint, proof, 'test-context');

    expect(valid).toBe(false);
  });

  it('proof fails with wrong context', () => {
    const secret = generateScalar();
    const publicPoint = scalarMulG(secret);

    const proof = schnorrProve(secret, publicPoint, 'context-A');
    const valid = schnorrVerify(publicPoint, proof, 'context-B');

    expect(valid).toBe(false);
  });
});
