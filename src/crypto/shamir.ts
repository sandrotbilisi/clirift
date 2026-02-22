import { randomBytes } from 'crypto';
import { CURVE_ORDER, hexToScalar, scalarToHex } from './secp256k1';

/**
 * Shamir Secret Sharing over the secp256k1 scalar field (Z_n).
 *
 * Implements a (t, n) threshold scheme:
 * - Secret s is split into n shares
 * - Any t shares can reconstruct s
 * - Fewer than t shares reveal nothing about s
 *
 * Polynomial: f(x) = s + a_1*x + a_2*x^2 + ... + a_{t-1}*x^{t-1} (mod n)
 * Share for party j (1-indexed): f(j)
 */

/** Generate a random polynomial with secret s as the constant term */
export function generatePolynomial(secret: bigint, threshold: number): bigint[] {
  if (threshold < 2) throw new Error('Threshold must be at least 2');
  const coefficients = [secret];
  for (let i = 1; i < threshold; i++) {
    const bytes = randomBytes(32);
    const coeff = BigInt('0x' + bytes.toString('hex')) % CURVE_ORDER;
    coefficients.push(coeff);
  }
  return coefficients;
}

/**
 * Evaluate polynomial at x (1-indexed party index).
 * f(x) = sum_i(coefficients[i] * x^i) mod n
 */
export function evaluatePolynomial(coefficients: bigint[], x: number): bigint {
  let result = 0n;
  let xPow = 1n;
  const xBig = BigInt(x);

  for (const coeff of coefficients) {
    result = (result + coeff * xPow) % CURVE_ORDER;
    xPow = (xPow * xBig) % CURVE_ORDER;
  }

  return ((result % CURVE_ORDER) + CURVE_ORDER) % CURVE_ORDER;
}

/**
 * Lagrange interpolation coefficient for party i among a set of party indices.
 * lambda_i = product_{j != i}( j / (j - i) ) mod n
 *
 * @param partyIndex 1-indexed index of the party we are computing the coefficient for
 * @param allIndices 1-indexed indices of ALL participating parties
 */
export function lagrangeCoefficient(partyIndex: number, allIndices: number[]): bigint {
  let num = 1n;
  let den = 1n;

  for (const j of allIndices) {
    if (j === partyIndex) continue;
    num = (num * BigInt(j)) % CURVE_ORDER;
    den = (den * BigInt(j - partyIndex)) % CURVE_ORDER;
  }

  // Handle negative denominator
  den = ((den % CURVE_ORDER) + CURVE_ORDER) % CURVE_ORDER;

  // Modular inverse of denominator
  const denInv = modInv(den, CURVE_ORDER);

  return (num * denInv) % CURVE_ORDER;
}

function modInv(a: bigint, m: bigint): bigint {
  // Extended Euclidean algorithm
  let [old_r, r] = [a, m];
  let [old_s, s] = [1n, 0n];

  while (r !== 0n) {
    const q = old_r / r;
    [old_r, r] = [r, old_r - q * r];
    [old_s, s] = [s, old_s - q * s];
  }

  return ((old_s % m) + m) % m;
}

/**
 * Reconstruct the secret from a threshold subset of shares.
 * @param shares Map of partyIndex (1-indexed) → share value
 */
export function reconstructSecret(shares: Map<number, bigint>): bigint {
  const allIndices = Array.from(shares.keys());
  let secret = 0n;

  for (const [index, share] of shares) {
    const lambda = lagrangeCoefficient(index, allIndices);
    secret = (secret + share * lambda) % CURVE_ORDER;
  }

  return ((secret % CURVE_ORDER) + CURVE_ORDER) % CURVE_ORDER;
}

/** Serialize share as hex */
export function shareToHex(share: bigint): string {
  return scalarToHex(share);
}

/** Deserialize share from hex */
export function hexToShare(hex: string): bigint {
  return hexToScalar(hex);
}
