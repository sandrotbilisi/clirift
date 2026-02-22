import { secp256k1 } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { hmac } from '@noble/hashes/hmac';
import { randomBytes } from 'crypto';

export const CURVE_ORDER = secp256k1.CURVE.n;

// ---- Scalar (private key) arithmetic ----

/** Generate a cryptographically random secp256k1 scalar */
export function generateScalar(): bigint {
  let scalar: bigint;
  do {
    const bytes = randomBytes(32);
    scalar = BigInt('0x' + bytes.toString('hex'));
  } while (scalar === 0n || scalar >= CURVE_ORDER);
  return scalar;
}

/** Add two scalars modulo the curve order */
export function scalarAdd(a: bigint, b: bigint): bigint {
  return ((a + b) % CURVE_ORDER + CURVE_ORDER) % CURVE_ORDER;
}

/** Multiply two scalars modulo the curve order */
export function scalarMul(a: bigint, b: bigint): bigint {
  return (a * b) % CURVE_ORDER;
}

/** Negate a scalar modulo the curve order */
export function scalarNeg(a: bigint): bigint {
  return (CURVE_ORDER - (a % CURVE_ORDER)) % CURVE_ORDER;
}

/** Modular inverse of a scalar (using Fermat's little theorem: a^(n-2) mod n) */
export function scalarInv(a: bigint): bigint {
  return modPow(a, CURVE_ORDER - 2n, CURVE_ORDER);
}

function modPow(base: bigint, exp: bigint, mod: bigint): bigint {
  let result = 1n;
  base = base % mod;
  while (exp > 0n) {
    if (exp % 2n === 1n) result = (result * base) % mod;
    exp = exp >> 1n;
    base = (base * base) % mod;
  }
  return result;
}

// ---- EC Point arithmetic ----

export type Point = ReturnType<typeof secp256k1.ProjectivePoint.fromHex>;
export const G = secp256k1.ProjectivePoint.BASE;

/** Scalar multiplication: scalar * G */
export function scalarMulG(scalar: bigint): Point {
  return G.multiply(scalar);
}

/** Scalar multiplication: scalar * P */
export function scalarMulPoint(scalar: bigint, P: Point): Point {
  return P.multiply(scalar);
}

/** Add two EC points */
export function pointAdd(P: Point, Q: Point): Point {
  return P.add(Q);
}

/** Convert scalar to big-endian 32-byte hex */
export function scalarToHex(scalar: bigint): string {
  return scalar.toString(16).padStart(64, '0');
}

/** Parse hex scalar */
export function hexToScalar(hex: string): bigint {
  return BigInt('0x' + hex.replace(/^0x/, ''));
}

/** Compress a point to 33-byte hex */
export function pointToHex(P: Point): string {
  return Buffer.from(P.toRawBytes(true)).toString('hex');
}

/** Parse compressed point from hex */
export function hexToPoint(hex: string): Point {
  return secp256k1.ProjectivePoint.fromHex(hex);
}

/** Uncompressed point bytes (65 bytes, prefix 04) — used for ETH address derivation */
export function pointToUncompressedBytes(P: Point): Uint8Array {
  return P.toRawBytes(false);
}

// ---- HMAC-SHA256 utility ----

export function hmacSha256(key: Uint8Array | Buffer, ...messages: (Uint8Array | Buffer)[]): Uint8Array {
  const h = hmac.create(sha256, key);
  for (const m of messages) h.update(m);
  return h.digest();
}
