import { sha256 } from '@noble/hashes/sha256';
import {
  scalarMulG,
  pointToHex,
  hexToPoint,
  scalarMulPoint,
  generateScalar,
  scalarToHex,
  hexToScalar,
  CURVE_ORDER,
  Point,
} from './secp256k1';

/**
 * Pedersen commitment: C = Hash(coefficients_points || blinding_factor)
 *
 * Used in DKG Round 1 to commit to the polynomial coefficients
 * before revealing them in Round 2.
 */

/** Compute Pedersen commitment to an array of EC points + blinding factor */
export function pedersenCommit(
  coefficientPoints: Point[],
  blindingFactor: bigint
): { commitment: string; blindingFactor: string } {
  const h = sha256.create();

  for (const P of coefficientPoints) {
    h.update(Buffer.from(pointToHex(P), 'hex'));
  }

  h.update(Buffer.from(scalarToHex(blindingFactor), 'hex'));

  return {
    commitment: Buffer.from(h.digest()).toString('hex'),
    blindingFactor: scalarToHex(blindingFactor),
  };
}

/** Verify that commitment opens correctly to the provided data */
export function pedersenVerify(
  commitment: string,
  coefficientPoints: Point[],
  blindingFactor: string
): boolean {
  const { commitment: recomputed } = pedersenCommit(
    coefficientPoints,
    hexToScalar(blindingFactor)
  );
  return recomputed === commitment;
}

/** Generate a fresh random blinding factor */
export function generateBlindingFactor(): bigint {
  return generateScalar();
}

/**
 * Schnorr proof of knowledge of secret scalar x such that P = x * G.
 * Non-interactive (Fiat-Shamir transform) using SHA-256.
 *
 * Prove: { (x, P) : P = x * G }
 */
export function schnorrProve(
  secret: bigint,
  publicPoint: Point,
  context: string = ''
): { R: string; s: string } {
  // Random nonce k
  const k = generateScalar();
  const R = scalarMulG(k);

  // Challenge: e = H(R || P || context)
  const e = schnorrChallenge(R, publicPoint, context);

  // Response: s = k - e * secret (mod n)
  const es = (e * secret) % CURVE_ORDER;
  const s = ((k - es) % CURVE_ORDER + CURVE_ORDER) % CURVE_ORDER;

  return { R: pointToHex(R), s: scalarToHex(s) };
}

/**
 * Verify a Schnorr proof.
 * Check: s * G + e * P == R
 */
export function schnorrVerify(
  publicPoint: Point,
  proof: { R: string; s: string },
  context: string = ''
): boolean {
  const R = hexToPoint(proof.R);
  const s = hexToScalar(proof.s);

  const e = schnorrChallenge(R, publicPoint, context);

  // s*G + e*P
  const lhs = scalarMulG(s).add(scalarMulPoint(e, publicPoint));

  return pointToHex(lhs) === proof.R;
}

function schnorrChallenge(R: Point, P: Point, context: string): bigint {
  const h = sha256.create();
  h.update(Buffer.from(pointToHex(R), 'hex'));
  h.update(Buffer.from(pointToHex(P), 'hex'));
  if (context) h.update(Buffer.from(context, 'utf8'));
  const hash = h.digest();
  return BigInt('0x' + Buffer.from(hash).toString('hex')) % CURVE_ORDER;
}
