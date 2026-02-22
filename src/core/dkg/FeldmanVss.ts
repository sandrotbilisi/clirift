import {
  scalarMulG,
  scalarMulPoint,
  pointAdd,
  pointToHex,
  hexToPoint,
  Point,
} from '../../crypto/secp256k1';

/**
 * Feldman Verifiable Secret Sharing (VSS).
 *
 * Each party publishes commitments to their polynomial coefficients:
 *   C_j = [a_{j,0}*G, a_{j,1}*G, ..., a_{j,t-1}*G]
 *
 * Any other party can verify their received Shamir share f_j(i) against C_j:
 *   f_j(i) * G == sum_k( C_{j,k} * i^k )
 */

/** Compute Feldman coefficient commitments for a polynomial */
export function feldmanCommitments(coefficients: bigint[]): string[] {
  return coefficients.map((c) => pointToHex(scalarMulG(c)));
}

/**
 * Verify that a Shamir share is consistent with the Feldman commitments.
 *
 * @param share f_j(i) — the share from party j intended for party i
 * @param partyIndex i — the receiving party's index (1-indexed)
 * @param commitments [C_{j,0}, C_{j,1}, ...] — Feldman commitments from party j
 */
export function verifyFeldmanShare(
  share: bigint,
  partyIndex: number,
  commitments: string[]
): boolean {
  // LHS: f_j(i) * G
  const lhs = scalarMulG(share);

  // RHS: sum_k( C_{j,k} * i^k )
  let rhs: Point | null = null;
  let iPow = 1n;
  const iBig = BigInt(partyIndex);

  for (const commitHex of commitments) {
    const C = hexToPoint(commitHex);
    const term = iPow === 1n ? C : scalarMulPoint(iPow, C);

    rhs = rhs === null ? term : pointAdd(rhs, term);
    iPow = (iPow * iBig) % BigInt('0x' + 'f'.repeat(64)); // just multiply in integers; no mod needed for the exponent
  }

  if (!rhs) return false;

  return pointToHex(lhs) === pointToHex(rhs);
}

/**
 * Compute the combined public key (PK_master) from all parties' intercept commitments.
 * PK_master = sum_j( C_{j,0} ) = sum_j( a_{j,0} * G )
 */
export function combinePkMaster(allInterceptCommitments: string[]): string {
  let total: Point | null = null;

  for (const hex of allInterceptCommitments) {
    const P = hexToPoint(hex);
    total = total === null ? P : pointAdd(total, P);
  }

  if (!total) throw new Error('No commitments provided');
  return pointToHex(total);
}
