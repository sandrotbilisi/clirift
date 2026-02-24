import {
  scalarMul,
  scalarInv,
  scalarMulG,
  hexToPoint,
  pointAdd,
  pointToHex,
  hexToScalar,
  scalarToHex,
  CURVE_ORDER,
} from '../../../crypto/secp256k1';
import { SigningSessionState } from '../SigningSession';
import { SignRound3Payload } from '../../../network/protocol/Message';
import { SigningError } from '../../../utils/errors';

/**
 * GG20 Signing Round 3: Compute partial signatures.
 *
 * With beta=0 in Round 2, delta_i = gamma_i * K (where K = sum(k_j)).
 * So delta_sum = Gamma * K, and R = (1/delta_sum) * Gamma*G = K^{-1} * G.
 * r = R.x mod n.
 *
 * Each party needs: s_i = k_i * m + K * r * L_i * x_i
 * where L_i is the Lagrange coefficient for party i's DKG index in the signing subset.
 *
 * Sum: s = K*m + K*r*sum(L_i*x_i) = K*(m + r*x)  ✓
 * Verify: s^{-1}*(m*G + r*P) = K^{-1} * G = R     ✓
 */

/**
 * Lagrange basis polynomial L_i(0) evaluated at 0 for party myIdx
 * in a threshold signing subset. otherIdxs are the other DKG party indices.
 *
 * L_i(0) = prod_{j in otherIdxs}( (0-j) / (i-j) ) mod n
 */
function lagrangeCoeff(myIdx: number, otherIdxs: number[]): bigint {
  let num = 1n;
  let den = 1n;
  for (const j of otherIdxs) {
    const jBig = BigInt(j);
    const myBig = BigInt(myIdx);
    // (0 - j) mod n
    num = (num * ((CURVE_ORDER - jBig) % CURVE_ORDER)) % CURVE_ORDER;
    // (myIdx - j) mod n
    den = (den * ((myBig - jBig + CURVE_ORDER) % CURVE_ORDER)) % CURVE_ORDER;
  }
  return scalarMul(num, scalarInv(den));
}

export function executeSignRound3(
  state: SigningSessionState,
  keyShare: bigint,   // x_i: this party's Shamir secret share from DKG
  txHash: string      // 32-byte hash (hex) of the transaction to sign
): {
  updatedState: SigningSessionState;
  broadcast: SignRound3Payload;
} {
  if (!state.myKi || !state.myGammaI || !state.myGammaIPoint || !state.myDeltaI) {
    throw new SigningError('Rounds 1 and 2 must be complete before Round 3');
  }

  const myNodeId = state.signers[state.mySignerIndex - 1].nodeId;
  const m = hexToScalar(txHash);

  // ── Compute R = (1 / sum(delta_i)) * sum(gamma_i * G) ───────────────────

  let deltaSum = state.myDeltaI;
  for (const r2data of state.round2Received.values()) {
    deltaSum = (deltaSum + hexToScalar(r2data.deltaShare)) % CURVE_ORDER;
  }

  const myGammaPoint = hexToPoint(state.myGammaIPoint);
  let gammaPointSum = myGammaPoint;
  for (const r1data of state.round1Received.values()) {
    gammaPointSum = pointAdd(gammaPointSum, hexToPoint(r1data.gammaCommitment));
  }

  const deltaInv = scalarInv(deltaSum);
  const R = gammaPointSum.multiply(deltaInv);
  const RHex = pointToHex(R);

  const rValue = R.toAffine().x % CURVE_ORDER;
  const rHex = scalarToHex(rValue);

  // R_i = k_i * G  (used by peer for verification, if desired)
  const RShare = pointToHex(scalarMulG(state.myKi));

  // ── Compute K = k_i + sum(peer k_j from Round 2 MtA) ───────────────────

  let K = state.myKi;
  for (const kj of (state.peerKi ?? new Map()).values()) {
    K = (K + kj) % CURVE_ORDER;
  }

  // ── Lagrange coefficient for my DKG party index in the signing subset ──

  const myPartyIndex = state.signers[state.mySignerIndex - 1].partyIndex;
  const otherPartyIndices = state.signers
    .filter((_, i) => i !== state.mySignerIndex - 1)
    .map((s) => s.partyIndex);

  const L_i = lagrangeCoeff(myPartyIndex, otherPartyIndices);

  // ── Partial signature: s_i = k_i * m + K * r * L_i * x_i (mod n) ──────
  //
  //   Sum over all signers:
  //     s = K*m + K*r*(L_1*x_1 + L_2*x_2) = K*(m + r*x)
  //   Verification: s^{-1}*(m*G + r*P) = K^{-1}*G = R  ✓

  const kiM = scalarMul(state.myKi, m);
  const KrLiXi = scalarMul(scalarMul(K, rValue), scalarMul(L_i, keyShare));
  const partialSig = (kiM + KrLiXi) % CURVE_ORDER;

  const updatedState: SigningSessionState = {
    ...state,
    status: 'round3',
    R: RHex,
    r: rHex,
    myRShare: RShare,
    myPartialSig: partialSig,
  };

  const broadcast: SignRound3Payload = {
    sessionId: state.sessionId,
    fromNodeId: myNodeId,
    partyIndex: state.mySignerIndex,
    partialSig: scalarToHex(partialSig),
    RShare,
  };

  return { updatedState, broadcast };
}

export function recordRound3(
  state: SigningSessionState,
  payload: SignRound3Payload
): SigningSessionState {
  const round3Received = new Map(state.round3Received);
  round3Received.set(payload.fromNodeId, {
    partialSig: payload.partialSig,
    RShare: payload.RShare,
  });
  return { ...state, round3Received };
}

export function isSignRound3Complete(state: SigningSessionState): boolean {
  return state.round3Received.size === state.signers.length - 1;
}

/**
 * Assemble the final ECDSA signature from partial signatures.
 * s = sum(s_i) mod n
 */
export function assembleSignature(
  state: SigningSessionState
): { r: string; s: string; v: number } {
  if (!state.myPartialSig || !state.r) {
    throw new SigningError('Round 3 not complete');
  }

  let sTotal = state.myPartialSig;
  for (const r3data of state.round3Received.values()) {
    sTotal = (sTotal + hexToScalar(r3data.partialSig)) % CURVE_ORDER;
  }

  const RPoint = hexToPoint(state.R!);
  const yParity = Number(RPoint.toAffine().y % 2n); // 0 = even, 1 = odd
  const v = yParity + 27; // 27 or 28

  return {
    r: state.r,
    s: scalarToHex(sTotal),
    v,
  };
}
