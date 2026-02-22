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
 * Each signer computes:
 *   R = (1/Σdelta) * Σ(delta_i * G)
 *   r = R.x mod n
 *   s_i = k_i * m + k_i * r * x_i  (where x_i is the key share)
 *
 * Note: In a full GG20 implementation, the x_i multiplication uses
 * the MtA-converted additive shares. Here we use x_i directly.
 */
export function executeSignRound3(
  state: SigningSessionState,
  keyShare: bigint,   // x_i: this party's key share
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

  // Compute R = (1 / sum(delta_i)) * sum(delta_i * G)
  // where gamma_i * G was broadcast as gammaCommitment in Round 1

  // Sum delta_i (scalars)
  let deltaSum = state.myDeltaI;
  for (const r2data of state.round2Received.values()) {
    deltaSum = (deltaSum + hexToScalar(r2data.deltaShare)) % CURVE_ORDER;
  }

  // Sum gamma_i * G (points)
  const myGammaPoint = hexToPoint(state.myGammaIPoint);
  let gammaPointSum = myGammaPoint;
  for (const r1data of state.round1Received.values()) {
    gammaPointSum = pointAdd(gammaPointSum, hexToPoint(r1data.gammaCommitment));
  }

  // R = (1 / deltaSum) * gammaPointSum
  const deltaInv = scalarInv(deltaSum);
  const R = gammaPointSum.multiply(deltaInv);
  const RHex = pointToHex(R);

  // r = R.x mod n
  const rValue = R.toAffine().x % CURVE_ORDER;
  const rHex = scalarToHex(rValue);

  // R_i = k_i * G
  const RShare = pointToHex(scalarMulG(state.myKi));

  // Partial signature: s_i = k_i * m + k_i * r * x_i (mod n)
  const kiM = scalarMul(state.myKi, m);
  const kiRXi = scalarMul(scalarMul(state.myKi, rValue), keyShare);
  const partialSig = (kiM + kiRXi) % CURVE_ORDER;

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

  // Determine recovery ID (v): try both 27 and 28
  // In production, use ecrecover to verify which v gives the correct address
  const v = 27; // simplified — real implementation should try both

  return {
    r: state.r,
    s: scalarToHex(sTotal),
    v,
  };
}
