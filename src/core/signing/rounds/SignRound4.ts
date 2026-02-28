import {
  scalarMul,
  scalarInv,
  hexToScalar,
  scalarToHex,
  hexToPoint,
  pointAdd,
  pointToHex,
  scalarMulG,
  CURVE_ORDER,
} from '../../../crypto/secp256k1';
import { SigningSessionState } from '../SigningSession';
import { SignRound4Payload } from '../../../network/protocol/Message';
import { SigningError } from '../../../utils/errors';

/**
 * GG20 Signing Round 4: compute partial signature s_i.
 *
 * Now that all delta shares are known (from Round 3), every party can compute:
 *
 *   delta_sum = sum(delta_i) = K * Gamma
 *   R         = (1 / delta_sum) * Gamma*G = K^{-1} * G
 *   r         = R.x mod n
 *
 * Then each party computes their partial signature:
 *
 *   s_i = k_i * m + r * sigma_i
 *
 * where sigma_i is their share of K*x (from Round 3, kept private).
 *
 * Each party also broadcasts Delta_i = sigma_i * G so others can verify:
 *   s_i * G == m * (k_i*G) + r * Delta_i
 *
 * Final assembly (in finalize()):
 *   s = sum(s_i) = K*m + r*K*x = K*(m + r*x)
 *   Verify: s^{-1}*(m*G + r*P) = K^{-1}*G = R  ✓
 */
export function executeSignRound4(
  state: SigningSessionState,
  txHash: string,
): {
  updatedState: SigningSessionState;
  broadcast: SignRound4Payload;
  r: string;  // r value needed by finalize()
} {
  if (!state.myKi || !state.myGammaIPoint ||
      state.myDeltaI === undefined || state.mySigmaI === undefined) {
    throw new SigningError('Rounds 1-3 must be complete before Round 4');
  }

  const myNodeId = state.signers[state.mySignerIndex - 1].nodeId;
  const m = hexToScalar(txHash);

  // ── Aggregate delta shares → R ───────────────────────────────────────────

  let deltaSum = state.myDeltaI;
  for (const r3data of state.round3Received.values()) {
    deltaSum = (deltaSum + hexToScalar(r3data.deltaShare)) % CURVE_ORDER;
  }

  if (deltaSum === 0n) {
    throw new SigningError('deltaSum is zero — aborting to prevent division by zero');
  }

  // Gamma*G = sum of all gamma_i*G points
  let gammaPointSum = hexToPoint(state.myGammaIPoint);
  for (const r1data of state.round1Received.values()) {
    gammaPointSum = pointAdd(gammaPointSum, hexToPoint(r1data.gammaCommitment));
  }

  const deltaInv = scalarInv(deltaSum);
  const R = gammaPointSum.multiply(deltaInv);
  const rValue = R.toAffine().x % CURVE_ORDER;

  if (rValue === 0n) {
    throw new SigningError('r-value is zero — nonce produced degenerate R point, aborting');
  }

  const rHex = scalarToHex(rValue);

  // ── Partial signature s_i = k_i * m + r * sigma_i ────────────────────────

  const kiM = scalarMul(state.myKi, m);
  const rSigmaI = scalarMul(rValue, state.mySigmaI);
  const partialSig = (kiM + rSigmaI) % CURVE_ORDER;

  // Delta_i = sigma_i * G — broadcast so peers can verify our partial sig
  const sigmaCommitment = pointToHex(scalarMulG(state.mySigmaI));

  const updatedState: SigningSessionState = {
    ...state,
    status: 'round4',
    myPartialSig: partialSig,
    computedR: rHex,
  };

  const broadcast: SignRound4Payload = {
    sessionId: state.sessionId,
    fromNodeId: myNodeId,
    partyIndex: state.mySignerIndex,
    partialSig: scalarToHex(partialSig),
    sigmaCommitment,
  };

  return { updatedState, broadcast, r: rHex };
}

/**
 * Record a peer's Round 4 partial signature, verifying it before accepting.
 *
 * Verification: s_i * G == m * (k_i*G) + r * (sigma_i*G)
 * This detects malicious partial signatures without revealing any secrets.
 */
export function recordRound4(
  state: SigningSessionState,
  payload: SignRound4Payload,
  rHex: string,
): SigningSessionState {
  // Equivocation check: reject duplicate messages from the same peer
  if (state.round4Received.has(payload.fromNodeId)) {
    throw new SigningError(`Equivocation detected: Round 4 duplicate from ${payload.fromNodeId}`);
  }

  // Partial signature verification: s_i*G == m*(k_i*G) + r*(sigma_i*G)
  const kiCommitmentHex = state.peerKiCommitment.get(payload.fromNodeId);
  if (!kiCommitmentHex) {
    throw new SigningError(`Missing k_i commitment for ${payload.fromNodeId} — cannot verify partial sig`);
  }

  const m = hexToScalar(state.txHash);
  const r = hexToScalar(rHex);
  const si = hexToScalar(payload.partialSig);

  if (si === 0n || si >= CURVE_ORDER) {
    throw new SigningError(`Partial signature out of range from ${payload.fromNodeId}`);
  }

  const siG = scalarMulG(si);
  const kiG = hexToPoint(kiCommitmentHex);
  const DeltaI = hexToPoint(payload.sigmaCommitment);

  // s_i * G should equal m * (k_i*G) + r * Delta_i
  const rhs = kiG.multiply(m).add(DeltaI.multiply(r));
  if (!siG.equals(rhs)) {
    throw new SigningError(`Partial signature verification failed for ${payload.fromNodeId}`);
  }

  const round4Received = new Map(state.round4Received);
  round4Received.set(payload.fromNodeId, {
    partialSig: payload.partialSig,
    sigmaCommitment: payload.sigmaCommitment,
  });
  return { ...state, round4Received };
}

export function isSignRound4Complete(state: SigningSessionState): boolean {
  return state.round4Received.size === state.signers.length - 1;
}

/**
 * Assemble the final ECDSA signature from partial signatures.
 * s = sum(s_i) mod n, with EIP-2 low-s normalisation.
 */
export function assembleSignature(
  state: SigningSessionState,
  rHex: string,
): { r: string; s: string; v: number } {
  if (state.myPartialSig === undefined) {
    throw new SigningError('Round 4 not complete');
  }

  let sTotal = state.myPartialSig;
  for (const r4data of state.round4Received.values()) {
    sTotal = (sTotal + hexToScalar(r4data.partialSig)) % CURVE_ORDER;
  }

  // Recover R point to determine y-parity for the recovery bit.
  // Re-derive from gamma/delta aggregation (same computation as executeSignRound4).
  const gammaPoint = hexToPoint(state.myGammaIPoint!);
  let gammaSum = gammaPoint;
  for (const r1data of state.round1Received.values()) {
    gammaSum = gammaSum.add(hexToPoint(r1data.gammaCommitment));
  }

  let deltaSum = state.myDeltaI!;
  for (const r3data of state.round3Received.values()) {
    deltaSum = (deltaSum + hexToScalar(r3data.deltaShare)) % CURVE_ORDER;
  }

  const R = gammaSum.multiply(scalarInv(deltaSum));
  let yParity = Number(R.toAffine().y % 2n);

  // EIP-2 low-s normalisation
  const HALF_ORDER = CURVE_ORDER >> 1n;
  if (sTotal > HALF_ORDER) {
    sTotal = CURVE_ORDER - sTotal;
    yParity = 1 - yParity;
  }

  return {
    r: rHex,
    s: scalarToHex(sTotal),
    v: yParity + 27,
  };
}
