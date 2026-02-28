import {
  scalarMul,
  scalarInv,
  scalarToHex,
  CURVE_ORDER,
} from '../../../crypto/secp256k1';
import {
  paillierDecrypt,
  PaillierPrivateKey,
} from '../../../crypto/paillier';
import { SigningSessionState } from '../SigningSession';
import { SignRound3Payload } from '../../../network/protocol/Message';
import { SigningError } from '../../../utils/errors';

/**
 * Lagrange basis coefficient L_i(0) for party myIdx in the signing subset.
 * otherIdxs contains the DKG party indices of all other signers.
 *
 * L_i(0) = prod_{j ∈ otherIdxs}( (0-j) / (i-j) ) mod n
 */
export function lagrangeCoeff(myIdx: number, otherIdxs: number[]): bigint {
  let num = 1n;
  let den = 1n;
  for (const j of otherIdxs) {
    const jBig = BigInt(j);
    const myBig = BigInt(myIdx);
    num = (num * ((CURVE_ORDER - jBig) % CURVE_ORDER)) % CURVE_ORDER;
    den = (den * ((myBig - jBig + CURVE_ORDER) % CURVE_ORDER)) % CURVE_ORDER;
  }
  return scalarMul(num, scalarInv(den));
}

/**
 * GG20 Signing Round 3: compute and broadcast delta_i share only.
 *
 * After receiving all Round 2 MtA ciphertexts, party i decrypts them using
 * their own Paillier private key and builds their additive shares:
 *
 *   delta_i = k_i * gamma_i
 *           + sum_{j≠i} Dec_{N_i}(deltaEnc_j)   [k_i * gamma_j + beta_ji from peer j]
 *           + sum_{j≠i} (−beta_d for j)           [kept in Round 2]
 *
 *   sigma_i = k_i * L_i * x_i
 *           + sum_{j≠i} Dec_{N_i}(sigmaEnc_j)   [k_i * L_j*x_j + beta_sji from peer j]
 *           + sum_{j≠i} (−beta_s for j)
 *
 * Security: only delta_i is broadcast; sigma_i stays private and is used
 * internally in Round 4 (broadcasting sigma_i would leak key-share information).
 *
 * Correctness (2-party, parties A and B):
 *   delta_A + delta_B = k_A*gamma_A + (k_A*gamma_B+β_BA) + (−β_AB)
 *                     + k_B*gamma_B + (k_B*gamma_A+β_AB) + (−β_BA)
 *                     = (k_A+k_B)*(gamma_A+gamma_B) = K*Gamma  ✓
 *   sigma_A + sigma_B = K * (L_A*x_A + L_B*x_B) = K*x  ✓
 */
export function executeSignRound3(
  state: SigningSessionState,
  keyShare: bigint,   // x_i: this party's tweaked Shamir secret share
): {
  updatedState: SigningSessionState;
  broadcast: SignRound3Payload;
} {
  if (!state.myKi || !state.myGammaI ||
      state.myPaillierN === undefined ||
      state.myPaillierLambda === undefined ||
      state.myPaillierMu === undefined) {
    throw new SigningError('Rounds 1 and 2 must be complete before Round 3');
  }

  const myNodeId = state.signers[state.mySignerIndex - 1].nodeId;
  const myPartyIndex = state.signers[state.mySignerIndex - 1].partyIndex;
  const otherPartyIndices = state.signers
    .filter((_, i) => i !== state.mySignerIndex - 1)
    .map((s) => s.partyIndex);

  const L_i = lagrangeCoeff(myPartyIndex, otherPartyIndices);
  const LiXi = scalarMul(L_i, keyShare);

  const paillierKey: PaillierPrivateKey = {
    n: state.myPaillierN,
    n2: state.myPaillierN * state.myPaillierN,
    lambda: state.myPaillierLambda,
    mu: state.myPaillierMu,
  };

  // Start with own k_i * gamma_i and k_i * L_i * x_i
  let deltaI = scalarMul(state.myKi, state.myGammaI);
  let sigmaI = scalarMul(state.myKi, LiXi);

  // Add decrypted MtA contributions from each peer
  for (const [fromNodeId, r2data] of state.round2Received) {
    const deltaEnc = BigInt('0x' + r2data.deltaEnc.replace(/^0x/, ''));
    const sigmaEnc = BigInt('0x' + r2data.sigmaEnc.replace(/^0x/, ''));

    // Validate ciphertexts are within the valid Paillier ciphertext space [1, N²)
    const N_i_sq = state.myPaillierN * state.myPaillierN;
    if (deltaEnc < 1n || deltaEnc >= N_i_sq) {
      throw new SigningError(`MtA deltaEnc from ${fromNodeId} is out of valid Paillier range`);
    }
    if (sigmaEnc < 1n || sigmaEnc >= N_i_sq) {
      throw new SigningError(`MtA sigmaEnc from ${fromNodeId} is out of valid Paillier range`);
    }

    // Decrypt: k_i * gamma_j + beta_ji  (encrypted under N_i by peer j)
    const deltaRaw = paillierDecrypt(paillierKey, deltaEnc);
    const sigmaRaw = paillierDecrypt(paillierKey, sigmaEnc);

    // Reduce Paillier plaintext (in [0, N)) to the curve scalar field
    const deltaContrib = deltaRaw % CURVE_ORDER;
    const sigmaContrib = sigmaRaw % CURVE_ORDER;

    deltaI = (deltaI + deltaContrib) % CURVE_ORDER;
    sigmaI = (sigmaI + sigmaContrib) % CURVE_ORDER;

    // Add own −beta terms kept from Round 2 (our additive share from the other direction MtA)
    const betaDelta = state.myBetaDelta.get(fromNodeId);
    const betaSigma = state.myBetaSigma.get(fromNodeId);
    if (betaDelta !== undefined) deltaI = (deltaI + betaDelta) % CURVE_ORDER;
    if (betaSigma !== undefined) sigmaI = (sigmaI + betaSigma) % CURVE_ORDER;
  }

  const updatedState: SigningSessionState = {
    ...state,
    status: 'round3',
    myDeltaI: deltaI,
    mySigmaI: sigmaI,
  };

  // Only broadcast delta_i — sigma_i is kept secret and used in Round 4
  const broadcast: SignRound3Payload = {
    sessionId: state.sessionId,
    fromNodeId: myNodeId,
    partyIndex: state.mySignerIndex,
    deltaShare: scalarToHex(deltaI),
  };

  return { updatedState, broadcast };
}

export function recordRound3(
  state: SigningSessionState,
  payload: SignRound3Payload
): SigningSessionState {
  // Equivocation check: reject duplicate messages from the same peer
  if (state.round3Received.has(payload.fromNodeId)) {
    throw new SigningError(`Equivocation detected: Round 3 duplicate from ${payload.fromNodeId}`);
  }

  const round3Received = new Map(state.round3Received);
  round3Received.set(payload.fromNodeId, {
    deltaShare: payload.deltaShare,
  });
  return { ...state, round3Received };
}

export function isSignRound3Complete(state: SigningSessionState): boolean {
  return state.round3Received.size === state.signers.length - 1;
}
