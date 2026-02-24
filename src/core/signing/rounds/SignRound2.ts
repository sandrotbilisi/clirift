import { privateDecrypt, constants } from 'crypto';
import {
  scalarMul,
  scalarToHex,
  hexToScalar,
  CURVE_ORDER,
} from '../../../crypto/secp256k1';
import { SigningSessionState } from '../SigningSession';
import { SignRound2Payload } from '../../../network/protocol/Message';

/**
 * GG20 Signing Round 2: MtA (Multiplicative-to-Additive) responses.
 *
 * Simplified MtA with beta = 0:
 *   Party i decrypts peer j's RSA-encrypted k_j, then computes:
 *     alpha_ij = k_j * gamma_i
 *     delta_i  = k_i * gamma_i + sum_{j≠i}(k_j * gamma_i)
 *              = gamma_i * K   where K = sum(k_i) over all signers
 *
 * So delta_sum = K * Gamma, and R = (1/delta_sum) * Gamma*G = K^{-1} * G ✓
 *
 * We also store each decrypted k_j in peerKi so Round 3 can compute K.
 */
export function executeSignRound2(
  state: SigningSessionState,
  myPrivKeyPem: string
): {
  updatedState: SigningSessionState;
  broadcast: SignRound2Payload;
} {
  if (!state.myKi || !state.myGammaI) {
    throw new Error('Round 1 not complete');
  }

  const myNodeId = state.signers[state.mySignerIndex - 1].nodeId;

  // Start delta_i = k_i * gamma_i (mod n)
  let deltaI = scalarMul(state.myKi, state.myGammaI);

  // Store decrypted peer k_j values so Round 3 can compute K = sum(k_i)
  const peerKi = new Map<string, bigint>(state.peerKi ?? []);

  // Process received MtA ciphertexts from other parties.
  // Each peer encrypted their k_j using our RSA public key in Round 1.
  for (const [fromNodeId, r1Data] of state.round1Received) {
    if (r1Data.mtaCiphertext) {
      try {
        const decrypted = privateDecrypt(
          { key: myPrivKeyPem, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' },
          Buffer.from(r1Data.mtaCiphertext, 'base64')
        );
        const kj = hexToScalar(decrypted.toString('hex'));
        peerKi.set(fromNodeId, kj);

        // alpha_ij = k_j * gamma_i  (beta = 0, so no subtraction)
        const alpha = scalarMul(kj, state.myGammaI);
        deltaI = (deltaI + alpha) % CURVE_ORDER;
      } catch {
        // Decryption failed — peer may have used different encryption
      }
    }
  }

  const updatedState: SigningSessionState = {
    ...state,
    status: 'round2',
    myDeltaI: deltaI,
    peerKi,
  };

  const broadcast: SignRound2Payload = {
    sessionId: state.sessionId,
    fromNodeId: myNodeId,
    partyIndex: state.mySignerIndex,
    mtaResponse: '',
    deltaShare: scalarToHex(deltaI),
  };

  return { updatedState, broadcast };
}

export function recordRound2(
  state: SigningSessionState,
  payload: SignRound2Payload
): SigningSessionState {
  const round2Received = new Map(state.round2Received);
  round2Received.set(payload.fromNodeId, {
    mtaResponse: payload.mtaResponse,
    deltaShare: payload.deltaShare,
  });
  return { ...state, round2Received };
}

export function isSignRound2Complete(state: SigningSessionState): boolean {
  return state.round2Received.size === state.signers.length - 1;
}
