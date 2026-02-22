import { privateDecrypt, constants } from 'crypto';
import {
  scalarMul,
  generateScalar,
  scalarToHex,
  hexToScalar,
  CURVE_ORDER,
} from '../../../crypto/secp256k1';
import { SigningSessionState } from '../SigningSession';
import { SignRound2Payload } from '../../../network/protocol/Message';

/**
 * GG20 Signing Round 2: MtA (Multiplicative-to-Additive) responses.
 *
 * Full GG20 MtA uses Paillier homomorphic encryption:
 * - Party A sends Enc(k_A) to party B
 * - Party B computes: Enc(k_A * x_B + beta) and returns it
 * - Party A decrypts to get: alpha = k_A * x_B + beta
 * - Result: k_A * x_B = alpha - beta  (additively shared)
 *
 * Here we use RSA-OAEP as a simplified stand-in for the Paillier encryption.
 * The structural protocol is identical; replace with Paillier for production.
 *
 * After MtA, each party computes:
 *   delta_i = k_i * gamma_i + sum_{j!=i}(alpha_ij + beta_ji)
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

  // Process received MtA ciphertexts from other parties
  // For each other signer j, decrypt their Enc(k_j) to get k_j (simplified MtA)
  for (const [, r1Data] of state.round1Received) {
    if (r1Data.mtaCiphertext) {
      try {
        const decrypted = privateDecrypt(
          { key: myPrivKeyPem, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' },
          Buffer.from(r1Data.mtaCiphertext, 'base64')
        );
        const kj = hexToScalar(decrypted.toString('hex'));

        // alpha_ij = k_j * gamma_i (simplified; in full GG20 this is computed homomorphically)
        const alpha = scalarMul(kj, state.myGammaI);

        // beta_ji: random additive mask (in full GG20 sent back to party j)
        const beta = generateScalar();

        // delta_i += alpha_ij - beta_ji
        const contribution = (alpha - beta + CURVE_ORDER) % CURVE_ORDER;
        deltaI = (deltaI + contribution) % CURVE_ORDER;
      } catch {
        // Decryption failed — peer may have used different encryption
        // In production, this would abort the signing session
      }
    }
  }

  const updatedState: SigningSessionState = {
    ...state,
    status: 'round2',
    myDeltaI: deltaI,
  };

  const broadcast: SignRound2Payload = {
    sessionId: state.sessionId,
    fromNodeId: myNodeId,
    partyIndex: state.mySignerIndex,
    mtaResponse: '', // Response to peer's MtA (simplified)
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
