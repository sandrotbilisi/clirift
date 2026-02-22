import { publicEncrypt, constants } from 'crypto';
import {
  generateScalar,
  scalarMulG,
  pointToHex,
} from '../../../crypto/secp256k1';
import { SigningSessionState } from '../SigningSession';
import { SignRound1Payload } from '../../../network/protocol/Message';

/**
 * GG20 Signing Round 1: Commitment phase.
 *
 * Each signer generates:
 * - k_i: random signing nonce
 * - gamma_i: random auxiliary nonce
 * - Publishes: gamma_i * G (commitment to gamma_i)
 * - Starts MtA for k_i with each other signer
 *
 * The MtA (Multiplicative-to-Additive) protocol converts
 * the product k_i * x_j into an additive share without revealing
 * k_i or x_j. Here we simplify to a placeholder ciphertext —
 * a full implementation would use Paillier homomorphic encryption.
 */
export function executeSignRound1(
  state: SigningSessionState,
  peerPubkeys: Map<string, string> // nodeId → RSA pubkey PEM (for MtA)
): {
  updatedState: SigningSessionState;
  broadcast: SignRound1Payload;
} {
  const ki = generateScalar();
  const gammaI = generateScalar();
  const gammaIG = scalarMulG(gammaI);
  const gammaCommitment = pointToHex(gammaIG);

  // MtA: We encrypt k_i for each peer signer using their public key.
  // In a full GG20 implementation this would be Paillier encryption.
  // Here we use RSA-OAEP as a placeholder (sufficient for the protocol structure).
  const mtaCiphertexts = new Map<string, string>();
  const myNodeId = state.signers[state.mySignerIndex - 1].nodeId;

  for (const signer of state.signers) {
    if (signer.nodeId === myNodeId) continue;
    const pubkey = peerPubkeys.get(signer.nodeId);
    if (!pubkey) continue;

    const kiBytes = Buffer.from(ki.toString(16).padStart(64, '0'), 'hex');
    const encrypted = publicEncrypt(
      { key: pubkey, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' },
      kiBytes
    );
    mtaCiphertexts.set(signer.nodeId, encrypted.toString('base64'));
  }

  // For the broadcast MtA ciphertext, we use the first peer's encrypted value
  // In a full implementation, each signer sends their ciphertext to each peer individually
  const firstPeerCiphertext = Array.from(mtaCiphertexts.values())[0] ?? '';

  const updatedState: SigningSessionState = {
    ...state,
    status: 'round1',
    myKi: ki,
    myGammaI: gammaI,
    myGammaIPoint: gammaCommitment,
    mtaCiphertexts,
  };

  const broadcast: SignRound1Payload = {
    sessionId: state.sessionId,
    fromNodeId: myNodeId,
    partyIndex: state.mySignerIndex,
    gammaCommitment,
    mtaCiphertext: firstPeerCiphertext,
  };

  return { updatedState, broadcast };
}

export function recordRound1(
  state: SigningSessionState,
  payload: SignRound1Payload
): SigningSessionState {
  const round1Received = new Map(state.round1Received);
  round1Received.set(payload.fromNodeId, {
    gammaCommitment: payload.gammaCommitment,
    mtaCiphertext: payload.mtaCiphertext,
  });
  return { ...state, round1Received };
}

export function isSignRound1Complete(state: SigningSessionState): boolean {
  return state.round1Received.size === state.signers.length - 1;
}
