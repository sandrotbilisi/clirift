import {
  generateScalar,
  scalarMulG,
  pointToHex,
  schnorrProve,
  schnorrVerify,
} from '../../../crypto/secp256k1';
import {
  generatePaillierKey,
  paillierEncrypt,
  bigintToHex,
  validatePaillierModulus,
} from '../../../crypto/paillier';
import { SigningSessionState } from '../SigningSession';
import { SignRound1Payload } from '../../../network/protocol/Message';
import { SigningError } from '../../../utils/errors';

/**
 * GG20 Signing Round 1: Paillier setup + commitment phase.
 *
 * Each signer:
 * - Generates k_i (signing nonce) and gamma_i (auxiliary nonce)
 * - Generates a fresh Paillier keypair (N_i, lambda_i, mu_i)
 * - Encrypts k_i under their own Paillier key: C_i = Enc_{N_i}(k_i)
 * - Broadcasts: gamma_i*G, k_i*G, N_i, C_i, and Schnorr PoK proofs for gamma_i and k_i
 *
 * Security additions vs basic GG20:
 *   - gammaProof: Schnorr PoK of gamma_i (prevents equivocation on gamma_i*G)
 *   - kiProof: Schnorr PoK of k_i (commitment binding)
 *   - kiCommitment (k_i*G): enables partial-sig verification in Round 4
 */
export async function executeSignRound1(
  state: SigningSessionState,
): Promise<{
  updatedState: SigningSessionState;
  broadcast: SignRound1Payload;
}> {
  const ki = generateScalar();
  const gammaI = generateScalar();
  const gammaIG = scalarMulG(gammaI);
  const gammaCommitment = pointToHex(gammaIG);
  const kiCommitment = pointToHex(scalarMulG(ki));

  // Generate a fresh Paillier keypair for this session's MtA
  const paillierKey = await generatePaillierKey(1024);

  // Encrypt k_i under our own Paillier key so peers can do MtA without learning k_i
  const kiEnc = paillierEncrypt(paillierKey.n, ki);

  // Schnorr proofs of knowledge — domain-separated per session
  const gammaProof = schnorrProve(gammaI, gammaCommitment, `GG20-GAMMA-${state.sessionId}`);
  const kiProof = schnorrProve(ki, kiCommitment, `GG20-KI-${state.sessionId}`);

  const myNodeId = state.signers[state.mySignerIndex - 1].nodeId;

  const updatedState: SigningSessionState = {
    ...state,
    status: 'round1',
    myKi: ki,
    myGammaI: gammaI,
    myGammaIPoint: gammaCommitment,
    myPaillierN: paillierKey.n,
    myPaillierLambda: paillierKey.lambda,
    myPaillierMu: paillierKey.mu,
  };

  const broadcast: SignRound1Payload = {
    sessionId: state.sessionId,
    fromNodeId: myNodeId,
    partyIndex: state.mySignerIndex,
    gammaCommitment,
    paillierN: bigintToHex(paillierKey.n),
    kiEnc: bigintToHex(kiEnc),
    kiCommitment,
    gammaProof,
    kiProof,
  };

  return { updatedState, broadcast };
}

export function recordRound1(
  state: SigningSessionState,
  payload: SignRound1Payload
): SigningSessionState {
  // Equivocation check: reject duplicate messages from the same peer
  if (state.round1Received.has(payload.fromNodeId)) {
    throw new SigningError(`Equivocation detected: Round 1 duplicate from ${payload.fromNodeId}`);
  }

  // Validate the peer's Paillier modulus before accepting it
  const N_j = BigInt('0x' + payload.paillierN.replace(/^0x/, ''));
  validatePaillierModulus(N_j);

  // Verify Schnorr proofs
  const gammaCtx = `GG20-GAMMA-${payload.sessionId}`;
  const kiCtx = `GG20-KI-${payload.sessionId}`;
  if (!schnorrVerify(payload.gammaCommitment, payload.gammaProof, gammaCtx)) {
    throw new SigningError(`Invalid gamma proof from ${payload.fromNodeId}`);
  }
  if (!schnorrVerify(payload.kiCommitment, payload.kiProof, kiCtx)) {
    throw new SigningError(`Invalid k_i proof from ${payload.fromNodeId}`);
  }

  const round1Received = new Map(state.round1Received);
  round1Received.set(payload.fromNodeId, {
    gammaCommitment: payload.gammaCommitment,
    paillierN: payload.paillierN,
    kiEnc: payload.kiEnc,
    kiCommitment: payload.kiCommitment,
  });

  const peerPaillierN = new Map(state.peerPaillierN);
  const peerKiEnc = new Map(state.peerKiEnc);
  const peerKiCommitment = new Map(state.peerKiCommitment);
  peerPaillierN.set(payload.fromNodeId, N_j);
  const kiEncBigint = BigInt('0x' + payload.kiEnc.replace(/^0x/, ''));
  if (kiEncBigint < 1n || kiEncBigint >= N_j * N_j) {
    throw new SigningError(`k_i ciphertext from ${payload.fromNodeId} is out of valid Paillier range`);
  }
  peerKiEnc.set(payload.fromNodeId, kiEncBigint);
  peerKiCommitment.set(payload.fromNodeId, payload.kiCommitment);

  return { ...state, round1Received, peerPaillierN, peerKiEnc, peerKiCommitment };
}

export function isSignRound1Complete(state: SigningSessionState): boolean {
  // Require BOTH: all peers sent their Round 1 AND our own async Paillier gen is done
  return state.round1Received.size === state.signers.length - 1 && state.myKi !== undefined;
}
