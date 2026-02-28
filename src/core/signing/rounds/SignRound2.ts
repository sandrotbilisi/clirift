import {
  scalarMul,
  CURVE_ORDER,
  generateScalar,
} from '../../../crypto/secp256k1';
import {
  paillierMtA,
  bigintToHex,
} from '../../../crypto/paillier';
import { SigningSessionState } from '../SigningSession';
import { SignRound2Payload } from '../../../network/protocol/Message';
import { lagrangeCoeff } from './SignRound3';
import { SigningError } from '../../../utils/errors';

/**
 * GG20 Signing Round 2: Paillier MtA ciphertext exchange (P2P).
 *
 * For each peer j, party i computes two MtA ciphertexts using peer j's
 * Paillier public key N_j and their encrypted nonce Enc_{N_j}(k_j):
 *
 *   deltaEnc = Enc_{N_j}(k_j * gamma_i + beta_d)
 *   sigmaEnc = Enc_{N_j}(k_j * L_i * x_i + beta_s)
 *
 * Party j will decrypt these (using their private Paillier key) and add the
 * results to their delta_j and sigma_j sums respectively.
 *
 * Party i keeps −beta_d and −beta_s as their own additive shares:
 *   delta_i += −beta_d    (from this MtA with j)
 *   sigma_i += −beta_s    (from this MtA with j)
 *
 * Security: neither party learns the other's k_i or x_i.
 * The beta blinding terms ensure the ciphertexts reveal nothing about
 * k_j * gamma_i or k_j * L_i * x_i individually.
 */
export function executeSignRound2(
  state: SigningSessionState,
  keyShare: bigint,  // x_i: this party's Shamir secret share (already tweaked)
): {
  updatedState: SigningSessionState;
  /** One payload per peer nodeId — caller must use sendTo for each */
  perPeerPayloads: Map<string, SignRound2Payload>;
} {
  if (!state.myKi || !state.myGammaI) {
    throw new Error('Round 1 not complete');
  }

  const myNodeId = state.signers[state.mySignerIndex - 1].nodeId;
  const myPartyIndex = state.signers[state.mySignerIndex - 1].partyIndex;
  const otherPartyIndices = state.signers
    .filter((_, i) => i !== state.mySignerIndex - 1)
    .map((s) => s.partyIndex);

  // Lagrange coefficient L_i for this party in the signing subset
  const L_i = lagrangeCoeff(myPartyIndex, otherPartyIndices);

  // L_i * x_i: this party's Lagrange-weighted key share contribution
  const LiXi = scalarMul(L_i, keyShare);

  const myBetaDelta = new Map(state.myBetaDelta);
  const myBetaSigma = new Map(state.myBetaSigma);
  const perPeerPayloads = new Map<string, SignRound2Payload>();

  for (const signer of state.signers) {
    if (signer.nodeId === myNodeId) continue;

    const N_j = state.peerPaillierN.get(signer.nodeId);
    const C_kj = state.peerKiEnc.get(signer.nodeId);
    if (!N_j || !C_kj) continue;

    // Random blinding scalars — keep −beta as our additive MtA share
    const beta_d = generateScalar();
    const beta_s = generateScalar();
    myBetaDelta.set(signer.nodeId, (CURVE_ORDER - beta_d % CURVE_ORDER) % CURVE_ORDER); // −beta_d mod n
    myBetaSigma.set(signer.nodeId, (CURVE_ORDER - beta_s % CURVE_ORDER) % CURVE_ORDER); // −beta_s mod n

    // MtA ciphertexts for peer j to decrypt: Enc_{N_j}(k_j * gamma_i + beta_d)
    const deltaEnc = paillierMtA(N_j, C_kj, state.myGammaI, beta_d);
    // Enc_{N_j}(k_j * L_i*x_i + beta_s)
    const sigmaEnc = paillierMtA(N_j, C_kj, LiXi, beta_s);

    perPeerPayloads.set(signer.nodeId, {
      sessionId: state.sessionId,
      fromNodeId: myNodeId,
      toNodeId: signer.nodeId,
      partyIndex: state.mySignerIndex,
      mtaResponse: JSON.stringify({
        deltaEnc: bigintToHex(deltaEnc),
        sigmaEnc: bigintToHex(sigmaEnc),
      }),
      deltaShare: '',  // not used in new protocol
    });
  }

  const updatedState: SigningSessionState = {
    ...state,
    status: 'round2',
    myBetaDelta,
    myBetaSigma,
  };

  return { updatedState, perPeerPayloads };
}

export function recordRound2(
  state: SigningSessionState,
  payload: SignRound2Payload
): SigningSessionState {
  // Equivocation check: reject duplicate MtA messages from the same peer
  if (state.round2Received.has(payload.fromNodeId)) {
    throw new SigningError(`Equivocation detected: Round 2 duplicate from ${payload.fromNodeId}`);
  }

  const { deltaEnc, sigmaEnc } = JSON.parse(payload.mtaResponse) as {
    deltaEnc: string;
    sigmaEnc: string;
  };
  const round2Received = new Map(state.round2Received);
  round2Received.set(payload.fromNodeId, { deltaEnc, sigmaEnc });
  return { ...state, round2Received };
}

export function isSignRound2Complete(state: SigningSessionState): boolean {
  return state.round2Received.size === state.signers.length - 1;
}
