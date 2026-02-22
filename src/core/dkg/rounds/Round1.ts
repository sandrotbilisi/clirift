import { generateScalar, scalarMulG } from '../../../crypto/secp256k1';
import { generatePolynomial } from '../../../crypto/shamir';
import {
  pedersenCommit,
  generateBlindingFactor,
} from '../../../crypto/commitment';
import { feldmanCommitments } from '../FeldmanVss';
import { DkgLocalState } from '../DkgState';
import { DkgRound1Payload } from '../../../network/protocol/Message';

export interface Round1Output {
  updatedState: DkgLocalState;
  broadcast: DkgRound1Payload;
}

/**
 * DKG Round 1: Generate secret polynomial and broadcast Pedersen commitment.
 *
 * Each party:
 * 1. Generates a random secret a_0 (their DKG secret seed)
 * 2. Builds a polynomial of degree t-1 with a_0 as the constant term
 * 3. Computes coefficient commitments: [a_0*G, a_1*G, ...]
 * 4. Commits to the coefficient points with a blinding factor: C = H(coeff_points, r)
 * 5. Broadcasts the commitment (NOT the points or the polynomial)
 */
export function executeRound1(state: DkgLocalState): Round1Output {
  const secret = generateScalar();
  const polynomial = generatePolynomial(secret, state.threshold);
  const coeffPoints = polynomial.map((c) => scalarMulG(c));
  const coeffCommitments = feldmanCommitments(polynomial);

  const blindingFactor = generateBlindingFactor();
  const { commitment } = pedersenCommit(coeffPoints, blindingFactor);

  const updatedState: DkgLocalState = {
    ...state,
    status: 'round1',
    secretPolynomial: polynomial,
    myCoeffCommitments: coeffCommitments,
    myBlindingFactor: blindingFactor.toString(16).padStart(64, '0'),
  };

  const broadcast: DkgRound1Payload = {
    ceremonyId: state.ceremonyId,
    fromNodeId: state.participants.find((p) => p.partyIndex === state.myPartyIndex)!.nodeId,
    partyIndex: state.myPartyIndex,
    commitment,
  };

  return { updatedState, broadcast };
}

/** Record a Round 1 message received from another party */
export function recordRound1(
  state: DkgLocalState,
  payload: DkgRound1Payload
): DkgLocalState {
  const round1Received = new Map(state.round1Received);
  round1Received.set(payload.fromNodeId, payload.commitment);
  return { ...state, round1Received };
}

/** Check if all Round 1 messages have been received */
export function isRound1Complete(state: DkgLocalState): boolean {
  return state.round1Received.size === state.totalParties - 1;
}
