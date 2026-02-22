import { hexToPoint, scalarMulG } from '../../../crypto/secp256k1';
import { pedersenVerify } from '../../../crypto/commitment';
import { schnorrProve, schnorrVerify } from '../../../crypto/commitment';
import { DkgLocalState } from '../DkgState';
import { DkgRound2Payload } from '../../../network/protocol/Message';
import { DkgError } from '../../../utils/errors';

export interface Round2Output {
  updatedState: DkgLocalState;
  broadcast: DkgRound2Payload;
}

/**
 * DKG Round 2: Open the Round 1 commitment and prove knowledge of a_0.
 *
 * Each party broadcasts:
 * - All coefficient points: [a_0*G, a_1*G, ...] (Feldman VSS commitments)
 * - The Round 1 blinding factor (so others can verify the commitment)
 * - A Schnorr proof of knowledge of a_0 (the secret)
 */
export function executeRound2(state: DkgLocalState): Round2Output {
  if (!state.secretPolynomial || !state.myCoeffCommitments || !state.myBlindingFactor) {
    throw new DkgError('Round 1 must be completed before Round 2');
  }

  const a0 = state.secretPolynomial[0];
  const a0G = scalarMulG(a0);

  // Schnorr proof of knowledge of a_0
  const ceremonyContext = `DKG-${state.ceremonyId}-party-${state.myPartyIndex}`;
  const zkProof = schnorrProve(a0, a0G, ceremonyContext);

  const myNodeId = state.participants.find((p) => p.partyIndex === state.myPartyIndex)!.nodeId;

  const broadcast: DkgRound2Payload = {
    ceremonyId: state.ceremonyId,
    fromNodeId: myNodeId,
    partyIndex: state.myPartyIndex,
    coefficientCommitments: state.myCoeffCommitments,
    zkProof,
    blindingFactor: state.myBlindingFactor,
  };

  return { updatedState: { ...state, status: 'round2' }, broadcast };
}

/** Record and verify a Round 2 message from another party */
export function recordRound2(
  state: DkgLocalState,
  payload: DkgRound2Payload
): DkgLocalState {
  // Verify Pedersen commitment opens correctly
  const coeffPoints = payload.coefficientCommitments.map(hexToPoint);
  const commitmentFromRound1 = state.round1Received.get(payload.fromNodeId);

  if (!commitmentFromRound1) {
    throw new DkgError(
      `No Round 1 commitment found for ${payload.fromNodeId} — cannot verify Round 2`
    );
  }

  const commitmentValid = pedersenVerify(
    commitmentFromRound1,
    coeffPoints,
    payload.blindingFactor
  );

  if (!commitmentValid) {
    throw new DkgError(
      `Round 2 commitment mismatch for party ${payload.partyIndex} (${payload.fromNodeId})`
    );
  }

  // Verify Schnorr ZK proof for a_0
  const a0G = hexToPoint(payload.coefficientCommitments[0]);
  const ceremonyContext = `DKG-${state.ceremonyId}-party-${payload.partyIndex}`;

  if (!schnorrVerify(a0G, payload.zkProof, ceremonyContext)) {
    throw new DkgError(
      `Schnorr ZK proof invalid for party ${payload.partyIndex} (${payload.fromNodeId})`
    );
  }

  const round2Received = new Map(state.round2Received);
  round2Received.set(payload.fromNodeId, {
    coefficientCommitments: payload.coefficientCommitments,
    zkProof: payload.zkProof,
    blindingFactor: payload.blindingFactor,
  });

  return { ...state, round2Received };
}

export function isRound2Complete(state: DkgLocalState): boolean {
  return state.round2Received.size === state.totalParties - 1;
}
