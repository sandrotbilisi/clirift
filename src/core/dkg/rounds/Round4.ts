import {
  scalarMulG,
  pointToHex,
  CURVE_ORDER,
} from '../../../crypto/secp256k1';
import { sha512 } from '@noble/hashes/sha512';
import { hmac } from '@noble/hashes/hmac';
import { combinePkMaster } from '../FeldmanVss';
import { DkgLocalState } from '../DkgState';
import { DkgRound4Payload, DkgCompletePayload } from '../../../network/protocol/Message';
import { DkgError } from '../../../utils/errors';
import { evaluatePolynomial } from '../../../crypto/shamir';

/**
 * DKG Round 4: Assemble key share and broadcast public key share.
 *
 * Each party:
 * 1. Sums all received Shamir shares to get their key share x_i = sum_j(f_j(i))
 * 2. Computes their public key share: x_i * G
 * 3. Broadcasts x_i * G so others can verify
 */
export function executeRound4(state: DkgLocalState): {
  updatedState: DkgLocalState;
  broadcast: DkgRound4Payload;
} {
  if (!state.secretPolynomial) throw new DkgError('Round 3 not complete');

  // My own share of my own polynomial: f_i(i)
  const myOwnShare = evaluatePolynomial(state.secretPolynomial, state.myPartyIndex);

  // Sum: x_i = f_i(i) + sum_j(f_j(i)) for j != i
  let keyShare = myOwnShare;
  for (const share of state.sharesReceived.values()) {
    keyShare = (keyShare + share) % CURVE_ORDER;
  }
  keyShare = ((keyShare % CURVE_ORDER) + CURVE_ORDER) % CURVE_ORDER;

  const publicKeyShare = pointToHex(scalarMulG(keyShare));

  const myNodeId = state.participants.find((p) => p.partyIndex === state.myPartyIndex)!.nodeId;

  const updatedState: DkgLocalState = {
    ...state,
    status: 'round4',
    myKeyShare: keyShare,
  };

  const broadcast: DkgRound4Payload = {
    ceremonyId: state.ceremonyId,
    fromNodeId: myNodeId,
    partyIndex: state.myPartyIndex,
    publicKeyShare,
    shareVerified: true,
  };

  return { updatedState, broadcast };
}

/** Record a Round 4 public key share from another party */
export function recordRound4(
  state: DkgLocalState,
  payload: DkgRound4Payload
): DkgLocalState {
  if (!payload.shareVerified) {
    throw new DkgError(
      `Party ${payload.partyIndex} (${payload.fromNodeId}) reported share verification failure`
    );
  }

  const publicKeySharesReceived = new Map(state.publicKeySharesReceived);
  publicKeySharesReceived.set(payload.fromNodeId, payload.publicKeyShare);

  return { ...state, publicKeySharesReceived };
}

export function isRound4Complete(state: DkgLocalState): boolean {
  return state.publicKeySharesReceived.size === state.totalParties - 1;
}

/**
 * Assemble PK_master and BIP32 chain code after all Round 4 messages received.
 *
 * PK_master = sum of all a_i(0)*G (the intercept points from each party)
 * = sum of Round 2 coefficient[0] points
 */
export function assemblePkMaster(state: DkgLocalState): {
  updatedState: DkgLocalState;
  complete: DkgCompletePayload;
} {
  // Collect all intercept commitments (a_j(0)*G) from Round 2
  const interceptCommitments: string[] = [];

  // My own intercept: myCoeffCommitments[0]
  if (!state.myCoeffCommitments) throw new DkgError('Missing my coefficient commitments');
  interceptCommitments.push(state.myCoeffCommitments[0]);

  // Others' intercepts from Round 2
  for (const { coefficientCommitments } of state.round2Received.values()) {
    interceptCommitments.push(coefficientCommitments[0]);
  }

  const pkMaster = combinePkMaster(interceptCommitments);

  // Derive BIP32 chain code: HMAC-SHA512(key="CLIRift v1", data=pkMasterBytes)[32:]
  const pkBytes = Buffer.from(pkMaster, 'hex');
  const chainCodeFull = hmac(sha512, Buffer.from('CLIRift v1', 'utf8'), pkBytes);
  const chainCode = Buffer.from(chainCodeFull.slice(32)).toString('hex');

  const updatedState: DkgLocalState = {
    ...state,
    status: 'complete',
    pkMaster,
    chainCode,
  };

  const complete: DkgCompletePayload = {
    ceremonyId: state.ceremonyId,
    pkMaster,
    chainCode,
  };

  return { updatedState, complete };
}
