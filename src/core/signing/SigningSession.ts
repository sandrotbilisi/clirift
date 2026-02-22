import { RawTxData } from '../../network/protocol/Message';

export type SigningStatus =
  | 'idle'
  | 'collecting'    // waiting for SIGN_ACCEPT from peers
  | 'round1'
  | 'round2'
  | 'round3'
  | 'complete'
  | 'aborted';

export interface SignerInfo {
  nodeId: string;
  partyIndex: number; // 1-indexed within the signing subset
}

/**
 * Local signing session state for one GG20 signing round.
 * Tracks the subset of parties participating and the per-round state.
 */
export interface SigningSessionState {
  sessionId: string;
  status: SigningStatus;
  txHash: string;          // Keccak256 of EIP-1559 signing hash (hex)
  rawTx: RawTxData;
  derivationPath: string;
  deadline: number;

  signers: SignerInfo[];   // Which parties are participating (2-of-3 subset)
  mySignerIndex: number;   // My index within the signers list (1-indexed)

  // Round 1 state (commitment phase)
  myKi?: bigint;           // k_i: signing nonce
  myGammaI?: bigint;       // gamma_i: auxiliary nonce
  myGammaIPoint?: string;  // gamma_i * G (compressed hex)

  /** MtA (multiplicative-to-additive) ciphertext we sent to each signer */
  mtaCiphertexts?: Map<string, string>; // nodeId → ciphertext (base64)

  /** Round 1 messages received from other signers */
  round1Received: Map<string, { gammaCommitment: string; mtaCiphertext: string }>;

  // Round 2 state (MtA responses)
  myDeltaI?: bigint;       // delta_i = k_i * gamma_i + sum(alpha_ij) + sum(beta_ji)
  /** Round 2 messages received */
  round2Received: Map<string, { mtaResponse: string; deltaShare: string }>;

  // Round 3 state (partial signatures)
  R?: string;              // Signature nonce point (compressed hex)
  r?: string;              // r = R.x mod n (hex scalar)
  myPartialSig?: bigint;   // s_i
  myRShare?: string;       // R_i = k_i * G (compressed hex)

  /** Round 3 messages received */
  round3Received: Map<string, { partialSig: string; RShare: string }>;

  // Final
  signature?: { r: string; s: string; v: number };
  signedTxHex?: string;
}

export function createSigningSession(
  sessionId: string,
  txHash: string,
  rawTx: RawTxData,
  derivationPath: string,
  deadline: number,
  signers: SignerInfo[],
  myNodeId: string
): SigningSessionState {
  const mySignerIndex = signers.findIndex((s) => s.nodeId === myNodeId);
  if (mySignerIndex === -1) {
    throw new Error(`This node (${myNodeId}) is not in the signer list`);
  }

  return {
    sessionId,
    status: 'round1',
    txHash,
    rawTx,
    derivationPath,
    deadline,
    signers,
    mySignerIndex: mySignerIndex + 1,
    round1Received: new Map(),
    round2Received: new Map(),
    round3Received: new Map(),
  };
}
