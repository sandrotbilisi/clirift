import { RawTxData } from '../../network/protocol/Message';

export type SigningStatus =
  | 'idle'
  | 'collecting'    // waiting for SIGN_ACCEPT from peers
  | 'round1'
  | 'round2'
  | 'round3'
  | 'round4'
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

  // Round 1 state
  myKi?: bigint;           // k_i: signing nonce
  myGammaI?: bigint;       // gamma_i: auxiliary nonce
  myGammaIPoint?: string;  // gamma_i * G (compressed hex)

  // Paillier keypair (generated fresh each session)
  myPaillierN?: bigint;
  myPaillierLambda?: bigint;
  myPaillierMu?: bigint;

  /** Peer Paillier public keys received in Round 1 */
  peerPaillierN: Map<string, bigint>;   // nodeId → N_j
  /** Peer encrypted k_j values received in Round 1 */
  peerKiEnc: Map<string, bigint>;       // nodeId → Enc_{N_j}(k_j)
  /** Peer k_i*G points received in Round 1 — used to verify partial sigs in Round 4 */
  peerKiCommitment: Map<string, string>; // nodeId → k_i*G compressed hex

  /** Round 1 messages received from other signers */
  round1Received: Map<string, { gammaCommitment: string; paillierN: string; kiEnc: string; kiCommitment: string }>;

  // Round 2 state — beta blinding terms kept by this party
  /** -beta_delta per peer (our additive share of k_j * gamma_i) */
  myBetaDelta: Map<string, bigint>;
  /** -beta_sigma per peer (our additive share of k_j * L_i * x_i) */
  myBetaSigma: Map<string, bigint>;

  /** Round 2 messages received (MtA ciphertexts addressed to us) */
  round2Received: Map<string, { deltaEnc: string; sigmaEnc: string }>;

  // Round 3 state — delta and sigma shares
  myDeltaI?: bigint;       // delta_i = k_i * gamma_i + sum of MtA contributions
  mySigmaI?: bigint;       // sigma_i = k_i * L_i * x_i + sum of MtA contributions

  /** Round 3 messages received (sigma_i is kept secret — only delta_i is shared) */
  round3Received: Map<string, { deltaShare: string }>;

  // Round 4 state — partial signatures
  myPartialSig?: bigint;   // s_i = k_i * m + r * sigma_i
  computedR?: string;       // r-value computed in Round 4, used by assembleSignature and recordRound4

  /** Round 4 messages received */
  round4Received: Map<string, { partialSig: string; sigmaCommitment: string }>;

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
  if (signers.length !== 2) {
    throw new Error(`Threshold signing requires exactly 2 signers, got ${signers.length}`);
  }
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
    peerPaillierN: new Map(),
    peerKiEnc: new Map(),
    peerKiCommitment: new Map(),
    round1Received: new Map(),
    myBetaDelta: new Map(),
    myBetaSigma: new Map(),
    round2Received: new Map(),
    round3Received: new Map(),
    round4Received: new Map(),
  };
}
