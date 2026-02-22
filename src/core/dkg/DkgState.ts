export type DkgCeremonyStatus =
  | 'idle'
  | 'proposed'
  | 'round1'
  | 'round2'
  | 'round3'
  | 'round4'
  | 'complete'
  | 'aborted';

export interface DkgParticipantInfo {
  nodeId: string;
  partyIndex: number; // 1-indexed
}

/** Per-party local state during a DKG ceremony */
export interface DkgLocalState {
  ceremonyId: string;
  status: DkgCeremonyStatus;
  myPartyIndex: number;
  participants: DkgParticipantInfo[];
  threshold: number;
  totalParties: number;

  // Round 1 — my secret polynomial
  secretPolynomial?: bigint[];        // [a_0, a_1, ..., a_{t-1}]
  myCoeffCommitments?: string[];     // [a_0*G, a_1*G, ...] compressed hex
  myBlindingFactor?: string;         // hex blinding factor for Pedersen commitment

  // Round 1 — received from others
  round1Received: Map<string, string>; // nodeId → Pedersen commitment hex

  // Round 2 — received from others
  round2Received: Map<string, {
    coefficientCommitments: string[];
    zkProof: { R: string; s: string };
    blindingFactor: string;
  }>;

  // Round 3 — received Shamir shares (after decryption)
  sharesReceived: Map<string, bigint>; // nodeId → f_j(myIndex)

  // Round 4 — received public key shares
  publicKeySharesReceived: Map<string, string>; // nodeId → a_j(0)*G hex

  // Final outputs
  myKeyShare?: bigint;      // x_i = sum_j f_j(i)
  pkMaster?: string;        // compressed hex
  chainCode?: string;       // BIP32 chain code hex
}

export function createInitialDkgState(
  ceremonyId: string,
  myPartyIndex: number,
  participants: DkgParticipantInfo[],
  threshold: number,
  totalParties: number
): DkgLocalState {
  return {
    ceremonyId,
    status: 'proposed',
    myPartyIndex,
    participants,
    threshold,
    totalParties,
    round1Received: new Map(),
    round2Received: new Map(),
    sharesReceived: new Map(),
    publicKeySharesReceived: new Map(),
  };
}
