export enum MessageType {
  // ---- Legacy (kept for backwards compatibility) ----
  AUTH_REQUEST = 'auth_request',
  AUTH_RESPONSE = 'auth_response',
  FINGERPRINT_VERIFY = 'fingerprint_verify',
  SESSION_START = 'session_start',
  CLIENT_JOINED = 'client_joined',
  CLIENT_LEFT = 'client_left',
  CLIENT_LIST = 'client_list',
  BROADCAST = 'broadcast',
  DIRECT_MESSAGE = 'direct_message',
  HEARTBEAT = 'heartbeat',
  ERROR = 'error',

  // ---- Node identity ----
  NODE_HELLO = 'node_hello',
  NODE_HELLO_ACK = 'node_hello_ack',

  // ---- DKG ceremony ----
  DKG_PROPOSE = 'dkg_propose',
  DKG_ACCEPT = 'dkg_accept',
  DKG_ROUND1 = 'dkg_round1',
  DKG_ROUND2 = 'dkg_round2',
  DKG_ROUND3_P2P = 'dkg_round3_p2p',
  DKG_ROUND4 = 'dkg_round4',
  DKG_COMPLETE = 'dkg_complete',
  DKG_ABORT = 'dkg_abort',

  // ---- Signing session ----
  SIGN_REQUEST = 'sign_request',
  SIGN_ACCEPT = 'sign_accept',
  SIGN_REJECT = 'sign_reject',
  SIGN_ROUND1 = 'sign_round1',
  SIGN_ROUND2 = 'sign_round2',
  SIGN_ROUND3 = 'sign_round3',
  SIGN_COMPLETE = 'sign_complete',
  SIGN_ABORT = 'sign_abort',

  // ---- Address derivation (informational) ----
  ADDRESS_QUERY = 'address_query',
  ADDRESS_RESPONSE = 'address_response',
}

// ---- Base envelope ----

export interface Message<T = unknown> {
  id: string;        // UUID v4
  type: MessageType;
  timestamp: number; // Unix timestamp ms
  nonce: string;     // Anti-replay nonce (hex)
  payload: T;
}

// ---- Legacy payloads (kept for compatibility) ----

export interface AuthRequestPayload {
  clientId: string;
  passwordHash: string;
}

export interface AuthResponsePayload {
  success: boolean;
  clientId?: string;
  sessionId?: string;
  error?: string;
  fingerprint?: string;
}

export interface ClientInfo {
  id: string;
  name?: string;
  connectedAt: number;
}

export interface ClientJoinedPayload { client: ClientInfo }
export interface ClientLeftPayload { clientId: string }
export interface ClientListPayload { clients: ClientInfo[] }
export interface BroadcastPayload { from: string; message: string; timestamp: number }
export interface DirectMessagePayload { from: string; to: string; message: string; timestamp: number }
export interface ErrorPayload { code: string; message: string; details?: unknown }
export type HeartbeatPayload = Record<string, never>;

// ---- Node identity payloads ----

export interface NodeHelloPayload {
  nodeId: string;          // Stable UUID for this node
  nodePubkeyPem: string;   // EC P-256 identity public key (PEM)
  version: string;         // CLIRift version
  capabilities: string[];  // e.g. ['dkg', 'sign']
}

export interface NodeHelloAckPayload extends NodeHelloPayload {}

// ---- DKG payloads ----

export interface DkgProposePayload {
  ceremonyId: string;
  initiatorNodeId: string;
  participants: string[];   // ordered list of nodeIds (determines party indices)
  threshold: number;        // t (e.g. 2)
  totalParties: number;     // n (e.g. 3)
  deadline: number;         // Unix ms — ceremony must complete before this
}

export interface DkgAcceptPayload {
  ceremonyId: string;
  nodeId: string;
  partyIndex: number;       // 1-indexed position in participants list
}

export interface DkgRound1Payload {
  ceremonyId: string;
  fromNodeId: string;
  partyIndex: number;
  /** Hex: Hash(a_0*G || a_1*G || ... || r) — Pedersen commitment to polynomial coefficients */
  commitment: string;
}

export interface DkgRound2Payload {
  ceremonyId: string;
  fromNodeId: string;
  partyIndex: number;
  /** Array of hex-encoded compressed EC points: [a_0*G, a_1*G, ...] (Feldman VSS) */
  coefficientCommitments: string[];
  /** Schnorr proof of knowledge of a_0 (secret): { R: hex point, s: hex scalar } */
  zkProof: { R: string; s: string };
  /** Hex blinding factor used in Round1 commitment */
  blindingFactor: string;
}

export interface DkgRound3P2PPayload {
  ceremonyId: string;
  fromNodeId: string;
  toNodeId: string;
  fromPartyIndex: number;
  toPartyIndex: number;
  /** ECIES-encrypted Shamir share f_i(j), using recipient's identity pubkey */
  encryptedShare: string;
}

export interface DkgRound4Payload {
  ceremonyId: string;
  fromNodeId: string;
  partyIndex: number;
  /** Compressed hex EC point: a_i(0)*G — this party's public key share */
  publicKeyShare: string;
  /** True if this party successfully verified all received Shamir shares */
  shareVerified: boolean;
}

export interface DkgCompletePayload {
  ceremonyId: string;
  /** Hex-encoded compressed secp256k1 point — the combined master public key */
  pkMaster: string;
  /** BIP32 chain code (hex) — derived deterministically, public */
  chainCode: string;
}

export interface DkgAbortPayload {
  ceremonyId: string;
  reason: string;
  fromNodeId: string;
}

// ---- Signing payloads ----

export interface RawTxData {
  to: string;                  // EIP-55 address
  value: string;               // ETH value as decimal string (wei)
  data: string;                // Hex calldata
  nonce: number;
  gasLimit: string;
  maxFeePerGas: string;        // Wei as decimal string
  maxPriorityFeePerGas: string;
  chainId: number;
}

export interface SignRequestPayload {
  sessionId: string;
  initiatorNodeId: string;
  initiatorPartyIndex: number;  // so participants can build the correct signers list
  /** Keccak256 of the EIP-1559 signing hash (hex, 32 bytes) */
  txHash: string;
  rawTx: RawTxData;
  /** BIP44 derivation path, e.g. "m/44'/60'/0'/0/0" */
  derivationPath: string;
  deadline: number;            // Unix ms
}

export interface SignAcceptPayload {
  sessionId: string;
  nodeId: string;
  partyIndex: number;
}

export interface SignRejectPayload {
  sessionId: string;
  nodeId: string;
  reason: string;
}

/** GG20 Round 1: commitment to k_i and gamma_i */
export interface SignRound1Payload {
  sessionId: string;
  fromNodeId: string;
  partyIndex: number;
  /** Compressed hex EC point: gamma_i * G */
  gammaCommitment: string;
  /** MtA (multiplicative-to-additive) ciphertext for k_i * x_j product */
  mtaCiphertext: string;
}

/** GG20 Round 2: MtA responses, delta_i */
export interface SignRound2Payload {
  sessionId: string;
  fromNodeId: string;
  partyIndex: number;
  /** MtA response ciphertext */
  mtaResponse: string;
  /** delta_i = k_i*gamma_i + alpha_ij + beta_ji (hex scalar) */
  deltaShare: string;
}

/** GG20 Round 3: partial signature */
export interface SignRound3Payload {
  sessionId: string;
  fromNodeId: string;
  partyIndex: number;
  /** s_i partial signature scalar (hex) */
  partialSig: string;
  /** R_i = k_i * G (compressed hex point) */
  RShare: string;
}

export interface SignCompletePayload {
  sessionId: string;
  signature: {
    r: string;  // hex 32-byte
    s: string;  // hex 32-byte
    v: number;  // recovery id (27 or 28)
  };
  /** RLP-encoded signed transaction hex, ready for eth_sendRawTransaction */
  signedTxHex: string;
}

export interface SignAbortPayload {
  sessionId: string;
  reason: string;
  fromNodeId: string;
}

// ---- Address payloads ----

export interface AddressQueryPayload {
  index: number;
  derivationPath?: string;
}

export interface AddressResponsePayload {
  index: number;
  derivationPath: string;
  address: string;          // EIP-55 checksummed
  publicKey: string;        // Compressed hex
}
