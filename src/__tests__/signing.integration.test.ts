/**
 * Integration test: full 2-of-3 threshold signing session.
 *
 * Wires two SigningCoordinator instances together in-memory with a mock
 * network (setImmediate delivery to simulate realistic async message arrival),
 * runs the complete GG20 4-round protocol, and asserts both sides emit
 * 'complete' with a properly-formatted EIP-1559 signed transaction.
 *
 * The 4-round protocol:
 *   Round 1 (broadcast): gamma_i*G, k_i*G, Paillier pubkey N_i, Enc_{N_i}(k_i), Schnorr proofs
 *   Round 2 (P2P):       Paillier MtA ciphertexts for delta and sigma
 *   Round 3 (broadcast): delta_i share only (sigma_i kept secret)
 *   Round 4 (broadcast): partial signature s_i + sigma_i*G for verification
 *
 * Security: no party ever learns the other's raw nonce k_j, preventing
 * the private key extraction attack present in the old RSA-based MtA.
 *
 * Key shares: valid 2-of-3 Shamir shares of private_key=1 for parties 1 and 2.
 *   Lagrange reconstruction: L_1=2, L_2=-1, so 2*x_1 - x_2 = private_key.
 *   With x_1=x_2=1: 2*1 - 1 = 1 ✓   pkMaster = 1*G = secp256k1 generator point.
 */

import { describe, it, expect } from 'vitest';
import { SigningCoordinator } from '../core/signing/SigningCoordinator';
import { MessageType } from '../network/protocol/Message';
import type { NodeServer } from '../core/NodeServer';
import type { KeyShareStore, KeyShareData } from '../storage/KeyShareStore';

// ─── Mock network ────────────────────────────────────────────────────────────

/**
 * Minimal NodeServer mock.
 * broadcast() → setImmediate-delivers to all registered peer coordinators.
 * sendTo()    → setImmediate-delivers to the target peer coordinator.
 * Using setImmediate instead of direct calls mimics the real async nature
 * of WebSocket message delivery so race conditions are observable.
 */
class MockNodeServer {
  private coord!: SigningCoordinator;
  private peers = new Map<string, MockNodeServer>();
  private nodeId!: string;

  attach(c: SigningCoordinator, nodeId: string) {
    this.coord = c;
    this.nodeId = nodeId;
  }

  addPeer(nodeId: string, peer: MockNodeServer) {
    this.peers.set(nodeId, peer);
  }

  broadcast<T>(type: MessageType, payload: T): void {
    for (const peer of this.peers.values()) {
      const senderId = this.nodeId;
      setImmediate(() => void peer.coord.handleMessage(senderId, { type, payload }));
    }
  }

  sendTo<T>(targetNodeId: string, type: MessageType, payload: T): boolean {
    const peer = this.peers.get(targetNodeId);
    if (!peer) return false;
    const senderId = this.nodeId;
    setImmediate(() => void peer.coord.handleMessage(senderId, { type, payload }));
    return true;
  }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function makeKeyShareStore(data: KeyShareData): KeyShareStore {
  return {
    async load() { return data; },
    async save() { /* no-op in tests */ },
    exists() { return true; },
    loadCeremonyMetadata() { return null; },
  } as unknown as KeyShareStore;
}

// Valid 2-of-3 Shamir shares of private_key=1 for parties with partyIndices 1 and 2.
// Lagrange coefficients for subset {1,2}: L_1=2, L_2=-1 (mod curve_order).
// Check: 2*1 + (-1)*1 = 1 = private_key ✓
// These are valid shares of the polynomial f(x)=1 (constant), with f(1)=f(2)=1.
const SECRET_SHARE_1 = '0000000000000000000000000000000000000000000000000000000000000001';
const SECRET_SHARE_2 = '0000000000000000000000000000000000000000000000000000000000000001';
// The secp256k1 generator point G = 1*G = pkMaster for private_key=1
const G_POINT = '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798';

const RAW_TX = {
  to: '0xCe0f7AB8Eab551FE39AebCfaAD0150D87C68791F' as const,
  value: '100000000000000000', // 0.1 ETH in wei
  data: '0x',
  nonce: 5,
  gasLimit: '21000',
  maxFeePerGas: '3000000000',
  maxPriorityFeePerGas: '1000000000',
  chainId: 56,
};

// keccak256 of the EIP-1559 signing payload for RAW_TX (no 0x prefix)
const TX_HASH = '0bf0c4b47c36fa5173ea107f90f33092ef676de96332fed4f08cb308d2eaf839';
const DERIVATION_PATH = "m/44'/60'/0'/0/5";

// ─── Tests ────────────────────────────────────────────────────────────────────

describe('SigningCoordinator — 2-of-3 threshold signing', () => {
  it('completes all 4 rounds and emits a signed EIP-1559 transaction', async () => {
    const nodeIdA = 'node-a'; // initiator
    const nodeIdB = 'node-b'; // participant

    const shareA: KeyShareData = {
      partyIndex: 1,
      secretShare: SECRET_SHARE_1,
      publicKeyShares: [G_POINT, G_POINT, G_POINT],
      pkMaster: G_POINT,
      chainCode: '0'.repeat(64),
      ceremonyId: 'test-ceremony',
    };

    const shareB: KeyShareData = {
      partyIndex: 2,
      secretShare: SECRET_SHARE_2,
      publicKeyShares: [G_POINT, G_POINT, G_POINT],
      pkMaster: G_POINT,
      chainCode: '0'.repeat(64),
      ceremonyId: 'test-ceremony',
    };

    const serverA = new MockNodeServer();
    const serverB = new MockNodeServer();

    const coordA = new SigningCoordinator({
      nodeId: nodeIdA,
      nodeServer: serverA as unknown as NodeServer,
      keyShareStore: makeKeyShareStore(shareA),
      myPrivateKeyPem: '',  // no longer used in signing
      timeoutMs: 30_000,
    });

    const coordB = new SigningCoordinator({
      nodeId: nodeIdB,
      nodeServer: serverB as unknown as NodeServer,
      keyShareStore: makeKeyShareStore(shareB),
      myPrivateKeyPem: '',  // no longer used in signing
      timeoutMs: 30_000,
    });

    // Wire coordinators to their mock servers
    serverA.attach(coordA, nodeIdA);
    serverB.attach(coordB, nodeIdB);

    // A → B routing, B → A routing
    serverA.addPeer(nodeIdB, serverB);
    serverB.addPeer(nodeIdA, serverA);

    // Capture complete/abort from both sides
    const waitForComplete = (coord: SigningCoordinator, label: string) =>
      new Promise<string>((resolve, reject) => {
        coord.once('complete', (_sig, txHex) => resolve(txHex));
        coord.once('aborted', (reason) => reject(new Error(`${label} aborted: ${reason}`)));
      });

    const [txHexA, txHexB] = await Promise.all([
      waitForComplete(coordA, 'initiator'),
      waitForComplete(coordB, 'participant'),
      // Kick off the signing session
      coordA.initiate(RAW_TX, DERIVATION_PATH, TX_HASH),
    ]);

    // Both sides must produce the same RLP-encoded signed transaction
    expect(txHexA).toBeTruthy();
    expect(txHexB).toBeTruthy();
    expect(txHexA).toMatch(/^0x02/); // EIP-1559 type-2 prefix
    expect(txHexB).toMatch(/^0x02/);
    expect(txHexA).toBe(txHexB);     // Both nodes assembled identical signatures
  }, 60_000); // 60-second timeout: Paillier key generation (1024-bit) takes ~100-500ms per key
});
