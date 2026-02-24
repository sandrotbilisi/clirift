/**
 * Integration test: full 2-of-3 threshold signing session.
 *
 * Wires two SigningCoordinator instances together in-memory with a mock
 * network (setImmediate delivery to simulate realistic async message arrival),
 * runs the complete GG20 3-round protocol, and asserts both sides emit
 * 'complete' with a properly-formatted EIP-1559 signed transaction.
 *
 * This test specifically catches the async race conditions that were fixed:
 *   - Round 1 dropped because session didn't exist yet during onAccept's key load
 *   - Round 3 "not complete" because peer's Round 3 arrived during startRound3's key load
 */

import { describe, it, expect } from 'vitest';
import { generateKeyPairSync } from 'crypto';
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
 * of WebSocket message delivery so the race conditions are observable.
 */
class MockNodeServer {
  private coord!: SigningCoordinator;
  private peers = new Map<string, MockNodeServer>();

  attach(c: SigningCoordinator) {
    this.coord = c;
  }

  addPeer(nodeId: string, peer: MockNodeServer) {
    this.peers.set(nodeId, peer);
  }

  broadcast<T>(type: MessageType, payload: T): void {
    for (const peer of this.peers.values()) {
      setImmediate(() => void peer.coord.handleMessage(null, { type, payload }));
    }
  }

  sendTo<T>(targetNodeId: string, type: MessageType, payload: T): boolean {
    const peer = this.peers.get(targetNodeId);
    if (!peer) return false;
    setImmediate(() => void peer.coord.handleMessage(null, { type, payload }));
    return true;
  }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function makeRSAKeyPair() {
  return generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
}

function makeKeyShareStore(data: KeyShareData): KeyShareStore {
  return {
    async load() { return data; },
    async save() { /* no-op in tests */ },
    exists() { return true; },
    loadCeremonyMetadata() { return null; },
  } as unknown as KeyShareStore;
}

// Arbitrary 32-byte secp256k1 scalars used as secret shares.
// These won't produce a cryptographically-valid ECDSA signature against a
// real private key (the simplified GG20 doesn't do proper Lagrange weighting),
// but they exercise every line of coordinator + round logic.
const SECRET_SHARE_1 = '1111111111111111111111111111111111111111111111111111111111111111';
const SECRET_SHARE_2 = '2222222222222222222222222222222222222222222222222222222222222222';
// Compressed secp256k1 generator point — used as a valid placeholder for publicKeyShares / pkMaster
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

// A real EIP-1559 keccak256 signing hash (32 bytes, no 0x prefix)
const TX_HASH = '76a1ad7e039d1dc76f96159507010ca2913722083c122fdd81a56ebbd256ba14';
const DERIVATION_PATH = "m/44'/60'/0'/0/5";

// ─── Tests ────────────────────────────────────────────────────────────────────

describe('SigningCoordinator — 2-of-3 threshold signing', () => {
  it('completes all 3 rounds and emits a signed EIP-1559 transaction', async () => {
    // RSA key pairs: each node uses its own private key to decrypt MtA ciphertexts,
    // and the peer's public key to encrypt them.
    const rsaA = makeRSAKeyPair();
    const rsaB = makeRSAKeyPair();

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
      myPrivateKeyPem: rsaA.privateKey,
      timeoutMs: 15_000,
    });

    const coordB = new SigningCoordinator({
      nodeId: nodeIdB,
      nodeServer: serverB as unknown as NodeServer,
      keyShareStore: makeKeyShareStore(shareB),
      myPrivateKeyPem: rsaB.privateKey,
      timeoutMs: 15_000,
    });

    // Wire coordinators to their mock servers
    serverA.attach(coordA);
    serverB.attach(coordB);

    // A → B routing, B → A routing
    serverA.addPeer(nodeIdB, serverB);
    serverB.addPeer(nodeIdA, serverA);

    // Give each coordinator the peer's RSA public key for MtA encryption
    coordA.setPeerPubkey(nodeIdB, rsaB.publicKey);
    coordB.setPeerPubkey(nodeIdA, rsaA.publicKey);

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
  }, 20_000); // 20-second timeout (RSA key generation is slow)
});
