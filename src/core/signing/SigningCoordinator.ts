import { EventEmitter } from 'events';
import { v4 as uuidv4 } from 'uuid';
import { keccak256, serializeTransaction } from 'viem';
import { secp256k1 as nobleSecp } from '@noble/curves/secp256k1';
import { computeChildKeyTweak } from '../../wallet/HdWallet';
import {
  SigningSessionState,
  SignerInfo,
  createSigningSession,
} from './SigningSession';
import {
  executeSignRound1,
  recordRound1 as recordSignRound1,
  isSignRound1Complete,
} from './rounds/SignRound1';
import {
  executeSignRound2,
  recordRound2 as recordSignRound2,
  isSignRound2Complete,
} from './rounds/SignRound2';
import {
  executeSignRound3,
  recordRound3 as recordSignRound3,
  isSignRound3Complete,
} from './rounds/SignRound3';
import {
  executeSignRound4,
  recordRound4 as recordSignRound4,
  isSignRound4Complete,
  assembleSignature,
} from './rounds/SignRound4';
import {
  MessageType,
  SignRequestPayload,
  SignAcceptPayload,
  SignRound1Payload,
  SignRound2Payload,
  SignRound3Payload,
  SignRound4Payload,
  SignCompletePayload,
  RawTxData,
} from '../../network/protocol/Message';
import { NodeServer } from '../NodeServer';
import { KeyShareStore } from '../../storage/KeyShareStore';
import { CURVE_ORDER, hexToScalar, hexToPoint, scalarMulG } from '../../crypto/secp256k1';
import { SigningError } from '../../utils/errors';
import logger from '../../utils/logger';

export interface SigningCoordinatorOptions {
  nodeId: string;
  nodeServer: NodeServer;
  keyShareStore: KeyShareStore;
  myPrivateKeyPem: string;   // kept for API compatibility; no longer used in signing
  timeoutMs: number;
}

export type SigningCoordinatorEvents = {
  complete: (sig: { r: string; s: string; v: number }, signedTxHex: string) => void;
  aborted: (reason: string) => void;
};

export declare interface SigningCoordinator {
  on<K extends keyof SigningCoordinatorEvents>(event: K, listener: SigningCoordinatorEvents[K]): this;
  emit<K extends keyof SigningCoordinatorEvents>(
    event: K,
    ...args: Parameters<SigningCoordinatorEvents[K]>
  ): boolean;
}

export class SigningCoordinator extends EventEmitter {
  private session: SigningSessionState | null = null;
  private acceptedSigners: Map<string, SignAcceptPayload> = new Map();
  private pendingRawTx: RawTxData | null = null;
  private pendingTxHash: string | null = null;
  private pendingDerivationPath: string | null = null;
  /** Cached key share from initiate() so onAccept creates the session without an async gap */
  private initiatorKeyShare: Awaited<ReturnType<KeyShareStore['load']>> | null = null;
  /** Cached tweaked secret share — set on both initiator and participant paths */
  private cachedSecretShare: bigint | null = null;
  /** Prevents async race where two duplicate messages both pass the `if (!this.session)` guard */
  private sessionPending = false;
  /** r value computed in Round 4, stored for use in finalize() */
  private cachedR: string | null = null;
  /** Guard against double 'complete' emission — both parties call finalize() independently */
  private alreadyFinalized = false;
  private timeoutHandle: NodeJS.Timeout | null = null;

  private opts: SigningCoordinatorOptions;

  constructor(opts: SigningCoordinatorOptions) {
    super();
    this.opts = opts;
  }

  /** Initiate a signing session as the request initiator */
  async initiate(rawTx: RawTxData, derivationPath: string, txHash: string): Promise<void> {
    this.pendingRawTx = rawTx;
    this.pendingTxHash = txHash;
    this.pendingDerivationPath = derivationPath;

    this.initiatorKeyShare = await this.opts.keyShareStore.load();

    const sessionId = uuidv4();
    const deadline = Date.now() + this.opts.timeoutMs;

    const request: SignRequestPayload = {
      sessionId,
      initiatorNodeId: this.opts.nodeId,
      initiatorPartyIndex: this.initiatorKeyShare.partyIndex,
      txHash,
      rawTx,
      derivationPath,
      deadline,
    };

    logger.info(`[SigningCoordinator] Broadcasting sign request ${sessionId}`);
    this.opts.nodeServer.broadcast(MessageType.SIGN_REQUEST, request);
    this.startTimeout(sessionId);
  }

  async handleMessage(fromNodeId: string | null, msg: { type: MessageType; payload: unknown }): Promise<void> {
    try {
      switch (msg.type) {
        case MessageType.SIGN_REQUEST:
          await this.onRequest(msg.payload as SignRequestPayload);
          break;
        case MessageType.SIGN_ACCEPT:
          await this.onAccept(fromNodeId!, msg.payload as SignAcceptPayload);
          break;
        case MessageType.SIGN_ROUND1:
          await this.onRound1(fromNodeId, msg.payload as SignRound1Payload);
          break;
        case MessageType.SIGN_ROUND2:
          await this.onRound2(fromNodeId, msg.payload as SignRound2Payload);
          break;
        case MessageType.SIGN_ROUND3:
          await this.onRound3(fromNodeId, msg.payload as SignRound3Payload);
          break;
        case MessageType.SIGN_ROUND4:
          await this.onRound4(fromNodeId, msg.payload as SignRound4Payload);
          break;
        case MessageType.SIGN_COMPLETE:
          await this.onComplete(msg.payload as SignCompletePayload);
          break;
        case MessageType.SIGN_ABORT:
          this.abort((msg.payload as { reason: string }).reason);
          break;
      }
    } catch (err) {
      const reason = err instanceof Error ? err.message : String(err);
      logger.error('[SigningCoordinator] Error:', err);
      this.abort(reason);
    }
  }

  private async onRequest(payload: SignRequestPayload): Promise<void> {
    if (this.session || this.sessionPending) return;

    // Reject stale requests
    if (Date.now() >= payload.deadline) {
      logger.warn(`[SigningCoordinator] Ignoring sign request ${payload.sessionId}: deadline already passed`);
      return;
    }

    // Independently verify the signing hash matches the raw transaction.
    // A compromised initiator could send txHash != keccak256(rawTx) to trick
    // participants into co-signing a different transaction than what was presented.
    let expectedHash: string;
    try {
      expectedHash = computeSigningHash(payload.rawTx);
    } catch (e) {
      logger.error(`[SigningCoordinator] Could not compute signing hash from rawTx — ignoring request: ${e}`);
      return;
    }
    if (expectedHash !== payload.txHash) {
      logger.error(`[SigningCoordinator] txHash mismatch in sign request ${payload.sessionId}: expected ${expectedHash}, got ${payload.txHash}`);
      return;
    }

    this.sessionPending = true;

    try {
      logger.info(`[SigningCoordinator] Received sign request ${payload.sessionId}`);

      const keyShare = await this.opts.keyShareStore.load();
      const partyIndex = keyShare.partyIndex;
      const addrIndex = parseAddressIndex(payload.derivationPath);
      const tweak = computeChildKeyTweak(keyShare.pkMaster, keyShare.chainCode, addrIndex);
      this.cachedSecretShare = (hexToScalar(keyShare.secretShare) + tweak) % CURVE_ORDER;

      const accept: SignAcceptPayload = {
        sessionId: payload.sessionId,
        nodeId: this.opts.nodeId,
        partyIndex,
      };

      this.opts.nodeServer.sendTo(payload.initiatorNodeId, MessageType.SIGN_ACCEPT, accept);
      logger.info(`[SigningCoordinator] Accepted signing session ${payload.sessionId}`);

      const initiatorSigner: SignerInfo = {
        nodeId: payload.initiatorNodeId,
        partyIndex: payload.initiatorPartyIndex,
      };
      const mySignerInfo: SignerInfo = { nodeId: this.opts.nodeId, partyIndex };

      this.session = createSigningSession(
        payload.sessionId,
        payload.txHash,
        payload.rawTx,
        payload.derivationPath,
        payload.deadline,
        [initiatorSigner, mySignerInfo],
        this.opts.nodeId
      );

      // Start participant timeout
      this.startTimeout(payload.sessionId);

      // Start Round 1 immediately as a participant
      await this.startRound1();
    } finally {
      this.sessionPending = false;
    }
  }

  private async onAccept(fromNodeId: string, payload: SignAcceptPayload): Promise<void> {
    this.acceptedSigners.set(fromNodeId, payload);
    logger.info(`[SigningCoordinator] ${fromNodeId} accepted signing (party ${payload.partyIndex}). Total: ${this.acceptedSigners.size}`);

    if (this.acceptedSigners.size >= 1 && !this.session && !this.sessionPending) {
      this.sessionPending = true;
      const keyShare = this.initiatorKeyShare!;
      const addrIndex = parseAddressIndex(this.pendingDerivationPath ?? '');
      const tweak = computeChildKeyTweak(keyShare.pkMaster, keyShare.chainCode, addrIndex);
      this.cachedSecretShare = (hexToScalar(keyShare.secretShare) + tweak) % CURVE_ORDER;

      const mySignerInfo: SignerInfo = { nodeId: this.opts.nodeId, partyIndex: keyShare.partyIndex };
      const otherSigners: SignerInfo[] = Array.from(this.acceptedSigners.values()).map((a) => ({
        nodeId: a.nodeId,
        partyIndex: a.partyIndex,
      }));

      const allSigners = [mySignerInfo, ...otherSigners];

      this.session = createSigningSession(
        payload.sessionId,
        this.pendingTxHash ?? '',
        this.pendingRawTx ?? {} as RawTxData,
        this.pendingDerivationPath ?? '',
        Date.now() + this.opts.timeoutMs,
        allSigners,
        this.opts.nodeId
      );

      await this.startRound1();
      this.sessionPending = false;
    }
  }

  private async startRound1(): Promise<void> {
    if (!this.session) return;
    const { updatedState, broadcast } = await executeSignRound1(this.session);
    // Paillier key generation is async. During the await, onRound1 may have fired and
    // updated this.session with peers' Paillier keys / round1Received entries.
    // Merge only our newly-generated fields into the CURRENT session to avoid
    // overwriting any concurrent state updates.
    if (!this.session) return; // aborted during key gen
    this.session = {
      ...this.session,
      myKi: updatedState.myKi,
      myGammaI: updatedState.myGammaI,
      myGammaIPoint: updatedState.myGammaIPoint,
      myPaillierN: updatedState.myPaillierN,
      myPaillierLambda: updatedState.myPaillierLambda,
      myPaillierMu: updatedState.myPaillierMu,
      status: 'round1',
    };
    this.opts.nodeServer.broadcast(MessageType.SIGN_ROUND1, broadcast);
    logger.info('[SigningCoordinator] Broadcast Sign Round 1');
    // Peers may have sent their Round 1 messages while Paillier gen was running.
    // Now that myKi is set, check if all Round 1 data is present to advance.
    if (isSignRound1Complete(this.session)) {
      this.startRound2();
    }
  }

  /** Throw if the current session has exceeded its deadline. */
  private checkDeadline(): void {
    if (this.session && Date.now() > this.session.deadline) {
      throw new SigningError(`Session ${this.session.sessionId} deadline exceeded`);
    }
  }

  private async onRound1(fromNodeId: string | null, payload: SignRound1Payload): Promise<void> {
    if (!this.session || payload.sessionId !== this.session.sessionId) return;
    if (!this.session.signers.some((s) => s.nodeId === payload.fromNodeId)) return;
    // Validate transport-layer sender matches self-reported fromNodeId
    if (fromNodeId !== null && fromNodeId !== payload.fromNodeId) {
      throw new SigningError(`Round 1 sender mismatch: transport says ${fromNodeId}, payload claims ${payload.fromNodeId}`);
    }
    this.checkDeadline();

    this.session = recordSignRound1(this.session, payload);
    logger.info(`[SigningCoordinator] Round 1 from ${payload.fromNodeId} (${this.session.round1Received.size}/${this.session.signers.length - 1})`);

    if (isSignRound1Complete(this.session)) {
      this.startRound2();
    }
  }

  private startRound2(): void {
    if (!this.session || this.session.status !== 'round1') return;
    this.session = { ...this.session, status: 'round2' };

    const x_i = this.cachedSecretShare!;
    const { updatedState, perPeerPayloads } = executeSignRound2(this.session, x_i);
    this.session = updatedState;

    for (const [nodeId, payload] of perPeerPayloads) {
      this.opts.nodeServer.sendTo(nodeId, MessageType.SIGN_ROUND2, payload);
    }
    logger.info('[SigningCoordinator] Sent Sign Round 2 (P2P MtA ciphertexts)');
  }

  private async onRound2(fromNodeId: string | null, payload: SignRound2Payload): Promise<void> {
    if (!this.session || payload.sessionId !== this.session.sessionId) return;
    // Only accept Round 2 messages addressed to us
    if (payload.toNodeId !== this.opts.nodeId) return;
    if (!this.session.signers.some((s) => s.nodeId === payload.fromNodeId)) return;
    if (fromNodeId !== null && fromNodeId !== payload.fromNodeId) {
      throw new SigningError(`Round 2 sender mismatch: transport says ${fromNodeId}, payload claims ${payload.fromNodeId}`);
    }
    this.checkDeadline();

    this.session = recordSignRound2(this.session, payload);
    logger.info(`[SigningCoordinator] Round 2 from ${payload.fromNodeId} (${this.session.round2Received.size}/${this.session.signers.length - 1})`);

    if (isSignRound2Complete(this.session)) {
      this.startRound3();
    }
  }

  private startRound3(): void {
    if (!this.session || this.session.status !== 'round2') return;
    this.session = { ...this.session, status: 'round3' };

    const x_i = this.cachedSecretShare!;
    const { updatedState, broadcast } = executeSignRound3(this.session, x_i);
    this.session = updatedState;
    this.opts.nodeServer.broadcast(MessageType.SIGN_ROUND3, broadcast);
    logger.info('[SigningCoordinator] Broadcast Sign Round 3 (delta+sigma shares)');
  }

  private async onRound3(fromNodeId: string | null, payload: SignRound3Payload): Promise<void> {
    if (!this.session || payload.sessionId !== this.session.sessionId) return;
    if (!this.session.signers.some((s) => s.nodeId === payload.fromNodeId)) return;
    if (fromNodeId !== null && fromNodeId !== payload.fromNodeId) {
      throw new SigningError(`Round 3 sender mismatch: transport says ${fromNodeId}, payload claims ${payload.fromNodeId}`);
    }
    this.checkDeadline();

    this.session = recordSignRound3(this.session, payload);
    logger.info(`[SigningCoordinator] Round 3 from ${payload.fromNodeId} (${this.session.round3Received.size}/${this.session.signers.length - 1})`);

    if (isSignRound3Complete(this.session)) {
      this.startRound4();
    }
  }

  private startRound4(): void {
    if (!this.session || this.session.status !== 'round3') return;
    this.session = { ...this.session, status: 'round4' };

    const { updatedState, broadcast, r } = executeSignRound4(this.session, this.session.txHash);
    this.session = updatedState;
    this.cachedR = r;
    this.opts.nodeServer.broadcast(MessageType.SIGN_ROUND4, broadcast);
    logger.info('[SigningCoordinator] Broadcast Sign Round 4 (partial signatures)');
  }

  private async onRound4(fromNodeId: string | null, payload: SignRound4Payload): Promise<void> {
    if (!this.session || payload.sessionId !== this.session.sessionId) return;
    if (!this.session.signers.some((s) => s.nodeId === payload.fromNodeId)) return;
    if (fromNodeId !== null && fromNodeId !== payload.fromNodeId) {
      throw new SigningError(`Round 4 sender mismatch: transport says ${fromNodeId}, payload claims ${payload.fromNodeId}`);
    }
    this.checkDeadline();

    if (!this.cachedR) {
      throw new SigningError('Received Round 4 message before our own Round 4 was computed');
    }
    this.session = recordSignRound4(this.session, payload, this.cachedR);
    logger.info(`[SigningCoordinator] Round 4 from ${payload.fromNodeId} (${this.session.round4Received.size}/${this.session.signers.length - 1})`);

    if (isSignRound4Complete(this.session)) {
      await this.finalize();
    }
  }

  private async finalize(): Promise<void> {
    if (!this.session || !this.cachedR) return;

    // Set immediately to prevent onComplete from double-emitting while we await below.
    this.alreadyFinalized = true;

    const sig = assembleSignature(this.session, this.cachedR);
    logger.info(`[SigningCoordinator] Signature assembled: r=${sig.r} s=${sig.s} v=${sig.v}`);

    // Verify signature against the derived child public key before broadcasting.
    // An invalid signature means a protocol error or malicious peer — abort immediately.
    try {
      const keyShare = await this.opts.keyShareStore.load();
      const addrIndex = parseAddressIndex(this.session.derivationPath);
      const tweak = computeChildKeyTweak(keyShare.pkMaster, keyShare.chainCode, addrIndex);
      const derivedPubKey = hexToPoint(keyShare.pkMaster).add(scalarMulG(tweak));
      const msgBytes = Buffer.from(this.session.txHash, 'hex');
      // @noble/curves d.ts types verify() as (Uint8Array, Uint8Array, Uint8Array).
      // Pass the signature as compact r‖s (64 bytes) and pubkey as compressed bytes.
      const sigBytes = Buffer.from(sig.r + sig.s, 'hex');
      const valid = nobleSecp.verify(sigBytes, msgBytes, derivedPubKey.toRawBytes());
      if (valid) {
        logger.info('[SigningCoordinator] Signature verified against derived public key ✓');
      } else {
        this.abort('Signature verification failed — aborting to prevent broadcasting invalid signature');
        return;
      }
    } catch (verifyErr) {
      this.abort(`Signature verification threw: ${verifyErr instanceof Error ? verifyErr.message : String(verifyErr)}`);
      return;
    }

    const rawTx = this.session.rawTx;
    if (!rawTx?.to) {
      this.abort('Cannot serialize transaction: rawTx.to is missing');
      return;
    }

    const signedTxHex = serializeTransaction(
      {
        type: 'eip1559',
        chainId: rawTx.chainId,
        nonce: rawTx.nonce,
        maxFeePerGas: BigInt(rawTx.maxFeePerGas),
        maxPriorityFeePerGas: BigInt(rawTx.maxPriorityFeePerGas),
        gas: BigInt(rawTx.gasLimit),
        to: rawTx.to as `0x${string}`,
        value: BigInt(rawTx.value),
        data: rawTx.data as `0x${string}`,
      },
      {
        r: `0x${sig.r}` as `0x${string}`,
        s: `0x${sig.s}` as `0x${string}`,
        yParity: (sig.v - 27) as 0 | 1,
      }
    );

    const complete: SignCompletePayload = {
      sessionId: this.session.sessionId,
      signature: sig,
      signedTxHex,
    };

    this.opts.nodeServer.broadcast(MessageType.SIGN_COMPLETE, complete);
    this.clearTimeout();
    this.emit('complete', sig, signedTxHex);
    // Release all sensitive session material after emitting
    this.resetState();
  }

  private async onComplete(payload: SignCompletePayload): Promise<void> {
    // Both parties independently call finalize() in this 4-round protocol, so
    // onComplete is redundant for participants who already completed. Ignore it.
    if (this.alreadyFinalized) return;
    // Guard against stale or crafted SIGN_COMPLETE for a different/expired session.
    if (!this.session || payload.sessionId !== this.session.sessionId) return;
    logger.info(`[SigningCoordinator] SIGN_COMPLETE received for session ${payload.sessionId}`);
    this.clearTimeout();
    this.emit('complete', payload.signature, payload.signedTxHex);
    this.resetState();
  }

  private abort(reason: string): void {
    logger.error(`[SigningCoordinator] Signing aborted: ${reason}`);
    this.clearTimeout();
    this.resetState();
    this.emit('aborted', reason);
  }

  /** Clear all session state and release sensitive material. Called on success and abort. */
  private resetState(): void {
    this.session = null;
    this.acceptedSigners.clear();
    this.pendingRawTx = null;
    this.pendingTxHash = null;
    this.pendingDerivationPath = null;
    this.initiatorKeyShare = null;
    this.cachedSecretShare = null;
    this.cachedR = null;
    this.sessionPending = false;
    this.alreadyFinalized = false;
  }

  private startTimeout(sessionId: string): void {
    this.clearTimeout();
    this.timeoutHandle = setTimeout(() => {
      this.abort(`Signing session ${sessionId} timed out`);
    }, this.opts.timeoutMs);
  }

  private clearTimeout(): void {
    if (this.timeoutHandle) {
      clearTimeout(this.timeoutHandle);
      this.timeoutHandle = null;
    }
  }

  /** Store a peer's RSA public key (kept for API compatibility; no longer used in signing). */
  setPeerPubkey(_nodeId: string, _pubkeyPem: string): void {
    // RSA keys are no longer used; MtA is now Paillier-based with keys exchanged in Round 1.
  }
}

// Helpers
function parseAddressIndex(derivationPath: string): number {
  const parts = derivationPath.split('/');
  const last = parseInt(parts[parts.length - 1], 10);
  if (isNaN(last)) {
    throw new SigningError(`Invalid derivation path — cannot parse address index: "${derivationPath}"`);
  }
  return last;
}

/**
 * Compute the EIP-1559 signing hash for a raw transaction.
 * Returns a 64-char lowercase hex string (no 0x prefix).
 *
 * Participants call this independently to verify that payload.txHash matches
 * keccak256(rawTx), preventing a compromised initiator from tricking them into
 * co-signing a different transaction than what was presented.
 */
export function computeSigningHash(rawTx: RawTxData): string {
  if (!rawTx.to) throw new SigningError('rawTx.to is missing');
  const unsigned = serializeTransaction({
    type: 'eip1559',
    chainId: rawTx.chainId,
    nonce: rawTx.nonce,
    maxFeePerGas: BigInt(rawTx.maxFeePerGas),
    maxPriorityFeePerGas: BigInt(rawTx.maxPriorityFeePerGas),
    gas: BigInt(rawTx.gasLimit),
    to: rawTx.to as `0x${string}`,
    value: BigInt(rawTx.value),
    data: rawTx.data as `0x${string}`,
  });
  return keccak256(unsigned).slice(2); // strip 0x prefix
}
