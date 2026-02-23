import { EventEmitter } from 'events';
import { v4 as uuidv4 } from 'uuid';
import { serializeTransaction } from 'viem';
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
  assembleSignature,
} from './rounds/SignRound3';
import {
  MessageType,
  SignRequestPayload,
  SignAcceptPayload,
  SignRound1Payload,
  SignRound2Payload,
  SignRound3Payload,
  SignCompletePayload,
  RawTxData,
} from '../../network/protocol/Message';
import { NodeServer } from '../NodeServer';
import { KeyShareStore } from '../../storage/KeyShareStore';
import logger from '../../utils/logger';

export interface SigningCoordinatorOptions {
  nodeId: string;
  nodeServer: NodeServer;
  keyShareStore: KeyShareStore;
  myPrivateKeyPem: string;
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
  private peerPubkeys: Map<string, string> = new Map();
  private opts: SigningCoordinatorOptions;
  private timeoutHandle: NodeJS.Timeout | null = null;
  private pendingRawTx: RawTxData | null = null;
  private pendingTxHash: string | null = null;
  private pendingDerivationPath: string | null = null;
  /** Prevents async race where two duplicate messages both pass the `if (!this.session)` guard */
  private sessionPending = false;

  constructor(opts: SigningCoordinatorOptions) {
    super();
    this.opts = opts;
  }

  /** Initiate a signing session as the request initiator */
  async initiate(rawTx: RawTxData, derivationPath: string, txHash: string): Promise<void> {
    this.pendingRawTx = rawTx;
    this.pendingTxHash = txHash;
    this.pendingDerivationPath = derivationPath;

    const keyShare = await this.opts.keyShareStore.load();

    const sessionId = uuidv4();
    const deadline = Date.now() + this.opts.timeoutMs;

    const request: SignRequestPayload = {
      sessionId,
      initiatorNodeId: this.opts.nodeId,
      initiatorPartyIndex: keyShare.partyIndex,
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
          await this.onRound1(fromNodeId!, msg.payload as SignRound1Payload);
          break;
        case MessageType.SIGN_ROUND2:
          await this.onRound2(fromNodeId!, msg.payload as SignRound2Payload);
          break;
        case MessageType.SIGN_ROUND3:
          await this.onRound3(fromNodeId!, msg.payload as SignRound3Payload);
          break;
        case MessageType.SIGN_COMPLETE:
          this.onComplete(msg.payload as SignCompletePayload);
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
    this.sessionPending = true;

    try {
      logger.info(`[SigningCoordinator] Received sign request ${payload.sessionId}`);

      const keyShare = await this.opts.keyShareStore.load();
      const partyIndex = keyShare.partyIndex;

      const accept: SignAcceptPayload = {
        sessionId: payload.sessionId,
        nodeId: this.opts.nodeId,
        partyIndex,
      };

      this.opts.nodeServer.sendTo(payload.initiatorNodeId, MessageType.SIGN_ACCEPT, accept);
      logger.info(`[SigningCoordinator] Accepted signing session ${payload.sessionId}`);

      // Build signers list: [initiator, me] — enough for a 2-of-3 threshold
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

      // Start Round 1 immediately as a participant
      await this.startRound1();
    } finally {
      this.sessionPending = false;
    }
  }

  private async onAccept(fromNodeId: string, payload: SignAcceptPayload): Promise<void> {
    this.acceptedSigners.set(fromNodeId, payload);
    logger.info(`[SigningCoordinator] ${fromNodeId} accepted signing (party ${payload.partyIndex}). Total: ${this.acceptedSigners.size}`);

    // Start signing once we have at least threshold-1 acceptances
    if (this.acceptedSigners.size >= 1 && !this.session && !this.sessionPending) {
      this.sessionPending = true;
      // Load key share
      const keyShare = await this.opts.keyShareStore.load();

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

      await this.startRound1(keyShare);
      this.sessionPending = false;
    }
  }

  private async startRound1(_keyShare?: Awaited<ReturnType<KeyShareStore['load']>>): Promise<void> {
    if (!this.session) return;
    const { updatedState, broadcast } = executeSignRound1(this.session, this.peerPubkeys);
    this.session = updatedState;
    this.opts.nodeServer.broadcast(MessageType.SIGN_ROUND1, broadcast);
    logger.info('[SigningCoordinator] Broadcast Sign Round 1');
  }

  private async onRound1(fromNodeId: string, payload: SignRound1Payload): Promise<void> {
    if (!this.session || payload.sessionId !== this.session.sessionId) return;
    this.session = recordSignRound1(this.session, payload);
    logger.info(`[SigningCoordinator] Round 1 from ${fromNodeId} (${this.session.round1Received.size}/${this.session.signers.length - 1})`);

    if (isSignRound1Complete(this.session)) {
      await this.startRound2();
    }
  }

  private async startRound2(): Promise<void> {
    if (!this.session || this.session.status !== 'round1') return;
    this.session = { ...this.session, status: 'round2' }; // reserve before any await
    const { updatedState, broadcast } = executeSignRound2(this.session, this.opts.myPrivateKeyPem);
    this.session = updatedState;
    this.opts.nodeServer.broadcast(MessageType.SIGN_ROUND2, broadcast);
    logger.info('[SigningCoordinator] Broadcast Sign Round 2');
  }

  private async onRound2(fromNodeId: string, payload: SignRound2Payload): Promise<void> {
    if (!this.session || payload.sessionId !== this.session.sessionId) return;
    this.session = recordSignRound2(this.session, payload);
    logger.info(`[SigningCoordinator] Round 2 from ${fromNodeId} (${this.session.round2Received.size}/${this.session.signers.length - 1})`);

    if (isSignRound2Complete(this.session)) {
      await this.startRound3();
    }
  }

  private async startRound3(): Promise<void> {
    if (!this.session || this.session.status !== 'round2') return;
    this.session = { ...this.session, status: 'round3' }; // reserve before await
    const keyShare = await this.opts.keyShareStore.load();
    const x_i = hexToScalar(keyShare.secretShare);

    const { updatedState, broadcast } = executeSignRound3(
      this.session,
      x_i,
      this.session.txHash
    );
    this.session = updatedState;
    this.opts.nodeServer.broadcast(MessageType.SIGN_ROUND3, broadcast);
    logger.info('[SigningCoordinator] Broadcast Sign Round 3');
  }

  private async onRound3(fromNodeId: string, payload: SignRound3Payload): Promise<void> {
    if (!this.session || payload.sessionId !== this.session.sessionId) return;
    this.session = recordSignRound3(this.session, payload);
    logger.info(`[SigningCoordinator] Round 3 from ${fromNodeId} (${this.session.round3Received.size}/${this.session.signers.length - 1})`);

    if (isSignRound3Complete(this.session)) {
      await this.finalize();
    }
  }

  private async finalize(): Promise<void> {
    if (!this.session) return;
    const sig = assembleSignature(this.session);

    logger.info(`[SigningCoordinator] Signature assembled: r=${sig.r} s=${sig.s} v=${sig.v}`);

    const rawTx = this.session.rawTx;
    let signedTxHex: string;
    if (rawTx?.to) {
      signedTxHex = serializeTransaction(
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
    } else {
      signedTxHex = `0x${sig.r}${sig.s}`;
    }

    const complete: SignCompletePayload = {
      sessionId: this.session.sessionId,
      signature: sig,
      signedTxHex,
    };

    this.opts.nodeServer.broadcast(MessageType.SIGN_COMPLETE, complete);
    this.clearTimeout();
    this.emit('complete', sig, signedTxHex);
  }

  private onComplete(payload: SignCompletePayload): void {
    logger.info(`[SigningCoordinator] SIGN_COMPLETE received for session ${payload.sessionId}`);
    this.clearTimeout();
    this.emit('complete', payload.signature, payload.signedTxHex);
  }

  private abort(reason: string): void {
    logger.error(`[SigningCoordinator] Signing aborted: ${reason}`);
    this.clearTimeout();
    this.session = null;
    this.emit('aborted', reason);
  }

  private startTimeout(sessionId: string): void {
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

  setPeerPubkey(nodeId: string, pubkeyPem: string): void {
    this.peerPubkeys.set(nodeId, pubkeyPem);
  }
}

// Helper
function hexToScalar(hex: string): bigint {
  return BigInt('0x' + hex.replace(/^0x/, ''));
}
