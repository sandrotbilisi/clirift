import { EventEmitter } from 'events';
import { v4 as uuidv4 } from 'uuid';
import {
  DkgLocalState,
  DkgParticipantInfo,
  createInitialDkgState,
} from './DkgState';
import { executeRound1, recordRound1, isRound1Complete } from './rounds/Round1';
import { executeRound2, recordRound2, isRound2Complete } from './rounds/Round2';
import { executeRound3, recordRound3, isRound3Complete } from './rounds/Round3';
import { executeRound4, recordRound4, isRound4Complete, assemblePkMaster } from './rounds/Round4';
import {
  MessageType,
  DkgRound1Payload,
  DkgRound2Payload,
  DkgRound3P2PPayload,
  DkgRound4Payload,
  DkgCompletePayload,
  DkgProposePayload,
  DkgAcceptPayload,
} from '../../network/protocol/Message';
import { NodeServer } from '../NodeServer';
import { KeyShareStore, KeyShareData, CeremonyMetadata } from '../../storage/KeyShareStore';
import logger from '../../utils/logger';
import { DkgError } from '../../utils/errors';

export interface DkgCoordinatorOptions {
  nodeId: string;
  nodeServer: NodeServer;
  keyShareStore: KeyShareStore;
  myPrivateKeyPem: string;
  threshold: number;
  totalParties: number;
  timeoutMs: number;
}

export type DkgCoordinatorEvents = {
  complete: (pkMaster: string, chainCode: string) => void;
  aborted: (reason: string) => void;
};

export declare interface DkgCoordinator {
  on<K extends keyof DkgCoordinatorEvents>(event: K, listener: DkgCoordinatorEvents[K]): this;
  emit<K extends keyof DkgCoordinatorEvents>(
    event: K,
    ...args: Parameters<DkgCoordinatorEvents[K]>
  ): boolean;
}

/**
 * DKG Coordinator: orchestrates the full 4-round DKG ceremony.
 * Can act as both initiator and participant.
 */
export class DkgCoordinator extends EventEmitter {
  private state: DkgLocalState | null = null;
  private opts: DkgCoordinatorOptions;
  private acceptedParticipants: Map<string, DkgAcceptPayload> = new Map();
  /** Map of nodeId → their public key PEM (for encrypting Round 3 shares) */
  private peerPubkeys: Map<string, string> = new Map();
  private ceremonyId: string | null = null;
  private timeoutHandle: NodeJS.Timeout | null = null;

  constructor(opts: DkgCoordinatorOptions) {
    super();
    this.opts = opts;
  }

  /**
   * Initiate a DKG ceremony. Broadcasts DKG_PROPOSE to all peers.
   * Call this after all peers are connected.
   */
  async initiate(): Promise<void> {
    const connectedNodeIds = this.opts.nodeServer.getConnectedNodeIds();

    if (connectedNodeIds.length < this.opts.totalParties - 1) {
      throw new DkgError(
        `Not enough peers connected: need ${this.opts.totalParties - 1}, have ${connectedNodeIds.length}`
      );
    }

    this.ceremonyId = uuidv4();
    const participants = [this.opts.nodeId, ...connectedNodeIds.slice(0, this.opts.totalParties - 1)];

    const propose: DkgProposePayload = {
      ceremonyId: this.ceremonyId,
      initiatorNodeId: this.opts.nodeId,
      participants,
      threshold: this.opts.threshold,
      totalParties: this.opts.totalParties,
      deadline: Date.now() + this.opts.timeoutMs,
    };

    logger.info(`[DkgCoordinator] Proposing ceremony ${this.ceremonyId} with participants: ${participants.join(', ')}`);
    this.opts.nodeServer.broadcast(MessageType.DKG_PROPOSE, propose);

    this.startTimeout();
  }

  /** Handle incoming DKG messages dispatched from NodeServer */
  async handleMessage(fromNodeId: string | null, msg: { type: MessageType; payload: unknown }): Promise<void> {
    try {
      switch (msg.type) {
        case MessageType.DKG_PROPOSE:
          await this.onPropose(msg.payload as DkgProposePayload);
          break;
        case MessageType.DKG_ACCEPT:
          await this.onAccept(fromNodeId!, msg.payload as DkgAcceptPayload);
          break;
        case MessageType.DKG_ROUND1:
          await this.onRound1(fromNodeId!, msg.payload as DkgRound1Payload);
          break;
        case MessageType.DKG_ROUND2:
          await this.onRound2(fromNodeId!, msg.payload as DkgRound2Payload);
          break;
        case MessageType.DKG_ROUND3_P2P:
          await this.onRound3(msg.payload as DkgRound3P2PPayload);
          break;
        case MessageType.DKG_ROUND4:
          await this.onRound4(fromNodeId!, msg.payload as DkgRound4Payload);
          break;
        case MessageType.DKG_COMPLETE:
          this.onComplete(msg.payload as DkgCompletePayload);
          break;
        case MessageType.DKG_ABORT:
          this.abort((msg.payload as { reason: string }).reason);
          break;
      }
    } catch (err) {
      const reason = err instanceof Error ? err.message : String(err);
      logger.error('[DkgCoordinator] Error handling message:', err);
      this.abort(reason);
    }
  }

  private async onPropose(payload: DkgProposePayload): Promise<void> {
    if (this.state) return; // already in a ceremony

    // Determine our party index
    const myIndex = payload.participants.indexOf(this.opts.nodeId) + 1;
    if (myIndex === 0) {
      logger.warn('[DkgCoordinator] Received DKG_PROPOSE but we are not in participants list');
      return;
    }

    this.ceremonyId = payload.ceremonyId;
    const participants: DkgParticipantInfo[] = payload.participants.map((id, i) => ({
      nodeId: id,
      partyIndex: i + 1,
    }));

    this.state = createInitialDkgState(
      payload.ceremonyId,
      myIndex,
      participants,
      payload.threshold,
      payload.totalParties
    );

    const accept: DkgAcceptPayload = {
      ceremonyId: payload.ceremonyId,
      nodeId: this.opts.nodeId,
      partyIndex: myIndex,
    };

    this.opts.nodeServer.sendTo(payload.initiatorNodeId, MessageType.DKG_ACCEPT, accept);
    logger.info(`[DkgCoordinator] Accepted ceremony ${payload.ceremonyId} as party ${myIndex}`);

    this.startTimeout();

    // Start Round 1 immediately (we don't wait for all accepts as participant)
    await this.startRound1();
  }

  private async onAccept(fromNodeId: string, payload: DkgAcceptPayload): Promise<void> {
    if (!this.ceremonyId || payload.ceremonyId !== this.ceremonyId) return;

    this.acceptedParticipants.set(fromNodeId, payload);
    logger.info(`[DkgCoordinator] ${fromNodeId} accepted (party ${payload.partyIndex}). Total: ${this.acceptedParticipants.size}`);

    // Once all other parties accept, set up state and start Round 1
    if (this.acceptedParticipants.size >= this.opts.totalParties - 1 && !this.state) {
      const allParticipants: DkgParticipantInfo[] = [
        { nodeId: this.opts.nodeId, partyIndex: 1 },
        ...Array.from(this.acceptedParticipants.values()).map((a) => ({
          nodeId: a.nodeId,
          partyIndex: a.partyIndex,
        })),
      ];

      this.state = createInitialDkgState(
        this.ceremonyId,
        1, // initiator is always party 1
        allParticipants,
        this.opts.threshold,
        this.opts.totalParties
      );

      await this.startRound1();
    }
  }

  private async startRound1(): Promise<void> {
    if (!this.state) return;
    const { updatedState, broadcast } = executeRound1(this.state);
    this.state = updatedState;
    logger.info('[DkgCoordinator] Broadcasting Round 1 commitment');
    this.opts.nodeServer.broadcast(MessageType.DKG_ROUND1, broadcast);
  }

  private async onRound1(fromNodeId: string, payload: DkgRound1Payload): Promise<void> {
    if (!this.state || payload.ceremonyId !== this.state.ceremonyId) return;
    this.state = recordRound1(this.state, payload);
    logger.info(`[DkgCoordinator] Round 1 received from ${fromNodeId} (${this.state.round1Received.size}/${this.state.totalParties - 1})`);

    if (isRound1Complete(this.state)) {
      await this.startRound2();
    }
  }

  private async startRound2(): Promise<void> {
    if (!this.state) return;
    const { updatedState, broadcast } = executeRound2(this.state);
    this.state = updatedState;
    logger.info('[DkgCoordinator] Broadcasting Round 2 decommitment + ZK proof');
    this.opts.nodeServer.broadcast(MessageType.DKG_ROUND2, broadcast);
  }

  private async onRound2(fromNodeId: string, payload: DkgRound2Payload): Promise<void> {
    if (!this.state || payload.ceremonyId !== this.state.ceremonyId) return;
    this.state = recordRound2(this.state, payload);
    logger.info(`[DkgCoordinator] Round 2 received from ${fromNodeId} (${this.state.round2Received.size}/${this.state.totalParties - 1})`);

    if (isRound2Complete(this.state)) {
      await this.startRound3();
    }
  }

  private async startRound3(): Promise<void> {
    if (!this.state) return;
    const messages = executeRound3(this.state, this.peerPubkeys);
    this.state = { ...this.state, status: 'round3' };

    logger.info(`[DkgCoordinator] Sending ${messages.length} P2P encrypted shares (Round 3)`);
    for (const m of messages) {
      this.opts.nodeServer.sendTo(m.toNodeId, MessageType.DKG_ROUND3_P2P, m.payload);
    }
  }

  private async onRound3(payload: DkgRound3P2PPayload): Promise<void> {
    if (!this.state || payload.ceremonyId !== this.state.ceremonyId) return;
    if (payload.toNodeId !== this.opts.nodeId) return; // not for us

    this.state = recordRound3(this.state, payload, this.opts.myPrivateKeyPem);
    logger.info(`[DkgCoordinator] Round 3 share received from ${payload.fromNodeId} (${this.state.sharesReceived.size}/${this.state.totalParties - 1})`);

    if (isRound3Complete(this.state)) {
      await this.startRound4();
    }
  }

  private async startRound4(): Promise<void> {
    if (!this.state) return;
    const { updatedState, broadcast } = executeRound4(this.state);
    this.state = updatedState;
    logger.info('[DkgCoordinator] Broadcasting Round 4 public key share');
    this.opts.nodeServer.broadcast(MessageType.DKG_ROUND4, broadcast);
  }

  private async onRound4(fromNodeId: string, payload: DkgRound4Payload): Promise<void> {
    if (!this.state || payload.ceremonyId !== this.state.ceremonyId) return;
    this.state = recordRound4(this.state, payload);
    logger.info(`[DkgCoordinator] Round 4 received from ${fromNodeId} (${this.state.publicKeySharesReceived.size}/${this.state.totalParties - 1})`);

    if (isRound4Complete(this.state)) {
      await this.finalize();
    }
  }

  private async finalize(): Promise<void> {
    if (!this.state) return;

    const { updatedState, complete } = assemblePkMaster(this.state);
    this.state = updatedState;

    logger.info(`[DkgCoordinator] Ceremony complete! PK_master: ${complete.pkMaster}`);

    // Save key share
    const shareData: KeyShareData = {
      partyIndex: this.state.myPartyIndex,
      secretShare: this.state.myKeyShare!.toString(16).padStart(64, '0'),
      publicKeyShares: [
        ...(this.state.myCoeffCommitments ? [this.state.myCoeffCommitments[0]] : []),
        ...Array.from(this.state.round2Received.values()).map((d) => d.coefficientCommitments[0]),
      ],
      pkMaster: complete.pkMaster,
      chainCode: complete.chainCode,
      ceremonyId: this.state.ceremonyId,
    };

    const metadata: CeremonyMetadata = {
      ceremonyId: this.state.ceremonyId,
      completedAt: Date.now(),
      participants: this.state.participants.map((p) => ({
        nodeId: p.nodeId,
        partyIndex: p.partyIndex,
        publicKeyShare:
          p.partyIndex === this.state!.myPartyIndex
            ? this.state!.myCoeffCommitments![0]
            : this.state!.round2Received.get(p.nodeId)?.coefficientCommitments[0] ?? '',
      })),
      threshold: this.state.threshold,
      totalParties: this.state.totalParties,
      pkMaster: complete.pkMaster,
      chainCode: complete.chainCode,
      version: '1.0.0',
    };

    await this.opts.keyShareStore.save(shareData, metadata);

    // Broadcast completion to all peers
    this.opts.nodeServer.broadcast(MessageType.DKG_COMPLETE, complete);

    this.clearTimeout();
    this.emit('complete', complete.pkMaster, complete.chainCode);
  }

  private onComplete(payload: DkgCompletePayload): void {
    logger.info(`[DkgCoordinator] Received DKG_COMPLETE: PK_master=${payload.pkMaster}`);
    // Non-initiator finalization is handled by their own finalize() call
  }

  private abort(reason: string): void {
    logger.error(`[DkgCoordinator] Ceremony aborted: ${reason}`);
    this.clearTimeout();

    if (this.state) {
      this.opts.nodeServer.broadcast(MessageType.DKG_ABORT, {
        ceremonyId: this.state.ceremonyId,
        reason,
        fromNodeId: this.opts.nodeId,
      });
    }

    this.state = null;
    this.emit('aborted', reason);
  }

  private startTimeout(): void {
    this.timeoutHandle = setTimeout(() => {
      this.abort('Ceremony timed out');
    }, this.opts.timeoutMs);
  }

  private clearTimeout(): void {
    if (this.timeoutHandle) {
      clearTimeout(this.timeoutHandle);
      this.timeoutHandle = null;
    }
  }

  /** Set peer public keys (called by NodeServer after NODE_HELLO handshakes) */
  setPeerPubkey(nodeId: string, pubkeyPem: string): void {
    this.peerPubkeys.set(nodeId, pubkeyPem);
  }
}
