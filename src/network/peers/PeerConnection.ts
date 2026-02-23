import { EventEmitter } from 'events';
import WebSocket from 'ws';
import {
  Message,
  MessageType,
  NodeHelloPayload,
  NodeHelloAckPayload,
} from '../protocol/Message';
import {
  createMessage,
  serializeMessage,
  deserializeMessage,
} from '../protocol/MessageCodec';
import { validateMessage, validateTimestamp } from '../protocol/MessageValidator';
import logger from '../../utils/logger';
import { ConnectionError } from '../../utils/errors';
import { backoffDelay, sleep } from '../../utils/retry';
import { PeerConfig } from './StaticPeerConfig';

export type PeerState = 'disconnected' | 'connecting' | 'handshaking' | 'connected';

export interface PeerInfo {
  nodeId: string;
  nodePubkeyPem: string;
  version: string;
  capabilities: string[];
  certFingerprint?: string;
}

export interface PeerConnectionEvents {
  connected: (peer: PeerInfo) => void;
  disconnected: () => void;
  message: (msg: Message) => void;
  error: (err: Error) => void;
}

export declare interface PeerConnection {
  on<K extends keyof PeerConnectionEvents>(event: K, listener: PeerConnectionEvents[K]): this;
  emit<K extends keyof PeerConnectionEvents>(
    event: K,
    ...args: Parameters<PeerConnectionEvents[K]>
  ): boolean;
}

export interface PeerConnectionOptions {
  config: PeerConfig;
  selfHello: NodeHelloPayload;
  /** Stop retrying after this many attempts (0 = retry forever) */
  maxAttempts?: number;
}

/**
 * Manages a single outbound WebSocket connection to a peer node.
 * Automatically reconnects with exponential backoff on disconnect.
 * Performs NODE_HELLO handshake on each connection.
 */
export class PeerConnection extends EventEmitter {
  private ws: WebSocket | null = null;
  private state: PeerState = 'disconnected';
  private peerInfo: PeerInfo | null = null;
  private attempt = 0;
  private stopped = false;
  private readonly opts: PeerConnectionOptions;

  constructor(opts: PeerConnectionOptions) {
    super();
    this.opts = opts;
  }

  get url(): string { return this.opts.config.url; }
  get currentState(): PeerState { return this.state; }
  get peer(): PeerInfo | null { return this.peerInfo; }

  /** Start the connection loop (runs forever until stop() is called). */
  async start(): Promise<void> {
    this.stopped = false;
    while (!this.stopped) {
      try {
        await this.connectOnce();
        this.attempt = 0; // reset backoff on success
        // Wait for disconnect before retrying
        await this.waitForClose();
      } catch (err) {
        if (this.stopped) break;
        const delay = backoffDelay(this.attempt++);
        logger.warn(
          `[PeerConnection] ${this.url} — connect failed (attempt ${this.attempt}), retrying in ${delay}ms: ${err}`
        );
        await sleep(delay);
      }
    }
  }

  stop(): void {
    this.stopped = true;
    this.ws?.close();
  }

  /** Send a message to this peer. */
  send<T>(type: MessageType, payload: T): void {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
      throw new ConnectionError(`Peer ${this.url} is not connected`);
    }
    const msg = createMessage(type, payload);
    this.ws.send(serializeMessage(msg));
  }

  /** Send pre-serialized bytes to this peer (use from PeerManager.broadcastRaw) */
  sendRaw(data: string): void {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
      throw new ConnectionError(`Peer ${this.url} is not connected`);
    }
    this.ws.send(data);
  }

  private connectOnce(): Promise<void> {
    return new Promise((resolve, reject) => {
      this.state = 'connecting';
      logger.info(`[PeerConnection] Connecting to ${this.url}...`);

      const ws = new WebSocket(this.url, {
        rejectUnauthorized: false, // self-signed identity certs allowed; pinning via fingerprint
      });

      this.ws = ws;

      ws.once('open', () => {
        this.state = 'handshaking';
        logger.info(`[PeerConnection] Connected to ${this.url}, sending NODE_HELLO`);
        this.sendHello(ws);
        resolve();
      });

      ws.once('error', (err) => {
        if (this.state === 'connecting') {
          reject(new ConnectionError(`${this.url}: ${err.message}`));
        } else {
          this.emit('error', new ConnectionError(err.message));
        }
      });

      ws.on('message', (data: Buffer) => {
        this.handleRaw(data.toString());
      });

      ws.once('close', () => {
        if (this.state !== 'disconnected') {
          this.state = 'disconnected';
          this.peerInfo = null;
          logger.info(`[PeerConnection] Disconnected from ${this.url}`);
          this.emit('disconnected');
        }
      });
    });
  }

  private waitForClose(): Promise<void> {
    return new Promise((resolve) => {
      if (!this.ws || this.state === 'disconnected') {
        resolve();
        return;
      }
      this.ws.once('close', () => resolve());
    });
  }

  private sendHello(ws: WebSocket): void {
    const msg = createMessage(MessageType.NODE_HELLO, this.opts.selfHello);
    ws.send(serializeMessage(msg));
  }

  private handleRaw(raw: string): void {
    try {
      const msg = deserializeMessage(raw);
      validateMessage(msg);
      validateTimestamp(msg.timestamp);

      if (this.state === 'handshaking' && msg.type === MessageType.NODE_HELLO_ACK) {
        this.handleHelloAck(msg as Message<NodeHelloAckPayload>);
        return;
      }

      // Forward all other messages to listeners
      this.emit('message', msg);
    } catch (err) {
      logger.error(`[PeerConnection] ${this.url} message error:`, err);
    }
  }

  private handleHelloAck(msg: Message<NodeHelloAckPayload>): void {
    const { nodeId, nodePubkeyPem, version, capabilities } = msg.payload;

    // Validate expected nodeId if configured
    if (
      this.opts.config.expectedNodeId &&
      nodeId !== this.opts.config.expectedNodeId
    ) {
      logger.error(
        `[PeerConnection] ${this.url}: expected nodeId ${this.opts.config.expectedNodeId}, got ${nodeId}`
      );
      this.ws?.close();
      return;
    }

    this.peerInfo = { nodeId, nodePubkeyPem, version, capabilities };
    this.state = 'connected';

    logger.info(
      `[PeerConnection] Handshake complete with ${nodeId} (${version}) at ${this.url}`
    );

    this.emit('connected', this.peerInfo);
  }
}
