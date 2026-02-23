import { EventEmitter } from 'events';
import { Message, MessageType, NodeHelloPayload } from '../protocol/Message';
import { PeerConnection, PeerInfo } from './PeerConnection';
import { PeerConfig } from './StaticPeerConfig';
import logger from '../../utils/logger';

export interface PeerManagerEvents {
  peerConnected: (nodeId: string, peer: PeerInfo) => void;
  peerDisconnected: (url: string) => void;
  message: (from: string | null, msg: Message) => void;
}

export declare interface PeerManager {
  on<K extends keyof PeerManagerEvents>(event: K, listener: PeerManagerEvents[K]): this;
  emit<K extends keyof PeerManagerEvents>(
    event: K,
    ...args: Parameters<PeerManagerEvents[K]>
  ): boolean;
}

/**
 * Manages outbound connections to all configured peer nodes.
 * Starts connection loops for each peer and aggregates events.
 */
export class PeerManager extends EventEmitter {
  private connections: Map<string, PeerConnection> = new Map(); // url → connection
  private selfHello: NodeHelloPayload;

  constructor(selfHello: NodeHelloPayload) {
    super();
    this.selfHello = selfHello;
  }

  /** Start connecting to all configured peers. Non-blocking. */
  start(peers: PeerConfig[]): void {
    for (const config of peers) {
      const conn = new PeerConnection({ config, selfHello: this.selfHello });
      this.connections.set(config.url, conn);

      conn.on('connected', (info) => {
        logger.info(`[PeerManager] Peer connected: ${info.nodeId} (${config.url})`);
        this.emit('peerConnected', info.nodeId, info);
      });

      conn.on('disconnected', () => {
        logger.info(`[PeerManager] Peer disconnected: ${config.url}`);
        this.emit('peerDisconnected', config.url);
      });

      conn.on('message', (msg) => {
        const peer = conn.peer;
        this.emit('message', peer?.nodeId ?? null, msg);
      });

      conn.on('error', (err) => {
        logger.warn(`[PeerManager] Peer error (${config.url}): ${err.message}`);
      });

      // Run connection loop in background (unhandled promise — errors logged internally)
      conn.start().catch((err) => {
        logger.error(`[PeerManager] Connection loop fatal error (${config.url}):`, err);
      });
    }

    logger.info(`[PeerManager] Started connections to ${peers.length} peer(s)`);
  }

  stop(): void {
    for (const conn of this.connections.values()) {
      conn.stop();
    }
  }

  /** Get all currently-connected peer infos */
  getConnectedPeers(): PeerInfo[] {
    const result: PeerInfo[] = [];
    for (const conn of this.connections.values()) {
      if (conn.peer && conn.currentState === 'connected') {
        result.push(conn.peer);
      }
    }
    return result;
  }

  /** Send a message to all connected peers */
  broadcast<T>(type: MessageType, payload: T): void {
    for (const [url, conn] of this.connections) {
      if (conn.currentState === 'connected') {
        try {
          conn.send(type, payload);
        } catch (err) {
          logger.warn(`[PeerManager] Failed to send to ${url}:`, err);
        }
      }
    }
  }

  /** Send pre-serialized bytes to all connected peers (same msg.id as TlsServer.broadcastRaw) */
  broadcastRaw(data: string): void {
    for (const [url, conn] of this.connections) {
      if (conn.currentState === 'connected') {
        try {
          conn.sendRaw(data);
        } catch (err) {
          logger.warn(`[PeerManager] Failed to send to ${url}:`, err);
        }
      }
    }
  }

  /** Send a message to a specific peer by nodeId */
  sendTo<T>(targetNodeId: string, type: MessageType, payload: T): boolean {
    for (const conn of this.connections.values()) {
      if (conn.peer?.nodeId === targetNodeId && conn.currentState === 'connected') {
        conn.send(type, payload);
        return true;
      }
    }
    return false;
  }
}
