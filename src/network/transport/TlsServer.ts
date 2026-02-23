import https from 'https';
import { WebSocketServer, WebSocket } from 'ws';
import { TlsCertificate } from '../security/TlsManager';
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
import { EventEmitter } from 'events';

export interface TlsServerOptions {
  port: number;
  host: string;
  certificate: TlsCertificate;
  selfHello: NodeHelloPayload;
}

export interface InboundPeer {
  socketId: string;        // Internal ID (before handshake)
  nodeId: string | null;   // Set after NODE_HELLO
  socket: WebSocket;
  connectedAt: number;
  handshakeComplete: boolean;
}

export interface TlsServerEvents {
  peerHandshaked: (socketId: string, nodeId: string, pubkeyPem: string) => void;
  peerDisconnected: (socketId: string, nodeId: string | null) => void;
  message: (socketId: string, nodeId: string | null, msg: Message) => void;
}

export declare interface TlsServer {
  on<K extends keyof TlsServerEvents>(event: K, listener: TlsServerEvents[K]): this;
  emit<K extends keyof TlsServerEvents>(
    event: K,
    ...args: Parameters<TlsServerEvents[K]>
  ): boolean;
}

/**
 * Inbound TLS WebSocket server for CLIRift node-to-node communication.
 * Performs NODE_HELLO / NODE_HELLO_ACK handshake on each inbound connection.
 * All further messages are forwarded via the 'message' event.
 */
export class TlsServer extends EventEmitter {
  private server: https.Server;
  private wss: WebSocketServer;
  private peers: Map<string, InboundPeer> = new Map();
  private readonly opts: TlsServerOptions;

  constructor(opts: TlsServerOptions) {
    super();
    this.opts = opts;

    this.server = https.createServer({
      cert: opts.certificate.cert,
      key: opts.certificate.key,
    });

    this.wss = new WebSocketServer({ server: this.server });
    this.setupWss();
  }

  private setupWss(): void {
    this.wss.on('connection', (ws: WebSocket) => {
      const socketId = `inbound-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;

      const peer: InboundPeer = {
        socketId,
        nodeId: null,
        socket: ws,
        connectedAt: Date.now(),
        handshakeComplete: false,
      };

      this.peers.set(socketId, peer);
      logger.debug(`[TlsServer] Inbound connection: ${socketId}`);

      ws.on('message', (data: Buffer) => {
        this.handleRaw(socketId, data.toString());
      });

      ws.on('close', () => {
        const p = this.peers.get(socketId);
        if (p) {
          logger.info(
            `[TlsServer] Peer disconnected: ${socketId} (nodeId=${p.nodeId ?? 'unknown'})`
          );
          this.peers.delete(socketId);
          this.emit('peerDisconnected', socketId, p.nodeId);
        }
      });

      ws.on('error', (err) => {
        logger.error(`[TlsServer] Socket error (${socketId}):`, err);
        this.peers.delete(socketId);
      });
    });
  }

  private handleRaw(socketId: string, raw: string): void {
    const peer = this.peers.get(socketId);
    if (!peer) return;

    try {
      const msg = deserializeMessage(raw);
      validateMessage(msg);
      validateTimestamp(msg.timestamp);

      if (!peer.handshakeComplete) {
        if (msg.type === MessageType.NODE_HELLO) {
          this.handleHello(peer, msg as Message<NodeHelloPayload>);
          return;
        }
        // Reject messages before handshake
        logger.warn(
          `[TlsServer] ${socketId}: message before handshake (type=${msg.type}), closing`
        );
        peer.socket.close();
        return;
      }

      // Forward message to node layer
      this.emit('message', socketId, peer.nodeId, msg);
    } catch (err) {
      logger.error(`[TlsServer] Message error (${socketId}):`, err);
    }
  }

  private handleHello(peer: InboundPeer, msg: Message<NodeHelloPayload>): void {
    const { nodeId, nodePubkeyPem, version, capabilities } = msg.payload;

    peer.nodeId = nodeId;
    peer.handshakeComplete = true;

    logger.info(
      `[TlsServer] NODE_HELLO from ${nodeId} (${version}), capabilities: ${capabilities.join(', ')}`
    );

    // Send ACK
    const ack: NodeHelloAckPayload = {
      nodeId: this.opts.selfHello.nodeId,
      nodePubkeyPem: this.opts.selfHello.nodePubkeyPem,
      version: this.opts.selfHello.version,
      capabilities: this.opts.selfHello.capabilities,
    };

    const ackMsg = createMessage(MessageType.NODE_HELLO_ACK, ack);
    peer.socket.send(serializeMessage(ackMsg));

    this.emit('peerHandshaked', peer.socketId, nodeId, nodePubkeyPem);
  }

  /** Send a message to a specific inbound peer by socketId */
  sendTo<T>(socketId: string, type: MessageType, payload: T): void {
    const peer = this.peers.get(socketId);
    if (!peer || peer.socket.readyState !== WebSocket.OPEN) {
      throw new ConnectionError(`Peer ${socketId} not available`);
    }
    const msg = createMessage(type, payload);
    peer.socket.send(serializeMessage(msg));
  }

  /** Send a message to all handshaked inbound peers */
  broadcast<T>(type: MessageType, payload: T): void {
    const msg = createMessage(type, payload);
    const data = serializeMessage(msg);
    this.broadcastRaw(data);
  }

  /** Send pre-serialized bytes to all handshaked inbound peers (use from NodeServer.broadcast) */
  broadcastRaw(data: string): void {
    for (const peer of this.peers.values()) {
      if (peer.handshakeComplete && peer.socket.readyState === WebSocket.OPEN) {
        peer.socket.send(data);
      }
    }
  }

  getConnectedPeers(): InboundPeer[] {
    return Array.from(this.peers.values()).filter((p) => p.handshakeComplete);
  }

  start(): Promise<void> {
    return new Promise((resolve, reject) => {
      this.server.listen(this.opts.port, this.opts.host, () => {
        logger.info(
          `[TlsServer] Listening on ${this.opts.host}:${this.opts.port}`
        );
        resolve();
      });

      this.server.on('error', (err) => {
        reject(new ConnectionError(`Failed to start server: ${err.message}`));
      });
    });
  }

  stop(): Promise<void> {
    return new Promise((resolve) => {
      for (const peer of this.peers.values()) {
        peer.socket.close();
      }
      this.wss.close(() => {
        this.server.close(() => {
          logger.info('[TlsServer] Stopped');
          resolve();
        });
      });
    });
  }
}
