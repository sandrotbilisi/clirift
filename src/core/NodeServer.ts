import { Config } from '../config/schema';
import { loadOrCreateNodeIdentity, extractPublicKeyPem } from '../network/security/NodeIdentity';
import { generateSelfSignedCertificate } from '../network/security/TlsManager';
import { TlsServer } from '../network/transport/TlsServer';
import { PeerManager } from '../network/peers/PeerManager';
import { parsePeerList } from '../network/peers/StaticPeerConfig';
import { Message, MessageType, NodeHelloPayload } from '../network/protocol/Message';
import logger from '../utils/logger';

export class NodeServer {
  private readonly config: Config;
  private tlsServer!: TlsServer;
  private peerManager!: PeerManager;
  /** Deduplicates messages that arrive via both inbound and outbound connections */
  private seenMessageIds = new Set<string>();

  constructor(config: Config) {
    this.config = config;
  }

  async start(): Promise<void> {
    const { config } = this;

    logger.info(`Starting CLIRift node ${config.CLIRFT_NODE_ID}...`);

    // 1. Load or create persistent node identity cert
    const identity = loadOrCreateNodeIdentity(
      config.CLIRFT_DATA_DIR,
      config.CLIRFT_NODE_ID
    );

    // 2. Build or load TLS server cert (separate from identity cert)
    const serverCert =
      config.CLIRFT_TLS_CERT_PATH && config.CLIRFT_TLS_KEY_PATH
        ? {
            cert: require('fs').readFileSync(config.CLIRFT_TLS_CERT_PATH, 'utf8'),
            key: require('fs').readFileSync(config.CLIRFT_TLS_KEY_PATH, 'utf8'),
            fingerprint: '',
          }
        : generateSelfSignedCertificate(
            87_600, // 10 years for persistent cloud node
            `clirft-node-${config.CLIRFT_NODE_ID}`
          );

    // 3. Build NODE_HELLO payload for this node
    const selfHello: NodeHelloPayload = {
      nodeId: config.CLIRFT_NODE_ID,
      nodePubkeyPem: extractPublicKeyPem(identity.certPem),
      version: '1.0.0',
      capabilities: ['dkg', 'sign'],
    };

    // 4. Start inbound TLS WebSocket server
    this.tlsServer = new TlsServer({
      port: config.CLIRFT_LISTEN_PORT,
      host: config.CLIRFT_LISTEN_HOST,
      certificate: serverCert,
      selfHello,
    });

    this.tlsServer.on('peerHandshaked', (socketId, nodeId, pubkeyPem) => {
      logger.info(`[NodeServer] Inbound peer handshaked: ${nodeId} (socket=${socketId})`);
      this.emitPeerIdentified(nodeId, pubkeyPem);
    });

    this.tlsServer.on('peerDisconnected', (socketId, nodeId) => {
      logger.info(
        `[NodeServer] Inbound peer disconnected: ${nodeId ?? 'unknown'} (socket=${socketId})`
      );
    });

    this.tlsServer.on('message', (socketId, nodeId, msg) => {
      this.handleMessage(socketId, nodeId, msg);
    });

    await this.tlsServer.start();

    // 5. Start outbound connections to configured peers
    const peers = parsePeerList(config.CLIRFT_PEERS.join(','));
    this.peerManager = new PeerManager(selfHello);

    this.peerManager.on('peerConnected', (nodeId, info) => {
      logger.info(`[NodeServer] Outbound peer connected: ${nodeId}`);
      this.emitPeerIdentified(nodeId, info.nodePubkeyPem);
    });

    this.peerManager.on('peerDisconnected', (url) => {
      logger.info(`[NodeServer] Outbound peer disconnected: ${url}`);
    });

    this.peerManager.on('message', (fromNodeId, msg) => {
      this.handleMessage(null, fromNodeId, msg);
    });

    this.peerManager.start(peers);

    logger.info(
      `[NodeServer] Node ${config.CLIRFT_NODE_ID} running on port ${config.CLIRFT_LISTEN_PORT}`
    );
  }

  private handleMessage(
    socketId: string | null,
    nodeId: string | null,
    msg: Message
  ): void {
    // Drop messages we've already processed (same msg arrives on both inbound+outbound connections)
    if (this.seenMessageIds.has(msg.id)) {
      logger.debug(`[NodeServer] Duplicate message ${msg.id} (type=${msg.type}) dropped`);
      return;
    }
    this.seenMessageIds.add(msg.id);
    if (this.seenMessageIds.size > 50_000) this.seenMessageIds.clear();

    logger.debug(
      `[NodeServer] Message from ${nodeId ?? 'unknown'} (${socketId ?? 'outbound'}): type=${msg.type}`
    );

    switch (msg.type) {
      case MessageType.HEARTBEAT:
        // Heartbeats are handled at transport level; ignore here
        break;

      case MessageType.DKG_PROPOSE:
      case MessageType.DKG_ACCEPT:
      case MessageType.DKG_ROUND1:
      case MessageType.DKG_ROUND2:
      case MessageType.DKG_ROUND3_P2P:
      case MessageType.DKG_ROUND4:
      case MessageType.DKG_COMPLETE:
      case MessageType.DKG_ABORT:
        // DKG messages are emitted for the DkgCoordinator/Participant layer
        this.emit('dkgMessage', nodeId, msg);
        break;

      case MessageType.SIGN_REQUEST:
      case MessageType.SIGN_ACCEPT:
      case MessageType.SIGN_REJECT:
      case MessageType.SIGN_ROUND1:
      case MessageType.SIGN_ROUND2:
      case MessageType.SIGN_ROUND3:
      case MessageType.SIGN_COMPLETE:
      case MessageType.SIGN_ABORT:
        this.emit('signMessage', nodeId, msg);
        break;

      default:
        logger.debug(`[NodeServer] Unhandled message type: ${msg.type}`);
    }
  }

  /** Broadcast a message to all connected peers (inbound + outbound) */
  broadcast<T>(type: MessageType, payload: T): void {
    this.tlsServer.broadcast(type, payload);
    this.peerManager.broadcast(type, payload);
  }

  /** Send a message to a specific peer by nodeId */
  sendTo<T>(targetNodeId: string, type: MessageType, payload: T): boolean {
    // Try outbound connections first
    if (this.peerManager.sendTo(targetNodeId, type, payload)) return true;

    // Try inbound connections
    for (const peer of this.tlsServer.getConnectedPeers()) {
      if (peer.nodeId === targetNodeId) {
        this.tlsServer.sendTo(peer.socketId, type, payload);
        return true;
      }
    }
    return false;
  }

  getConnectedNodeIds(): string[] {
    const ids = new Set<string>();
    for (const p of this.peerManager.getConnectedPeers()) ids.add(p.nodeId);
    for (const p of this.tlsServer.getConnectedPeers()) {
      if (p.nodeId) ids.add(p.nodeId);
    }
    return Array.from(ids);
  }

  // ── Peer public key registry (populated after NODE_HELLO handshake) ─────────
  private peerPubkeys: Map<string, string> = new Map();
  private _peerIdentifiedListeners: ((nodeId: string, pubkeyPem: string) => void)[] = [];

  getPeerPubkeys(): Map<string, string> {
    return new Map(this.peerPubkeys);
  }

  onPeerIdentified(listener: (nodeId: string, pubkeyPem: string) => void): void {
    this._peerIdentifiedListeners.push(listener);
  }

  private emitPeerIdentified(nodeId: string, pubkeyPem: string): void {
    this.peerPubkeys.set(nodeId, pubkeyPem);
    for (const l of this._peerIdentifiedListeners) l(nodeId, pubkeyPem);
  }

  // Simple event emitter for DKG / signing layers
  private _listeners: Map<string, ((nodeId: string | null, msg: Message) => void)[]> =
    new Map();

  emit(event: string, ...args: unknown[]): boolean {
    const listeners = this._listeners.get(event);
    if (listeners) {
      for (const l of listeners) l(args[0] as string | null, args[1] as Message);
    }
    return true;
  }

  on(event: string, listener: (nodeId: string | null, msg: Message) => void): this {
    if (!this._listeners.has(event)) this._listeners.set(event, []);
    this._listeners.get(event)!.push(listener);
    return this;
  }

  async stop(): Promise<void> {
    this.peerManager?.stop();
    await this.tlsServer?.stop();
    logger.info('[NodeServer] Stopped');
  }
}
