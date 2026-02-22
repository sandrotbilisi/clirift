/**
 * TlsClient is now a thin re-export kept for compatibility.
 * Outbound peer connections are handled by PeerConnection in network/peers/.
 */
export { PeerConnection as TlsClient } from '../peers/PeerConnection';
export type { PeerConnectionOptions as TlsClientOptions } from '../peers/PeerConnection';
