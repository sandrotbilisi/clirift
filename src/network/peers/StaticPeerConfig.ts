import { CLIRiftError } from '../../utils/errors';

export interface PeerConfig {
  url: string;   // Full WSS URL, e.g. wss://node2.example.com:8443
  /** Expected node ID (UUID). Optional — validated after NODE_HELLO handshake */
  expectedNodeId?: string;
  /** Expected cert fingerprint (formatted XX:XX:...). Optional — validated after connect */
  expectedFingerprint?: string;
}

/**
 * Parse the CLIRFT_PEERS env var into a list of PeerConfig objects.
 * Format: comma-separated WSS URLs, optionally with nodeId and fingerprint:
 *
 *   wss://node2.example.com:8443
 *   wss://node2.example.com:8443?nodeId=<uuid>&fingerprint=<XX:XX:...>
 */
export function parsePeerList(peersEnvVar: string): PeerConfig[] {
  const entries = peersEnvVar
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);

  if (entries.length === 0) {
    throw new CLIRiftError('CLIRFT_PEERS must contain at least one peer URL');
  }

  return entries.map((entry) => {
    try {
      const url = new URL(entry);

      if (url.protocol !== 'wss:') {
        throw new CLIRiftError(
          `Peer URL must use wss:// protocol, got: ${entry}`
        );
      }

      const expectedNodeId = url.searchParams.get('nodeId') ?? undefined;
      const expectedFingerprint = url.searchParams.get('fingerprint') ?? undefined;

      // Strip query params from the WS URL used for connection
      url.search = '';

      return { url: url.toString(), expectedNodeId, expectedFingerprint };
    } catch (err) {
      if (err instanceof CLIRiftError) throw err;
      throw new CLIRiftError(`Invalid peer URL: ${entry}`);
    }
  });
}
