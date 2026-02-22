import fs from 'fs';
import path from 'path';
import { KmsEncryption, KmsEncryptedBlob } from './encryption/KmsEncryption';
import { LocalEncryption, LocalEncryptedBlob } from './encryption/LocalEncryption';
import { StorageError } from '../utils/errors';
import logger from '../utils/logger';

export interface KeyShareData {
  partyIndex: number;         // 1-indexed
  secretShare: string;        // x_i — hex big-endian scalar (32 bytes)
  publicKeyShares: string[];  // [x_1*G, x_2*G, x_3*G] compressed hex points
  pkMaster: string;           // compressed hex secp256k1 point
  chainCode: string;          // BIP32 chain code hex
  ceremonyId: string;
}

export interface CeremonyMetadata {
  ceremonyId: string;
  completedAt: number;
  participants: Array<{
    nodeId: string;
    partyIndex: number;
    publicKeyShare: string; // a_i(0)*G compressed hex
  }>;
  threshold: number;
  totalParties: number;
  pkMaster: string;
  chainCode: string;
  version: string;
}

type EncryptedBlob = KmsEncryptedBlob | LocalEncryptedBlob;

/**
 * Encrypted key share persistence layer.
 * Supports AWS KMS (production) and local AES-256-GCM (dev/test).
 *
 * Key share is ALWAYS encrypted at rest. The secret share (x_i) is
 * zeroed from memory as soon as it is no longer needed.
 */
export class KeyShareStore {
  private readonly sharePath: string;
  private readonly ceremonyPath: string;
  private readonly kms?: KmsEncryption;
  private readonly local?: LocalEncryption;
  private readonly backend: 'kms' | 'local';
  private readonly nodeId: string;

  constructor(
    dataDir: string,
    nodeId: string,
    backend: 'kms' | 'local',
    opts: { kmsKeyId?: string; localPassphrase?: string }
  ) {
    this.sharePath = path.join(dataDir, 'keyshare', 'keyshare.enc');
    this.ceremonyPath = path.join(dataDir, 'keyshare', 'ceremony.json');
    this.backend = backend;
    this.nodeId = nodeId;

    if (backend === 'kms') {
      if (!opts.kmsKeyId) throw new StorageError('kmsKeyId required for KMS backend');
      this.kms = new KmsEncryption(opts.kmsKeyId);
    } else {
      if (!opts.localPassphrase) throw new StorageError('localPassphrase required for local backend');
      this.local = new LocalEncryption(opts.localPassphrase);
    }
  }

  /** Save encrypted key share and public ceremony metadata */
  async save(share: KeyShareData, metadata: CeremonyMetadata): Promise<void> {
    const dir = path.dirname(this.sharePath);
    fs.mkdirSync(dir, { recursive: true });

    const plaintext = Buffer.from(JSON.stringify(share), 'utf8');

    let blob: EncryptedBlob;

    if (this.backend === 'kms' && this.kms) {
      blob = await this.kms.encrypt(plaintext, {
        NodeId: this.nodeId,
        CeremonyId: share.ceremonyId,
        Purpose: 'CLIRift-KeyShare',
      });
    } else if (this.backend === 'local' && this.local) {
      blob = await this.local.encrypt(plaintext);
    } else {
      throw new StorageError('No encryption backend configured');
    }

    // Write encrypted blob
    fs.writeFileSync(this.sharePath, JSON.stringify(blob, null, 2), { mode: 0o600 });
    logger.info(`[KeyShareStore] Key share saved to ${this.sharePath}`);

    // Write public ceremony metadata (unencrypted — contains no secret material)
    fs.writeFileSync(this.ceremonyPath, JSON.stringify(metadata, null, 2), { mode: 0o644 });
    logger.info(`[KeyShareStore] Ceremony metadata saved to ${this.ceremonyPath}`);

    // Zero plaintext buffer
    plaintext.fill(0);
  }

  /** Load and decrypt the key share. Caller must zero the secretShare field when done. */
  async load(): Promise<KeyShareData> {
    if (!fs.existsSync(this.sharePath)) {
      throw new StorageError(
        `Key share file not found: ${this.sharePath}. Run 'clirft keygen' first.`
      );
    }

    const blobRaw = JSON.parse(fs.readFileSync(this.sharePath, 'utf8')) as EncryptedBlob;

    let plaintext: Buffer;

    if (this.backend === 'kms' && this.kms) {
      plaintext = await this.kms.decrypt(blobRaw as KmsEncryptedBlob);
    } else if (this.backend === 'local' && this.local) {
      plaintext = await this.local.decrypt(blobRaw as LocalEncryptedBlob);
    } else {
      throw new StorageError('No encryption backend configured');
    }

    try {
      return JSON.parse(plaintext.toString('utf8')) as KeyShareData;
    } finally {
      plaintext.fill(0);
    }
  }

  /** Load public ceremony metadata (no decryption needed). */
  loadCeremonyMetadata(): CeremonyMetadata | null {
    if (!fs.existsSync(this.ceremonyPath)) return null;
    return JSON.parse(fs.readFileSync(this.ceremonyPath, 'utf8')) as CeremonyMetadata;
  }

  exists(): boolean {
    return fs.existsSync(this.sharePath);
  }
}
