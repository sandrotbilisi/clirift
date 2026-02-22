import { KMSClient, GenerateDataKeyCommand, DecryptCommand } from '@aws-sdk/client-kms';
import { createCipheriv, createDecipheriv, randomBytes } from 'crypto';
import { StorageError } from '../../utils/errors';
import logger from '../../utils/logger';

const ALGORITHM = 'aes-256-gcm';
const KEY_SPEC = 'AES_256';

export interface KmsEncryptedBlob {
  version: 1;
  algorithm: 'AES-256-GCM';
  kmsKeyId: string;
  encryptedDataKey: string; // base64
  iv: string;               // base64, 12 bytes
  authTag: string;          // base64, 16 bytes
  ciphertext: string;       // base64
  encryptionContext: Record<string, string>;
}

/**
 * AWS KMS envelope encryption for key shares.
 *
 * Security model:
 * - Each encrypt call generates a fresh 256-bit DEK via KMS GenerateDataKey
 * - The DEK is used to AES-256-GCM encrypt the plaintext
 * - The KMS-wrapped DEK ciphertext is stored alongside the encrypted data
 * - Decryption requires the instance's IAM role to have kms:Decrypt on this key
 * - EncryptionContext binds the ciphertext to this specific node
 */
export class KmsEncryption {
  private client: KMSClient;
  private readonly keyId: string;

  constructor(keyId: string, region?: string) {
    this.keyId = keyId;
    this.client = new KMSClient({ region: region ?? process.env.AWS_REGION ?? 'us-east-1' });
  }

  async encrypt(
    plaintext: Buffer,
    context: Record<string, string>
  ): Promise<KmsEncryptedBlob> {
    logger.info('[KmsEncryption] Generating data key via KMS...');

    // Generate a 256-bit DEK
    const genKeyResult = await this.client.send(
      new GenerateDataKeyCommand({
        KeyId: this.keyId,
        KeySpec: KEY_SPEC,
        EncryptionContext: context,
      })
    );

    if (!genKeyResult.Plaintext || !genKeyResult.CiphertextBlob) {
      throw new StorageError('KMS GenerateDataKey returned incomplete response');
    }

    const dek = Buffer.from(genKeyResult.Plaintext);
    const encryptedDek = Buffer.from(genKeyResult.CiphertextBlob);

    try {
      // Encrypt plaintext with DEK using AES-256-GCM
      const iv = randomBytes(12);
      const cipher = createCipheriv(ALGORITHM, dek, iv);
      const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
      const authTag = cipher.getAuthTag();

      return {
        version: 1,
        algorithm: 'AES-256-GCM',
        kmsKeyId: this.keyId,
        encryptedDataKey: encryptedDek.toString('base64'),
        iv: iv.toString('base64'),
        authTag: authTag.toString('base64'),
        ciphertext: encrypted.toString('base64'),
        encryptionContext: context,
      };
    } finally {
      // Zero DEK from memory
      dek.fill(0);
    }
  }

  async decrypt(blob: KmsEncryptedBlob): Promise<Buffer> {
    logger.info('[KmsEncryption] Decrypting data key via KMS...');

    const decryptResult = await this.client.send(
      new DecryptCommand({
        CiphertextBlob: Buffer.from(blob.encryptedDataKey, 'base64'),
        EncryptionContext: blob.encryptionContext,
        KeyId: this.keyId,
      })
    );

    if (!decryptResult.Plaintext) {
      throw new StorageError('KMS Decrypt returned empty plaintext');
    }

    const dek = Buffer.from(decryptResult.Plaintext);

    try {
      const iv = Buffer.from(blob.iv, 'base64');
      const authTag = Buffer.from(blob.authTag, 'base64');
      const ciphertext = Buffer.from(blob.ciphertext, 'base64');

      const decipher = createDecipheriv(ALGORITHM, dek, iv);
      decipher.setAuthTag(authTag);

      return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    } finally {
      // Zero DEK from memory
      dek.fill(0);
    }
  }
}
