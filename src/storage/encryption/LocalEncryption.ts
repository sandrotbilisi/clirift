import { createCipheriv, createDecipheriv, randomBytes } from 'crypto';
import argon2 from 'argon2';
import { StorageError } from '../../utils/errors';
import logger from '../../utils/logger';

const ALGORITHM = 'aes-256-gcm';
const SALT_LEN = 32;

export interface LocalEncryptedBlob {
  version: 1;
  algorithm: 'AES-256-GCM';
  kdf: 'argon2id';
  /** Argon2id salt (base64) */
  salt: string;
  iv: string;       // base64, 12 bytes
  authTag: string;  // base64, 16 bytes
  ciphertext: string; // base64
}

/**
 * Local AES-256-GCM encryption with Argon2id key derivation.
 * FOR DEVELOPMENT / TESTING ONLY.
 *
 * In production, use KmsEncryption instead.
 * This implementation is secure but the passphrase must be managed externally.
 */
export class LocalEncryption {
  private readonly passphrase: string;

  constructor(passphrase: string) {
    if (passphrase.length < 32) {
      throw new StorageError('LocalEncryption passphrase must be at least 32 characters');
    }
    this.passphrase = passphrase;
  }

  async encrypt(plaintext: Buffer): Promise<LocalEncryptedBlob> {
    logger.info('[LocalEncryption] Encrypting with Argon2id-derived key...');

    const salt = randomBytes(SALT_LEN);

    // Derive 256-bit key from passphrase
    const key = await argon2.hash(this.passphrase, {
      type: argon2.argon2id,
      salt,
      memoryCost: 65536, // 64 MB
      timeCost: 3,
      parallelism: 4,
      hashLength: 32,
      raw: true,
    });

    const keyBuf = Buffer.isBuffer(key) ? key : Buffer.from(key as Uint8Array);

    try {
      const iv = randomBytes(12);
      const cipher = createCipheriv(ALGORITHM, keyBuf, iv);
      const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
      const authTag = cipher.getAuthTag();

      return {
        version: 1,
        algorithm: 'AES-256-GCM',
        kdf: 'argon2id',
        salt: salt.toString('base64'),
        iv: iv.toString('base64'),
        authTag: authTag.toString('base64'),
        ciphertext: encrypted.toString('base64'),
      };
    } finally {
      keyBuf.fill(0);
    }
  }

  async decrypt(blob: LocalEncryptedBlob): Promise<Buffer> {
    logger.info('[LocalEncryption] Deriving key and decrypting...');

    const salt = Buffer.from(blob.salt, 'base64');

    const key = await argon2.hash(this.passphrase, {
      type: argon2.argon2id,
      salt,
      memoryCost: 65536,
      timeCost: 3,
      parallelism: 4,
      hashLength: 32,
      raw: true,
    });

    const keyBuf = Buffer.isBuffer(key) ? key : Buffer.from(key as Uint8Array);

    try {
      const iv = Buffer.from(blob.iv, 'base64');
      const authTag = Buffer.from(blob.authTag, 'base64');
      const ciphertext = Buffer.from(blob.ciphertext, 'base64');

      const decipher = createDecipheriv(ALGORITHM, keyBuf, iv);
      decipher.setAuthTag(authTag);

      return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    } finally {
      keyBuf.fill(0);
    }
  }
}
