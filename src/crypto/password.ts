import { randomBytes, timingSafeEqual } from 'crypto';
import argon2 from 'argon2';
import { v4 as uuidv4 } from 'uuid';

// Base58 alphabet (no 0, O, I, l to avoid confusion)
const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

/**
 * Encode bytes to base58 string
 */
function toBase58(buffer: Buffer): string {
  const digits = [0];

  for (let i = 0; i < buffer.length; i++) {
    let carry = buffer[i];
    for (let j = 0; j < digits.length; j++) {
      carry += digits[j] << 8;
      digits[j] = carry % 58;
      carry = (carry / 58) | 0;
    }

    while (carry > 0) {
      digits.push(carry % 58);
      carry = (carry / 58) | 0;
    }
  }

  let result = '';
  for (let i = digits.length - 1; i >= 0; i--) {
    result += BASE58_ALPHABET[digits[i]];
  }

  return result;
}

/**
 * Generate a cryptographically secure password
 * @param length Number of bytes (default 32)
 * @returns Base58-encoded password
 */
export function generatePassword(length: number = 32): string {
  const bytes = randomBytes(length);
  return toBase58(bytes);
}

/**
 * Hash a password using Argon2id
 * @param password Password to hash
 * @param salt Optional salt (generated if not provided)
 * @returns Hash and salt
 */
export async function hashPassword(
  password: string,
  salt?: Buffer
): Promise<{ hash: string; salt: string }> {
  const saltBuffer = salt || randomBytes(32);

  const hash = await argon2.hash(password, {
    type: argon2.argon2id,
    memoryCost: 65536, // 64 MB
    timeCost: 3, // 3 iterations
    parallelism: 4, // 4 threads
    salt: saltBuffer,
    hashLength: 32, // 256 bits
  });

  return {
    hash,
    salt: saltBuffer.toString('hex'),
  };
}

/**
 * Verify a password against a hash using timing-safe comparison
 * @param password Password to verify
 * @param hash Argon2id hash (includes salt)
 * @returns True if password matches
 */
export async function verifyPassword(password: string, hash: string): Promise<boolean> {
  try {
    return await argon2.verify(hash, password);
  } catch (error) {
    return false;
  }
}

/**
 * Generate a unique client ID
 * @returns UUID v4
 */
export function generateClientId(): string {
  return uuidv4();
}

/**
 * Generate a secure random token (hex string)
 * @param bytes Number of bytes (default 32)
 * @returns Hex-encoded token
 */
export function generateToken(bytes: number = 32): string {
  return randomBytes(bytes).toString('hex');
}

/**
 * Timing-safe comparison of two strings
 * @param a First string
 * @param b Second string
 * @returns True if strings are equal
 */
export function timingSafeCompare(a: string, b: string): boolean {
  if (a.length !== b.length) {
    return false;
  }

  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);

  return timingSafeEqual(bufA, bufB);
}
