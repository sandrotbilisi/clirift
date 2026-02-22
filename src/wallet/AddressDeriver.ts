import { keccak256 } from 'viem';
import { secp256k1 as nobleSecp } from '@noble/curves/secp256k1';

/**
 * Derive an EIP-55 checksummed Ethereum address from a compressed secp256k1 public key.
 *
 * Process:
 *   1. Decompress the 33-byte public key to 65 bytes (0x04 prefix + 64 bytes)
 *   2. Drop the 0x04 prefix → 64 bytes of raw (x, y) coordinates
 *   3. keccak256(64 bytes) → 32-byte hash
 *   4. Take the last 20 bytes → raw address
 *   5. Apply EIP-55 checksum encoding
 */
export function pubkeyToAddress(compressedPubkeyHex: string): string {
  const pubkeyBytes = Buffer.from(compressedPubkeyHex.replace(/^0x/, ''), 'hex');

  if (pubkeyBytes.length !== 33) {
    throw new Error(
      `Expected 33-byte compressed public key, got ${pubkeyBytes.length} bytes`
    );
  }

  // Decompress: 65 bytes (starts with 0x04)
  const point = nobleSecp.ProjectivePoint.fromHex(pubkeyBytes);
  const uncompressed = point.toRawBytes(false); // 65 bytes

  // Strip the 0x04 prefix
  const pubkeyUnprefixed = uncompressed.slice(1); // 64 bytes

  // keccak256 of the 64 raw bytes
  const hash = keccak256(pubkeyUnprefixed as unknown as `0x${string}`); // returns 0x-prefixed hex

  // Last 20 bytes = raw address (40 hex chars)
  const rawAddress = '0x' + hash.slice(-40);

  // Apply EIP-55 checksum
  return toChecksumAddress(rawAddress);
}

/**
 * Apply EIP-55 mixed-case checksum encoding to a lowercase Ethereum address.
 */
export function toChecksumAddress(address: string): string {
  const lower = address.toLowerCase().replace('0x', '');
  const hash = keccak256(Buffer.from(lower, 'utf8') as unknown as `0x${string}`);
  const hashHex = hash.slice(2); // strip 0x

  let checksummed = '0x';
  for (let i = 0; i < lower.length; i++) {
    const char = lower[i];
    if (/[0-9]/.test(char)) {
      checksummed += char;
    } else {
      // Uppercase if the corresponding nibble in the hash is >= 8
      checksummed += parseInt(hashHex[i], 16) >= 8 ? char.toUpperCase() : char;
    }
  }
  return checksummed;
}
