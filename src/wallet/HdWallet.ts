import { HDKey } from '@scure/bip32';
import { sha512 } from '@noble/hashes/sha512';
import { hmac } from '@noble/hashes/hmac';
import { CLIRiftError } from '../utils/errors';

/**
 * Construct a BIP32 HD wallet root from a raw secp256k1 compressed public key (33 bytes).
 *
 * Since we only have PK_master (no private key), we use **public-key-only BIP32**.
 * This means we can only derive non-hardened child keys — which is sufficient for
 * generating Ethereum receive addresses.
 *
 * Chain code derivation (deterministic, public):
 *   HMAC-SHA512(key="CLIRift v1", data=pkMasterBytes), take the right 32 bytes.
 *   This is stored in ceremony.json alongside PK_master.
 */
export function buildHdKey(pkMasterHex: string, chainCodeHex: string): HDKey {
  const publicKey = Buffer.from(pkMasterHex.replace(/^0x/, ''), 'hex');
  const chainCode = Buffer.from(chainCodeHex.replace(/^0x/, ''), 'hex');

  if (publicKey.length !== 33) {
    throw new CLIRiftError(
      `PK_master must be a 33-byte compressed secp256k1 point, got ${publicKey.length} bytes`
    );
  }

  if (chainCode.length !== 32) {
    throw new CLIRiftError(`chainCode must be 32 bytes, got ${chainCode.length} bytes`);
  }

  return new HDKey({
    publicKey,
    chainCode,
    depth: 0,
    index: 0,
    parentFingerprint: 0,
    versions: { public: 0x0488b21e, private: 0x0488ade4 }, // mainnet xpub/xprv
  });
}

/**
 * Derive the chain code deterministically from PK_master.
 * HMAC-SHA512(key="CLIRift v1", data=pkMasterBytes)[32:]
 */
export function deriveChainCode(pkMasterHex: string): string {
  const pkBytes = Buffer.from(pkMasterHex.replace(/^0x/, ''), 'hex');
  const key = Buffer.from('CLIRift v1', 'utf8');
  const result = hmac(sha512, key, pkBytes);
  // Take the right half (bytes 32-63) as chain code
  return Buffer.from(result.slice(32)).toString('hex');
}

/**
 * Derive a child public key at a relative non-hardened path from the HDKey root.
 * For Ethereum: use path "0/{index}" (external chain, index N) relative to PK_master.
 * Full BIP44 equivalent: m/44'/60'/0'/0/{index}
 *
 * Returns the compressed child public key (33 bytes, hex).
 */
export function deriveChildPublicKey(hdKey: HDKey, index: number): string {
  // Non-hardened derivation: change chain (0) then address index
  const child = hdKey.deriveChild(0).deriveChild(index);

  if (!child.publicKey) {
    throw new CLIRiftError(`Failed to derive child key at index ${index}`);
  }

  return Buffer.from(child.publicKey).toString('hex');
}

/** Build the BIP44 derivation path string for display purposes */
export function bip44Path(index: number): string {
  return `m/44'/60'/0'/0/${index}`;
}
