import { HDKey } from '@scure/bip32';
import { sha512 } from '@noble/hashes/sha512';
import { hmac } from '@noble/hashes/hmac';
import { secp256k1 as secp } from '@noble/curves/secp256k1';
import { CLIRiftError } from '../utils/errors';
import { CURVE_ORDER } from '../crypto/secp256k1';

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

/**
 * Compute the additive scalar tweak for one non-hardened BIP32 child derivation step.
 *
 *   IL || IR = HMAC-SHA512(key=parentChainCode, data=parentCompressedPubkey || index_BE32)
 *   child_priv = parent_priv + IL (mod n)
 *
 * Returns IL as a bigint and the derived child pubkey/chainCode for chaining.
 */
function nonHardenedTweakStep(
  parentPubkeyHex: string,
  parentChainCodeHex: string,
  index: number
): { IL: bigint; childPubkeyHex: string; childChainCodeHex: string } {
  const parentPubBytes = Buffer.from(parentPubkeyHex, 'hex');
  const parentCCBytes = Buffer.from(parentChainCodeHex, 'hex');

  const indexBuf = Buffer.allocUnsafe(4);
  indexBuf.writeUInt32BE(index, 0);

  const I = Buffer.from(hmac(sha512, parentCCBytes, Buffer.concat([parentPubBytes, indexBuf])));
  const IL = I.slice(0, 32);
  const IR = I.slice(32);

  const ILn = BigInt('0x' + IL.toString('hex'));

  // child pubkey = IL*G + parent_pubkey (for chaining to the next step)
  const parentPoint = secp.ProjectivePoint.fromHex(parentPubkeyHex);
  const childPoint = secp.ProjectivePoint.BASE.multiply(ILn).add(parentPoint);
  const childPubkeyHex = Buffer.from(childPoint.toRawBytes(true)).toString('hex');

  return { IL: ILn, childPubkeyHex, childChainCodeHex: IR.toString('hex') };
}

/**
 * Compute the total scalar tweak needed to adapt a master private key share for
 * signing as the BIP32 child address at the given index.
 *
 * `deriveChildPublicKey` does exactly two non-hardened steps: deriveChild(0).deriveChild(index).
 * The corresponding private-key relationship is:
 *   child_priv = master_priv + IL_0 + IL_index  (mod n)
 *
 * For threshold signing, each party computes:
 *   child_share_i = x_i + tweak
 * Lagrange combination then gives:
 *   Σ L_i * child_share_i = Σ(L_i * x_i) + tweak * Σ(L_i) = master_priv + tweak = child_priv ✓
 */
export function computeChildKeyTweak(
  pkMasterHex: string,
  chainCodeHex: string,
  addressIndex: number
): bigint {
  const step0 = nonHardenedTweakStep(pkMasterHex, chainCodeHex, 0);
  const stepIdx = nonHardenedTweakStep(step0.childPubkeyHex, step0.childChainCodeHex, addressIndex);
  return (step0.IL + stepIdx.IL) % CURVE_ORDER;
}
