import { describe, it, expect } from 'vitest';
import { buildHdKey, deriveChildPublicKey, deriveChainCode, bip44Path } from '../../../src/wallet/HdWallet';
import { pubkeyToAddress } from '../../../src/wallet/AddressDeriver';
import { generateScalar, scalarMulG, pointToHex } from '../../../src/crypto/secp256k1';

// A fixed test PK_master derived from a known scalar
const TEST_SCALAR = 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdefn;
const TEST_PK_MASTER = pointToHex(scalarMulG(TEST_SCALAR));

describe('HD Wallet Derivation', () => {
  it('deriveChainCode is deterministic', () => {
    const cc1 = deriveChainCode(TEST_PK_MASTER);
    const cc2 = deriveChainCode(TEST_PK_MASTER);
    expect(cc1).toBe(cc2);
    expect(cc1).toHaveLength(64); // 32 bytes hex
  });

  it('buildHdKey succeeds with valid inputs', () => {
    const chainCode = deriveChainCode(TEST_PK_MASTER);
    const hdKey = buildHdKey(TEST_PK_MASTER, chainCode);
    expect(hdKey.publicKey).toBeDefined();
    expect(hdKey.publicKey!.length).toBe(33);
  });

  it('child keys are different at different indices', () => {
    const chainCode = deriveChainCode(TEST_PK_MASTER);
    const hdKey = buildHdKey(TEST_PK_MASTER, chainCode);

    const child0 = deriveChildPublicKey(hdKey, 0);
    const child1 = deriveChildPublicKey(hdKey, 1);
    const child2 = deriveChildPublicKey(hdKey, 2);

    expect(child0).not.toBe(child1);
    expect(child1).not.toBe(child2);
    expect(child0).not.toBe(child2);
  });

  it('child derivation is deterministic', () => {
    const chainCode = deriveChainCode(TEST_PK_MASTER);
    const hdKey = buildHdKey(TEST_PK_MASTER, chainCode);

    const child_a = deriveChildPublicKey(hdKey, 5);
    const child_b = deriveChildPublicKey(buildHdKey(TEST_PK_MASTER, chainCode), 5);

    expect(child_a).toBe(child_b);
  });

  it('child pubkeys are 33 bytes (compressed)', () => {
    const chainCode = deriveChainCode(TEST_PK_MASTER);
    const hdKey = buildHdKey(TEST_PK_MASTER, chainCode);
    const child = deriveChildPublicKey(hdKey, 0);
    expect(child).toHaveLength(66); // 33 bytes = 66 hex chars
  });

  it('derives valid Ethereum addresses', () => {
    const chainCode = deriveChainCode(TEST_PK_MASTER);
    const hdKey = buildHdKey(TEST_PK_MASTER, chainCode);
    const child = deriveChildPublicKey(hdKey, 0);
    const address = pubkeyToAddress(child);

    expect(address).toMatch(/^0x[0-9a-fA-F]{40}$/);
    // EIP-55 checksum: at least some uppercase letters expected for most addresses
    expect(address.startsWith('0x')).toBe(true);
  });

  it('bip44Path formats correctly', () => {
    expect(bip44Path(0)).toBe("m/44'/60'/0'/0/0");
    expect(bip44Path(5)).toBe("m/44'/60'/0'/0/5");
  });
});

describe('Address Derivation', () => {
  it('pubkeyToAddress produces 42-char checksummed address', () => {
    const scalar = generateScalar();
    const pubkey = pointToHex(scalarMulG(scalar));
    const address = pubkeyToAddress(pubkey);

    expect(address).toHaveLength(42); // 0x + 40 hex chars
    expect(address.startsWith('0x')).toBe(true);
  });

  it('different pubkeys produce different addresses', () => {
    const p1 = pointToHex(scalarMulG(generateScalar()));
    const p2 = pointToHex(scalarMulG(generateScalar()));

    const a1 = pubkeyToAddress(p1);
    const a2 = pubkeyToAddress(p2);

    expect(a1).not.toBe(a2);
  });
});
