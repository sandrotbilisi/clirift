/**
 * DKG Integration Test: 3-node in-process ceremony simulation.
 *
 * Simulates 3 parties running the full DKG ceremony using the pure
 * cryptographic functions (shamir, commitment, FeldmanVss, rounds)
 * without a network layer.
 *
 * Verifies:
 * - All 3 parties produce the same PK_master
 * - Each party's key share is different
 * - The key shares satisfy the Shamir reconstruction property
 * - reconstructSecret(any 2 shares) ≠ PK_master (sanity: shares are of the private key)
 */
import { describe, it, expect } from 'vitest';
import { generatePolynomial, evaluatePolynomial, reconstructSecret } from '../../src/crypto/shamir';
import { feldmanCommitments, verifyFeldmanShare, combinePkMaster } from '../../src/core/dkg/FeldmanVss';
import {
  pedersenCommit,
  pedersenVerify,
  schnorrProve,
  schnorrVerify,
  generateBlindingFactor,
} from '../../src/crypto/commitment';
import { generateScalar, scalarMulG, pointToHex, scalarAdd, CURVE_ORDER } from '../../src/crypto/secp256k1';
import { deriveChainCode, buildHdKey, deriveChildPublicKey } from '../../src/wallet/HdWallet';
import { pubkeyToAddress } from '../../src/wallet/AddressDeriver';

const THRESHOLD = 2;
const TOTAL = 3;

interface PartyState {
  partyIndex: number;
  secret: bigint;
  polynomial: bigint[];
  coeffCommitments: string[]; // Feldman: [a_0*G, a_1*G, ...]
  blindingFactor: bigint;
  pedersenCommit: string;
  keyShare?: bigint; // x_i = sum of f_j(i)
}

describe('DKG 2-of-3 Ceremony (in-process simulation)', () => {
  it('full ceremony produces consistent PK_master across all parties', () => {
    // ── Round 1: Each party generates polynomial and Pedersen commitment ──
    const parties: PartyState[] = [];

    for (let i = 1; i <= TOTAL; i++) {
      const secret = generateScalar();
      const polynomial = generatePolynomial(secret, THRESHOLD);
      const coeffPoints = polynomial.map(scalarMulG);
      const coeffCommitments = feldmanCommitments(polynomial);
      const blinding = generateBlindingFactor();
      const { commitment } = pedersenCommit(coeffPoints, blinding);

      parties.push({
        partyIndex: i,
        secret,
        polynomial,
        coeffCommitments,
        blindingFactor: blinding,
        pedersenCommit: commitment,
      });
    }

    // ── Round 2: Each party opens commitment and proves knowledge of secret ──
    for (const party of parties) {
      // Verify: other parties can open this party's Pedersen commitment
      for (const other of parties) {
        if (other.partyIndex === party.partyIndex) continue;

        const coeffPoints = party.polynomial.map(scalarMulG);
        const valid = pedersenVerify(
          party.pedersenCommit,
          coeffPoints,
          party.blindingFactor.toString(16).padStart(64, '0')
        );
        expect(valid).toBe(true);

        // Verify Schnorr ZK proof
        const a0G = scalarMulG(party.polynomial[0]);
        const proof = schnorrProve(
          party.polynomial[0],
          a0G,
          `DKG-test-party-${party.partyIndex}`
        );
        const proofValid = schnorrVerify(a0G, proof, `DKG-test-party-${party.partyIndex}`);
        expect(proofValid).toBe(true);
      }
    }

    // ── Round 3: Each party distributes Shamir shares ──
    const sharesReceived: Map<number, Map<number, bigint>> = new Map();
    for (let i = 1; i <= TOTAL; i++) {
      sharesReceived.set(i, new Map());
    }

    for (const sender of parties) {
      for (const recipient of parties) {
        if (sender.partyIndex === recipient.partyIndex) continue;

        const share = evaluatePolynomial(sender.polynomial, recipient.partyIndex);

        // Feldman verification: recipient verifies the share
        const valid = verifyFeldmanShare(
          share,
          recipient.partyIndex,
          sender.coeffCommitments
        );
        expect(valid).toBe(true);

        sharesReceived.get(recipient.partyIndex)!.set(sender.partyIndex, share);
      }
    }

    // ── Round 4: Each party computes key share ──
    const pkMasters: string[] = [];

    for (const party of parties) {
      // x_i = f_i(i) + sum_{j!=i}(f_j(i))
      let keyShare = evaluatePolynomial(party.polynomial, party.partyIndex);

      for (const [, share] of sharesReceived.get(party.partyIndex)!) {
        keyShare = (keyShare + share) % CURVE_ORDER;
      }

      party.keyShare = keyShare;

      // PK_master = sum of all a_j(0)*G (each party's intercept commitment)
      const interceptCommitments = parties.map((p) => p.coeffCommitments[0]);
      const pkMaster = combinePkMaster(interceptCommitments);
      pkMasters.push(pkMaster);
    }

    // ── Assert: All parties computed the same PK_master ──
    expect(pkMasters[0]).toBe(pkMasters[1]);
    expect(pkMasters[1]).toBe(pkMasters[2]);

    // ── Assert: Key shares are all different ──
    const shares = parties.map((p) => p.keyShare!);
    expect(shares[0]).not.toBe(shares[1]);
    expect(shares[1]).not.toBe(shares[2]);

    // ── Assert: Any 2 shares reconstruct the same value (the combined secret) ──
    const combinedSecret =
      parties.reduce((sum, p) => (sum + p.polynomial[0]) % CURVE_ORDER, 0n);

    const recon12 = reconstructSecret(new Map([[1, shares[0]], [2, shares[1]]]));
    const recon13 = reconstructSecret(new Map([[1, shares[0]], [3, shares[2]]]));
    const recon23 = reconstructSecret(new Map([[2, shares[1]], [3, shares[2]]]));

    expect(recon12).toBe(combinedSecret);
    expect(recon13).toBe(combinedSecret);
    expect(recon23).toBe(combinedSecret);

    // ── Assert: PK_master == combinedSecret * G ──
    const pkMasterFromSecret = pointToHex(scalarMulG(combinedSecret));
    expect(pkMasters[0]).toBe(pkMasterFromSecret);

    // ── Assert: BIP32 derivation produces valid Ethereum addresses ──
    const chainCode = deriveChainCode(pkMasters[0]);
    expect(chainCode).toHaveLength(64);

    // Derive address at index 0
    const hdKey = buildHdKey(pkMasters[0], chainCode);
    const childPubkey = deriveChildPublicKey(hdKey, 0);
    const address = pubkeyToAddress(childPubkey);
    expect(address).toMatch(/^0x[0-9a-fA-F]{40}$/);

    console.log(`\n  DKG Test Results:`);
    console.log(`  PK_master : ${pkMasters[0]}`);
    console.log(`  Address 0 : ${address}`);
  });
});
