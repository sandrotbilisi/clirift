import { publicEncrypt, privateDecrypt, constants } from 'crypto';
import { evaluatePolynomial } from '../../../crypto/shamir';
import { verifyFeldmanShare } from '../FeldmanVss';
import { hexToScalar, scalarToHex } from '../../../crypto/secp256k1';
import { DkgLocalState } from '../DkgState';
import { DkgRound3P2PPayload } from '../../../network/protocol/Message';
import { DkgError } from '../../../utils/errors';

export interface Round3P2PMessage {
  toNodeId: string;
  toPartyIndex: number;
  payload: DkgRound3P2PPayload;
}

/**
 * DKG Round 3: Distribute encrypted Shamir shares to each peer.
 *
 * Party i computes f_i(j) for each other party j and encrypts it
 * with party j's identity public key (RSA-OAEP).
 * Each message is sent directly (unicast) to the recipient.
 */
export function executeRound3(
  state: DkgLocalState,
  peerPubkeys: Map<string, string> // nodeId → PEM public key
): Round3P2PMessage[] {
  if (!state.secretPolynomial) {
    throw new DkgError('Round 2 must be completed before Round 3');
  }

  const myNodeId = state.participants.find((p) => p.partyIndex === state.myPartyIndex)!.nodeId;
  const messages: Round3P2PMessage[] = [];

  for (const participant of state.participants) {
    if (participant.partyIndex === state.myPartyIndex) continue;

    const { nodeId: toNodeId, partyIndex: toPartyIndex } = participant;

    // Compute the Shamir share for party j: f_i(j)
    const shareValue = evaluatePolynomial(state.secretPolynomial, toPartyIndex);

    // Encrypt with recipient's public key (RSA-OAEP + SHA-256)
    const recipientPubkeyPem = peerPubkeys.get(toNodeId);
    if (!recipientPubkeyPem) {
      throw new DkgError(`No public key available for peer ${toNodeId}`);
    }

    const shareHex = scalarToHex(shareValue);
    const encrypted = encryptShare(shareHex, recipientPubkeyPem);

    messages.push({
      toNodeId,
      toPartyIndex,
      payload: {
        ceremonyId: state.ceremonyId,
        fromNodeId: myNodeId,
        toNodeId,
        fromPartyIndex: state.myPartyIndex,
        toPartyIndex,
        encryptedShare: encrypted,
      },
    });
  }

  return messages;
}

/**
 * Decrypt and verify a received Shamir share from another party.
 * Adds the share to state if valid.
 */
export function recordRound3(
  state: DkgLocalState,
  payload: DkgRound3P2PPayload,
  myPrivateKeyPem: string
): DkgLocalState {
  // Decrypt the share
  const shareHex = decryptShare(payload.encryptedShare, myPrivateKeyPem);
  const shareValue = hexToScalar(shareHex);

  // Verify against Feldman commitments from Round 2
  const senderData = state.round2Received.get(payload.fromNodeId);
  if (!senderData) {
    throw new DkgError(
      `No Round 2 data for sender ${payload.fromNodeId} — cannot verify share`
    );
  }

  const valid = verifyFeldmanShare(
    shareValue,
    state.myPartyIndex,
    senderData.coefficientCommitments
  );

  if (!valid) {
    throw new DkgError(
      `Feldman VSS verification failed for share from party ${payload.fromPartyIndex} (${payload.fromNodeId})`
    );
  }

  const sharesReceived = new Map(state.sharesReceived);
  sharesReceived.set(payload.fromNodeId, shareValue);

  return { ...state, status: 'round3', sharesReceived };
}

export function isRound3Complete(state: DkgLocalState): boolean {
  // Need shares from all other parties
  return state.sharesReceived.size === state.totalParties - 1;
}

// ---- ECIES-style encryption using RSA-OAEP ----
// (node-forge RSA cert → Node.js crypto public key)

function encryptShare(shareHex: string, pubkeyPem: string): string {
  const plaintext = Buffer.from(shareHex, 'hex');
  const encrypted = publicEncrypt(
    { key: pubkeyPem, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' },
    plaintext
  );
  return encrypted.toString('base64');
}

function decryptShare(encryptedBase64: string, privkeyPem: string): string {
  const ciphertext = Buffer.from(encryptedBase64, 'base64');
  const decrypted = privateDecrypt(
    { key: privkeyPem, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' },
    ciphertext
  );
  return decrypted.toString('hex');
}
