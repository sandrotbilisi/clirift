import fs from 'fs';
import path from 'path';
import { buildHdKey, deriveChildPublicKey, bip44Path } from './HdWallet';
import { pubkeyToAddress } from './AddressDeriver';

export interface AddressEntry {
  path: string;
  pubkey: string;    // compressed hex
  address: string;   // EIP-55 checksummed
  derivedAt: number; // Unix timestamp ms
}

export interface AddressIndexFile {
  pkMaster: string;
  derivationRoot: string;
  entries: Record<number, AddressEntry>;
}

/**
 * Persistent address index: caches derived BIP44 addresses for PK_master.
 * Stored in <dataDir>/wallet/address_index.json.
 */
export class AddressIndex {
  private readonly indexPath: string;
  private data: AddressIndexFile;

  constructor(dataDir: string, pkMasterHex: string, chainCodeHex: string) {
    this.indexPath = path.join(dataDir, 'wallet', 'address_index.json');

    const existing = this.load(pkMasterHex);
    if (existing) {
      this.data = existing;
    } else {
      this.data = {
        pkMaster: pkMasterHex,
        derivationRoot: "m/44'/60'/0'/0",
        entries: {},
      };
    }

    this.pkMasterHex = pkMasterHex;
    this.chainCodeHex = chainCodeHex;
  }

  private pkMasterHex: string;
  private chainCodeHex: string;

  /** Derive and cache addresses from index 0 to (count - 1). */
  deriveRange(count: number): AddressEntry[] {
    const hdKey = buildHdKey(this.pkMasterHex, this.chainCodeHex);
    const results: AddressEntry[] = [];

    for (let i = 0; i < count; i++) {
      if (!this.data.entries[i]) {
        const pubkey = deriveChildPublicKey(hdKey, i);
        const address = pubkeyToAddress(pubkey);
        this.data.entries[i] = {
          path: bip44Path(i),
          pubkey,
          address,
          derivedAt: Date.now(),
        };
      }
      results.push(this.data.entries[i]);
    }

    this.save();
    return results;
  }

  /** Derive (or return cached) address at a single index. */
  deriveOne(index: number): AddressEntry {
    if (!this.data.entries[index]) {
      const hdKey = buildHdKey(this.pkMasterHex, this.chainCodeHex);
      const pubkey = deriveChildPublicKey(hdKey, index);
      const address = pubkeyToAddress(pubkey);
      this.data.entries[index] = {
        path: bip44Path(index),
        pubkey,
        address,
        derivedAt: Date.now(),
      };
      this.save();
    }
    return this.data.entries[index];
  }

  private load(pkMasterHex: string): AddressIndexFile | null {
    if (!fs.existsSync(this.indexPath)) return null;

    try {
      const raw = JSON.parse(fs.readFileSync(this.indexPath, 'utf8')) as AddressIndexFile;
      if (raw.pkMaster !== pkMasterHex) {
        // Different PK_master — discard cached index
        return null;
      }
      return raw;
    } catch {
      return null;
    }
  }

  private save(): void {
    const dir = path.dirname(this.indexPath);
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(this.indexPath, JSON.stringify(this.data, null, 2), 'utf8');
  }
}
