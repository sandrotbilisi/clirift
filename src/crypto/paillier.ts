import { randomBytes } from 'crypto';
import { CURVE_ORDER } from './secp256k1';
import { SigningError } from '../utils/errors';

// ---- Modular arithmetic helpers ----

function modPow(base: bigint, exp: bigint, mod: bigint): bigint {
  let result = 1n;
  base = base % mod;
  while (exp > 0n) {
    if (exp & 1n) result = (result * base) % mod;
    exp >>= 1n;
    base = (base * base) % mod;
  }
  return result;
}

function modInv(a: bigint, m: bigint): bigint {
  // Extended Euclidean algorithm
  let [old_r, r] = [a, m];
  let [old_s, s] = [1n, 0n];
  while (r !== 0n) {
    const q = old_r / r;
    [old_r, r] = [r, old_r - q * r];
    [old_s, s] = [s, old_s - q * s];
  }
  return ((old_s % m) + m) % m;
}

function gcd(a: bigint, b: bigint): bigint {
  while (b) { [a, b] = [b, a % b]; }
  return a;
}

function lcm(a: bigint, b: bigint): bigint {
  return (a / gcd(a, b)) * b;
}

// ---- Miller-Rabin primality test ----

const SMALL_PRIMES = [2n, 3n, 5n, 7n, 11n, 13n, 17n, 19n, 23n, 29n, 31n, 37n];

function millerRabin(n: bigint, witnesses: readonly bigint[]): boolean {
  if (n < 2n) return false;
  if (n === 2n || n === 3n) return true;
  if ((n & 1n) === 0n) return false;

  let d = n - 1n;
  let r = 0;
  while ((d & 1n) === 0n) { d >>= 1n; r++; }

  outer: for (const a of witnesses) {
    if (a >= n) continue;
    let x = modPow(a, d, n);
    if (x === 1n || x === n - 1n) continue;
    for (let i = 0; i < r - 1; i++) {
      x = (x * x) % n;
      if (x === n - 1n) continue outer;
    }
    return false;
  }
  return true;
}

const WITNESSES = [
  2n, 3n, 5n, 7n, 11n, 13n, 17n, 19n, 23n, 29n, 31n, 37n,
  41n, 43n, 47n, 53n, 59n, 61n, 67n, 71n,
] as const;

function isPrime(n: bigint): boolean {
  for (const p of SMALL_PRIMES) {
    if (n === p) return true;
    if (n % p === 0n) return false;
  }
  return millerRabin(n, WITNESSES);
}

// ---- Random prime generation ----

function randomOdd(bits: number): bigint {
  const bytes = randomBytes(Math.ceil(bits / 8));
  // Set top bit to guarantee bit length, set bottom bit to guarantee odd
  bytes[0] |= 0x80;
  bytes[bytes.length - 1] |= 0x01;
  return BigInt('0x' + bytes.toString('hex'));
}

/**
 * Generate a random prime of the given bit length.
 * Resolves via setImmediate between candidates to avoid blocking the event loop.
 */
export function generatePrime(bits: number): Promise<bigint> {
  return new Promise((resolve) => {
    function attempt() {
      const candidate = randomOdd(bits);
      if (isPrime(candidate)) {
        resolve(candidate);
      } else {
        setImmediate(attempt);
      }
    }
    attempt();
  });
}

// ---- Paillier key generation ----

export interface PaillierPublicKey {
  n: bigint;   // modulus p*q
  n2: bigint;  // n^2 (cached)
}

export interface PaillierPrivateKey {
  n: bigint;
  n2: bigint;
  lambda: bigint;  // lcm(p-1, q-1)
  mu: bigint;      // lambda^{-1} mod n
}

/**
 * Generate a Paillier keypair.
 * @param bits - bit length of the public modulus N (p and q each have bits/2 bits)
 */
export async function generatePaillierKey(bits = 1024): Promise<PaillierPrivateKey> {
  const halfBits = bits >> 1;
  let p: bigint, q: bigint;
  do {
    [p, q] = await Promise.all([generatePrime(halfBits), generatePrime(halfBits)]);
  } while (p === q);

  const n = p * q;
  const n2 = n * n;
  const lambda = lcm(p - 1n, q - 1n);
  // g = n+1 is the standard generator: L(g^lambda mod n^2) = lambda
  const mu = modInv(lambda, n);
  return { n, n2, lambda, mu };
}

// ---- Paillier modulus validation ----

/**
 * Validate that a received Paillier public modulus N is safe to use.
 * Throws SigningError on any failure.
 *
 * Checks:
 *   - N is odd (RSA moduli must be odd)
 *   - N >= 2^1023 (minimum 1024-bit modulus for secp256k1 security level)
 *   - gcd(N, curve_order) == 1 (no shared factors with the curve group)
 *   - N is not a perfect square (rules out prime-power moduli p^2)
 */
export function validatePaillierModulus(n: bigint): void {
  if ((n & 1n) === 0n) {
    throw new SigningError('Paillier modulus is even — not a valid RSA modulus');
  }
  // For a 1024-bit Paillier key (two 512-bit primes each with top bit set),
  // N = p*q >= 2^511 * 2^511 = 2^1022. Reject anything smaller.
  if (n < (1n << 1022n)) {
    throw new SigningError('Paillier modulus is too small (< 2^1022)');
  }
  if (gcd(n, CURVE_ORDER) !== 1n) {
    throw new SigningError('Paillier modulus shares a factor with the curve order');
  }
  // Rough perfect-square check: isqrt(n)^2 == n
  const root = isqrt(n);
  if (root * root === n) {
    throw new SigningError('Paillier modulus is a perfect square — possible prime-power attack');
  }
}

/** Integer square root (floor) via Newton's method */
function isqrt(n: bigint): bigint {
  if (n < 0n) throw new RangeError('isqrt: negative input');
  if (n === 0n) return 0n;
  let x = n;
  let y = (x + 1n) >> 1n;
  while (y < x) {
    x = y;
    y = (x + n / x) >> 1n;
  }
  return x;
}

// ---- Encryption / Decryption ----

/** L function: L(x) = (x - 1) / n */
function L(x: bigint, n: bigint): bigint {
  return (x - 1n) / n;
}

/**
 * Encrypt plaintext m under Paillier public key n.
 * c = (1 + n*m) * r^n mod n^2   (using g = n+1 simplification)
 */
export function paillierEncrypt(n: bigint, m: bigint): bigint {
  const n2 = n * n;
  // Reduce m mod n to keep it in plaintext space
  const mMod = ((m % n) + n) % n;
  // Random r coprime to n (overwhelming probability for large n)
  let r: bigint;
  do {
    const bytes = randomBytes(Math.ceil(n.toString(16).length / 2));
    r = BigInt('0x' + bytes.toString('hex')) % n;
  } while (r === 0n);
  const g_m = (1n + n * mMod) % n2;   // (n+1)^m mod n^2 simplified
  const r_n = modPow(r, n, n2);
  return (g_m * r_n) % n2;
}

/**
 * Decrypt ciphertext c using Paillier private key.
 */
export function paillierDecrypt(key: PaillierPrivateKey, c: bigint): bigint {
  const { n, n2, lambda, mu } = key;
  const x = modPow(c, lambda, n2);
  return (L(x, n) * mu) % n;
}

// ---- MtA (Multiplicative-to-Additive) operation ----

/**
 * Compute the MtA ciphertext: Enc_{n}(plaintext * multiplier + beta)
 * using the existing ciphertext Enc_{n}(plaintext).
 *
 * This uses Paillier homomorphic properties:
 *   - Scalar mul: c^k mod n^2 = Enc(m * k)
 *   - Additive: c1 * c2 mod n^2 = Enc(m1 + m2)
 *
 * @param n          Recipient's Paillier public modulus
 * @param ciphertext Enc_{n}(plaintext) — e.g. Enc_{N_j}(k_j) from peer's Round 1
 * @param multiplier Our secret value (e.g. gamma_i or L_i * x_i), reduced mod n
 * @param beta       Random blinding scalar — caller keeps −beta as their MtA share
 */
export function paillierMtA(
  n: bigint,
  ciphertext: bigint,
  multiplier: bigint,
  beta: bigint,
): bigint {
  const n2 = n * n;
  // Reduce multiplier to [0, n) since Paillier plaintext space is Z_n
  const mult = ((multiplier % n) + n) % n;
  const scaled = modPow(ciphertext, mult, n2);          // Enc(plaintext * mult)
  const blindEnc = paillierEncrypt(n, beta % n);        // Enc(beta)
  return (scaled * blindEnc) % n2;                      // Enc(plaintext * mult + beta)
}

// ---- Serialisation helpers ----

export function bigintToHex(n: bigint): string {
  return n.toString(16);
}

export function hexToBigint(hex: string): bigint {
  return BigInt('0x' + hex.replace(/^0x/, ''));
}
