import { z } from 'zod';

export const ConfigSchema = z.object({
  // ---- Node identity ----
  CLIRFT_NODE_ID: z.string().uuid(),

  // ---- Network ----
  CLIRFT_LISTEN_PORT: z.coerce.number().int().min(1).max(65535).default(8443),
  CLIRFT_LISTEN_HOST: z.string().default('0.0.0.0'),
  /** WSS URL for how OTHER nodes reach THIS node, e.g. wss://node1.example.com:8443 */
  CLIRFT_PUBLIC_URL: z.string().url(),
  /**
   * Comma-separated WSS URLs of peer nodes (not including self).
   * e.g. "wss://node2.example.com:8443,wss://node3.example.com:8443"
   */
  CLIRFT_PEERS: z
    .string()
    .transform((val) =>
      val
        .split(',')
        .map((p) => p.trim())
        .filter(Boolean)
    )
    .pipe(z.string().url().array().min(1)),

  // ---- Data directory ----
  CLIRFT_DATA_DIR: z.string().default('/var/lib/clirft'),

  // ---- Key share encryption ----
  CLIRFT_STORAGE_BACKEND: z.enum(['kms', 'local']).default('kms'),
  /** ARN of the AWS KMS CMK. Required when CLIRFT_STORAGE_BACKEND=kms */
  CLIRFT_KMS_KEY_ID: z.string().optional(),
  /**
   * Passphrase for local AES-256-GCM encryption (dev/test only).
   * Min 32 characters. Required when CLIRFT_STORAGE_BACKEND=local
   */
  CLIRFT_LOCAL_PASSPHRASE: z.string().min(32).optional(),

  // ---- Ethereum ----
  CLIRFT_CHAIN_ID: z.coerce.number().int().positive().default(1),
  CLIRFT_ETH_RPC_URL: z.string().url().optional(),

  // ---- TLS ----
  /** Path to a pre-existing TLS cert PEM. If absent, a self-signed cert is generated. */
  CLIRFT_TLS_CERT_PATH: z.string().optional(),
  CLIRFT_TLS_KEY_PATH: z.string().optional(),

  // ---- Logging ----
  NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),
  LOG_LEVEL: z.enum(['error', 'warn', 'info', 'debug']).default('info'),

  // ---- Security ----
  /** Message replay window in ms. Default: 30 seconds. */
  CLIRFT_MSG_TIMESTAMP_TOLERANCE_MS: z.coerce.number().int().positive().default(30_000),

  // ---- DKG ----
  CLIRFT_THRESHOLD: z.coerce.number().int().min(2).default(2),
  CLIRFT_TOTAL_PARTIES: z.coerce.number().int().min(2).default(3),
  CLIRFT_DKG_TIMEOUT_MS: z.coerce.number().int().positive().default(300_000),

  // ---- Signing ----
  CLIRFT_SIGN_TIMEOUT_MS: z.coerce.number().int().positive().default(120_000),
});

export type Config = z.infer<typeof ConfigSchema>;
