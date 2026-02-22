import 'dotenv/config';
import { ConfigSchema, Config } from './schema';
import { CLIRiftError } from '../utils/errors';

let _config: Config | null = null;

/** Parse and validate all environment variables. Throws on validation failure. */
export function loadConfig(): Config {
  if (_config) return _config;

  const result = ConfigSchema.safeParse(process.env);

  if (!result.success) {
    const issues = result.error.issues
      .map((i) => `  ${i.path.join('.')}: ${i.message}`)
      .join('\n');
    throw new CLIRiftError(`Configuration error:\n${issues}`);
  }

  // Cross-field validation
  const cfg = result.data;

  if (cfg.CLIRFT_STORAGE_BACKEND === 'kms' && !cfg.CLIRFT_KMS_KEY_ID) {
    throw new CLIRiftError(
      'CLIRFT_KMS_KEY_ID is required when CLIRFT_STORAGE_BACKEND=kms'
    );
  }

  if (cfg.CLIRFT_STORAGE_BACKEND === 'local' && !cfg.CLIRFT_LOCAL_PASSPHRASE) {
    throw new CLIRiftError(
      'CLIRFT_LOCAL_PASSPHRASE is required when CLIRFT_STORAGE_BACKEND=local'
    );
  }

  if (cfg.CLIRFT_THRESHOLD >= cfg.CLIRFT_TOTAL_PARTIES) {
    throw new CLIRiftError(
      `CLIRFT_THRESHOLD (${cfg.CLIRFT_THRESHOLD}) must be less than CLIRFT_TOTAL_PARTIES (${cfg.CLIRFT_TOTAL_PARTIES})`
    );
  }

  _config = cfg;
  return cfg;
}

/** Reset cached config (for testing). */
export function resetConfig(): void {
  _config = null;
}
