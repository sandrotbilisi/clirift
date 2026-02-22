import { createHash } from 'crypto';

/**
 * Calculate SHA-256 fingerprint of a certificate
 * @param cert Certificate in PEM format or DER buffer
 * @returns SHA-256 fingerprint as hex string
 */
export function calculateFingerprint(cert: string | Buffer): string {
  let certBuffer: Buffer;

  if (typeof cert === 'string') {
    // Remove PEM headers and convert to buffer
    const pemData = cert
      .replace(/-----BEGIN CERTIFICATE-----/, '')
      .replace(/-----END CERTIFICATE-----/, '')
      .replace(/\s/g, '');
    certBuffer = Buffer.from(pemData, 'base64');
  } else {
    certBuffer = cert;
  }

  return createHash('sha256').update(certBuffer).digest('hex');
}

/**
 * Format fingerprint for display (XX:XX:XX:XX:... format)
 * @param fingerprint Hex string fingerprint
 * @returns Formatted fingerprint
 */
export function formatFingerprint(fingerprint: string): string {
  return fingerprint.match(/.{2}/g)?.join(':').toUpperCase() || fingerprint.toUpperCase();
}

/**
 * Calculate and format fingerprint from certificate
 * @param cert Certificate in PEM format or DER buffer
 * @returns Formatted SHA-256 fingerprint
 */
export function getFormattedFingerprint(cert: string | Buffer): string {
  const fingerprint = calculateFingerprint(cert);
  return formatFingerprint(fingerprint);
}
