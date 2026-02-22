import forge from 'node-forge';
import { getFormattedFingerprint } from '../../crypto/fingerprint';
import logger from '../../utils/logger';

export interface TlsCertificate {
  cert: string; // PEM format
  key: string; // PEM format
  fingerprint: string; // SHA-256 fingerprint (formatted)
}

/**
 * Generate a self-signed TLS certificate with Ed25519 keys
 * @param validityHours Certificate validity in hours (default 24)
 * @param commonName Common name for the certificate (default MPC-Session-<random>)
 * @returns TLS certificate, private key, and fingerprint
 */
export function generateSelfSignedCertificate(
  validityHours: number = 24,
  commonName?: string
): TlsCertificate {
  logger.info('Generating self-signed TLS certificate...');

  // Generate RSA key pair (Ed25519 not fully supported in node-forge for TLS)
  // Using RSA-4096 for production-grade security
  const keys = forge.pki.rsa.generateKeyPair({ bits: 4096 });

  // Create certificate
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = '01';

  const notBefore = new Date();
  const notAfter = new Date();
  notAfter.setHours(notAfter.getHours() + validityHours);

  cert.validity.notBefore = notBefore;
  cert.validity.notAfter = notAfter;

  // Set subject and issuer
  const cn = commonName || `CLIRift-${Date.now()}`;
  const attrs = [
    { name: 'commonName', value: cn },
    { name: 'countryName', value: 'US' },
    { shortName: 'ST', value: 'State' },
    { name: 'localityName', value: 'City' },
    { name: 'organizationName', value: 'CLIRift' },
    { shortName: 'OU', value: 'MPC Node' },
  ];

  cert.setSubject(attrs);
  cert.setIssuer(attrs);

  // Add extensions
  cert.setExtensions([
    {
      name: 'basicConstraints',
      cA: true,
    },
    {
      name: 'keyUsage',
      keyCertSign: true,
      digitalSignature: true,
      nonRepudiation: true,
      keyEncipherment: true,
      dataEncipherment: true,
    },
    {
      name: 'extKeyUsage',
      serverAuth: true,
      clientAuth: true,
    },
    {
      name: 'subjectAltName',
      altNames: [
        { type: 2, value: 'localhost' },
        { type: 7, ip: '127.0.0.1' },
      ],
    },
  ]);

  // Self-sign certificate
  cert.sign(keys.privateKey, forge.md.sha256.create());

  // Convert to PEM format
  const certPem = forge.pki.certificateToPem(cert);
  const keyPem = forge.pki.privateKeyToPem(keys.privateKey);

  // Calculate fingerprint
  const fingerprint = getFormattedFingerprint(certPem);

  logger.info(`Certificate generated. Fingerprint: ${fingerprint}`);

  return {
    cert: certPem,
    key: keyPem,
    fingerprint,
  };
}

/**
 * Verify that a certificate matches an expected fingerprint
 * @param cert Certificate in PEM format
 * @param expectedFingerprint Expected fingerprint (formatted or raw hex)
 * @returns True if fingerprint matches
 */
export function verifyCertificateFingerprint(
  cert: string,
  expectedFingerprint: string
): boolean {
  const actualFingerprint = getFormattedFingerprint(cert);

  // Normalize both fingerprints (remove colons, lowercase)
  const normalize = (fp: string) => fp.replace(/:/g, '').toLowerCase();

  return normalize(actualFingerprint) === normalize(expectedFingerprint);
}
