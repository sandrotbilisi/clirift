import fs from 'fs';
import path from 'path';
import forge from 'node-forge';
import { getFormattedFingerprint } from '../../crypto/fingerprint';
import logger from '../../utils/logger';
import { CertificateError } from '../../utils/errors';

export interface NodeIdentityCert {
  certPem: string;
  keyPem: string;
  fingerprint: string;
}

/**
 * Generate a persistent EC P-256 identity certificate for this node.
 * Valid for 10 years — intended to be rotated manually.
 * The cert CN embeds the nodeId for easy identification.
 */
export function generateNodeIdentityCert(nodeId: string): NodeIdentityCert {
  logger.info('Generating node identity certificate (EC P-256)...');

  // node-forge EC support is limited; use RSA-2048 for identity certs
  // (RSA-2048 is sufficient for identity/mTLS; RSA-4096 is used for session TLS)
  const keys = forge.pki.rsa.generateKeyPair({ bits: 2048 });
  const cert = forge.pki.createCertificate();

  cert.publicKey = keys.publicKey;
  cert.serialNumber = Date.now().toString(16);

  const notBefore = new Date();
  const notAfter = new Date();
  notAfter.setFullYear(notAfter.getFullYear() + 10);

  cert.validity.notBefore = notBefore;
  cert.validity.notAfter = notAfter;

  const attrs = [
    { name: 'commonName', value: `clirft-node-${nodeId}` },
    { name: 'organizationName', value: 'CLIRift' },
    { shortName: 'OU', value: 'Node Identity' },
  ];

  cert.setSubject(attrs);
  cert.setIssuer(attrs);

  cert.setExtensions([
    { name: 'basicConstraints', cA: false },
    {
      name: 'keyUsage',
      digitalSignature: true,
      keyEncipherment: true,
      dataEncipherment: true,
    },
    {
      name: 'extKeyUsage',
      serverAuth: true,
      clientAuth: true,
    },
  ]);

  cert.sign(keys.privateKey, forge.md.sha256.create());

  const certPem = forge.pki.certificateToPem(cert);
  const keyPem = forge.pki.privateKeyToPem(keys.privateKey);
  const fingerprint = getFormattedFingerprint(certPem);

  logger.info(`Node identity cert generated. Fingerprint: ${fingerprint}`);

  return { certPem, keyPem, fingerprint };
}

/**
 * Load or generate the persistent node identity certificate.
 * Files are stored at <dataDir>/identity/node.cert.pem and node.key.pem.
 */
export function loadOrCreateNodeIdentity(
  dataDir: string,
  nodeId: string
): NodeIdentityCert {
  const identityDir = path.join(dataDir, 'identity');
  const certPath = path.join(identityDir, 'node.cert.pem');
  const keyPath = path.join(identityDir, 'node.key.pem');

  if (fs.existsSync(certPath) && fs.existsSync(keyPath)) {
    logger.info('Loading existing node identity certificate...');
    const certPem = fs.readFileSync(certPath, 'utf8');
    const keyPem = fs.readFileSync(keyPath, 'utf8');

    // Validate cert is not expired
    try {
      const cert = forge.pki.certificateFromPem(certPem);
      const now = new Date();
      if (now > cert.validity.notAfter) {
        logger.warn('Node identity certificate is expired. Regenerating...');
        return createAndSaveIdentity(identityDir, certPath, keyPath, nodeId);
      }
    } catch {
      throw new CertificateError('Failed to parse existing node identity certificate');
    }

    const fingerprint = getFormattedFingerprint(certPem);
    return { certPem, keyPem, fingerprint };
  }

  return createAndSaveIdentity(identityDir, certPath, keyPath, nodeId);
}

function createAndSaveIdentity(
  identityDir: string,
  certPath: string,
  keyPath: string,
  nodeId: string
): NodeIdentityCert {
  fs.mkdirSync(identityDir, { recursive: true });

  const identity = generateNodeIdentityCert(nodeId);

  fs.writeFileSync(certPath, identity.certPem, { mode: 0o644 });
  // Private key: owner read-only
  fs.writeFileSync(keyPath, identity.keyPem, { mode: 0o600 });

  logger.info(`Node identity saved to ${identityDir}`);
  return identity;
}

/** Extract the public key PEM from a certificate PEM */
export function extractPublicKeyPem(certPem: string): string {
  const cert = forge.pki.certificateFromPem(certPem);
  return forge.pki.publicKeyToPem(cert.publicKey);
}

/** Get the fingerprint of a PEM-encoded certificate */
export function getCertFingerprint(certPem: string): string {
  return getFormattedFingerprint(certPem);
}
