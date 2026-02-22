export class CLIRiftError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'CLIRiftError';
    Error.captureStackTrace(this, this.constructor);
  }
}

export class AuthenticationError extends CLIRiftError {
  constructor(message: string = 'Authentication failed') {
    super(message);
    this.name = 'AuthenticationError';
  }
}

export class ConnectionError extends CLIRiftError {
  constructor(message: string = 'Connection failed') {
    super(message);
    this.name = 'ConnectionError';
  }
}

export class CertificateError extends CLIRiftError {
  constructor(message: string = 'Certificate error') {
    super(message);
    this.name = 'CertificateError';
  }
}

export class ValidationError extends CLIRiftError {
  constructor(message: string = 'Validation failed') {
    super(message);
    this.name = 'ValidationError';
  }
}

export class DkgError extends CLIRiftError {
  constructor(message: string = 'DKG ceremony failed') {
    super(message);
    this.name = 'DkgError';
  }
}

export class SigningError extends CLIRiftError {
  constructor(message: string = 'Signing session failed') {
    super(message);
    this.name = 'SigningError';
  }
}

export class StorageError extends CLIRiftError {
  constructor(message: string = 'Storage operation failed') {
    super(message);
    this.name = 'StorageError';
  }
}
