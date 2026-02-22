# RiftRaspberry

Secure LAN-based instance system for distributed protocols.

## Overview

RiftRaspberry provides a simple, password-protected connection system for secure device-to-device communication on local area networks. It features TLS encryption, password authentication, and can run on Windows, Linux, macOS, and Raspberry Pi.

## Features

- 🔐 Production-grade security with TLS 1.3
- 🔑 Password-protected sessions with Argon2id hashing
- 🤝 TLS fingerprint verification
- 📡 Message broadcasting between clients
- 🍇 Cross-platform support (including Raspberry Pi ARM64)
- 🚀 Simple CLI interface

## Installation

```bash
# Install dependencies
npm install

# Run in development mode
npm run dev
```

## Usage

### Host Mode

Start a host instance:

```bash
riftberry host --name "My Session"
```

The host will display:
- A secure password for clients to connect
- TLS certificate fingerprint for verification
- LAN IP addresses where the server is listening

### Client Mode

Join a host instance:

```bash
riftberry join --host 192.168.1.100:8443
```

You will be prompted to:
- Enter the password provided by the host
- Verify the TLS fingerprint matches the host's display

## Development

```bash
# Install dependencies
npm install

# Run in dev mode
npm run dev -- host --name "Test"
npm run dev -- join --host 192.168.1.100:8443

# Build TypeScript
npm run build

# Build platform-specific executables
npm run build:exe

# Lint code
npm run lint

# Format code
npm run format
```

## Building Executables

Create platform-specific executables for distribution:

```bash
npm run build:exe
```

This creates builds in the `build/` directory for:
- **Windows (x64)** - `riftberry-windows-x64/`
- **Linux (x64)** - `riftberry-linux-x64/`
- **Linux (ARM64)** - `riftberry-linux-arm64/` (for Raspberry Pi)
- **macOS (Intel)** - `riftberry-macos-x64/`
- **macOS (Apple Silicon)** - `riftberry-macos-arm64/`

Each build includes everything needed to run:
- Compiled application code
- All dependencies (including native modules)
- Platform-specific launcher script (`.bat` or `.sh`)
- README with quick start instructions

**Usage:**
```bash
# Windows
cd build\riftberry-windows-x64
riftberry.bat host --name "Session"

# Linux/Mac/Raspberry Pi
cd build/riftberry-linux-arm64
chmod +x riftberry.sh
./riftberry.sh host --name "Session"
```

See [DISTRIBUTION.md](DISTRIBUTION.md) for complete distribution instructions and how to create archives for sharing.

## Security

- **TLS 1.3**: All connections are encrypted with self-signed certificates
- **Argon2id**: Passwords are hashed with memory-hard KDF (64MB, 3 iterations)
- **Fingerprint Verification**: Clients must verify TLS certificate fingerprints
- **Rate Limiting**: Maximum 3 authentication attempts per connection
- **LAN-only**: Designed for trusted local area networks

## License

MIT
