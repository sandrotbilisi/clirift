# RiftRaspberry Deployment Package

## Quick Start

1. Run setup to install dependencies:
   ```bash
   ./setup.sh
   ```

2. Start the host:
   ```bash
   ./riftberry.sh host --name "My Session"
   ```

3. Join from clients:
   ```bash
   ./riftberry.sh join --host <HOST_IP>:8443
   ```

## Requirements

- Node.js 18 or higher
- npm

## Installation

If Node.js is not installed:

**Debian/Ubuntu/Raspberry Pi OS:**
```bash
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt install -y nodejs
```

**CentOS/RHEL:**
```bash
curl -fsSL https://rpm.nodesource.com/setup_18.x | sudo bash -
sudo yum install -y nodejs
```

**macOS:**
```bash
brew install node
```

## Troubleshooting

If you get permission errors:
```bash
chmod +x setup.sh riftberry.sh
```

If native module errors occur:
```bash
npm rebuild
```
