# RiftRaspberry Deployment Guide

## Recommended Deployment Method

Since this project uses native modules (argon2), the best deployment approach is to distribute the compiled code with dependencies rather than using bundlers like `pkg`.

### Method 1: Direct Deployment (Recommended for Raspberry Pi)

This is the simplest and most reliable method.

**Steps:**

1. **On your development machine:**
   ```bash
   npm run build
   ```

2. **Copy these files/folders to your target device:**
   ```
   RiftRaspberry/
   ├── dist/           # Compiled JavaScript
   ├── node_modules/   # All dependencies (including native binaries)
   ├── config/         # Configuration files
   ├── package.json
   └── package-lock.json
   ```

3. **On the target device (e.g., Raspberry Pi):**
   ```bash
   # If architecture matches your dev machine, just run:
   node dist/cli/index.js host --name "My Session"

   # If architecture differs (e.g., ARM64), reinstall native modules:
   npm rebuild
   node dist/cli/index.js host --name "My Session"
   ```

### Method 2: Fresh Install on Target

For cross-architecture deployment (e.g., Windows → Raspberry Pi ARM64):

1. **Copy source files to target:**
   ```
   RiftRaspberry/
   ├── src/
   ├── package.json
   ├── package-lock.json
   └── tsconfig.json
   ```

2. **On target device:**
   ```bash
   # Install dependencies (native modules compile for target architecture)
   npm install

   # Build TypeScript
   npm run build

   # Run
   node dist/cli/index.js host --name "My Session"
   ```

### Method 3: NPM Link (For Development)

For testing on multiple machines:

1. **On development machine:**
   ```bash
   npm run build
   npm link
   ```

2. **Now you can run from anywhere:**
   ```bash
   riftberry host --name "Test"
   riftberry join --host 192.168.1.100:8443
   ```

## Raspberry Pi Specific Instructions

### Prerequisites
```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Node.js 18+ (if not already installed)
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt install -y nodejs

# Verify installation
node --version  # Should be v18.x or higher
npm --version
```

### Installation
```bash
# Option A: Copy from dev machine (faster)
scp -r dist node_modules config package.json pi@raspberrypi.local:~/riftberry/
ssh pi@raspberrypi.local
cd ~/riftberry
npm rebuild  # Rebuild native modules for ARM64

# Option B: Fresh install (more reliable)
scp -r src package.json package-lock.json tsconfig.json pi@raspberrypi.local:~/riftberry/
ssh pi@raspberrypi.local
cd ~/riftberry
npm install
npm run build
```

### Running as a Service (systemd)

Create a service file for automatic startup:

```bash
sudo nano /etc/systemd/system/riftberry.service
```

```ini
[Unit]
Description=RiftRaspberry Host
After=network.target

[Service]
Type=simple
User=pi
WorkingDirectory=/home/pi/riftberry
ExecStart=/usr/bin/node /home/pi/riftberry/dist/cli/index.js host --name "Pi Session" --port 8443
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable riftberry
sudo systemctl start riftberry
sudo systemctl status riftberry

# View logs
journalctl -u riftberry -f
```

### Configure Static IP (Optional but Recommended)

Edit network config:
```bash
sudo nano /etc/dhcpcd.conf
```

Add at the end:
```
interface wlan0  # or eth0 for ethernet
static ip_address=192.168.1.100/24
static routers=192.168.1.1
static domain_name_servers=192.168.1.1 8.8.8.8
```

Restart networking:
```bash
sudo systemctl restart dhcpcd
```

### Firewall Configuration

Open port 8443:
```bash
sudo ufw allow 8443/tcp
sudo ufw enable
sudo ufw status
```

## Cross-Platform Notes

### Windows
- Use `node dist\cli\index.js` (backslashes)
- Firewall: Allow Node.js through Windows Defender Firewall

### macOS
- Use `node dist/cli/index.js` (forward slashes)
- Firewall: System Preferences → Security & Privacy → Firewall → Firewall Options

### Linux
- Use `node dist/cli/index.js`
- Firewall: `sudo ufw allow 8443/tcp`

## Troubleshooting

### "Cannot find module" errors
```bash
npm install
npm rebuild
```

### Permission errors on Linux/Mac
```bash
chmod +x dist/cli/index.js
```

### Port already in use
```bash
# Check what's using port 8443
sudo lsof -i :8443  # Linux/Mac
netstat -ano | findstr :8443  # Windows

# Use different port
node dist/cli/index.js host --port 9443
```

### argon2 binding errors
```bash
# Rebuild native modules for your platform
npm rebuild argon2
```

## Performance Tips

- Use `NODE_ENV=production` for better performance
- Disable logging in production: `LOG_LEVEL=error`
- Use a static IP for the host to avoid connection issues

## Quick Reference

```bash
# Host (default port 8443)
node dist/cli/index.js host --name "Session Name"

# Host (custom port)
node dist/cli/index.js host --name "Session" --port 9443

# Client
node dist/cli/index.js join --host 192.168.1.100:8443

# With npm link
riftberry host --name "Session"
riftberry join --host 192.168.1.100:8443
```
