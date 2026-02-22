# RiftRaspberry Distribution Guide

## 📦 Available Builds

After running `npm run build:exe`, you'll find platform-specific builds in the `build/` directory:

```
build/
├── riftberry-windows-x64/      # Windows 64-bit
├── riftberry-linux-x64/         # Linux 64-bit
├── riftberry-linux-arm64/       # Raspberry Pi / ARM64 Linux
├── riftberry-macos-x64/         # macOS Intel
└── riftberry-macos-arm64/       # macOS Apple Silicon
```

Each build contains:
- `dist/` - Compiled application
- `node_modules/` - All dependencies (including native binaries)
- `config/` - Configuration files
- `riftberry.bat` or `riftberry.sh` - Launcher script
- `README` - Platform-specific instructions

## 🚀 How to Use

### Windows (riftberry-windows-x64)

1. **Copy the folder** to your Windows machine
2. **Open Command Prompt or PowerShell** in that folder
3. **Run the application:**
   ```cmd
   riftberry.bat host --name "My Session"
   riftberry.bat join --host 192.168.1.100:8443
   ```

### Linux / macOS (riftberry-linux-x64, riftberry-macos-x64, etc.)

1. **Copy the folder** to your Linux/Mac machine
2. **Make the launcher executable:**
   ```bash
   chmod +x riftberry.sh
   ```
3. **Run the application:**
   ```bash
   ./riftberry.sh host --name "My Session"
   ./riftberry.sh join --host 192.168.1.100:8443
   ```

### Raspberry Pi (riftberry-linux-arm64)

1. **Transfer the folder** to your Raspberry Pi:
   ```bash
   scp -r build/riftberry-linux-arm64 pi@raspberrypi.local:~/
   ```

2. **SSH into the Pi:**
   ```bash
   ssh pi@raspberrypi.local
   cd ~/riftberry-linux-arm64
   ```

3. **Make executable and run:**
   ```bash
   chmod +x riftberry.sh
   ./riftberry.sh host --name "Pi Session"
   ```

## 📋 Requirements

- **Node.js 18+** must be installed on the target system
- All dependencies are bundled in `node_modules/`
- Native modules (argon2) are platform-specific

## 🔧 Creating Archives for Distribution

### Create ZIP archives for each platform:

**Windows:**
```powershell
# In PowerShell
Compress-Archive -Path build\riftberry-windows-x64 -DestinationPath riftberry-windows-x64.zip
```

**Linux/macOS:**
```bash
cd build
tar -czf riftberry-linux-x64.tar.gz riftberry-linux-x64/
tar -czf riftberry-linux-arm64.tar.gz riftberry-linux-arm64/
tar -czf riftberry-macos-x64.tar.gz riftberry-macos-x64/
tar -czf riftberry-macos-arm64.tar.gz riftberry-macos-arm64/
```

## 🎯 Quick Start for End Users

### Download & Extract

1. Download the archive for your platform
2. Extract to any location
3. Open terminal/command prompt in that folder

### Host Mode (Server)

```bash
# Windows
riftberry.bat host --name "My Session"

# Linux/Mac/Raspberry Pi
./riftberry.sh host --name "My Session"
```

The host will display:
- **Password** - Share with clients
- **Fingerprint** - Clients verify this
- **IP addresses** - Where clients should connect

### Client Mode

```bash
# Windows
riftberry.bat join --host 192.168.1.100:8443

# Linux/Mac/Raspberry Pi
./riftberry.sh join --host 192.168.1.100:8443
```

You'll be prompted for:
- Password (from host)
- Fingerprint confirmation

## 🔍 Troubleshooting

### "node: command not found"

Install Node.js 18 or higher:
- **Windows:** https://nodejs.org/
- **Linux:** `sudo apt install nodejs npm`
- **macOS:** `brew install node`
- **Raspberry Pi:** `curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash - && sudo apt install -y nodejs`

### "Permission denied" (Linux/Mac)

Make the launcher executable:
```bash
chmod +x riftberry.sh
```

### Native module errors

If you copied from a different platform, rebuild native modules:
```bash
cd node_modules/argon2
npm rebuild
```

### Port already in use

Use a different port:
```bash
# Windows
riftberry.bat host --port 9443

# Linux/Mac
./riftberry.sh host --port 9443
```

## 📦 Distribution Checklist

When distributing to others:

- [ ] Test on target platform
- [ ] Include README with quick start instructions
- [ ] Document Node.js requirement
- [ ] Provide sample commands
- [ ] Include troubleshooting tips
- [ ] Test with non-technical users

## 🔐 Security Notes

- ✅ All connections are encrypted with TLS 1.3
- ✅ Passwords are hashed with Argon2id
- ✅ Fingerprint verification prevents MITM attacks
- ⚠️ Designed for trusted LAN environments only
- ⚠️ Not intended for internet-exposed deployments

## 📊 Package Sizes

Each platform package includes the compiled app + ~200MB of node_modules:

- Windows: ~230 MB
- Linux: ~230 MB
- Raspberry Pi (ARM64): ~230 MB
- macOS: ~230 MB

The large size is due to native dependencies (argon2, node-forge) being bundled.

## 🚢 Advanced: Create Installer

For production distribution, consider creating installers:

### Windows (NSIS)
Use NSIS to create a Windows installer that:
- Checks for Node.js
- Installs to Program Files
- Creates desktop shortcut
- Adds to Start Menu

### Linux (DEB/RPM)
Create packages with:
- `dpkg-deb` for Debian/Ubuntu
- `rpmbuild` for RedHat/CentOS

### macOS (DMG)
Create a DMG file with:
- Application bundle
- Node.js check script
- Installation instructions

## 📝 License

Include your license file in each distribution package.
