#!/bin/bash
# Setup script - installs dependencies

echo "🔧 RiftRaspberry Setup"
echo ""
echo "Installing dependencies..."
npm install --production

if [ $? -eq 0 ]; then
    echo ""
    echo "✅ Setup complete!"
    echo ""
    echo "Usage:"
    echo "  ./riftberry.sh host --name \"My Session\""
    echo "  ./riftberry.sh join --host 192.168.1.100:8443"
    echo ""
else
    echo ""
    echo "❌ Setup failed. Make sure Node.js 18+ is installed."
    echo "   Install Node.js: https://nodejs.org/"
    exit 1
fi
