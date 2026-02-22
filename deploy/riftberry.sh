#!/bin/bash
# RiftRaspberry Launcher

APP_DIR="$(cd "$(dirname "$0")" && pwd)"
node "$APP_DIR/dist/cli/index.js" "$@"
