#!/usr/bin/env bash

set -euo pipefail

# Configuration
TUNNEL_NAME=${TUNNEL_NAME:-inspiredownloader}
HOSTNAME=${HOSTNAME:-inspiredownloader.majictab.com}
LOCAL_SERVICE=${LOCAL_SERVICE:-http://localhost:8000}
CONFIG_DIR=${CONFIG_DIR:-$HOME/.cloudflared}
CONFIG_FILE="$CONFIG_DIR/config.yml"

echo "Cloudflare Tunnel setup starting..."

if ! command -v cloudflared >/dev/null 2>&1; then
  echo "Error: cloudflared not found. Install it before running this script." >&2
  exit 1
fi

mkdir -p "$CONFIG_DIR"

if [ ! -f "$CONFIG_DIR/cert.pem" ]; then
  echo "No Cloudflare cert found. Please run 'cloudflared login' once to authenticate." >&2
  exit 1
fi

if [ ! -f "$CONFIG_DIR/$TUNNEL_NAME.json" ]; then
  echo "Creating tunnel '$TUNNEL_NAME'..."
  cloudflared tunnel create "$TUNNEL_NAME"
else
  echo "Tunnel '$TUNNEL_NAME' already exists; skipping creation."
fi

cat > "$CONFIG_FILE" <<EOF
tunnel: $TUNNEL_NAME
credentials-file: $CONFIG_DIR/$TUNNEL_NAME.json

ingress:
  - hostname: $HOSTNAME
    service: $LOCAL_SERVICE
  - service: http_status:404
EOF

echo "Config written to $CONFIG_FILE"

echo "Creating/updating DNS record for $HOSTNAME..."
cloudflared tunnel route dns "$TUNNEL_NAME" "$HOSTNAME"

echo "Cloudflare tunnel setup complete. Start it with:"
echo "  cloudflared tunnel run $TUNNEL_NAME"
