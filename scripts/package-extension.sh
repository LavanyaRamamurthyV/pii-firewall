#!/usr/bin/env bash
# Build dist/pii-firewall-extension.zip for the Chrome Web Store / Edge Add-ons.
set -euo pipefail
cd "$(dirname "$0")/.."
./scripts/sync-core.sh
mkdir -p dist
rm -f dist/pii-firewall-extension.zip
(cd extension && zip -qr ../dist/pii-firewall-extension.zip manifest.json icons lib src)
echo "dist/pii-firewall-extension.zip"
