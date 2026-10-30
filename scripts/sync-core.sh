#!/usr/bin/env bash
# Copy the shared JS core into the extension (extensions can't load files outside their folder).
set -euo pipefail
cd "$(dirname "$0")/.."
cp core/js/pii-core.js extension/lib/pii-core.js
echo "extension/lib/pii-core.js updated"
