#!/usr/bin/env bash
# Copy the shared JS core into the extension (extensions can't load files outside their folder).
set -euo pipefail
cd "$(dirname "$0")/.."
cp core/js/pii-core.js core/js/pii-names.js extension/lib/
echo "extension/lib updated"
