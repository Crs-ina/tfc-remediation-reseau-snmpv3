#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"
PACKAGE="$PROJECT_DIR/dist/okapi_1.0.0_amd64.deb"

if [ ! -f "$PACKAGE" ]; then
    echo "Package not found: $PACKAGE" >&2
    echo "Build it first with: bash packaging/debian/build-deb.sh" >&2
    exit 1
fi

sudo apt install "$PACKAGE"
echo "Configure /etc/okapi/secrets.env before starting okapi.service."
