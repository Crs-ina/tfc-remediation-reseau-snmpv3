#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="/home/exauceeadm/tfc-remediation-reseau-snmpv3"
SERVICE_SOURCE="$REPO_DIR/deploy/systemd/okapi-backend.service"

test -f "$REPO_DIR/.env"
test -x "$REPO_DIR/.venv/bin/gunicorn"
test -x "$REPO_DIR/.venv/bin/okapi"
sudo install -m 0644 "$SERVICE_SOURCE" /etc/systemd/system/okapi-backend.service
sudo ln -sfn "$REPO_DIR/.venv/bin/okapi" /usr/local/bin/okapi
sudo systemctl daemon-reload
sudo systemctl enable okapi-backend
sudo systemctl restart okapi-backend
sudo systemctl --no-pager --full status okapi-backend
curl --fail --silent --show-error http://127.0.0.1:5000/health
