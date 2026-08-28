#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd -- "$SCRIPT_DIR/../.." && pwd)"
VERSION="${OKAPI_VERSION:-1.0.0}"
ARCHITECTURE="amd64"
BUILD_ARCHITECTURE="$(dpkg --print-architecture)"
OUTPUT_DIR="${OKAPI_OUTPUT_DIR:-$PROJECT_DIR/dist}"
BUILD_DIR="$(mktemp -d)"
PACKAGE_ROOT="$BUILD_DIR/okapi_${VERSION}_${ARCHITECTURE}"

cleanup() {
    rm -rf -- "$BUILD_DIR"
}
trap cleanup EXIT

if [ "$BUILD_ARCHITECTURE" != "$ARCHITECTURE" ]; then
    echo "Build host must be amd64 because native Python wheels are bundled." >&2
    echo "Detected build architecture: $BUILD_ARCHITECTURE" >&2
    exit 1
fi

for command in dpkg-deb python3; do
    command -v "$command" >/dev/null || {
        echo "Missing build command: $command" >&2
        exit 1
    }
done

install -d "$PACKAGE_ROOT/DEBIAN"
install -d "$PACKAGE_ROOT/opt/okapi/bin" "$PACKAGE_ROOT/opt/okapi/wheels"
install -d "$PACKAGE_ROOT/etc/okapi/playbooks"
install -d "$PACKAGE_ROOT/usr/bin" "$PACKAGE_ROOT/lib/systemd/system"
install -d "$PACKAGE_ROOT/usr/share/doc/okapi"

cp -a "$PROJECT_DIR/app" "$PACKAGE_ROOT/opt/okapi/"
cp -a "$PROJECT_DIR/migrations" "$PACKAGE_ROOT/opt/okapi/"
cp -a "$PROJECT_DIR/schemas" "$PACKAGE_ROOT/opt/okapi/"
install -m 0644 "$PROJECT_DIR/config.py" "$PACKAGE_ROOT/opt/okapi/config.py"
install -m 0644 "$PROJECT_DIR/run.py" "$PACKAGE_ROOT/opt/okapi/run.py"
install -m 0644 "$SCRIPT_DIR/requirements-runtime.txt" \
    "$PACKAGE_ROOT/opt/okapi/requirements-runtime.txt"

install -m 0644 "$PROJECT_DIR/config/remediation.json" \
    "$PACKAGE_ROOT/etc/okapi/remediation.json"
install -m 0644 "$PROJECT_DIR/config/whitelist.json" \
    "$PACKAGE_ROOT/etc/okapi/whitelist.json"
install -m 0644 "$PROJECT_DIR/config/automation_schedule.json" \
    "$PACKAGE_ROOT/etc/okapi/automation_schedule.json"
install -m 0644 "$PROJECT_DIR/config/snmp_capabilities.json" \
    "$PACKAGE_ROOT/etc/okapi/snmp_capabilities.json"
cp -a "$PROJECT_DIR/playbooks/." "$PACKAGE_ROOT/etc/okapi/playbooks/"
install -m 0644 "$SCRIPT_DIR/okapi.env" "$PACKAGE_ROOT/etc/okapi/okapi.env"
install -m 0644 "$SCRIPT_DIR/secrets.env.example" \
    "$PACKAGE_ROOT/etc/okapi/secrets.env.example"

install -m 0755 "$SCRIPT_DIR/okapi" "$PACKAGE_ROOT/usr/bin/okapi"
install -m 0755 "$SCRIPT_DIR/migrate-database" \
    "$PACKAGE_ROOT/opt/okapi/bin/migrate-database"
install -m 0644 "$SCRIPT_DIR/okapi.service" \
    "$PACKAGE_ROOT/lib/systemd/system/okapi.service"
install -m 0644 "$SCRIPT_DIR/INSTALL.md" \
    "$PACKAGE_ROOT/usr/share/doc/okapi/INSTALL.md"

install -m 0755 "$SCRIPT_DIR/DEBIAN/postinst" "$PACKAGE_ROOT/DEBIAN/postinst"
install -m 0755 "$SCRIPT_DIR/DEBIAN/prerm" "$PACKAGE_ROOT/DEBIAN/prerm"
install -m 0755 "$SCRIPT_DIR/DEBIAN/postrm" "$PACKAGE_ROOT/DEBIAN/postrm"
install -m 0644 "$SCRIPT_DIR/DEBIAN/conffiles" "$PACKAGE_ROOT/DEBIAN/conffiles"
sed "s/@ARCHITECTURE@/$ARCHITECTURE/g" "$SCRIPT_DIR/DEBIAN/control.in" \
    > "$PACKAGE_ROOT/DEBIAN/control"

python3 -m pip download \
    --disable-pip-version-check \
    --only-binary=:all: \
    --dest "$PACKAGE_ROOT/opt/okapi/wheels" \
    --requirement "$SCRIPT_DIR/requirements-runtime.txt"

find "$PACKAGE_ROOT/opt/okapi" -type d -name __pycache__ -prune -exec rm -rf {} +
find "$PACKAGE_ROOT/opt/okapi" -type f -name '*.pyc' -delete

install -d "$OUTPUT_DIR"
dpkg-deb --root-owner-group --build "$PACKAGE_ROOT" \
    "$OUTPUT_DIR/okapi_${VERSION}_${ARCHITECTURE}.deb"
echo "$OUTPUT_DIR/okapi_${VERSION}_${ARCHITECTURE}.deb"
