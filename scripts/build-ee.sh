#!/bin/bash
set -euo pipefail

# Build the unified Execution Environment for security.compliance_windows
#
# The single EE supports all scanner backends:
#   - PowerSTIG (DSC-based, recommended default)
#   - DISA SCC (SCAP 1.3 certified, portable download at scan time)
#   - infra.windows_ops (CIS benchmarks)
#
# Prerequisites:
#   - ansible-builder >= 3.0 (pip install ansible-builder)
#   - podman or docker
#   - Access to registry.redhat.io (authenticated via podman/docker login)
#
# Usage:
#   ./scripts/build-ee.sh                                  # Build with default tag
#   TAG=myregistry/ee:v1 ./scripts/build-ee.sh             # Custom tag
#   CONTAINER_RUNTIME=docker ./scripts/build-ee.sh         # Use docker

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_DIR="${BUILD_DIR:-$REPO_ROOT/build/ee}"
CONTAINER_RUNTIME="${CONTAINER_RUNTIME:-podman}"
TAG="${TAG:-compliance-windows:latest}"

echo "=== Building compliance-windows unified EE ==="
echo "  Tag:       $TAG"
echo "  Runtime:   $CONTAINER_RUNTIME"
echo ""

# Check prerequisites
for cmd in ansible-builder "$CONTAINER_RUNTIME"; do
    if ! command -v "$cmd" &> /dev/null; then
        echo "ERROR: $cmd not found."
        [ "$cmd" = "ansible-builder" ] && echo "Install with: pip install ansible-builder"
        exit 1
    fi
done

# Clean and prepare build context
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"

# Copy EE definition
cp "$REPO_ROOT/ee/execution-environment.yml" "$BUILD_DIR/execution-environment.yml"

# Create ansible-builder context
cd "$BUILD_DIR"
ansible-builder create -f execution-environment.yml -v 3

# Copy this collection into the build context
mkdir -p context/_build/collections/ansible_collections/security
cp -r "$REPO_ROOT" context/_build/collections/ansible_collections/security/compliance_windows
# Remove build artifacts from the copy
rm -rf context/_build/collections/ansible_collections/security/compliance_windows/build
rm -rf context/_build/collections/ansible_collections/security/compliance_windows/.git

# Fetch SCAP benchmarks from NIWC Atlantic (public domain)
echo "  Fetching SCAP benchmarks from niwc-atlantic/scap-content-library..."
mkdir -p context/_build/scap-content
if command -v git &> /dev/null; then
    git clone --depth 1 https://github.com/niwc-atlantic/scap-content-library.git \
        /tmp/scap-content-library 2>/dev/null || true
    if [ -d /tmp/scap-content-library ]; then
        cp -r /tmp/scap-content-library/scap1.4/ context/_build/scap-content/ 2>/dev/null || \
        cp -r /tmp/scap-content-library/ context/_build/scap-content/ 2>/dev/null || true
        rm -rf /tmp/scap-content-library
        echo "  SCAP content fetched."
    else
        echo "  WARNING: Could not fetch SCAP content. EE will work but SCAP benchmarks"
        echo "           must be provided at scan time or pre-installed on targets."
        touch context/_build/scap-content/.placeholder
    fi
else
    echo "  WARNING: git not found, skipping SCAP content fetch."
    touch context/_build/scap-content/.placeholder
fi

# Build
$CONTAINER_RUNTIME build -f context/Containerfile -t "$TAG" context

echo ""
echo "=== Unified EE built: $TAG ==="
echo ""
echo "Supports: PowerSTIG (default), DISA SCC, CIS (infra.windows_ops)"
echo ""
echo "To push to a registry:"
echo "  $CONTAINER_RUNTIME push $TAG"
echo ""
echo "To mirror to PAH:"
echo "  skopeo copy docker://$TAG docker://<pah-host>/compliance-windows:latest --dest-tls-verify=false"
echo ""
echo "To register on Controller, run:"
echo "  ansible-playbook install.yml -e aap_host=https://controller.example.com -e aap_token=<token>"
