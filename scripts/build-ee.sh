#!/bin/bash
set -euo pipefail

# Build Execution Environments for security.compliance_windows
#
# Builds two EE variants:
#   - STIG EE: pywinrm + SCAP benchmarks (SCC downloaded at scan time)
#   - CIS EE:  pywinrm + infra.windows_ops collection
#
# Prerequisites:
#   - ansible-builder >= 3.0 (pip install ansible-builder)
#   - podman or docker
#   - Access to registry.redhat.io (authenticated via podman/docker login)
#
# Usage:
#   ./scripts/build-ee.sh                    # Build STIG EE with default tag
#   ./scripts/build-ee.sh stig               # Build STIG EE only
#   ./scripts/build-ee.sh cis                # Build CIS EE only
#   ./scripts/build-ee.sh all                # Build both
#   TAG=myregistry/ee:v1 ./scripts/build-ee.sh stig  # Custom tag

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_DIR="${BUILD_DIR:-$REPO_ROOT/build/ee}"
CONTAINER_RUNTIME="${CONTAINER_RUNTIME:-podman}"
PROFILE="${1:-stig}"

echo "=== Building compliance-windows EE ==="
echo "  Profile:   $PROFILE"
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

build_ee() {
    local ee_file="$1"
    local tag="$2"
    local label="$3"

    echo "=== Building $label ==="
    echo "  EE file: $ee_file"
    echo "  Tag:     $tag"

    # Clean and prepare build context
    rm -rf "$BUILD_DIR"
    mkdir -p "$BUILD_DIR"

    # Copy EE definition
    cp "$REPO_ROOT/$ee_file" "$BUILD_DIR/execution-environment.yml"

    # Create ansible-builder context
    cd "$BUILD_DIR"
    ansible-builder create -f execution-environment.yml -v 3

    # Copy this collection into the build context
    mkdir -p context/_build/collections/ansible_collections/security
    cp -r "$REPO_ROOT" context/_build/collections/ansible_collections/security/compliance_windows
    # Remove build artifacts from the copy
    rm -rf context/_build/collections/ansible_collections/security/compliance_windows/build
    rm -rf context/_build/collections/ansible_collections/security/compliance_windows/.git

    # For STIG EE: fetch SCAP benchmarks from NIWC Atlantic (public domain)
    if echo "$ee_file" | grep -qv "cis"; then
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
    fi

    # Build
    $CONTAINER_RUNTIME build -f context/Containerfile -t "$tag" context

    echo ""
    echo "=== $label built: $tag ==="
    echo ""
}

case "$PROFILE" in
    stig)
        TAG="${TAG:-compliance-windows-stig:latest}"
        build_ee "ee/execution-environment.yml" "$TAG" "Windows STIG EE"
        ;;
    cis)
        TAG="${TAG:-compliance-windows-cis:latest}"
        build_ee "ee/execution-environment-cis.yml" "$TAG" "Windows CIS EE"
        ;;
    all)
        build_ee "ee/execution-environment.yml" \
            "${STIG_TAG:-compliance-windows-stig:latest}" "Windows STIG EE"
        build_ee "ee/execution-environment-cis.yml" \
            "${CIS_TAG:-compliance-windows-cis:latest}" "Windows CIS EE"
        ;;
    *)
        echo "Usage: $0 [stig|cis|all]"
        exit 1
        ;;
esac

echo "To push to a registry:"
echo "  $CONTAINER_RUNTIME push <tag>"
echo ""
echo "To mirror to PAH:"
echo "  skopeo copy docker://<ghcr-tag> docker://<pah-host>/compliance-windows-stig:latest --dest-tls-verify=false"
echo ""
echo "To register on Controller, run:"
echo "  ansible-playbook install.yml -e aap_host=https://controller.example.com -e aap_token=<token>"
