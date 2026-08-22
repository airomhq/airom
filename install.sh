#!/bin/sh
# AIROM 1-Line Installer for Linux and macOS
# Usage: curl -sSfL https://raw.githubusercontent.com/airomhq/airom/main/install.sh | sh

set -e

OWNER="airomhq"
REPO="airom"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"

# 1. Detect OS
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
case "$OS" in
    linux*)  OS="linux" ;;
    darwin*) OS="darwin" ;;
    *)
        echo "Error: Unsupported operating system: $OS"
        exit 1
        ;;
esac

# 2. Detect Architecture
ARCH="$(uname -m)"
case "$ARCH" in
    x86_64|amd64)  ARCH="amd64" ;;
    arm64|aarch64) ARCH="arm64" ;;
    *)
        echo "Error: Unsupported CPU architecture: $ARCH"
        exit 1
        ;;
esac

echo "=> Detected platform: ${OS}/${ARCH}"

# 3. Get Latest Version Tag
TAG="${VERSION:-}"
if [ -z "$TAG" ]; then
    TAG="$(curl -sSfL "https://api.github.com/repos/${OWNER}/${REPO}/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/' || echo "v0.1.0")"
fi
VERSION_NUM="${TAG#v}"

echo "=> Installing AIROM version: ${TAG}"

TARBALL="airom_${VERSION_NUM}_${OS}_${ARCH}.tar.gz"
URL="https://github.com/${OWNER}/${REPO}/releases/download/${TAG}/${TARBALL}"

# 4. Download and Extract
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

echo "=> Downloading ${URL}..."
if ! curl -sSfL "$URL" -o "${TMP_DIR}/${TARBALL}"; then
    echo "Warning: Direct binary release download failed, building from source with Go..."
    if command -v go >/dev/null 2>&1; then
        GOBIN="$INSTALL_DIR" go install github.com/airomhq/airom/cmd/airom@latest
        echo "=> Successfully installed airom via Go!"
        exit 0
    else
        echo "Error: Failed to download release binary and Go compiler is not installed."
        exit 1
    fi
fi

tar -xzf "${TMP_DIR}/${TARBALL}" -C "$TMP_DIR"

# 5. Install to target directory
if [ -w "$INSTALL_DIR" ]; then
    mv "${TMP_DIR}/airom" "${INSTALL_DIR}/airom"
else
    echo "=> Root permissions required to write to ${INSTALL_DIR}."
    sudo mv "${TMP_DIR}/airom" "${INSTALL_DIR}/airom"
fi
chmod +x "${INSTALL_DIR}/airom"

echo "=> AIROM successfully installed to ${INSTALL_DIR}/airom"
"${INSTALL_DIR}/airom" version || true
