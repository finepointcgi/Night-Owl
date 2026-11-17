#!/bin/sh
# Installs the latest Night Owl release (or NIGHTOWL_VERSION) for this OS/CPU and verifies its
# SHA-256 against the release's SHA256SUMS before installing.
#
#   curl -fsSL https://raw.githubusercontent.com/finepointcgi/Night-Owl/main/scripts/install.sh | sh
#
# Env: NIGHTOWL_REPO (owner/repo), NIGHTOWL_VERSION (e.g. 1.2.0), NIGHTOWL_INSTALL_DIR (default ~/.local/bin)
set -eu

repo="${NIGHTOWL_REPO:-finepointcgi/Night-Owl}"
dir="${NIGHTOWL_INSTALL_DIR:-$HOME/.local/bin}"

case "$(uname -s)" in
  Linux) os=linux ;;
  Darwin) os=osx ;;
  *) echo "unsupported OS: $(uname -s) (Windows: download the .exe from the releases page)" >&2; exit 1 ;;
esac
case "$(uname -m)" in
  x86_64|amd64) arch=x64 ;;
  arm64|aarch64) arch=arm64 ;;
  *) echo "unsupported CPU: $(uname -m)" >&2; exit 1 ;;
esac

if [ -z "${NIGHTOWL_VERSION:-}" ]; then
  NIGHTOWL_VERSION=$(curl -fsSL "https://api.github.com/repos/$repo/releases/latest" | sed -n 's/.*"tag_name": *"v\{0,1\}\([^"]*\)".*/\1/p' | head -1)
fi
[ -n "$NIGHTOWL_VERSION" ] || { echo "could not determine the latest release of $repo" >&2; exit 1; }

asset="nightowl-$NIGHTOWL_VERSION-$os-$arch"
base="https://github.com/$repo/releases/download/v$NIGHTOWL_VERSION"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

curl -fsSL -o "$tmp/$asset" "$base/$asset"
curl -fsSL -o "$tmp/SHA256SUMS" "$base/SHA256SUMS"
expected=$(grep " $asset\$" "$tmp/SHA256SUMS" | cut -d' ' -f1)
if command -v sha256sum >/dev/null 2>&1; then actual=$(sha256sum "$tmp/$asset" | cut -d' ' -f1); else actual=$(shasum -a 256 "$tmp/$asset" | cut -d' ' -f1); fi
[ -n "$expected" ] && [ "$expected" = "$actual" ] || { echo "checksum mismatch for $asset; not installing" >&2; exit 1; }

mkdir -p "$dir"
install -m 0755 "$tmp/$asset" "$dir/nightowl"
echo "Installed nightowl $NIGHTOWL_VERSION to $dir/nightowl"
case ":$PATH:" in *":$dir:"*) ;; *) echo "Add $dir to your PATH." ;; esac
