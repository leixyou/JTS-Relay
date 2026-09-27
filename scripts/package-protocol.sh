#!/usr/bin/env bash
set -euo pipefail
relay_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$relay_root"
protocol_artifact="artifacts/jts-relay-protocol-1.0.0-alpha.1.tar.gz"
if [[ -e "$protocol_artifact" ]]; then
  echo 'Protocol artifact already exists; do not overwrite an immutable snapshot.' >&2
  exit 2
fi
mkdir -p artifacts
tar -czf "$protocol_artifact" -C protocol v1
if command -v sha256sum >/dev/null; then sha256sum "$protocol_artifact"; else shasum -a 256 "$protocol_artifact"; fi
