#!/usr/bin/env bash
set -euo pipefail
relay_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$relay_root"
relay_dotnet="${JTS_DOTNET:-dotnet}"
relay_rid="${1:-linux-x64}"
case "$relay_rid" in linux-x64|linux-arm64) ;; *) echo 'Expected linux-x64 or linux-arm64' >&2; exit 2;; esac
relay_version="1.0.0-alpha.1"
relay_output="$relay_root/artifacts/jts-relay-$relay_version-$relay_rid"
if [[ -e "$relay_output" || -e "$relay_output.tar.gz" ]]; then
  echo "Package exists; preserve it or choose a fresh checkout before packaging: $relay_output" >&2
  exit 2
fi
"$relay_dotnet" publish src/JTS.Relay.Server/JTS.Relay.Server.csproj -c Release -r "$relay_rid" --self-contained true -o "$relay_output/app" /p:ContinuousIntegrationBuild=true /p:RestoreLockedMode=true
mkdir -p "$relay_output/deploy" "$relay_output/docs" "$relay_output/protocol"
cp config/relay.example.json "$relay_output/deploy/relay.example.json"
cp deploy/jts-relay.service deploy/compose.yaml deploy/Dockerfile.package "$relay_output/deploy/"
cp README.md SECURITY.md NOTICE.md LICENSE "$relay_output/"
cp docs/*.md "$relay_output/docs/"
cp -R protocol/v1 "$relay_output/protocol/"
cp -R protocol/enrollment-v1 "$relay_output/protocol/"
cp -R third-party "$relay_output/third-party"
cp global.json Directory.Build.props "$relay_output/"
tar -czf "$relay_output.tar.gz" -C "$relay_root/artifacts" "$(basename "$relay_output")"
if command -v sha256sum >/dev/null; then sha256sum "$relay_output.tar.gz"; else shasum -a 256 "$relay_output.tar.gz"; fi
