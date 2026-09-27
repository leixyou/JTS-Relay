#!/usr/bin/env bash
set -euo pipefail
relay_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$relay_root"
relay_dotnet="${JTS_DOTNET:-dotnet}"
relay_rid="${1:-linux-x64}"
case "$relay_rid" in linux-x64|linux-arm64) ;; *) echo 'Expected linux-x64 or linux-arm64' >&2; exit 2;; esac
relay_version="1.0.0-alpha.1"
relay_name="${JTS_RELAY_PACKAGE_NAME:-jts-relay-$relay_version-$relay_rid}"
[[ "$relay_name" =~ ^[A-Za-z0-9][A-Za-z0-9._-]+$ ]] || { echo 'Invalid package name' >&2; exit 2; }
relay_output="$relay_root/artifacts/$relay_name"
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
cp -R protocol/security-v2 "$relay_output/protocol/"
cp -R third-party "$relay_output/third-party"
cp global.json Directory.Build.props "$relay_output/"
python3 - "$relay_root" "$relay_output" <<'PY'
import hashlib, json, subprocess, sys
from pathlib import Path
root, output = map(Path, sys.argv[1:])
commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip()
dirty = bool(subprocess.check_output(['git', 'status', '--porcelain', '--untracked-files=no'], cwd=root))
if dirty: raise SystemExit('Package requires a committed, clean source tree')
def entry(file, base):
    data = file.read_bytes()
    return dict(path=str(file.relative_to(base)), size=len(data), sha256=hashlib.sha256(data).hexdigest())
sources = subprocess.check_output(['git', 'ls-files', '-z'], cwd=root).decode().split('\0')
manifest = dict(commit=commit, sourceCommit=commit, sourceDirty=dirty,
    sourceFiles=[entry(root/name, root) for name in sources if name and (root/name).is_file()],
    files=[entry(file, output) for file in sorted(output.rglob('*')) if file.is_file()])
(output/'SOURCE-AND-FILES.json').write_text(json.dumps(manifest, indent=2)+'\n')
PY
tar -czf "$relay_output.tar.gz" -C "$relay_root/artifacts" "$(basename "$relay_output")"
if command -v sha256sum >/dev/null; then sha256sum "$relay_output.tar.gz"; else shasum -a 256 "$relay_output.tar.gz"; fi
