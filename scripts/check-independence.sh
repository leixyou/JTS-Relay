#!/usr/bin/env bash
set -euo pipefail
relay_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$relay_root"
# Resolve references against each project, allowing internal ../../src references.
if find src tests -type d \( -name obj -o -name bin \) -prune -o -type f \( -name '*.csproj' -o -name '*.props' -o -name '*.targets' \) -print | while IFS= read -r project_file; do
  if grep -En '/Users/|[A-Za-z]:\\|WindowsCompanion|JTSTerminal|FreeRDP' "$project_file"; then
    exit 1
  fi
  while IFS= read -r reference; do
    [[ -z "$reference" ]] && continue
    case "$reference" in *'$('*|/*|*\\*) echo 'Nonportable project reference' >&2; exit 1;; esac
    reference_parent="$(cd "$(dirname "$project_file")/$(dirname "$reference")" && pwd -P)"
    case "$reference_parent/" in "$relay_root/"*) ;; *) echo 'Reference escapes relay checkout' >&2; exit 1;; esac
  done < <(sed -nE 's/.*<ProjectReference[^>]*Include="([^"]+)".*/\1/p' "$project_file")
done; then
  :
else
  echo 'External/platform project dependency detected.' >&2
  exit 1
fi
if find src -name '*.cs' -exec grep -En 'JTS\.WindowsCompanion|DllImport.*(wtsapi|user32)|Process\.Start' {} +; then
  echo 'Endpoint execution or platform code must not be embedded in the relay.' >&2
  exit 1
fi
echo 'Independent relay source boundary: PASS'
if command -v sha256sum >/dev/null 2>&1; then
  (cd protocol/security-v2 && sha256sum -c SHA256SUMS)
else
  (cd protocol/security-v2 && shasum -a 256 -c SHA256SUMS)
fi
