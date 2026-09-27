#!/usr/bin/env bash
set -euo pipefail
relay_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$relay_root"
relay_dotnet="${JTS_DOTNET:-dotnet}"
"$relay_dotnet" restore JTSRelay.slnx --locked-mode
"$relay_dotnet" test JTSRelay.slnx --no-restore -c Release --logger 'trx;LogFileName=relay.trx' --results-directory artifacts/tests
bash scripts/check-independence.sh
python3 -m unittest discover -s tests/operator -v
