#!/usr/bin/env bash
# Package-only smoke: no SDK, client checkout, official identity or external host.
set -euo pipefail
[[ "$(uname -s)" == Linux && "$(id -u)" != 0 ]] || { echo 'Run as a non-root Linux user.' >&2; exit 2; }
[[ $# == 1 && -f "$1" ]] || { echo 'Usage: smoke-linux-package.sh /path/release.tar.gz' >&2; exit 2; }
for relay_command in openssl curl jq sqlite3 tar; do command -v "$relay_command" >/dev/null; done
relay_work="$(mktemp -d /tmp/jts-relay-package.XXXXXXXX)"
relay_pid=''
cleanup() {
  if [[ -n "$relay_pid" ]]; then kill "$relay_pid" 2>/dev/null || true; wait "$relay_pid" 2>/dev/null || true; fi
  case "$relay_work" in /tmp/jts-relay-package.*) rm -rf -- "$relay_work";; esac
}
trap cleanup EXIT
umask 077
tar -xzf "$1" -C "$relay_work"
relay_app="$(find "$relay_work" -mindepth 2 -maxdepth 2 -type d -name app)"
[[ -n "$relay_app" && -x "$relay_app/JTS.Relay.Server" ]]
relay_release="$(dirname "$relay_app")"
mkdir "$relay_work/state" "$relay_work/backup"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -keyout "$relay_work/tls.key" -out "$relay_work/tls.crt" -days 1 \
  -subj /CN=localhost -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1' >/dev/null 2>&1
# Independent ephemeral endpoint public identities; these keys are NEVER shipped.
for relay_role in controller companion; do
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 -out "$relay_work/$relay_role.key" 2>/dev/null
  openssl pkey -in "$relay_work/$relay_role.key" -pubout -outform DER -out "$relay_work/$relay_role.spki" 2>/dev/null
done
relay_controller_id="$(openssl dgst -sha256 "$relay_work/controller.spki" | awk '{print $NF}')"
relay_companion_id="$(openssl dgst -sha256 "$relay_work/companion.spki" | awk '{print $NF}')"
jq --arg root "$relay_work" --arg controller "$relay_controller_id" --arg companion "$relay_companion_id" \
  --arg controllerSpki "$(openssl base64 -A -in "$relay_work/controller.spki")" \
  --arg companionSpki "$(openssl base64 -A -in "$relay_work/companion.spki")" \
  '.Kestrel.Endpoints.Https.Url="https://127.0.0.1:18443" |
   .Kestrel.Endpoints.Https.Certificate={Path:($root+"/tls.crt"),KeyPath:($root+"/tls.key")} |
   .Relay.DatabasePath=($root+"/state/relay.sqlite") |
   .Relay.PublicOrigin="https://localhost:18443" |
   .Relay.Devices=[{DeviceId:$controller,PublicKeySpkiBase64:$controllerSpki,Role:"controller",Peers:[$companion]},
                   {DeviceId:$companion,PublicKeySpkiBase64:$companionSpki,Role:"companion",Peers:[$controller]}]' \
  "$relay_release/deploy/relay.example.json" > "$relay_work/relay.json"
relay_start() {
  "$relay_app/JTS.Relay.Server" --config "$relay_work/relay.json" >"$relay_work/server.log" 2>&1 &
  relay_pid=$!
  local relay_ready=0
  for ((relay_attempt=0; relay_attempt<50; relay_attempt++)); do
    kill -0 "$relay_pid" 2>/dev/null || { echo 'Package exited during startup.' >&2; sed -n '1,8p' "$relay_work/server.log" >&2; return 1; }
    if curl --silent --fail --cacert "$relay_work/tls.crt" https://localhost:18443/healthz > /dev/null; then relay_ready=1; break; fi
    sleep 0.1
  done
  [[ "$relay_ready" == 1 ]]
}
relay_stop() { kill "$relay_pid"; wait "$relay_pid"; relay_pid=''; }
"$relay_app/JTS.Relay.Server" --version
relay_start
curl --silent --show-error --fail --cacert "$relay_work/tls.crt" https://localhost:18443/v1/info | jq -e '.protocolVersion==1 and .lanes==["control","file","rdp"]' >/dev/null
[[ "$(stat -c %a "$relay_work/state")" == 700 ]]
relay_stop
# Consistent offline SQLite snapshot exercises package restart/recovery, not E2E traffic.
sqlite3 "$relay_work/state/relay.sqlite" 'PRAGMA integrity_check;' | grep -qx ok
sqlite3 "$relay_work/state/relay.sqlite" ".backup '$relay_work/backup/relay.sqlite'"
relay_start
"$relay_app/JTS.Relay.Server" --status --config "$relay_work/relay.json" > "$relay_work/status-before.json"
relay_stop
cp "$relay_work/backup/relay.sqlite" "$relay_work/state/relay.sqlite"
relay_start
"$relay_app/JTS.Relay.Server" --status --config "$relay_work/relay.json" > "$relay_work/status-restored.json"
cmp "$relay_work/status-before.json" "$relay_work/status-restored.json"
relay_stop
printf '%s\n' 'PASS: package-only non-root HTTPS, protocol discovery, protected state, restart and SQLite backup restore.'
printf '%s\n' 'Not covered: systemd installation, version migration, OCI image, Windows endpoints or public networking.'
