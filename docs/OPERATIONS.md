# Operations

## Health and diagnosis

`/healthz` is non-sensitive liveness; `/v1/info` describes protocol/lanes. Neither
proves a device is authorized or that a Windows desktop can be reached. Use a
paired, disposable endpoint test for that. A generic error code intentionally
does not echo request content or exception details.

Check TLS hostname/expiry, endpoint SPKI identity, reciprocal admission, protocol
version, system UTC time, route reachability and quotas. Never resolve a failure
by disabling TLS or replacing a saved endpoint pin without owner confirmation.
Missing Windows RDP service or NLA failure is not repaired by a relay login.
`JTS.Relay.Server --version` reports the assembly informational version, including
the prerelease suffix; `--help` shows the basic command syntax. Neither command
loads configuration, opens a database or starts a listener.

## Quotas and privacy

The sample allows 10 Companion devices, 3 RDP sessions and 100 GiB/month of metered
forwarded outbound bytes, with a 100 MiB control reserve. Monthly counters are
durable, not reset by service restart; failed forwarding may conservatively count
reserved bytes. Control also has bounds and is not an unlimited free tunnel.
The current month is retained through its end even when nominal retention is
30 days, so cleanup cannot reset a 31-day month's quota.

Protocol 1 permits at most 128 peers per admitted device and
`MaxSessionsPerDevice` in 2–32. These are response-size compatibility limits,
not just pilot defaults; larger directories require a future paginated protocol.
`MaxSessions` must also be at least two. Admission reserves one quarter of the
global session limit (rounded down, minimum one) and one slot per device for new
control channels. New file/RDP offers are rejected when current occupancy reaches
the hard limit minus its reservation; control can use the full hard limit. Counts
include waiting and active streams, even existing control streams. This keeps bulk
admission from taking the last control slot without evicting any existing stream.
If control streams themselves fill the hard limit, new control requests can still
fail with `capacity_exhausted`; the reservation is not unlimited admission.

Read the local budget without opening a listener or changing admission:

```sh
/opt/jts-relay/current/JTS.Relay.Server --status --config /etc/jts-relay/relay.json
```

Run it as the service account or another authorized local operator that can read
the configured database and WAL files. The command opens SQLite read-only and
does not create a missing database. It returns only the UTC month, reserved
outbound bytes, monthly limit, control reserve, remaining bulk/control bytes and
`normal`, `warning_80`, `warning_95` or `exhausted`. It returns no devices, keys,
tickets or paths. `relay_status_failed` and a nonzero exit code mean status was
unavailable; they must not be interpreted as zero usage.

The service emits bounded warning codes `relay_budget_80_percent`,
`relay_budget_95_percent` and `relay_budget_exhausted` to stderr when usage reaches
a new highest threshold. The threshold marker is persisted in the same transaction
as accounting and survives restart. A single large reservation may skip directly
to a higher tier; a crash between commit and emission may suppress one warning.
Use `--status` for authoritative counters, not log scraping alone. Thresholds
refer to the total monthly limit; bulk forwarding stops earlier to preserve the
configured control reserve. This is not a public metrics or administration API.

Application metering cannot cap provider billing for TLS overhead or hostile
traffic. Configure independent provider spending limits and network alerts.
At quota exhaustion bulk forwarding fails closed; do not automatically purchase
capacity or increase limits. Set an explicit operator budget and monitor the
provider's actual billing separately from the relay's application counters.

Default intended retention is 7 days for security metadata and 30 days for
completed usage periods. Presence and required active configuration are separate
operational state. No stream content is written to disk. Console logs are bounded
by the supplied Compose settings; systemd operators must set equivalent journal
retention. Do not enable request/body/Authorization logging at an external proxy.

## Upgrade and rollback

1. Obtain a specific release and verify its published checksums and provenance.
2. Pause new admission, stop the service, record `--status` counters and back up
   state/configuration. Keep a dated copy of the current month's high-water mark
   separately from the database backup.
3. For native deployment, extract to a NEW version directory and atomically switch
   `current`; for Compose, select the exact new image tag/digest.
4. Start, check health/TLS, and perform one authorized end-to-end smoke.
5. If it fails, stop and record the newest available monthly counters before
   restoring the previous version and its matching database backup. Do not point
   old binaries at a newer incompatible database. Follow the reconciliation rule
   below before restarting traffic; restoring an old backup can reduce usage.

Do not automatically retry endpoint jobs during server upgrades. Stream closure
is visible to endpoints; durable file/job recovery belongs there, not in the relay.

## Backup and recovery

Stop the service before copying the database and any remaining SQLite WAL/SHM
files, or use a SQLite-aware online backup procedure. Back up admitted public-key
configuration separately. Keep TLS private keys under your secret backup policy,
not beside a public release archive. Encrypt backups and restrict access.

Recovery uses the same compatible binary with restored configuration/state.
All old tickets/challenges/sockets are invalid after restart. Do not advertise
ticket recovery or active-session failover. Verify durable usage before reopening
admission so a restore cannot accidentally provide an unmetered service.

An old snapshot cannot recover bytes forwarded since that snapshot. Compare its
current-month `--status` with the separately retained high-water mark and provider
egress records. This alpha has no supported counter-reconciliation/write command;
do not edit SQLite by guesswork or assume a backup restores exact usage. If any
usage is missing or uncertain, keep the service stopped until an operator-reviewed
reconciliation is available. Merely watching warning logs or running `--status`
does not repair a lower counter. Resume large-stream traffic only after the
uncertainty is resolved and independent provider spending/egress hard limits are
in effect. The provider limit remains necessary even with a consistent database.

## Revoke and uninstall

For additive admission of a controller/Companion pair, use the bounded
[public-device admission workflow](DEVICE_ADMISSION.md). It prepares a private
candidate and backup by default, requires an explicit apply operation, and never
restarts the service itself.

Remove the device and reciprocal peer entries, then restart to close its active
node sessions. Endpoint grants require their own revocation; an offline endpoint
may retain an explicitly accepted task until its deadline.

To uninstall, first stop/disable the unit or run `docker compose down` WITHOUT
`--volumes`. Preserve data/config by default. Remove only the exact installed
unit/version after review. Deleting a volume, database or private key is a separate
destructive operation requiring an explicit operator decision.
