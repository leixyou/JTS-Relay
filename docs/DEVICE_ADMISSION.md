# Admit a public device pair

`scripts/admit-device-pair.py` is a local operator tool for an already authorized
relay node. It changes only the reciprocal public admission records in the relay
JSON. It does not contact endpoints, read a TLS private-key file, change the relay
protocol, start the service, or restart it. Python 3 with the standard library is
the only runtime dependency. Keep these four files together:

- `admit-device-pair.py`
- `relay_admission_public.py`
- `relay_admission_transaction.py`
- `relay_admission_metadata.py`

Inputs are the controller's public enrollment request and the companion's public
enrollment bundle. For generic endpoints, each JSON may instead contain
`DeviceId`, `PublicKeySpkiBase64`, and `Role`. `--controller-spki` and
`--companion-spki` accept canonical public P-256 DER SPKI or Base64 files. Private
keys are not an input. A complete MCP response must first be reduced to its
`enrollmentRequest` public object; nested response wrappers are rejected.

The tool checks canonical DER, the actual P-256 curve point, SHA-256 device IDs,
roles, duplicate records and peers, reciprocal relationships throughout the
existing directory, and configured device/Companion/peer capacity. Existing
devices and unrelated configuration remain intact. It does not expand quotas.

## Prepare

After placing the public inputs and the four scripts on the authorized node:

```sh
sudo python3 /opt/jts-relay/admin/admit-device-pair.py \
  --config /etc/jts-relay/relay.json \
  --controller-json /var/tmp/jts-admission/controller-public.json \
  --companion-json /var/tmp/jts-admission/companion-public.json
```

This default action leaves the active config unchanged. It returns JSON paths
and hashes for a new `/etc/jts-relay/relay-admission-<random>/` directory:

- `original.json`: exact original bytes, for backup and rollback;
- `candidate.json`: the merged admission configuration;
- `manifest.json`: source identity/metadata, hashes, and transaction state.

The directory is mode `0700` and its files are `0600`. `--output-dir` can select
another existing directory. Use the returned manifest path; never guess the
random component. Review the pair's public device IDs and candidate diff without
printing keys or sensitive configuration to shared logs.

## Explicit publication

```sh
sudo python3 /opt/jts-relay/admin/admit-device-pair.py \
  --config /etc/jts-relay/relay.json \
  --apply /etc/jts-relay/relay-admission-<returned-id>/manifest.json
```

Publication uses `/etc/jts-relay/relay.json.admission.lock`, verifies the original
bytes, inode, mode, owner/group, times, and extended metadata, writes and fsyncs a
temporary file, then atomically replaces the config. Owner/group, mode, mtime,
xattrs and ACL metadata are restored on the replacement. All operator config
writers must honor the same lock; arbitrary writers ignoring advisory locks
cannot be given a universal filesystem compare-and-swap guarantee. An observed
concurrent change rejects publication rather than overwriting it.

Only this device pair may differ between the original and candidate. Editing
TLS settings, quotas or another device in a candidate causes rejection even if
its recorded checksum was also changed. A failed operation prints only a fixed
error code, never config contents or public/private key bytes.

Reapplying an already published transaction is a no-op if its exact published
state is still current. If the process stopped after atomic replacement but
before writing the manifest, reapply recovers the manifest only when the exact
candidate and preserved metadata are present; it does not republish or replay
endpoint work.

The running relay loads configuration only at process start. Apply therefore
means **configuration published**, not **new pair usable**. Schedule the already
authorized service restart separately, after active acceptance traffic completes,
then verify the new pair's signed admission and the actual endpoint operation.
Never restart automatically from this tool or infer Windows readiness from it.

## Rollback

```sh
sudo python3 /opt/jts-relay/admin/admit-device-pair.py \
  --config /etc/jts-relay/relay.json \
  --rollback /etc/jts-relay/relay-admission-<returned-id>/manifest.json
```

Rollback atomically restores `original.json` and its recorded permissions only
when the active config still exactly matches this transaction's published
candidate and metadata. Any later edit blocks rollback; prepare a new reviewed
change instead of copying an old backup over newer admissions. Rollback also
does not restart the service, restore a database, or touch TLS key files.

## Verification

```sh
python3 -m unittest discover -s tests/operator -v
```

The 12 operator tests cover public identity checks, existing-device
preservation, capacity, reciprocal peers, prepare without publication, file
metadata, stale content/inode rejection, lock exclusion, candidate tampering,
crash recovery and rollback refusing newer edits. They use temporary fixture
configurations and do not read a deployed relay's keys or configuration. See
[verification](VERIFICATION.md) for the checks run on this source snapshot.
Deploy the scripts to your own node, for example `relay.example.com`, and verify
the installed file checksums. A recommended installation is a root-owned
`/opt/jts-relay/admin` directory with mode `0750` and script mode `0640`.
Operator-tool tests do not prove endpoint admission or Windows readiness.
