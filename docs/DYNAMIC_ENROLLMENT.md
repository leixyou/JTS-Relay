# One-use device enrollment

This development preview accepts one-use enrollment without changing the running
node's configuration or restarting it for each Windows device. See the additive
[wire contract](../protocol/enrollment-v1/PROTOCOL.md). Existing signed relay v1
operations and opaque control/file/RDP streams retain their protocol.

## Initial Mac admission

The first controller must still be admitted by the node operator. There is no
anonymous controller registration or default enrollment password. Export only the
Mac's canonical P-256 public SPKI to a DER or Base64 file, then run as the relay OS
account, with its ordinary access to the protected config and database:

```sh
sudo -u jts-relay /opt/jts-relay/current/JTS.Relay.Server \
  --admit-controller-spki /var/lib/jts-relay/controller-public.spki \
  --config /etc/jts-relay/relay.json
```

This writes public identity metadata to SQLite and starts no listener. An already
running relay sees the controller immediately. Repeating the same key is a no-op;
role conflicts or exhausted device capacity fail. Never pass an endpoint private
key, invitation secret, or TLS key to this command. An empty `Relay.Devices` list
is allowed; the node then denies signed client operations until local admission.

## Connecting Windows

An admitted Mac creates and retains a single high-entropy invitation link. Windows
receives the link and exchanges encrypted enrollment material through the node.
Only the Mac that created the invitation can confirm its exact Windows claim.
The node then commits reciprocal admission and the bound receipt in one SQLite
transaction. The endpoints retain authority over their own pins and lane grants.

Windows claiming a link alone does not enable relay access. A changed claimant,
ciphertext, or signature cannot replace the first claim. Retrying the exact saved
claim or confirmation is safe after a dropped response. Bound receipts remain
available with the same claim token after the original expiry until revocation.
RDP login and endpoint connection failures do not revoke a bound device or consume
an unbound invitation; an unbound invitation retains its original time limit.

The node stores token hashes and opaque offer/response ciphertext, never the
independent link secret or decrypted enrollment. The controller's signed create
request sets expiry 300–1800 seconds ahead. Both ciphertexts are limited to 8192
decoded bytes. Public endpoints are limited globally and per source IP; forwarded
IP headers are not trusted. Responses use `Cache-Control: no-store`.

## Revocation and persistence

The signed `enrollment` operation's `revoke` action removes only that controller's
relationship with the specified peer, cancels its matching enrollment records,
invalidates pending tickets, and closes active lanes before acknowledging success.
Other controllers' relationships remain valid. Endpoint grants have their own
revocation and accepted-task semantics; removing a route does not roll back a
previously completed Windows action.

On first startup, `Relay.Devices` is validated and seeded into durable tables in
the existing SQLite database. A transaction records that migration exactly once.
Later config edits and restarts do not re-import old pairs or resurrect revocations.
The older JSON admission script is useful only for preparing that initial seed;
use dynamic enrollment after migration. Keep the database when upgrading. A backup
now contains admission records as well as usage, so restoring an older backup can
restore old authorization and requires deliberate operator review.

Default bounds are 256 pending/claimed invitations globally, 8 per controller,
4096 retained records, and 600 public enrollment requests per minute globally.
`MaxRequestsPerMinute` also limits each public source IP. The corresponding settings
are `MaxEnrollmentInvitations`, `MaxEnrollmentInvitationsPerController`,
`MaxStoredEnrollments`, and `MaxPublicEnrollmentRequestsPerMinute`. Expired/cancelled
records become eligible for cleanup after `SecurityRetentionDays`; bound records
are retained for recovery and never evicted merely to admit another invitation.

Changing server TLS, listeners, or resource limits remains a deployment operation.
Source tests establish protocol and transaction behavior, not a completed Windows
installation or end-to-end production acceptance.
