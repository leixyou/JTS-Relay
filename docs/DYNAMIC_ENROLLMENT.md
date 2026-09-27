# One-use device enrollment

This development preview accepts one-use enrollment without changing the running
node's configuration or restarting it for each Windows device. See the additive
[security v2 contract](../protocol/security-v2/PROTOCOL.md), which extends the
immutable enrollment v1 format. Authentication now requires V2 audience-bound
signatures and the operator's `Relay.PublicOrigin`; there is no V1 fallback.
Opaque control/file/RDP forwarding retains its protocol.

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
Only the Mac that created the invitation can sign confirmation of its exact
Windows claim. The node commits that signature and reciprocal admission together.
Windows independently verifies the pinned Mac signature before creating grants;
an unsigned node assertion that the invitation is bound is insufficient.

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

The signed `revocations` mailbox persists the controller's request and removes
only its relationship with the named peer, invalidates pending tickets, and
closes active lanes. The state stays pending until Windows verifies the request,
durably revokes the exact named grant epoch, drains its jobs and signs a receipt.
The companion remains admitted to poll that mailbox. A new binding is blocked
while that edge has pending revocations. Other controllers remain unaffected.
Exact retries survive restarts without cutting a newer completed binding.
The older enrollment `revoke` action is node-only and does not prove endpoint
revocation. Previously completed Windows actions cannot be rolled back.

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
Mailbox records are separately capped by `MaxStoredEnrollments`, with at most
128 pending requests per companion. Poll replies contain at most 32 records and
64 KiB. Pending revocations never expire or get evicted to make space.

Anonymous challenge issuance uses a source-IP quota, independently of verified
device requests. Challenges do not reserve per-device slots. Only successful
proofs enter bounded replay state (`MaxChallenges`) or consume device quotas;
`MaxChallengesPerDevice` is a retained legacy configuration field with no effect
on the stateless V2 challenge issuer. Rejected per-IP enrollment requests do not
consume global enrollment quota.

Changing server TLS, listeners, or resource limits remains a deployment operation.
Source tests establish protocol and transaction behavior, not a completed Windows
installation or end-to-end production acceptance.
