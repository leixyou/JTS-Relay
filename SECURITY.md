# Security boundary

- Node admission requires an operator-admitted controller, authenticated one-use
  enrollment (or initial configured public keys), and reciprocal peer permission.
  Identity is SHA-256 of DER SPKI. Node admission never grants
  Windows command, file, desktop or MCP permission.
- Challenges and role-specific tickets are short-lived and single-use. Restart
  invalidates all live challenges, sessions and tickets. Admission is durable;
  the signed enrollment revoke action immediately closes the caller's peer lanes.
  Initial static configuration is seeded once and cannot resurrect a revoked pair.
- Normal deployments require HTTPS. Explicit HTTP development mode is limited
  to loopback clients and must not be exposed through an unauthenticated proxy.
- Outer HTTPS ends at the relay. Inner mutually authenticated TLS ends only at
  the paired Mac and Windows endpoint. A malicious node can deny service and
  observe timing/traffic size, but must not authenticate as an endpoint.
- JTS endpoints encrypt HTTPS/WSS to this server while skipping relay certificate
  PKI validation by default. Mandatory inner mutual TLS and paired SPKI pins still
  authenticate endpoints. The outer certificate policy belongs to the endpoint
  clients; the deployed relay still requires HTTPS.
- A tunnel carries one bound control/file/RDP lane. There is no hostname/port
  request, CONNECT proxy, shell, plugin loader or Windows broker in this server.
- Request, body, token, exception-detail and payload logging are disabled.
  SQLite contains presence/usage, public admission records, token hashes and
  bounded opaque enrollment ciphertext; no forwarded stream payload is stored.
  Protect it and node configuration with owner-only permissions.
- Budget enforcement is application metering, not a cloud-provider billing
  guarantee: TLS/HTTP overhead and attacks still consume bandwidth. Use provider
  spending limits, edge protection and alerts before public admission.
- Node administration and first-controller admission require local OS authority.
  Existing controllers may invite/revoke their own peers using signed operations;
  no unauthenticated admin or controller-registration HTTP endpoint exists.
  See [dynamic enrollment](docs/DYNAMIC_ENROLLMENT.md) for migration and recovery.

Do not send keys, ticket values, packet captures or user content in bug reports.
Report only a sanitized error code, version, time window and reproduction using
disposable test identities. Use GitHub private vulnerability reporting when it is
enabled for this repository. Otherwise request a private contact channel in a
general issue without including exploit details, credentials or user content.

This repository is an alpha preview. A passing source test or encrypted transport
does not establish production hardening or real Windows endpoint acceptance.
