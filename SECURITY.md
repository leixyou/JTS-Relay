# Security boundary

- Node admission requires operator-configured P-256 public keys and reciprocal
  peer permission. Identity is SHA-256 of DER SPKI. Node admission never grants
  Windows command, file, desktop or MCP permission.
- Challenges and role-specific tickets are short-lived and single-use. Restart
  invalidates all live challenges, sessions and tickets. Alpha configuration is
  loaded on startup; revoke node admission by editing config and restarting.
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
  SQLite contains only minimal presence/usage metadata, not encrypted stream
  content. Protect it and node configuration with owner-only permissions.
- Budget enforcement is application metering, not a cloud-provider billing
  guarantee: TLS/HTTP overhead and attacks still consume bandwidth. Use provider
  spending limits, edge protection and alerts before public admission.
- Keep administrative access outside the relay protocol. Use OS access controls
  to update node configuration; no unauthenticated admin HTTP endpoint exists.

Do not send keys, ticket values, packet captures or user content in bug reports.
Report only a sanitized error code, version, time window and reproduction using
disposable test identities. Use GitHub private vulnerability reporting when it is
enabled for this repository. Otherwise request a private contact channel in a
general issue without including exploit details, credentials or user content.

This repository is an alpha preview. A passing source test or encrypted transport
does not establish production hardening or real Windows endpoint acceptance.
