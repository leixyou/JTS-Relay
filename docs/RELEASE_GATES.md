# JTS Relay release gates

This is an alpha source release. Public source availability does not certify a
binary, hosted node, endpoint combination or production deployment. Record exact
versions, commands and results for the artifacts being released.

- [ ] A clean Linux x64 checkout restores locked dependencies, builds and tests.
- [ ] Linux x64 and ARM64 packages start as non-root with real HTTPS.
- [ ] Package-derived containers work with a read-only root and protected state.
- [ ] Restart preserves usage and expires every challenge, ticket and stream.
- [ ] Upgrade, rollback, backup, recovery and uninstall use actual artifacts.
- [ ] Control, file and RDP pass through real paired endpoint mutual TLS.
- [ ] Windows 11 and the explicitly supported Windows 10 configuration pass.
- [ ] Wrong pins, replay, wrong lanes, expiry, revocation and malformed input fail.
- [ ] Concurrent lanes, quota exhaustion, cancellation and slow peers stay bounded.
- [ ] Self-hosted nodes run the same documented executable and protocol.
- [ ] Bounded concurrency and a 24-hour stability observation pass.
- [ ] Protocol digests, dependency/SBOM inventory and notices match final artifacts.
- [ ] Distribution configs contain no fixture identities, keys or operator data.
- [ ] Operators configure provider budgets and metadata retention for their nodes.

Development source checks belong in `VERIFICATION.md`. They must not be promoted
to real Windows, public-network, spending or application-release claims.
