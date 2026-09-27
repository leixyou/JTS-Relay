# JTS Relay

This is the independent JTS Relay public source project. See `LICENSE` for the
project's license and `third-party/` for dependency notices. Keep release
publication, infrastructure deployment and service purchases within the owner's
explicitly authorized scope.

- Read current code before editing. Use small, layered, bounded modules.
- No dependency on JTS Terminal, Windows Companion, Xcode, Windows SDK, sibling
  directories, operator home directories, or official service credentials.
- The relay handles authenticated rendezvous and opaque byte forwarding only.
  Never execute client commands or terminate endpoint-to-endpoint TLS.
- Official and self-hosted deployments use the same executable and protocol.
- Fail closed on unknown identities, invalid signatures, expired/replayed tickets,
  unsupported protocol, exhausted resources, and invalid configuration.
- Never log request bodies, authorization headers, tickets, payload bytes or keys.
- Use apply_patch for source edits. Run affected tests once; expand for failures
  or release candidates. Do not claim endpoint or Linux runtime evidence from
  unit tests. Track unimplemented release gates explicitly.
