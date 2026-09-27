# Source verification

This public snapshot contains the independent relay implementation, locked build
configuration, tests, generic deployment recipes and a data-only protocol. It
does not include operator environments, deployed configurations, private keys,
test-node evidence, binaries or historical private development artifacts.

## Reproduce

Install the .NET SDK selected in `global.json` and Python 3, then run:

```sh
bash scripts/verify.sh
```

The script restores locked dependencies, runs server tests, checks that project
references stay within this repository, and runs the operator admission tests.
The GitHub workflow additionally packages and smoke-tests Linux x64 output.
Workflow configuration is not a claim that a hosted run has completed.

On 2026-09-27 the exported source passed this command on macOS with the pinned
.NET 10.0.401 SDK: **34 server tests passed, 0 skipped**, the source independence
check passed, and **12 Python operator tests passed**. This was a source-only
check in a standalone export directory. It did not deploy a node or build and
accept a Linux release artifact.

## Protocol snapshot

Endpoints consume immutable copies of `protocol/v1/` as data. They must not
reference this server's source or project files. These three file digests identify
the alpha.1 contract without publishing a private development archive:

| File | SHA-256 |
| --- | --- |
| `PROTOCOL.md` | `33092bd83ce3668522a51b4b96847e4815e017cb654b463603be1059931c0d28` |
| `schema.json` | `c7fbdc161c2b993899fe0c02770325293abed913891d74c637cc995388a886a5` |
| `fixtures/auth-presence.json` | `9a93360810ea55f5c8ecbc08ac7500f2a7d38cc0cbfb34cda4fc20b10a71bc35` |

The fixture contains a public key and a fixed signature for interoperability
testing. It is not a deployment identity. Never admit fixture keys on a node.

## Acceptance limits

Source tests and package smoke tests cover their named scopes only. Real Mac and
Windows endpoint enrollment, mutually authenticated inner TLS, unattended service
behavior, RDP/NLA, upgrades, quotas under real load and stability need their own
acceptance. See `RELEASE_GATES.md`; opening the source does not close those gates.
