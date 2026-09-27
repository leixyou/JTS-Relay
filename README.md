# JTS Relay

**一个 JTS 终端，让 AI 像操作本机一样操作远程设备；Relay 负责跨网络的加密连接。**

JTS brings remote machines into one terminal workspace for AI-assisted work.
Through [JTS Terminal](https://github.com/leixyou/JTS-Terminal-2.0), AI clients
invoke commands, file operations and semantic Windows UI Automation on paired
devices and receive structured results. The
[Windows Companion](https://github.com/leixyou/JTS-Windows-Companion) provides
the Windows capabilities; JTS Relay connects the endpoints when a direct network
path is unavailable.

This repository contains the independent, self-hostable rendezvous and encrypted
byte relay for that workflow. Remote operations execute at the endpoints, with
their own device identity and permissions. Control, file and RDP streams pass
through the relay as encrypted bytes.

**Status: 1.0.0-alpha.1 development preview, not a production/release approval.**
Control, file and RDP are separate relay lanes. The relay does not execute
commands, store transferred files, interpret RDP or decrypt endpoint TLS.
Endpoint production integration and real Windows/public-network acceptance are
tracked separately. An opaque loopback test is not proof of those capabilities.

Deployed traffic uses encrypted HTTPS/WSS. JTS endpoint clients skip relay
certificate PKI validation by default while still requiring paired endpoint
SPKI pins and inner mutual TLS. The relay cannot decrypt those inner streams.
The endpoint policy does not enable plaintext relay deployment.

## Choose the distribution

The source checkout and the self-contained binary archive are different artifacts:

| Artifact | Contents | Use |
| --- | --- | --- |
| Source checkout | `src/`, `tests/`, `scripts/`, `JTSRelay.slnx`, deployment recipes | Build and test with the pinned SDK |
| `jts-relay-<version>-linux-<architecture>.tar.gz` | `app/`, `deploy/`, `docs/`, `protocol/`, `third-party/` | Install the included executable without the .NET SDK |

From an extracted binary archive, run `./app/JTS.Relay.Server --version` and follow
[self-hosting](docs/SELF_HOSTING.md). Its example is `deploy/relay.example.json`,
not the source checkout's `config/relay.example.json`. A binary archive does not
include the source solution or build/test scripts. Keep the whole archive together,
including dependency notices; do not redistribute only the executable.

Both artifacts can build a container, but use different recipes: source uses
`deploy/Dockerfile`; the extracted binary archive uses `deploy/Dockerfile.package`
and must match the build host/image architecture. Neither recipe is itself a
published OCI image or evidence that Linux x64 runtime acceptance passed.

## Build and verify from source

Install the SDK selected by `global.json`, then run from this directory:

```sh
dotnet restore JTSRelay.slnx --locked-mode
bash scripts/verify.sh
bash scripts/package.sh linux-x64
docker build -f deploy/Dockerfile -t jts-relay:1.0.0-alpha.1 .
```

`JTS_DOTNET` may name a locally installed SDK executable for the shell scripts.
No sibling checkout, Xcode, Windows SDK, official account or JTS license server
is used. Tests use only public fixture keys and disposable local data.

## Deploy

Start with [self-hosting](docs/SELF_HOSTING.md). Supply your own HTTPS certificate,
admitted endpoint public keys and reciprocal peer permissions. The sample has no
admitted devices and intentionally cannot accept clients. Never use fixture keys.

The same build runs official and self-hosted nodes. The sample caps are a
conservative pilot configuration, not a paid tier or throughput guarantee; an
operator can adjust them for their own server budget. Nothing calls an official
admission, licensing, telemetry or update service.

See [operations](docs/OPERATIONS.md), [security V2 protocol](protocol/security-v2/PROTOCOL.md),
[security](SECURITY.md), and [release gates](docs/RELEASE_GATES.md).

JTS source is licensed under Apache-2.0; see [LICENSE](LICENSE) and [CONTRIBUTING.md](CONTRIBUTING.md)
for contribution and verification instructions. Third-party components retain
their own licenses. Preserve their notices when redistributing them; the
[third-party inventory](third-party/README.md) records dependency versions,
retained license texts, provenance and outstanding binary-release review.
