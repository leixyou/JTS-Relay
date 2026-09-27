# Self-hosting alpha.1

## Requirements and limits

Choose the archive matching the machine: `linux-x64` for x86-64 or `linux-arm64`
for ARM64. The project defines both Linux RIDs; each distributed package needs
its own native runtime acceptance. The package-container recipe uses Debian 13
(trixie). Other distributions and Alpine/musl require separate verification.
Consult `VERIFICATION.md` and `RELEASE_GATES.md` before deploying this preview.

A self-contained package includes .NET/ASP.NET Core 10.0.12 but still depends on
Linux system libraries. The Debian 13 package-container recipe installs
`ca-certificates`, `libicu76`, `libssl3t64`, `libstdc++6`, `libgcc-s1` and `zlib1g`
over the base system's glibc. Install corresponding prerequisites before native
execution; do not copy Debian package names to another distribution unchanged.
See Microsoft's [Linux dependency guidance](https://learn.microsoft.com/en-us/dotnet/core/install/linux-scripted-manual#dependencies).
No separate .NET SDK/runtime is required to execute the native package.

Use a hostname you control and a valid certificate/private key for that hostname.
Container builds need network access to their base-image and OS-package sources;
this is not a dependency on an official JTS service. No Mac/Windows source,
official JTS account or license key is required. This alpha is not a certified
production deployment.

The server always presents an HTTPS certificate. JTS endpoint clients currently
encrypt outer HTTPS/WSS without validating the relay certificate by default;
they independently verify the paired endpoint's key inside mutual TLS. This
does not authenticate the relay's HTTPS identity. Supply a valid hostname
certificate so standard clients and operator tools can validate it normally.
Bring your own certificate-renewal procedure and restart after replacement.
Never deploy shared fixture identities or disable endpoint key verification.

## Admit devices

Copy `config/relay.example.json` from a source checkout, or
`deploy/relay.example.json` from an extracted binary archive, to your protected
deployment directory as `relay.json`. Populate
`Relay.Devices` using the public identities exported by your endpoints:

```json
[
  {"DeviceId":"<controller SPKI SHA-256>","PublicKeySpkiBase64":"<controller DER SPKI>","Role":"controller","Peers":["<companion SPKI SHA-256>"]},
  {"DeviceId":"<companion SPKI SHA-256>","PublicKeySpkiBase64":"<companion DER SPKI>","Role":"companion","Peers":["<controller SPKI SHA-256>"]}
]
```

These are placeholders, not usable keys. Never admit the public fixtures from
the protocol tests. Pair the endpoints independently and grant only necessary
capabilities there; admission to your node cannot substitute for that consent.
There is no default account, password or license key. Static public records seed
the durable registry only on its first startup. After that, use
[one-use enrollment](DYNAMIC_ENROLLMENT.md) and the local first-controller command
to add devices without editing JSON or restarting the service.

## Container

From a source checkout, build using its README command. From an extracted
self-contained archive, run this in the archive root (which contains `app/` and
`third-party/`):

```sh
docker build -f deploy/Dockerfile.package -t jts-relay:1.0.0-alpha.1 .
```

Use an ARM64 archive on an ARM64 build host, or an x64 archive on an x64 host;
this recipe does not convert architectures. Alternatively, load a separately
provided, exact-architecture OCI archive with `docker load` after verifying its
published digest. The native tar archive is not an OCI image, and an x64 package
or Dockerfile is not evidence that an x64 image was built or runtime-tested.

Put `compose.yaml`, `relay.json`, `tls.crt` (certificate chain) and `tls.key` in a
dedicated deployment directory. The certificate paths in relay.json must match
`/etc/jts-relay/tls.crt` and `/etc/jts-relay/tls.key`.

The container runs as the .NET image's non-root app user (UID 1654). Give that UID
read access to the mounted config/certificate/key without making the key public;
on Linux, owner UID 1654 with mode 0400 is sufficient. Keep the surrounding
directory private. The named volume retains the database across image upgrades.

```sh
docker compose up -d
docker compose logs --tail=30 relay
curl --fail --resolve your-relay-hostname:8443:127.0.0.1 https://your-relay-hostname:8443/healthz
```

By default Compose publishes only on 127.0.0.1. After verifying admission, TLS,
firewall rules and provider budget limits, explicitly set
`JTS_RELAY_BIND_ADDRESS=0.0.0.0` for IPv4 public listening (configure IPv6 binding
and firewall separately). Public clients must reach the advertised TLS port;
you may map host port 443 to container port 8443. Do not disable TLS.
The local `--resolve` check preserves normal hostname/certificate verification;
replace `your-relay-hostname` with the hostname on your certificate.

## Native Linux service

Extract the matching self-contained `jts-relay-<version>-linux-<architecture>.tar.gz` into a new
versioned directory beneath `/opt/jts-relay/releases/`. The release `app/` directory
contains `JTS.Relay.Server`. Create the non-login `jts-relay` OS service account.
Link `/opt/jts-relay/current` to that version's `app/` directory. Install the
provided unit in `/etc/systemd/system/jts-relay.service` after reviewing it.

Create `/etc/jts-relay/relay.json` and certificate files readable only by the
administrator and service account. `StateDirectory=jts-relay` creates protected
`/var/lib/jts-relay`; its database path must match configuration. Use port 8443
unless a separately reviewed local TLS proxy or platform port mapping is present.
The service does not require root or CAP_NET_ADMIN/CAP_NET_BIND_SERVICE.

After explicit administrator review:

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now jts-relay
sudo systemctl status jts-relay --no-pager
```

Review [operations](OPERATIONS.md) before opening the firewall. Automatic package
installation, account creation and firewall changes are intentionally absent.
