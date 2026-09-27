# Distribution notice

JTS Relay is an independent encrypted-stream relay. See `LICENSE` for the JTS
source license. This notice describes separately licensed dependencies.

Runtime and package dependencies retain their own licenses. `third-party/`
contains the current .NET/ASP.NET Core runtime license and notices, SQLitePCLRaw
license, package metadata, source/version inventory and known review gaps.
Publishing with .NET does not automatically place all these files beside the
executable; the JTS packaging step explicitly includes them. Keep this directory
with redistributed binaries and container images.

These third-party terms apply to their named components only and do not replace
the JTS source license. Binary distribution still requires the dependency/SBOM
and notice review in docs/RELEASE_GATES.md.
