# Third-party distribution inventory

This inventory applies to JTS Relay `1.0.0-alpha.1`, built with SDK `10.0.401`
and .NET/ASP.NET Core `10.0.12` for `linux-x64` and `linux-arm64`. It does not
license JTS source; see the repository's root `LICENSE` for those terms.

## Shipped components and retained texts

| Components | Version | Package-declared license | Retained material |
| --- | --- | --- | --- |
| Microsoft.NETCore.App.Runtime and native apphost, both Linux RIDs | 10.0.12 | MIT | `dotnet-10.0.12/LICENSE.txt`, `RUNTIME-THIRD-PARTY-NOTICES.txt` |
| Microsoft.AspNetCore.App.Runtime, both Linux RIDs | 10.0.12 | MIT | same license, `ASPNETCORE-THIRD-PARTY-NOTICES.txt` |
| Microsoft.Data.Sqlite and Microsoft.Data.Sqlite.Core | 10.0.12 | MIT | same .NET repository license and exact package metadata |
| SQLitePCLRaw.core, bundle_e_sqlite3, provider.e_sqlite3, lib.e_sqlite3 | 2.1.12 | Apache-2.0 | `sqlitepclraw-2.1.12/LICENSE.txt` and exact package metadata |

`DEPENDENCIES.json` records all six locked server NuGet dependencies plus both
runtime packs and native apphost for both RIDs, with official NuGet package URLs
and content SHA-512 values. The package declarations, copyright strings and
repository provenance are retained in `package-metadata/`. Those metadata copies
omit only UTF-8 BOMs and normalize line endings; no license terms were changed.
Runtime notices and license copies match the cached official package bytes.

The runtime archives and Data.Sqlite packages identify the Microsoft source
revision as `95017c711e6afc1085133d440e42b4bd78155701` in the
[dotnet/dotnet repository](https://github.com/dotnet/dotnet/tree/95017c711e6afc1085133d440e42b4bd78155701).
The repository's [MIT license](https://raw.githubusercontent.com/dotnet/dotnet/95017c711e6afc1085133d440e42b4bd78155701/LICENSE.TXT)
matches the retained runtime license. Linux x64/ARM64 runtime license and notice
files were compared and have identical hashes within each component family.

SQLitePCLRaw's package metadata declares Copyright 2014-2024 SourceGear, LLC.
Its retained Apache-2.0 text comes from the upstream
[v2.1.12 license file](https://raw.githubusercontent.com/ericsink/SQLitePCL.raw/v2.1.12/LICENSE.TXT).
No standalone upstream `NOTICE` file was found at that release root; this is not
a claim that all upstream attribution review is complete. Preserve the package
metadata and license along with any future additional upstream notices.

The bundled native SQLite library reports version `3.53.3` in the currently
resolved Linux x64 binary's version strings, with source ID
`2026-06-26 20:14:12 d4c0e51e4aeb96955b99185ab9cde75c339e2c29c3f3f12428d364a10d782c62`.
SQLite's own [copyright statement](https://www.sqlite.org/copyright.html) describes
its deliverable library as dedicated to the public domain. That statement does
not replace the SQLitePCLRaw package's Apache-2.0 notice. Formal provenance review
must still confirm the exact bundled native build, not infer it from package name.

## File verification

| Retained file | SHA-256 |
| --- | --- |
| .NET MIT license | `cfc21f5e8bd655ae997eec916138b707b1d290b83272c02a95c9f821b8c87310` |
| Runtime third-party notices | `66f1d4e44973185519bb4aa8a9718eb22fc7af2cc532e3ae9cfc4c127ee7fc54` |
| ASP.NET Core third-party notices | `52af3d603b6d069e635f8afd08ec44ec01559255b5f3afd161ae9e6fe7e7aa54` |
| SQLitePCLRaw Apache-2.0 license | `cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30` |

## Remaining release review

- This is a component inventory, not a completed SPDX/CycloneDX SBOM or legal
  approval. Reconcile it against the final native archive and OCI image digests.
- The SDK, unit-test tools and their dependencies are build-time only and are not
  copied into native binary packages. Source redistribution needs its own review.
- Container operating-system packages, their `/usr/share/doc` material, base image
  provenance and exact package versions need a per-image inventory. They are not
  covered merely by the managed dependency list here.
- Verify the SQLite native build/source correspondence and any additional notices
  before formal redistribution. Do not download alternative binaries to silently
  replace a locked component.
- Package and image release gates must confirm this directory is included. Updating
  SDK/runtime/NuGet versions requires refreshing notices, metadata and hashes.
