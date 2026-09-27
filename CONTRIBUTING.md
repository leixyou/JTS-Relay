# Contributing

JTS Relay owns authenticated rendezvous and opaque byte forwarding. Keep Mac and
Windows application code in their endpoint repositories. Protocol changes need
versioned specifications, public fixtures and endpoint compatibility review.

Install the .NET SDK pinned in `global.json` and Python 3, then run:

```sh
bash scripts/verify.sh
```

`JTS_DOTNET=/path/to/dotnet` selects a specific SDK executable. Restore remains
locked to the checked-in NuGet lock files. Tests generate disposable local
identities and data; never include real keys, admission configurations, node
addresses, command output or user files in a patch or test artifact.

Keep changes focused and add meaningful tests for changed authentication,
forwarding, resource bounds or persistence behavior. Describe what changed and
which checks passed in the pull request. Preserve existing third-party notices.
See `LICENSE` for source license terms and `SECURITY.md` for security reports.

Packaging and deployment are separate from source verification. Do not claim
Linux runtime, real Windows, end-to-end TLS, unattended service or RDP acceptance
from unit tests. The release checks are listed in `docs/RELEASE_GATES.md`.
