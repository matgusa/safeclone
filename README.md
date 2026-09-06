# safeclone

safeclone is a local-only **Windows CLI and library** for preparing an untrusted
workspace for external AI editing while keeping the original unchanged. It
provides an irreversible one-way clone workflow and a separate round-trip
session workflow with private encrypted state.

## Get started

**Windows 11 25H2 Home or Pro · native x64 · ordinary user · qualifying
fixed/local NTFS**

[**Download safeclone v0.1.0 for Windows →**](https://github.com/matgusa/safeclone/releases/download/v0.1.0/safeclone-0.1.0-windows-x64-public.zip)

The download is a **portable ZIP, not an installer**. Use this sequence:
**Download → Extract → Run**. Extract it to a trusted local folder and run
`safeclone.exe` there. The executable is unsigned and requires an existing x64
Microsoft Visual C++ v14 runtime; safeclone does not bundle or install that
prerequisite.

1. Download the ZIP.
2. Extract it to a trusted local folder outside untrusted workspaces and
   remote or sync-provider locations.
3. Open PowerShell in that folder and run:

```powershell
.\safeclone.exe --version
.\safeclone.exe status
```

`status` reports product capabilities and safety limits.

### Create a one-way clone

Inspect the original first, then create a separate sanitized output:

```powershell
.\safeclone.exe inspect 'C:\path\to\original'
.\safeclone.exe clone 'C:\path\to\original' 'C:\path\to\sanitized'
```

The original must exist, the output must be absent, and the output parent must
exist. `inspect` is read-only. The clone transforms supported text and names,
omits unsupported or high-risk files, independently verifies the result, and
publishes an irreversible sanitized directory; it creates no restoration
mapping. Inspect the result before deciding what to share.

## Important limits

Version **0.1.0** is an **experimental prerelease MVP**, not production-ready.
Detection is incomplete: undetected secrets, ordinary names and other
sensitive information can remain. Verification is relative to the compiled
policy; a successful `PASS` does not prove that a workspace is safe to disclose
or that edited code is safe to execute.

The supported boundary is **Windows 11 25H2 Home or Pro**, **native x64**,
**ordinary-user execution**, and **qualifying fixed/local NTFS**. Other Windows
releases or editions, ARM64/32-bit or emulation substitutes, Linux, macOS,
WSL filesystem operation, non-NTFS, network and provider-backed locations are
outside the initial support scope. safeclone does not require elevation. No
network access or telemetry is implemented by safeclone.

For the separate round-trip workflow, safeclone creates a typed-token AI
workspace, reviews and approves eligible edits against the unchanged original,
and reconstructs a separate sensitive candidate using CurrentUser-DPAPI-
protected private session state. Only the AI workspace is intended for external
editing; keep the original and private state confidential. The candidate
contains sensitive plaintext. See the [security model](docs/security-model.md)
before using that workflow.

## Build from source

For source builds, use the Rust MSVC toolchain and Microsoft C++ build tools
described in [building and testing](docs/build.md):

```powershell
cargo build --release --locked
.\target\release\safeclone.exe --help
.\target\release\safeclone.exe status
```

## Read next

- [Command reference and lifecycle](docs/usage.md): examples, profiles,
  approvals, confidential output, exit codes and disposal.
- [Support and exclusions](docs/support.md): exact Windows scope, runtime
  prerequisite and environment-testing limits.
- [Security model](docs/security-model.md): trust boundaries, reconstruction
  guarantees and residual risks.
- [Architecture](docs/architecture.md): source map and authority flow.
- [Build and verification](docs/build.md): Cargo checks and exact reproduction.
- [Release notes for v0.1.0](https://github.com/matgusa/safeclone/releases/tag/v0.1.0).
- [Security reporting](SECURITY.md): verified GitHub Private Vulnerability
  Reporting and the current reporting link.

safeclone is licensed under [Apache-2.0](LICENSE). [Third-party provenance and
licenses](THIRD_PARTY.md) identify the dependencies and adapted code.
