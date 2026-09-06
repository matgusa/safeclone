# safeclone

safeclone is a local Rust CLI and library for preparing an untrusted workspace
for external AI editing while keeping the original unchanged. It offers two
separate workflows:

- **One-way clone:** transform supported text and names, omit unsupported or
  high-risk files, independently verify the result, and publish an irreversible
  sanitized directory. No restoration mapping is created.
- **Round-trip session:** create a typed-token AI workspace, review edits against
  the unchanged original, approve eligible changes, and reconstruct a separate
  sensitive candidate using private encrypted session state.

Version **0.1.0** is an experimental MVP. Detection is incomplete: undetected
secrets, ordinary names and other sensitive information can remain. Successful
verification is relative to the compiled policy; it does not prove that a
workspace is safe to disclose or that edited code is safe to execute.

## Support

Windows 11 **25H2 Home or Pro**, **native x64**, an **ordinary user**, and
**qualifying fixed/local NTFS**. The executable uses an existing x64 Microsoft
Visual C++ v14 runtime. See [support and exclusions](docs/support.md), including
the limits of the environment testing. No network access or telemetry is
implemented by safeclone.

## Build and try

Use the Rust MSVC toolchain and Microsoft C++ build tools described in
[building and testing](docs/build.md). From a clean source checkout:

```powershell
cargo build --release --locked
.\target\release\safeclone.exe --help
.\target\release\safeclone.exe status
.\target\release\safeclone.exe inspect 'C:\safeclone-example\original'
.\target\release\safeclone.exe clone 'C:\safeclone-example\original' 'C:\safeclone-example\one-way'
```

Choose your own separate local paths. The original must exist; a new output
must be absent and its parent must exist. Keep every participating location
outside Git metadata and remote or sync-provider locations. Do not execute
the untrusted project to inspect it.

For round-trip work, the lifecycle is **create → edit the AI workspace → review
→ approve eligible events → apply → close**. Only the AI workspace is intended
for external editing. Keep the original unchanged and private state confidential.
The candidate contains reconstructed plaintext and is sensitive.

## Read next

- [Command reference and lifecycle](docs/usage.md): examples, profiles, approvals,
  confidential output, exit codes and disposal.
- [Security model](docs/security-model.md): trust boundaries, DPAPI, reconstruction
  guarantees and residual risks.
- [Architecture](docs/architecture.md): source map and authority flow.
- [Build and verification](docs/build.md): Cargo checks and exact reproduction.
- [Security reporting](SECURITY.md): planned private reporting and current availability.

safeclone is licensed under [Apache-2.0](LICENSE). [Third-party provenance and
licenses](THIRD_PARTY.md) identify the dependencies and adapted code.
