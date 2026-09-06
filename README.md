# safeclone

safeclone is a **Windows tool that runs on your PC** to prepare a folder you plan
to share with an AI service. It leaves the original unchanged, makes a separate
copy with some detected sensitive information removed or replaced, and can also
let an AI edit a separate copy before you review and bring approved changes back.

## Get started

**Windows 11 25H2 Home or Pro · 64-bit Windows (x64)**

[**Download safeclone v0.1.0 for Windows →**](https://github.com/matgusa/safeclone/releases/download/v0.1.0/safeclone-0.1.0-windows-x64-public.zip)

There is no installer: this is a portable ZIP. Download it, extract it, and run
`safeclone.exe`.
Use this sequence: **Download → Extract → Run**. Run safeclone normally; do not
run it as Administrator. The executable is unsigned and requires an existing
x64 Microsoft Visual C++ v14 runtime; safeclone does not bundle or install that
prerequisite.

Use a local NTFS drive. Network drives, cloud-synced folders and other
filesystems are not supported.

1. Download the ZIP.
2. Extract it to a trusted local folder.
3. Open PowerShell in that folder and run:

```powershell
.\safeclone.exe --version
.\safeclone.exe status
```

`status` shows what the program can do and its important limits.

### Create a cleaned copy (the `clone` command)

Use `inspect` to see what safeclone can find, then use `clone` to make a separate
copy for AI editing:

```powershell
.\safeclone.exe inspect 'C:\path\to\original'
.\safeclone.exe clone 'C:\path\to\original' 'C:\path\to\cleaned-copy'
```

The original must exist. The destination must not exist yet, and its parent
folder must already exist. `inspect` only reads the source. The `clone` command
checks supported text and names, removes or replaces information it knows how to
detect, leaves unsupported or high-risk entries out, and verifies the copy
before publishing it. This is irreversible: it does not create a way to restore
removed or replaced values. Inspect the result before deciding what to share.

## Important limits

Version **0.1.0** is an **experimental prerelease MVP**, not production-ready.
safeclone only checks for the kinds of information it knows how to detect.
Secrets and other sensitive information can be missed and may remain. A
successful `PASS` means only that the current checks completed; it does not prove
that a folder is safe to disclose or that edited code is safe to execute.

Use Windows 11 **25H2 Home or Pro** on a **64-bit Windows (x64)** PC and a
local NTFS drive. Other Windows releases or editions, ARM64/32-bit or emulation
substitutes, Linux, macOS, WSL filesystem operation, network drives,
cloud-synced folders, virtual/remote storage and other filesystems are outside
the initial support scope. Run safeclone normally; do not run it as
Administrator. safeclone does not require elevation. No network access or
telemetry is implemented by safeclone.

## Let an AI edit a separate copy

In the advanced edit-and-return workflow, safeclone lets an AI edit a separate
copy, helps you review and approve eligible changes, and brings approved changes
back into a separate set of reconstructed files. Those reconstructed files may
contain the original sensitive information again. Private session data is
encrypted using Windows and tied to your Windows user account. Only the
separate AI copy is intended for external editing; keep the original, private
session data and reconstructed files confidential. See the [security model](docs/security-model.md)
before using this workflow.

## Build from source

For developers who want to build safeclone themselves, use the Rust MSVC
toolchain and Microsoft C++ build tools described in [building and testing](docs/build.md):

```powershell
cargo build --release --locked
.\target\release\safeclone.exe --help
.\target\release\safeclone.exe status
```

## Read next

- [Command reference and lifecycle](docs/usage.md): step-by-step commands,
  advanced editing, approvals, output handling and failure states.
- [Support and exclusions](docs/support.md): supported Windows versions, drives,
  runtime prerequisite and testing limits.
- [Security model](docs/security-model.md): what safeclone checks, protects and
  cannot guarantee.
- [Architecture](docs/architecture.md): how the main parts fit together.
- [Build and verification](docs/build.md): Cargo checks and exact reproduction.
- [Release notes for v0.1.0](https://github.com/matgusa/safeclone/releases/tag/v0.1.0).
- [Security reporting](SECURITY.md): verified GitHub Private Vulnerability
  Reporting and the current reporting link.

safeclone is licensed under [Apache-2.0](LICENSE). [Third-party provenance and
licenses](THIRD_PARTY.md) identify the dependencies and adapted code.
