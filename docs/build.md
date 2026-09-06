# Build, test and reproduce

Use a clean source checkout on the [supported Windows environment](support.md).
The executable is Rust with native Windows bindings; there is no JavaScript,
Python package or downloaded build script in the runtime dependency graph.
Cargo.toml and Cargo.lock fix the dependencies. No private repository, Git
history, release-service account or public Git identity is needed to build.

## Normal validation

Install the Rust **1.97.1 x86_64-pc-windows-msvc** toolchain with rustfmt and
clippy, Microsoft C++ x64 build tools, and the Windows SDK. The reference build
uses MSVC **14.50.35717**, Windows SDK **10.0.26100.0** and the precompiled Rust
standard library; it does not rebuild std. Use a developer PowerShell configured
for the C++ tools. The executable also needs the runtime described in
[support.md](support.md#runtime-prerequisite-and-portable-use).

```powershell
cargo fetch --locked
cargo fmt --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --all-targets --locked
cargo build --release --locked
cargo tree --locked --target x86_64-pc-windows-msvc --edges normal,build,features
cargo metadata --locked --format-version 1 --filter-platform x86_64-pc-windows-msvc
```

Run filesystem tests as an ordinary user on qualifying local NTFS with a suitable
temporary directory. They use isolated synthetic fixtures and retained native
handles. A restrictive process sandbox can reject the required handle operations;
running the unchanged tests normally is appropriate, elevating them or weakening
the product checks is not. Opt-in native probes remain ignored in normal Cargo
tests; inspect their preconditions before explicitly running one.

The tests exercise actual CLI output, one-way and session lifecycles, hostile
trees, stale and malformed authority, exact replay, cryptographic golden vectors,
failure checkpoints and independent reference models. Source-boundary contracts
also guard reporting/authority separation and native API assumptions. Passing
tests does not prove complete detection or security.

After fetching dependencies, append `--offline` to Cargo commands to enforce
cache-only operation. Dependency acquisition is a build prerequisite, not
network behavior of safeclone. Cargo's default `target/` and Python bytecode
caches are ignored and are not publication files.

## Exact executable reproduction

An ordinary release build need not have the same bytes: paths, linker flags and
toolchain inputs matter. The optional standard-library-only Python procedure
uses the frozen [build inputs](../build/reproducibility.json), audited crate
checksums and path remapping. Python **3.12.14** is required by that fingerprint.
It makes two new independent build directories, verifies cached crate archives
and unpacked sources, and checks identical executables and build-script outputs.
It does not use Git metadata or packaging history.

Choose an absent output directory outside this checkout, and substitute the
actual installed tool locations:

```powershell
python scripts/reproduce.py --sysroot (rustc --print sysroot) --msvc '<MSVC toolset directory>' --sdk '<Windows Kits Lib version directory>' --cargo-home $env:CARGO_HOME --out '<new reproduction directory>'
```

`--cargo-home` must name your actual cache directory; set it explicitly if
`CARGO_HOME` is unset. The MSVC directory contains `bin/Hostx64/x64` and `lib/x64`;
the SDK directory contains `um/x64` and `ucrt/x64`. The procedure rejects
unexpected Cargo configuration and mismatched tool/library fingerprints.
It requires a populated cache and runs Cargo with `--locked --offline`.

The v0.1.0 reference executable SHA-256 is:

```text
8b894ce172dfcf9bec97455f6f134b5dc8497c3f0ded1baaa29a7db49f5a3c4c
```

The script verifies this hash after its two-build comparison and writes local
`BUILD.json`, logs and `safeclone.exe` under the selected output directory.
These are local results, not source files. A hash comparison establishes byte
identity against a trusted value, not publisher authentication or a signature.
The source snapshot has no embedded commit/author metadata. Packaging is a
separate operation and this source procedure does not create a release ZIP.

## Third-party checks

Run `python scripts/check-licenses.py` to verify the retained license file set,
its recorded hashes, and the locked dependency inventory. The command needs only
Python 3.12 and this checkout. [THIRD_PARTY.md](../THIRD_PARTY.md) explains the
three code ports and selected license obligations. Native Microsoft prerequisites
are not redistributed in this source tree. License integrity checks are not a
current vulnerability scan; review dependency advisories before a future release
or a dependency/toolchain change.
