# Third-party code and licenses

safeclone's own source is [Apache-2.0](LICENSE). Preserve the applicable upstream
license/copyright notices and modification attributions when copying or
redistributing the material below. The license files retain exact upstream
bytes; author names and public upstream source references are attribution.

## Dependency inventory

[third_party/dependencies.json](third_party/dependencies.json) records all **59**
locked registry packages, including target-specific packages not used on Windows.
Its `packages` list describes the **39** Windows x64 normal/build packages with
exact checksums, resolved features, edges, upstream sources and selected licenses.
Cargo acquires these dependencies; their source trees are not vendored here.

The eight `components` entries cover the precompiled Rust standard-library
bundle, its selected incorporated components, and three local ports. They are
not extra Cargo dependencies. The retained **62** license/notice files also
include rustix's MIT/COPYRIGHT for non-Windows source paths. An unused platform
edge does not grant runtime support for that platform.

Selected materials include MIT, Apache-2.0, Unicode, compiler-builtins' LLVM
exception and supplemental copyright/permission notices. Microsoft C++ runtime,
SDK and toolchain binaries/installers are not redistributed here. Run
`python scripts/check-licenses.py` to verify the exact retained file set, hashes
and lockfile mapping. This is an integrity check, not a vulnerability scan.

## Gitleaks rule adaptations

[Gitleaks](https://github.com/gitleaks/gitleaks) is MIT-licensed, copyright 2019
Zachary Rice. The unchanged [MIT license](third_party/licenses/gitleaks-MIT.txt)
applies to the adaptations in [src/secrets.rs](src/secrets.rs).

- Commit `83d9cd684c87d95d656c1458ef04895a7f1cbd8e`: private-key material from
  `config/gitleaks.toml`, plus `cmd/generate/config/rules/github.go` and
  `cmd/generate/config/rules/generic.go`, including the classic GitHub PAT shape.
- Commit `b58d3f102cf3a2c84cb7f923d05c25c9b1aed84b`:
  [cmd/generate/config/rules/github.go](https://github.com/gitleaks/gitleaks/blob/b58d3f102cf3a2c84cb7f923d05c25c9b1aed84b/cmd/generate/config/rules/github.go),
  specifically `GitHubFineGrainedPat`, `GitHubOauth`, `GitHubApp` and `GitHubRefresh`.

Modifications translate Go rule metadata to bounded Rust matching, use explicit
ASCII classes, apply entropy and boundary checks, and retain raw-free byte-span
evidence. App-token `ghu_` and `ghs_` forms share one logical budget. Gitleaks
scanner, allowlists, Git integration and reporting are not copied. Tests use
synthetic local fixtures. No NOTICE was present at the selected revisions.

## Context Armor filename rules

[Context Armor](https://github.com/feelyday/context-armor), commit
`e31f60715c102cf92d3efbef304202da1284d5fe`, is Apache-2.0, copyright 2026 Context
Armor contributors. The unchanged [license](third_party/licenses/context-armor-Apache-2.0.txt)
and modification notice in [src/filename.rs](src/filename.rs) are retained.

The port maps `src/rules.js::filenameRules`, lines 163–192, source blob
`97425c57f62240f6352555c405880f5dff5c6b9d`, to `FILE_ENV`, `FILE_PRIVATE_KEY`,
`FILE_CREDENTIALS` and `FILE_AUTH_CONFIG`. License source blob:
`059c376ed0bfda8bd607e06daaefbc0c16a996e4`. No upstream NOTICE was present.

Modifications replace full-relative-path JavaScript matching with bounded
transient-basename Rust predicates; narrow the service-account spelling set;
remove severity, replacement, override and reporting behavior; deduplicate
evidence; and add checked file/run bounds. Non-Unicode basenames are uninspectable
rather than lossily converted. No upstream tests, database-dump rules, document
extractors, scanner or transformation code are copied.

## Exact reporting diff from similar

The narrow Myers core from `similar` **3.1.2**, VCS revision
`71f0a30e449f857aec934b839cc4c9ca5b21eb26`, is adapted in
[src/roundtrip/report_diff.rs](src/roundtrip/report_diff.rs). Archive SHA-256:
`85EE016AF5D736B69FC89E19254540FA4B5F5492853FB5503920F084011C78B6`.
There is no `similar` Cargo dependency.

The package lists Armin Ronacher, Pierre-Étienne Meunier and Brandon Williams
as authors. The [upstream module](https://github.com/mitsuhiko/similar/blob/71f0a30e449f857aec934b839cc4c9ca5b21eb26/src/algorithms/myers.rs)
credits Eugene W. Myers for the algorithm and bases its implementation on
Brandon Williams' implementation. These source attributions are retained in
the local module header.

Primary source `src/algorithms/myers.rs` has SHA-256
`0C10102279AD0946946DB9BD116A5BC0BD28C50C3C5BDF1ADCCED2F96B713177`.
Adapted portions are the `V` frontier, `max_d`, `find_middle_snake`, `conquer`
structure and the `ABCABBA`/`CBABAC` parity fixture with split `(4, 1)`.
Operation-emission semantics also consulted `src/algorithms/capture.rs`,
`src/algorithms/hook.rs` and `src/types.rs` from that same exact package.

Modifications use an explicit bounded work stack, checked work/memory/line/region
limits, byte-exact borrowed logical lines, explicit deadline errors and independent
replay validation. No heuristic, approximate result or timeout fallback is
accepted. The parity fixture uses LF-terminated lines; other fixtures and the
independent LCS oracle are local. This port supplies reporting regions only,
not placement, approval or reconstruction authority.

The unchanged [Apache-2.0 license](third_party/licenses/similar-Apache-2.0.txt)
has SHA-256 `A60EEA817514531668D7E00765731449FE14D059D3249E0BC93B36DE45F759F2`.
No NOTICE was present in that archive. The source retains its modification
notice. Public upstream hashes establish provenance, not private safeclone history.
