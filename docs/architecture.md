# Architecture

safeclone separates CLI presentation, policy, hostile filesystem observation,
transformation, verification and authority-bearing state. `main.rs` delegates to
`cli.rs`; the CLI parses arguments and formats bounded results. Filesystem and
session policy live in library modules. This source exposes a library for
inspection and testing, without promising a stable cross-version Rust API.

## Source map

| Modules under `src/` | Responsibility |
| --- | --- |
| `locality`, `fs_boundary` | Pre-I/O platform/path checks and retained local filesystem authority |
| `inventory`, `content`, `policy` | Bounded traversal, readable-content classification and disposition |
| `secrets`, `sensitive`, `filename`, `path_evidence`, `detection`, `rule_metadata` | Deterministic, bounded evidence and compiled rule descriptions |
| `transform`, `path_transform` | Pure content-span and path-component transformation |
| `staging`, `staging_tree`, `verification`, `promotion`, `pipeline` | One-way construction, independent verification and exclusive promotion |
| `roundtrip/token`, `tokenize`, `ruleset`, `crypto`, `canonical`, `schema`, `dpapi` | Tokens, compatibility, key separation, bounded encoding and authenticated private envelopes |
| `roundtrip/observe`, `baseline`, `workspace`, `create` | Stable Original observation, tokenized baseline and independently verified AI workspace |
| `roundtrip/edited`, `anchor`, `events`, `classify` | Fresh hostile edited-tree observation, exact relative anchors and transient event authority |
| `roundtrip/review_identity`, `review_ids`, `approval`, `approve` | Opaque IDs and fresh authenticated approval authority |
| `roundtrip/report_diff`, `manifest_projection`, `manifest`, `review` | Reporting-only differences, encrypted changed manifest and review presentation |
| `roundtrip/reconstruct`, `reconstruction_reference`, `candidate_model` | File-local reconstruction, independent retokenization and complete logical candidate model |
| `roundtrip/candidate_identity`, `candidate_marker`, `candidate`, `apply` | Retained-root sensitive writes, physical commitments, independent checks and exact replay |
| `roundtrip/capsule`, `status`, `close` | Immutable private generations, mutation lock, authenticated state and retirement |

## Filesystem boundary

All participating paths pass lexical checks before any selected user path is
opened. Windows drive mappings must positively match OS-enumerated local
volumes. Only an OS-generated volume GUID anchor is opened; validated components
are traversed no-follow from retained handles. Every accepted handle must report
non-remote, exact NTFS and the selected volume identity. There is no ambient
user-path fallback. All path preflights for a transaction precede its opens.

Root and entry identities bind each observation. Traversal is depth-first and
bounded. Source, staging and final/private/candidate roots must not overlap.
Regular-file content proceeds only after a handle-derived link count of one.
Session namespaces bind canonical long components and transient alias evidence;
aliases are not saved as mappings or used as another naming authority.

## One-way flow

`inspect` returns aggregate evidence without constructing an output. `clone`
retains the source capability, creates fixed staging beside an absent output,
and transforms every selected readable text file before writing, including
zero-finding files. Sensitive filename disposition takes precedence over reads.
Path transforms preserve only known text/code suffixes. Sibling collisions abort.

The builder returns an unpublished tree. A separate output-only walk verifies
its actual structure, names, bytes and identity. A verified object is only
point-in-time authority: promotion re-verifies and performs one retained-parent
exclusive rename followed by an exact identity check. Only that committed result
becomes `PublishedClone`. Failures after staging creation leave manual inspection
state on Windows. No automatic deletion or retry is performed.

The public default inventory bounds are depth 64 and 100,000 entries; readable
content is bounded to 4 MiB per file and 64 MiB total. Additional rule, occurrence,
allocation and transformation bounds apply. Unsupported content is not raw-copied.

## Session authority flow

Create binds the unchanged Original, immutable profile, ruleset and tokenized
baseline before publishing an independently verified AI workspace and committing
private authority. Review, approve and apply freshly re-observe the actual inputs
under a mutation lock. Canonical transient events provide classification and
opaque review identity. Persisted reports and diff regions cannot grant authority.

The exact Myers-derived reporting diff has finite work/memory/deadline limits
and no approximate fallback. It supplies human review regions only. Approval
authenticates the complete current event set directly; reconstruction consumes
fresh classification and approval evidence, never report alignment.

Apply first derives a complete expected logical candidate. Independent projected
retokenization and occurrence checks precede sensitive output. Candidate
population requires authenticated incomplete-state authority and a retained
physical root. Original-only entries are streamed from retained read-only
authority with byte checks. Post-checks compare actual structure, reconstruction,
byte placement and keyed commitments before authenticated completion. Candidate
volume/root commitments combine same-handle volume GUID, serial and file ID facts
under `K_tree_commit`; a pathname or marker filename alone cannot substitute.

Private state is an immutable, authenticated generation chain. Pending files
never become authority by filename. Completed replay validates the exact state
and candidate commitments; incomplete output is not resumed. Close appends a
tombstone and does not erase data. See [security model](security-model.md) and
[command behavior](usage.md) for the user-visible consequences.

Tests include product lifecycles, malformed/forged authority, resource bounds,
native filesystem races, generation interruptions, golden protocol vectors and
independent algorithm models. The absolute-position reference model is a
deliberately stricter contrast model; StandardV2 uses the relative-context
implementation in `roundtrip/anchor.rs`.
