# Security model

safeclone treats workspace contents, names and concurrent changes as hostile.
It keeps the original read-only, applies a finite compiled policy and rejects
unsupported or ambiguous authority. Successful verification is evidence under
that policy. It is not complete secret detection, permission to disclose data,
or proof that edited code is safe.

## Trust zones and disclosure

| Location | Role and confidentiality |
| --- | --- |
| Original | Hostile to traversal, authoritative for re-deriving original values; never modified |
| One-way clone | Irreversible policy-relative output; no restoration mapping; undetected information may remain |
| AI workspace | Untrusted editable tokenized input; only this session location is intended for external AI |
| Private state | Confidential CurrentUser-DPAPI-protected, application-authenticated session authority and reports |
| Sensitive candidate | Reconstructed original plaintext and preserved original-only files; never an AI-safe output |

Safeclone does not execute project code, upload data, contact services or collect
telemetry. The OS, filesystem filters, indexing, backup/sync software and other
processes can still observe local files or generate network traffic. Keep all
sensitive locations outside remote and sync providers.

The adversary may supply malformed trees, token strings and edits; race names
and files; introduce links or aliases; and interrupt ordinary processes. The
guarantees do not cover same-user malware that can decrypt DPAPI or read memory,
process injection, administrator/kernel compromise, complete valid historical
state rollback, account recovery, forensic recovery, cloud copies or physical
attacks. Physical file IDs are point-in-time filesystem facts, not a hardware
root of trust.

## Detection and one-way invariants

The compiled detectors cover bounded secret patterns and conservative email,
international phone, IP, Japanese postal, My Number, corporate number and domestic
phone shapes. Numbering-plan shape or check-digit agreement does not prove
allocation, identity, ownership, reachability or legal/PII status. False positives
and false negatives are expected. Classification by extension is also incomplete.

One-way reports retain aggregate counts, not raw source/output paths, matched
values, source-derived IDs, raw context, path manifests or restoration authority.
Transforms replace covered spans with fixed irreversible markers before writing.
There is no raw-copy fast path for zero findings. Nevertheless, undetected content
and ordinary names may remain unchanged. High-risk, unsupported and untransformable
files are omitted; name collisions, races and unresolved states fail closed.
Actual output is independently verified again before no-clobber promotion.

All filesystem commands enforce the [supported boundary](support.md). Retained
handles, no-follow traversal, positive local-volume membership and identity
rechecks prevent an observed entry from silently becoming an ambient-path reopen.
Git metadata is excluded. Hardlinks, streams, reparse points and ambiguous
namespace states do not authorize content access or sensitive writes.

## Tokens and private state

The suite identifier `SAFECLONE-RT1-HS256-DPAPI-CU` and token form
`__SAFECLONE_RT1_<CAT>_<SID>_<OID>_<AUTH>__` are actual compatibility identifiers.
Their spelling is significant. Encodings use canonical unpadded uppercase Base32;
an apparently valid token grants no authority until session, occurrence, category
and authentication checks pass.

The suite uses Windows `BCryptGenRandom`, HKDF-SHA-256, HMAC-SHA-256, constant-time
authentication checks and CurrentUser `CryptProtectData`/`CryptUnprotectData`.
Distinct `safeclone/rt1/...` HKDF labels separate key purposes. Additional exact
`safeclone/rt2/...`, `safeclone/rt3/...` and `safeclone/rt6/...` domain strings bind
different authenticated messages. These are protocol bytes, not release status.
Unkeyed hashes of raw source values cannot serve as token or private identity.

Current compatibility is `safeclone-roundtrip-engine-v3`, policy `roundtrip-v3`,
token suite 1, CapsuleV1 schema 1 and ChangedManifestV1 schema 1. Profile values
3 and 4 represent StandardV2 and StrictTokenFilesV2; values 1 and 2 are reserved
and not reinterpreted. The ruleset ID hashes only the public compiled rule
descriptor. See [token definitions](../src/roundtrip/token.rs),
[cryptographic domains](../src/roundtrip/crypto.rs) and
[schema registries](../src/roundtrip/schema.rs) for the exact executable contract.
Cross-version session migration is not provided.

Private artifacts use bounded deterministic CBOR: definite lengths, shortest
integers and strictly ordered numeric keys. Decoders reject malformed, oversized,
noncanonical or unsupported input. DPAPI envelopes also have application
authentication binding the role, suite, schema, session and generation.

The private persistence exception permits protected original relative paths,
authenticated approvals and keyed commitments. It never permits raw original
values/content, token-to-value mappings, absolute source/output paths, raw
changed values, raw short-alias mappings or raw anchor context. Private manifests
are never plaintext files and never belong in the AI workspace. Unknown-token
reports cannot adopt an observed unknown OID as a trusted token identity; reporting
projection preserves the distinction between null identity and known authority.

Sensitive byte buffers are bounded and use secret-memory wrappers where defined.
This is not proof that compilers, OS libraries, crash dumps, swap or the terminal
retain no copies. CurrentUser DPAPI does not supply same-user isolation or make
copied state portable. Keep the same user/machine profile and unchanged Original;
their loss can make reconstruction unavailable.

## Reconstruction

Reconstruction proves that a restored occurrence comes from the unchanged
Original and is placed at an authenticated, policy-permitted edited boundary.
It does not assess the meaning or safety of the surrounding code.

StandardV2 uses exact relative context. It normalizes token atoms in a protected
run, selects the first unique baseline envelope from radii 1 through 16 logical
lines per side, and binds that selection. Logical lines retain their exact
newline bytes; BOF/EOF are explicit. Ambiguity at the bound rejects creation.
Edited input cannot reselect the radius or use nearest position, fuzzy matching,
diff alignment or an OID to resolve ambiguity.

A surviving run must preserve its protected core, token identity/category/order,
the selected unique envelope, logical file and safe-path correspondence, and
stable observed physical identity. Absolute line shifts can be accepted when the
whole envelope remains intact and protected-run order is preserved. Cross-file
token movement, protected block swaps, changed context and ambiguous repeats
fail closed. Path anchors separately bind component skeleton, lineage, kind and
suffix; relative content anchors do not relax path policy.

Permitted token deletion projects only the exact token bytes out of the protected
core and requires its own approval. Removing neighboring syntax, spaces or the
whole line is not equivalent. StrictTokenFilesV2 adds explicit approval for a
token-bearing file edit and never permits unknown tokens or broken identity.

Observation/event authority is transient and complete. A changed manifest is a
report, not an input to approval or reconstruction authority. Every mutation
freshly checks Original, edited workspace, review identity and the authenticated
complete approval set. Stale or forged approval, duplicate/unknown/malformed
tokens, resource exhaustion and unsupported edits cannot be overridden by a
reason code. Original-only preservation has a separate retained-capability,
byte-verification contract and never changes one-way clone behavior.

## Completion, interruption and remaining risks

Candidate writes require the exact retained root and authenticated apply state.
Keyed physical and logical commitments, markers and independent actual-tree
checks establish completion. A COMPLETE filename alone is insufficient.
Authenticated exact replay can succeed; incomplete output is never resumed or
repaired. The private store uses immutable generations, bounded locking and
authenticated readback. It cannot prevent rollback by an attacker able to
replace the entire store with valid historical state.

Write-through, pre/post rename flushes and atomic rename do not establish a
physical power-loss guarantee. Device/controller faults and storage caches remain
outside the bounded process-interruption claim. Exit `3` requires manual
inspection, not automatic retry. Close is logical retirement and **not secure
erase**; pending files, encrypted keys and sensitive workspaces can remain.

Read [confidential-output and disposal instructions](usage.md) before using the
private path view or handling a candidate. Reporting-channel status is in
[SECURITY.md](../SECURITY.md).
