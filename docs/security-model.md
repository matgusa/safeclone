# Security model

safeclone leaves the original folder read-only and only removes or replaces
information that its known checks can identify. Treat every file, file name and
change made while it runs as potentially unsafe. It refuses unsupported or
ambiguous situations. Passing verification means the checks completed under the
current rules; it does not mean all secrets were found, data is safe to share or
edited code is safe to run.

## Folders and what they contain

| Location | Meaning and confidentiality |
| --- | --- |
| Original | The folder supplied to safeclone; never modified and used as the source for reconstruction |
| Cleaned copy | An irreversible copy; some detected information is removed or replaced, but missed information may remain |
| AI copy | A separate copy an AI may edit; only this location is intended for external AI editing |
| Private state | Encrypted session data protected by Windows' CurrentUser DPAPI and safeclone authentication |
| Reconstructed files | Files written after approved edits; they may contain the original plaintext again and are not an AI-safe output |

safeclone does not execute project code, upload data, contact services or collect
telemetry. The operating system, filesystem filters, indexing, backup software,
sync software and other local processes can still observe files or generate
network traffic. Keep sensitive folders off network drives and cloud-synced
locations.

A folder may be malformed or change while it is being read. It may contain
links, aliases, strange names or edits designed to confuse the process. The
guarantees do not cover malware running as the same Windows user, an
administrator or kernel-level attacker, complete rollback to valid historical
state, account recovery, forensic recovery, cloud copies or physical attacks.
Physical file IDs are point-in-time filesystem facts, not a hardware root of
trust.

## What safeclone checks and what it cannot promise

safeclone checks a bounded set of secret patterns and conservative forms of
email, international phone, IP, Japanese postal, My Number, corporate number and
domestic phone data. A matching number shape or check digit does not prove that
the number is assigned, belongs to someone or is reachable. False positives and
false negatives are expected, and file-extension classification is incomplete.

Reports contain totals, not original paths, matched values, raw context, path
lists or a way to restore the original. Detected portions are replaced with
fixed irreversible markers before writing. Even when no match is found, readable
text is processed; safeclone does not simply copy it unchanged because the check
found nothing. Missed information and ordinary names may still remain. High-risk,
unsupported or untransformable files are left out; collisions, races and
uncertain states fail closed. The output is checked again before it can replace
an absent destination.

All filesystem commands enforce the [supported boundary](support.md). Internally,
safeclone keeps an already-open reference to each accepted folder, does not
follow link-like entries, confirms the drive is local and checks identity again.
This prevents an observed entry from being reopened through a different path.
Git metadata is excluded. Hardlinks, streams, reparse points and ambiguous names
do not authorize content access or sensitive writes.

## Technical details for private session data

Most users do not need the token format. This section records the exact
compatibility details for auditing and for the advanced edit-and-return
workflow. Private session data is encrypted with Windows' CurrentUser DPAPI
(protection tied to the current Windows account) and then authenticated by
safeclone.

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

## Bringing approved edits back

Reconstruction writes approved edits into separate files. It proves that each
restored value came from the unchanged Original and is placed at an approved
edited location. It does not judge the meaning or safety of surrounding code.

The detailed profiles below describe how those checks work. The standard-v2
profile uses exact relative context. It normalizes token atoms in a protected
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
inspection, not automatic retry. Close is logical retirement and **not secure erase**;
pending files, encrypted keys and sensitive workspaces can remain.

Read [confidential-output and disposal instructions](usage.md) before using the
private path view or handling a candidate. Reporting-channel status is in
[SECURITY.md](../SECURITY.md).
