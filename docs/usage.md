# Using safeclone 0.1.0

Run `safeclone --version` to display `safeclone 0.1.0`. Run `safeclone --help`
for the exact command syntax. Product `status` reports capabilities and safety
limits; it is distinct from the authenticated state of an individual session.

```text
safeclone status
safeclone inspect <SOURCE_DIRECTORY>
safeclone clone <SOURCE_DIRECTORY> <OUTPUT_DIRECTORY>
safeclone session create <ORIGINAL> <AI_WORKSPACE> --state <PRIVATE_SESSION_DIRECTORY> [--profile standard-v2|strict-token-files-v2]
safeclone session status --state <PRIVATE_SESSION_DIRECTORY>
safeclone session review <ORIGINAL> <AI_WORKSPACE> --state <PRIVATE_SESSION_DIRECTORY> [--show-private-paths]
safeclone session approve <ORIGINAL> <AI_WORKSPACE> --state <PRIVATE_SESSION_DIRECTORY> --review-id <REVIEW_ID> --event-id <EVENT_ID> --reason-code <REASON_CODE>
safeclone session apply <ORIGINAL> <AI_WORKSPACE> <SENSITIVE_CANDIDATE> --state <PRIVATE_SESSION_DIRECTORY>
safeclone session close --state <PRIVATE_SESSION_DIRECTORY> [--acknowledge-incomplete <APPLY_ID>]
```

## Locations and one-way output

Use [supported local locations](support.md) under your control. Original, AI,
private-state, one-way output and candidate roots must be separate and
non-overlapping. New output roots must be absent, with existing parents. Paths
inside `.git` are rejected; a child `.git` within an ordinary workspace is omitted.
An existing output is never overwritten. Source code is never executed.

`inspect` inventories structure and reports aggregate evidence; it creates no
sanitized workspace. `clone` applies the compiled policy to text and names before
writing staging, omits unsupported/high-risk entries, verifies the actual tree,
then promotes it with a no-clobber rename. Detection includes bounded secret
patterns, conservative sensitive-identifier shapes, sensitive filenames and
path-component evidence. Extension classification and zero findings do not
prove safety. Inspect the result before deciding what to share.

## Session workflow

The following example uses paths you must replace with your own locations:

```powershell
safeclone session create 'C:\safeclone-example\original' 'C:\safeclone-example\ai' --state 'C:\safeclone-example\private'
safeclone session status --state 'C:\safeclone-example\private'
# Edit only the AI workspace, then review those edits.
safeclone session review 'C:\safeclone-example\original' 'C:\safeclone-example\ai' --state 'C:\safeclone-example\private'
safeclone session apply 'C:\safeclone-example\original' 'C:\safeclone-example\ai' 'C:\safeclone-example\candidate' --state 'C:\safeclone-example\private'
safeclone session close --state 'C:\safeclone-example\private'
```

Apply without approvals works only when the current review permits it. The
default immutable profile is `standard-v2` (StandardV2). It protects exact token
cores and unique relative context; ordinary edits outside the protected context
can remain eligible. Moving tokens between files, changing protected context or
using ambiguous repeated blocks is rejected. Token-bearing path movement is
also constrained. See [placement rules](security-model.md#reconstruction).

The alternative `--profile strict-token-files-v2` (StrictTokenFilesV2) requires
explicit review of a token-bearing file edit. It still requires correct token
identity, multiplicity, file correspondence and all other safety checks. Strict
approval cannot override an unknown token or unsupported edit. A session cannot
switch profiles or migrate to a different engine version.

`review` produces opaque review and event IDs. One `approve` command accepts one
eligible event from the current authenticated review, with one of:

| Reason code | Eligible intent |
| --- | --- |
| `INTENTIONAL_TOKEN_REMOVAL` | Exact permitted token deletion |
| `INTENTIONAL_FILE_DELETE` | Permitted file deletion |
| `STRICT_TOKEN_FILE_EDIT_REVIEWED` | Strict profile token-bearing file edit |

Pass the exact canonical `--review-id`, `--event-id` and `--reason-code` to
`session approve`. Changed inputs invalidate previous review/approval authority.
Apply re-observes the inputs and verifies the complete approval set. Approval
does not assess code semantics, authorize disclosure, or approve deployment.

Apply creates a new sensitive candidate, including permitted reconstruction and
byte-exact original-only files. It does not modify Original or build/test the
edited project. The warning is:

```text
warning=sensitive candidate contains reconstructed plaintext; semantic safety was not assessed
```

An authenticated `APPLIED_COMPLETE` result and verified exact replay establish
completion; a file named COMPLETE alone does not. Incomplete candidates are
never resumed or repaired. Status is the authenticated read-only state view.

## Confidential output

Normal output contains aggregates and opaque identifiers, not private paths or
matched values. Review's optional `--show-private-paths` is a confidential view
of accepted relative-path fields. It first writes and flushes this stderr warning:

```text
warning=confidential review output; do not send to AI or persist in public logs
```

Names can be sensitive. Shell history, terminal capture, screenshots and
redirection can retain them. safeclone writes UTF-8 bytes to redirected output;
downstream tools may transcode them. Never send Original, private state,
confidential review output or a sensitive candidate to external AI or public logs.

## Failure, retirement and disposal

| Exit | Meaning and action |
| --- | --- |
| `0` | Requested work succeeded or exact authenticated replay was verified |
| `2` | Definite failure; inspect the bounded diagnostic |
| `3` | Manual or indeterminate artifact state; stop automatic retries and inspect the known locations |

A one-way failure after staging creation retains `.safeclone-staging-v1` for
manual inspection. Incomplete create/apply, private orphans and uncertain
commits can retain sensitive data. Do not edit private artifacts, rename pending
files into authority, or infer completion from filenames.

`session close` appends authenticated logical retirement. For `APPLY_ARMED` or
`APPLY_INCOMPLETE`, supply the exact current opaque apply ID with
`--acknowledge-incomplete`. This accepts responsibility for retained sensitive
artifacts; it grants no cleanup or resume authority.

Close deletes no workspace, candidate, private generation, manifest or orphan.
It is **not secure erase**. Retained encrypted material and keys may remain.
After reviewing status and retention needs, use ordinary file management for
the exact locations you selected. Deletion cannot erase backups, snapshots,
cloud copies, SSD remapping or memory.

There is no installer or global installation identity. Removing a stopped
portable executable's directory leaves session/workspace data intact. Use the
explicit executable you intended. No updater, cross-version session migration,
or state rollback workflow is supplied.
