# Using safeclone 0.1.0

Run `safeclone --version` to display `safeclone 0.1.0`. Run `safeclone --help`
for the exact command syntax. `status` shows what the program can do and its
important limits.

For the basic workflow, use `inspect` and `clone` to examine a folder and make
a separate copy for AI editing. The `session` commands are the advanced
edit-and-return workflow: they create a separate AI copy, let you review and
approve changes, and write reconstructed files. Session status is a read-only
view of encrypted private session data; it is separate from product status. The
uppercase names in the command list are placeholders; replace them with your
own paths or IDs.

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

## Folders and the cleaned copy

Use [supported local locations](support.md) under your control. Keep the
original folder, AI copy, private session data, cleaned-copy output and
reconstructed files separate; none may contain another. The output folder must
not exist yet, and its parent folder must already exist. Paths inside `.git` are
rejected; a `.git` folder inside a normal project is left out. An existing
output is never overwritten. Source code is never executed.

`inspect` looks through the folder structure and reports totals for information
it recognizes; it creates no output. `clone` checks supported text and names,
removes or replaces detected values, leaves unsupported or high-risk entries
out, verifies the separate copy and publishes it only if those checks pass. It
looks for some secrets and personal identifiers in file contents and names, and
it can miss things. A folder with no findings is not proven safe. Inspect the
result before deciding what to share.

## Let an AI edit a separate copy

Use this advanced workflow when you want an AI to edit a separate copy, review
the changes and bring approved changes back. In technical documentation this
feature is also called a **round-trip session**. The example uses paths you must
replace with your own locations:

```powershell
safeclone session create 'C:\safeclone-example\original' 'C:\safeclone-example\ai-copy' --state 'C:\safeclone-example\private'
safeclone session status --state 'C:\safeclone-example\private'
# Edit only the AI workspace, then review those edits.
safeclone session review 'C:\safeclone-example\original' 'C:\safeclone-example\ai-copy' --state 'C:\safeclone-example\private'
safeclone session apply 'C:\safeclone-example\original' 'C:\safeclone-example\ai-copy' 'C:\safeclone-example\reconstructed' --state 'C:\safeclone-example\private'
safeclone session close --state 'C:\safeclone-example\private'
```

Only edit the AI copy. The original is never changed. The reconstructed files
may contain the original sensitive information again and must not be sent to an
AI service.

safeclone checks each approved change against the original and the current AI
copy so a change is not applied to the wrong file or wrong occurrence. The
default profile is `standard-v2` (`StandardV2`). It protects the exact value and
the surrounding text that identify where an approved change belongs. Moving a
value between files, changing protected surrounding text or creating an
ambiguous match is rejected. File-name changes involving protected values are
also constrained. See [placement rules](security-model.md#bringing-approved-edits-back).

The optional `--profile strict-token-files-v2` (`StrictTokenFilesV2`) profile
requires explicit review of any AI-copy file that contains a protected value.
It still rejects unknown values, wrong files, duplicate values and unsupported
edits. A session cannot switch profiles or migrate to a different engine
version.

`review` prints opaque review and event IDs, not private paths or matched values.
One `approve` command accepts one allowed change from the current review, with
one of:

| Reason code | Eligible intent |
| --- | --- |
| `INTENTIONAL_TOKEN_REMOVAL` | Remove one exact protected value |
| `INTENTIONAL_FILE_DELETE` | Delete an allowed file |
| `STRICT_TOKEN_FILE_EDIT_REVIEWED` | Review a file edit under the strict profile |

Pass the exact IDs and reason code to `session approve`. If the original or AI
copy changes, earlier review/approval information is no longer valid. `apply`
checks the current folders again. Approval does not judge code meaning or safety,
authorize disclosure or approve deployment.

`apply` writes a new set of reconstructed files, including allowed files kept
unchanged from the original. Those files may contain original sensitive
information. It does not modify the original or build/test the edited project.
The warning is:

```text
warning=sensitive candidate contains reconstructed plaintext; semantic safety was not assessed
```

A verified `APPLIED_COMPLETE` result confirms completion; a file named COMPLETE
alone does not. Incomplete reconstructed files are never resumed or repaired.
Session status is the authenticated, read-only view of the private session data.

## Confidential output

Normal output contains totals and opaque identifiers, not private paths or
matched values. Review's optional `--show-private-paths` is a confidential view
of accepted relative-path fields; it first writes and flushes this stderr warning:

```text
warning=confidential review output; do not send to AI or persist in public logs
```

File and folder names can be sensitive. Shell history, terminal capture,
screenshots and redirection can retain them. safeclone writes UTF-8 bytes to
redirected output; downstream tools may transcode them. Never send the original,
private session data, confidential review output or reconstructed files to an
AI service or public logs.

## If a command fails

| Exit | Meaning and action |
| --- | --- |
| `0` | Requested work succeeded or exact authenticated replay was verified |
| `2` | Definite failure; inspect the bounded diagnostic |
| `3` | Manual or indeterminate artifact state; stop automatic retries and inspect the known locations |

If `clone` fails after it has started creating the output,
`.safeclone-staging-v1` may remain for manual inspection. Incomplete
edit-and-return operations, private orphan data and uncertain writes can retain
sensitive data. Do not edit private files, rename pending files into place or
infer completion from a filename.

`session close` records that the session is retired. For `APPLY_ARMED` or
`APPLY_INCOMPLETE`, supply the exact current opaque apply ID with
`--acknowledge-incomplete`. This accepts responsibility for retained sensitive
data; it grants no cleanup or resume authority.

Close deletes no workspace, reconstructed files, private generation, manifest or
orphan. It is **not secure erase**. Retained encrypted material and keys may
remain. After reviewing what you need to keep, use ordinary file management for
the exact locations you selected. Deletion cannot erase backups, snapshots,
cloud copies, SSD remapping or memory.

There is no installer or global installation identity. Removing a stopped
executable's folder leaves session/workspace data intact. Use the explicit
executable you intended. No updater, cross-version session migration or state
rollback workflow is supplied.
