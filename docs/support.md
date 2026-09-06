# Supported environment

safeclone 0.1.0 is for **Windows 11 25H2 Home or Pro** on a 64-bit PC and a
local NTFS drive. Run it normally; do not run it as Administrator. Network
drives, cloud-synced folders, virtual or remote storage and other filesystems
are not supported.

For reference, the formal support label is **native x64**, **ordinary-user
execution**, and **qualifying fixed/local NTFS**. Use the applicable supported
Windows security updates. The runtime checks the drive and path; a command being
present or general Windows help text is not a broader support claim. safeclone
does not require elevation and cannot make an unsupported input supported.

## Exclusions

- Windows 11 23H2, 24H2 and 26H1; Pro Education, Pro for Workstations,
  Enterprise, Education, SE, Enterprise multi-session, IoT Enterprise and all
  LTSC channels; every Windows 10 edition/channel, including ESU, LTSC and LTSB.
- ARM64, 32-bit compatibility mode and emulation substitutes; Linux, macOS and
  WSL filesystem operation. Non-Windows filesystem commands reject before
  accessing user paths.
- ReFS, CsvFS, FAT/FAT32, exFAT and other non-NTFS filesystems; network drives,
  mapped drives, remote locations and cloud/virtual storage.
- Folders in case-sensitive mode, reparse points and link-like entries,
  hard-linked files, named streams and unsupported or ambiguous names.
  Unsupported child entries may be left out of a cleaned copy; the advanced
  edit-and-return workflow has stricter whole-tree and preservation rules.

The advanced edit-and-return workflow has additional NTFS folder-name checks.
A long folder name and any Windows short-name alias must point to one physical
entry; an alias cannot bypass a protected name. A changed short-name setting,
duplicate names, ambiguous capitalization or unstable identity fails closed.
Disabling a safety check is not a supported workaround.

## Microsoft runtime prerequisite and using the ZIP

The reference build uses MSVC **14.50.35717** and needs the x64 Microsoft Visual
C++ v14 runtime at least as recent as its build toolset. Windows supplies the
Universal CRT. Tests observed VCRUNTIME140 **14.50.35719.0** and UCRT
**10.0.26100.9278**. These observations are not a claim that every supported
machine already has the prerequisite.

safeclone does not bundle or install Microsoft's runtime. If it is missing, the
machine owner must use Microsoft's supported x64 v14 runtime installation
process; that prerequisite installer may require administrative authority.
See [Microsoft's runtime requirements](https://learn.microsoft.com/en-us/cpp/windows/latest-supported-vc-redist).
For another build, use that build's recorded toolset requirements.

Keep the executable in a trusted local folder, separate from folders you plan to
inspect or share, and protect its parent folders against replacement. Do not add
adjacent DLLs, .local redirection files or external manifests. An executable
checksum does not inspect adjacent files or authenticate its publisher. The
reference executable is unsigned; safeclone provides no installer, automatic
update, PATH change, registry integration or signing service. Windows reputation
and policy warnings depend on delivery and machine policy; local testing does not
establish SmartScreen reputation. Do not disable Windows protections to run an
untrusted copy.

## What was exercised

Lifecycle testing used a Home 25H2 host with Unicode paths and enabled NTFS
short names. Disposable NTFS testing separately covered stable-disabled short
names and rejection of case-sensitive directories. Pro support relies on the
shared Windows API/dependency paths exercised on Home. Locale coverage relies
on native UTF-16 path handling, UTF-8 output and adversarial encoding tests.
Neither a Pro host nor a second-locale Windows host was executed.

The exact reference executable was exercised after fresh extraction on the same
Home host. No separate Windows user, clean machine, fresh Windows installation
or host missing the C++ runtime was executed. These limits matter when assessing
portability; they do not expand the support boundary.

## Profile and persistence limits

Keep the same Windows user account and machine, and keep the original folder
unchanged. Copying private session data to another account or machine is not a
supported recovery method. Losing the original, private data, account or machine
can prevent reconstruction. Windows' CurrentUser DPAPI protection is tied to the
user account but does not isolate private data from malware running as that user
or from an administrator.

When private data is written, safeclone requests write-through and flushes before
and after renaming, then checks identity, authentication and readback. These
steps cover bounded process interruptions; atomic rename and successful flush do
not prove survival of **physical power-loss**, controller/cache faults or device
failure. No physical power-loss guarantee is made. See [security limits](security-model.md)
and [manual-state handling](usage.md#if-a-command-fails).
