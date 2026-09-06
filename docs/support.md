# Supported environment

safeclone 0.1.0 supports **Windows 11 25H2 Home or Pro, native x64,
ordinary-user execution, qualifying fixed/local NTFS**. Use the applicable
supported Windows security updates. The runtime checks filesystem eligibility;
the presence of a command or general Windows help text is not a broader support
claim. It does not require elevation and must not be run as an administrator
to make an unsupported input pass.

## Exclusions

- Windows 11 23H2, 24H2 and 26H1; Pro Education, Pro for Workstations,
  Enterprise, Education, SE, Enterprise multi-session, IoT Enterprise and all
  LTSC channels; every Windows 10 edition/channel, including ESU, LTSC and LTSB.
- ARM64, 32-bit/WoW64 and emulation substitutes; Linux, Darwin and WSL filesystem
  operation. Non-Windows filesystem entry points reject before user-path access.
- ReFS, CsvFS, FAT/FAT32, exFAT and other non-NTFS filesystems; UNC, mapped,
  network, remote or provider-backed locations.
- Participating case-sensitive directories, reparse/link-like entries,
  hard-linked files, named streams and unsupported/ambiguous names. Unsupported
  child entries may be omitted in one-way output; sessions enforce their stricter
  whole-tree and original-only preservation contracts.

Session namespace checks accept stable NTFS short-name policy states only.
Canonical long names and observed aliases must select a unique physical entry;
aliases cannot become an alternate authority or bypass protected names. A
short-name policy change, alias collision, case ambiguity or unstable identity
fails closed. Disabling a safety check is not a supported workaround.

## Runtime prerequisite and portable use

The reference build uses MSVC **14.50.35717** and needs the x64 Microsoft Visual
C++ v14 runtime at least as recent as its build toolset. Windows supplies the
Universal CRT. Tests observed VCRUNTIME140 **14.50.35719.0** and UCRT
**10.0.26100.9278**. These observations are not a claim that every supported
machine already has the prerequisite.

safeclone neither bundles nor installs Microsoft's runtime. If it is missing,
the machine owner must use Microsoft's supported x64 v14 runtime installation
process; that prerequisite installer may require administrative authority.
See [Microsoft's runtime requirements](https://learn.microsoft.com/en-us/cpp/windows/latest-supported-vc-redist).
For another build, use that build's recorded toolset requirements.

Keep the executable in a trusted local directory outside untrusted workspaces,
and protect its ancestors against replacement. Do not add adjacent DLLs,
`.local` redirection files or external manifests. An executable checksum does
not inspect adjacent files or authenticate its publisher. The reference
executable is unsigned; no installer, automatic update, PATH mutation, registry
integration or signing service is provided. Windows reputation and policy
warnings depend on delivery and machine policy; local testing does not establish
SmartScreen reputation. Do not disable Windows protections to run an untrusted copy.

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

Keep access to the same Windows user/machine profile and the unchanged Original.
Copying private state to another user or machine is not a supported recovery
method. Losing Original, private state, the profile or the machine can prevent
reconstruction. CurrentUser DPAPI has account recovery/roaming characteristics
and does not isolate data from same-user malware or privileged attackers.

The private-generation protocol requests write-through and pre/post rename
flushes, then checks identity, authentication and readback. It supports bounded
process-interruption classification. Atomic rename and successful flush do not
prove survival of physical power loss, controller/cache faults or device failure.
No physical power-loss guarantee is made. See [security limits](security-model.md)
and [manual-state handling](usage.md#failure-retirement-and-disposal).
