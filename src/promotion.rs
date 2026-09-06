//! Atomic, policy-relative publication of a freshly re-verified staging tree.
//!
//! This module never reconstructs an ambient output path. Publication is one
//! exclusive namespace transition between two leaves of the retained output
//! parent capability. It does not provide crash-durability guarantees.

use std::ffi::OsStr;
use std::fmt;
use std::io;
use std::path::{Component, Path};

#[cfg(any(target_os = "linux", target_os = "macos"))]
use cap_fs_ext::DirExt;
use cap_std::fs::Dir;

use crate::fs_boundary::{self, FilesystemIdentity};
use crate::staging::{PromotionBoundaryParts, StagingError, UNVERIFIED_STAGING_LEAF};
use crate::verification::{
    self, VerificationError, VerificationLimits, VerificationReport, VerifiedStagedTree,
};

// Linux UAPI v6.18 include/uapi/linux/magic.h. These are a positive
// eligibility allowlist, not a heuristic denylist.
#[cfg(any(target_os = "linux", test))]
const EXT_SUPER_MAGIC: u32 = 0x0000_EF53;
#[cfg(any(target_os = "linux", test))]
const BTRFS_SUPER_MAGIC: u32 = 0x9123_683E;
#[cfg(any(target_os = "linux", test))]
const XFS_SUPER_MAGIC: u32 = 0x5846_5342;
#[cfg(any(target_os = "linux", test))]
const TMPFS_MAGIC: u32 = 0x0102_1994;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PromotionPlatform {
    LinuxExtFamily,
    LinuxBtrfs,
    LinuxXfs,
    LinuxTmpfs,
    WindowsNtfs,
}

impl PromotionPlatform {
    /// Stable, explicit labels for raw-free user-facing reports.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::WindowsNtfs => "windows-ntfs",
            Self::LinuxExtFamily => "linux-ext-family",
            Self::LinuxBtrfs => "linux-btrfs",
            Self::LinuxXfs => "linux-xfs",
            Self::LinuxTmpfs => "linux-tmpfs",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublicationReport {
    pub verification: VerificationReport,
    pub platform: PromotionPlatform,
}

/// A policy-relative published clone. Its private fields and lack of a public
/// constructor make it obtainable only after fresh verification, an exclusive
/// rename, and post-transition identity validation all succeed.
pub struct PublishedClone {
    report: PublicationReport,
}

impl PublishedClone {
    pub fn report(&self) -> PublicationReport {
        self.report
    }
}

impl fmt::Debug for PublishedClone {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PublishedClone")
            .field("report", &self.report)
            .field("state", &"policy-relative-published")
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExclusiveRenameError {
    InvalidLeaf,
    IdenticalLeaves,
    SourceOpenFailed,
    SourceNotDirectory,
    SourceIdentityChanged,
    EncodingLimitExceeded,
    PrimitiveUnsupported,
    PrimitiveFailed,
}

impl fmt::Display for ExclusiveRenameError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidLeaf => "promotion name is not one valid relative leaf",
            Self::IdenticalLeaves => "promotion source and destination leaves are identical",
            Self::SourceOpenFailed => "promotion source could not be opened safely",
            Self::SourceNotDirectory => "promotion source is not an ordinary directory",
            Self::SourceIdentityChanged => "promotion source identity changed",
            Self::EncodingLimitExceeded => "promotion name exceeds the native API limit",
            Self::PrimitiveUnsupported => "atomic exclusive rename is unsupported",
            Self::PrimitiveFailed => "atomic exclusive rename failed",
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PromotionError {
    FreshVerification(VerificationError),
    Boundary(StagingError),
    FilesystemUnsupported,
    ExclusiveRename(ExclusiveRenameError),
    DestinationOccupied,
    PromotionStateIndeterminate,
    ManualInspectionRequired,
    PromotionCleanupFailed,
}

impl fmt::Display for PromotionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FreshVerification(error) => error.fmt(formatter),
            Self::Boundary(error) => error.fmt(formatter),
            Self::FilesystemUnsupported => {
                formatter.write_str("output-parent filesystem is unsupported for promotion")
            }
            Self::ExclusiveRename(error) => error.fmt(formatter),
            Self::DestinationOccupied => formatter.write_str("final destination became occupied"),
            Self::PromotionStateIndeterminate => {
                formatter.write_str("promotion namespace state is indeterminate")
            }
            Self::ManualInspectionRequired => formatter.write_str(
                "unpublished staging may remain; no automatic cleanup was attempted; manual inspection is required; do not retry automatically",
            ),
            Self::PromotionCleanupFailed => {
                formatter.write_str("failed promotion staging cleanup failed")
            }
        }
    }
}

/// Consume verified point-in-time evidence, freshly re-verify the actual
/// staging tree, and publish it through one atomic no-clobber transition.
pub fn promote_verified_staged_tree(
    verified: VerifiedStagedTree,
) -> Result<PublishedClone, PromotionError> {
    promote_with_hook(verified, |_, _| {})
}

fn promote_with_hook(
    verified: VerifiedStagedTree,
    before_rename: impl FnOnce(&Dir, &OsStr),
) -> Result<PublishedClone, PromotionError> {
    let verified =
        verification::reverify_verified_staged_tree(verified, VerificationLimits::default())
            .map_err(map_reverification_error)?;
    let (boundary, report) = verified.into_boundary_and_report();

    let platform = match filesystem_eligibility(boundary.parent()) {
        Ok(platform) => platform,
        Err(error) => return dispose_boundary_after_failure(boundary, error),
    };
    if let Err(error) = boundary.validate_current() {
        let promotion_error = if error == StagingError::FinalOutputAlreadyExists {
            PromotionError::DestinationOccupied
        } else {
            PromotionError::Boundary(error)
        };
        return dispose_boundary_after_failure(boundary, promotion_error);
    }

    let mut parts = boundary.into_promotion_parts();
    #[cfg(windows)]
    parts.close_staging_handle();

    match observe_namespace(&parts) {
        Ok(state)
            if state.staging_is_expected(parts.staging_identity) && state.final_is_absent() => {}
        Ok(state)
            if state.staging_is_expected(parts.staging_identity)
                && state.final_is_unrelated(parts.staging_identity) =>
        {
            return dispose_parts_after_failure(parts, PromotionError::DestinationOccupied);
        }
        Ok(_) | Err(()) => return Err(PromotionError::PromotionStateIndeterminate),
    }

    before_rename(&parts.parent, &parts.output_leaf);
    let primitive = exclusive_rename(
        &parts.parent,
        OsStr::new(UNVERIFIED_STAGING_LEAF),
        &parts.output_leaf,
        Some(parts.staging_identity),
    );
    let state =
        observe_namespace(&parts).map_err(|()| PromotionError::PromotionStateIndeterminate)?;
    match classify_post_state(primitive.is_ok(), state, parts.staging_identity) {
        PostState::Published => {
            drop(parts);
            Ok(PublishedClone {
                report: PublicationReport {
                    verification: report,
                    platform,
                },
            })
        }
        PostState::PrimitiveFailed => dispose_parts_after_failure(
            parts,
            PromotionError::ExclusiveRename(primitive.expect_err("classified primitive failure")),
        ),
        PostState::DestinationOccupied => {
            dispose_parts_after_failure(parts, PromotionError::DestinationOccupied)
        }
        PostState::Indeterminate => Err(PromotionError::PromotionStateIndeterminate),
    }
}

fn map_reverification_error(error: VerificationError) -> PromotionError {
    match error {
        VerificationError::Boundary(StagingError::FinalOutputAlreadyExists) => {
            PromotionError::DestinationOccupied
        }
        VerificationError::ManualInspectionRequired => PromotionError::ManualInspectionRequired,
        VerificationError::VerificationCleanupFailed => PromotionError::PromotionCleanupFailed,
        _ => PromotionError::FreshVerification(error),
    }
}

fn dispose_boundary_after_failure<T>(
    boundary: crate::staging::UnverifiedStagingRoot,
    original: PromotionError,
) -> Result<T, PromotionError> {
    match boundary.discard_staging_preserving_final() {
        Ok(()) => Err(original),
        Err(error) => Err(map_staging_disposal_error(error)),
    }
}

fn dispose_parts_after_failure<T>(
    parts: PromotionBoundaryParts,
    original: PromotionError,
) -> Result<T, PromotionError> {
    match parts.discard_staging() {
        Ok(()) => Err(original),
        Err(error) => Err(map_staging_disposal_error(error)),
    }
}

const fn map_staging_disposal_error(error: StagingError) -> PromotionError {
    match error {
        StagingError::StagingRequiresManualInspection => PromotionError::ManualInspectionRequired,
        _ => PromotionError::PromotionCleanupFailed,
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum LeafState {
    Absent,
    Directory(FilesystemIdentity),
    Other,
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct NamespaceState {
    staging: LeafState,
    final_output: LeafState,
}

impl NamespaceState {
    fn staging_is_expected(self, expected: FilesystemIdentity) -> bool {
        self.staging == LeafState::Directory(expected)
    }

    fn final_is_absent(self) -> bool {
        self.final_output == LeafState::Absent
    }

    fn final_is_expected(self, expected: FilesystemIdentity) -> bool {
        self.final_output == LeafState::Directory(expected)
    }

    fn final_is_unrelated(self, expected: FilesystemIdentity) -> bool {
        !self.final_is_absent() && !self.final_is_expected(expected)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PostState {
    Published,
    PrimitiveFailed,
    DestinationOccupied,
    Indeterminate,
}

fn classify_post_state(
    primitive_succeeded: bool,
    state: NamespaceState,
    expected: FilesystemIdentity,
) -> PostState {
    if primitive_succeeded {
        if state.staging == LeafState::Absent && state.final_is_expected(expected) {
            PostState::Published
        } else {
            PostState::Indeterminate
        }
    } else if state.staging_is_expected(expected) && state.final_is_absent() {
        PostState::PrimitiveFailed
    } else if state.staging_is_expected(expected) && state.final_is_unrelated(expected) {
        PostState::DestinationOccupied
    } else {
        PostState::Indeterminate
    }
}

fn observe_namespace(parts: &PromotionBoundaryParts) -> Result<NamespaceState, ()> {
    Ok(NamespaceState {
        staging: observe_leaf(&parts.parent, OsStr::new(UNVERIFIED_STAGING_LEAF))?,
        final_output: observe_leaf(&parts.parent, &parts.output_leaf)?,
    })
}

fn observe_leaf(parent: &Dir, leaf: &OsStr) -> Result<LeafState, ()> {
    match parent.symlink_metadata(leaf) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                Ok(LeafState::Other)
            } else {
                Ok(LeafState::Directory(fs_boundary::metadata_identity(
                    &metadata,
                )))
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(LeafState::Absent),
        Err(_) => Err(()),
    }
}

fn filesystem_eligibility(parent: &Dir) -> Result<PromotionPlatform, PromotionError> {
    #[cfg(target_os = "linux")]
    {
        let statistics =
            rustix::fs::fstatfs(parent).map_err(|_| PromotionError::FilesystemUnsupported)?;
        return classify_linux_filesystem(statistics.f_type as u32)
            .ok_or(PromotionError::FilesystemUnsupported);
    }

    #[cfg(target_os = "macos")]
    {
        let _ = parent;
        return Err(PromotionError::FilesystemUnsupported);
    }

    #[cfg(windows)]
    {
        return windows_filesystem_eligibility(parent);
    }

    #[allow(unreachable_code)]
    {
        let _ = parent;
        Err(PromotionError::FilesystemUnsupported)
    }
}

#[cfg(any(target_os = "linux", test))]
const fn classify_linux_filesystem(magic: u32) -> Option<PromotionPlatform> {
    match magic {
        EXT_SUPER_MAGIC => Some(PromotionPlatform::LinuxExtFamily),
        BTRFS_SUPER_MAGIC => Some(PromotionPlatform::LinuxBtrfs),
        XFS_SUPER_MAGIC => Some(PromotionPlatform::LinuxXfs),
        TMPFS_MAGIC => Some(PromotionPlatform::LinuxTmpfs),
        _ => None,
    }
}

fn exclusive_rename(
    parent: &Dir,
    from_leaf: &OsStr,
    to_leaf: &OsStr,
    expected: Option<FilesystemIdentity>,
) -> Result<(), ExclusiveRenameError> {
    validate_leaf(from_leaf)?;
    validate_leaf(to_leaf)?;
    if from_leaf == to_leaf {
        return Err(ExclusiveRenameError::IdenticalLeaves);
    }
    exclusive_rename_platform(parent, from_leaf, to_leaf, expected)
}

fn validate_leaf(leaf: &OsStr) -> Result<(), ExclusiveRenameError> {
    let mut components = Path::new(leaf).components();
    let one_normal = matches!(
        components.next(),
        Some(Component::Normal(component)) if component == leaf
    ) && components.next().is_none();
    if !one_normal || leaf_has_forbidden_units(leaf) {
        Err(ExclusiveRenameError::InvalidLeaf)
    } else {
        Ok(())
    }
}

#[cfg(unix)]
fn leaf_has_forbidden_units(leaf: &OsStr) -> bool {
    use std::os::unix::ffi::OsStrExt;

    let bytes = leaf.as_bytes();
    bytes.is_empty() || bytes.iter().any(|byte| matches!(byte, 0 | b'/' | b'\\'))
}

#[cfg(windows)]
fn leaf_has_forbidden_units(leaf: &OsStr) -> bool {
    use std::os::windows::ffi::OsStrExt;

    let mut saw_unit = false;
    for unit in leaf.encode_wide() {
        saw_unit = true;
        if unit == 0
            || unit == u16::from(b'/')
            || unit == u16::from(b'\\')
            || unit == u16::from(b':')
        {
            return true;
        }
    }
    !saw_unit
}

#[cfg(not(any(unix, windows)))]
fn leaf_has_forbidden_units(leaf: &OsStr) -> bool {
    leaf.is_empty()
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn exclusive_rename_platform(
    parent: &Dir,
    from_leaf: &OsStr,
    to_leaf: &OsStr,
    expected: Option<FilesystemIdentity>,
) -> Result<(), ExclusiveRenameError> {
    let source = parent
        .open_dir_nofollow(from_leaf)
        .map_err(|_| ExclusiveRenameError::SourceOpenFailed)?;
    let source_identity = fs_boundary::directory_identity(&source)
        .map_err(|_| ExclusiveRenameError::SourceNotDirectory)?;
    let relative_metadata = parent
        .symlink_metadata(from_leaf)
        .map_err(|_| ExclusiveRenameError::SourceIdentityChanged)?;
    if relative_metadata.file_type().is_symlink()
        || !relative_metadata.is_dir()
        || fs_boundary::metadata_identity(&relative_metadata) != source_identity
        || expected.is_some_and(|identity| identity != source_identity)
    {
        return Err(ExclusiveRenameError::SourceIdentityChanged);
    }

    rustix::fs::renameat_with(
        parent,
        from_leaf,
        parent,
        to_leaf,
        rustix::fs::RenameFlags::NOREPLACE,
    )
    .map_err(|_| ExclusiveRenameError::PrimitiveFailed)
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
fn exclusive_rename_platform(
    _parent: &Dir,
    _from_leaf: &OsStr,
    _to_leaf: &OsStr,
    _expected: Option<FilesystemIdentity>,
) -> Result<(), ExclusiveRenameError> {
    Err(ExclusiveRenameError::PrimitiveUnsupported)
}

#[cfg(windows)]
fn windows_filesystem_eligibility(parent: &Dir) -> Result<PromotionPlatform, PromotionError> {
    use std::mem::size_of;
    use std::os::windows::io::AsRawHandle;
    use std::ptr;

    use windows_sys::Wdk::Storage::FileSystem::{
        FileIsRemoteDeviceInformation, NtQueryInformationFile,
    };
    use windows_sys::Wdk::System::SystemServices::FILE_IS_REMOTE_DEVICE_INFORMATION;
    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::Storage::FileSystem::GetVolumeInformationByHandleW;
    use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

    let handle = parent.as_raw_handle() as HANDLE;
    let mut io_status = IO_STATUS_BLOCK::default();
    let mut remote = FILE_IS_REMOTE_DEVICE_INFORMATION::default();
    // SAFETY: `handle` is a live retained directory handle; both output
    // buffers are correctly sized writable windows-sys ABI values.
    let status = unsafe {
        NtQueryInformationFile(
            handle,
            &mut io_status,
            (&mut remote as *mut FILE_IS_REMOTE_DEVICE_INFORMATION).cast(),
            u32::try_from(size_of::<FILE_IS_REMOTE_DEVICE_INFORMATION>())
                .map_err(|_| PromotionError::FilesystemUnsupported)?,
            FileIsRemoteDeviceInformation,
        )
    };
    if status < 0 {
        return Err(PromotionError::FilesystemUnsupported);
    }

    let mut filesystem_name = [0u16; 16];
    // SAFETY: the retained directory handle is valid and the filesystem-name
    // output points to a writable fixed-size UTF-16 buffer. Optional outputs
    // are deliberately null.
    let queried = unsafe {
        GetVolumeInformationByHandleW(
            handle,
            ptr::null_mut(),
            0,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            filesystem_name.as_mut_ptr(),
            filesystem_name.len() as u32,
        )
    };
    if queried == 0 {
        return Err(PromotionError::FilesystemUnsupported);
    }
    let end = filesystem_name
        .iter()
        .position(|unit| *unit == 0)
        .ok_or(PromotionError::FilesystemUnsupported)?;
    classify_windows_query_results(Some(remote.IsRemote), Some(&filesystem_name[..end]))
        .ok_or(PromotionError::FilesystemUnsupported)
}

#[cfg(windows)]
fn classify_windows_query_results(
    is_remote: Option<bool>,
    filesystem_name: Option<&[u16]>,
) -> Option<PromotionPlatform> {
    classify_windows_filesystem(is_remote?, filesystem_name?)
}

#[cfg(windows)]
fn classify_windows_filesystem(
    is_remote: bool,
    filesystem_name: &[u16],
) -> Option<PromotionPlatform> {
    if !is_remote && utf16_ascii_eq_ignore_case(filesystem_name, b"NTFS") {
        Some(PromotionPlatform::WindowsNtfs)
    } else {
        None
    }
}

#[cfg(windows)]
fn utf16_ascii_eq_ignore_case(actual: &[u16], expected: &[u8]) -> bool {
    actual.len() == expected.len()
        && actual.iter().zip(expected).all(|(actual, expected)| {
            u8::try_from(*actual).is_ok_and(|actual| actual.eq_ignore_ascii_case(expected))
        })
}

#[cfg(windows)]
fn exclusive_rename_platform(
    parent: &Dir,
    from_leaf: &OsStr,
    to_leaf: &OsStr,
    expected: Option<FilesystemIdentity>,
) -> Result<(), ExclusiveRenameError> {
    use windows_sys::Wdk::Storage::FileSystem::{FileRenameInformation, NtSetInformationFile};
    use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

    exclusive_rename_windows_with(
        parent,
        from_leaf,
        to_leaf,
        expected,
        |source, information, buffer_size| {
            let mut io_status = IO_STATUS_BLOCK::default();
            // SAFETY: the caller keeps the DELETE-capable source handle and
            // aligned FILE_RENAME_INFORMATION buffer live for this one call.
            let status = unsafe {
                NtSetInformationFile(
                    source,
                    &mut io_status,
                    information,
                    buffer_size,
                    FileRenameInformation,
                )
            };
            if status < 0 {
                Err(ExclusiveRenameError::PrimitiveFailed)
            } else {
                Ok(())
            }
        },
    )
}

#[cfg(windows)]
fn exclusive_rename_windows_with(
    parent: &Dir,
    from_leaf: &OsStr,
    to_leaf: &OsStr,
    expected: Option<FilesystemIdentity>,
    invoke: impl FnOnce(
        windows_sys::Win32::Foundation::HANDLE,
        *const std::ffi::c_void,
        u32,
    ) -> Result<(), ExclusiveRenameError>,
) -> Result<(), ExclusiveRenameError> {
    use std::ffi::c_void;
    use std::mem::{offset_of, size_of};
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::AsRawHandle;

    use cap_std::fs::{OpenOptions, OpenOptionsExt};
    use windows_sys::Wdk::Storage::FileSystem::FILE_RENAME_INFORMATION;
    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::Storage::FileSystem::{
        DELETE, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ, FILE_SHARE_WRITE,
    };

    let mut options = OpenOptions::new();
    options
        .access_mode(DELETE | FILE_READ_ATTRIBUTES)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT);
    let source = parent
        .open_with(from_leaf, &options)
        .map_err(|_| ExclusiveRenameError::SourceOpenFailed)?;
    let source_metadata = source
        .metadata()
        .map_err(|_| ExclusiveRenameError::SourceNotDirectory)?;
    if source_metadata.file_type().is_symlink() || !source_metadata.is_dir() {
        return Err(ExclusiveRenameError::SourceNotDirectory);
    }
    let source_identity = fs_boundary::metadata_identity(&source_metadata);
    let relative_metadata = parent
        .symlink_metadata(from_leaf)
        .map_err(|_| ExclusiveRenameError::SourceIdentityChanged)?;
    if relative_metadata.file_type().is_symlink()
        || !relative_metadata.is_dir()
        || fs_boundary::metadata_identity(&relative_metadata) != source_identity
        || expected.is_some_and(|identity| identity != source_identity)
    {
        return Err(ExclusiveRenameError::SourceIdentityChanged);
    }

    let target = to_leaf.encode_wide().collect::<Vec<_>>();
    let target_bytes = target
        .len()
        .checked_mul(size_of::<u16>())
        .ok_or(ExclusiveRenameError::EncodingLimitExceeded)?;
    let buffer_bytes = offset_of!(FILE_RENAME_INFORMATION, FileName)
        .checked_add(target_bytes)
        .ok_or(ExclusiveRenameError::EncodingLimitExceeded)?;
    let buffer_size =
        u32::try_from(buffer_bytes).map_err(|_| ExclusiveRenameError::EncodingLimitExceeded)?;
    let words = buffer_bytes
        .checked_add(size_of::<usize>() - 1)
        .ok_or(ExclusiveRenameError::EncodingLimitExceeded)?
        / size_of::<usize>();
    let mut storage = vec![0usize; words];
    let information = storage.as_mut_ptr().cast::<FILE_RENAME_INFORMATION>();
    // SAFETY: `storage` is usize-aligned and sized for the windows-sys fixed
    // header plus the exact non-NUL-terminated UTF-16 target. Every field is
    // initialized before the native call and all pointers remain live.
    unsafe {
        (*information).Anonymous.ReplaceIfExists = false;
        (*information).RootDirectory = parent.as_raw_handle() as HANDLE;
        (*information).FileNameLength =
            u32::try_from(target_bytes).map_err(|_| ExclusiveRenameError::EncodingLimitExceeded)?;
        std::ptr::copy_nonoverlapping(
            target.as_ptr(),
            (*information).FileName.as_mut_ptr(),
            target.len(),
        );
    }

    invoke(
        source.as_raw_handle() as HANDLE,
        information.cast::<c_void>(),
        buffer_size,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn platform_labels_are_stable_and_explicit() {
        assert_eq!(PromotionPlatform::WindowsNtfs.as_str(), "windows-ntfs");
        assert_eq!(
            PromotionPlatform::LinuxExtFamily.as_str(),
            "linux-ext-family"
        );
        assert_eq!(PromotionPlatform::LinuxBtrfs.as_str(), "linux-btrfs");
        assert_eq!(PromotionPlatform::LinuxXfs.as_str(), "linux-xfs");
        assert_eq!(PromotionPlatform::LinuxTmpfs.as_str(), "linux-tmpfs");
    }

    #[test]
    fn linux_filesystem_allowlist_is_exact() {
        assert_eq!(
            classify_linux_filesystem(EXT_SUPER_MAGIC),
            Some(PromotionPlatform::LinuxExtFamily)
        );
        assert_eq!(
            classify_linux_filesystem(BTRFS_SUPER_MAGIC),
            Some(PromotionPlatform::LinuxBtrfs)
        );
        assert_eq!(
            classify_linux_filesystem(XFS_SUPER_MAGIC),
            Some(PromotionPlatform::LinuxXfs)
        );
        assert_eq!(
            classify_linux_filesystem(TMPFS_MAGIC),
            Some(PromotionPlatform::LinuxTmpfs)
        );
        for denied in [0x6969, 0xFF53_4D42, 0x6573_5546, 0x794C_7630, 0] {
            assert_eq!(classify_linux_filesystem(denied), None);
        }
    }

    #[test]
    fn post_state_requires_exact_namespace_transition() {
        let expected = FilesystemIdentity::synthetic(7, 11);
        let unrelated = FilesystemIdentity::synthetic(7, 12);
        assert_eq!(
            classify_post_state(
                true,
                NamespaceState {
                    staging: LeafState::Absent,
                    final_output: LeafState::Directory(expected),
                },
                expected,
            ),
            PostState::Published
        );
        assert_eq!(
            classify_post_state(
                true,
                NamespaceState {
                    staging: LeafState::Directory(expected),
                    final_output: LeafState::Absent,
                },
                expected,
            ),
            PostState::Indeterminate
        );
        assert_eq!(
            classify_post_state(
                true,
                NamespaceState {
                    staging: LeafState::Absent,
                    final_output: LeafState::Directory(unrelated),
                },
                expected,
            ),
            PostState::Indeterminate
        );
        assert_eq!(
            classify_post_state(
                false,
                NamespaceState {
                    staging: LeafState::Directory(expected),
                    final_output: LeafState::Absent,
                },
                expected,
            ),
            PostState::PrimitiveFailed
        );
        assert_eq!(
            classify_post_state(
                false,
                NamespaceState {
                    staging: LeafState::Absent,
                    final_output: LeafState::Directory(expected),
                },
                expected,
            ),
            PostState::Indeterminate
        );
        assert_eq!(
            classify_post_state(
                false,
                NamespaceState {
                    staging: LeafState::Directory(unrelated),
                    final_output: LeafState::Other,
                },
                expected,
            ),
            PostState::Indeterminate
        );
        assert_eq!(
            classify_post_state(
                false,
                NamespaceState {
                    staging: LeafState::Directory(expected),
                    final_output: LeafState::Other,
                },
                expected,
            ),
            PostState::DestinationOccupied
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_filesystem_classifier_requires_local_exact_ntfs() {
        let ntfs = "NTFS".encode_utf16().collect::<Vec<_>>();
        let lowercase = "ntfs".encode_utf16().collect::<Vec<_>>();
        let refs = "ReFS".encode_utf16().collect::<Vec<_>>();
        let csvfs = "CsvFS".encode_utf16().collect::<Vec<_>>();
        assert_eq!(
            classify_windows_filesystem(false, &ntfs),
            Some(PromotionPlatform::WindowsNtfs)
        );
        assert_eq!(
            classify_windows_filesystem(false, &lowercase),
            Some(PromotionPlatform::WindowsNtfs)
        );
        assert_eq!(classify_windows_filesystem(true, &ntfs), None);
        assert_eq!(classify_windows_filesystem(false, &refs), None);
        assert_eq!(classify_windows_filesystem(false, &csvfs), None);
        assert_eq!(classify_windows_filesystem(false, &[]), None);
        assert_eq!(classify_windows_query_results(None, Some(&ntfs)), None);
        assert_eq!(classify_windows_query_results(Some(false), None), None);
    }

    #[cfg(windows)]
    mod windows {
        use super::*;
        use std::fs;
        use std::io::Write;
        use std::path::{Path, PathBuf};
        use std::process::Command;
        use std::sync::atomic::{AtomicU64, Ordering};

        use cap_std::ambient_authority;
        use cap_std::fs::{Dir, OpenOptions};

        use crate::staging::{
            create_unverified_staging_root_for_test as create_unverified_staging_root,
            UNVERIFIED_STAGING_LEAF,
        };
        use crate::staging_tree::{
            build_unverified_sanitized_staging_tree, Limits as StagingTreeLimits,
        };
        use crate::verification::{
            verify_unverified_staged_tree, VerificationLimits, VerifiedStagedTree,
        };

        struct Fixture(PathBuf);

        impl Fixture {
            fn new(label: &str) -> Self {
                static NEXT: AtomicU64 = AtomicU64::new(0);
                let nonce = NEXT.fetch_add(1, Ordering::Relaxed);
                let path = std::env::temp_dir().join(format!(
                    "safeclone-promotion-{label}-{}-{nonce}",
                    std::process::id()
                ));
                fs::create_dir(&path).expect("create promotion fixture");
                Self(path)
            }

            fn parent(&self) -> (PathBuf, Dir) {
                let path = self.0.join("parent");
                fs::create_dir(&path).expect("create output parent");
                let parent = Dir::open_ambient_dir(&path, ambient_authority())
                    .expect("open output-parent capability");
                (path, parent)
            }
        }

        impl Drop for Fixture {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }

        struct Workspace {
            fixture: Fixture,
            source: PathBuf,
            parent: PathBuf,
            output: PathBuf,
        }

        impl Workspace {
            fn new(label: &str, output_leaf: &str) -> Self {
                let fixture = Fixture::new(label);
                let source = fixture.0.join("source");
                let parent = fixture.0.join("destination");
                let output = parent.join(output_leaf);
                fs::create_dir(&source).expect("create source");
                fs::create_dir(&parent).expect("create output parent");
                Self {
                    fixture,
                    source,
                    parent,
                    output,
                }
            }

            fn staging(&self) -> PathBuf {
                self.parent.join(UNVERIFIED_STAGING_LEAF)
            }

            fn verify(&self) -> VerifiedStagedTree {
                let boundary = create_unverified_staging_root(&self.source, &self.output)
                    .expect("create staging boundary");
                let tree =
                    build_unverified_sanitized_staging_tree(boundary, StagingTreeLimits::default())
                        .expect("build sanitized staging tree");
                verify_unverified_staged_tree(tree, VerificationLimits::default())
                    .expect("verify sanitized staging tree")
            }

            fn assert_manual_staging_retained(&self) {
                assert!(self.staging().is_dir());
                assert!(fs::symlink_metadata(&self.output).is_err());
            }
        }

        fn synthetic_github_token() -> String {
            const ALPHABET: &[u8] = b"A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0";
            let body = (0..36)
                .map(|index| ALPHABET[index % ALPHABET.len()])
                .collect::<Vec<_>>();
            format!(
                "gho_{}",
                String::from_utf8(body).expect("ASCII synthetic token")
            )
        }

        fn primitive(parent: &Dir, from: &OsStr, to: &OsStr) -> Result<(), ExclusiveRenameError> {
            exclusive_rename(parent, from, to, None)
        }

        #[test]
        fn retained_parent_is_local_ntfs_in_the_windows_test_environment() {
            let fixture = Fixture::new("eligibility");
            let (_, parent) = fixture.parent();
            assert_eq!(
                filesystem_eligibility(&parent),
                Ok(PromotionPlatform::WindowsNtfs)
            );
        }

        #[test]
        fn production_primitive_renames_absent_destination_relative_to_parent() {
            let fixture = Fixture::new("primitive-success");
            let (path, parent) = fixture.parent();
            fs::create_dir(path.join("staging")).expect("create staging source");

            primitive(&parent, OsStr::new("staging"), OsStr::new("output"))
                .expect("exclusive rename succeeds");

            assert!(fs::symlink_metadata(path.join("staging")).is_err());
            assert!(path.join("output").is_dir());
        }

        #[test]
        fn production_primitive_never_clobbers_file_directory_or_junction() {
            for destination_kind in ["file", "directory", "junction"] {
                let fixture = Fixture::new(destination_kind);
                let (path, parent) = fixture.parent();
                fs::create_dir(path.join("staging")).expect("create staging source");
                let output = path.join("output");
                let junction_target = fixture.0.join("junction-target");
                match destination_kind {
                    "file" => {
                        fs::write(&output, b"unchanged-file").expect("create destination file")
                    }
                    "directory" => {
                        fs::create_dir(&output).expect("create destination directory");
                        fs::write(output.join("sentinel"), b"unchanged-directory")
                            .expect("write directory sentinel");
                    }
                    "junction" => {
                        fs::create_dir(&junction_target).expect("create junction target");
                        fs::write(junction_target.join("sentinel"), b"unchanged-junction")
                            .expect("write junction sentinel");
                        create_junction(&output, &junction_target);
                    }
                    _ => unreachable!(),
                }

                primitive(&parent, OsStr::new("staging"), OsStr::new("output"))
                    .expect_err("occupied destination rejects exclusive rename");

                assert!(path.join("staging").is_dir());
                match destination_kind {
                    "file" => assert_eq!(
                        fs::read(&output).expect("read destination file"),
                        b"unchanged-file"
                    ),
                    "directory" => assert_eq!(
                        fs::read(output.join("sentinel")).expect("read directory sentinel"),
                        b"unchanged-directory"
                    ),
                    "junction" => {
                        assert_eq!(
                            fs::read(output.join("sentinel")).expect("read junction sentinel"),
                            b"unchanged-junction"
                        );
                        fs::remove_dir(&output).expect("remove junction only");
                    }
                    _ => unreachable!(),
                }
            }
        }

        #[test]
        fn production_primitive_rejects_destination_inserted_after_precheck() {
            let fixture = Fixture::new("primitive-race");
            let (path, parent) = fixture.parent();
            fs::create_dir(path.join("staging")).expect("create staging source");
            assert_eq!(
                parent
                    .symlink_metadata("output")
                    .expect_err("destination begins absent")
                    .kind(),
                io::ErrorKind::NotFound
            );
            fs::write(path.join("output"), b"racing-destination").expect("insert destination");

            primitive(&parent, OsStr::new("staging"), OsStr::new("output"))
                .expect_err("exclusive rename rejects raced destination");

            assert!(path.join("staging").is_dir());
            assert_eq!(
                fs::read(path.join("output")).expect("read raced destination"),
                b"racing-destination"
            );
        }

        #[test]
        fn production_primitive_rejects_missing_same_and_non_leaf_inputs() {
            let fixture = Fixture::new("primitive-inputs");
            let (path, parent) = fixture.parent();
            primitive(&parent, OsStr::new("missing"), OsStr::new("output"))
                .expect_err("missing source rejects rename");
            fs::create_dir(path.join("staging")).expect("create staging source");
            assert_eq!(
                primitive(&parent, OsStr::new("staging"), OsStr::new("staging")),
                Err(ExclusiveRenameError::IdenticalLeaves)
            );
            for invalid in [
                OsStr::new(""),
                OsStr::new("."),
                OsStr::new(".."),
                OsStr::new("nested\\output"),
                OsStr::new("C:\\output"),
                OsStr::new("output:stream"),
            ] {
                assert_eq!(
                    primitive(&parent, OsStr::new("staging"), invalid),
                    Err(ExclusiveRenameError::InvalidLeaf)
                );
                assert!(path.join("staging").is_dir());
            }
        }

        #[test]
        fn unsupported_native_result_has_no_fallback() {
            let fixture = Fixture::new("primitive-unsupported");
            let (path, parent) = fixture.parent();
            fs::create_dir(path.join("staging")).expect("create staging source");

            let error = exclusive_rename_windows_with(
                &parent,
                OsStr::new("staging"),
                OsStr::new("output"),
                None,
                |_source, _information, _size| Err(ExclusiveRenameError::PrimitiveUnsupported),
            )
            .expect_err("unsupported result fails closed");

            assert_eq!(error, ExclusiveRenameError::PrimitiveUnsupported);
            assert!(path.join("staging").is_dir());
            assert!(fs::symlink_metadata(path.join("output")).is_err());
        }

        #[test]
        fn end_to_end_promotion_publishes_only_freshly_verified_sanitized_tree() {
            let workspace = Workspace::new("end-to-end", "final-output");
            let email = "fixture.user@example.invalid";
            let phone = "090-1234-5678";
            let token = synthetic_github_token();
            fs::create_dir(workspace.source.join(email)).expect("create sensitive directory");
            let source_file = workspace.source.join(email).join("192.0.2.10.rs");
            let source_text = format!("email={email}\nphone={phone}\ntoken={token}\n");
            fs::write(&source_file, &source_text).expect("write detector fixture");
            let source_before = fs::read(&source_file).expect("read source before");
            let initially_verified = workspace.verify();
            let initial_report = initially_verified.report();
            let staging_capability =
                Dir::open_ambient_dir(workspace.staging(), ambient_authority())
                    .expect("open staged identity before promotion");
            let expected_identity = crate::fs_boundary::directory_identity(&staging_capability)
                .expect("read staged identity before promotion");
            drop(staging_capability);

            let published = promote_verified_staged_tree(initially_verified)
                .expect("fresh verification and exclusive promotion succeed");
            let report = published.report();

            assert_eq!(report.verification, initial_report);
            assert_eq!(report.platform, PromotionPlatform::WindowsNtfs);
            assert!(fs::symlink_metadata(workspace.staging()).is_err());
            let published_capability =
                Dir::open_ambient_dir(&workspace.output, ambient_authority())
                    .expect("open final identity after promotion");
            assert_eq!(
                crate::fs_boundary::directory_identity(&published_capability)
                    .expect("read final identity after promotion"),
                expected_identity
            );
            let final_file = workspace
                .output
                .join("__REDACTED_EMAIL__")
                .join("__REDACTED_IP__.rs");
            let output_text = fs::read_to_string(final_file).expect("read published content");
            for raw in [&token, email, phone] {
                assert!(!output_text.contains(raw));
            }
            assert!(output_text.contains("[REDACTED:SECRET]"));
            assert!(output_text.contains("[REDACTED:EMAIL]"));
            assert!(output_text.contains("[REDACTED:PHONE]"));
            assert_eq!(
                fs::read(&source_file).expect("read source after"),
                source_before
            );
            let debug = format!("{published:?}");
            for raw in [&token, email, phone] {
                assert!(!debug.contains(raw));
            }
            assert!(workspace.fixture.0.exists());
        }

        #[test]
        fn fresh_verification_rejects_same_identity_same_length_secret_and_email_mutations() {
            for (label, replacement) in [
                ("same-length-token", synthetic_github_token()),
                (
                    "same-length-email",
                    "fixture.user@example.invalid".to_owned(),
                ),
            ] {
                let workspace = Workspace::new(label, "final-output");
                fs::write(
                    workspace.source.join("main.txt"),
                    "z".repeat(replacement.len()),
                )
                .expect("write harmless source");
                let verified = workspace.verify();
                let staging = Dir::open_ambient_dir(workspace.staging(), ambient_authority())
                    .expect("open staging for identity assertion");
                let before = fs_boundary::metadata_identity(
                    &staging
                        .symlink_metadata("main.txt")
                        .expect("metadata before mutation"),
                );
                fs::write(workspace.staging().join("main.txt"), replacement.as_bytes())
                    .expect("mutate existing file in place");
                let after = fs_boundary::metadata_identity(
                    &staging
                        .symlink_metadata("main.txt")
                        .expect("metadata after mutation"),
                );
                assert_eq!(before, after);
                assert_eq!(
                    fs::metadata(workspace.staging().join("main.txt"))
                        .expect("mutated metadata")
                        .len(),
                    replacement.len() as u64
                );
                drop(staging);

                let error = promote_verified_staged_tree(verified)
                    .expect_err("fresh verification rejects raw mutation");

                assert_eq!(error, PromotionError::ManualInspectionRequired);
                workspace.assert_manual_staging_retained();
            }
        }

        #[test]
        fn fresh_verification_rejects_filename_git_and_hard_link_injections() {
            for mutation in ["dangerous-filename", "git", "hard-link"] {
                let workspace = Workspace::new(mutation, "final-output");
                fs::write(workspace.source.join("main.rs"), b"fn main() {}\n")
                    .expect("write source");
                let verified = workspace.verify();
                match mutation {
                    "dangerous-filename" => {
                        fs::write(workspace.staging().join("credentials.json"), b"{}\n")
                            .expect("inject dangerous filename");
                    }
                    "git" => {
                        fs::create_dir(workspace.staging().join(".git"))
                            .expect("inject git metadata directory");
                    }
                    "hard-link" => {
                        fs::hard_link(
                            workspace.staging().join("main.rs"),
                            workspace.staging().join("linked.rs"),
                        )
                        .expect("inject hard link");
                    }
                    _ => unreachable!(),
                }

                let error = promote_verified_staged_tree(verified)
                    .expect_err("fresh verification rejects injected staging state");

                assert_eq!(error, PromotionError::ManualInspectionRequired);
                workspace.assert_manual_staging_retained();
            }
        }

        #[test]
        fn promotion_preserves_post_staging_file_directory_and_junction_destinations() {
            for destination_kind in ["file", "directory", "junction"] {
                let workspace = Workspace::new(destination_kind, "final-output");
                fs::write(workspace.source.join("main.rs"), b"fn main() {}\n")
                    .expect("write source");
                let verified = workspace.verify();
                let junction_target = workspace.fixture.0.join("published-junction-target");
                match destination_kind {
                    "file" => {
                        fs::write(&workspace.output, b"existing-file").expect("create final file")
                    }
                    "directory" => {
                        fs::create_dir(&workspace.output).expect("create final directory");
                        fs::write(workspace.output.join("sentinel"), b"existing-directory")
                            .expect("write final directory sentinel");
                    }
                    "junction" => {
                        fs::create_dir(&junction_target).expect("create final junction target");
                        fs::write(junction_target.join("sentinel"), b"existing-junction")
                            .expect("write final junction sentinel");
                        create_junction(&workspace.output, &junction_target);
                    }
                    _ => unreachable!(),
                }

                let error = promote_verified_staged_tree(verified)
                    .expect_err("existing final destination rejects promotion");

                assert_eq!(error, PromotionError::ManualInspectionRequired);
                assert!(workspace.staging().is_dir());
                match destination_kind {
                    "file" => assert_eq!(
                        fs::read(&workspace.output).expect("read existing file"),
                        b"existing-file"
                    ),
                    "directory" => assert_eq!(
                        fs::read(workspace.output.join("sentinel"))
                            .expect("read existing directory sentinel"),
                        b"existing-directory"
                    ),
                    "junction" => {
                        assert_eq!(
                            fs::read(workspace.output.join("sentinel"))
                                .expect("read existing junction sentinel"),
                            b"existing-junction"
                        );
                        fs::remove_dir(&workspace.output).expect("remove final junction only");
                    }
                    _ => unreachable!(),
                }
            }
        }

        #[test]
        fn destination_race_after_precheck_is_not_clobbered() {
            let workspace = Workspace::new("promotion-race", "final-output");
            fs::write(workspace.source.join("main.rs"), b"fn main() {}\n").expect("write source");
            let verified = workspace.verify();

            let error = promote_with_hook(verified, |parent, output_leaf| {
                let mut options = OpenOptions::new();
                options.write(true).create_new(true);
                let mut inserted = parent
                    .open_with(output_leaf, &options)
                    .expect("insert destination through retained parent");
                inserted
                    .write_all(b"racing-destination")
                    .expect("write raced destination");
            })
            .expect_err("exclusive primitive rejects raced destination");

            assert_eq!(error, PromotionError::ManualInspectionRequired);
            assert!(workspace.staging().is_dir());
            assert_eq!(
                fs::read(&workspace.output).expect("read raced destination"),
                b"racing-destination"
            );
        }

        #[test]
        fn eligibility_and_definite_primitive_failures_abandon_staging_without_deletion() {
            let eligibility = Workspace::new("eligibility-failure-policy", "final-output");
            fs::write(eligibility.source.join("main.rs"), b"fn main() {}\n").expect("write source");
            let (boundary, _) = eligibility.verify().into_boundary_and_report();
            let error = dispose_boundary_after_failure::<PublishedClone>(
                boundary,
                PromotionError::FilesystemUnsupported,
            )
            .expect_err("post-staging eligibility failure is manual");
            assert_eq!(error, PromotionError::ManualInspectionRequired);
            eligibility.assert_manual_staging_retained();

            let primitive = Workspace::new("primitive-failure-policy", "final-output");
            fs::write(primitive.source.join("main.rs"), b"fn main() {}\n").expect("write source");
            let (boundary, _) = primitive.verify().into_boundary_and_report();
            let mut parts = boundary.into_promotion_parts();
            parts.close_staging_handle();
            let error = dispose_parts_after_failure::<PublishedClone>(
                parts,
                PromotionError::ExclusiveRename(ExclusiveRenameError::PrimitiveFailed),
            )
            .expect_err("definite native failure is manual");
            assert_eq!(error, PromotionError::ManualInspectionRequired);
            primitive.assert_manual_staging_retained();
        }

        #[test]
        fn promotion_state_indeterminate_does_not_retry_or_cleanup() {
            let workspace = Workspace::new("indeterminate-no-cleanup", "final-output");
            fs::write(workspace.source.join("main.rs"), b"fn main() {}\n").expect("write source");
            let verified = workspace.verify();
            let moved = workspace.parent.join("moved-expected-staging");

            let error = promote_with_hook(verified, |_, _| {
                fs::rename(workspace.staging(), &moved)
                    .expect("move synthetic staging before primitive");
            })
            .expect_err("unexpected namespace state is indeterminate");

            assert_eq!(error, PromotionError::PromotionStateIndeterminate);
            assert!(moved.join("main.rs").is_file());
            assert!(fs::symlink_metadata(workspace.staging()).is_err());
            assert!(fs::symlink_metadata(&workspace.output).is_err());
        }

        #[test]
        fn errors_and_published_state_do_not_expose_raw_output_metadata() {
            let raw_output = "synthetic-output-fixture.user@example.invalid";
            let workspace = Workspace::new("raw-free-error", raw_output);
            fs::write(workspace.source.join("main.rs"), b"fn main() {}\n").expect("write source");
            let verified = workspace.verify();
            fs::write(&workspace.output, b"occupied").expect("occupy final destination");

            let error = promote_verified_staged_tree(verified)
                .expect_err("occupied raw-named destination rejects promotion");
            let rendered = format!("{error:?} {error}");
            assert!(!rendered.contains(raw_output));
            assert_eq!(error, PromotionError::ManualInspectionRequired);
            assert!(error.to_string().contains("do not retry automatically"));
            assert_eq!(
                fs::read(&workspace.output).expect("read final"),
                b"occupied"
            );
            assert!(workspace.staging().is_dir());
        }

        fn create_junction(link: &Path, target: &Path) {
            let status = Command::new("cmd")
                .args(["/c", "mklink", "/J"])
                .arg(link)
                .arg(target)
                .status()
                .expect("run junction fixture command");
            assert!(status.success(), "create junction fixture");
        }
    }
}
