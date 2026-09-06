//! Pre-I/O locality authorization and post-open handle confirmation.

#[cfg(windows)]
use std::ffi::OsString;
use std::fmt;
use std::path::Path;

use cap_std::fs::Dir;

use crate::fs_boundary::FilesystemIdentity;

#[cfg(windows)]
mod windows;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalityError {
    UnsupportedPlatform,
    UnsupportedPathClass,
    GitMetadataBoundaryRejected,
    LocalityUnavailable,
    LocalVolumeNotProven,
    PreflightChanged,
    CapabilityOpenFailed,
    RemoteFilesystem,
    UnsupportedFilesystem,
    HandleVolumeMismatch,
}

impl fmt::Display for LocalityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::UnsupportedPlatform => {
                "filesystem commands are unsupported on this release platform"
            }
            Self::UnsupportedPathClass => "path class is unsupported by the locality boundary",
            Self::GitMetadataBoundaryRejected => {
                "git metadata is forbidden in a filesystem boundary path"
            }
            Self::LocalityUnavailable => "filesystem locality could not be established",
            Self::LocalVolumeNotProven => "local volume membership was not proven",
            Self::PreflightChanged => "filesystem locality changed during preflight",
            Self::CapabilityOpenFailed => "preflighted filesystem capability could not be opened",
            Self::RemoteFilesystem => "remote filesystem rejected",
            Self::UnsupportedFilesystem => "filesystem is unsupported by the release boundary",
            Self::HandleVolumeMismatch => "opened filesystem does not match the preflighted volume",
        })
    }
}

pub(crate) struct PreflightedSourcePath {
    #[cfg(windows)]
    path: crate::fs_boundary::TrustedVolumePath,
}

impl fmt::Debug for PreflightedSourcePath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreflightedSourcePath")
            .field("state", &"local-volume-selected")
            .finish_non_exhaustive()
    }
}

pub(crate) struct PreflightedOutputPath {
    #[cfg(windows)]
    parent: crate::fs_boundary::TrustedVolumePath,
    #[cfg(windows)]
    output_leaf: std::ffi::OsString,
}

impl fmt::Debug for PreflightedOutputPath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreflightedOutputPath")
            .field("state", &"local-volume-selected")
            .field("output_leaf_retained", &cfg!(windows))
            .finish_non_exhaustive()
    }
}

pub(crate) struct ConfirmedLocalSource {
    directory: Dir,
    identity: FilesystemIdentity,
}

impl ConfirmedLocalSource {
    pub(crate) fn into_directory(self) -> Dir {
        self.directory
    }

    pub(crate) fn into_parts(self) -> (Dir, FilesystemIdentity) {
        (self.directory, self.identity)
    }
}

impl fmt::Debug for ConfirmedLocalSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConfirmedLocalSource")
            .field("state", &"handle-confirmed-local-ntfs")
            .finish_non_exhaustive()
    }
}

pub(crate) struct ConfirmedLocalOutputParent {
    directory: Dir,
    output_leaf: std::ffi::OsString,
    ancestor_identities: Vec<FilesystemIdentity>,
}

/// Lexically classified three-path session-create input. Construction opens
/// no user-supplied component; only the Windows namespace/volume selection
/// phase is permitted before this value exists.
#[cfg(windows)]
pub(crate) struct PreflightedRoundTripCreatePaths {
    original: crate::fs_boundary::TrustedVolumePath,
    ai_parent: crate::fs_boundary::TrustedVolumePath,
    ai_leaf: OsString,
    state_parent: crate::fs_boundary::TrustedVolumePath,
    state_leaf: OsString,
}

#[cfg(windows)]
impl fmt::Debug for PreflightedRoundTripCreatePaths {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreflightedRoundTripCreatePaths")
            .field("state", &"three-local-volumes-selected")
            .finish_non_exhaustive()
    }
}

/// One selected path paired with a confirmed retained volume-root handle.
/// The user components remain unopened and are consumed only by the
/// alias-aware round-trip observer.
#[cfg(windows)]
pub(crate) struct ConfirmedLocalVolumePath {
    volume_root: Dir,
    components: Vec<OsString>,
    anchor: crate::fs_boundary::TrustedVolumeAnchor,
}

#[cfg(windows)]
impl ConfirmedLocalVolumePath {
    pub(crate) fn into_parts(
        self,
    ) -> (Dir, Vec<OsString>, crate::fs_boundary::TrustedVolumeAnchor) {
        (self.volume_root, self.components, self.anchor)
    }
}

#[cfg(windows)]
impl fmt::Debug for ConfirmedLocalVolumePath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConfirmedLocalVolumePath")
            .field("state", &"volume-root-confirmed-components-unopened")
            .field("component_count", &self.components.len())
            .finish_non_exhaustive()
    }
}

#[cfg(windows)]
pub(crate) struct ConfirmedRoundTripCreatePaths {
    pub(crate) original: ConfirmedLocalVolumePath,
    pub(crate) ai_parent: ConfirmedLocalVolumePath,
    pub(crate) ai_leaf: OsString,
    pub(crate) state_parent: ConfirmedLocalVolumePath,
    pub(crate) state_leaf: OsString,
}

/// Four-path apply preflight. All user path shapes and selected local volume
/// anchors are fixed before any user component is opened.
#[cfg(windows)]
pub(crate) struct PreflightedRoundTripApplyPaths {
    original: crate::fs_boundary::TrustedVolumePath,
    ai_parent: crate::fs_boundary::TrustedVolumePath,
    ai_leaf: OsString,
    state_parent: crate::fs_boundary::TrustedVolumePath,
    state_leaf: OsString,
    candidate_parent: crate::fs_boundary::TrustedVolumePath,
    candidate_leaf: OsString,
}

#[cfg(windows)]
impl fmt::Debug for PreflightedRoundTripApplyPaths {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreflightedRoundTripApplyPaths")
            .field("state", &"four-local-volumes-selected")
            .finish_non_exhaustive()
    }
}

#[cfg(windows)]
pub(crate) struct ConfirmedRoundTripApplyPaths {
    pub(crate) original: ConfirmedLocalVolumePath,
    pub(crate) ai_parent: ConfirmedLocalVolumePath,
    pub(crate) ai_leaf: OsString,
    pub(crate) state_parent: ConfirmedLocalVolumePath,
    pub(crate) state_leaf: OsString,
    pub(crate) candidate_parent: ConfirmedLocalVolumePath,
    pub(crate) candidate_leaf: OsString,
}

#[cfg(windows)]
impl fmt::Debug for ConfirmedRoundTripApplyPaths {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConfirmedRoundTripApplyPaths")
            .field("state", &"four-volume-roots-confirmed-components-unopened")
            .finish_non_exhaustive()
    }
}

#[cfg(windows)]
impl fmt::Debug for ConfirmedRoundTripCreatePaths {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConfirmedRoundTripCreatePaths")
            .field("state", &"volume-roots-confirmed-components-unopened")
            .finish_non_exhaustive()
    }
}

impl ConfirmedLocalOutputParent {
    pub(crate) fn into_parts(self) -> (Dir, std::ffi::OsString, Vec<FilesystemIdentity>) {
        (self.directory, self.output_leaf, self.ancestor_identities)
    }
}

impl fmt::Debug for ConfirmedLocalOutputParent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConfirmedLocalOutputParent")
            .field("state", &"handle-confirmed-local-ntfs")
            .field("output_leaf_retained", &true)
            .finish_non_exhaustive()
    }
}

#[cfg(windows)]
pub(crate) fn preflight_source_path(source: &Path) -> Result<PreflightedSourcePath, LocalityError> {
    windows::preflight_source_path(source)
}

#[cfg(not(windows))]
pub(crate) fn preflight_source_path(
    _source: &Path,
) -> Result<PreflightedSourcePath, LocalityError> {
    Err(LocalityError::UnsupportedPlatform)
}

#[cfg(windows)]
pub(crate) fn preflight_clone_paths(
    source: &Path,
    output: &Path,
) -> Result<(PreflightedSourcePath, PreflightedOutputPath), LocalityError> {
    windows::preflight_clone_paths(source, output)
}

#[cfg(not(windows))]
pub(crate) fn preflight_clone_paths(
    _source: &Path,
    _output: &Path,
) -> Result<(PreflightedSourcePath, PreflightedOutputPath), LocalityError> {
    Err(LocalityError::UnsupportedPlatform)
}

#[cfg(windows)]
pub(crate) fn open_and_confirm_source(
    source: PreflightedSourcePath,
) -> Result<ConfirmedLocalSource, LocalityError> {
    windows::open_and_confirm_source(source)
}

#[cfg(not(windows))]
pub(crate) fn open_and_confirm_source(
    _source: PreflightedSourcePath,
) -> Result<ConfirmedLocalSource, LocalityError> {
    Err(LocalityError::UnsupportedPlatform)
}

#[cfg(windows)]
pub(crate) fn open_and_confirm_output_parent(
    output: PreflightedOutputPath,
) -> Result<ConfirmedLocalOutputParent, LocalityError> {
    windows::open_and_confirm_output_parent(output)
}

#[cfg(windows)]
pub(crate) fn preflight_roundtrip_create_paths(
    original: &Path,
    ai_workspace: &Path,
    private_state: &Path,
) -> Result<PreflightedRoundTripCreatePaths, LocalityError> {
    windows::preflight_roundtrip_create_paths(original, ai_workspace, private_state)
}

#[cfg(windows)]
pub(crate) fn preflight_roundtrip_state_path(
    private_state: &Path,
) -> Result<PreflightedSourcePath, LocalityError> {
    windows::preflight_roundtrip_state_path(private_state)
}

#[cfg(not(windows))]
pub(crate) fn preflight_roundtrip_state_path(
    _private_state: &Path,
) -> Result<PreflightedSourcePath, LocalityError> {
    Err(LocalityError::UnsupportedPlatform)
}

#[cfg(not(windows))]
pub(crate) fn preflight_roundtrip_create_paths(
    _original: &Path,
    _ai_workspace: &Path,
    _private_state: &Path,
) -> Result<(), LocalityError> {
    Err(LocalityError::UnsupportedPlatform)
}

#[cfg(windows)]
pub(crate) fn open_and_confirm_roundtrip_volumes(
    paths: PreflightedRoundTripCreatePaths,
) -> Result<ConfirmedRoundTripCreatePaths, LocalityError> {
    windows::open_and_confirm_roundtrip_volumes(paths)
}

#[cfg(windows)]
pub(crate) fn open_and_confirm_roundtrip_state_volume(
    path: PreflightedSourcePath,
) -> Result<ConfirmedLocalVolumePath, LocalityError> {
    windows::open_and_confirm_roundtrip_state_volume(path)
}

#[cfg(windows)]
pub(crate) fn preflight_roundtrip_apply_paths(
    original: &Path,
    ai_workspace: &Path,
    private_state: &Path,
    candidate: &Path,
) -> Result<PreflightedRoundTripApplyPaths, LocalityError> {
    windows::preflight_roundtrip_apply_paths(original, ai_workspace, private_state, candidate)
}

#[cfg(windows)]
pub(crate) fn open_and_confirm_roundtrip_apply_volumes(
    paths: PreflightedRoundTripApplyPaths,
) -> Result<ConfirmedRoundTripApplyPaths, LocalityError> {
    windows::open_and_confirm_roundtrip_apply_volumes(paths)
}

#[cfg(not(windows))]
pub(crate) fn open_and_confirm_output_parent(
    _output: PreflightedOutputPath,
) -> Result<ConfirmedLocalOutputParent, LocalityError> {
    Err(LocalityError::UnsupportedPlatform)
}

#[cfg(test)]
mod tests {
    use super::LocalityError;

    #[test]
    fn locality_diagnostics_are_stable_and_raw_free() {
        let raw_values = [
            "synthetic-private-path",
            "C:",
            "HarddiskVolume",
            "Volume{",
            "provider",
        ];
        for error in [
            LocalityError::UnsupportedPlatform,
            LocalityError::UnsupportedPathClass,
            LocalityError::GitMetadataBoundaryRejected,
            LocalityError::LocalityUnavailable,
            LocalityError::LocalVolumeNotProven,
            LocalityError::PreflightChanged,
            LocalityError::CapabilityOpenFailed,
            LocalityError::RemoteFilesystem,
            LocalityError::UnsupportedFilesystem,
            LocalityError::HandleVolumeMismatch,
        ] {
            for formatted in [format!("{error:?}"), error.to_string()] {
                for raw in raw_values {
                    assert!(!formatted.contains(raw));
                }
            }
        }
    }
}
