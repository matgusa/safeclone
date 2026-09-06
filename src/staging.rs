//! Capability-relative creation of one empty, unverified staging root.

use std::ffi::{OsStr, OsString};
use std::fmt;
use std::io;
#[cfg(test)]
use std::path::Path;

use cap_fs_ext::DirExt;
use cap_std::fs::Dir;
#[cfg(unix)]
use cap_std::fs::{DirBuilder, DirBuilderExt};

#[cfg(test)]
use crate::fs_boundary::BoundaryError;
use crate::fs_boundary::{self, FilesystemIdentity};
use crate::locality::{ConfirmedLocalOutputParent, ConfirmedLocalSource};

pub const UNVERIFIED_STAGING_LEAF: &str = ".safeclone-staging-v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StagingError {
    SourceRootRejected,
    SourceIdentityUnavailable,
    OutputPathRejected,
    OutputParentRejected,
    OutputParentIdentityUnavailable,
    SourceOutputOverlap,
    FinalOutputAlreadyExists,
    FinalOutputMetadataFailed,
    OutputLeafConflictsWithStaging,
    StagingAlreadyExists,
    StagingMetadataFailed,
    StagingCreationFailed,
    StagingOpenFailed,
    StagingIdentityUnavailable,
    StagingIdentityChanged,
    StagingInspectionFailed,
    StagingNotEmpty,
    SourceCapabilityCloneFailed,
    StagingCapabilityCloneFailed,
    StagingRequiresManualInspection,
    StagingCleanupFailed,
}

impl fmt::Display for StagingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::SourceRootRejected => "source root could not be opened safely",
            Self::SourceIdentityUnavailable => "source root identity could not be established",
            Self::OutputPathRejected => "output path is not an acceptable destination",
            Self::OutputParentRejected => "output parent could not be opened safely",
            Self::OutputParentIdentityUnavailable => {
                "output parent identity could not be established"
            }
            Self::SourceOutputOverlap => "source and output boundaries overlap",
            Self::FinalOutputAlreadyExists => "final output already exists",
            Self::FinalOutputMetadataFailed => "final output absence could not be established",
            Self::OutputLeafConflictsWithStaging => {
                "final output leaf conflicts with the staging leaf"
            }
            Self::StagingAlreadyExists => "unverified staging root already exists",
            Self::StagingMetadataFailed => {
                "unverified staging root absence could not be established"
            }
            Self::StagingCreationFailed => "unverified staging root could not be created",
            Self::StagingOpenFailed => "unverified staging root could not be opened safely",
            Self::StagingIdentityUnavailable => {
                "unverified staging root identity could not be established"
            }
            Self::StagingIdentityChanged => "unverified staging root identity changed",
            Self::StagingInspectionFailed => {
                "unverified staging root could not be inspected consistently"
            }
            Self::StagingNotEmpty => "unverified staging root is not empty",
            Self::SourceCapabilityCloneFailed => "source capability could not be duplicated",
            Self::StagingCapabilityCloneFailed => "staging capability could not be duplicated",
            Self::StagingRequiresManualInspection => {
                "unpublished staging may remain; no automatic cleanup was attempted; manual inspection is required; do not retry automatically"
            }
            Self::StagingCleanupFailed => "unverified staging root cleanup failed",
        })
    }
}

pub struct UnverifiedStagingRoot {
    source: Dir,
    source_identity: FilesystemIdentity,
    parent: Dir,
    staging: Dir,
    output_leaf: OsString,
    staging_identity: FilesystemIdentity,
}

pub(crate) struct PromotionBoundaryParts {
    pub(crate) parent: Dir,
    pub(crate) staging: Option<Dir>,
    pub(crate) output_leaf: OsString,
    pub(crate) staging_identity: FilesystemIdentity,
}

enum UnpublishedStagingAuthority {
    Root {
        source: Dir,
        parent: Dir,
        staging: Dir,
        output_leaf: OsString,
        staging_identity: FilesystemIdentity,
    },
    Promotion {
        parent: Dir,
        staging: Option<Dir>,
        staging_identity: FilesystemIdentity,
    },
    Created {
        parent: Dir,
        staging: Option<Dir>,
        expected_identity: Option<FilesystemIdentity>,
    },
}

impl fmt::Debug for UnverifiedStagingRoot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UnverifiedStagingRoot")
            .field("state", &"empty-unverified")
            .field("output_leaf_retained", &true)
            .finish_non_exhaustive()
    }
}

/// Create one empty unverified staging directory next to a nonexistent final
/// output. The returned handle must be explicitly discarded or consumed by the
/// staging-tree builder.
pub(crate) fn create_unverified_staging_root(
    source: ConfirmedLocalSource,
    output: ConfirmedLocalOutputParent,
) -> Result<UnverifiedStagingRoot, StagingError> {
    create_unverified_staging_root_with_hook(source, output, |_| Ok(()))
}

impl UnverifiedStagingRoot {
    /// Consume an unpublished staging tree according to the platform cleanup
    /// policy. Windows closes the retained authorities and requires manual
    /// inspection without attempting deletion.
    pub fn discard(self) -> Result<(), StagingError> {
        let Self {
            source,
            source_identity: _,
            parent,
            staging,
            output_leaf,
            staging_identity,
        } = self;

        abandon_or_cleanup_unpublished_staging(UnpublishedStagingAuthority::Root {
            source,
            parent,
            staging,
            output_leaf,
            staging_identity,
        })
    }

    /// Dispose of only the staging authority while preserving any
    /// concurrently-created final destination. Verification and promotion
    /// failures use this seam; Windows abandons the staging tree without
    /// attempting deletion.
    pub(crate) fn discard_staging_preserving_final(self) -> Result<(), StagingError> {
        self.into_promotion_parts().discard_staging()
    }

    pub(crate) fn source_capability(&self) -> Result<Dir, StagingError> {
        self.source
            .try_clone()
            .map_err(|_| StagingError::SourceCapabilityCloneFailed)
    }

    pub(crate) fn staging_capability(&self) -> Result<Dir, StagingError> {
        self.staging
            .try_clone()
            .map_err(|_| StagingError::StagingCapabilityCloneFailed)
    }

    pub(crate) fn staging(&self) -> &Dir {
        &self.staging
    }

    pub(crate) fn parent(&self) -> &Dir {
        &self.parent
    }

    pub(crate) fn validate_current(&self) -> Result<(), StagingError> {
        if fs_boundary::directory_identity(&self.source)
            .map_err(|_| StagingError::SourceIdentityUnavailable)?
            != self.source_identity
        {
            return Err(StagingError::SourceRootRejected);
        }
        if fs_boundary::directory_identity(&self.staging)
            .map_err(|_| StagingError::StagingIdentityUnavailable)?
            != self.staging_identity
        {
            return Err(StagingError::StagingIdentityChanged);
        }
        verify_current_staging(&self.parent, self.staging_identity)?;
        ensure_absent(
            &self.parent,
            &self.output_leaf,
            StagingError::FinalOutputAlreadyExists,
            StagingError::FinalOutputMetadataFailed,
        )
    }

    /// Drop source authority and transfer only the retained publication
    /// boundary. This is available only after fresh verification.
    pub(crate) fn into_promotion_parts(self) -> PromotionBoundaryParts {
        let Self {
            source,
            source_identity: _,
            parent,
            staging,
            output_leaf,
            staging_identity,
        } = self;
        drop(source);
        PromotionBoundaryParts {
            parent,
            staging: Some(staging),
            output_leaf,
            staging_identity,
        }
    }
}

impl PromotionBoundaryParts {
    #[cfg(windows)]
    pub(crate) fn close_staging_handle(&mut self) {
        drop(self.staging.take());
    }

    pub(crate) fn discard_staging(self) -> Result<(), StagingError> {
        abandon_or_cleanup_unpublished_staging(UnpublishedStagingAuthority::Promotion {
            parent: self.parent,
            staging: self.staging,
            staging_identity: self.staging_identity,
        })
    }
}

fn create_unverified_staging_root_with_hook(
    source: ConfirmedLocalSource,
    output: ConfirmedLocalOutputParent,
    after_open: impl FnOnce(&Dir) -> Result<(), StagingError>,
) -> Result<UnverifiedStagingRoot, StagingError> {
    let (source_root, source_identity) = source.into_parts();
    let (parent, output_leaf, output_ancestor_identities) = output.into_parts();
    if output_ancestor_identities.contains(&source_identity) {
        return Err(StagingError::SourceOutputOverlap);
    }
    create_unverified_staging_root_from_parts(
        source_root,
        source_identity,
        parent,
        output_leaf,
        after_open,
    )
}

fn create_unverified_staging_root_from_parts(
    source_root: Dir,
    source_identity: FilesystemIdentity,
    parent: Dir,
    output_leaf: OsString,
    after_open: impl FnOnce(&Dir) -> Result<(), StagingError>,
) -> Result<UnverifiedStagingRoot, StagingError> {
    create_unverified_staging_root_from_parts_with_operations(
        source_root,
        source_identity,
        parent,
        output_leaf,
        after_open,
        |parent| parent.open_dir_nofollow(UNVERIFIED_STAGING_LEAF),
        fs_boundary::directory_identity,
    )
}

fn create_unverified_staging_root_from_parts_with_operations<OpenError, IdentityError>(
    source_root: Dir,
    source_identity: FilesystemIdentity,
    parent: Dir,
    output_leaf: OsString,
    after_open: impl FnOnce(&Dir) -> Result<(), StagingError>,
    open_staging: impl FnOnce(&Dir) -> Result<Dir, OpenError>,
    staging_identity: impl FnOnce(&Dir) -> Result<FilesystemIdentity, IdentityError>,
) -> Result<UnverifiedStagingRoot, StagingError> {
    if output_leaf_conflicts_with_staging(&output_leaf) {
        return Err(StagingError::OutputLeafConflictsWithStaging);
    }
    ensure_absent(
        &parent,
        &output_leaf,
        StagingError::FinalOutputAlreadyExists,
        StagingError::FinalOutputMetadataFailed,
    )?;
    ensure_absent(
        &parent,
        OsStr::new(UNVERIFIED_STAGING_LEAF),
        StagingError::StagingAlreadyExists,
        StagingError::StagingMetadataFailed,
    )?;

    create_private_directory(&parent, OsStr::new(UNVERIFIED_STAGING_LEAF))
        .map_err(|_| StagingError::StagingCreationFailed)?;
    let staging = match open_staging(&parent) {
        Ok(staging) => staging,
        Err(_) => {
            return fail_after_creation(parent, None, None, StagingError::StagingOpenFailed);
        }
    };
    let staging_identity = match staging_identity(&staging) {
        Ok(identity) => identity,
        Err(_) => {
            return fail_after_creation(
                parent,
                Some(staging),
                None,
                StagingError::StagingIdentityUnavailable,
            );
        }
    };
    if verify_current_staging(&parent, staging_identity).is_err() {
        return fail_after_creation(
            parent,
            Some(staging),
            Some(staging_identity),
            StagingError::StagingIdentityChanged,
        );
    }
    if let Err(error) = ensure_absent(
        &parent,
        &output_leaf,
        StagingError::FinalOutputAlreadyExists,
        StagingError::FinalOutputMetadataFailed,
    ) {
        return fail_after_creation(parent, Some(staging), Some(staging_identity), error);
    }
    if let Err(error) = after_open(&staging) {
        return fail_after_creation(parent, Some(staging), Some(staging_identity), error);
    }
    match directory_is_empty(&staging) {
        Ok(true) => {}
        Ok(false) => {
            return fail_after_creation(
                parent,
                Some(staging),
                Some(staging_identity),
                StagingError::StagingNotEmpty,
            );
        }
        Err(_) => {
            return fail_after_creation(
                parent,
                Some(staging),
                Some(staging_identity),
                StagingError::StagingInspectionFailed,
            );
        }
    }

    Ok(UnverifiedStagingRoot {
        source: source_root,
        source_identity,
        parent,
        staging,
        output_leaf,
        staging_identity,
    })
}

#[cfg(test)]
pub(crate) fn create_unverified_staging_root_for_test(
    source: &Path,
    output: &Path,
) -> Result<UnverifiedStagingRoot, StagingError> {
    create_unverified_staging_root_for_test_with_hook(source, output, |_| Ok(()))
}

#[cfg(test)]
fn create_unverified_staging_root_for_test_with_hook(
    source: &Path,
    output: &Path,
    after_open: impl FnOnce(&Dir) -> Result<(), StagingError>,
) -> Result<UnverifiedStagingRoot, StagingError> {
    let source_root = fs_boundary::open_ambient_dir_nofollow(source)
        .map_err(|_| StagingError::SourceRootRejected)?;
    let source_identity = fs_boundary::directory_identity(&source_root)
        .map_err(|_| StagingError::SourceIdentityUnavailable)?;
    let (parent, output_leaf) =
        fs_boundary::open_parent_nofollow_excluding(output, source_identity).map_err(|error| {
            match error {
                BoundaryError::PathRejected => StagingError::OutputPathRejected,
                BoundaryError::OpenFailed => StagingError::OutputParentRejected,
                BoundaryError::IdentityUnavailable => StagingError::OutputParentIdentityUnavailable,
                BoundaryError::ForbiddenIdentity => StagingError::SourceOutputOverlap,
            }
        })?;
    create_unverified_staging_root_from_parts(
        source_root,
        source_identity,
        parent,
        output_leaf,
        after_open,
    )
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CreationFault {
    Open,
    Identity,
}

#[cfg(test)]
fn create_unverified_staging_root_for_test_with_creation_fault(
    source: &Path,
    output: &Path,
    fault: CreationFault,
) -> Result<UnverifiedStagingRoot, StagingError> {
    let source_root = fs_boundary::open_ambient_dir_nofollow(source)
        .map_err(|_| StagingError::SourceRootRejected)?;
    let source_identity = fs_boundary::directory_identity(&source_root)
        .map_err(|_| StagingError::SourceIdentityUnavailable)?;
    let (parent, output_leaf) =
        fs_boundary::open_parent_nofollow_excluding(output, source_identity).map_err(|error| {
            match error {
                BoundaryError::PathRejected => StagingError::OutputPathRejected,
                BoundaryError::OpenFailed => StagingError::OutputParentRejected,
                BoundaryError::IdentityUnavailable => StagingError::OutputParentIdentityUnavailable,
                BoundaryError::ForbiddenIdentity => StagingError::SourceOutputOverlap,
            }
        })?;
    create_unverified_staging_root_from_parts_with_operations(
        source_root,
        source_identity,
        parent,
        output_leaf,
        |_| Ok(()),
        |parent| {
            if fault == CreationFault::Open {
                Err(io::Error::other("injected staging open failure"))
            } else {
                parent.open_dir_nofollow(UNVERIFIED_STAGING_LEAF)
            }
        },
        |staging| {
            if fault == CreationFault::Identity {
                Err(BoundaryError::IdentityUnavailable)
            } else {
                fs_boundary::directory_identity(staging)
            }
        },
    )
}

fn output_leaf_conflicts_with_staging(output_leaf: &OsStr) -> bool {
    output_leaf == OsStr::new(UNVERIFIED_STAGING_LEAF)
        || output_leaf
            .to_str()
            .is_some_and(|leaf| leaf.eq_ignore_ascii_case(UNVERIFIED_STAGING_LEAF))
}

fn ensure_absent(
    parent: &Dir,
    leaf: &OsStr,
    exists: StagingError,
    metadata_failed: StagingError,
) -> Result<(), StagingError> {
    match parent.symlink_metadata(leaf) {
        Ok(_) => Err(exists),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(metadata_failed),
    }
}

pub(crate) fn create_private_directory(parent: &Dir, name: &OsStr) -> io::Result<()> {
    #[cfg(unix)]
    {
        let mut builder = DirBuilder::new();
        builder.mode(0o700);
        parent.create_dir_with(name, &builder)
    }
    #[cfg(not(unix))]
    {
        parent.create_dir(name)
    }
}

fn verify_current_staging(parent: &Dir, expected: FilesystemIdentity) -> Result<(), StagingError> {
    let metadata = parent
        .symlink_metadata(UNVERIFIED_STAGING_LEAF)
        .map_err(|_| StagingError::StagingMetadataFailed)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || fs_boundary::metadata_identity(&metadata) != expected
    {
        return Err(StagingError::StagingIdentityChanged);
    }
    Ok(())
}

fn directory_is_empty(directory: &Dir) -> io::Result<bool> {
    let mut entries = directory.entries()?;
    match entries.next() {
        None => Ok(true),
        Some(Ok(_)) => Ok(false),
        Some(Err(error)) => Err(error),
    }
}

fn fail_after_creation(
    parent: Dir,
    staging: Option<Dir>,
    expected_identity: Option<FilesystemIdentity>,
    original: StagingError,
) -> Result<UnverifiedStagingRoot, StagingError> {
    match abandon_or_cleanup_unpublished_staging(UnpublishedStagingAuthority::Created {
        parent,
        staging,
        expected_identity,
    }) {
        Ok(()) => Err(original),
        Err(error) => Err(error),
    }
}

fn abandon_or_cleanup_unpublished_staging(
    authority: UnpublishedStagingAuthority,
) -> Result<(), StagingError> {
    platform_abandon_or_cleanup_unpublished_staging(authority)
}

#[cfg(windows)]
fn platform_abandon_or_cleanup_unpublished_staging(
    authority: UnpublishedStagingAuthority,
) -> Result<(), StagingError> {
    match authority {
        UnpublishedStagingAuthority::Root {
            source,
            parent,
            staging,
            output_leaf,
            staging_identity,
        } => drop((source, parent, staging, output_leaf, staging_identity)),
        UnpublishedStagingAuthority::Promotion {
            parent,
            staging,
            staging_identity,
        } => drop((parent, staging, staging_identity)),
        UnpublishedStagingAuthority::Created {
            parent,
            staging,
            expected_identity,
        } => drop((parent, staging, expected_identity)),
    }
    Err(StagingError::StagingRequiresManualInspection)
}

#[cfg(not(windows))]
fn platform_abandon_or_cleanup_unpublished_staging(
    authority: UnpublishedStagingAuthority,
) -> Result<(), StagingError> {
    match authority {
        UnpublishedStagingAuthority::Root {
            source,
            parent,
            staging,
            output_leaf,
            staging_identity,
        } => {
            verify_current_staging(&parent, staging_identity)
                .map_err(|_| StagingError::StagingCleanupFailed)?;
            ensure_absent(
                &parent,
                &output_leaf,
                StagingError::FinalOutputAlreadyExists,
                StagingError::FinalOutputMetadataFailed,
            )
            .map_err(|_| StagingError::StagingCleanupFailed)?;
            drop(source);
            staging
                .remove_open_dir_all()
                .map_err(|_| StagingError::StagingCleanupFailed)?;
            ensure_absent(
                &parent,
                OsStr::new(UNVERIFIED_STAGING_LEAF),
                StagingError::StagingAlreadyExists,
                StagingError::StagingMetadataFailed,
            )
            .map_err(|_| StagingError::StagingCleanupFailed)?;
            ensure_absent(
                &parent,
                &output_leaf,
                StagingError::FinalOutputAlreadyExists,
                StagingError::FinalOutputMetadataFailed,
            )
            .map_err(|_| StagingError::StagingCleanupFailed)
        }
        UnpublishedStagingAuthority::Promotion {
            parent,
            mut staging,
            staging_identity,
        } => {
            verify_current_staging(&parent, staging_identity)
                .map_err(|_| StagingError::StagingCleanupFailed)?;
            let staging = match staging.take() {
                Some(staging) => staging,
                None => parent
                    .open_dir_nofollow(UNVERIFIED_STAGING_LEAF)
                    .map_err(|_| StagingError::StagingCleanupFailed)?,
            };
            if fs_boundary::directory_identity(&staging)
                .map_err(|_| StagingError::StagingCleanupFailed)?
                != staging_identity
            {
                return Err(StagingError::StagingCleanupFailed);
            }
            staging
                .remove_open_dir_all()
                .map_err(|_| StagingError::StagingCleanupFailed)?;
            ensure_absent(
                &parent,
                OsStr::new(UNVERIFIED_STAGING_LEAF),
                StagingError::StagingAlreadyExists,
                StagingError::StagingMetadataFailed,
            )
            .map_err(|_| StagingError::StagingCleanupFailed)
        }
        UnpublishedStagingAuthority::Created {
            parent,
            staging,
            expected_identity,
        } => {
            if let Some(expected_identity) = expected_identity {
                if verify_current_staging(&parent, expected_identity).is_err() {
                    drop(staging);
                    return Err(StagingError::StagingCleanupFailed);
                }
            }
            drop(staging);
            parent
                .remove_dir(UNVERIFIED_STAGING_LEAF)
                .map_err(|_| StagingError::StagingCleanupFailed)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::{
        create_unverified_staging_root_for_test as create_unverified_staging_root,
        create_unverified_staging_root_for_test_with_hook as create_unverified_staging_root_with_hook,
    };
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_ID: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new(label: &str) -> Self {
            let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "safeclone-staging-{label}-{}-{id}",
                std::process::id()
            ));
            fs::create_dir(&path).expect("create isolated test directory");
            Self(path)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn create_source_and_parent(fixture: &TestDirectory) -> (PathBuf, PathBuf) {
        let source = fixture.0.join("source");
        let parent = fixture.0.join("destination");
        fs::create_dir(&source).expect("create source");
        fs::create_dir(&parent).expect("create output parent");
        (source, parent)
    }

    fn assert_no_staging(parent: &Path) {
        assert!(fs::symlink_metadata(parent.join(UNVERIFIED_STAGING_LEAF)).is_err());
    }

    fn assert_disposal_policy(result: Result<(), StagingError>, parent: &Path, output: &Path) {
        #[cfg(windows)]
        {
            assert_eq!(result, Err(StagingError::StagingRequiresManualInspection));
            assert!(parent.join(UNVERIFIED_STAGING_LEAF).is_dir());
        }
        #[cfg(not(windows))]
        {
            result.expect("automatic staging cleanup succeeds");
            assert_no_staging(parent);
        }
        assert!(fs::symlink_metadata(output).is_err());
    }

    fn assert_post_creation_failure(error: StagingError, original: StagingError, parent: &Path) {
        #[cfg(windows)]
        {
            let _ = original;
            assert_eq!(error, StagingError::StagingRequiresManualInspection);
            assert!(parent.join(UNVERIFIED_STAGING_LEAF).is_dir());
        }
        #[cfg(not(windows))]
        {
            assert_eq!(error, original);
            assert_no_staging(parent);
        }
    }

    #[test]
    fn valid_sibling_creates_empty_staging_and_discard_follows_platform_policy() {
        let fixture = TestDirectory::new("valid");
        let (source, parent) = create_source_and_parent(&fixture);
        let output = parent.join("final-output");
        let source_file = source.join("unchanged.rs");
        fs::write(&source_file, b"fn unchanged() {}\n").expect("write source fixture");
        let source_before = fs::read(&source_file).expect("read source before");

        let staging = create_unverified_staging_root(&source, &output).expect("create staging");
        let staging_path = parent.join(UNVERIFIED_STAGING_LEAF);
        assert!(staging_path.is_dir());
        assert!(staging
            .staging()
            .entries()
            .expect("inspect staging")
            .next()
            .is_none());
        assert!(fs::symlink_metadata(&output).is_err());
        assert_eq!(
            fs::read(&source_file).expect("read source after"),
            source_before
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let mode = fs::metadata(&staging_path)
                .expect("staging metadata")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o700);
        }

        let debug = format!("{staging:?}");
        assert!(!debug.contains("source"));
        assert!(!debug.contains("final-output"));
        assert!(debug.contains("empty-unverified"));

        assert_disposal_policy(staging.discard(), &parent, &output);
    }

    #[test]
    fn overlap_and_existing_final_outputs_are_rejected_before_creation() {
        let fixture = TestDirectory::new("boundaries");
        let (source, parent) = create_source_and_parent(&fixture);

        assert_eq!(
            create_unverified_staging_root(&source, &source).expect_err("source is output"),
            StagingError::FinalOutputAlreadyExists
        );
        assert_eq!(
            create_unverified_staging_root(&source, &source.join("inside"))
                .expect_err("output inside source"),
            StagingError::SourceOutputOverlap
        );

        let file_output = parent.join("existing-file");
        fs::write(&file_output, b"untouched").expect("create output file");
        assert_eq!(
            create_unverified_staging_root(&source, &file_output)
                .expect_err("existing file rejected"),
            StagingError::FinalOutputAlreadyExists
        );
        assert_eq!(fs::read(&file_output).expect("file remains"), b"untouched");

        let directory_output = parent.join("existing-directory");
        fs::create_dir(&directory_output).expect("create output directory");
        assert_eq!(
            create_unverified_staging_root(&source, &directory_output)
                .expect_err("existing directory rejected"),
            StagingError::FinalOutputAlreadyExists
        );
        assert_no_staging(&parent);
    }

    #[test]
    fn lexical_normalization_does_not_bypass_identity_overlap() {
        let fixture = TestDirectory::new("identity");
        let source = fixture.0.join("source");
        fs::create_dir(&source).expect("create source");
        let spelled_source = fixture.0.join(".").join("source");
        let output = source.join(".").join("final-output");

        assert_eq!(
            create_unverified_staging_root(&spelled_source, &output)
                .expect_err("same directory identity is rejected"),
            StagingError::SourceOutputOverlap
        );
        assert_no_staging(&source);
    }

    #[test]
    fn output_leaf_must_not_alias_the_fixed_staging_leaf() {
        let fixture = TestDirectory::new("reserved-leaf");
        let (source, parent) = create_source_and_parent(&fixture);
        for leaf in [UNVERIFIED_STAGING_LEAF, ".SAFECLONE-STAGING-V1"] {
            assert_eq!(
                create_unverified_staging_root(&source, &parent.join(leaf))
                    .expect_err("reserved leaf rejected"),
                StagingError::OutputLeafConflictsWithStaging
            );
        }
        assert_no_staging(&parent);
    }

    #[test]
    fn root_output_and_missing_parent_are_rejected() {
        let fixture = TestDirectory::new("invalid-output");
        let source = fixture.0.join("source");
        fs::create_dir(&source).expect("create source");
        let filesystem_root = fixture
            .0
            .ancestors()
            .last()
            .expect("fixture has filesystem root");
        assert_eq!(
            create_unverified_staging_root(&source, filesystem_root)
                .expect_err("filesystem root rejected"),
            StagingError::OutputPathRejected
        );
        assert_eq!(
            create_unverified_staging_root(
                &source,
                &fixture.0.join("missing-parent").join("output"),
            )
            .expect_err("missing parent rejected"),
            StagingError::OutputParentRejected
        );
    }

    #[test]
    fn preexisting_staging_file_and_directory_are_rejected_and_untouched() {
        let fixture = TestDirectory::new("stale");
        let source = fixture.0.join("source");
        fs::create_dir(&source).expect("create source");

        let file_parent = fixture.0.join("file-parent");
        fs::create_dir(&file_parent).expect("create file parent");
        let staging_file = file_parent.join(UNVERIFIED_STAGING_LEAF);
        fs::write(&staging_file, b"stale").expect("create stale file");
        assert_eq!(
            create_unverified_staging_root(&source, &file_parent.join("output"))
                .expect_err("stale file rejected"),
            StagingError::StagingAlreadyExists
        );
        assert_eq!(
            fs::read(&staging_file).expect("stale file remains"),
            b"stale"
        );

        let directory_parent = fixture.0.join("directory-parent");
        fs::create_dir(&directory_parent).expect("create directory parent");
        let staging_directory = directory_parent.join(UNVERIFIED_STAGING_LEAF);
        fs::create_dir(&staging_directory).expect("create stale directory");
        fs::write(staging_directory.join("marker"), b"untouched").expect("write marker");
        assert_eq!(
            create_unverified_staging_root(&source, &directory_parent.join("output"))
                .expect_err("stale directory rejected"),
            StagingError::StagingAlreadyExists
        );
        assert_eq!(
            fs::read(staging_directory.join("marker")).expect("marker remains"),
            b"untouched"
        );
    }

    #[test]
    fn post_creation_failures_follow_the_platform_abandonment_policy() {
        let empty_fixture = TestDirectory::new("empty-post-creation-failure");
        let (source, parent) = create_source_and_parent(&empty_fixture);
        let output = parent.join("output");
        let error = create_unverified_staging_root_with_hook(&source, &output, |_| {
            Err(StagingError::StagingInspectionFailed)
        })
        .expect_err("post-create failure");
        assert_post_creation_failure(error, StagingError::StagingInspectionFailed, &parent);
        assert!(fs::symlink_metadata(&output).is_err());

        #[cfg(windows)]
        assert_eq!(
            create_unverified_staging_root(&source, &output)
                .expect_err("later run rejects stale staging"),
            StagingError::StagingAlreadyExists
        );

        let populated_fixture = TestDirectory::new("populated-post-creation-failure");
        let (source, parent) = create_source_and_parent(&populated_fixture);
        let output = parent.join("output");
        let error = create_unverified_staging_root_with_hook(&source, &output, |staging| {
            staging
                .write("unexpected", b"test-only entry")
                .expect("create unexpected entry");
            Err(StagingError::StagingInspectionFailed)
        })
        .expect_err("populated post-create failure");
        #[cfg(windows)]
        assert_eq!(error, StagingError::StagingRequiresManualInspection);
        #[cfg(not(windows))]
        assert_eq!(error, StagingError::StagingCleanupFailed);
        assert_eq!(
            fs::read(parent.join(UNVERIFIED_STAGING_LEAF).join("unexpected"))
                .expect("unexpected entry remains"),
            b"test-only entry"
        );
        assert!(fs::symlink_metadata(&output).is_err());
    }

    #[test]
    fn staging_open_and_identity_failures_after_creation_are_manual_on_windows() {
        for fault in [CreationFault::Open, CreationFault::Identity] {
            let fixture = TestDirectory::new(match fault {
                CreationFault::Open => "open-failure",
                CreationFault::Identity => "identity-failure",
            });
            let (source, parent) = create_source_and_parent(&fixture);
            let output = parent.join("output");

            let error = create_unverified_staging_root_for_test_with_creation_fault(
                &source, &output, fault,
            )
            .expect_err("injected post-creation failure");

            #[cfg(windows)]
            {
                assert_eq!(error, StagingError::StagingRequiresManualInspection);
                assert!(parent.join(UNVERIFIED_STAGING_LEAF).is_dir());
            }
            #[cfg(not(windows))]
            {
                assert_eq!(
                    error,
                    match fault {
                        CreationFault::Open => StagingError::StagingOpenFailed,
                        CreationFault::Identity => StagingError::StagingIdentityUnavailable,
                    }
                );
                assert_no_staging(&parent);
            }
            assert!(fs::symlink_metadata(output).is_err());
        }
    }

    #[cfg(windows)]
    #[test]
    fn final_inserted_after_creation_is_preserved_and_requires_manual_inspection_on_windows() {
        let fixture = TestDirectory::new("final-after-create");
        let (source, parent) = create_source_and_parent(&fixture);
        let output = parent.join("output");
        let staging = create_unverified_staging_root_with_hook(&source, &output, |_| {
            fs::write(&output, b"unrelated final").expect("insert final after staging creation");
            Ok(())
        })
        .expect("boundary creation completes after the test hook");
        assert_eq!(
            staging.validate_current(),
            Err(StagingError::FinalOutputAlreadyExists)
        );
        let error = staging
            .discard()
            .expect_err("raced final requires abandonment");

        assert_eq!(error, StagingError::StagingRequiresManualInspection);
        assert!(parent.join(UNVERIFIED_STAGING_LEAF).is_dir());
        assert_eq!(
            fs::read(&output).expect("unrelated final remains"),
            b"unrelated final"
        );
    }

    #[cfg(windows)]
    #[test]
    fn namespace_replacement_model_abandons_empty_and_nonempty_trees_without_deletion() {
        for populated in [false, true] {
            let fixture = TestDirectory::new(if populated {
                "replacement-nonempty"
            } else {
                "replacement-empty"
            });
            let (source, parent) = create_source_and_parent(&fixture);
            let output = parent.join("output");
            let staging = create_unverified_staging_root(&source, &output).expect("create staging");
            if populated {
                staging
                    .staging()
                    .write("original-marker", b"original")
                    .expect("populate original staging");
            }
            let mut parts = staging.into_promotion_parts();
            parts.close_staging_handle();
            let staging_path = parent.join(UNVERIFIED_STAGING_LEAF);
            let moved = parent.join("moved-expected-staging");
            fs::rename(&staging_path, &moved).expect("move expected synthetic staging");
            fs::create_dir(&staging_path).expect("insert replacement staging");
            if populated {
                fs::write(staging_path.join("replacement-marker"), b"replacement")
                    .expect("populate replacement staging");
            }

            assert_eq!(
                parts.discard_staging(),
                Err(StagingError::StagingRequiresManualInspection)
            );
            assert!(moved.is_dir());
            assert!(staging_path.is_dir());
            if populated {
                assert_eq!(
                    fs::read(moved.join("original-marker")).expect("original remains"),
                    b"original"
                );
                assert_eq!(
                    fs::read(staging_path.join("replacement-marker")).expect("replacement remains"),
                    b"replacement"
                );
            }
            assert!(fs::symlink_metadata(&output).is_err());
        }
    }

    #[test]
    fn errors_and_debug_do_not_expose_source_or_output_paths() {
        let fixture = TestDirectory::new("raw-leak");
        let source_name = "synthetic-private-source-name";
        let output_name = "synthetic-private-output-name";
        let source = fixture.0.join(source_name);
        fs::create_dir(&source).expect("create source");
        let output = fixture.0.join("missing-parent").join(output_name);
        let error = create_unverified_staging_root(&source, &output).expect_err("reject output");
        let display = error.to_string();
        let debug = format!("{error:?}");
        for raw in [source_name, output_name] {
            assert!(!display.contains(raw));
            assert!(!debug.contains(raw));
        }

        let manual = StagingError::StagingRequiresManualInspection;
        assert!(manual.to_string().contains("do not retry automatically"));
        for raw in [source_name, output_name] {
            assert!(!manual.to_string().contains(raw));
            assert!(!format!("{manual:?}").contains(raw));
        }
    }

    #[cfg(unix)]
    #[test]
    fn unix_symlink_boundaries_and_stale_staging_are_rejected() {
        use std::os::unix::fs::symlink;

        let fixture = TestDirectory::new("unix-links");
        let source = fixture.0.join("source");
        let target_parent = fixture.0.join("target-parent");
        fs::create_dir(&source).expect("create source");
        fs::create_dir(&target_parent).expect("create target parent");

        let source_link = fixture.0.join("source-link");
        symlink(&source, &source_link).expect("create source symlink");
        assert_eq!(
            create_unverified_staging_root(&source_link, &target_parent.join("output"))
                .expect_err("source symlink rejected"),
            StagingError::SourceRootRejected
        );

        let parent_link = fixture.0.join("parent-link");
        symlink(&target_parent, &parent_link).expect("create parent symlink");
        assert_eq!(
            create_unverified_staging_root(&source, &parent_link.join("output"))
                .expect_err("parent symlink rejected"),
            StagingError::OutputParentRejected
        );

        let final_link = target_parent.join("existing-link");
        symlink(&source, &final_link).expect("create final symlink");
        assert_eq!(
            create_unverified_staging_root(&source, &final_link)
                .expect_err("final symlink rejected"),
            StagingError::FinalOutputAlreadyExists
        );

        let stale_parent = fixture.0.join("stale-parent");
        fs::create_dir(&stale_parent).expect("create stale parent");
        let stale_link = stale_parent.join(UNVERIFIED_STAGING_LEAF);
        symlink(&source, &stale_link).expect("create stale staging symlink");
        assert_eq!(
            create_unverified_staging_root(&source, &stale_parent.join("output"))
                .expect_err("stale staging symlink rejected"),
            StagingError::StagingAlreadyExists
        );
        assert!(fs::symlink_metadata(&stale_link)
            .expect("stale link remains")
            .file_type()
            .is_symlink());
    }

    #[cfg(windows)]
    #[test]
    fn windows_junction_boundaries_and_stale_staging_are_rejected() {
        let fixture = TestDirectory::new("windows-junctions");
        let source = fixture.0.join("source");
        let target_parent = fixture.0.join("target-parent");
        fs::create_dir(&source).expect("create source");
        fs::create_dir(&target_parent).expect("create target parent");

        let source_junction = fixture.0.join("source-junction");
        create_junction(&source_junction, &source);
        assert_eq!(
            create_unverified_staging_root(&source_junction, &target_parent.join("output"))
                .expect_err("source junction rejected"),
            StagingError::SourceRootRejected
        );

        let parent_junction = fixture.0.join("parent-junction");
        create_junction(&parent_junction, &target_parent);
        assert_eq!(
            create_unverified_staging_root(&source, &parent_junction.join("output"))
                .expect_err("parent junction rejected"),
            StagingError::OutputParentRejected
        );

        let final_junction = target_parent.join("existing-junction");
        create_junction(&final_junction, &source);
        assert_eq!(
            create_unverified_staging_root(&source, &final_junction)
                .expect_err("final junction rejected"),
            StagingError::FinalOutputAlreadyExists
        );

        let stale_parent = fixture.0.join("stale-parent");
        fs::create_dir(&stale_parent).expect("create stale parent");
        let stale_junction = stale_parent.join(UNVERIFIED_STAGING_LEAF);
        create_junction(&stale_junction, &source);
        assert_eq!(
            create_unverified_staging_root(&source, &stale_parent.join("output"))
                .expect_err("stale staging junction rejected"),
            StagingError::StagingAlreadyExists
        );
        assert!(fs::symlink_metadata(&stale_junction).is_ok());
    }

    #[cfg(windows)]
    fn create_junction(link: &Path, target: &Path) {
        let status = std::process::Command::new("cmd")
            .args(["/c", "mklink", "/J"])
            .arg(link)
            .arg(target)
            .status()
            .expect("run mklink");
        assert!(status.success(), "create junction fixture");
    }
}
