//! Independent verification of an unverified sanitized staging tree.
//!
//! Verification deliberately owns the unverified tree and performs a fresh,
//! output-only walk. A successful value is a type-state transition, not a
//! forgeable boolean/report publication gate.

use std::ffi::OsStr;
use std::fmt;
use std::io::Read;
use std::path::Path;

use cap_fs_ext::{DirExt, FollowSymlinks, MetadataExt, OpenOptionsFollowExt};
use cap_std::fs::{Dir, OpenOptions};

use crate::content;
use crate::detection::{classify_path, is_git_metadata_component, DetectedKind};
use crate::filename::{self, FilenameError, Session as FilenameSession};
use crate::fs_boundary;
use crate::inventory;
use crate::path_evidence::{
    self, ComponentKind, PathEvidenceError, Session as PathEvidenceSession,
};
use crate::path_transform::{self, PathTransformError};
use crate::secrets::{self, SecretError, Session as SecretSession};
use crate::sensitive::{self, SensitiveError, Session as SensitiveSession};
use crate::staging::{StagingError, UnverifiedStagingRoot};
use crate::staging_tree::UnverifiedStagedTree;
use crate::transform;

pub const DEFAULT_MAX_TOTAL_STAGED_BYTES: usize =
    content::DEFAULT_MAX_TOTAL_BYTES * transform::MAX_REPLACEMENT_MARKER_BYTES;

/// Independent output-only verification limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerificationLimits {
    pub max_depth: usize,
    pub max_entries: usize,
    pub max_file_bytes: usize,
    pub max_total_bytes: usize,
    pub filename: filename::Limits,
    pub path_evidence: path_evidence::Limits,
    pub secrets: secrets::Limits,
    pub sensitive: sensitive::Limits,
}

impl Default for VerificationLimits {
    fn default() -> Self {
        Self {
            max_depth: inventory::DEFAULT_MAX_DEPTH,
            max_entries: inventory::DEFAULT_MAX_ENTRIES,
            max_file_bytes: transform::DEFAULT_MAX_OUTPUT_BYTES_PER_FILE,
            max_total_bytes: DEFAULT_MAX_TOTAL_STAGED_BYTES,
            filename: filename::Limits::default(),
            path_evidence: path_evidence::Limits::default(),
            secrets: secrets::Limits::default(),
            sensitive: sensitive::Limits::default(),
        }
    }
}

/// Raw-free aggregate evidence produced only after a complete independent
/// verification walk.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct VerificationReport {
    pub files_verified: usize,
    pub directories_verified: usize,
    pub bytes_verified: usize,
    pub filename_components_scanned: usize,
    pub path_components_scanned: usize,
    pub content_files_scanned: usize,
}

/// Verification failures are intentionally descriptive but never carry a
/// source path, component, content value, or detector match.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerificationError {
    Boundary(StagingError),
    Filename(FilenameError),
    PathEvidence(PathEvidenceError),
    PathTransform(PathTransformError),
    Secret(SecretError),
    Sensitive(SensitiveError),
    CountOverflow,
    InconsistentCounts,
    EntryLimitExceeded,
    DepthLimitExceeded,
    UninspectableComponent,
    GitMetadataFound,
    UnexpectedEntryType,
    DirectoryOpenFailed,
    DirectoryIdentityChanged,
    UnsupportedFile,
    UnknownFile,
    FilenameFindingDetected,
    PathFindingDetected,
    FileOpenFailed,
    FileIdentityChanged,
    HardLinkedFile,
    FileTooLarge,
    ReadFailed,
    TotalBytesExceeded,
    NulByte,
    InvalidUtf8,
    SecretFindingDetected,
    SensitiveFindingDetected,
    StagedBytesExceeded,
    StagedByteMismatch,
    ManualInspectionRequired,
    VerificationCleanupFailed,
}

impl fmt::Display for VerificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Boundary(error) => error.fmt(formatter),
            Self::Filename(error) => error.fmt(formatter),
            Self::PathEvidence(error) => error.fmt(formatter),
            Self::PathTransform(error) => error.fmt(formatter),
            Self::Secret(error) => error.fmt(formatter),
            Self::Sensitive(error) => error.fmt(formatter),
            Self::CountOverflow => formatter.write_str("verification arithmetic overflowed"),
            Self::InconsistentCounts => {
                formatter.write_str("staged verification observations are inconsistent")
            }
            Self::EntryLimitExceeded => formatter.write_str("verification entry limit exceeded"),
            Self::DepthLimitExceeded => formatter.write_str("verification depth limit exceeded"),
            Self::UninspectableComponent => {
                formatter.write_str("staged component is not inspectable Unicode")
            }
            Self::GitMetadataFound => {
                formatter.write_str("staged repository metadata is not allowed")
            }
            Self::UnexpectedEntryType => formatter.write_str("staged entry type is not allowed"),
            Self::DirectoryOpenFailed => {
                formatter.write_str("staged directory could not be opened safely")
            }
            Self::DirectoryIdentityChanged => {
                formatter.write_str("staged directory identity changed unexpectedly")
            }
            Self::UnsupportedFile => formatter.write_str("staged file format is unsupported"),
            Self::UnknownFile => formatter.write_str("staged file format is unknown"),
            Self::FilenameFindingDetected => {
                formatter.write_str("staged filename evidence was detected")
            }
            Self::PathFindingDetected => {
                formatter.write_str("staged path-component evidence was detected")
            }
            Self::FileOpenFailed => formatter.write_str("staged file could not be opened safely"),
            Self::FileIdentityChanged => {
                formatter.write_str("staged file identity changed unexpectedly")
            }
            Self::HardLinkedFile => formatter.write_str("staged file is hard-linked"),
            Self::FileTooLarge => formatter.write_str("staged file exceeds the verification limit"),
            Self::ReadFailed => formatter.write_str("staged file could not be read consistently"),
            Self::TotalBytesExceeded => formatter.write_str("staged byte limit exceeded"),
            Self::NulByte => formatter.write_str("staged text contains a NUL byte"),
            Self::InvalidUtf8 => formatter.write_str("staged file is not valid UTF-8"),
            Self::SecretFindingDetected => {
                formatter.write_str("staged secret evidence was detected")
            }
            Self::SensitiveFindingDetected => {
                formatter.write_str("staged sensitive-identifier evidence was detected")
            }
            Self::StagedBytesExceeded => {
                formatter.write_str("builder staged bytes exceed the verification ceiling")
            }
            Self::StagedByteMismatch => {
                formatter.write_str("verified staged bytes do not match builder observations")
            }
            Self::ManualInspectionRequired => formatter.write_str(
                "unpublished staging may remain; no automatic cleanup was attempted; manual inspection is required; do not retry automatically",
            ),
            Self::VerificationCleanupFailed => formatter.write_str("verification cleanup failed"),
        }
    }
}

/// A verified, still-unpublished staging tree. Its fields and constructor are
/// private; only a successful verification can create this state.
pub struct VerifiedStagedTree {
    boundary: UnverifiedStagingRoot,
    report: VerificationReport,
}

impl fmt::Debug for VerifiedStagedTree {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedStagedTree")
            .field("report", &self.report)
            .field("state", &"verified-unpublished")
            .finish_non_exhaustive()
    }
}

impl VerifiedStagedTree {
    /// Read the raw-free aggregate produced by the successful verification.
    pub fn report(&self) -> VerificationReport {
        self.report
    }

    /// Explicitly dispose of the verified-but-unpublished staging tree
    /// according to the platform cleanup policy.
    pub fn discard(self) -> Result<(), VerificationError> {
        self.boundary
            .discard_staging_preserving_final()
            .map_err(map_staging_disposal_error)
    }

    pub(crate) fn into_boundary_and_report(self) -> (UnverifiedStagingRoot, VerificationReport) {
        (self.boundary, self.report)
    }
}

/// Verify an unverified staging tree using only fresh reads from staging.
///
/// The source capability is retained only for boundary identity checks; no
/// source content is reopened or scanned. Failure consumes the input tree and
/// applies the platform cleanup or abandonment policy.
pub fn verify_unverified_staged_tree(
    tree: UnverifiedStagedTree,
    limits: VerificationLimits,
) -> Result<VerifiedStagedTree, VerificationError> {
    let (boundary, expected_files, expected_directories, expected_bytes) =
        tree.into_verification_parts();
    verify_owned_boundary(
        boundary,
        expected_files,
        expected_directories,
        expected_bytes,
        limits,
    )
}

/// Consume point-in-time verified evidence and independently verify the
/// actual staging tree again. Promotion is the only current caller.
pub(crate) fn reverify_verified_staged_tree(
    verified: VerifiedStagedTree,
    limits: VerificationLimits,
) -> Result<VerifiedStagedTree, VerificationError> {
    let (boundary, report) = verified.into_boundary_and_report();
    verify_owned_boundary(
        boundary,
        report.files_verified,
        report.directories_verified,
        report.bytes_verified,
        limits,
    )
}

fn verify_owned_boundary(
    boundary: UnverifiedStagingRoot,
    expected_files: usize,
    expected_directories: usize,
    expected_bytes: usize,
    limits: VerificationLimits,
) -> Result<VerifiedStagedTree, VerificationError> {
    let result = (|| {
        boundary
            .validate_current()
            .map_err(VerificationError::Boundary)?;
        let report = verify_inner(
            &boundary,
            expected_files,
            expected_directories,
            expected_bytes,
            limits,
        )?;
        boundary
            .validate_current()
            .map_err(VerificationError::Boundary)?;
        Ok(report)
    })();

    match result {
        Ok(report) => Ok(VerifiedStagedTree { boundary, report }),
        Err(error) => match boundary.discard_staging_preserving_final() {
            Ok(()) => Err(error),
            Err(disposal_error) => Err(map_staging_disposal_error(disposal_error)),
        },
    }
}

const fn map_staging_disposal_error(error: StagingError) -> VerificationError {
    match error {
        StagingError::StagingRequiresManualInspection => {
            VerificationError::ManualInspectionRequired
        }
        _ => VerificationError::VerificationCleanupFailed,
    }
}

struct VerificationState {
    limits: VerificationLimits,
    filename: FilenameSession,
    path_evidence: PathEvidenceSession,
    secrets: SecretSession,
    sensitive: SensitiveSession,
    expected_bytes: usize,
    entries_seen: usize,
    report: VerificationReport,
}

impl VerificationState {
    fn new(limits: VerificationLimits) -> Result<Self, VerificationError> {
        Ok(Self {
            limits,
            filename: FilenameSession::new(limits.filename),
            path_evidence: PathEvidenceSession::new(limits.path_evidence)
                .map_err(VerificationError::PathEvidence)?,
            secrets: SecretSession::new(limits.secrets).map_err(VerificationError::Secret)?,
            sensitive: SensitiveSession::new(limits.sensitive)
                .map_err(VerificationError::Sensitive)?,
            expected_bytes: 0,
            entries_seen: 0,
            report: VerificationReport::default(),
        })
    }

    fn record_entry(&mut self) -> Result<(), VerificationError> {
        self.entries_seen = self
            .entries_seen
            .checked_add(1)
            .ok_or(VerificationError::CountOverflow)?;
        if self.entries_seen > self.limits.max_entries {
            return Err(VerificationError::EntryLimitExceeded);
        }
        Ok(())
    }

    fn scan_directory_component(&mut self, text: &str) -> Result<(), VerificationError> {
        let mut secret_findings = 0_usize;
        let mut sensitive_findings = 0_usize;
        let inspectability = self
            .path_evidence
            .scan_component_with_findings(
                OsStr::new(text),
                ComponentKind::Directory,
                |secrets, sensitive| {
                    secret_findings = secrets.len();
                    sensitive_findings = sensitive.len();
                },
            )
            .map_err(VerificationError::PathEvidence)?;
        if inspectability != crate::detection::ComponentInspectability::Inspectable {
            return Err(VerificationError::UninspectableComponent);
        }
        if secret_findings != 0 || sensitive_findings != 0 {
            return Err(VerificationError::PathFindingDetected);
        }
        self.report.path_components_scanned = self
            .report
            .path_components_scanned
            .checked_add(1)
            .ok_or(VerificationError::CountOverflow)?;
        Ok(())
    }

    fn scan_file_component(&mut self, name: &str) -> Result<(), VerificationError> {
        let mut filename_findings = 0_usize;
        self.filename
            .scan_basename(OsStr::new(name), |findings| {
                filename_findings = findings.len();
            })
            .map_err(VerificationError::Filename)?;
        if filename_findings != 0 {
            return Err(VerificationError::FilenameFindingDetected);
        }
        self.report.filename_components_scanned = self
            .report
            .filename_components_scanned
            .checked_add(1)
            .ok_or(VerificationError::CountOverflow)?;

        let (stem, _suffix) = path_transform::split_transformable_file_component(name)
            .map_err(VerificationError::PathTransform)?;
        let mut secret_findings = 0_usize;
        let mut sensitive_findings = 0_usize;
        let inspectability = self
            .path_evidence
            .scan_component_with_findings(
                OsStr::new(stem),
                ComponentKind::File,
                |secrets, sensitive| {
                    secret_findings = secrets.len();
                    sensitive_findings = sensitive.len();
                },
            )
            .map_err(VerificationError::PathEvidence)?;
        if inspectability != crate::detection::ComponentInspectability::Inspectable {
            return Err(VerificationError::UninspectableComponent);
        }
        if secret_findings != 0 || sensitive_findings != 0 {
            return Err(VerificationError::PathFindingDetected);
        }
        self.report.path_components_scanned = self
            .report
            .path_components_scanned
            .checked_add(1)
            .ok_or(VerificationError::CountOverflow)?;
        Ok(())
    }

    fn record_file(&mut self, bytes: usize) -> Result<(), VerificationError> {
        let next_bytes = self
            .report
            .bytes_verified
            .checked_add(bytes)
            .ok_or(VerificationError::CountOverflow)?;
        if next_bytes > self.limits.max_total_bytes {
            return Err(VerificationError::TotalBytesExceeded);
        }
        if next_bytes > self.expected_bytes {
            return Err(VerificationError::StagedByteMismatch);
        }
        self.report.bytes_verified = next_bytes;
        self.report.files_verified = self
            .report
            .files_verified
            .checked_add(1)
            .ok_or(VerificationError::CountOverflow)?;
        self.report.content_files_scanned = self
            .report
            .content_files_scanned
            .checked_add(1)
            .ok_or(VerificationError::CountOverflow)?;
        Ok(())
    }

    fn record_directory(&mut self) -> Result<(), VerificationError> {
        self.report.directories_verified = self
            .report
            .directories_verified
            .checked_add(1)
            .ok_or(VerificationError::CountOverflow)?;
        Ok(())
    }

    fn finish(
        self,
        expected_files: usize,
        expected_directories: usize,
        expected_bytes: usize,
    ) -> Result<VerificationReport, VerificationError> {
        let filename = self
            .filename
            .finish()
            .map_err(VerificationError::Filename)?;
        let path = self
            .path_evidence
            .finish()
            .map_err(VerificationError::PathEvidence)?;
        let secrets = self.secrets.finish().map_err(VerificationError::Secret)?;
        let sensitive = self
            .sensitive
            .finish()
            .map_err(VerificationError::Sensitive)?;
        let expected_entries = expected_files
            .checked_add(expected_directories)
            .ok_or(VerificationError::CountOverflow)?;
        if self.report.bytes_verified != expected_bytes {
            return Err(VerificationError::StagedByteMismatch);
        }
        if self.report.files_verified != expected_files
            || self.report.directories_verified != expected_directories
            || self.entries_seen != expected_entries
            || filename.scan_candidates != self.report.filename_components_scanned
            || filename.uninspectable != 0
            || path.scan_candidates != self.report.path_components_scanned
            || path.uninspectable != 0
            || secrets.scan_candidates != self.report.content_files_scanned
            || sensitive.scan_candidates != self.report.content_files_scanned
            || secrets.findings != 0
            || sensitive.findings != 0
        {
            return Err(VerificationError::InconsistentCounts);
        }
        Ok(self.report)
    }
}

fn verify_inner(
    boundary: &UnverifiedStagingRoot,
    expected_files: usize,
    expected_directories: usize,
    expected_bytes: usize,
    limits: VerificationLimits,
) -> Result<VerificationReport, VerificationError> {
    let derived_ceiling = content::DEFAULT_MAX_TOTAL_BYTES
        .checked_mul(transform::MAX_REPLACEMENT_MARKER_BYTES)
        .ok_or(VerificationError::CountOverflow)?;
    if limits.max_total_bytes > derived_ceiling || expected_bytes > limits.max_total_bytes {
        return Err(VerificationError::StagedBytesExceeded);
    }
    let expected_entries = expected_files
        .checked_add(expected_directories)
        .ok_or(VerificationError::CountOverflow)?;
    if expected_entries > limits.max_entries {
        return Err(VerificationError::EntryLimitExceeded);
    }

    let mut state = VerificationState::new(limits)?;
    state.expected_bytes = expected_bytes;
    let staging = boundary
        .staging_capability()
        .map_err(VerificationError::Boundary)?;
    verify_directory(&mut state, staging, 0)?;
    state.finish(expected_files, expected_directories, expected_bytes)
}

fn verify_directory(
    state: &mut VerificationState,
    directory: Dir,
    depth: usize,
) -> Result<(), VerificationError> {
    let entries = directory
        .entries()
        .map_err(|_| VerificationError::DirectoryOpenFailed)?;
    for entry in entries {
        let entry = entry.map_err(|_| VerificationError::DirectoryOpenFailed)?;
        state.record_entry()?;
        let name = entry.file_name();
        if is_git_metadata_component(&name) {
            return Err(VerificationError::GitMetadataFound);
        }
        let name_text = name
            .to_str()
            .ok_or(VerificationError::UninspectableComponent)?;
        let file_type = entry
            .file_type()
            .map_err(|_| VerificationError::UnexpectedEntryType)?;
        if file_type.is_symlink() {
            return Err(VerificationError::UnexpectedEntryType);
        }
        if file_type.is_dir() {
            let child_depth = depth
                .checked_add(1)
                .ok_or(VerificationError::CountOverflow)?;
            if child_depth > state.limits.max_depth {
                return Err(VerificationError::DepthLimitExceeded);
            }
            let child = directory
                .open_dir_nofollow(&name)
                .map_err(|_| VerificationError::DirectoryOpenFailed)?;
            validate_directory_identity(&directory, &name, &child)?;
            state.scan_directory_component(name_text)?;
            state.record_directory()?;
            verify_directory(state, child, child_depth)?;
        } else if file_type.is_file() {
            verify_regular_file(state, &directory, &name, name_text)?;
        } else {
            return Err(VerificationError::UnexpectedEntryType);
        }
    }
    Ok(())
}

fn verify_regular_file(
    state: &mut VerificationState,
    parent: &Dir,
    name: &OsStr,
    name_text: &str,
) -> Result<(), VerificationError> {
    match classify_path(Path::new(name), false) {
        DetectedKind::TextOrCodeCandidate => {}
        DetectedKind::Unsupported => return Err(VerificationError::UnsupportedFile),
        DetectedKind::Unknown => return Err(VerificationError::UnknownFile),
        DetectedKind::LinkLikeEntry | DetectedKind::GitMetadata => {
            return Err(VerificationError::UnexpectedEntryType)
        }
    }
    state.scan_file_component(name_text)?;
    verify_file_content(state, parent, name)
}

fn verify_file_content(
    state: &mut VerificationState,
    parent: &Dir,
    name: &OsStr,
) -> Result<(), VerificationError> {
    let mut options = OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    let mut file = parent
        .open_with(name, &options)
        .map_err(|_| VerificationError::FileOpenFailed)?;
    let opened_before = file
        .metadata()
        .map_err(|_| VerificationError::FileOpenFailed)?;
    validate_opened_file(parent, name, &opened_before)?;
    let max_file_bytes =
        u64::try_from(state.limits.max_file_bytes).map_err(|_| VerificationError::CountOverflow)?;
    if opened_before.len() > max_file_bytes {
        return Err(VerificationError::FileTooLarge);
    }

    let remaining_total = state
        .limits
        .max_total_bytes
        .checked_sub(state.report.bytes_verified)
        .ok_or(VerificationError::TotalBytesExceeded)?;
    let file_probe = state
        .limits
        .max_file_bytes
        .checked_add(1)
        .ok_or(VerificationError::CountOverflow)?;
    let total_probe = remaining_total
        .checked_add(1)
        .ok_or(VerificationError::CountOverflow)?;
    let read_limit =
        u64::try_from(file_probe.min(total_probe)).map_err(|_| VerificationError::CountOverflow)?;
    let mut bytes = Vec::new();
    file.by_ref()
        .take(read_limit)
        .read_to_end(&mut bytes)
        .map_err(|_| VerificationError::ReadFailed)?;
    if bytes.len() > state.limits.max_file_bytes {
        return Err(VerificationError::FileTooLarge);
    }
    if bytes.len() > remaining_total {
        return Err(VerificationError::TotalBytesExceeded);
    }
    let opened_after = file
        .metadata()
        .map_err(|_| VerificationError::FileIdentityChanged)?;
    validate_opened_file(parent, name, &opened_after)?;
    let bytes_len = u64::try_from(bytes.len()).map_err(|_| VerificationError::CountOverflow)?;
    if opened_before.len() != opened_after.len() || opened_before.len() != bytes_len {
        return Err(VerificationError::FileIdentityChanged);
    }
    if bytes.contains(&0) {
        return Err(VerificationError::NulByte);
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| VerificationError::InvalidUtf8)?;

    let secret_findings = state
        .secrets
        .scan_file(text, |_| {})
        .map_err(VerificationError::Secret)?;
    if secret_findings != 0 {
        return Err(VerificationError::SecretFindingDetected);
    }
    let sensitive_findings = state
        .sensitive
        .scan_file(text, |_| {})
        .map_err(VerificationError::Sensitive)?;
    if sensitive_findings != 0 {
        return Err(VerificationError::SensitiveFindingDetected);
    }
    state.record_file(bytes.len())
}

fn validate_directory_identity(
    parent: &Dir,
    name: &OsStr,
    child: &Dir,
) -> Result<(), VerificationError> {
    let opened = child
        .dir_metadata()
        .map_err(|_| VerificationError::DirectoryIdentityChanged)?;
    let current = parent
        .symlink_metadata(name)
        .map_err(|_| VerificationError::DirectoryIdentityChanged)?;
    if !opened.is_dir()
        || current.file_type().is_symlink()
        || !current.is_dir()
        || fs_boundary::metadata_identity(&opened) != fs_boundary::metadata_identity(&current)
    {
        return Err(VerificationError::DirectoryIdentityChanged);
    }
    Ok(())
}

fn validate_opened_file(
    parent: &Dir,
    name: &OsStr,
    opened: &cap_std::fs::Metadata,
) -> Result<(), VerificationError> {
    let current = parent
        .symlink_metadata(name)
        .map_err(|_| VerificationError::FileIdentityChanged)?;
    if !opened.is_file()
        || opened.nlink() != 1
        || current.file_type().is_symlink()
        || !current.is_file()
        || fs_boundary::metadata_identity(opened) != fs_boundary::metadata_identity(&current)
    {
        return Err(if opened.nlink() != 1 {
            VerificationError::HardLinkedFile
        } else {
            VerificationError::FileIdentityChanged
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::staging::create_unverified_staging_root_for_test as create_unverified_staging_root;
    use crate::staging_tree::{
        build_unverified_sanitized_staging_tree, Limits as StagingTreeLimits,
    };
    use std::fs;
    use std::path::{Path, PathBuf};
    #[cfg(windows)]
    use std::process::Command;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_ID: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new(label: &str) -> Self {
            let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "safeclone-verification-{label}-{}-{id}",
                std::process::id()
            ));
            fs::create_dir(&path).expect("create isolated test directory");
            Self(path)
        }

        fn source(&self) -> PathBuf {
            self.0.join("source")
        }

        fn parent(&self) -> PathBuf {
            self.0.join("destination")
        }

        fn staging(&self) -> PathBuf {
            self.parent().join(crate::staging::UNVERIFIED_STAGING_LEAF)
        }

        fn output(&self) -> PathBuf {
            self.parent().join("final-output")
        }

        fn setup(&self) {
            fs::create_dir(self.source()).expect("create source");
            fs::create_dir(self.parent()).expect("create destination");
        }

        fn build(&self) -> UnverifiedStagedTree {
            let boundary = create_unverified_staging_root(&self.source(), &self.output())
                .expect("create boundary");
            build_unverified_sanitized_staging_tree(boundary, StagingTreeLimits::default())
                .expect("build unverified tree")
        }

        fn assert_disposed(&self, result: Result<(), VerificationError>) {
            #[cfg(windows)]
            {
                assert_eq!(result, Err(VerificationError::ManualInspectionRequired));
                assert!(self.staging().is_dir());
            }
            #[cfg(not(windows))]
            {
                result.expect("automatic staging cleanup succeeds");
                assert!(fs::symlink_metadata(self.staging()).is_err());
            }
            assert!(fs::symlink_metadata(self.output()).is_err());
        }

        fn assert_failure(&self, error: VerificationError, expected: VerificationError) {
            #[cfg(windows)]
            {
                let _ = expected;
                assert_eq!(error, VerificationError::ManualInspectionRequired);
                assert!(self.staging().is_dir());
            }
            #[cfg(not(windows))]
            {
                assert_eq!(error, expected);
                assert!(fs::symlink_metadata(self.staging()).is_err());
            }
            assert!(fs::symlink_metadata(self.output()).is_err());
        }

        fn assert_failure_state(&self) {
            #[cfg(windows)]
            assert!(self.staging().is_dir());
            #[cfg(not(windows))]
            assert!(fs::symlink_metadata(self.staging()).is_err());
            assert!(fs::symlink_metadata(self.output()).is_err());
        }
    }

    fn synthetic_github_token() -> String {
        const ALPHABET: &[u8] = b"A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0UvWxYz_";
        let body = (0..36)
            .map(|index| ALPHABET[index % ALPHABET.len()])
            .collect::<Vec<_>>();
        format!(
            "gho_{}",
            String::from_utf8(body).expect("ASCII synthetic token")
        )
    }

    fn synthetic_my_number(base: &str) -> String {
        let sum = base
            .bytes()
            .rev()
            .enumerate()
            .map(|(index, byte)| {
                let position = index as u32 + 1;
                let weight = if position <= 6 {
                    position + 1
                } else {
                    position - 5
                };
                u32::from(byte - b'0') * weight
            })
            .sum::<u32>();
        let remainder = sum % 11;
        let check = if remainder <= 1 { 0 } else { 11 - remainder };
        format!("{base}{check}")
    }

    fn synthetic_corporate_number(base: &str) -> String {
        let sum = base
            .bytes()
            .rev()
            .enumerate()
            .map(|(index, byte)| {
                let weight = if index % 2 == 0 { 1 } else { 2 };
                u32::from(byte - b'0') * weight
            })
            .sum::<u32>();
        format!("{}{base}", 9 - (sum % 9))
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn build_then_independently_verify_produces_type_state_and_counts() {
        let fixture = TestDirectory::new("positive");
        fixture.setup();
        fs::create_dir(fixture.source().join("ordinary")).expect("create source directory");
        fs::write(
            fixture.source().join("ordinary/main.rs"),
            b"fn main() { println!(\"fixture\"); }\n",
        )
        .expect("write source");
        fs::write(
            fixture.source().join("contact.rs"),
            b"contact = \"fixture.user@example.invalid\"\n",
        )
        .expect("write sensitive source");

        let tree = fixture.build();
        assert!(tree.staged_bytes_written > 0);
        let verified = verify_unverified_staged_tree(tree, VerificationLimits::default())
            .expect("sanitized staging verifies independently");
        let report = verified.report();
        assert_eq!(report.files_verified, 2);
        assert_eq!(report.directories_verified, 1);
        assert_eq!(report.filename_components_scanned, 2);
        assert_eq!(report.path_components_scanned, 3);
        assert_eq!(report.content_files_scanned, 2);
        assert!(report.bytes_verified > 0);
        let debug = format!("{verified:?}");
        assert!(!debug.contains("fixture.user@example.invalid"));
        fixture.assert_disposed(verified.discard());
    }

    #[test]
    fn detector_fixture_build_then_verify_covers_content_and_path_evidence() {
        let fixture = TestDirectory::new("detector-integration");
        fixture.setup();
        let token = synthetic_github_token();
        let email = "fixture.user@example.invalid";
        let phone = "090-1234-5678";
        let my_number = synthetic_my_number("10000000000");
        let corporate_number = synthetic_corporate_number("102030405060");
        fs::create_dir(fixture.source().join(email)).expect("create sensitive directory");
        fs::write(
            fixture.source().join("main.rs"),
            format!(
                "email={email}\nphone={phone}\ntoken={token}\nmy={my_number}\ncorp={corporate_number}\n"
            ),
        )
        .expect("write detector fixture");
        fs::write(
            fixture
                .source()
                .join(email)
                .join(format!("report_{phone}.md")),
            b"ordinary transformed path fixture\n",
        )
        .expect("write nested detector fixture");
        fs::write(
            fixture.source().join("192.0.2.10.rs"),
            b"ordinary IP path fixture\n",
        )
        .expect("write IP path fixture");
        fs::write(
            fixture.source().join(format!("{token}.txt")),
            b"ordinary token path fixture\n",
        )
        .expect("write token path fixture");

        let tree = fixture.build();
        let verified = verify_unverified_staged_tree(tree, VerificationLimits::default())
            .expect("fresh verification accepts transformed detector fixture");
        let report = verified.report();
        assert_eq!(report.files_verified, 4);
        assert_eq!(report.directories_verified, 1);
        assert_eq!(report.content_files_scanned, 4);
        assert_eq!(report.filename_components_scanned, 4);
        assert_eq!(report.path_components_scanned, 5);
        fixture.assert_disposed(verified.discard());
    }

    #[test]
    fn raw_sensitive_content_injection_follows_platform_disposal_policy() {
        let fixture = TestDirectory::new("raw-injection");
        fixture.setup();
        fs::write(fixture.source().join("main.rs"), b"ordinary").expect("write source");
        let tree = fixture.build();
        fs::write(
            fixture.staging().join("main.rs"),
            b"fixture.user@example.invalid",
        )
        .expect("inject raw sensitive content");

        let error = verify_unverified_staged_tree(tree, VerificationLimits::default())
            .expect_err("raw sensitive content must fail verification");
        #[cfg(windows)]
        assert_eq!(error, VerificationError::ManualInspectionRequired);
        #[cfg(not(windows))]
        assert!(matches!(
            error,
            VerificationError::SensitiveFindingDetected
                | VerificationError::StagedByteMismatch
                | VerificationError::FileIdentityChanged
        ));
        assert!(!error.to_string().contains("fixture.user@example.invalid"));
        fixture.assert_failure_state();
    }

    #[test]
    fn injected_git_and_dangerous_components_fail_closed() {
        let fixture = TestDirectory::new("structure-injection");
        fixture.setup();
        let tree = fixture.build();
        fs::create_dir(fixture.staging().join(".GIT")).expect("inject git component");

        let error = verify_unverified_staged_tree(tree, VerificationLimits::default())
            .expect_err("git metadata must fail verification");
        fixture.assert_failure(error, VerificationError::GitMetadataFound);
    }

    #[test]
    fn injected_filename_and_path_findings_fail_closed() {
        let file_fixture = TestDirectory::new("filename-injection");
        file_fixture.setup();
        let tree = file_fixture.build();
        fs::write(file_fixture.staging().join("credentials.rs"), b"ordinary")
            .expect("inject dangerous filename");
        let error = verify_unverified_staged_tree(tree, VerificationLimits::default())
            .expect_err("filename evidence must fail verification");
        file_fixture.assert_failure(error, VerificationError::FilenameFindingDetected);

        let directory_fixture = TestDirectory::new("path-injection");
        directory_fixture.setup();
        let tree = directory_fixture.build();
        fs::create_dir(
            directory_fixture
                .staging()
                .join("fixture.user@example.invalid"),
        )
        .expect("inject sensitive directory component");
        let error = verify_unverified_staged_tree(tree, VerificationLimits::default())
            .expect_err("path evidence must fail verification");
        directory_fixture.assert_failure(error, VerificationError::PathFindingDetected);
    }

    #[test]
    fn depth_and_entry_limits_follow_platform_disposal_policy() {
        let depth_fixture = TestDirectory::new("depth-limit");
        depth_fixture.setup();
        fs::create_dir(depth_fixture.source().join("nested")).expect("create nested source");
        let tree = depth_fixture.build();
        let error = verify_unverified_staged_tree(
            tree,
            VerificationLimits {
                max_depth: 0,
                ..VerificationLimits::default()
            },
        )
        .expect_err("verification depth limit must fail");
        depth_fixture.assert_failure(error, VerificationError::DepthLimitExceeded);

        let entry_fixture = TestDirectory::new("entry-limit");
        entry_fixture.setup();
        fs::write(entry_fixture.source().join("main.rs"), b"ordinary").expect("write source");
        let tree = entry_fixture.build();
        let error = verify_unverified_staged_tree(
            tree,
            VerificationLimits {
                max_entries: 0,
                ..VerificationLimits::default()
            },
        )
        .expect_err("verification entry limit must fail");
        entry_fixture.assert_failure(error, VerificationError::EntryLimitExceeded);
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_staged_component_fails_without_lossy_scan() {
        use std::os::unix::ffi::OsStringExt;

        let fixture = TestDirectory::new("non-utf8-component");
        fixture.setup();
        let tree = fixture.build();
        let name = std::ffi::OsString::from_vec(b"bad-\xff.rs".to_vec());
        fs::write(fixture.staging().join(&name), b"ordinary").expect("inject non-UTF8 file");
        let error = verify_unverified_staged_tree(tree, VerificationLimits::default())
            .expect_err("non-UTF8 staged name must fail");
        fixture.assert_failure(error, VerificationError::UninspectableComponent);
    }

    #[cfg(unix)]
    #[test]
    fn injected_hard_link_and_symlink_fail_closed() {
        use std::os::unix::fs::symlink;

        let hard_fixture = TestDirectory::new("hard-link-injection");
        hard_fixture.setup();
        fs::write(hard_fixture.source().join("main.rs"), b"ordinary").expect("write source");
        let tree = hard_fixture.build();
        fs::hard_link(
            hard_fixture.staging().join("main.rs"),
            hard_fixture.staging().join("hard.rs"),
        )
        .expect("inject hard link");
        let error = verify_unverified_staged_tree(tree, VerificationLimits::default())
            .expect_err("hard-linked staging file must fail");
        hard_fixture.assert_failure(error, VerificationError::HardLinkedFile);

        let symlink_fixture = TestDirectory::new("symlink-injection");
        symlink_fixture.setup();
        let outside = symlink_fixture.0.join("outside.rs");
        fs::write(&outside, b"outside").expect("write outside fixture");
        let tree = symlink_fixture.build();
        symlink(&outside, symlink_fixture.staging().join("linked.rs")).expect("inject symlink");
        let error = verify_unverified_staged_tree(tree, VerificationLimits::default())
            .expect_err("symlink staging entry must fail");
        symlink_fixture.assert_failure(error, VerificationError::UnexpectedEntryType);
    }

    #[cfg(windows)]
    #[test]
    fn windows_hard_link_junction_and_invalid_utf8_fail_manual_without_deletion() {
        let hard_fixture = TestDirectory::new("windows-hard-link-injection");
        hard_fixture.setup();
        fs::write(hard_fixture.source().join("main.rs"), b"ordinary").expect("write source");
        let tree = hard_fixture.build();
        fs::hard_link(
            hard_fixture.staging().join("main.rs"),
            hard_fixture.staging().join("hard.rs"),
        )
        .expect("inject hard link");
        let error = verify_unverified_staged_tree(tree, VerificationLimits::default())
            .expect_err("hard-linked staging rejects verification");
        hard_fixture.assert_failure(error, VerificationError::HardLinkedFile);
        assert!(hard_fixture.staging().join("main.rs").is_file());
        assert!(hard_fixture.staging().join("hard.rs").is_file());

        let junction_fixture = TestDirectory::new("windows-junction-injection");
        junction_fixture.setup();
        let outside = junction_fixture.0.join("outside");
        fs::create_dir(&outside).expect("create junction target");
        fs::write(outside.join("sentinel"), b"outside remains").expect("write sentinel");
        let tree = junction_fixture.build();
        let junction = junction_fixture.staging().join("injected-junction");
        create_junction(&junction, &outside);
        let error = verify_unverified_staged_tree(tree, VerificationLimits::default())
            .expect_err("junction rejects verification");
        junction_fixture.assert_failure(error, VerificationError::UnexpectedEntryType);
        assert_eq!(
            fs::read(outside.join("sentinel")).expect("outside sentinel remains"),
            b"outside remains"
        );
        assert!(fs::symlink_metadata(&junction).is_ok());
        fs::remove_dir(&junction).expect("test harness removes junction only");

        let utf8_fixture = TestDirectory::new("windows-invalid-utf8-injection");
        utf8_fixture.setup();
        fs::write(utf8_fixture.source().join("main.rs"), b"ordinary").expect("write source");
        let tree = utf8_fixture.build();
        fs::write(utf8_fixture.staging().join("main.rs"), [0xff, 0xfe])
            .expect("inject invalid UTF-8");
        let error = verify_unverified_staged_tree(tree, VerificationLimits::default())
            .expect_err("invalid UTF-8 rejects verification");
        assert_eq!(error, VerificationError::ManualInspectionRequired);
        assert_eq!(
            fs::read(utf8_fixture.staging().join("main.rs")).expect("invalid bytes remain"),
            [0xff, 0xfe]
        );
        utf8_fixture.assert_failure_state();
    }

    #[cfg(unix)]
    #[test]
    fn verification_does_not_reopen_or_rescan_source_content() {
        let fixture = TestDirectory::new("source-not-reopened");
        fixture.setup();
        fs::write(fixture.source().join("main.rs"), b"ordinary").expect("write source");
        let tree = fixture.build();
        let moved_source = fixture.0.join("source-moved-after-build");
        fs::rename(fixture.source(), &moved_source).expect("rename source root");

        let verified = verify_unverified_staged_tree(tree, VerificationLimits::default())
            .expect("verification uses staging only");
        assert_eq!(verified.report().files_verified, 1);
        fixture.assert_disposed(verified.discard());
        assert!(moved_source.join("main.rs").is_file());
    }

    #[test]
    fn staged_byte_mismatch_is_not_a_success() {
        let fixture = TestDirectory::new("byte-mismatch");
        fixture.setup();
        fs::write(fixture.source().join("main.rs"), b"ordinary\n").expect("write source");
        let tree = fixture.build();
        let mut bytes = fs::read(fixture.staging().join("main.rs")).expect("read staged file");
        bytes.push(b'!');
        fs::write(fixture.staging().join("main.rs"), bytes).expect("grow staged file");

        let error = verify_unverified_staged_tree(tree, VerificationLimits::default())
            .expect_err("staged byte mismatch must fail");
        fixture.assert_failure(error, VerificationError::StagedByteMismatch);
    }

    #[test]
    fn verification_limits_are_derived_without_numeric_marker_duplication() {
        let limits = VerificationLimits::default();
        assert_eq!(
            limits.max_total_bytes,
            content::DEFAULT_MAX_TOTAL_BYTES * transform::MAX_REPLACEMENT_MARKER_BYTES
        );
        assert_eq!(
            limits.max_file_bytes,
            transform::DEFAULT_MAX_OUTPUT_BYTES_PER_FILE
        );
    }

    #[test]
    fn verification_errors_and_debug_are_raw_free() {
        let raw = "fixture.user@example.invalid";
        let error = VerificationError::SensitiveFindingDetected;
        assert!(!error.to_string().contains(raw));
        assert!(!format!("{error:?}").contains(raw));
        let report = VerificationReport {
            files_verified: 1,
            directories_verified: 0,
            bytes_verified: 3,
            filename_components_scanned: 1,
            path_components_scanned: 1,
            content_files_scanned: 1,
        };
        assert!(!format!("{report:?}").contains(raw));
        let manual = VerificationError::ManualInspectionRequired;
        assert!(manual.to_string().contains("do not retry automatically"));
        assert!(!manual.to_string().contains(raw));
        assert!(!format!("{manual:?}").contains(raw));
        let _ = Path::new("test-only");
    }

    #[cfg(windows)]
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
