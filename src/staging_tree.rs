//! Capability-relative construction of an unverified sanitized staging tree.

use std::ffi::OsStr;
use std::fmt;
use std::io::{self, Write};

use cap_fs_ext::{DirExt, FollowSymlinks, MetadataExt, OpenOptionsFollowExt};
use cap_std::fs::{Dir, OpenOptions};

use crate::content::{self, ContentError, ContentOutcome, Session as ContentSession};
use crate::detection::{ComponentInspectability, DetectedKind};
use crate::filename::{self, FilenameError, Session as FilenameSession};
use crate::fs_boundary;
use crate::inventory::{self, InventoryError, ObservedComponent, StreamingError};
use crate::path_evidence::{
    self, ComponentKind, PathEvidenceError, Session as PathEvidenceSession,
};
use crate::path_transform::{self, PathTransformError, TransformedComponent};
use crate::policy::{self, Decision, FileDispositionInput, FilenameEvidence, PolicyPlanError};
use crate::secrets::{self, SecretError, Session as SecretSession};
use crate::sensitive::{self, SensitiveError, Session as SensitiveSession};
use crate::staging::{self, StagingError, UnverifiedStagingRoot};
use crate::transform::{self, TransformError, TransformedText};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Limits {
    pub inventory: inventory::Limits,
    pub filename: filename::Limits,
    pub path_evidence: path_evidence::Limits,
    pub content: content::Limits,
    pub secrets: secrets::Limits,
    pub sensitive: sensitive::Limits,
    pub transform: transform::Limits,
    pub path_transform: path_transform::Limits,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StagingTreeError {
    Boundary(StagingError),
    Inventory(InventoryError),
    Filename(FilenameError),
    PathEvidence(PathEvidenceError),
    Content(ContentError),
    Secret(SecretError),
    Sensitive(SensitiveError),
    Policy(PolicyPlanError),
    Transform(TransformError),
    PathTransform(PathTransformError),
    UninspectableDirectory,
    StagingCollision,
    StagingDirectoryCreationFailed,
    StagingEntryOpenFailed,
    StagingEntryChanged,
    StagingFileCreationFailed,
    StagingWriteFailed,
    CountOverflow,
    StagingEntryLimitExceeded,
    InconsistentBuild,
    ManualInspectionRequired,
    CleanupFailed,
}

/// Raw-free builder observations retained for reporting only.
///
/// This summary is not verification evidence and cannot authorize promotion.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct StagingBuildSummary {
    pub files_written: usize,
    pub directories_written: usize,
    pub staged_bytes_written: usize,
    pub files_omitted: usize,
    pub source_bytes_redacted: usize,
    pub content_regions: usize,
    pub path_regions: usize,
}

impl fmt::Display for StagingTreeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Boundary(error) => error.fmt(formatter),
            Self::Inventory(error) => error.fmt(formatter),
            Self::Filename(error) => error.fmt(formatter),
            Self::PathEvidence(error) => error.fmt(formatter),
            Self::Content(error) => error.fmt(formatter),
            Self::Secret(error) => error.fmt(formatter),
            Self::Sensitive(error) => error.fmt(formatter),
            Self::Policy(error) => error.fmt(formatter),
            Self::Transform(error) => error.fmt(formatter),
            Self::PathTransform(error) => error.fmt(formatter),
            Self::UninspectableDirectory => {
                formatter.write_str("source directory component is not inspectable Unicode")
            }
            Self::StagingCollision => {
                formatter.write_str("sanitized staging component collision detected")
            }
            Self::StagingDirectoryCreationFailed => {
                formatter.write_str("sanitized staging directory could not be created")
            }
            Self::StagingEntryOpenFailed => {
                formatter.write_str("sanitized staging entry could not be opened safely")
            }
            Self::StagingEntryChanged => {
                formatter.write_str("sanitized staging entry changed unexpectedly")
            }
            Self::StagingFileCreationFailed => {
                formatter.write_str("sanitized staging file could not be created safely")
            }
            Self::StagingWriteFailed => {
                formatter.write_str("sanitized staging content could not be written completely")
            }
            Self::CountOverflow => formatter.write_str("staging tree counts overflowed"),
            Self::StagingEntryLimitExceeded => {
                formatter.write_str("post-build staging structural entry limit exceeded")
            }
            Self::InconsistentBuild => {
                formatter.write_str("staging tree observations are inconsistent")
            }
            Self::ManualInspectionRequired => formatter.write_str(
                "unpublished staging may remain; no automatic cleanup was attempted; manual inspection is required; do not retry automatically",
            ),
            Self::CleanupFailed => formatter.write_str("unverified staging tree cleanup failed"),
        }
    }
}

/// An unpublished staging tree and its raw-free aggregate evidence.
///
/// Debug intentionally exposes aggregates only. The retained boundary keeps
/// source and staging capabilities alive for a later verification phase.
pub struct UnverifiedStagedTree {
    boundary: UnverifiedStagingRoot,
    pub files_written: usize,
    pub directories_written: usize,
    pub staged_bytes_written: usize,
    pub files_omitted: usize,
    pub source_bytes_redacted: usize,
    pub content_regions: usize,
    pub path_regions: usize,
}

impl fmt::Debug for UnverifiedStagedTree {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UnverifiedStagedTree")
            .field("files_written", &self.files_written)
            .field("directories_written", &self.directories_written)
            .field("staged_bytes_written", &self.staged_bytes_written)
            .field("files_omitted", &self.files_omitted)
            .field("source_bytes_redacted", &self.source_bytes_redacted)
            .field("content_regions", &self.content_regions)
            .field("path_regions", &self.path_regions)
            .field("state", &"unverified-unpublished")
            .finish()
    }
}

impl UnverifiedStagedTree {
    /// Copy the raw-free build observations before verification consumes this
    /// tree. The independent verifier remains the publication authority.
    pub fn summary(&self) -> StagingBuildSummary {
        StagingBuildSummary {
            files_written: self.files_written,
            directories_written: self.directories_written,
            staged_bytes_written: self.staged_bytes_written,
            files_omitted: self.files_omitted,
            source_bytes_redacted: self.source_bytes_redacted,
            content_regions: self.content_regions,
            path_regions: self.path_regions,
        }
    }

    /// Explicitly dispose of the non-empty unverified staging tree according
    /// to the platform cleanup policy.
    pub fn discard(self) -> Result<(), StagingTreeError> {
        self.boundary.discard().map_err(map_staging_disposal_error)
    }

    /// Transfer only the retained boundary and builder byte/count observations
    /// into the independent verification stage.
    pub(crate) fn into_verification_parts(self) -> (UnverifiedStagingRoot, usize, usize, usize) {
        let Self {
            boundary,
            files_written,
            directories_written,
            staged_bytes_written,
            ..
        } = self;
        (
            boundary,
            files_written,
            directories_written,
            staged_bytes_written,
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BuildEvent {
    BeforeFileWrite,
    BeforeStructuralValidation,
}

/// Build an unpublished sanitized tree from the source capability retained by
/// the staging boundary. No ambient source reopen, final output, verification,
/// promotion, or clone publication occurs.
pub fn build_unverified_sanitized_staging_tree(
    boundary: UnverifiedStagingRoot,
    limits: Limits,
) -> Result<UnverifiedStagedTree, StagingTreeError> {
    build_with_hook(boundary, limits, |_| Ok(()))
}

fn build_with_hook(
    boundary: UnverifiedStagingRoot,
    limits: Limits,
    mut on_event: impl FnMut(BuildEvent) -> Result<(), StagingTreeError>,
) -> Result<UnverifiedStagedTree, StagingTreeError> {
    let build = build_inner(&boundary, limits, &mut on_event);
    match build {
        Ok(aggregate) => {
            if let Err(error) = boundary.validate_current() {
                return dispose_after_failure(boundary, StagingTreeError::Boundary(error));
            }
            if let Err(error) = on_event(BuildEvent::BeforeStructuralValidation) {
                return dispose_after_failure(boundary, error);
            }
            if let Err(error) = validate_staged_structure(
                boundary.staging(),
                aggregate,
                limits.inventory.max_depth,
                limits.inventory.max_entries,
            ) {
                return dispose_after_failure(boundary, error);
            }
            if let Err(error) = boundary.validate_current() {
                return dispose_after_failure(boundary, StagingTreeError::Boundary(error));
            }
            Ok(UnverifiedStagedTree {
                boundary,
                files_written: aggregate.files_written,
                directories_written: aggregate.directories_written,
                staged_bytes_written: aggregate.staged_bytes_written,
                files_omitted: aggregate.files_omitted,
                source_bytes_redacted: aggregate.source_bytes_redacted,
                content_regions: aggregate.content_regions,
                path_regions: aggregate.path_regions,
            })
        }
        Err(error) => dispose_after_failure(boundary, error),
    }
}

fn dispose_after_failure(
    boundary: UnverifiedStagingRoot,
    original: StagingTreeError,
) -> Result<UnverifiedStagedTree, StagingTreeError> {
    match boundary.discard() {
        Ok(()) => Err(original),
        Err(error) => Err(map_staging_disposal_error(error)),
    }
}

const fn map_staging_disposal_error(error: StagingError) -> StagingTreeError {
    match error {
        StagingError::StagingRequiresManualInspection => StagingTreeError::ManualInspectionRequired,
        _ => StagingTreeError::CleanupFailed,
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct Aggregate {
    files_written: usize,
    directories_written: usize,
    staged_bytes_written: usize,
    files_omitted: usize,
    source_bytes_redacted: usize,
    content_regions: usize,
    path_regions: usize,
    uninspectable_files: usize,
    preflight_omitted: usize,
    content_omitted: usize,
}

impl Aggregate {
    fn with_directory(self, path_regions: usize) -> Result<Self, StagingTreeError> {
        Ok(Self {
            directories_written: self
                .directories_written
                .checked_add(1)
                .ok_or(StagingTreeError::CountOverflow)?,
            path_regions: self
                .path_regions
                .checked_add(path_regions)
                .ok_or(StagingTreeError::CountOverflow)?,
            ..self
        })
    }

    fn with_omitted_file(
        self,
        uninspectable: bool,
        preflight: bool,
    ) -> Result<Self, StagingTreeError> {
        Ok(Self {
            files_omitted: self
                .files_omitted
                .checked_add(1)
                .ok_or(StagingTreeError::CountOverflow)?,
            uninspectable_files: self
                .uninspectable_files
                .checked_add(usize::from(uninspectable))
                .ok_or(StagingTreeError::CountOverflow)?,
            preflight_omitted: self
                .preflight_omitted
                .checked_add(usize::from(preflight))
                .ok_or(StagingTreeError::CountOverflow)?,
            content_omitted: self
                .content_omitted
                .checked_add(usize::from(!preflight))
                .ok_or(StagingTreeError::CountOverflow)?,
            ..self
        })
    }

    fn with_written_file(self, file: &PreparedFile) -> Result<Self, StagingTreeError> {
        Ok(Self {
            files_written: self
                .files_written
                .checked_add(1)
                .ok_or(StagingTreeError::CountOverflow)?,
            source_bytes_redacted: self
                .source_bytes_redacted
                .checked_add(file.content.source_bytes_redacted)
                .ok_or(StagingTreeError::CountOverflow)?,
            staged_bytes_written: self
                .staged_bytes_written
                .checked_add(file.content.text.len())
                .ok_or(StagingTreeError::CountOverflow)?,
            content_regions: self
                .content_regions
                .checked_add(file.content.regions)
                .ok_or(StagingTreeError::CountOverflow)?,
            path_regions: self
                .path_regions
                .checked_add(file.path_regions)
                .ok_or(StagingTreeError::CountOverflow)?,
            ..self
        })
    }
}

struct BuilderState {
    filename: FilenameSession,
    path_evidence: PathEvidenceSession,
    content: ContentSession,
    secrets: SecretSession,
    sensitive: SensitiveSession,
    transform_limits: transform::Limits,
    path_transform_limits: path_transform::Limits,
    aggregate: Aggregate,
}

impl BuilderState {
    fn new(limits: Limits) -> Result<Self, StagingTreeError> {
        Ok(Self {
            filename: FilenameSession::new(limits.filename),
            path_evidence: PathEvidenceSession::new(limits.path_evidence)
                .map_err(StagingTreeError::PathEvidence)?,
            content: ContentSession::new(limits.content),
            secrets: SecretSession::new(limits.secrets).map_err(StagingTreeError::Secret)?,
            sensitive: SensitiveSession::new(limits.sensitive)
                .map_err(StagingTreeError::Sensitive)?,
            transform_limits: limits.transform,
            path_transform_limits: limits.path_transform,
            aggregate: Aggregate::default(),
        })
    }

    fn process_directory(
        &mut self,
        staging_parent: &Dir,
        name: &OsStr,
    ) -> Result<Dir, StagingTreeError> {
        let text = name
            .to_str()
            .ok_or(StagingTreeError::UninspectableDirectory)?;
        let transformed = scan_and_transform_component(
            &mut self.path_evidence,
            text,
            ComponentKind::Directory,
            self.path_transform_limits,
        )?;
        let next_aggregate = self.aggregate.with_directory(transformed.regions)?;
        let output_name = OsStr::new(&transformed.text);

        create_child_directory(staging_parent, output_name)?;
        let child = staging_parent
            .open_dir_nofollow(output_name)
            .map_err(|_| StagingTreeError::StagingEntryOpenFailed)?;
        validate_directory_entry(staging_parent, output_name, &child)?;
        if child
            .entries()
            .map_err(|_| StagingTreeError::StagingEntryChanged)?
            .next()
            .is_some()
        {
            return Err(StagingTreeError::StagingEntryChanged);
        }

        self.aggregate = next_aggregate;
        Ok(child)
    }

    fn process_regular_file(
        &mut self,
        source_parent: &Dir,
        staging_parent: &Dir,
        name: &OsStr,
        kind: DetectedKind,
        on_event: &mut impl FnMut(BuildEvent) -> Result<(), StagingTreeError>,
    ) -> Result<(), StagingTreeError> {
        let Some(name_text) = name.to_str() else {
            let decision = policy::effective_decision(FileDispositionInput {
                detected_kind: kind,
                content_outcome: None,
                filename: FilenameEvidence::default(),
                path_component: ComponentInspectability::Uninspectable,
            })
            .map_err(StagingTreeError::Policy)?;
            if decision != Decision::Omit {
                return Err(StagingTreeError::InconsistentBuild);
            }
            self.aggregate = self.aggregate.with_omitted_file(true, true)?;
            return Ok(());
        };

        let mut filename_evidence = FilenameEvidence::default();
        self.filename
            .scan_basename(name, |findings| {
                filename_evidence = FilenameEvidence::from_findings(findings);
            })
            .map_err(StagingTreeError::Filename)?;

        let preflight = policy::effective_decision(FileDispositionInput {
            detected_kind: kind,
            content_outcome: None,
            filename: filename_evidence,
            path_component: ComponentInspectability::Inspectable,
        });
        match preflight {
            Ok(Decision::Omit) => {
                self.aggregate = self.aggregate.with_omitted_file(false, true)?;
                return Ok(());
            }
            Err(PolicyPlanError::MissingContentOutcome)
                if kind == DetectedKind::TextOrCodeCandidate => {}
            Ok(_) | Err(_) => {
                return Err(preflight
                    .err()
                    .map(StagingTreeError::Policy)
                    .unwrap_or(StagingTreeError::InconsistentBuild));
            }
        }

        let transform_limits = self.transform_limits;
        let path_transform_limits = self.path_transform_limits;
        let mut prepared = None;
        let outcome = self
            .content
            .inspect_candidate(source_parent, name, |text| {
                prepared = Some(prepare_readable_file(
                    text,
                    name_text,
                    &mut self.secrets,
                    &mut self.sensitive,
                    &mut self.path_evidence,
                    transform_limits,
                    path_transform_limits,
                ));
            })
            .map_err(StagingTreeError::Content)?;

        let decision = policy::effective_decision(FileDispositionInput {
            detected_kind: kind,
            content_outcome: Some(outcome),
            filename: filename_evidence,
            path_component: ComponentInspectability::Inspectable,
        })
        .map_err(StagingTreeError::Policy)?;
        match decision {
            Decision::Omit => {
                if prepared.is_some() {
                    return Err(StagingTreeError::InconsistentBuild);
                }
                self.aggregate = self.aggregate.with_omitted_file(false, false)?;
                Ok(())
            }
            Decision::Transform => {
                if outcome != ContentOutcome::ReadableText {
                    return Err(StagingTreeError::InconsistentBuild);
                }
                let file = prepared.ok_or(StagingTreeError::InconsistentBuild)??;
                let next_aggregate = self.aggregate.with_written_file(&file)?;
                write_destination_file(staging_parent, &file, on_event)?;
                self.aggregate = next_aggregate;
                Ok(())
            }
            Decision::Allow | Decision::StructureOnly | Decision::Block => {
                Err(StagingTreeError::InconsistentBuild)
            }
        }
    }
}

fn build_inner(
    boundary: &UnverifiedStagingRoot,
    limits: Limits,
    on_event: &mut impl FnMut(BuildEvent) -> Result<(), StagingTreeError>,
) -> Result<Aggregate, StagingTreeError> {
    boundary
        .validate_current()
        .map_err(StagingTreeError::Boundary)?;
    let source = boundary
        .source_capability()
        .map_err(StagingTreeError::Boundary)?;
    let staging = boundary
        .staging_capability()
        .map_err(StagingTreeError::Boundary)?;
    let mut state = BuilderState::new(limits)?;

    let inventory = inventory::inspect_open_root_with_state(
        source,
        staging,
        limits.inventory,
        |source_parent, staging_parent, name, component| match component {
            ObservedComponent::Directory => state.process_directory(staging_parent, name).map(Some),
            ObservedComponent::RegularFile(kind) => {
                state.process_regular_file(source_parent, staging_parent, name, kind, on_event)?;
                Ok(None)
            }
        },
    )
    .map_err(|error| match error {
        StreamingError::Inventory(error) => StagingTreeError::Inventory(error),
        StreamingError::Component(error) => error,
    })?;

    let filename = state
        .filename
        .finish()
        .map_err(StagingTreeError::Filename)?;
    let path = state
        .path_evidence
        .finish()
        .map_err(StagingTreeError::PathEvidence)?;
    let content = state.content.finish().map_err(StagingTreeError::Content)?;
    let secrets = state.secrets.finish().map_err(StagingTreeError::Secret)?;
    let sensitive = state
        .sensitive
        .finish()
        .map_err(StagingTreeError::Sensitive)?;

    let file_total = state
        .aggregate
        .files_written
        .checked_add(state.aggregate.files_omitted)
        .ok_or(StagingTreeError::CountOverflow)?;
    let path_candidates = state
        .aggregate
        .directories_written
        .checked_add(state.aggregate.files_written)
        .ok_or(StagingTreeError::CountOverflow)?;
    let preflight_and_content_omitted = state
        .aggregate
        .preflight_omitted
        .checked_add(state.aggregate.content_omitted)
        .ok_or(StagingTreeError::CountOverflow)?;
    let inspected_and_uninspectable_names = filename
        .scan_candidates
        .checked_add(state.aggregate.uninspectable_files)
        .ok_or(StagingTreeError::CountOverflow)?;
    let written_entries = state
        .aggregate
        .directories_written
        .checked_add(state.aggregate.files_written)
        .ok_or(StagingTreeError::CountOverflow)?;
    if file_total != inventory.regular_files
        || state.aggregate.directories_written != inventory.directories
        || preflight_and_content_omitted != state.aggregate.files_omitted
        || inspected_and_uninspectable_names != inventory.regular_files
        || filename.uninspectable != 0
        || path.scan_candidates != path_candidates
        || path.uninspectable != 0
        || content.readable_text != state.aggregate.files_written
        || secrets.scan_candidates != content.readable_text
        || sensitive.scan_candidates != content.readable_text
        || written_entries > inventory.total_entries
        || state.aggregate.files_written > limits.inventory.max_entries
        || state.aggregate.directories_written > limits.inventory.max_entries
    {
        return Err(StagingTreeError::InconsistentBuild);
    }

    Ok(state.aggregate)
}

struct PreparedFile {
    output_name: String,
    content: TransformedText,
    path_regions: usize,
}

fn prepare_readable_file(
    text: &str,
    name: &str,
    secrets: &mut SecretSession,
    sensitive: &mut SensitiveSession,
    path_evidence: &mut PathEvidenceSession,
    transform_limits: transform::Limits,
    path_transform_limits: path_transform::Limits,
) -> Result<PreparedFile, StagingTreeError> {
    let mut secret_findings = Vec::new();
    secrets
        .scan_file(text, |findings| secret_findings.extend_from_slice(findings))
        .map_err(StagingTreeError::Secret)?;
    let mut sensitive_findings = Vec::new();
    sensitive
        .scan_file(text, |findings| {
            sensitive_findings.extend_from_slice(findings)
        })
        .map_err(StagingTreeError::Sensitive)?;
    let content = transform::transform_with_limits(
        text,
        &secret_findings,
        &sensitive_findings,
        transform_limits,
    )
    .map_err(StagingTreeError::Transform)?;

    let (stem, suffix) = path_transform::split_transformable_file_component(name)
        .map_err(StagingTreeError::PathTransform)?;
    let transformed_stem = scan_and_transform_component(
        path_evidence,
        stem,
        ComponentKind::File,
        path_transform_limits,
    )?;
    let output_len = transformed_stem
        .text
        .len()
        .checked_add(suffix.len())
        .ok_or(StagingTreeError::CountOverflow)?;
    if output_len > path_transform_limits.max_output_bytes_per_component {
        return Err(StagingTreeError::PathTransform(
            PathTransformError::OutputLimitExceeded,
        ));
    }
    let mut output_name = String::with_capacity(output_len);
    output_name.push_str(&transformed_stem.text);
    output_name.push_str(suffix);

    Ok(PreparedFile {
        output_name,
        content,
        path_regions: transformed_stem.regions,
    })
}

fn scan_and_transform_component(
    path_evidence: &mut PathEvidenceSession,
    text: &str,
    kind: ComponentKind,
    limits: path_transform::Limits,
) -> Result<TransformedComponent, StagingTreeError> {
    let mut transformed = None;
    let inspectability = path_evidence
        .scan_component_with_findings(
            OsStr::new(text),
            kind,
            |secret_findings, sensitive_findings| {
                transformed = Some(path_transform::transform_component_with_limits(
                    text,
                    secret_findings,
                    sensitive_findings,
                    limits,
                ));
            },
        )
        .map_err(StagingTreeError::PathEvidence)?;
    if inspectability != ComponentInspectability::Inspectable {
        return Err(StagingTreeError::InconsistentBuild);
    }
    transformed
        .ok_or(StagingTreeError::InconsistentBuild)?
        .map_err(StagingTreeError::PathTransform)
}

fn create_child_directory(parent: &Dir, name: &OsStr) -> Result<(), StagingTreeError> {
    match staging::create_private_directory(parent, name) {
        Ok(()) => Ok(()),
        Err(error) if destination_exists(parent, name, &error) => {
            Err(StagingTreeError::StagingCollision)
        }
        Err(_) => Err(StagingTreeError::StagingDirectoryCreationFailed),
    }
}

fn write_destination_file(
    parent: &Dir,
    file: &PreparedFile,
    on_event: &mut impl FnMut(BuildEvent) -> Result<(), StagingTreeError>,
) -> Result<(), StagingTreeError> {
    let name = OsStr::new(&file.output_name);
    let mut options = OpenOptions::new();
    options
        .write(true)
        .create_new(true)
        .follow(FollowSymlinks::No);
    let mut destination = match parent.open_with(name, &options) {
        Ok(file) => file,
        Err(error) if destination_exists(parent, name, &error) => {
            return Err(StagingTreeError::StagingCollision);
        }
        Err(_) => return Err(StagingTreeError::StagingFileCreationFailed),
    };
    validate_file_entry(parent, name, &destination)?;
    on_event(BuildEvent::BeforeFileWrite)?;
    destination
        .write_all(file.content.text.as_bytes())
        .map_err(|_| StagingTreeError::StagingWriteFailed)?;
    validate_file_entry(parent, name, &destination)
}

fn destination_exists(parent: &Dir, name: &OsStr, create_error: &io::Error) -> bool {
    create_error.kind() == io::ErrorKind::AlreadyExists || parent.symlink_metadata(name).is_ok()
}

fn validate_directory_entry(
    parent: &Dir,
    name: &OsStr,
    directory: &Dir,
) -> Result<(), StagingTreeError> {
    let opened = directory
        .dir_metadata()
        .map_err(|_| StagingTreeError::StagingEntryChanged)?;
    let current = parent
        .symlink_metadata(name)
        .map_err(|_| StagingTreeError::StagingEntryChanged)?;
    if !opened.is_dir()
        || current.file_type().is_symlink()
        || !current.is_dir()
        || fs_boundary::metadata_identity(&opened) != fs_boundary::metadata_identity(&current)
    {
        return Err(StagingTreeError::StagingEntryChanged);
    }
    Ok(())
}

fn validate_file_entry(
    parent: &Dir,
    name: &OsStr,
    file: &cap_std::fs::File,
) -> Result<(), StagingTreeError> {
    let opened = file
        .metadata()
        .map_err(|_| StagingTreeError::StagingEntryChanged)?;
    let current = parent
        .symlink_metadata(name)
        .map_err(|_| StagingTreeError::StagingEntryChanged)?;
    if !opened.is_file()
        || opened.nlink() != 1
        || current.file_type().is_symlink()
        || !current.is_file()
        || fs_boundary::metadata_identity(&opened) != fs_boundary::metadata_identity(&current)
    {
        return Err(StagingTreeError::StagingEntryChanged);
    }
    Ok(())
}

fn validate_staged_structure(
    root: &Dir,
    expected: Aggregate,
    max_depth: usize,
    max_entries: usize,
) -> Result<(), StagingTreeError> {
    validate_staged_structure_with_observer(root, expected, max_depth, max_entries, &mut || {})
}

fn validate_staged_structure_with_observer(
    root: &Dir,
    expected: Aggregate,
    max_depth: usize,
    max_entries: usize,
    on_entry: &mut impl FnMut(),
) -> Result<(), StagingTreeError> {
    let expected_entries = expected
        .files_written
        .checked_add(expected.directories_written)
        .ok_or(StagingTreeError::CountOverflow)?;
    if expected_entries > max_entries {
        return Err(StagingTreeError::StagingEntryLimitExceeded);
    }
    let root = root
        .try_clone()
        .map_err(|_| StagingTreeError::StagingEntryOpenFailed)?;
    let mut counts = StructuralValidationCounts::default();
    validate_staged_directory(
        root,
        0,
        max_depth,
        max_entries,
        expected_entries,
        &mut counts,
        on_entry,
    )?;
    if counts.files != expected.files_written
        || counts.directories != expected.directories_written
        || counts.total != expected_entries
    {
        return Err(StagingTreeError::InconsistentBuild);
    }
    Ok(())
}

#[derive(Default)]
struct StructuralValidationCounts {
    files: usize,
    directories: usize,
    total: usize,
}

impl StructuralValidationCounts {
    fn record_entry(
        &mut self,
        max_entries: usize,
        expected_entries: usize,
    ) -> Result<(), StagingTreeError> {
        let next_total = self
            .total
            .checked_add(1)
            .ok_or(StagingTreeError::CountOverflow)?;
        if next_total > max_entries || next_total > expected_entries {
            return Err(StagingTreeError::StagingEntryLimitExceeded);
        }
        self.total = next_total;
        Ok(())
    }
}

/// Validate one staging directory before returning to its parent. This keeps
/// structural-validation directory handles bounded by the configured depth.
fn validate_staged_directory(
    directory: Dir,
    depth: usize,
    max_depth: usize,
    max_entries: usize,
    expected_entries: usize,
    counts: &mut StructuralValidationCounts,
    on_entry: &mut impl FnMut(),
) -> Result<(), StagingTreeError> {
    let entries = directory
        .entries()
        .map_err(|_| StagingTreeError::StagingEntryChanged)?;
    for entry in entries {
        let entry = entry.map_err(|_| StagingTreeError::StagingEntryChanged)?;
        on_entry();
        counts.record_entry(max_entries, expected_entries)?;
        let name = entry.file_name();
        let file_type = entry
            .file_type()
            .map_err(|_| StagingTreeError::StagingEntryChanged)?;
        if file_type.is_symlink() {
            return Err(StagingTreeError::StagingEntryChanged);
        }
        if file_type.is_dir() {
            let child_depth = depth
                .checked_add(1)
                .ok_or(StagingTreeError::CountOverflow)?;
            if child_depth > max_depth {
                return Err(StagingTreeError::StagingEntryChanged);
            }
            let child = directory
                .open_dir_nofollow(&name)
                .map_err(|_| StagingTreeError::StagingEntryChanged)?;
            validate_directory_entry(&directory, &name, &child)?;
            counts.directories = counts
                .directories
                .checked_add(1)
                .ok_or(StagingTreeError::CountOverflow)?;
            validate_staged_directory(
                child,
                child_depth,
                max_depth,
                max_entries,
                expected_entries,
                counts,
                on_entry,
            )?;
        } else if file_type.is_file() {
            counts.files = counts
                .files
                .checked_add(1)
                .ok_or(StagingTreeError::CountOverflow)?;
        } else {
            return Err(StagingTreeError::StagingEntryChanged);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::staging::{
        create_unverified_staging_root_for_test as create_unverified_staging_root,
        UNVERIFIED_STAGING_LEAF,
    };
    use std::cell::Cell;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_ID: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new(label: &str) -> Self {
            let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "safeclone-staging-tree-{label}-{}-{id}",
                std::process::id()
            ));
            fs::create_dir(&path).expect("create isolated test directory");
            Self(path)
        }

        fn layout(&self) -> Layout {
            let source = self.0.join("synthetic-private-source");
            let parent = self.0.join("destination");
            let output = parent.join("synthetic-private-output");
            fs::create_dir(&source).expect("create source");
            fs::create_dir(&parent).expect("create output parent");
            Layout {
                source,
                parent,
                output,
            }
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    struct Layout {
        source: PathBuf,
        parent: PathBuf,
        output: PathBuf,
    }

    impl Layout {
        fn staging(&self) -> PathBuf {
            self.parent.join(UNVERIFIED_STAGING_LEAF)
        }

        fn boundary(&self) -> UnverifiedStagingRoot {
            create_unverified_staging_root(&self.source, &self.output).expect("create boundary")
        }

        fn assert_disposed(&self, result: Result<(), StagingTreeError>) {
            #[cfg(windows)]
            {
                assert_eq!(result, Err(StagingTreeError::ManualInspectionRequired));
                assert!(self.staging().is_dir());
            }
            #[cfg(not(windows))]
            {
                result.expect("automatic staging cleanup succeeds");
                assert!(fs::symlink_metadata(self.staging()).is_err());
            }
            assert!(fs::symlink_metadata(&self.output).is_err());
        }

        fn assert_failure(&self, error: StagingTreeError, expected: StagingTreeError) {
            #[cfg(windows)]
            {
                let _ = expected;
                assert_eq!(error, StagingTreeError::ManualInspectionRequired);
                assert!(self.staging().is_dir());
            }
            #[cfg(not(windows))]
            {
                assert_eq!(error, expected);
                assert!(fs::symlink_metadata(self.staging()).is_err());
            }
            assert!(fs::symlink_metadata(&self.output).is_err());
        }

        #[cfg(unix)]
        fn assert_cleaned(&self) {
            assert!(fs::symlink_metadata(self.staging()).is_err());
            assert!(fs::symlink_metadata(&self.output).is_err());
        }
    }

    fn synthetic_github_token() -> String {
        const ALPHABET: &[u8] = b"A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0UvWxYz_";
        let body = (0..36)
            .map(|index| ALPHABET[index % ALPHABET.len()])
            .collect::<Vec<_>>();
        format!("gho_{}", String::from_utf8(body).expect("ASCII fixture"))
    }

    fn assert_tree_excludes_raw(root: &Path, raw_values: &[&str]) {
        for entry in fs::read_dir(root).expect("read staged directory") {
            let entry = entry.expect("read staged entry");
            let name = entry
                .file_name()
                .into_string()
                .expect("staging names are UTF-8");
            for raw in raw_values {
                assert!(!name.contains(raw));
            }
            let file_type = entry.file_type().expect("staged entry type");
            if file_type.is_dir() {
                assert_tree_excludes_raw(&entry.path(), raw_values);
            } else {
                assert!(file_type.is_file());
                let text = fs::read_to_string(entry.path()).expect("read staged text");
                for raw in raw_values {
                    assert!(!text.contains(raw));
                }
            }
        }
    }

    #[test]
    fn builds_only_transformed_content_and_sanitized_component_names() {
        let fixture = TestDirectory::new("happy");
        let layout = fixture.layout();
        let token = synthetic_github_token();
        let email = "fixture.user@example.invalid";
        let phone = "090-1234-5678";
        let src = layout.source.join("src");
        let email_directory = layout.source.join(email);
        fs::create_dir(&src).expect("create src directory");
        fs::create_dir(&email_directory).expect("create email directory");
        fs::write(src.join("main.rs"), b"fn main() {}\n").expect("write ordinary source");
        let config = format!("contact={email}\ntoken={token}\nphone={phone}\n");
        fs::write(src.join("config.rs"), config.as_bytes()).expect("write sensitive source");
        fs::write(
            email_directory.join(format!("report_{phone}.md")),
            b"ordinary report\n",
        )
        .expect("write phone-named source");
        fs::write(layout.source.join("192.0.2.10.rs"), b"ordinary ip file\n")
            .expect("write IP-named source");
        fs::write(
            layout.source.join(format!("{token}.txt")),
            b"ordinary token-named file\n",
        )
        .expect("write token-named source");
        let source_main_before = fs::read(src.join("main.rs")).expect("read before");
        let source_config_before = fs::read(src.join("config.rs")).expect("read before");

        let tree = build_unverified_sanitized_staging_tree(layout.boundary(), Limits::default())
            .expect("build unverified sanitized tree");

        assert_eq!(tree.files_written, 5);
        assert_eq!(tree.directories_written, 2);
        assert_eq!(
            tree.staged_bytes_written,
            fs::read(layout.staging().join("src/config.rs"))
                .expect("read staged config")
                .len()
                + fs::read(layout.staging().join("src/main.rs"))
                    .expect("read staged main")
                    .len()
                + fs::read(
                    layout
                        .staging()
                        .join("__REDACTED_EMAIL__")
                        .join("report___REDACTED_PHONE__.md"),
                )
                .expect("read staged report")
                .len()
                + fs::read(layout.staging().join("__REDACTED_IP__.rs"))
                    .expect("read staged IP")
                    .len()
                + fs::read(layout.staging().join("__REDACTED_SECRET__.txt"))
                    .expect("read staged token file")
                    .len()
        );
        assert_eq!(tree.files_omitted, 0);
        assert!(tree.source_bytes_redacted > 0);
        assert!(tree.content_regions >= 3);
        assert!(tree.path_regions >= 4);
        let staging = layout.staging();
        let sanitized_config =
            fs::read_to_string(staging.join("src/config.rs")).expect("read sanitized config");
        assert!(!sanitized_config.contains(email));
        assert!(!sanitized_config.contains(&token));
        assert!(!sanitized_config.contains(phone));
        assert!(sanitized_config.contains("[REDACTED:EMAIL]"));
        assert!(sanitized_config.contains("[REDACTED:SECRET]"));
        assert!(sanitized_config.contains("[REDACTED:PHONE]"));
        assert!(staging.join("__REDACTED_EMAIL__").is_dir());
        assert!(staging
            .join("__REDACTED_EMAIL__")
            .join("report___REDACTED_PHONE__.md")
            .is_file());
        assert!(staging.join("__REDACTED_IP__.rs").is_file());
        assert!(staging.join("__REDACTED_SECRET__.txt").is_file());
        assert!(!staging.join(email).exists());
        assert!(!staging.join(format!("{token}.txt")).exists());
        assert_tree_excludes_raw(&staging, &[email, phone, &token]);
        assert!(fs::symlink_metadata(&layout.output).is_err());
        assert_eq!(
            fs::read(src.join("main.rs")).expect("read after"),
            source_main_before
        );
        assert_eq!(
            fs::read(src.join("config.rs")).expect("read after"),
            source_config_before
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            for directory in [
                staging.clone(),
                staging.join("src"),
                staging.join("__REDACTED_EMAIL__"),
            ] {
                let mode = fs::metadata(directory)
                    .expect("directory metadata")
                    .permissions()
                    .mode()
                    & 0o777;
                assert_eq!(mode, 0o700);
            }
        }

        let debug = format!("{tree:?}");
        for raw in [email, phone, token.as_str()] {
            assert!(!debug.contains(raw));
        }
        assert!(debug.contains("unverified-unpublished"));
        layout.assert_disposed(tree.discard());
    }

    #[test]
    fn wide_sibling_staging_tree_builds_with_depth_first_validation() {
        let fixture = TestDirectory::new("wide-staging-tree");
        let layout = fixture.layout();
        let width = 256;
        for index in 0..width {
            fs::create_dir(layout.source.join(format!("ordinary-{index:03}")))
                .expect("create sibling source directory");
        }

        let tree = build_unverified_sanitized_staging_tree(layout.boundary(), Limits::default())
            .expect("wide sibling tree is buildable");

        assert_eq!(tree.directories_written, width);
        assert_eq!(tree.files_written, 0);
        assert_eq!(tree.files_omitted, 0);
        assert_eq!(
            fs::read_dir(layout.staging())
                .expect("read staged siblings")
                .count(),
            width
        );
        layout.assert_disposed(tree.discard());
    }

    #[test]
    fn structural_validation_stops_at_expected_count_plus_one() {
        let fixture = TestDirectory::new("structural-expected-bound");
        let layout = fixture.layout();
        let boundary = layout.boundary();
        for index in 0..8 {
            boundary
                .staging()
                .write(format!("injected-{index}.rs"), b"synthetic")
                .expect("inject staging sibling");
        }
        let observed = Cell::new(0_usize);

        let error = validate_staged_structure_with_observer(
            boundary.staging(),
            Aggregate {
                files_written: 1,
                ..Aggregate::default()
            },
            inventory::DEFAULT_MAX_DEPTH,
            100,
            &mut || observed.set(observed.get() + 1),
        )
        .expect_err("second actual entry exceeds expected aggregate");

        assert_eq!(error, StagingTreeError::StagingEntryLimitExceeded);
        assert_eq!(observed.get(), 2);
    }

    #[test]
    fn structural_validation_rejects_expected_entries_above_global_bound_before_walk() {
        let fixture = TestDirectory::new("structural-global-preflight");
        let layout = fixture.layout();
        let boundary = layout.boundary();
        boundary
            .staging()
            .write("must-not-be-observed.rs", b"synthetic")
            .expect("write staging entry");

        for (expected_files, max_entries) in [(3_usize, 2_usize), (101, 100)] {
            let observed = Cell::new(0_usize);
            let error = validate_staged_structure_with_observer(
                boundary.staging(),
                Aggregate {
                    files_written: expected_files,
                    ..Aggregate::default()
                },
                inventory::DEFAULT_MAX_DEPTH,
                max_entries,
                &mut || observed.set(observed.get() + 1),
            )
            .expect_err("expected aggregate above global limit rejects before walk");

            assert_eq!(error, StagingTreeError::StagingEntryLimitExceeded);
            assert_eq!(observed.get(), 0);
        }
    }

    #[test]
    fn structural_validation_uses_expected_bound_when_it_is_stricter() {
        let fixture = TestDirectory::new("structural-dual-bound");
        let layout = fixture.layout();
        let boundary = layout.boundary();
        for index in 0..3 {
            boundary
                .staging()
                .write(format!("entry-{index}.rs"), b"synthetic")
                .expect("inject staging sibling");
        }
        let observed = Cell::new(0_usize);

        let error = validate_staged_structure_with_observer(
            boundary.staging(),
            Aggregate {
                files_written: 2,
                ..Aggregate::default()
            },
            inventory::DEFAULT_MAX_DEPTH,
            100,
            &mut || observed.set(observed.get() + 1),
        )
        .expect_err("third entry exceeds expected bound");

        assert_eq!(error, StagingTreeError::StagingEntryLimitExceeded);
        assert_eq!(observed.get(), 3);
    }

    #[test]
    fn structural_validation_checked_arithmetic_fails_closed() {
        let fixture = TestDirectory::new("structural-arithmetic");
        let layout = fixture.layout();
        let boundary = layout.boundary();
        let observed = Cell::new(0_usize);

        let expected_error = validate_staged_structure_with_observer(
            boundary.staging(),
            Aggregate {
                files_written: usize::MAX,
                directories_written: 1,
                ..Aggregate::default()
            },
            inventory::DEFAULT_MAX_DEPTH,
            usize::MAX,
            &mut || observed.set(observed.get() + 1),
        )
        .expect_err("expected aggregate overflow rejects");
        assert_eq!(expected_error, StagingTreeError::CountOverflow);
        assert_eq!(observed.get(), 0);

        let mut counts = StructuralValidationCounts {
            total: usize::MAX,
            ..StructuralValidationCounts::default()
        };
        assert_eq!(
            counts.record_entry(usize::MAX, usize::MAX),
            Err(StagingTreeError::CountOverflow)
        );
    }

    #[test]
    fn structural_validation_accepts_exact_and_zero_entry_trees() {
        let exact_fixture = TestDirectory::new("structural-exact");
        let exact_layout = exact_fixture.layout();
        let exact_boundary = exact_layout.boundary();
        fs::create_dir(exact_layout.staging().join("nested"))
            .expect("create expected staging directory");
        fs::write(
            exact_layout.staging().join("nested/inside.rs"),
            b"synthetic",
        )
        .expect("write expected staged file");
        let exact_observed = Cell::new(0_usize);
        validate_staged_structure_with_observer(
            exact_boundary.staging(),
            Aggregate {
                files_written: 1,
                directories_written: 1,
                ..Aggregate::default()
            },
            inventory::DEFAULT_MAX_DEPTH,
            2,
            &mut || exact_observed.set(exact_observed.get() + 1),
        )
        .expect("exact tree validates");
        assert_eq!(exact_observed.get(), 2);

        let zero_fixture = TestDirectory::new("structural-zero");
        let zero_layout = zero_fixture.layout();
        let zero_boundary = zero_layout.boundary();
        let zero_observed = Cell::new(0_usize);
        validate_staged_structure_with_observer(
            zero_boundary.staging(),
            Aggregate::default(),
            inventory::DEFAULT_MAX_DEPTH,
            0,
            &mut || zero_observed.set(zero_observed.get() + 1),
        )
        .expect("empty tree validates");
        assert_eq!(zero_observed.get(), 0);
    }

    #[test]
    fn zero_expected_entry_stops_before_opening_injected_deep_directory() {
        let fixture = TestDirectory::new("structural-deep-injection");
        let layout = fixture.layout();
        let boundary = layout.boundary();
        let injected = layout.staging().join("injected-directory");
        fs::create_dir(&injected).expect("create injected directory");
        for index in 0..32 {
            fs::write(
                injected.join(format!("descendant-{index}.rs")),
                b"synthetic",
            )
            .expect("write injected descendant");
        }
        let observed = Cell::new(0_usize);

        let error = validate_staged_structure_with_observer(
            boundary.staging(),
            Aggregate::default(),
            inventory::DEFAULT_MAX_DEPTH,
            100,
            &mut || observed.set(observed.get() + 1),
        )
        .expect_err("first unexpected root entry exceeds zero expected bound");

        assert_eq!(error, StagingTreeError::StagingEntryLimitExceeded);
        assert_eq!(observed.get(), 1);
    }

    #[test]
    fn effective_policy_omits_untransformable_and_sensitive_filename_files() {
        let fixture = TestDirectory::new("omissions");
        let layout = fixture.layout();
        let outside = fixture.0.join("outside.rs");
        fs::write(layout.source.join(".env"), b"SECRET=fixture\n").expect("write env");
        fs::write(layout.source.join("id_rsa"), b"synthetic private fixture")
            .expect("write key name");
        fs::write(
            layout.source.join("credentials.json"),
            b"{\"fixture\":true}\n",
        )
        .expect("write credentials");
        fs::write(layout.source.join(".npmrc"), b"fixture=true\n").expect("write auth config");
        fs::write(layout.source.join("archive.bin"), [0_u8, 1, 2]).expect("write binary");
        fs::write(layout.source.join("unknown.data"), b"unknown").expect("write unknown");
        fs::write(layout.source.join("invalid.rs"), [0xff, 0xfe]).expect("write invalid UTF-8");
        fs::write(layout.source.join("oversized.rs"), b"12345").expect("write oversized");
        fs::write(&outside, b"external hard-link fixture").expect("write external fixture");
        fs::hard_link(&outside, layout.source.join("hard.rs")).expect("create hard link");
        let source_before = fs::read(layout.source.join("credentials.json")).expect("read before");

        let tree = build_unverified_sanitized_staging_tree(
            layout.boundary(),
            Limits {
                content: content::Limits {
                    max_file_bytes: 4,
                    max_total_bytes: 64,
                },
                ..Limits::default()
            },
        )
        .expect("omissions are successful policy outcomes");

        assert_eq!(tree.files_written, 0);
        assert_eq!(tree.files_omitted, 9);
        assert_eq!(tree.directories_written, 0);
        assert!(fs::read_dir(layout.staging())
            .expect("read empty staging")
            .next()
            .is_none());
        assert_eq!(
            fs::read(layout.source.join("credentials.json")).expect("read after"),
            source_before
        );
        assert_eq!(
            fs::read(&outside).expect("read external"),
            b"external hard-link fixture"
        );
        layout.assert_disposed(tree.discard());
    }

    #[test]
    fn filename_omit_prevents_content_budget_consumption() {
        let fixture = TestDirectory::new("filename-preflight");
        let layout = fixture.layout();
        fs::write(
            layout.source.join("credentials.json"),
            b"must not be opened",
        )
        .expect("write filename-evidenced file");

        let tree = build_unverified_sanitized_staging_tree(
            layout.boundary(),
            Limits {
                content: content::Limits {
                    max_file_bytes: 1024,
                    max_total_bytes: 0,
                },
                ..Limits::default()
            },
        )
        .expect("filename evidence omits before content access");

        assert_eq!(tree.files_written, 0);
        assert_eq!(tree.files_omitted, 1);
        layout.assert_disposed(tree.discard());
    }

    #[test]
    fn sanitized_directory_and_file_collisions_follow_platform_disposal_policy() {
        let directory_fixture = TestDirectory::new("directory-collision");
        let directory_layout = directory_fixture.layout();
        fs::create_dir(directory_layout.source.join("alice@example.invalid"))
            .expect("create first email directory");
        fs::create_dir(directory_layout.source.join("bob@example.invalid"))
            .expect("create second email directory");
        let error =
            build_unverified_sanitized_staging_tree(directory_layout.boundary(), Limits::default())
                .expect_err("directory collision must fail");
        directory_layout.assert_failure(error, StagingTreeError::StagingCollision);
        for raw in ["alice@example.invalid", "bob@example.invalid"] {
            assert!(!error.to_string().contains(raw));
            assert!(!format!("{error:?}").contains(raw));
        }

        let file_fixture = TestDirectory::new("file-collision");
        let file_layout = file_fixture.layout();
        fs::write(
            file_layout.source.join("alice@example.invalid.txt"),
            b"first",
        )
        .expect("write first email file");
        fs::write(
            file_layout.source.join("bob@example.invalid.txt"),
            b"second",
        )
        .expect("write second email file");
        let error =
            build_unverified_sanitized_staging_tree(file_layout.boundary(), Limits::default())
                .expect_err("file collision must fail");
        file_layout.assert_failure(error, StagingTreeError::StagingCollision);
        #[cfg(windows)]
        assert!(file_layout
            .staging()
            .join("__REDACTED_EMAIL__.txt")
            .is_file());
        for raw in ["alice@example.invalid.txt", "bob@example.invalid.txt"] {
            assert!(!error.to_string().contains(raw));
            assert!(!format!("{error:?}").contains(raw));
        }
    }

    #[test]
    fn injected_entry_is_never_overwritten_or_merged() {
        let fixture = TestDirectory::new("injected-entry");
        let layout = fixture.layout();
        fs::write(layout.source.join("main.rs"), b"source remains unchanged")
            .expect("write source");
        let source_before = fs::read(layout.source.join("main.rs")).expect("read source before");
        let boundary = layout.boundary();
        boundary
            .staging()
            .write("main.rs", b"injected staging bytes")
            .expect("inject collision");

        let error = build_unverified_sanitized_staging_tree(boundary, Limits::default())
            .expect_err("create-new collision must fail");
        layout.assert_failure(error, StagingTreeError::StagingCollision);
        assert_eq!(
            fs::read(layout.source.join("main.rs")).expect("read source after"),
            source_before
        );
    }

    #[test]
    fn post_build_regular_file_injection_hits_manual_disposal_policy() {
        let fixture = TestDirectory::new("post-build-file-injection");
        let layout = fixture.layout();
        let source_file = layout.source.join("main.rs");
        fs::write(&source_file, b"source remains unchanged").expect("write source");
        let source_before = fs::read(&source_file).expect("read source before build");
        let staging = layout.staging();
        let raw_name = "synthetic-private-unexpected-entry.rs";

        let error = build_with_hook(layout.boundary(), Limits::default(), |event| {
            if event == BuildEvent::BeforeStructuralValidation {
                fs::write(staging.join(raw_name), b"injected after build")
                    .map_err(|_| StagingTreeError::StagingWriteFailed)?;
            }
            Ok(())
        })
        .expect_err("unexpected post-build file exceeds trusted aggregate");

        layout.assert_failure(error, StagingTreeError::StagingEntryLimitExceeded);
        assert_eq!(
            fs::read(&source_file).expect("read source after build"),
            source_before
        );
        assert!(!error.to_string().contains(raw_name));
        assert!(!format!("{error:?}").contains(raw_name));
        #[cfg(windows)]
        assert!(staging.join(raw_name).is_file());
    }

    #[test]
    fn post_build_directory_injection_stops_before_descendant_walk() {
        let fixture = TestDirectory::new("post-build-directory-injection");
        let layout = fixture.layout();
        let staging = layout.staging();
        let raw_name = "synthetic-private-unexpected-directory";

        let error = build_with_hook(layout.boundary(), Limits::default(), |event| {
            if event == BuildEvent::BeforeStructuralValidation {
                let injected = staging.join(raw_name);
                fs::create_dir(&injected)
                    .map_err(|_| StagingTreeError::StagingDirectoryCreationFailed)?;
                for index in 0..32 {
                    fs::write(
                        injected.join(format!("descendant-{index}.rs")),
                        b"synthetic",
                    )
                    .map_err(|_| StagingTreeError::StagingWriteFailed)?;
                }
            }
            Ok(())
        })
        .expect_err("unexpected root directory exceeds zero expected entries");

        layout.assert_failure(error, StagingTreeError::StagingEntryLimitExceeded);
        assert!(fs::read_dir(&layout.source)
            .expect("read unchanged source")
            .next()
            .is_none());
        assert!(!error.to_string().contains(raw_name));
        assert!(!format!("{error:?}").contains(raw_name));
        #[cfg(windows)]
        assert!(staging.join(raw_name).is_dir());
    }

    #[test]
    fn post_build_injection_cannot_exceed_small_global_entry_limit() {
        let fixture = TestDirectory::new("post-build-global-limit");
        let layout = fixture.layout();
        fs::write(layout.source.join("main.rs"), b"ordinary source").expect("write source");
        let staging = layout.staging();

        let error = build_with_hook(
            layout.boundary(),
            Limits {
                inventory: inventory::Limits {
                    max_entries: 1,
                    ..inventory::Limits::default()
                },
                ..Limits::default()
            },
            |event| {
                if event == BuildEvent::BeforeStructuralValidation {
                    fs::write(staging.join("unexpected.rs"), b"injected after build")
                        .map_err(|_| StagingTreeError::StagingWriteFailed)?;
                }
                Ok(())
            },
        )
        .expect_err("actual staging cannot exceed global entry limit");

        layout.assert_failure(error, StagingTreeError::StagingEntryLimitExceeded);
        assert!(layout.source.join("main.rs").is_file());
        #[cfg(windows)]
        assert!(staging.join("unexpected.rs").is_file());
    }

    #[test]
    fn transform_and_write_failures_follow_platform_disposal_policy() {
        let transform_fixture = TestDirectory::new("transform-failure");
        let transform_layout = transform_fixture.layout();
        fs::create_dir(transform_layout.source.join("ordinary")).expect("create parent");
        fs::write(
            transform_layout.source.join("ordinary/inside.rs"),
            b"nonempty",
        )
        .expect("write source");
        let error = build_unverified_sanitized_staging_tree(
            transform_layout.boundary(),
            Limits {
                transform: transform::Limits {
                    max_output_bytes_per_file: 0,
                    ..transform::Limits::default()
                },
                ..Limits::default()
            },
        )
        .expect_err("content transform limit must fail");
        transform_layout.assert_failure(
            error,
            StagingTreeError::Transform(TransformError::OutputLimitExceeded),
        );

        let path_fixture = TestDirectory::new("path-transform-failure");
        let path_layout = path_fixture.layout();
        fs::create_dir(path_layout.source.join("a")).expect("create first directory");
        fs::create_dir(path_layout.source.join("a/bb")).expect("create nested directory");
        let error = build_unverified_sanitized_staging_tree(
            path_layout.boundary(),
            Limits {
                path_transform: path_transform::Limits {
                    max_output_bytes_per_component: 1,
                    ..path_transform::Limits::default()
                },
                ..Limits::default()
            },
        )
        .expect_err("nested path transform limit must fail");
        path_layout.assert_failure(
            error,
            StagingTreeError::PathTransform(PathTransformError::OutputLimitExceeded),
        );

        let write_fixture = TestDirectory::new("write-failure");
        let write_layout = write_fixture.layout();
        fs::create_dir(write_layout.source.join("ordinary")).expect("create parent");
        fs::write(write_layout.source.join("ordinary/inside.rs"), b"content")
            .expect("write source");
        let error = build_with_hook(
            write_layout.boundary(),
            Limits::default(),
            |event| match event {
                BuildEvent::BeforeFileWrite => Err(StagingTreeError::StagingWriteFailed),
                BuildEvent::BeforeStructuralValidation => Ok(()),
            },
        )
        .expect_err("write failure must fail the run");
        write_layout.assert_failure(error, StagingTreeError::StagingWriteFailed);
    }

    #[cfg(windows)]
    #[test]
    fn builder_failure_before_first_write_is_manual_and_leaves_empty_staging() {
        let fixture = TestDirectory::new("before-first-write-failure");
        let layout = fixture.layout();
        fs::write(layout.source.join("main.rs"), b"nonempty").expect("write source");

        let error = build_unverified_sanitized_staging_tree(
            layout.boundary(),
            Limits {
                transform: transform::Limits {
                    max_output_bytes_per_file: 0,
                    ..transform::Limits::default()
                },
                ..Limits::default()
            },
        )
        .expect_err("pre-write transform failure rejects build");

        assert_eq!(error, StagingTreeError::ManualInspectionRequired);
        assert!(layout.staging().is_dir());
        assert!(fs::read_dir(layout.staging())
            .expect("inspect abandoned staging")
            .next()
            .is_none());
        assert!(fs::symlink_metadata(&layout.output).is_err());
    }

    #[test]
    fn content_and_path_detector_limit_failures_follow_platform_disposal_policy() {
        let token = synthetic_github_token();

        let content_fixture = TestDirectory::new("content-detector-limit");
        let content_layout = content_fixture.layout();
        fs::write(
            content_layout.source.join("main.rs"),
            format!("const TOKEN: &str = \"{token}\";\n"),
        )
        .expect("write synthetic token content");
        let error = build_unverified_sanitized_staging_tree(
            content_layout.boundary(),
            Limits {
                secrets: secrets::Limits {
                    max_matches_per_rule_per_file: 0,
                    ..secrets::Limits::default()
                },
                ..Limits::default()
            },
        )
        .expect_err("content detector limit must fail the build");
        content_layout.assert_failure(
            error,
            StagingTreeError::Secret(SecretError::MatchLimitExceeded),
        );

        let path_fixture = TestDirectory::new("path-detector-limit");
        let path_layout = path_fixture.layout();
        fs::create_dir(path_layout.source.join(&token)).expect("create synthetic token directory");
        let error = build_unverified_sanitized_staging_tree(
            path_layout.boundary(),
            Limits {
                path_evidence: path_evidence::Limits {
                    secrets: secrets::Limits {
                        max_matches_per_rule_per_file: 0,
                        ..secrets::Limits::default()
                    },
                    ..path_evidence::Limits::default()
                },
                ..Limits::default()
            },
        )
        .expect_err("path detector limit must fail the build");
        path_layout.assert_failure(
            error,
            StagingTreeError::PathEvidence(PathEvidenceError::Secret(
                SecretError::MatchLimitExceeded,
            )),
        );
    }

    #[test]
    fn aggregate_arithmetic_is_checked() {
        assert_eq!(
            Aggregate {
                files_written: usize::MAX,
                ..Aggregate::default()
            }
            .with_written_file(&PreparedFile {
                output_name: "safe.rs".to_owned(),
                content: TransformedText {
                    text: String::new(),
                    regions: 0,
                    source_bytes_redacted: 0,
                },
                path_regions: 0,
            }),
            Err(StagingTreeError::CountOverflow)
        );
        assert_eq!(
            Aggregate {
                staged_bytes_written: usize::MAX,
                ..Aggregate::default()
            }
            .with_written_file(&PreparedFile {
                output_name: "safe.rs".to_owned(),
                content: TransformedText {
                    text: "x".to_owned(),
                    regions: 0,
                    source_bytes_redacted: 0,
                },
                path_regions: 0,
            }),
            Err(StagingTreeError::CountOverflow)
        );
        assert_eq!(
            Aggregate {
                directories_written: usize::MAX,
                ..Aggregate::default()
            }
            .with_directory(0),
            Err(StagingTreeError::CountOverflow)
        );
    }

    #[cfg(unix)]
    #[test]
    fn retained_source_capability_survives_ambient_root_rename() {
        let fixture = TestDirectory::new("retained-source-capability");
        let layout = fixture.layout();
        fs::write(layout.source.join("main.rs"), b"fn main() {}\n").expect("write source");
        let boundary = layout.boundary();
        let moved_source = fixture.0.join("ambient-name-removed-after-boundary");
        fs::rename(&layout.source, &moved_source).expect("rename ambient source root");

        let tree = build_unverified_sanitized_staging_tree(boundary, Limits::default())
            .expect("builder must walk the retained source handle");

        assert_eq!(tree.files_written, 1);
        assert_eq!(tree.files_omitted, 0);
        assert!(layout.staging().join("main.rs").is_file());
        assert_eq!(
            fs::read(moved_source.join("main.rs")).expect("read moved source"),
            b"fn main() {}\n"
        );
        layout.assert_disposed(tree.discard());
    }

    #[cfg(unix)]
    #[test]
    fn changed_fixed_staging_identity_makes_discard_fail_closed() {
        let fixture = TestDirectory::new("cleanup-identity-change");
        let layout = fixture.layout();
        fs::write(layout.source.join("main.rs"), b"fn main() {}\n").expect("write source");
        let tree = build_unverified_sanitized_staging_tree(layout.boundary(), Limits::default())
            .expect("build tree");
        let moved_staging = layout.parent.join("moved-original-staging");
        fs::rename(layout.staging(), &moved_staging).expect("move expected staging leaf");
        fs::create_dir(layout.staging()).expect("create replacement fixed leaf");
        fs::write(layout.staging().join("replacement"), b"untouched")
            .expect("populate replacement");

        assert_eq!(tree.discard(), Err(StagingTreeError::CleanupFailed));
        assert_eq!(
            fs::read(layout.staging().join("replacement")).expect("replacement remains"),
            b"untouched"
        );
        assert!(moved_staging.join("main.rs").is_file());
        assert!(fs::symlink_metadata(&layout.output).is_err());

        fs::remove_dir_all(layout.staging()).expect("remove test replacement");
        fs::remove_dir_all(moved_staging).expect("remove moved test staging");
        layout.assert_cleaned();
    }

    #[cfg(unix)]
    #[test]
    fn unix_non_utf8_file_is_omitted_and_directory_aborts_with_cleanup() {
        use std::os::unix::ffi::OsStringExt;

        let file_fixture = TestDirectory::new("non-utf8-file");
        let file_layout = file_fixture.layout();
        let file_name = std::ffi::OsString::from_vec(b"fixture-\xff@example.invalid.rs".to_vec());
        fs::write(file_layout.source.join(&file_name), b"not read").expect("write raw file name");
        let tree =
            build_unverified_sanitized_staging_tree(file_layout.boundary(), Limits::default())
                .expect("non-UTF8 file is omitted");
        assert_eq!(tree.files_written, 0);
        assert_eq!(tree.files_omitted, 1);
        file_layout.assert_disposed(tree.discard());

        let directory_fixture = TestDirectory::new("non-utf8-directory");
        let directory_layout = directory_fixture.layout();
        fs::create_dir(directory_layout.source.join("ordinary")).expect("create ordinary parent");
        let directory_name = std::ffi::OsString::from_vec(b"private-\xff-directory".to_vec());
        fs::create_dir(
            directory_layout
                .source
                .join("ordinary")
                .join(directory_name),
        )
        .expect("create raw directory name");
        let error =
            build_unverified_sanitized_staging_tree(directory_layout.boundary(), Limits::default())
                .expect_err("non-UTF8 directory is unresolved");
        directory_layout.assert_failure(error, StagingTreeError::UninspectableDirectory);
    }

    #[cfg(unix)]
    #[test]
    fn unix_source_and_staging_symlinks_are_never_followed_or_accepted() {
        use std::os::unix::fs::symlink;

        let fixture = TestDirectory::new("unix-source-links");
        let layout = fixture.layout();
        let outside = fixture.0.join("outside");
        fs::create_dir(&outside).expect("create outside");
        fs::write(outside.join("outside.rs"), b"must not be read").expect("write outside");
        fs::create_dir(layout.source.join(".git")).expect("create git metadata");
        fs::write(layout.source.join(".git/hidden.rs"), b"hidden").expect("write hidden");
        symlink(&outside, layout.source.join("linked")).expect("create source symlink");
        fs::write(layout.source.join("main.rs"), b"fn main() {}\n").expect("write source");

        let tree = build_unverified_sanitized_staging_tree(layout.boundary(), Limits::default())
            .expect("source links and git metadata are excluded");
        assert_eq!(tree.files_written, 1);
        assert_eq!(tree.directories_written, 0);
        assert_eq!(tree.files_omitted, 0);
        assert!(layout.staging().join("main.rs").is_file());
        assert!(!layout.staging().join("linked").exists());
        assert!(!layout.staging().join(".git").exists());
        layout.assert_disposed(tree.discard());

        let injected_fixture = TestDirectory::new("unix-injected-link");
        let injected_layout = injected_fixture.layout();
        let injected_outside = injected_fixture.0.join("outside");
        fs::create_dir(&injected_outside).expect("create outside");
        fs::write(injected_layout.source.join("main.rs"), b"fn main() {}\n").expect("write source");
        let boundary = injected_layout.boundary();
        symlink(
            &injected_outside,
            injected_layout.staging().join("unexpected-link"),
        )
        .expect("inject staging symlink");

        let error = build_unverified_sanitized_staging_tree(boundary, Limits::default())
            .expect_err("unexpected staging symlink must fail structural validation");
        injected_layout.assert_failure(error, StagingTreeError::StagingEntryChanged);
    }

    #[cfg(windows)]
    #[test]
    fn windows_source_and_staging_junctions_are_never_followed_or_accepted() {
        let fixture = TestDirectory::new("windows-source-junctions");
        let layout = fixture.layout();
        let outside = fixture.0.join("outside");
        fs::create_dir(&outside).expect("create outside");
        fs::write(outside.join("outside.rs"), b"must not be read").expect("write outside");
        fs::create_dir(layout.source.join(".git")).expect("create git metadata");
        fs::write(layout.source.join(".git/hidden.rs"), b"hidden").expect("write hidden");
        create_junction(&layout.source.join("linked"), &outside);
        fs::write(layout.source.join("main.rs"), b"fn main() {}\n").expect("write source");

        let tree = build_unverified_sanitized_staging_tree(layout.boundary(), Limits::default())
            .expect("source junctions and git metadata are excluded");
        assert_eq!(tree.files_written, 1);
        assert_eq!(tree.directories_written, 0);
        assert_eq!(tree.files_omitted, 0);
        assert!(layout.staging().join("main.rs").is_file());
        assert!(!layout.staging().join("linked").exists());
        assert!(!layout.staging().join(".git").exists());
        layout.assert_disposed(tree.discard());

        let injected_fixture = TestDirectory::new("windows-injected-junction");
        let injected_layout = injected_fixture.layout();
        let injected_outside = injected_fixture.0.join("outside");
        fs::create_dir(&injected_outside).expect("create outside");
        fs::write(injected_layout.source.join("main.rs"), b"fn main() {}\n").expect("write source");
        let boundary = injected_layout.boundary();
        create_junction(
            &injected_layout.staging().join("unexpected-junction"),
            &injected_outside,
        );

        let error = build_unverified_sanitized_staging_tree(boundary, Limits::default())
            .expect_err("unexpected staging junction must fail structural validation");
        injected_layout.assert_failure(error, StagingTreeError::StagingEntryChanged);
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
