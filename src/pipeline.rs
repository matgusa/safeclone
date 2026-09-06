//! Thin orchestration boundary.

use std::ffi::OsStr;
use std::fmt;
use std::path::PathBuf;

use crate::content::{self, ContentError, Report as ContentReport, Session as ContentSession};
use crate::detection::DetectedKind;
use crate::filename::{self, FilenameError, Report as FilenameReport, Session as FilenameSession};
use crate::inventory::{self, Inventory, InventoryError};
use crate::locality::{
    self, ConfirmedLocalOutputParent, ConfirmedLocalSource, LocalityError, PreflightedOutputPath,
    PreflightedSourcePath,
};
use crate::path_evidence::{
    self, ComponentKind, PathEvidenceError, Report as PathEvidenceReport,
    Session as PathEvidenceSession,
};
use crate::policy::{
    self, EffectiveDispositionPlan, FileDispositionInput, FilenameEvidence, PolicyPlanError,
    RegularFileClassifications, RegularFilePolicyPlan,
};
use crate::promotion::{self, PromotionError, PublicationReport};
use crate::secrets::{self, Report as SecretReport, SecretError, Session as SecretSession};
use crate::sensitive::{
    self, Report as SensitiveReport, SensitiveError, Session as SensitiveSession,
};
use crate::staging::{self, StagingError};
use crate::staging_tree::{self, StagingBuildSummary, StagingTreeError};
use crate::verification::{self, VerificationError, VerificationLimits};

#[derive(Eq, PartialEq)]
pub struct CloneRequest {
    pub source: PathBuf,
    pub output: PathBuf,
}

impl fmt::Debug for CloneRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CloneRequest")
            .field("source_path_retained", &true)
            .field("output_path_retained", &true)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CloneReport {
    pub build: StagingBuildSummary,
    pub publication: PublicationReport,
    pub policy_id: &'static str,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CloneFailureClass {
    DefiniteFailure,
    ManualInspectionRequired,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CloneError {
    Locality(LocalityError),
    Staging(StagingError),
    Build(StagingTreeError),
    Verification(VerificationError),
    Promotion(PromotionError),
}

impl CloneError {
    /// Pure certainty classification for a future CLI. Cleanup failures and
    /// indeterminate namespace states require manual inspection; all other
    /// failures have a definite fail-closed outcome.
    pub const fn classification(&self) -> CloneFailureClass {
        let requires_manual_inspection = match self {
            Self::Locality(_) => false,
            Self::Staging(error) => staging_error_requires_manual_inspection(*error),
            Self::Build(error) => build_error_requires_manual_inspection(*error),
            Self::Verification(error) => verification_error_requires_manual_inspection(*error),
            Self::Promotion(error) => promotion_error_requires_manual_inspection(*error),
        };
        if requires_manual_inspection {
            CloneFailureClass::ManualInspectionRequired
        } else {
            CloneFailureClass::DefiniteFailure
        }
    }
}

impl fmt::Display for CloneError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Locality(error) => error.fmt(formatter),
            Self::Staging(error) => error.fmt(formatter),
            Self::Build(error) => error.fmt(formatter),
            Self::Verification(error) => error.fmt(formatter),
            Self::Promotion(error) => error.fmt(formatter),
        }
    }
}

trait LocalityOperations {
    type SourcePreflight;
    type OutputPreflight;
    type SourceConfirmed;
    type OutputConfirmed;

    fn preflight_source(
        &mut self,
        source: &std::path::Path,
    ) -> Result<Self::SourcePreflight, LocalityError>;
    fn preflight_clone(
        &mut self,
        source: &std::path::Path,
        output: &std::path::Path,
    ) -> Result<(Self::SourcePreflight, Self::OutputPreflight), LocalityError>;
    fn open_confirm_source(
        &mut self,
        source: Self::SourcePreflight,
    ) -> Result<Self::SourceConfirmed, LocalityError>;
    fn open_confirm_output(
        &mut self,
        output: Self::OutputPreflight,
    ) -> Result<Self::OutputConfirmed, LocalityError>;
}

struct SystemLocalityOperations;

impl LocalityOperations for SystemLocalityOperations {
    type SourcePreflight = PreflightedSourcePath;
    type OutputPreflight = PreflightedOutputPath;
    type SourceConfirmed = ConfirmedLocalSource;
    type OutputConfirmed = ConfirmedLocalOutputParent;

    fn preflight_source(
        &mut self,
        source: &std::path::Path,
    ) -> Result<Self::SourcePreflight, LocalityError> {
        locality::preflight_source_path(source)
    }

    fn preflight_clone(
        &mut self,
        source: &std::path::Path,
        output: &std::path::Path,
    ) -> Result<(Self::SourcePreflight, Self::OutputPreflight), LocalityError> {
        locality::preflight_clone_paths(source, output)
    }

    fn open_confirm_source(
        &mut self,
        source: Self::SourcePreflight,
    ) -> Result<Self::SourceConfirmed, LocalityError> {
        locality::open_and_confirm_source(source)
    }

    fn open_confirm_output(
        &mut self,
        output: Self::OutputPreflight,
    ) -> Result<Self::OutputConfirmed, LocalityError> {
        locality::open_and_confirm_output_parent(output)
    }
}

fn acquire_clone_authority<O: LocalityOperations>(
    request: &CloneRequest,
    operations: &mut O,
) -> Result<(O::SourceConfirmed, O::OutputConfirmed), LocalityError> {
    let (source, output) = operations.preflight_clone(&request.source, &request.output)?;
    let source = operations.open_confirm_source(source)?;
    let output = operations.open_confirm_output(output)?;
    Ok((source, output))
}

fn acquire_inspect_authority<O: LocalityOperations>(
    request: &InspectRequest,
    operations: &mut O,
) -> Result<O::SourceConfirmed, LocalityError> {
    let source = operations.preflight_source(&request.source)?;
    operations.open_confirm_source(source)
}

/// Orchestrate one complete policy-relative library clone workflow.
///
/// This function deliberately does not call `execute_inspect`: the staging
/// boundary retains the source capability used by the builder. A successful
/// `PublishedClone` is the commit point; only Copy report extraction and
/// `CloneReport` construction occur afterward.
pub fn execute_clone(request: CloneRequest) -> Result<CloneReport, CloneError> {
    let mut operations = SystemLocalityOperations;
    let (source, output) =
        acquire_clone_authority(&request, &mut operations).map_err(CloneError::Locality)?;
    drop(request);
    let boundary =
        staging::create_unverified_staging_root(source, output).map_err(CloneError::Staging)?;
    let tree = staging_tree::build_unverified_sanitized_staging_tree(
        boundary,
        staging_tree::Limits::default(),
    )
    .map_err(CloneError::Build)?;
    let build = tree.summary();
    let verified = verification::verify_unverified_staged_tree(tree, VerificationLimits::default())
        .map_err(CloneError::Verification)?;
    let published =
        promotion::promote_verified_staged_tree(verified).map_err(CloneError::Promotion)?;

    let publication = published.report();
    Ok(CloneReport {
        build,
        publication,
        policy_id: policy::DEFAULT_POLICY_ID,
    })
}

const fn staging_error_requires_manual_inspection(error: StagingError) -> bool {
    matches!(
        error,
        StagingError::StagingRequiresManualInspection | StagingError::StagingCleanupFailed
    )
}

const fn build_error_requires_manual_inspection(error: StagingTreeError) -> bool {
    match error {
        StagingTreeError::ManualInspectionRequired | StagingTreeError::CleanupFailed => true,
        StagingTreeError::Boundary(error) => staging_error_requires_manual_inspection(error),
        _ => false,
    }
}

const fn verification_error_requires_manual_inspection(error: VerificationError) -> bool {
    match error {
        VerificationError::ManualInspectionRequired
        | VerificationError::VerificationCleanupFailed => true,
        VerificationError::Boundary(error) => staging_error_requires_manual_inspection(error),
        _ => false,
    }
}

const fn promotion_error_requires_manual_inspection(error: PromotionError) -> bool {
    match error {
        PromotionError::ManualInspectionRequired
        | PromotionError::PromotionCleanupFailed
        | PromotionError::PromotionStateIndeterminate => true,
        PromotionError::Boundary(error) => staging_error_requires_manual_inspection(error),
        PromotionError::FreshVerification(error) => {
            verification_error_requires_manual_inspection(error)
        }
        _ => false,
    }
}

#[derive(Eq, PartialEq)]
pub struct InspectRequest {
    pub source: PathBuf,
}

impl fmt::Debug for InspectRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InspectRequest")
            .field("source_path_retained", &true)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct InspectLimits {
    pub(crate) inventory: inventory::Limits,
    pub(crate) filename: filename::Limits,
    pub(crate) path_evidence: path_evidence::Limits,
    pub(crate) content: content::Limits,
    pub(crate) secrets: secrets::Limits,
    pub(crate) sensitive: sensitive::Limits,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct StructuralExclusions {
    pub link_like: usize,
    pub git_metadata: usize,
    pub special: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InspectReport {
    pub inventory: Inventory,
    pub filename: FilenameReport,
    pub path_evidence: PathEvidenceReport,
    pub regular_file_policy: RegularFilePolicyPlan,
    pub effective_policy: EffectiveDispositionPlan,
    pub structural_exclusions: StructuralExclusions,
    pub content: ContentReport,
    pub secrets: SecretReport,
    pub sensitive: SensitiveReport,
    pub inspection_only: bool,
    pub sanitization_performed: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InspectError {
    Locality(LocalityError),
    Inventory(InventoryError),
    Filename(FilenameError),
    PathEvidence(PathEvidenceError),
    PolicyPlan(PolicyPlanError),
    Content(ContentError),
    Secrets(SecretError),
    Sensitive(SensitiveError),
}

impl fmt::Display for InspectError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Locality(error) => error.fmt(formatter),
            Self::Inventory(error) => error.fmt(formatter),
            Self::Filename(error) => error.fmt(formatter),
            Self::PathEvidence(error) => error.fmt(formatter),
            Self::PolicyPlan(error) => error.fmt(formatter),
            Self::Content(error) => error.fmt(formatter),
            Self::Secrets(error) => error.fmt(formatter),
            Self::Sensitive(error) => error.fmt(formatter),
        }
    }
}

pub fn execute_inspect(request: InspectRequest) -> Result<InspectReport, InspectError> {
    execute_inspect_with_limits(request, InspectLimits::default())
}

fn execute_inspect_with_limits(
    request: InspectRequest,
    limits: InspectLimits,
) -> Result<InspectReport, InspectError> {
    execute_inspect_with_hook(request, limits, |_, _| {})
}

fn execute_inspect_with_hook(
    request: InspectRequest,
    limits: InspectLimits,
    before_child_open: impl FnMut(&OsStr, usize),
) -> Result<InspectReport, InspectError> {
    let mut operations = SystemLocalityOperations;
    let source =
        acquire_inspect_authority(&request, &mut operations).map_err(InspectError::Locality)?;
    drop(request);
    execute_inspect_from_open_source(source.into_directory(), limits, before_child_open)
}

fn execute_inspect_from_open_source(
    source: cap_std::fs::Dir,
    limits: InspectLimits,
    before_child_open: impl FnMut(&OsStr, usize),
) -> Result<InspectReport, InspectError> {
    let mut filename = FilenameSession::new(limits.filename);
    let mut path_evidence =
        PathEvidenceSession::new(limits.path_evidence).map_err(InspectError::PathEvidence)?;
    let mut effective_policy = policy::EffectiveDispositionSession::new();
    let mut content = ContentSession::new(limits.content);
    let mut secrets = SecretSession::new(limits.secrets).map_err(InspectError::Secrets)?;
    let mut sensitive = SensitiveSession::new(limits.sensitive).map_err(InspectError::Sensitive)?;
    let inventory = inventory::inspect_components_with_hook(
        source,
        limits.inventory,
        before_child_open,
        |directory, name, component| {
            let component_kind = match component {
                inventory::ObservedComponent::Directory => ComponentKind::Directory,
                inventory::ObservedComponent::RegularFile(_) => ComponentKind::File,
            };
            let component_inspectability = path_evidence
                .scan_component(name, component_kind)
                .map_err(ComponentError::PathEvidence)?;

            match component {
                inventory::ObservedComponent::Directory => effective_policy
                    .observe_directory(component_inspectability)
                    .map_err(ComponentError::Policy),
                inventory::ObservedComponent::RegularFile(kind) => {
                    let mut filename_evidence = FilenameEvidence::default();
                    filename
                        .scan_basename(name, |findings| {
                            filename_evidence = FilenameEvidence::from_findings(findings);
                        })
                        .map_err(ComponentError::Filename)?;

                    let content_outcome = if kind == DetectedKind::TextOrCodeCandidate {
                        let mut detector_result = Ok(());
                        let outcome = content
                            .inspect_candidate(directory, name, |text| {
                                detector_result = secrets
                                    .scan_file(text, |_| {})
                                    .map(|_| ())
                                    .map_err(ComponentError::Secrets)
                                    .and_then(|()| {
                                        sensitive
                                            .scan_file(text, |_| {})
                                            .map(|_| ())
                                            .map_err(ComponentError::Sensitive)
                                    });
                            })
                            .map_err(ComponentError::Content)?;
                        detector_result?;
                        Some(outcome)
                    } else {
                        None
                    };

                    effective_policy
                        .observe_file(FileDispositionInput {
                            detected_kind: kind,
                            content_outcome,
                            filename: filename_evidence,
                            path_component: component_inspectability,
                        })
                        .map_err(ComponentError::Policy)
                }
            }
        },
    )
    .map_err(|error| match error {
        inventory::StreamingError::Inventory(error) => InspectError::Inventory(error),
        inventory::StreamingError::Component(error) => map_component_error(error),
    })?;
    let path_evidence = path_evidence.finish().map_err(InspectError::PathEvidence)?;
    let filename = filename.finish().map_err(InspectError::Filename)?;
    let content = content.finish().map_err(InspectError::Content)?;
    let secrets = secrets.finish().map_err(InspectError::Secrets)?;
    let sensitive = sensitive.finish().map_err(InspectError::Sensitive)?;
    let effective_policy = effective_policy
        .finish(inventory.regular_files, inventory.directories)
        .map_err(InspectError::PolicyPlan)?;
    build_inspect_report_with_path_and_effective(
        inventory,
        path_evidence,
        filename,
        content,
        secrets,
        sensitive,
        effective_policy,
    )
}

#[cfg(test)]
fn execute_inspect_with_limits_for_test(
    request: InspectRequest,
    limits: InspectLimits,
) -> Result<InspectReport, InspectError> {
    execute_inspect_with_hook_for_test(request, limits, |_, _| {})
}

#[cfg(test)]
fn execute_inspect_with_hook_for_test(
    request: InspectRequest,
    limits: InspectLimits,
    before_child_open: impl FnMut(&OsStr, usize),
) -> Result<InspectReport, InspectError> {
    let source = crate::fs_boundary::open_ambient_dir_nofollow(&request.source)
        .map_err(|_| InspectError::Inventory(InventoryError::RootRejected))?;
    execute_inspect_from_open_source(source, limits, before_child_open)
}

enum ComponentError {
    PathEvidence(PathEvidenceError),
    Filename(FilenameError),
    Content(ContentError),
    Secrets(SecretError),
    Sensitive(SensitiveError),
    Policy(PolicyPlanError),
}

fn map_component_error(error: ComponentError) -> InspectError {
    match error {
        ComponentError::PathEvidence(error) => InspectError::PathEvidence(error),
        ComponentError::Filename(error) => InspectError::Filename(error),
        ComponentError::Content(error) => InspectError::Content(error),
        ComponentError::Secrets(error) => InspectError::Secrets(error),
        ComponentError::Sensitive(error) => InspectError::Sensitive(error),
        ComponentError::Policy(error) => InspectError::PolicyPlan(error),
    }
}

#[cfg(test)]
fn build_inspect_report(
    inventory: Inventory,
    filename: FilenameReport,
    content: ContentReport,
    secrets: SecretReport,
    sensitive: SensitiveReport,
) -> Result<InspectReport, InspectError> {
    let scan_candidates = inventory
        .directories
        .checked_add(inventory.regular_files)
        .ok_or(InspectError::PathEvidence(PathEvidenceError::CountOverflow))?;
    build_inspect_report_with_path(
        inventory,
        PathEvidenceReport {
            scan_candidates,
            ..PathEvidenceReport::default()
        },
        filename,
        content,
        secrets,
        sensitive,
    )
}

#[cfg(test)]
fn build_inspect_report_with_path(
    inventory: Inventory,
    path_evidence: PathEvidenceReport,
    filename: FilenameReport,
    content: ContentReport,
    secrets: SecretReport,
    sensitive: SensitiveReport,
) -> Result<InspectReport, InspectError> {
    let effective_policy = test_effective_policy(inventory, &path_evidence, &content)?;
    build_inspect_report_with_path_and_effective(
        inventory,
        path_evidence,
        filename,
        content,
        secrets,
        sensitive,
        effective_policy,
    )
}

fn build_inspect_report_with_path_and_effective(
    inventory: Inventory,
    path_evidence: PathEvidenceReport,
    filename: FilenameReport,
    content: ContentReport,
    secrets: SecretReport,
    sensitive: SensitiveReport,
    effective_policy: EffectiveDispositionPlan,
) -> Result<InspectReport, InspectError> {
    path_evidence
        .validate()
        .map_err(InspectError::PathEvidence)?;
    let observed_components = path_evidence
        .observed_component_total()
        .map_err(InspectError::PathEvidence)?;
    let expected_components = inventory
        .directories
        .checked_add(inventory.regular_files)
        .ok_or(InspectError::PathEvidence(PathEvidenceError::CountOverflow))?;
    if observed_components != expected_components {
        return Err(InspectError::PathEvidence(
            PathEvidenceError::InconsistentCounts,
        ));
    }
    filename.validate().map_err(InspectError::Filename)?;
    let observed_basenames = filename
        .observed_basename_total()
        .map_err(InspectError::Filename)?;
    if observed_basenames != inventory.regular_files {
        return Err(InspectError::Filename(FilenameError::InconsistentCounts));
    }
    let content_outcomes = content.outcome_total().map_err(InspectError::Content)?;
    if content_outcomes != content.candidates {
        return Err(InspectError::Content(ContentError::InconsistentCounts));
    }
    if content.candidates != inventory.text_or_code_candidates {
        return Err(InspectError::Content(ContentError::InconsistentCounts));
    }
    secrets.validate().map_err(InspectError::Secrets)?;
    if secrets.scan_candidates != content.readable_text {
        return Err(InspectError::Secrets(SecretError::InconsistentCounts));
    }
    sensitive.validate().map_err(InspectError::Sensitive)?;
    if sensitive.scan_candidates != content.readable_text {
        return Err(InspectError::Sensitive(SensitiveError::InconsistentCounts));
    }
    let regular_file_policy = policy::build_default_regular_file_plan(
        RegularFileClassifications {
            text_or_code_candidates: inventory.text_or_code_candidates,
            unsupported_files: inventory.unsupported_files,
            unknown_files: inventory.unknown_files,
        },
        inventory.regular_files,
    )
    .map_err(InspectError::PolicyPlan)?;
    effective_policy
        .validate(inventory.regular_files, inventory.directories)
        .map_err(InspectError::PolicyPlan)?;

    Ok(InspectReport {
        inventory,
        filename,
        path_evidence,
        regular_file_policy,
        effective_policy,
        structural_exclusions: StructuralExclusions {
            link_like: inventory.link_like_entries,
            git_metadata: inventory.git_metadata_entries,
            special: inventory.special_entries,
        },
        content,
        secrets,
        sensitive,
        inspection_only: true,
        sanitization_performed: false,
    })
}

#[cfg(test)]
fn test_effective_policy(
    inventory: Inventory,
    path_evidence: &PathEvidenceReport,
    content: &ContentReport,
) -> Result<EffectiveDispositionPlan, InspectError> {
    let effective_transform = content.readable_text.min(inventory.regular_files);
    let effective_omit = inventory
        .regular_files
        .checked_sub(effective_transform)
        .ok_or(InspectError::PolicyPlan(
            PolicyPlanError::InconsistentCounts,
        ))?;
    let decisions = crate::policy::DecisionCounts {
        allow: 0,
        transform: effective_transform,
        structure_only: 0,
        omit: effective_omit,
        block: 0,
    };
    Ok(EffectiveDispositionPlan {
        policy_id: crate::policy::DEFAULT_POLICY_ID,
        regular_files: inventory.regular_files,
        effective_transform,
        effective_omit,
        effective_block: 0,
        effective_unresolved: path_evidence.uninspectable.min(inventory.directories),
        decisions,
    })
}

#[cfg(test)]
mod tests {
    use super::{
        acquire_clone_authority, acquire_inspect_authority, build_inspect_report,
        build_inspect_report_with_path,
        execute_inspect_with_hook_for_test as execute_inspect_with_hook,
        execute_inspect_with_limits_for_test as execute_inspect_with_limits, CloneError,
        CloneFailureClass, CloneReport, CloneRequest, InspectError, InspectLimits, InspectRequest,
        LocalityOperations, StructuralExclusions,
    };
    use crate::content::{ContentError, Limits as ContentLimits, Report as ContentReport};
    use crate::filename::{FilenameError, Limits as FilenameLimits, Report as FilenameReport};
    use crate::inventory::Inventory;
    use crate::path_evidence::{
        Limits as PathEvidenceLimits, PathEvidenceError, Report as PathEvidenceReport,
    };
    use crate::policy::{DecisionCounts, PolicyPlanError, DEFAULT_POLICY_ID};
    use crate::promotion::{PromotionError, PromotionPlatform, PublicationReport};
    use crate::secrets::{Limits as SecretLimits, Report as SecretReport, SecretError};
    use crate::sensitive::{Limits as SensitiveLimits, Report as SensitiveReport, SensitiveError};
    use crate::staging::{StagingError, UNVERIFIED_STAGING_LEAF};
    use crate::staging_tree::{StagingBuildSummary, StagingTreeError};
    use crate::verification::{VerificationError, VerificationReport};
    use crate::LocalityError;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_ID: AtomicU64 = AtomicU64::new(0);

    #[derive(Clone, Copy, Eq, PartialEq)]
    enum LocalityFailurePoint {
        None,
        SourcePreflight,
        OutputPreflight,
        SourceConfirmation,
        OutputConfirmation,
    }

    struct RecordingLocality {
        failure: LocalityFailurePoint,
        calls: Vec<&'static str>,
    }

    impl RecordingLocality {
        fn new(failure: LocalityFailurePoint) -> Self {
            Self {
                failure,
                calls: Vec::new(),
            }
        }

        fn result(&self, point: LocalityFailurePoint) -> Result<(), LocalityError> {
            if self.failure == point {
                Err(LocalityError::LocalityUnavailable)
            } else {
                Ok(())
            }
        }
    }

    impl LocalityOperations for RecordingLocality {
        type SourcePreflight = ();
        type OutputPreflight = ();
        type SourceConfirmed = ();
        type OutputConfirmed = ();

        fn preflight_source(
            &mut self,
            _source: &std::path::Path,
        ) -> Result<Self::SourcePreflight, LocalityError> {
            self.calls.push("source-preflight");
            self.result(LocalityFailurePoint::SourcePreflight)
        }

        fn preflight_clone(
            &mut self,
            _source: &std::path::Path,
            _output: &std::path::Path,
        ) -> Result<(Self::SourcePreflight, Self::OutputPreflight), LocalityError> {
            self.calls.push("source-preflight");
            self.result(LocalityFailurePoint::SourcePreflight)?;
            self.calls.push("output-preflight");
            self.result(LocalityFailurePoint::OutputPreflight)?;
            Ok(((), ()))
        }

        fn open_confirm_source(
            &mut self,
            _source: Self::SourcePreflight,
        ) -> Result<Self::SourceConfirmed, LocalityError> {
            self.calls.push("source-open-confirm");
            self.result(LocalityFailurePoint::SourceConfirmation)
        }

        fn open_confirm_output(
            &mut self,
            _output: Self::OutputPreflight,
        ) -> Result<Self::OutputConfirmed, LocalityError> {
            self.calls.push("output-open-confirm");
            self.result(LocalityFailurePoint::OutputConfirmation)
        }
    }

    #[test]
    fn clone_completes_both_preflights_before_either_open() {
        let request = CloneRequest {
            source: PathBuf::from("source-must-not-be-opened"),
            output: PathBuf::from("output-must-not-be-opened"),
        };

        let mut source_failure = RecordingLocality::new(LocalityFailurePoint::SourcePreflight);
        assert_eq!(
            acquire_clone_authority(&request, &mut source_failure),
            Err(LocalityError::LocalityUnavailable)
        );
        assert_eq!(source_failure.calls, vec!["source-preflight"]);

        let mut output_failure = RecordingLocality::new(LocalityFailurePoint::OutputPreflight);
        assert_eq!(
            acquire_clone_authority(&request, &mut output_failure),
            Err(LocalityError::LocalityUnavailable)
        );
        assert_eq!(
            output_failure.calls,
            vec!["source-preflight", "output-preflight"]
        );

        let mut success = RecordingLocality::new(LocalityFailurePoint::None);
        assert_eq!(
            acquire_clone_authority(&request, &mut success),
            Ok(((), ()))
        );
        assert_eq!(
            success.calls,
            vec![
                "source-preflight",
                "output-preflight",
                "source-open-confirm",
                "output-open-confirm"
            ]
        );
    }

    #[test]
    fn confirmation_failure_stops_before_filesystem_work() {
        let clone_request = CloneRequest {
            source: PathBuf::from("source-must-not-be-read"),
            output: PathBuf::from("output-must-not-be-written"),
        };
        let mut source_failure = RecordingLocality::new(LocalityFailurePoint::SourceConfirmation);
        assert_eq!(
            acquire_clone_authority(&clone_request, &mut source_failure),
            Err(LocalityError::LocalityUnavailable)
        );
        assert_eq!(
            source_failure.calls,
            vec![
                "source-preflight",
                "output-preflight",
                "source-open-confirm"
            ]
        );

        let mut output_failure = RecordingLocality::new(LocalityFailurePoint::OutputConfirmation);
        assert_eq!(
            acquire_clone_authority(&clone_request, &mut output_failure),
            Err(LocalityError::LocalityUnavailable)
        );
        assert_eq!(
            output_failure.calls,
            vec![
                "source-preflight",
                "output-preflight",
                "source-open-confirm",
                "output-open-confirm"
            ]
        );

        let inspect_request = InspectRequest {
            source: PathBuf::from("source-must-not-be-inventoried"),
        };
        let mut inspect_preflight = RecordingLocality::new(LocalityFailurePoint::SourcePreflight);
        assert_eq!(
            acquire_inspect_authority(&inspect_request, &mut inspect_preflight),
            Err(LocalityError::LocalityUnavailable)
        );
        assert_eq!(inspect_preflight.calls, vec!["source-preflight"]);

        let mut inspect_confirmation =
            RecordingLocality::new(LocalityFailurePoint::SourceConfirmation);
        assert_eq!(
            acquire_inspect_authority(&inspect_request, &mut inspect_confirmation),
            Err(LocalityError::LocalityUnavailable)
        );
        assert_eq!(
            inspect_confirmation.calls,
            vec!["source-preflight", "source-open-confirm"]
        );
    }

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new(label: &str) -> Self {
            let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "safeclone-pipeline-{label}-{}-{id}",
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

    fn synthetic_my_number(base: &str) -> String {
        assert_eq!(base.len(), 11);
        let sum = base
            .bytes()
            .rev()
            .enumerate()
            .map(|(index, byte)| {
                let n = index as u32 + 1;
                let weight = if n <= 6 { n + 1 } else { n - 5 };
                u32::from(byte - b'0') * weight
            })
            .sum::<u32>();
        let remainder = sum % 11;
        let check = if remainder <= 1 { 0 } else { 11 - remainder };
        format!("{base}{check}")
    }

    fn synthetic_corporate_number(base: &str) -> String {
        assert_eq!(base.len(), 12);
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

    fn synthetic_detection_evidence() -> String {
        let my_number = synthetic_my_number("10000000000");
        let corporate_number = synthetic_corporate_number("102030405060");
        format!(
            "password = \"N0nLive_Fixture_4A7c9E2b\"\nfixture.user+test@example.invalid\n+12345678\n090-0000-0000\n192.0.2.10\n〒123-4567\n{my_number}\n{corporate_number}"
        )
    }

    fn synthetic_github_token() -> String {
        const ALPHABET: &[u8] = b"A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0";
        let body = (0..36)
            .map(|index| ALPHABET[index % ALPHABET.len()])
            .collect::<Vec<_>>();
        format!(
            "gho_{}",
            String::from_utf8(body).expect("synthetic token body is ASCII")
        )
    }

    fn filename_report(scan_candidates: usize) -> FilenameReport {
        FilenameReport {
            scan_candidates,
            ..FilenameReport::default()
        }
    }

    #[cfg(windows)]
    #[test]
    fn execute_clone_orchestrates_build_verify_and_atomic_publication() {
        let fixture = TestDirectory::new("core-clone");
        let source = fixture.0.join("source");
        let destination_parent = fixture.0.join("destination");
        let output = destination_parent.join("published");
        let email = "fixture.user@example.invalid";
        let phone = "090-1234-5678";
        let token = synthetic_github_token();
        let source_directory = source.join(email);
        let source_file = source_directory.join(format!("report_{phone}.rs"));
        let source_text = format!("token={token}\nemail={email}\nphone={phone}\n");
        let omitted_text = b"synthetic omitted environment value";

        fs::create_dir(&source).expect("create source");
        fs::create_dir(&destination_parent).expect("create destination parent");
        fs::create_dir(&source_directory).expect("create sensitive source directory");
        fs::write(&source_file, &source_text).expect("write synthetic readable source");
        fs::write(source.join(".env"), omitted_text).expect("write omitted source file");
        let source_before = fs::read(&source_file).expect("read source before clone");

        let request = CloneRequest {
            source: source.clone(),
            output: output.clone(),
        };
        let request_debug = format!("{request:?}");
        assert!(!request_debug.contains(source.to_string_lossy().as_ref()));
        assert!(!request_debug.contains(output.to_string_lossy().as_ref()));

        let report = super::execute_clone(request).expect("core clone workflow succeeds");

        assert_eq!(report.build.files_written, 1);
        assert_eq!(report.build.directories_written, 1);
        assert_eq!(report.build.files_omitted, 1);
        assert_eq!(report.publication.platform, PromotionPlatform::WindowsNtfs);
        assert_eq!(
            report.publication.verification.files_verified,
            report.build.files_written
        );
        assert_eq!(
            report.publication.verification.directories_verified,
            report.build.directories_written
        );
        assert_eq!(
            report.publication.verification.bytes_verified,
            report.build.staged_bytes_written
        );
        assert!(fs::symlink_metadata(destination_parent.join(UNVERIFIED_STAGING_LEAF)).is_err());
        assert!(output.is_dir());
        assert!(fs::symlink_metadata(output.join(".env")).is_err());

        let published_file = output
            .join("__REDACTED_EMAIL__")
            .join("report___REDACTED_PHONE__.rs");
        let published_text = fs::read_to_string(published_file).expect("read published text");
        for raw in [&token, email, phone] {
            assert!(!published_text.contains(raw));
            assert!(!format!("{report:?}").contains(raw));
        }
        assert!(published_text.contains("[REDACTED:SECRET]"));
        assert!(published_text.contains("[REDACTED:EMAIL]"));
        assert!(published_text.contains("[REDACTED:PHONE]"));
        assert_eq!(
            fs::read(&source_file).expect("read source after clone"),
            source_before
        );
        assert_eq!(
            fs::read(source.join(".env")).expect("read omitted source after clone"),
            omitted_text
        );
    }

    #[cfg(windows)]
    #[test]
    fn execute_clone_preserves_existing_destination_without_creating_staging() {
        let fixture = TestDirectory::new("clone-existing-output");
        let source = fixture.0.join("source");
        let destination_parent = fixture.0.join("destination");
        let output = destination_parent.join("published");
        fs::create_dir(&source).expect("create source");
        fs::create_dir(&destination_parent).expect("create destination parent");
        fs::write(&output, b"existing destination").expect("create existing destination");

        let error = super::execute_clone(CloneRequest {
            source,
            output: output.clone(),
        })
        .expect_err("existing destination rejects clone");

        assert_eq!(
            error,
            CloneError::Staging(StagingError::FinalOutputAlreadyExists)
        );
        assert_eq!(error.classification(), CloneFailureClass::DefiniteFailure);
        assert_eq!(
            fs::read(&output).expect("existing destination remains readable"),
            b"existing destination"
        );
        assert!(fs::symlink_metadata(destination_parent.join(UNVERIFIED_STAGING_LEAF)).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn execute_clone_collision_requires_manual_inspection_and_retains_staging_on_windows() {
        let fixture = TestDirectory::new("clone-collision");
        let source = fixture.0.join("source");
        let destination_parent = fixture.0.join("destination");
        let output = destination_parent.join("published");
        fs::create_dir(&source).expect("create source");
        fs::create_dir(&destination_parent).expect("create destination parent");
        fs::write(source.join("alice@example.invalid.txt"), b"first")
            .expect("write first colliding source");
        fs::write(source.join("bob@example.invalid.txt"), b"second")
            .expect("write second colliding source");

        let error = super::execute_clone(CloneRequest {
            source,
            output: output.clone(),
        })
        .expect_err("sanitized collision rejects clone");

        assert_eq!(
            error,
            CloneError::Build(StagingTreeError::ManualInspectionRequired)
        );
        assert_eq!(
            error.classification(),
            CloneFailureClass::ManualInspectionRequired
        );
        assert!(fs::symlink_metadata(&output).is_err());
        assert!(destination_parent.join(UNVERIFIED_STAGING_LEAF).is_dir());
    }

    #[cfg(windows)]
    #[test]
    fn clone_rejects_output_parent_junction_before_staging_or_source_read() {
        let fixture = TestDirectory::new("clone-output-parent-junction");
        let source = fixture.0.join("source");
        let target_parent = fixture.0.join("target-parent");
        let parent_junction = fixture.0.join("parent-junction");
        fs::create_dir(&source).expect("create source");
        fs::create_dir(&target_parent).expect("create target parent");
        fs::write(source.join("main.rs"), b"source remains unread").expect("write source fixture");
        create_junction(&target_parent, &parent_junction);

        let error = super::execute_clone(CloneRequest {
            source,
            output: parent_junction.join("published"),
        })
        .expect_err("output-parent junction must reject");

        assert_eq!(
            error,
            CloneError::Locality(LocalityError::CapabilityOpenFailed)
        );
        assert!(fs::symlink_metadata(target_parent.join(UNVERIFIED_STAGING_LEAF)).is_err());
        assert!(fs::symlink_metadata(target_parent.join("published")).is_err());
        fs::remove_dir(parent_junction).expect("remove junction without following it");
    }

    #[test]
    fn clone_error_classification_centralizes_uncertain_cleanup_and_state() {
        for error in [
            CloneError::Staging(StagingError::StagingRequiresManualInspection),
            CloneError::Staging(StagingError::StagingCleanupFailed),
            CloneError::Build(StagingTreeError::ManualInspectionRequired),
            CloneError::Build(StagingTreeError::CleanupFailed),
            CloneError::Build(StagingTreeError::Boundary(
                StagingError::StagingCleanupFailed,
            )),
            CloneError::Verification(VerificationError::ManualInspectionRequired),
            CloneError::Verification(VerificationError::VerificationCleanupFailed),
            CloneError::Verification(VerificationError::Boundary(
                StagingError::StagingCleanupFailed,
            )),
            CloneError::Promotion(PromotionError::ManualInspectionRequired),
            CloneError::Promotion(PromotionError::PromotionCleanupFailed),
            CloneError::Promotion(PromotionError::PromotionStateIndeterminate),
            CloneError::Promotion(PromotionError::Boundary(StagingError::StagingCleanupFailed)),
            CloneError::Promotion(PromotionError::FreshVerification(
                VerificationError::VerificationCleanupFailed,
            )),
        ] {
            assert_eq!(
                error.classification(),
                CloneFailureClass::ManualInspectionRequired
            );
        }
        for error in [
            CloneError::Locality(LocalityError::UnsupportedPlatform),
            CloneError::Locality(LocalityError::GitMetadataBoundaryRejected),
            CloneError::Locality(LocalityError::RemoteFilesystem),
            CloneError::Staging(StagingError::FinalOutputAlreadyExists),
            CloneError::Build(StagingTreeError::StagingCollision),
            CloneError::Verification(VerificationError::SecretFindingDetected),
            CloneError::Promotion(PromotionError::FilesystemUnsupported),
            CloneError::Promotion(PromotionError::DestinationOccupied),
        ] {
            assert_eq!(error.classification(), CloneFailureClass::DefiniteFailure);
        }
    }

    #[test]
    fn clone_and_inspect_request_report_and_error_debug_are_raw_free() {
        let raw_source = "synthetic-private-source-path";
        let raw_output = "synthetic-private-output-path";
        let raw_value = "synthetic-private-token-value";
        let clone_request = CloneRequest {
            source: PathBuf::from(raw_source),
            output: PathBuf::from(raw_output),
        };
        let inspect_request = InspectRequest {
            source: PathBuf::from(raw_source),
        };
        let report = CloneReport {
            build: StagingBuildSummary::default(),
            publication: PublicationReport {
                verification: VerificationReport::default(),
                platform: PromotionPlatform::WindowsNtfs,
            },
            policy_id: crate::policy::DEFAULT_POLICY_ID,
        };
        let error = CloneError::Promotion(PromotionError::PromotionStateIndeterminate);

        for formatted in [
            format!("{clone_request:?}"),
            format!("{inspect_request:?}"),
            format!("{report:?}"),
            format!("{error:?}"),
            error.to_string(),
        ] {
            assert!(!formatted.contains(raw_source));
            assert!(!formatted.contains(raw_output));
            assert!(!formatted.contains(raw_value));
        }
    }

    #[test]
    fn policy_plan_counts_regular_files_without_structural_exclusions() {
        let report = build_inspect_report(
            Inventory {
                total_entries: 31,
                regular_files: 9,
                directories: 4,
                link_like_entries: 5,
                git_metadata_entries: 6,
                special_entries: 7,
                text_or_code_candidates: 2,
                unsupported_files: 3,
                unknown_files: 4,
            },
            filename_report(9),
            ContentReport {
                candidates: 2,
                readable_text: 1,
                binary_like: 1,
                bytes_inspected: 20,
                ..ContentReport::default()
            },
            SecretReport {
                scan_candidates: 1,
                ..SecretReport::default()
            },
            SensitiveReport {
                scan_candidates: 1,
                ..SensitiveReport::default()
            },
        )
        .expect("consistent inventory produces a report");

        assert_eq!(report.regular_file_policy.policy_id, DEFAULT_POLICY_ID);
        assert_eq!(report.regular_file_policy.policy_regular_files, 9);
        assert_eq!(
            report.regular_file_policy.decisions,
            DecisionCounts {
                allow: 0,
                transform: 2,
                structure_only: 0,
                omit: 7,
                block: 0,
            }
        );
        assert_eq!(
            report.regular_file_policy.decisions.total(),
            Ok(report.regular_file_policy.policy_regular_files)
        );
        assert_eq!(
            report.structural_exclusions,
            StructuralExclusions {
                link_like: 5,
                git_metadata: 6,
                special: 7,
            }
        );
        assert!(report.inspection_only);
        assert!(!report.sanitization_performed);
        assert_eq!(report.content.candidates, 2);
        assert_eq!(report.content.readable_text, 1);
        assert_eq!(report.content.binary_like, 1);
        assert_eq!(report.filename.scan_candidates, 9);
        assert_eq!(report.filename.uninspectable, 0);
        assert_eq!(report.filename.findings, 0);
        assert_eq!(report.secrets.scan_candidates, 1);
        assert_eq!(report.secrets.findings, 0);
        assert_eq!(report.sensitive.scan_candidates, 1);
        assert_eq!(report.sensitive.findings, 0);
    }

    #[test]
    fn inconsistent_inventory_cannot_produce_a_policy_plan() {
        let result = build_inspect_report(
            Inventory {
                regular_files: 2,
                text_or_code_candidates: 1,
                ..Inventory::default()
            },
            filename_report(2),
            ContentReport {
                candidates: 1,
                readable_text: 1,
                ..ContentReport::default()
            },
            SecretReport {
                scan_candidates: 1,
                ..SecretReport::default()
            },
            SensitiveReport {
                scan_candidates: 1,
                ..SensitiveReport::default()
            },
        );

        assert_eq!(
            result,
            Err(InspectError::PolicyPlan(
                PolicyPlanError::InconsistentCounts
            ))
        );
    }

    #[test]
    fn inconsistent_filename_counts_cannot_produce_a_report() {
        let category_mismatch = build_inspect_report(
            Inventory {
                regular_files: 1,
                ..Inventory::default()
            },
            FilenameReport {
                scan_candidates: 1,
                findings: 1,
                files_with_findings: 1,
                ..FilenameReport::default()
            },
            ContentReport::default(),
            SecretReport::default(),
            SensitiveReport::default(),
        );
        assert_eq!(
            category_mismatch,
            Err(InspectError::Filename(FilenameError::InconsistentCounts))
        );

        let eligible_mismatch = build_inspect_report(
            Inventory {
                regular_files: 1,
                ..Inventory::default()
            },
            FilenameReport::default(),
            ContentReport::default(),
            SecretReport::default(),
            SensitiveReport::default(),
        );
        assert_eq!(
            eligible_mismatch,
            Err(InspectError::Filename(FilenameError::InconsistentCounts))
        );
    }

    #[test]
    fn inconsistent_path_component_counts_cannot_produce_a_report() {
        let result = build_inspect_report_with_path(
            Inventory {
                regular_files: 1,
                ..Inventory::default()
            },
            PathEvidenceReport::default(),
            FilenameReport::default(),
            ContentReport::default(),
            SecretReport::default(),
            SensitiveReport::default(),
        );

        assert_eq!(
            result,
            Err(InspectError::PathEvidence(
                PathEvidenceError::InconsistentCounts
            ))
        );
    }

    #[test]
    fn inconsistent_content_counts_cannot_produce_a_report() {
        let result = build_inspect_report(
            Inventory {
                regular_files: 1,
                text_or_code_candidates: 1,
                ..Inventory::default()
            },
            filename_report(1),
            ContentReport::default(),
            SecretReport::default(),
            SensitiveReport::default(),
        );

        assert_eq!(
            result,
            Err(InspectError::Content(ContentError::InconsistentCounts))
        );
    }

    #[test]
    fn inconsistent_content_outcomes_cannot_produce_a_report() {
        let result = build_inspect_report(
            Inventory {
                regular_files: 1,
                text_or_code_candidates: 1,
                ..Inventory::default()
            },
            filename_report(1),
            ContentReport {
                candidates: 1,
                ..ContentReport::default()
            },
            SecretReport::default(),
            SensitiveReport::default(),
        );

        assert_eq!(
            result,
            Err(InspectError::Content(ContentError::InconsistentCounts))
        );
    }

    #[test]
    fn inconsistent_secret_counts_cannot_produce_a_report() {
        let result = build_inspect_report(
            Inventory {
                regular_files: 1,
                text_or_code_candidates: 1,
                ..Inventory::default()
            },
            filename_report(1),
            ContentReport {
                candidates: 1,
                readable_text: 1,
                ..ContentReport::default()
            },
            SecretReport::default(),
            SensitiveReport {
                scan_candidates: 1,
                ..SensitiveReport::default()
            },
        );

        assert_eq!(
            result,
            Err(InspectError::Secrets(SecretError::InconsistentCounts))
        );
    }

    #[test]
    fn inconsistent_sensitive_counts_cannot_produce_a_report() {
        let result = build_inspect_report(
            Inventory {
                regular_files: 1,
                text_or_code_candidates: 1,
                ..Inventory::default()
            },
            filename_report(1),
            ContentReport {
                candidates: 1,
                readable_text: 1,
                ..ContentReport::default()
            },
            SecretReport {
                scan_candidates: 1,
                ..SecretReport::default()
            },
            SensitiveReport::default(),
        );

        assert_eq!(
            result,
            Err(InspectError::Sensitive(SensitiveError::InconsistentCounts))
        );

        let category_mismatch = build_inspect_report(
            Inventory {
                regular_files: 1,
                text_or_code_candidates: 1,
                ..Inventory::default()
            },
            filename_report(1),
            ContentReport {
                candidates: 1,
                readable_text: 1,
                ..ContentReport::default()
            },
            SecretReport {
                scan_candidates: 1,
                ..SecretReport::default()
            },
            SensitiveReport {
                scan_candidates: 1,
                findings: 1,
                files_with_findings: 1,
                ..SensitiveReport::default()
            },
        );
        assert_eq!(
            category_mismatch,
            Err(InspectError::Sensitive(SensitiveError::InconsistentCounts))
        );
    }

    #[test]
    fn total_content_limit_fails_the_whole_run() {
        let fixture = TestDirectory::new("total-limit");
        fs::write(fixture.0.join("one.rs"), b"1234").expect("write first candidate");
        fs::write(fixture.0.join("two.rs"), b"5678").expect("write second candidate");

        let result = execute_inspect_with_limits(
            InspectRequest {
                source: fixture.0.clone(),
            },
            InspectLimits {
                content: ContentLimits {
                    max_file_bytes: 4,
                    max_total_bytes: 6,
                },
                ..InspectLimits::default()
            },
        );

        assert_eq!(
            result,
            Err(InspectError::Content(ContentError::TotalLimitExceeded))
        );
    }

    #[test]
    fn unsupported_unknown_and_git_content_are_never_read() {
        let fixture = TestDirectory::new("non-candidates");
        let synthetic_evidence = synthetic_detection_evidence();
        fs::write(fixture.0.join("main.rs"), b"x").expect("write candidate");
        fs::write(
            fixture.0.join("credentials.bin"),
            synthetic_evidence.as_bytes(),
        )
        .expect("write unsupported");
        fs::write(
            fixture.0.join("value.custom"),
            synthetic_evidence.as_bytes(),
        )
        .expect("write unknown");
        fs::create_dir(fixture.0.join(".git")).expect("create git directory");
        fs::write(
            fixture.0.join(".git/secret.rs"),
            synthetic_evidence.as_bytes(),
        )
        .expect("write git candidate");

        let report = execute_inspect_with_limits(
            InspectRequest {
                source: fixture.0.clone(),
            },
            InspectLimits {
                content: ContentLimits {
                    max_file_bytes: 256,
                    max_total_bytes: 1,
                },
                ..InspectLimits::default()
            },
        )
        .expect("only the one-byte candidate consumes the budget");

        assert_eq!(report.inventory.text_or_code_candidates, 1);
        assert_eq!(report.inventory.unsupported_files, 1);
        assert_eq!(report.inventory.unknown_files, 1);
        assert_eq!(report.inventory.git_metadata_entries, 1);
        assert_eq!(report.path_evidence.scan_candidates, 3);
        assert_eq!(report.path_evidence.uninspectable, 0);
        assert_eq!(report.path_evidence.components_with_findings, 0);
        assert_eq!(report.path_evidence.secret_findings, 0);
        assert_eq!(report.path_evidence.sensitive_findings, 0);
        assert_eq!(report.filename.scan_candidates, 3);
        assert_eq!(report.filename.uninspectable, 0);
        assert_eq!(report.filename.findings, 1);
        assert_eq!(report.filename.files_with_findings, 1);
        assert_eq!(report.filename.environment_findings, 0);
        assert_eq!(report.filename.private_key_findings, 0);
        assert_eq!(report.filename.credential_findings, 1);
        assert_eq!(report.filename.auth_config_findings, 0);
        assert_eq!(report.content.candidates, 1);
        assert_eq!(report.content.readable_text, 1);
        assert_eq!(report.content.bytes_inspected, 1);
        assert_eq!(report.secrets.scan_candidates, 1);
        assert_eq!(report.secrets.findings, 0);
        assert_eq!(report.sensitive.scan_candidates, 1);
        assert_eq!(report.sensitive.findings, 0);
        assert_eq!(report.regular_file_policy.decisions.transform, 1);
        assert_eq!(report.regular_file_policy.decisions.omit, 2);
        assert_eq!(report.regular_file_policy.decisions.block, 0);
        assert_eq!(report.effective_policy.effective_transform, 1);
        assert_eq!(report.effective_policy.effective_omit, 2);
        assert_eq!(report.effective_policy.effective_block, 0);
        assert_eq!(report.effective_policy.effective_unresolved, 0);
    }

    #[test]
    fn filename_evidence_omits_otherwise_transformable_regular_files() {
        let fixture = TestDirectory::new("effective-filename-omit");
        fs::write(fixture.0.join("normal.rs"), b"ordinary").expect("write ordinary text");
        fs::write(fixture.0.join("credentials.rs"), b"credential-looking name")
            .expect("write credentials text");
        fs::write(fixture.0.join("secret.yaml"), b"secret-looking name")
            .expect("write secret text");
        fs::write(fixture.0.join(".pypirc"), b"auth config-looking name")
            .expect("write auth config text");

        let report = execute_inspect_with_limits(
            InspectRequest {
                source: fixture.0.clone(),
            },
            InspectLimits::default(),
        )
        .expect("evidence and effective policy complete");

        assert_eq!(report.inventory.regular_files, 4);
        assert_eq!(report.inventory.text_or_code_candidates, 3);
        assert_eq!(report.filename.findings, 3);
        assert_eq!(report.effective_policy.effective_transform, 1);
        assert_eq!(report.effective_policy.effective_omit, 3);
        assert_eq!(report.effective_policy.decisions.allow, 0);
        assert_eq!(report.effective_policy.decisions.structure_only, 0);
    }

    #[test]
    fn directory_names_are_not_filename_scan_candidates() {
        let fixture = TestDirectory::new("directory-name-not-scanned");
        let directory = fixture.0.join(".env.production");
        fs::create_dir(&directory).expect("create sensitive-looking directory");
        fs::write(directory.join("ordinary.rs"), b"x").expect("write ordinary file");

        let report = execute_inspect_with_limits(
            InspectRequest {
                source: fixture.0.clone(),
            },
            InspectLimits::default(),
        )
        .expect("directory components remain out of scope");

        assert_eq!(report.inventory.directories, 1);
        assert_eq!(report.inventory.regular_files, 1);
        assert_eq!(report.filename.scan_candidates, 1);
        assert_eq!(report.filename.findings, 0);
        assert_eq!(report.filename.files_with_findings, 0);
        assert_eq!(report.path_evidence.scan_candidates, 2);
        assert_eq!(report.path_evidence.uninspectable, 0);
        assert_eq!(report.path_evidence.components_with_findings, 0);
    }

    #[test]
    fn rejected_database_rule_does_not_change_existing_classification() {
        let fixture = TestDirectory::new("database-rule-absent");
        for name in [
            "migration.sql",
            "schema.sql",
            "database.sqlite",
            "backup.bak",
        ] {
            fs::write(fixture.0.join(name), b"not opened").expect("write database fixture");
        }

        let report = execute_inspect_with_limits(
            InspectRequest {
                source: fixture.0.clone(),
            },
            InspectLimits::default(),
        )
        .expect("database names remain ordinary unsupported policy inputs");

        assert_eq!(report.inventory.regular_files, 4);
        assert_eq!(report.inventory.unknown_files, 4);
        assert_eq!(report.inventory.text_or_code_candidates, 0);
        assert_eq!(report.filename.scan_candidates, 4);
        assert_eq!(report.filename.findings, 0);
        assert_eq!(report.path_evidence.scan_candidates, 4);
        assert_eq!(report.path_evidence.uninspectable, 0);
        assert_eq!(report.path_evidence.components_with_findings, 0);
        assert_eq!(report.content.candidates, 0);
        assert_eq!(report.regular_file_policy.decisions.omit, 4);
    }

    #[test]
    fn only_readable_text_reaches_detection() {
        let fixture = TestDirectory::new("readable-only-detection");
        let source = fixture.0.join("source");
        let outside = fixture.0.join("outside");
        fs::create_dir(&source).expect("create source directory");
        fs::create_dir(&outside).expect("create outside directory");
        let synthetic_evidence = synthetic_detection_evidence();
        fs::write(source.join("readable.rs"), synthetic_evidence.as_bytes())
            .expect("write readable");

        let mut binary = synthetic_evidence.as_bytes().to_vec();
        binary.push(0);
        fs::write(source.join("binary.rs"), binary).expect("write binary-like");

        let mut invalid = synthetic_evidence.as_bytes().to_vec();
        invalid.push(0xff);
        fs::write(source.join("invalid.rs"), invalid).expect("write invalid UTF-8");

        let oversized = synthetic_evidence.repeat(3);
        fs::write(source.join("oversized.rs"), oversized).expect("write oversized");

        let external = outside.join("external.rs");
        fs::write(&external, synthetic_evidence.as_bytes())
            .expect("write external hard-link target");
        fs::hard_link(&external, source.join("hard-linked.rs")).expect("create hard link");

        fs::create_dir(source.join(".git")).expect("create git metadata");
        fs::write(source.join(".git/secret.rs"), synthetic_evidence.as_bytes())
            .expect("write excluded git content");

        let report = execute_inspect_with_limits(
            InspectRequest { source },
            InspectLimits {
                content: ContentLimits {
                    max_file_bytes: 256,
                    max_total_bytes: 1_024,
                },
                ..InspectLimits::default()
            },
        )
        .expect("non-readable outcomes remain aggregate evidence");

        assert_eq!(report.content.candidates, 5);
        assert_eq!(report.content.readable_text, 1);
        assert_eq!(report.content.binary_like, 1);
        assert_eq!(report.content.invalid_utf8, 1);
        assert_eq!(report.content.oversized, 1);
        assert_eq!(report.content.hard_linked, 1);
        assert_eq!(report.path_evidence.scan_candidates, 5);
        assert_eq!(report.path_evidence.uninspectable, 0);
        assert_eq!(report.path_evidence.components_with_findings, 0);
        assert_eq!(report.filename.scan_candidates, 5);
        assert_eq!(report.filename.uninspectable, 0);
        assert_eq!(report.filename.findings, 0);
        assert_eq!(report.secrets.scan_candidates, 1);
        assert_eq!(report.secrets.findings, 1);
        assert_eq!(report.secrets.files_with_findings, 1);
        assert_eq!(report.sensitive.scan_candidates, 1);
        assert_eq!(report.sensitive.findings, 7);
        assert_eq!(report.sensitive.files_with_findings, 1);
        assert_eq!(report.sensitive.email_findings, 1);
        assert_eq!(report.sensitive.phone_findings, 1);
        assert_eq!(report.sensitive.jp_phone_findings, 1);
        assert_eq!(report.sensitive.ip_findings, 1);
        assert_eq!(report.sensitive.jp_postal_findings, 1);
        assert_eq!(report.sensitive.my_number_candidate_findings, 1);
        assert_eq!(report.sensitive.corporate_number_candidate_findings, 1);
        assert_eq!(report.regular_file_policy.decisions.transform, 5);
        assert_eq!(report.regular_file_policy.decisions.block, 0);
        assert_eq!(report.effective_policy.effective_transform, 1);
        assert_eq!(report.effective_policy.effective_omit, 4);
        assert_eq!(report.effective_policy.effective_unresolved, 0);
    }

    #[test]
    fn secret_finding_limits_abort_the_whole_inspection() {
        let fixture = TestDirectory::new("secret-finding-limits");
        fs::write(
            fixture.0.join("two.rs"),
            b"password = \"N0nLive_Fixture_4A7c9E2b\"\ntoken = \"A7c9E2bN0nLive_Fixture_4\"",
        )
        .expect("write two-finding fixture");

        let file_limited = execute_inspect_with_limits(
            InspectRequest {
                source: fixture.0.clone(),
            },
            InspectLimits {
                secrets: SecretLimits {
                    max_findings_per_file: 1,
                    ..SecretLimits::default()
                },
                ..InspectLimits::default()
            },
        );
        assert_eq!(
            file_limited,
            Err(InspectError::Secrets(SecretError::FileFindingLimitExceeded))
        );

        let run_fixture = TestDirectory::new("secret-run-limit");
        for name in ["one.rs", "two.rs"] {
            fs::write(
                run_fixture.0.join(name),
                b"password = \"N0nLive_Fixture_4A7c9E2b\"",
            )
            .expect("write one-finding fixture");
        }
        let run_limited = execute_inspect_with_limits(
            InspectRequest {
                source: run_fixture.0.clone(),
            },
            InspectLimits {
                secrets: SecretLimits {
                    max_findings_per_run: 1,
                    ..SecretLimits::default()
                },
                ..InspectLimits::default()
            },
        );
        assert_eq!(
            run_limited,
            Err(InspectError::Secrets(SecretError::RunFindingLimitExceeded))
        );
    }

    #[test]
    fn filename_finding_limit_aborts_the_whole_inspection() {
        let fixture = TestDirectory::new("filename-finding-limit");
        fs::write(fixture.0.join("secrets.key"), b"not opened")
            .expect("write overlapping filename fixture");

        let result = execute_inspect_with_limits(
            InspectRequest {
                source: fixture.0.clone(),
            },
            InspectLimits {
                filename: FilenameLimits {
                    max_findings_per_run: 1,
                },
                ..InspectLimits::default()
            },
        );

        assert_eq!(
            result,
            Err(InspectError::Filename(
                FilenameError::RunFindingLimitExceeded
            ))
        );
    }

    #[test]
    fn path_component_finding_limit_aborts_the_whole_inspection() {
        let fixture = TestDirectory::new("path-component-finding-limit");
        fs::write(
            fixture.0.join("ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"),
            b"not opened",
        )
        .expect("write provider-like basename fixture");

        let result = execute_inspect_with_limits(
            InspectRequest {
                source: fixture.0.clone(),
            },
            InspectLimits {
                path_evidence: PathEvidenceLimits {
                    max_findings_per_run: 0,
                    ..PathEvidenceLimits::default()
                },
                ..InspectLimits::default()
            },
        );

        assert_eq!(
            result,
            Err(InspectError::PathEvidence(
                PathEvidenceError::RunFindingLimitExceeded
            ))
        );
    }

    #[test]
    fn sensitive_finding_limits_abort_the_whole_inspection() {
        let candidate_fixture = TestDirectory::new("sensitive-candidate-limits");
        fs::write(
            candidate_fixture.0.join("candidates.rs"),
            b"060-0000-0000\n060-0000-0000",
        )
        .expect("write rejected 060 candidates");
        let candidate_limited = execute_inspect_with_limits(
            InspectRequest {
                source: candidate_fixture.0.clone(),
            },
            InspectLimits {
                sensitive: SensitiveLimits {
                    max_candidates_per_rule_per_file: 1,
                    ..SensitiveLimits::default()
                },
                ..InspectLimits::default()
            },
        );
        assert_eq!(
            candidate_limited,
            Err(InspectError::Sensitive(
                SensitiveError::CandidateLimitExceeded
            ))
        );

        let fixture = TestDirectory::new("sensitive-finding-limits");
        fs::write(
            fixture.0.join("two.rs"),
            b"fixture.one@example.invalid\nfixture.two@example.invalid",
        )
        .expect("write two-finding fixture");

        let file_limited = execute_inspect_with_limits(
            InspectRequest {
                source: fixture.0.clone(),
            },
            InspectLimits {
                sensitive: SensitiveLimits {
                    max_findings_per_file: 1,
                    ..SensitiveLimits::default()
                },
                ..InspectLimits::default()
            },
        );
        assert_eq!(
            file_limited,
            Err(InspectError::Sensitive(
                SensitiveError::FileFindingLimitExceeded
            ))
        );

        let run_fixture = TestDirectory::new("sensitive-run-limit");
        for name in ["one.rs", "two.rs"] {
            fs::write(run_fixture.0.join(name), b"fixture.user@example.invalid")
                .expect("write one-finding fixture");
        }
        let run_limited = execute_inspect_with_limits(
            InspectRequest {
                source: run_fixture.0.clone(),
            },
            InspectLimits {
                sensitive: SensitiveLimits {
                    max_findings_per_run: 1,
                    ..SensitiveLimits::default()
                },
                ..InspectLimits::default()
            },
        );
        assert_eq!(
            run_limited,
            Err(InspectError::Sensitive(
                SensitiveError::RunFindingLimitExceeded
            ))
        );
    }

    #[test]
    fn secret_and_sensitive_evidence_coexist_without_policy_refinement() {
        let fixture = TestDirectory::new("secret-sensitive-overlap");
        let my_number = synthetic_my_number("10000000000");
        let corporate_number = synthetic_corporate_number("102030405060");
        fs::write(
            fixture.0.join("config.rs"),
            format!(
                "https://fixture-user:N0nLiveFixtureP4ss@[2001:db8::10]/repo\n電話：090-0000-0000。\n〒123-4567\n{my_number}\n{corporate_number}"
            ),
        )
        .expect("write coexistence fixture");

        let report = execute_inspect_with_limits(
            InspectRequest {
                source: fixture.0.clone(),
            },
            InspectLimits::default(),
        )
        .expect("both detectors produce independent evidence");

        assert_eq!(report.secrets.scan_candidates, 1);
        assert_eq!(report.secrets.findings, 1);
        assert_eq!(report.sensitive.scan_candidates, 1);
        assert_eq!(report.sensitive.findings, 5);
        assert_eq!(report.sensitive.ip_findings, 1);
        assert_eq!(report.sensitive.jp_phone_findings, 1);
        assert_eq!(report.sensitive.jp_postal_findings, 1);
        assert_eq!(report.sensitive.my_number_candidate_findings, 1);
        assert_eq!(report.sensitive.corporate_number_candidate_findings, 1);
        assert_eq!(report.regular_file_policy.decisions.allow, 0);
        assert_eq!(report.regular_file_policy.decisions.transform, 1);
        assert_eq!(report.regular_file_policy.decisions.block, 0);
    }

    #[cfg(unix)]
    #[test]
    fn nested_symlink_content_is_never_read() {
        use std::os::unix::fs::symlink;

        let fixture = TestDirectory::new("static-symlink-content");
        let source = fixture.0.join("source");
        let outside = fixture.0.join("outside");
        fs::create_dir(&source).expect("create source");
        fs::create_dir(&outside).expect("create outside");
        fs::write(source.join("inside.rs"), b"x").expect("write local candidate");
        fs::write(
            outside.join("outside.rs"),
            b"fixture.external@example.invalid\n+1 (202) 555-0100\n192.0.2.80",
        )
        .expect("write external content");
        symlink(&outside, source.join("credentials.json")).expect("create nested symlink");

        let report = execute_inspect_with_limits(
            InspectRequest { source },
            InspectLimits {
                content: ContentLimits {
                    max_file_bytes: 256,
                    max_total_bytes: 1,
                },
                ..InspectLimits::default()
            },
        )
        .expect("only the local candidate consumes the budget");

        assert_eq!(report.inventory.link_like_entries, 1);
        assert_eq!(report.path_evidence.scan_candidates, 1);
        assert_eq!(report.path_evidence.uninspectable, 0);
        assert_eq!(report.path_evidence.components_with_findings, 0);
        assert_eq!(report.filename.scan_candidates, 1);
        assert_eq!(report.filename.findings, 0);
        assert_eq!(report.content.candidates, 1);
        assert_eq!(report.content.bytes_inspected, 1);
        assert_eq!(report.sensitive.scan_candidates, 1);
        assert_eq!(report.sensitive.findings, 0);
    }

    #[cfg(unix)]
    #[test]
    fn directory_to_symlink_race_never_reads_external_content() {
        use std::os::unix::fs::symlink;

        let fixture = TestDirectory::new("symlink-race-content");
        let source = fixture.0.join("source");
        let outside = fixture.0.join("outside");
        let child = source.join("child");
        fs::create_dir(&source).expect("create source");
        fs::create_dir(&outside).expect("create outside");
        fs::write(
            outside.join("outside.rs"),
            b"external raw marker fixture.external@example.invalid 192.0.2.81",
        )
        .expect("write external content");
        fs::create_dir(&child).expect("create ordinary child");
        let mut replaced = false;
        let mut outside_observed = false;

        let result = execute_inspect_with_hook(
            InspectRequest {
                source: source.clone(),
            },
            InspectLimits::default(),
            |name, _| {
                if name == "outside.rs" {
                    outside_observed = true;
                }
                if !replaced && name == "child" {
                    fs::remove_dir(&child).expect("remove ordinary child");
                    symlink(&outside, &child).expect("replace child with external symlink");
                    replaced = true;
                }
            },
        );

        fs::remove_file(&child).expect("remove replacement symlink");
        assert!(replaced);
        assert!(!outside_observed);
        match result {
            Ok(report) => {
                assert_eq!(report.filename.scan_candidates, 0);
                assert_eq!(report.filename.uninspectable, 0);
                assert_eq!(report.filename.findings, 0);
                assert_eq!(report.path_evidence.scan_candidates, 0);
                assert_eq!(report.path_evidence.uninspectable, 0);
                assert_eq!(report.path_evidence.components_with_findings, 0);
                assert_eq!(report.content.candidates, 0);
                assert_eq!(report.content.bytes_inspected, 0);
                assert_eq!(report.secrets.scan_candidates, 0);
                assert_eq!(report.sensitive.scan_candidates, 0);
            }
            Err(error) => assert_eq!(
                error,
                InspectError::Inventory(crate::inventory::InventoryError::TraversalFailed)
            ),
        }
    }

    #[cfg(windows)]
    #[test]
    fn nested_junction_content_is_never_read() {
        let fixture = TestDirectory::new("static-junction-content");
        let source = fixture.0.join("source");
        let outside = fixture.0.join("outside");
        let linked = source.join("credentials.json");
        fs::create_dir(&source).expect("create source");
        fs::create_dir(&outside).expect("create outside");
        fs::write(source.join("inside.rs"), b"x").expect("write local candidate");
        fs::write(
            outside.join("outside.rs"),
            b"fixture.external@example.invalid\n+1 (202) 555-0100\n192.0.2.82",
        )
        .expect("write external content");
        create_junction(&outside, &linked);

        let report = execute_inspect_with_limits(
            InspectRequest { source },
            InspectLimits {
                content: ContentLimits {
                    max_file_bytes: 256,
                    max_total_bytes: 1,
                },
                ..InspectLimits::default()
            },
        )
        .expect("only the local candidate consumes the budget");

        fs::remove_dir(&linked).expect("remove nested junction");
        assert_eq!(report.inventory.link_like_entries, 1);
        assert_eq!(report.path_evidence.scan_candidates, 1);
        assert_eq!(report.path_evidence.uninspectable, 0);
        assert_eq!(report.path_evidence.components_with_findings, 0);
        assert_eq!(report.filename.scan_candidates, 1);
        assert_eq!(report.filename.findings, 0);
        assert_eq!(report.content.candidates, 1);
        assert_eq!(report.content.bytes_inspected, 1);
        assert_eq!(report.sensitive.scan_candidates, 1);
        assert_eq!(report.sensitive.findings, 0);
    }

    #[cfg(windows)]
    #[test]
    fn directory_to_junction_race_never_reads_external_content() {
        let fixture = TestDirectory::new("junction-race-content");
        let source = fixture.0.join("source");
        let outside = fixture.0.join("outside");
        let child = source.join("child");
        fs::create_dir(&source).expect("create source");
        fs::create_dir(&outside).expect("create outside");
        fs::write(
            outside.join("outside.rs"),
            b"external raw marker fixture.external@example.invalid 192.0.2.83",
        )
        .expect("write external content");
        fs::create_dir(&child).expect("create ordinary child");
        let mut replaced = false;
        let mut outside_observed = false;

        let result = execute_inspect_with_hook(
            InspectRequest {
                source: source.clone(),
            },
            InspectLimits::default(),
            |name, _| {
                if name == "outside.rs" {
                    outside_observed = true;
                }
                if !replaced && name == "child" {
                    fs::remove_dir(&child).expect("remove ordinary child");
                    create_junction(&outside, &child);
                    replaced = true;
                }
            },
        );

        fs::remove_dir(&child).expect("remove replacement junction");
        assert!(replaced);
        assert!(!outside_observed);
        match result {
            Ok(report) => {
                assert_eq!(report.filename.scan_candidates, 0);
                assert_eq!(report.filename.uninspectable, 0);
                assert_eq!(report.filename.findings, 0);
                assert_eq!(report.path_evidence.scan_candidates, 0);
                assert_eq!(report.path_evidence.uninspectable, 0);
                assert_eq!(report.path_evidence.components_with_findings, 0);
                assert_eq!(report.content.candidates, 0);
                assert_eq!(report.content.bytes_inspected, 0);
                assert_eq!(report.secrets.scan_candidates, 0);
                assert_eq!(report.sensitive.scan_candidates, 0);
            }
            Err(error) => assert_eq!(
                error,
                InspectError::Inventory(crate::inventory::InventoryError::TraversalFailed)
            ),
        }
    }

    #[cfg(windows)]
    fn create_junction(target: &std::path::Path, junction: &std::path::Path) {
        let status = std::process::Command::new("cmd")
            .args(["/c", "mklink", "/J"])
            .arg(junction)
            .arg(target)
            .status()
            .expect("run mklink");
        assert!(status.success(), "create junction fixture");
    }
}
