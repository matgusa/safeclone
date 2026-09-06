//! Policy decisions derived from detection results.

use std::fmt;

use crate::content::ContentOutcome;
use crate::detection::{ComponentInspectability, DetectedKind};
use crate::filename::{FilenameCategory, FilenameFinding};

pub const DEFAULT_POLICY_ID: &str = "default-strict-v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Decision {
    Allow,
    Transform,
    StructureOnly,
    Omit,
    Block,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RegularFileClassifications {
    pub text_or_code_candidates: usize,
    pub unsupported_files: usize,
    pub unknown_files: usize,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DecisionCounts {
    pub allow: usize,
    pub transform: usize,
    pub structure_only: usize,
    pub omit: usize,
    pub block: usize,
}

impl DecisionCounts {
    pub fn total(self) -> Result<usize, PolicyPlanError> {
        [
            self.allow,
            self.transform,
            self.structure_only,
            self.omit,
            self.block,
        ]
        .into_iter()
        .try_fold(0_usize, |total, count| {
            total
                .checked_add(count)
                .ok_or(PolicyPlanError::CountOverflow)
        })
    }

    fn add(&mut self, decision: Decision, count: usize) -> Result<(), PolicyPlanError> {
        let target = match decision {
            Decision::Allow => &mut self.allow,
            Decision::Transform => &mut self.transform,
            Decision::StructureOnly => &mut self.structure_only,
            Decision::Omit => &mut self.omit,
            Decision::Block => &mut self.block,
        };
        *target = target
            .checked_add(count)
            .ok_or(PolicyPlanError::CountOverflow)?;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegularFilePolicyPlan {
    pub policy_id: &'static str,
    pub policy_regular_files: usize,
    pub decisions: DecisionCounts,
}

/// The effective disposition used by the clone writer. This is kept
/// separate from the initial extension-only plan so inspection can retain the
/// earlier evidence without allowing a clone to rely on it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EffectiveDispositionPlan {
    pub policy_id: &'static str,
    pub regular_files: usize,
    pub effective_transform: usize,
    pub effective_omit: usize,
    pub effective_block: usize,
    pub effective_unresolved: usize,
    pub decisions: DecisionCounts,
}

impl EffectiveDispositionPlan {
    pub(crate) fn validate(
        self,
        expected_regular_files: usize,
        expected_directories: usize,
    ) -> Result<(), PolicyPlanError> {
        let effective_total = self
            .effective_transform
            .checked_add(self.effective_omit)
            .and_then(|total| total.checked_add(self.effective_block))
            .ok_or(PolicyPlanError::CountOverflow)?;
        if self.policy_id != DEFAULT_POLICY_ID
            || self.regular_files != expected_regular_files
            || self.effective_unresolved > expected_directories
            || effective_total != expected_regular_files
            || self.decisions.total()? != expected_regular_files
            || self.effective_transform != self.decisions.transform
            || self.effective_omit != self.decisions.omit
            || self.effective_block != self.decisions.block
            || self.decisions.allow != 0
            || self.decisions.structure_only != 0
        {
            return Err(PolicyPlanError::InconsistentCounts);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicyPlanError {
    CountOverflow,
    InconsistentCounts,
    InvalidInput,
    MissingContentOutcome,
}

impl fmt::Display for PolicyPlanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::CountOverflow => "policy plan counts overflowed",
            Self::InconsistentCounts => "regular-file inventory counts are inconsistent",
            Self::InvalidInput => "effective policy received a non-regular-file input",
            Self::MissingContentOutcome => "effective policy content outcome is missing",
        })
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct FilenameEvidence {
    environment_file: bool,
    private_key_filename: bool,
    credential_filename: bool,
    auth_config_filename: bool,
}

impl FilenameEvidence {
    pub(crate) fn from_findings(findings: &[FilenameFinding]) -> Self {
        let mut evidence = Self::default();
        for finding in findings {
            match finding.category {
                FilenameCategory::EnvironmentFile => evidence.environment_file = true,
                FilenameCategory::PrivateKeyFilename => evidence.private_key_filename = true,
                FilenameCategory::CredentialFilename => evidence.credential_filename = true,
                FilenameCategory::AuthConfigFilename => evidence.auth_config_filename = true,
            }
        }
        evidence
    }

    const fn omits(self) -> bool {
        self.environment_file
            || self.private_key_filename
            || self.credential_filename
            || self.auth_config_filename
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FileDispositionInput {
    pub(crate) detected_kind: DetectedKind,
    pub(crate) content_outcome: Option<ContentOutcome>,
    pub(crate) filename: FilenameEvidence,
    pub(crate) path_component: ComponentInspectability,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct EffectiveDispositionAggregate {
    regular_files: usize,
    effective_transform: usize,
    effective_omit: usize,
    effective_block: usize,
    effective_unresolved: usize,
    decisions: DecisionCounts,
}

impl EffectiveDispositionAggregate {
    fn add_file(&mut self, decision: Decision) -> Result<(), PolicyPlanError> {
        self.regular_files = self
            .regular_files
            .checked_add(1)
            .ok_or(PolicyPlanError::CountOverflow)?;
        self.decisions.add(decision, 1)?;
        match decision {
            Decision::Transform => {
                self.effective_transform = self
                    .effective_transform
                    .checked_add(1)
                    .ok_or(PolicyPlanError::CountOverflow)?;
            }
            Decision::Omit => {
                self.effective_omit = self
                    .effective_omit
                    .checked_add(1)
                    .ok_or(PolicyPlanError::CountOverflow)?;
            }
            Decision::Block => {
                self.effective_block = self
                    .effective_block
                    .checked_add(1)
                    .ok_or(PolicyPlanError::CountOverflow)?;
            }
            Decision::Allow | Decision::StructureOnly => {}
        }
        Ok(())
    }

    fn add_unresolved_directory(&mut self) -> Result<(), PolicyPlanError> {
        self.effective_unresolved = self
            .effective_unresolved
            .checked_add(1)
            .ok_or(PolicyPlanError::CountOverflow)?;
        Ok(())
    }

    fn finish(
        self,
        expected_regular_files: usize,
        expected_directories: usize,
    ) -> Result<EffectiveDispositionPlan, PolicyPlanError> {
        let plan = EffectiveDispositionPlan {
            policy_id: DEFAULT_POLICY_ID,
            regular_files: expected_regular_files,
            effective_transform: self.effective_transform,
            effective_omit: self.effective_omit,
            effective_block: self.effective_block,
            effective_unresolved: self.effective_unresolved,
            decisions: self.decisions,
        };
        plan.validate(expected_regular_files, expected_directories)?;
        Ok(plan)
    }
}

pub(crate) struct EffectiveDispositionSession {
    aggregate: EffectiveDispositionAggregate,
}

impl EffectiveDispositionSession {
    pub(crate) const fn new() -> Self {
        Self {
            aggregate: EffectiveDispositionAggregate {
                regular_files: 0,
                effective_transform: 0,
                effective_omit: 0,
                effective_block: 0,
                effective_unresolved: 0,
                decisions: DecisionCounts {
                    allow: 0,
                    transform: 0,
                    structure_only: 0,
                    omit: 0,
                    block: 0,
                },
            },
        }
    }

    pub(crate) fn observe_directory(
        &mut self,
        inspectability: ComponentInspectability,
    ) -> Result<(), PolicyPlanError> {
        if inspectability == ComponentInspectability::Uninspectable {
            self.aggregate.add_unresolved_directory()?;
        }
        Ok(())
    }

    pub(crate) fn observe_file(
        &mut self,
        input: FileDispositionInput,
    ) -> Result<(), PolicyPlanError> {
        let decision = effective_decision(input)?;
        self.aggregate.add_file(decision)
    }

    pub(crate) fn finish(
        self,
        expected_regular_files: usize,
        expected_directories: usize,
    ) -> Result<EffectiveDispositionPlan, PolicyPlanError> {
        self.aggregate
            .finish(expected_regular_files, expected_directories)
    }
}

pub(crate) fn effective_decision(input: FileDispositionInput) -> Result<Decision, PolicyPlanError> {
    if !matches!(
        input.detected_kind,
        DetectedKind::TextOrCodeCandidate | DetectedKind::Unsupported | DetectedKind::Unknown
    ) {
        return Err(PolicyPlanError::InvalidInput);
    }

    if input.path_component == ComponentInspectability::Uninspectable || input.filename.omits() {
        return Ok(Decision::Omit);
    }

    let content_decision = match input.detected_kind {
        DetectedKind::TextOrCodeCandidate => match input.content_outcome {
            Some(ContentOutcome::ReadableText) => Decision::Transform,
            Some(
                ContentOutcome::BinaryLike
                | ContentOutcome::InvalidUtf8
                | ContentOutcome::Oversized
                | ContentOutcome::HardLinked,
            ) => Decision::Omit,
            None => return Err(PolicyPlanError::MissingContentOutcome),
        },
        DetectedKind::Unsupported | DetectedKind::Unknown => Decision::Omit,
        DetectedKind::LinkLikeEntry | DetectedKind::GitMetadata => {
            return Err(PolicyPlanError::InvalidInput)
        }
    };

    Ok(content_decision)
}

/// Conservative policy: eligible text still requires transformation;
/// everything unknown, unsupported, linked, or repository-internal is omitted.
pub fn decide(kind: DetectedKind) -> Decision {
    match kind {
        DetectedKind::TextOrCodeCandidate => Decision::Transform,
        DetectedKind::Unsupported
        | DetectedKind::Unknown
        | DetectedKind::LinkLikeEntry
        | DetectedKind::GitMetadata => Decision::Omit,
    }
}

/// Builds the aggregate regular-file plan for the explicit default policy.
/// Structural filesystem exclusions are intentionally outside this input.
pub fn build_default_regular_file_plan(
    classifications: RegularFileClassifications,
    expected_regular_files: usize,
) -> Result<RegularFilePolicyPlan, PolicyPlanError> {
    let classified_regular_files = [
        classifications.text_or_code_candidates,
        classifications.unsupported_files,
        classifications.unknown_files,
    ]
    .into_iter()
    .try_fold(0_usize, |total, count| {
        total
            .checked_add(count)
            .ok_or(PolicyPlanError::CountOverflow)
    })?;

    if classified_regular_files != expected_regular_files {
        return Err(PolicyPlanError::InconsistentCounts);
    }

    let mut decisions = DecisionCounts::default();
    for (kind, count) in [
        (
            DetectedKind::TextOrCodeCandidate,
            classifications.text_or_code_candidates,
        ),
        (DetectedKind::Unsupported, classifications.unsupported_files),
        (DetectedKind::Unknown, classifications.unknown_files),
    ] {
        decisions.add(decide(kind), count)?;
    }

    if decisions.total()? != expected_regular_files {
        return Err(PolicyPlanError::InconsistentCounts);
    }

    Ok(RegularFilePolicyPlan {
        policy_id: DEFAULT_POLICY_ID,
        policy_regular_files: expected_regular_files,
        decisions,
    })
}

#[cfg(test)]
mod tests {
    use super::{
        build_default_regular_file_plan, effective_decision, ContentOutcome, Decision,
        DecisionCounts, EffectiveDispositionPlan, EffectiveDispositionSession,
        FileDispositionInput, FilenameEvidence, PolicyPlanError, RegularFileClassifications,
        DEFAULT_POLICY_ID,
    };
    use crate::detection::{ComponentInspectability, DetectedKind};

    #[test]
    fn default_regular_file_plan_is_strict_and_versioned() {
        let plan = build_default_regular_file_plan(
            RegularFileClassifications {
                text_or_code_candidates: 2,
                unsupported_files: 3,
                unknown_files: 4,
            },
            9,
        )
        .expect("consistent counts produce a plan");

        assert_eq!(plan.policy_id, DEFAULT_POLICY_ID);
        assert_eq!(plan.policy_id, "default-strict-v1");
        assert_eq!(plan.policy_regular_files, 9);
        assert_eq!(
            plan.decisions,
            DecisionCounts {
                allow: 0,
                transform: 2,
                structure_only: 0,
                omit: 7,
                block: 0,
            }
        );
        assert_eq!(plan.decisions.total(), Ok(plan.policy_regular_files));
    }

    #[test]
    fn inconsistent_regular_file_counts_fail_closed() {
        let result = build_default_regular_file_plan(
            RegularFileClassifications {
                text_or_code_candidates: 1,
                unsupported_files: 1,
                unknown_files: 1,
            },
            4,
        );

        assert_eq!(result, Err(PolicyPlanError::InconsistentCounts));
    }

    #[test]
    fn aggregate_count_overflow_fails_closed() {
        let result = build_default_regular_file_plan(
            RegularFileClassifications {
                text_or_code_candidates: usize::MAX,
                unsupported_files: 1,
                unknown_files: 0,
            },
            usize::MAX,
        );

        assert_eq!(result, Err(PolicyPlanError::CountOverflow));
    }

    fn file_input(
        detected_kind: DetectedKind,
        content_outcome: Option<ContentOutcome>,
    ) -> FileDispositionInput {
        FileDispositionInput {
            detected_kind,
            content_outcome,
            filename: FilenameEvidence::default(),
            path_component: ComponentInspectability::Inspectable,
        }
    }

    #[test]
    fn effective_policy_omits_untransformable_content_and_transforms_readable_text() {
        for outcome in [
            ContentOutcome::BinaryLike,
            ContentOutcome::InvalidUtf8,
            ContentOutcome::Oversized,
            ContentOutcome::HardLinked,
        ] {
            let mut session = EffectiveDispositionSession::new();
            session
                .observe_file(file_input(DetectedKind::TextOrCodeCandidate, Some(outcome)))
                .expect("content outcome is valid");
            let plan = session.finish(1, 0).expect("counts are consistent");
            assert_eq!(plan.effective_transform, 0);
            assert_eq!(plan.effective_omit, 1);
            assert_eq!(plan.decisions.omit, 1);
        }

        let mut session = EffectiveDispositionSession::new();
        session
            .observe_file(file_input(
                DetectedKind::TextOrCodeCandidate,
                Some(ContentOutcome::ReadableText),
            ))
            .expect("readable content is transformable");
        let plan = session.finish(1, 0).expect("counts are consistent");
        assert_eq!(plan.effective_transform, 1);
        assert_eq!(plan.effective_omit, 0);
        assert_eq!(plan.decisions.transform, 1);
    }

    #[test]
    fn unsupported_unknown_and_zero_finding_text_do_not_become_allow() {
        let mut session = EffectiveDispositionSession::new();
        session
            .observe_file(file_input(DetectedKind::Unsupported, None))
            .expect("unsupported is omitted");
        session
            .observe_file(file_input(DetectedKind::Unknown, None))
            .expect("unknown is omitted");
        session
            .observe_file(file_input(
                DetectedKind::TextOrCodeCandidate,
                Some(ContentOutcome::ReadableText),
            ))
            .expect("zero findings do not affect disposition");
        let plan = session.finish(3, 0).expect("counts are consistent");
        assert_eq!(plan.decisions.allow, 0);
        assert_eq!(plan.decisions.structure_only, 0);
        assert_eq!(plan.effective_transform, 1);
        assert_eq!(plan.effective_omit, 2);
    }

    #[test]
    fn filename_and_uninspectable_path_evidence_omit_before_content() {
        let mut filename_session = EffectiveDispositionSession::new();
        filename_session
            .observe_file(FileDispositionInput {
                filename: FilenameEvidence {
                    environment_file: true,
                    ..FilenameEvidence::default()
                },
                ..file_input(
                    DetectedKind::TextOrCodeCandidate,
                    Some(ContentOutcome::ReadableText),
                )
            })
            .expect("environment evidence omits");
        filename_session
            .observe_file(FileDispositionInput {
                filename: FilenameEvidence {
                    private_key_filename: true,
                    ..FilenameEvidence::default()
                },
                ..file_input(
                    DetectedKind::TextOrCodeCandidate,
                    Some(ContentOutcome::ReadableText),
                )
            })
            .expect("private-key evidence omits");
        filename_session
            .observe_file(FileDispositionInput {
                filename: FilenameEvidence {
                    credential_filename: true,
                    ..FilenameEvidence::default()
                },
                ..file_input(
                    DetectedKind::TextOrCodeCandidate,
                    Some(ContentOutcome::ReadableText),
                )
            })
            .expect("credential evidence omits");
        filename_session
            .observe_file(FileDispositionInput {
                filename: FilenameEvidence {
                    auth_config_filename: true,
                    ..FilenameEvidence::default()
                },
                ..file_input(
                    DetectedKind::TextOrCodeCandidate,
                    Some(ContentOutcome::ReadableText),
                )
            })
            .expect("auth-config evidence omits");
        filename_session
            .observe_file(FileDispositionInput {
                path_component: ComponentInspectability::Uninspectable,
                ..file_input(
                    DetectedKind::TextOrCodeCandidate,
                    Some(ContentOutcome::ReadableText),
                )
            })
            .expect("uninspectable file component omits");
        let plan = filename_session
            .finish(5, 0)
            .expect("counts are consistent");
        assert_eq!(plan.effective_transform, 0);
        assert_eq!(plan.effective_omit, 5);
    }

    #[test]
    fn preflight_omit_evidence_does_not_require_content_access() {
        assert_eq!(
            effective_decision(FileDispositionInput {
                detected_kind: DetectedKind::TextOrCodeCandidate,
                content_outcome: None,
                filename: FilenameEvidence {
                    credential_filename: true,
                    ..FilenameEvidence::default()
                },
                path_component: ComponentInspectability::Inspectable,
            }),
            Ok(Decision::Omit)
        );
        assert_eq!(
            effective_decision(FileDispositionInput {
                detected_kind: DetectedKind::TextOrCodeCandidate,
                content_outcome: None,
                filename: FilenameEvidence::default(),
                path_component: ComponentInspectability::Uninspectable,
            }),
            Ok(Decision::Omit)
        );
    }

    #[test]
    fn uninspectable_directory_is_unresolved_not_a_regular_file_decision() {
        let mut session = EffectiveDispositionSession::new();
        session
            .observe_directory(ComponentInspectability::Uninspectable)
            .expect("directory unresolved count is checked");
        let plan = session.finish(0, 1).expect("counts are consistent");
        assert_eq!(plan.regular_files, 0);
        assert_eq!(plan.effective_unresolved, 1);
        assert_eq!(plan.decisions.total(), Ok(0));
    }

    #[test]
    fn missing_content_and_non_regular_inputs_fail_closed() {
        let mut missing = EffectiveDispositionSession::new();
        assert_eq!(
            missing.observe_file(file_input(DetectedKind::TextOrCodeCandidate, None,)),
            Err(PolicyPlanError::MissingContentOutcome)
        );

        let mut invalid = EffectiveDispositionSession::new();
        assert_eq!(
            invalid.observe_file(file_input(DetectedKind::LinkLikeEntry, None)),
            Err(PolicyPlanError::InvalidInput)
        );
    }

    #[test]
    fn effective_counts_must_match_observed_regular_files_and_directories() {
        let mut session = EffectiveDispositionSession::new();
        session
            .observe_file(file_input(
                DetectedKind::TextOrCodeCandidate,
                Some(ContentOutcome::ReadableText),
            ))
            .expect("file observation succeeds");
        assert_eq!(
            session.finish(2, 0),
            Err(PolicyPlanError::InconsistentCounts)
        );

        let mut unresolved = EffectiveDispositionSession::new();
        unresolved
            .observe_directory(ComponentInspectability::Uninspectable)
            .expect("directory observation succeeds");
        assert_eq!(
            unresolved.finish(0, 0),
            Err(PolicyPlanError::InconsistentCounts)
        );
    }

    #[test]
    fn effective_plan_validation_checks_field_sum_and_overflow() {
        let overflow = EffectiveDispositionPlan {
            policy_id: DEFAULT_POLICY_ID,
            regular_files: usize::MAX,
            effective_transform: usize::MAX,
            effective_omit: 1,
            effective_block: 0,
            effective_unresolved: 0,
            decisions: DecisionCounts {
                allow: 0,
                transform: usize::MAX,
                structure_only: 0,
                omit: 1,
                block: 0,
            },
        };
        assert_eq!(
            overflow.validate(usize::MAX, 0),
            Err(PolicyPlanError::CountOverflow)
        );

        let mismatch = EffectiveDispositionPlan {
            policy_id: DEFAULT_POLICY_ID,
            regular_files: 1,
            effective_transform: 1,
            effective_omit: 0,
            effective_block: 0,
            effective_unresolved: 0,
            decisions: DecisionCounts {
                allow: 1,
                transform: 0,
                structure_only: 0,
                omit: 0,
                block: 0,
            },
        };
        assert_eq!(
            mismatch.validate(1, 0),
            Err(PolicyPlanError::InconsistentCounts)
        );
    }
}
