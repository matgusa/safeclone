//! Read-only round-trip edited-workspace classification.
//!
//! classification keeps detailed events and all canonical paths crate-private. The
//! public result is aggregate, raw-free evidence only; no manifest, approval,
//! candidate, or session generation is created here.

use std::fmt;
use std::path::Path;

use super::token::{ReviewProfile, ENGINE_VERSION, POLICY_ID, TOKEN_SUITE_ID};
use super::Error;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClassificationDecision {
    AutomaticEligible,
    ApprovalRequired,
    Reject,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClassificationReport {
    pub profile: ReviewProfile,
    pub engine_version: &'static str,
    pub policy_id: &'static str,
    pub ruleset_id: &'static str,
    pub token_suite_id: u16,
    pub capsule_generation: u64,
    pub edited_tree_commitment: [u8; 32],
    pub total_events: u32,
    pub primary_token_events: u32,
    pub token_events: u32,
    pub file_events: u32,
    pub directory_events: u32,
    pub structural_events: u32,
    pub automatic_events: u32,
    pub approval_required_events: u32,
    pub rejected_events: u32,
    pub derived_events: u32,
    pub decision: ClassificationDecision,
    pub semantic_safety_assessed: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClassificationFailure(Error);

impl ClassificationFailure {
    pub const fn error(self) -> Error {
        self.0
    }
}

impl fmt::Display for ClassificationFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "round-trip classification failed: {}", self.0)
    }
}

impl std::error::Error for ClassificationFailure {}

pub type ClassificationResult<T> = std::result::Result<T, ClassificationFailure>;

#[cfg(not(windows))]
pub fn classify_session(
    _original: &Path,
    _ai_workspace: &Path,
    _private_state: &Path,
) -> ClassificationResult<ClassificationReport> {
    Err(ClassificationFailure(Error::UnsupportedPlatform))
}

#[cfg(windows)]
pub fn classify_session(
    original: &Path,
    ai_workspace: &Path,
    private_state: &Path,
) -> ClassificationResult<ClassificationReport> {
    windows::classify_session(original, ai_workspace, private_state).map_err(ClassificationFailure)
}

#[cfg(windows)]
pub(crate) use windows::ReconstructionInputs;
#[cfg(windows)]
pub(crate) use windows::{
    BaselineEntry, BaselineEntryKind, BaselineTokenLocation, CandidateSelection,
    PreparedApplyAuthority, PreparedReviewAuthority, ReviewEntryAuthority,
    ReviewEntryAuthorityKind,
};

#[cfg(windows)]
pub(crate) fn prepare_review_authority(
    original: &Path,
    ai_workspace: &Path,
    private_state: &Path,
) -> Result<PreparedReviewAuthority, Error> {
    windows::prepare_review_authority(original, ai_workspace, private_state)
}

#[cfg(windows)]
pub(crate) fn prepare_approval_authority(
    original: &Path,
    ai_workspace: &Path,
    private_state: &Path,
) -> Result<PreparedReviewAuthority, Error> {
    windows::prepare_approval_authority(original, ai_workspace, private_state)
}

#[cfg(windows)]
pub(crate) fn prepare_reconstruction_authority(
    original: &Path,
    ai_workspace: &Path,
    private_state: &Path,
) -> Result<PreparedReviewAuthority, Error> {
    windows::prepare_reconstruction_authority(original, ai_workspace, private_state)
}

#[cfg(windows)]
pub(crate) fn prepare_apply_authority(
    original: &Path,
    ai_workspace: &Path,
    private_state: &Path,
    candidate: &Path,
) -> Result<PreparedApplyAuthority, Error> {
    windows::prepare_apply_authority(original, ai_workspace, private_state, candidate)
}

#[cfg(windows)]
mod windows {
    use std::collections::{BTreeMap, BTreeSet};

    use super::*;
    use crate::roundtrip::anchor::{
        build_baseline_content_template, ContentAnchorReportFact, ContentTokenSpan,
        EditedAnchorOutcome, EditedContentClassification, TokenFact,
    };
    use crate::roundtrip::baseline::{
        canonical_path, derive_two_prepublication_passes, rederive_planned_file_output,
        BaselineDerivation, FileDisposition, PlannedEntry, StreamEncoder,
    };
    use crate::roundtrip::crypto::{constant_time_equal, KeyPurpose, KeySchedule};
    use crate::roundtrip::edited::{
        exact_file_match_commitment, forms_by_known_oid, observe_pass, require_same_summary,
        EditedEntry, EditedEntryKind, EditedFileInput, EditedPass, ReservedForm, ReservedFormState,
        ReservedLocationKind,
    };
    use crate::roundtrip::events::{
        CanonicalEvent, CanonicalEventSet, EventClass, EventDecision, EventGroup, EventKind,
        StructuralReason, MAX_CANONICAL_EVENTS,
    };
    use crate::roundtrip::observe::NamespaceScope;
    use crate::roundtrip::token::{parse_token, TokenCategory, TOKEN_PREFIX};
    use crate::roundtrip::Result;

    const MAX_BASELINE_TOKEN_BYTES: usize = 128;

    #[cfg(test)]
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum TestCheckpoint {
        AfterEditedPassOne,
    }

    #[cfg(test)]
    type TestHook = Box<dyn FnMut(TestCheckpoint) -> Result<()>>;

    #[cfg(test)]
    std::thread_local! {
        static TEST_HOOK: std::cell::RefCell<Option<TestHook>> =
            std::cell::RefCell::new(None);
    }

    #[cfg(test)]
    fn test_checkpoint(checkpoint: TestCheckpoint) -> Result<()> {
        TEST_HOOK.with(|slot| {
            let mut slot = slot.try_borrow_mut().map_err(|_| Error::InvalidState)?;
            match slot.as_mut() {
                Some(hook) => hook(checkpoint),
                None => Ok(()),
            }
        })
    }

    #[cfg(test)]
    struct TestHookGuard;

    #[cfg(test)]
    impl Drop for TestHookGuard {
        fn drop(&mut self) {
            TEST_HOOK.with(|slot| *slot.borrow_mut() = None);
        }
    }

    #[cfg(test)]
    fn install_test_hook(
        hook: impl FnMut(TestCheckpoint) -> Result<()> + 'static,
    ) -> TestHookGuard {
        TEST_HOOK.with(|slot| {
            let prior = slot.borrow_mut().replace(Box::new(hook));
            assert!(prior.is_none(), "nested classification test hook");
        });
        TestHookGuard
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(crate) enum BaselineEntryKind {
        Directory,
        File,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(crate) struct PathTokenBoundary {
        pub(crate) component_index: u32,
        pub(crate) start: usize,
        pub(crate) end: usize,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(crate) enum BaselineTokenLocation {
        Content,
        Path(PathTokenBoundary),
    }

    pub(crate) struct BaselineToken {
        pub(crate) category: TokenCategory,
        pub(crate) entry_path: Vec<u8>,
        pub(crate) location: BaselineTokenLocation,
        pub(crate) before_anchor: [u8; 32],
    }

    pub(crate) struct BaselineEntry {
        pub(crate) original_path: Option<Vec<u8>>,
        pub(crate) path: Vec<u8>,
        pub(crate) components: Vec<String>,
        pub(crate) kind: BaselineEntryKind,
        pub(crate) logical_id: [u8; 32],
        pub(crate) exact_file_match: Option<[u8; 32]>,
        pub(crate) path_spans: Vec<ContentTokenSpan>,
        pub(crate) content_token_facts: Vec<TokenFact>,
        pub(crate) content_anchor_facts: Vec<crate::roundtrip::anchor::ContentAnchorFact>,
        pub(crate) planned_index: Option<usize>,
        pub(crate) own_token_oids: Vec<[u8; 16]>,
        reporting_bytes: Option<Vec<u8>>,
        reporting_content_anchors: Vec<ContentAnchorReportFact>,
    }

    pub(crate) struct ReviewBaseline {
        pub(crate) derivation: BaselineDerivation,
        pub(crate) entries: BTreeMap<Vec<u8>, BaselineEntry>,
        pub(crate) tokens: BTreeMap<[u8; 16], BaselineToken>,
        pub(crate) original_only_paths: Vec<Vec<String>>,
        pub(crate) token_oids_by_components: BTreeMap<Vec<String>, Vec<[u8; 16]>>,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum AttributedTokenState {
        Missing,
        Authentic,
        Duplicated,
        CategoryMismatch,
        Modified,
    }

    struct TokenAttribution {
        states: BTreeMap<[u8; 16], AttributedTokenState>,
        zero_attribution: BTreeSet<[u8; 16]>,
    }

    pub(crate) struct FileAnchorResults {
        pub(crate) by_path: BTreeMap<Vec<u8>, EditedContentClassification>,
    }

    type StableEditedObservation = (
        EditedPass,
        TokenAttribution,
        PathProjection,
        FileAnchorResults,
        BTreeMap<Vec<u8>, Vec<u8>>,
    );

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(crate) enum CorrespondenceKind {
        Exact,
        PathDeletionProjection,
        FileRenamed,
        FileMoved,
        DirectoryRenamed,
        DirectoryMoved,
    }

    pub(crate) struct Correspondence {
        pub(crate) baseline_to_edited: BTreeMap<Vec<u8>, (Vec<u8>, CorrespondenceKind)>,
        pub(crate) paired_edited: BTreeSet<Vec<u8>>,
        relationship_events: Vec<CanonicalEvent>,
    }

    struct ClassificationAuthority {
        report: ClassificationReport,
        events: CanonicalEventSet,
        event_set_commitment: [u8; 32],
        correspondence: Correspondence,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(crate) enum ReviewEntryAuthorityKind {
        File,
        Directory,
    }

    pub(crate) struct ReviewContentAnchorAuthority {
        pub(crate) occurrence_ids: Vec<[u8; 16]>,
        pub(crate) selected_radius: u8,
        pub(crate) final_anchor_commitment: [u8; 32],
        pub(crate) first_line: u32,
        pub(crate) end_line_exclusive: u32,
    }

    #[derive(Clone, Copy)]
    pub(crate) struct ReviewPathAnchorAuthority {
        pub(crate) occurrence_id: [u8; 16],
        pub(crate) category: TokenCategory,
        pub(crate) component_index: u32,
        pub(crate) token_start: u64,
        pub(crate) token_end: u64,
        pub(crate) exact_path_anchor_commitment: [u8; 32],
    }

    /// Confidential paths and AI-safe bytes remain transaction-local and this
    /// type deliberately has no `Debug` implementation.
    pub(crate) struct ReviewEntryAuthority {
        pub(crate) kind: ReviewEntryAuthorityKind,
        pub(crate) original_path: Option<Vec<u8>>,
        pub(crate) safe_path_before: Option<Vec<u8>>,
        pub(crate) safe_path_after: Option<Vec<u8>>,
        pub(crate) before_ai_safe_bytes: Option<Vec<u8>>,
        pub(crate) after_ai_bytes: Option<Vec<u8>>,
        pub(crate) content_anchors: Vec<ReviewContentAnchorAuthority>,
        pub(crate) path_anchors: Vec<ReviewPathAnchorAuthority>,
    }

    /// A fresh classification authority retained under the session mutation lock for an
    /// review review or approval approval transaction. Raw values and Original bytes
    /// are absent.
    pub(crate) struct PreparedReviewAuthority {
        pub(crate) report: ClassificationReport,
        pub(crate) events: CanonicalEventSet,
        pub(crate) event_set_commitment: [u8; 32],
        pub(crate) original_tree_commitment: [u8; 32],
        pub(crate) observed_files: u32,
        pub(crate) observed_directories: u32,
        pub(crate) entries: Vec<ReviewEntryAuthority>,
        pub(crate) store: crate::roundtrip::capsule::GenerationStore,
        pub(crate) lock: crate::roundtrip::capsule::MutationLock,
        pub(crate) owner: Box<crate::roundtrip::dpapi::AuthenticatedLiveCapsule>,
        ai_parent: crate::roundtrip::observe::QualifiedDirectory,
        ai_leaf: std::ffi::OsString,
        ai_identity: crate::roundtrip::observe::FileIdentity,
        state_parent: crate::roundtrip::observe::QualifiedDirectory,
        state_leaf: std::ffi::OsString,
        state_identity: crate::roundtrip::observe::FileIdentity,
        reconstruction: Option<ReconstructionInputs>,
    }

    /// Fresh retained inputs available only in reconstruction preparation mode.  Raw
    /// Original and edited bytes remain transaction-local; no formatter or
    /// serialization implementation exists.
    pub(crate) struct ReconstructionInputs {
        pub(crate) original: crate::roundtrip::observe::QualifiedDirectory,
        pub(crate) ai: crate::roundtrip::observe::QualifiedDirectory,
        pub(crate) profile: ReviewProfile,
        pub(crate) baseline: ReviewBaseline,
        pub(crate) edited: EditedPass,
        pub(crate) correspondence: Correspondence,
        pub(crate) anchors: FileAnchorResults,
    }

    pub(crate) enum CandidateSelection {
        Absent(crate::roundtrip::observe::ValidatedLeaf),
        Existing(crate::roundtrip::observe::QualifiedDirectory),
    }

    /// Fresh four-path candidate construction authority. Candidate path text remains transient;
    /// this value retains only the qualified parent, exact leaf selection and
    /// the classification/reconstruction transaction under the mutation lock.
    pub(crate) struct PreparedApplyAuthority {
        pub(crate) review: PreparedReviewAuthority,
        pub(crate) candidate_parent: crate::roundtrip::observe::QualifiedDirectory,
        pub(crate) candidate_leaf: std::ffi::OsString,
        pub(crate) candidate: CandidateSelection,
    }

    impl PreparedReviewAuthority {
        pub(crate) fn verify_selected_roots(&self) -> Result<()> {
            verify_selected_root(
                &self.ai_parent,
                &self.ai_leaf,
                NamespaceScope::Workspace,
                self.ai_identity,
            )?;
            verify_selected_root(
                &self.state_parent,
                &self.state_leaf,
                NamespaceScope::Workspace,
                self.state_identity,
            )
        }

        pub(crate) fn take_reconstruction_inputs(&mut self) -> Result<ReconstructionInputs> {
            self.reconstruction.take().ok_or(Error::InvalidState)
        }
    }

    pub(super) fn classify_session(
        original_path: &Path,
        ai_path: &Path,
        state_path: &Path,
    ) -> Result<ClassificationReport> {
        let authority = integrated_classify(original_path, ai_path, state_path)?;
        let _ = (&authority.events, authority.event_set_commitment);
        Ok(authority.report)
    }

    fn build_review_baseline(
        original: &crate::roundtrip::observe::QualifiedDirectory,
        derivation: BaselineDerivation,
        schedule: &KeySchedule<'_>,
        profile: ReviewProfile,
        retain_reporting_bytes: bool,
        retain_identity_paths: bool,
    ) -> Result<ReviewBaseline> {
        let mut entries = BTreeMap::new();
        let mut tokens = BTreeMap::new();
        let mut original_only_paths = Vec::new();
        let mut token_oids_by_components = BTreeMap::new();
        let mut safe_directories_by_original = BTreeMap::<Vec<String>, Vec<String>>::new();

        for (planned_index, planned) in derivation.plan.entries.iter().enumerate() {
            match planned {
                PlannedEntry::Directory {
                    original_components,
                    safe_components,
                    token_facts,
                    ..
                } => {
                    safe_directories_by_original
                        .insert(original_components.clone(), safe_components.clone());
                    let path = canonical_path(safe_components)?;
                    let original_path = retain_identity_paths
                        .then(|| canonical_path(original_components))
                        .transpose()?;
                    let leaf = safe_components.last().ok_or(Error::InvalidState)?;
                    let path_spans = scan_expected_tokens(leaf.as_bytes(), token_facts)?;
                    let logical_id =
                        logical_entry_id(schedule, &path, BaselineEntryKind::Directory)?;
                    let own_token_oids = token_fact_oids(token_facts)?;
                    if !own_token_oids.is_empty()
                        && token_oids_by_components
                            .insert(safe_components.clone(), own_token_oids.clone())
                            .is_some()
                    {
                        return Err(Error::InvalidState);
                    }
                    insert_path_tokens(
                        &mut tokens,
                        token_facts,
                        &path_spans,
                        &path,
                        u32::try_from(safe_components.len() - 1)
                            .map_err(|_| Error::BoundExceeded)?,
                        logical_id,
                    )?;
                    let entry = BaselineEntry {
                        original_path,
                        path: path.clone(),
                        components: safe_components.clone(),
                        kind: BaselineEntryKind::Directory,
                        logical_id,
                        exact_file_match: None,
                        path_spans,
                        content_token_facts: Vec::new(),
                        content_anchor_facts: Vec::new(),
                        planned_index: Some(planned_index),
                        own_token_oids,
                        reporting_bytes: None,
                        reporting_content_anchors: Vec::new(),
                    };
                    if entries.insert(path, entry).is_some() {
                        return Err(Error::InvalidState);
                    }
                }
                PlannedEntry::File {
                    original_components,
                    safe_components: None,
                    disposition: FileDisposition::Omit(_),
                    ..
                } => {
                    let (leaf, original_parent) = original_components
                        .split_last()
                        .ok_or(Error::InvalidState)?;
                    let mut collision_path = if original_parent.is_empty() {
                        Vec::new()
                    } else {
                        safe_directories_by_original
                            .get(original_parent)
                            .cloned()
                            .ok_or(Error::InvalidState)?
                    };
                    collision_path
                        .try_reserve_exact(1)
                        .map_err(|_| Error::BoundExceeded)?;
                    collision_path.push(leaf.clone());
                    original_only_paths
                        .try_reserve(1)
                        .map_err(|_| Error::BoundExceeded)?;
                    original_only_paths.push(collision_path);
                }
                PlannedEntry::File {
                    original_components,
                    safe_components: Some(safe_components),
                    disposition: FileDisposition::Transform,
                    path_token_facts,
                    content_token_facts,
                    content_anchor_facts,
                    ..
                } => {
                    let path = canonical_path(safe_components)?;
                    let bytes = rederive_planned_file_output(original, planned, schedule, profile)?;
                    let reporting_bytes = if retain_reporting_bytes {
                        Some(bytes.clone())
                    } else {
                        None
                    };
                    let exact_file_match = exact_file_match_commitment(schedule, &bytes)?;
                    let leaf = safe_components.last().ok_or(Error::InvalidState)?;
                    let path_spans = scan_expected_tokens(leaf.as_bytes(), path_token_facts)?;
                    let content_spans = scan_expected_tokens(&bytes, content_token_facts)?;
                    let logical_id = logical_entry_id(schedule, &path, BaselineEntryKind::File)?;
                    insert_path_tokens(
                        &mut tokens,
                        path_token_facts,
                        &path_spans,
                        &path,
                        u32::try_from(safe_components.len() - 1)
                            .map_err(|_| Error::BoundExceeded)?,
                        logical_id,
                    )?;
                    let content_template = if content_token_facts.is_empty() {
                        None
                    } else {
                        Some(build_baseline_content_template(
                            schedule,
                            bytes,
                            &content_spans,
                            content_anchor_facts,
                        )?)
                    };
                    let reporting_content_anchors =
                        match (&content_template, retain_reporting_bytes) {
                            (Some(template), true) => template.reporting_anchor_facts()?,
                            _ => Vec::new(),
                        };
                    if let Some(template) = &content_template {
                        for fact in template.token_order() {
                            let before_anchor = template
                                .pre_token_anchor(&fact.occurrence_id)
                                .ok_or(Error::InvalidState)?;
                            if tokens
                                .insert(
                                    fact.occurrence_id,
                                    BaselineToken {
                                        category: fact.category,
                                        entry_path: path.clone(),
                                        location: BaselineTokenLocation::Content,
                                        before_anchor,
                                    },
                                )
                                .is_some()
                            {
                                return Err(Error::InvalidToken);
                            }
                        }
                    }
                    let mut own_token_oids = token_fact_oids(path_token_facts)?;
                    own_token_oids
                        .try_reserve_exact(content_token_facts.len())
                        .map_err(|_| Error::BoundExceeded)?;
                    own_token_oids
                        .extend(content_token_facts.iter().map(|fact| fact.occurrence_id));
                    if !own_token_oids.is_empty()
                        && token_oids_by_components
                            .insert(safe_components.clone(), own_token_oids.clone())
                            .is_some()
                    {
                        return Err(Error::InvalidState);
                    }
                    let entry = BaselineEntry {
                        original_path: retain_identity_paths
                            .then(|| canonical_path(original_components))
                            .transpose()?,
                        path: path.clone(),
                        components: safe_components.clone(),
                        kind: BaselineEntryKind::File,
                        logical_id,
                        exact_file_match: Some(exact_file_match),
                        path_spans,
                        content_token_facts: content_token_facts.clone(),
                        content_anchor_facts: content_anchor_facts.clone(),
                        planned_index: Some(planned_index),
                        own_token_oids,
                        reporting_bytes,
                        reporting_content_anchors,
                    };
                    if entries.insert(path, entry).is_some() {
                        return Err(Error::InvalidState);
                    }
                }
                PlannedEntry::File { .. } => return Err(Error::InvalidState),
            }
        }
        if tokens.len() != derivation.plan.inventory.len()
            || derivation.plan.inventory.iter().any(|(oid, category)| {
                tokens
                    .get(oid)
                    .is_none_or(|token| &token.category != category)
            })
        {
            return Err(Error::InvalidToken);
        }
        crate::roundtrip::observe::sort_namespace_paths(&mut original_only_paths)?;
        Ok(ReviewBaseline {
            derivation,
            entries,
            tokens,
            original_only_paths,
            token_oids_by_components,
        })
    }

    fn scan_expected_tokens(bytes: &[u8], facts: &[TokenFact]) -> Result<Vec<ContentTokenSpan>> {
        let prefix = TOKEN_PREFIX.as_bytes();
        let mut spans = Vec::new();
        spans
            .try_reserve_exact(facts.len())
            .map_err(|_| Error::BoundExceeded)?;
        let mut cursor = 0usize;
        while let Some(relative) = bytes.get(cursor..).and_then(|tail| {
            tail.windows(prefix.len())
                .position(|window| window == prefix)
        }) {
            let start = cursor.checked_add(relative).ok_or(Error::BoundExceeded)?;
            let maximum = start
                .checked_add(MAX_BASELINE_TOKEN_BYTES)
                .ok_or(Error::BoundExceeded)?
                .min(bytes.len());
            let body_start = start
                .checked_add(prefix.len())
                .ok_or(Error::BoundExceeded)?;
            let suffix = bytes
                .get(body_start..maximum)
                .and_then(|tail| tail.windows(2).position(|window| window == b"__"))
                .ok_or(Error::InvalidToken)?;
            let end = body_start
                .checked_add(suffix)
                .and_then(|value| value.checked_add(2))
                .ok_or(Error::BoundExceeded)?;
            let token = std::str::from_utf8(bytes.get(start..end).ok_or(Error::InvalidToken)?)
                .map_err(|_| Error::InvalidToken)?;
            let parsed = parse_token(token)?;
            spans.push(ContentTokenSpan {
                start,
                end,
                fact: TokenFact {
                    category: parsed.category(),
                    occurrence_id: *parsed.occurrence_id(),
                },
            });
            cursor = end;
        }
        if spans.len() != facts.len()
            || spans
                .iter()
                .zip(facts)
                .any(|(span, fact)| span.fact != *fact)
        {
            return Err(Error::InvalidToken);
        }
        Ok(spans)
    }

    fn token_fact_oids(facts: &[TokenFact]) -> Result<Vec<[u8; 16]>> {
        let mut output = Vec::new();
        output
            .try_reserve_exact(facts.len())
            .map_err(|_| Error::BoundExceeded)?;
        output.extend(facts.iter().map(|fact| fact.occurrence_id));
        Ok(output)
    }

    fn insert_path_tokens(
        tokens: &mut BTreeMap<[u8; 16], BaselineToken>,
        facts: &[TokenFact],
        spans: &[ContentTokenSpan],
        path: &[u8],
        component_index: u32,
        before_anchor: [u8; 32],
    ) -> Result<()> {
        for (fact, span) in facts.iter().zip(spans) {
            if tokens
                .insert(
                    fact.occurrence_id,
                    BaselineToken {
                        category: fact.category,
                        entry_path: path.to_vec(),
                        location: BaselineTokenLocation::Path(PathTokenBoundary {
                            component_index,
                            start: span.start,
                            end: span.end,
                        }),
                        before_anchor,
                    },
                )
                .is_some()
            {
                return Err(Error::InvalidToken);
            }
        }
        Ok(())
    }

    fn logical_entry_id(
        schedule: &KeySchedule<'_>,
        path: &[u8],
        kind: BaselineEntryKind,
    ) -> Result<[u8; 32]> {
        let mut output = StreamEncoder::new(
            schedule,
            KeyPurpose::TreeCommit,
            b"safeclone/rt3/logical-baseline-entry-v1",
        )?;
        output.u8(match kind {
            BaselineEntryKind::Directory => 1,
            BaselineEntryKind::File => 2,
        });
        output.bytes(path)?;
        Ok(output.finish())
    }

    fn attribute_tokens(
        baseline: &ReviewBaseline,
        pass: &EditedPass,
        session_id: [u8; 16],
    ) -> Result<TokenAttribution> {
        let by_oid = forms_by_known_oid(&pass.forms, &baseline.derivation.plan.inventory)?;
        let mut states = BTreeMap::new();
        let mut zero_attribution = BTreeSet::new();
        for (oid, expected) in baseline.derivation.plan.inventory.iter() {
            let attributable = by_oid.get(oid).map(Vec::as_slice).unwrap_or(&[]);
            let state = match attributable.len() {
                0 => {
                    zero_attribution.insert(*oid);
                    AttributedTokenState::Missing
                }
                1 => {
                    let form = attributable[0];
                    if form.session_id == Some(session_id)
                        && form.category.is_some_and(|category| category != *expected)
                    {
                        AttributedTokenState::CategoryMismatch
                    } else if form.authenticated_known
                        && form.category == Some(*expected)
                        && form.state == ReservedFormState::Canonical
                    {
                        AttributedTokenState::Authentic
                    } else {
                        AttributedTokenState::Modified
                    }
                }
                _ => AttributedTokenState::Duplicated,
            };
            if states.insert(*oid, state).is_some() {
                return Err(Error::InvalidToken);
            }
        }
        Ok(TokenAttribution {
            states,
            zero_attribution,
        })
    }

    struct PathProjection {
        correspondence: BTreeMap<Vec<u8>, Vec<u8>>,
        deletion_eligible: BTreeSet<[u8; 16]>,
    }

    fn path_deletion_projection(
        baseline: &ReviewBaseline,
        edited: &EditedPass,
        zero: &BTreeSet<[u8; 16]>,
    ) -> Result<PathProjection> {
        let edited_by_path = edited
            .entries
            .iter()
            .map(|entry| (entry.path.as_slice(), entry))
            .collect::<BTreeMap<_, _>>();
        let mut correspondence = BTreeMap::new();
        let mut deletion_eligible = BTreeSet::new();
        let mut candidates = BTreeMap::<Vec<u8>, Vec<(Vec<u8>, Vec<[u8; 16]>)>>::new();
        for entry in baseline.entries.values() {
            let mut missing = Vec::new();
            missing
                .try_reserve_exact(entry.path_spans.len())
                .map_err(|_| Error::BoundExceeded)?;
            missing.extend(
                entry
                    .path_spans
                    .iter()
                    .filter(|span| zero.contains(&span.fact.occurrence_id)),
            );
            if missing.is_empty() {
                continue;
            }
            let leaf = entry.components.last().ok_or(Error::InvalidState)?;
            let projected_leaf = remove_exact_token_spans(leaf.as_bytes(), &missing)?;
            if projected_leaf.is_empty() {
                continue;
            }
            let projected_leaf = match std::str::from_utf8(&projected_leaf) {
                Ok(value) => value,
                Err(_) => continue,
            };
            let mut projected_components = entry.components[..entry.components.len() - 1].to_vec();
            projected_components
                .try_reserve_exact(1)
                .map_err(|_| Error::BoundExceeded)?;
            projected_components.push(projected_leaf.to_owned());
            let projected_path = canonical_path(&projected_components)?;
            if baseline.entries.contains_key(&projected_path) {
                continue;
            }
            let Some(edited_entry) = edited_by_path.get(projected_path.as_slice()) else {
                continue;
            };
            let same_kind = matches!(
                (entry.kind, edited_entry.kind),
                (BaselineEntryKind::File, EditedEntryKind::File)
                    | (BaselineEntryKind::Directory, EditedEntryKind::Directory)
            );
            if !same_kind || edited_entry.protected_name {
                continue;
            }
            let mut missing_oids = Vec::new();
            missing_oids
                .try_reserve_exact(missing.len())
                .map_err(|_| Error::BoundExceeded)?;
            missing_oids.extend(missing.into_iter().map(|span| span.fact.occurrence_id));
            push_group(
                &mut candidates,
                projected_path,
                (entry.path.clone(), missing_oids),
            )?;
        }
        for (after, mut owners) in candidates {
            if owners.len() != 1 {
                continue;
            }
            let (before, oids) = owners.pop().ok_or(Error::InvalidState)?;
            correspondence.insert(before, after);
            deletion_eligible.extend(oids);
        }
        Ok(PathProjection {
            correspondence,
            deletion_eligible,
        })
    }

    fn remove_exact_token_spans(bytes: &[u8], missing: &[&ContentTokenSpan]) -> Result<Vec<u8>> {
        let mut output = Vec::new();
        output
            .try_reserve_exact(bytes.len())
            .map_err(|_| Error::BoundExceeded)?;
        let mut cursor = 0usize;
        for span in missing {
            if span.start < cursor || span.start >= span.end || span.end > bytes.len() {
                return Err(Error::InvalidToken);
            }
            output.extend_from_slice(bytes.get(cursor..span.start).ok_or(Error::InvalidToken)?);
            cursor = span.end;
        }
        output.extend_from_slice(bytes.get(cursor..).ok_or(Error::InvalidToken)?);
        Ok(output)
    }

    fn observe_edited_stably(
        original: &crate::roundtrip::observe::QualifiedDirectory,
        root: &crate::roundtrip::observe::QualifiedDirectory,
        baseline: &ReviewBaseline,
        schedule: &KeySchedule<'_>,
        profile: ReviewProfile,
        retain_reporting_bytes: bool,
    ) -> Result<StableEditedObservation> {
        let first = observe_pass(
            root,
            schedule,
            &baseline.derivation.plan.inventory,
            profile,
            |_| Ok(()),
        )?;
        #[cfg(test)]
        test_checkpoint(TestCheckpoint::AfterEditedPassOne)
            .map_err(|_| Error::WorkspaceUnstable)?;
        let attribution = attribute_tokens(baseline, &first, *schedule.session_id().as_bytes())?;
        let projection = path_deletion_projection(baseline, &first, &attribution.zero_attribution)?;
        let edited_to_baseline = edited_to_baseline_paths(baseline, &first, &projection)?;
        let mut anchors = FileAnchorResults {
            by_path: BTreeMap::new(),
        };
        let mut reporting_bytes = BTreeMap::new();
        let second = observe_pass(
            root,
            schedule,
            &baseline.derivation.plan.inventory,
            profile,
            |input: EditedFileInput<'_>| {
                if retain_reporting_bytes
                    && reporting_bytes
                        .insert(input.path.to_vec(), input.bytes.to_vec())
                        .is_some()
                {
                    return Err(Error::InvalidState);
                }
                let Some(baseline_path) = edited_to_baseline.get(input.path) else {
                    return Ok(());
                };
                let baseline_entry = baseline
                    .entries
                    .get(baseline_path)
                    .ok_or(Error::InvalidState)?;
                if baseline_entry.content_token_facts.is_empty() {
                    return Ok(());
                }
                let planned = baseline
                    .derivation
                    .plan
                    .entries
                    .get(baseline_entry.planned_index.ok_or(Error::InvalidState)?)
                    .ok_or(Error::InvalidState)?;
                let baseline_bytes =
                    rederive_planned_file_output(original, planned, schedule, profile)
                        .map_err(|_| Error::OriginalBaselineMismatch)?;
                let baseline_spans =
                    scan_expected_tokens(&baseline_bytes, &baseline_entry.content_token_facts)?;
                let template = build_baseline_content_template(
                    schedule,
                    baseline_bytes,
                    &baseline_spans,
                    &baseline_entry.content_anchor_facts,
                )?;
                let result = crate::roundtrip::anchor::classify_edited_content(
                    schedule,
                    &template,
                    input.bytes,
                    input.authenticated_tokens,
                    &attribution.zero_attribution,
                )?;
                if anchors
                    .by_path
                    .insert(baseline_path.clone(), result)
                    .is_some()
                {
                    return Err(Error::InvalidState);
                }
                Ok(())
            },
        )?;
        require_same_summary(&first.summary, &second.summary)?;
        Ok((second, attribution, projection, anchors, reporting_bytes))
    }

    fn edited_to_baseline_paths(
        baseline: &ReviewBaseline,
        edited: &EditedPass,
        projection: &PathProjection,
    ) -> Result<BTreeMap<Vec<u8>, Vec<u8>>> {
        let mut paths = BTreeMap::<Vec<u8>, Vec<u8>>::new();
        for path in baseline.entries.keys() {
            insert_edited_baseline_path(&mut paths, path.clone(), path.clone())?;
        }
        let edited_by_path = edited
            .entries
            .iter()
            .map(|entry| (entry.path.as_slice(), entry))
            .collect::<BTreeMap<_, _>>();
        for (before_path, after_path) in &projection.correspondence {
            insert_edited_baseline_path(&mut paths, after_path.clone(), before_path.clone())?;
            let before = baseline
                .entries
                .get(before_path)
                .ok_or(Error::InvalidState)?;
            if before.kind != BaselineEntryKind::Directory {
                continue;
            }
            let after = edited_by_path
                .get(after_path.as_slice())
                .ok_or(Error::InvalidState)?;
            let subtree_prefix = descendant_prefix(&before.path)?;
            for (path, child) in baseline.entries.range(subtree_prefix.clone()..) {
                if !path.starts_with(&subtree_prefix) {
                    break;
                }
                let mut projected = after.components.clone();
                projected.extend_from_slice(&child.components[before.components.len()..]);
                insert_edited_baseline_path(
                    &mut paths,
                    canonical_path(&projected)?,
                    child.path.clone(),
                )?;
            }
        }
        Ok(paths)
    }

    fn insert_edited_baseline_path(
        paths: &mut BTreeMap<Vec<u8>, Vec<u8>>,
        edited: Vec<u8>,
        baseline: Vec<u8>,
    ) -> Result<()> {
        match paths.insert(edited, baseline.clone()) {
            Some(previous) if previous != baseline => Err(Error::InvalidState),
            _ => Ok(()),
        }
    }

    fn build_correspondence(
        baseline: &ReviewBaseline,
        edited: &EditedPass,
        projection: &PathProjection,
        schedule: &KeySchedule<'_>,
    ) -> Result<Correspondence> {
        let edited_by_path = edited
            .entries
            .iter()
            .map(|entry| (entry.path.clone(), entry))
            .collect::<BTreeMap<_, _>>();
        let mut output = Correspondence {
            baseline_to_edited: BTreeMap::new(),
            paired_edited: BTreeSet::new(),
            relationship_events: Vec::new(),
        };

        // Exact canonical safe paths are the first and strongest relation.
        for (path, before) in &baseline.entries {
            let Some(after) = edited_by_path.get(path) else {
                continue;
            };
            if kinds_match(before.kind, after.kind) {
                insert_correspondence(
                    &mut output,
                    path.clone(),
                    path.clone(),
                    CorrespondenceKind::Exact,
                )?;
            }
        }

        // Accepted path-token deletion is the sole non-exact token-bearing
        // path relation. A projected directory carries its exact descendant
        // relative paths, but does not authorize similarity matching.
        for (before_path, after_path) in &projection.correspondence {
            if output.baseline_to_edited.contains_key(before_path)
                || output.paired_edited.contains(after_path)
            {
                return Err(Error::InvalidState);
            }
            insert_correspondence(
                &mut output,
                before_path.clone(),
                after_path.clone(),
                CorrespondenceKind::PathDeletionProjection,
            )?;
            let before_root = baseline
                .entries
                .get(before_path)
                .ok_or(Error::InvalidState)?;
            let after_root = edited_by_path.get(after_path).ok_or(Error::InvalidState)?;
            let (group, class, event_kind) = match before_root.kind {
                BaselineEntryKind::Directory => (
                    EventGroup::Directory,
                    EventClass::Directory,
                    EventKind::DirectoryRenamed,
                ),
                BaselineEntryKind::File => {
                    (EventGroup::File, EventClass::File, EventKind::FileRenamed)
                }
            };
            push_event(
                &mut output.relationship_events,
                entry_event(
                    group,
                    class,
                    event_kind,
                    EventDecision::Automatic,
                    StructuralReason::Exact,
                    Some(before_root.logical_id),
                    Some(logical_entry_id(schedule, after_path, before_root.kind)?),
                    Some(before_path.clone()),
                    Some(after_path.clone()),
                ),
            )?;
            if before_root.kind == BaselineEntryKind::Directory {
                pair_relative_descendants(
                    baseline,
                    &edited_by_path,
                    before_root,
                    after_root,
                    CorrespondenceKind::PathDeletionProjection,
                    &mut output,
                )?;
            }
        }

        pair_unique_token_free_directories(
            baseline,
            edited,
            &edited_by_path,
            schedule,
            &mut output,
        )?;
        pair_unique_token_free_files(baseline, edited, &edited_by_path, schedule, &mut output)?;
        Ok(output)
    }

    fn kinds_match(before: BaselineEntryKind, after: EditedEntryKind) -> bool {
        matches!(
            (before, after),
            (BaselineEntryKind::Directory, EditedEntryKind::Directory)
                | (BaselineEntryKind::File, EditedEntryKind::File)
        )
    }

    fn insert_correspondence(
        output: &mut Correspondence,
        before: Vec<u8>,
        after: Vec<u8>,
        kind: CorrespondenceKind,
    ) -> Result<()> {
        if output
            .baseline_to_edited
            .insert(before, (after.clone(), kind))
            .is_some()
            || !output.paired_edited.insert(after)
        {
            return Err(Error::InvalidState);
        }
        Ok(())
    }

    fn push_group<K: Ord, V>(groups: &mut BTreeMap<K, Vec<V>>, key: K, value: V) -> Result<()> {
        let group = groups.entry(key).or_default();
        group.try_reserve(1).map_err(|_| Error::BoundExceeded)?;
        group.push(value);
        Ok(())
    }

    const COMMITMENT_INDEX_PREFIX_BYTES: usize = 31;
    type CommitmentIndexPrefix = [u8; COMMITMENT_INDEX_PREFIX_BYTES];

    struct IndexedCommitmentCandidate {
        commitment: [u8; 32],
        paths: Vec<Vec<u8>>,
    }

    #[derive(Default)]
    struct CommitmentCandidateIndex {
        // The prefix and final-byte maps are candidate-discovery indexes only.
        // Equal full commitments cannot land in different buckets, while a
        // prefix bucket can contain up to 256 distinct full commitments. This
        // keeps confirmation bounded without letting map equality authorize a
        // correspondence: callers can obtain paths only through the full-width
        // constant-time verifier below.
        buckets: BTreeMap<CommitmentIndexPrefix, BTreeMap<u8, IndexedCommitmentCandidate>>,
    }

    impl CommitmentCandidateIndex {
        fn insert(&mut self, commitment: [u8; 32], path: Vec<u8>) -> Result<()> {
            let prefix = commitment_index_prefix(&commitment);
            let discriminator = commitment[COMMITMENT_INDEX_PREFIX_BYTES];
            let candidate = self
                .buckets
                .entry(prefix)
                .or_default()
                .entry(discriminator)
                .or_insert_with(|| IndexedCommitmentCandidate {
                    commitment,
                    paths: Vec::new(),
                });
            candidate
                .paths
                .try_reserve(1)
                .map_err(|_| Error::BoundExceeded)?;
            candidate.paths.push(path);
            Ok(())
        }

        fn commitments(&self) -> impl Iterator<Item = &[u8; 32]> {
            self.buckets
                .values()
                .flat_map(|bucket| bucket.values().map(|candidate| &candidate.commitment))
        }

        fn unique_constant_time_confirmed_path(
            &self,
            query: &[u8; 32],
        ) -> Result<Option<&Vec<u8>>> {
            let prefix = commitment_index_prefix(query);
            let Some(bucket) = self.buckets.get(&prefix) else {
                return Ok(None);
            };

            let mut confirmed_count = 0usize;
            let mut unique = None;
            for candidate in bucket.values() {
                if constant_time_equal(query, &candidate.commitment) {
                    for path in &candidate.paths {
                        confirmed_count =
                            confirmed_count.checked_add(1).ok_or(Error::BoundExceeded)?;
                        unique = (confirmed_count == 1).then_some(path);
                    }
                }
            }

            if confirmed_count == 1 {
                Ok(Some(unique.ok_or(Error::InvalidState)?))
            } else {
                Ok(None)
            }
        }
    }

    fn commitment_index_prefix(commitment: &[u8; 32]) -> CommitmentIndexPrefix {
        let mut prefix = [0u8; COMMITMENT_INDEX_PREFIX_BYTES];
        prefix.copy_from_slice(&commitment[..COMMITMENT_INDEX_PREFIX_BYTES]);
        prefix
    }

    fn unique_constant_time_confirmed_pair<'a>(
        before: &'a CommitmentCandidateIndex,
        after: &'a CommitmentCandidateIndex,
        query: &[u8; 32],
    ) -> Result<Option<(&'a Vec<u8>, &'a Vec<u8>)>> {
        let Some(before_path) = before.unique_constant_time_confirmed_path(query)? else {
            return Ok(None);
        };
        let Some(after_path) = after.unique_constant_time_confirmed_path(query)? else {
            return Ok(None);
        };
        Ok(Some((before_path, after_path)))
    }

    fn pair_relative_descendants(
        baseline: &ReviewBaseline,
        edited_by_path: &BTreeMap<Vec<u8>, &EditedEntry>,
        before_root: &BaselineEntry,
        after_root: &EditedEntry,
        kind: CorrespondenceKind,
        output: &mut Correspondence,
    ) -> Result<()> {
        let subtree_prefix = descendant_prefix(&before_root.path)?;
        for (path, child) in baseline.entries.range(subtree_prefix.clone()..) {
            if !path.starts_with(&subtree_prefix) {
                break;
            }
            let mut projected = after_root.components.clone();
            projected.extend_from_slice(&child.components[before_root.components.len()..]);
            let after_path = canonical_path(&projected)?;
            let Some(after) = edited_by_path.get(&after_path) else {
                continue;
            };
            if kinds_match(child.kind, after.kind)
                && !output.baseline_to_edited.contains_key(&child.path)
                && !output.paired_edited.contains(&after_path)
            {
                insert_correspondence(output, child.path.clone(), after_path, kind)?;
            }
        }
        Ok(())
    }

    fn pair_unique_token_free_directories(
        baseline: &ReviewBaseline,
        edited: &EditedPass,
        edited_by_path: &BTreeMap<Vec<u8>, &EditedEntry>,
        schedule: &KeySchedule<'_>,
        output: &mut Correspondence,
    ) -> Result<()> {
        let mut before_index = CommitmentCandidateIndex::default();
        for entry in baseline.entries.values() {
            if entry.kind != BaselineEntryKind::Directory
                || output.baseline_to_edited.contains_key(&entry.path)
                || has_unpaired_baseline_directory_ancestor(baseline, entry, output)?
            {
                continue;
            }
            let Some(commitment) = baseline_subtree_commitment(baseline, entry, schedule)? else {
                continue;
            };
            before_index.insert(commitment, entry.path.clone())?;
        }
        let mut after_index = CommitmentCandidateIndex::default();
        for entry in &edited.entries {
            if entry.kind != EditedEntryKind::Directory
                || output.paired_edited.contains(&entry.path)
                || has_unpaired_edited_directory_ancestor(edited_by_path, entry, output)?
            {
                continue;
            }
            let Some(commitment) = edited_subtree_commitment(edited_by_path, entry, schedule)?
            else {
                continue;
            };
            after_index.insert(commitment, entry.path.clone())?;
        }
        for commitment in before_index.commitments() {
            let Some((before_path, after_path)) =
                unique_constant_time_confirmed_pair(&before_index, &after_index, commitment)?
            else {
                continue;
            };
            if output.baseline_to_edited.contains_key(before_path)
                || output.paired_edited.contains(after_path)
            {
                continue;
            }
            let before = baseline
                .entries
                .get(before_path)
                .ok_or(Error::InvalidState)?;
            let after = edited_by_path.get(after_path).ok_or(Error::InvalidState)?;
            let moved = parents_differ(&before.components, &after.components);
            let kind = if moved {
                CorrespondenceKind::DirectoryMoved
            } else {
                CorrespondenceKind::DirectoryRenamed
            };
            insert_correspondence(output, before_path.clone(), after_path.clone(), kind)?;
            pair_relative_descendants(baseline, edited_by_path, before, after, kind, output)?;
            push_event(
                &mut output.relationship_events,
                entry_event(
                    EventGroup::Directory,
                    EventClass::Directory,
                    if moved {
                        EventKind::DirectoryMoved
                    } else {
                        EventKind::DirectoryRenamed
                    },
                    EventDecision::Automatic,
                    StructuralReason::Exact,
                    Some(before.logical_id),
                    Some(logical_entry_id(
                        schedule,
                        after_path,
                        BaselineEntryKind::Directory,
                    )?),
                    Some(before_path.clone()),
                    Some(after_path.clone()),
                ),
            )?;
        }
        Ok(())
    }

    fn pair_unique_token_free_files(
        baseline: &ReviewBaseline,
        edited: &EditedPass,
        edited_by_path: &BTreeMap<Vec<u8>, &EditedEntry>,
        schedule: &KeySchedule<'_>,
        output: &mut Correspondence,
    ) -> Result<()> {
        let edited_reserved_components = edited
            .entries
            .iter()
            .filter(|entry| !entry.path_form_range.is_empty())
            .map(|entry| entry.components.clone())
            .collect::<BTreeSet<_>>();
        let mut before_index = CommitmentCandidateIndex::default();
        for entry in baseline.entries.values().filter(|entry| {
            entry.kind == BaselineEntryKind::File
                && !output.baseline_to_edited.contains_key(&entry.path)
                && !baseline_path_has_token(baseline, &entry.components)
        }) {
            let commitment = entry.exact_file_match.ok_or(Error::InvalidState)?;
            before_index.insert(commitment, entry.path.clone())?;
        }
        let mut after_index = CommitmentCandidateIndex::default();
        for entry in edited.entries.iter().filter(|entry| {
            entry.kind == EditedEntryKind::File
                && !output.paired_edited.contains(&entry.path)
                && edited_entry_safe_for_automatic(entry)
                && !edited_path_has_reserved(&edited_reserved_components, &entry.components)
                && entry.path_form_range.is_empty()
                && entry.content_form_range.is_empty()
        }) {
            let commitment = entry.exact_file_match.ok_or(Error::InvalidState)?;
            after_index.insert(commitment, entry.path.clone())?;
        }
        for commitment in before_index.commitments() {
            let Some((before_path, after_path)) =
                unique_constant_time_confirmed_pair(&before_index, &after_index, commitment)?
            else {
                continue;
            };
            if output.baseline_to_edited.contains_key(before_path)
                || output.paired_edited.contains(after_path)
            {
                continue;
            }
            let before = baseline
                .entries
                .get(before_path)
                .ok_or(Error::InvalidState)?;
            let after = edited_by_path.get(after_path).ok_or(Error::InvalidState)?;
            let moved = parents_differ(&before.components, &after.components);
            let kind = if moved {
                CorrespondenceKind::FileMoved
            } else {
                CorrespondenceKind::FileRenamed
            };
            insert_correspondence(output, before_path.clone(), after_path.clone(), kind)?;
            push_event(
                &mut output.relationship_events,
                entry_event(
                    EventGroup::File,
                    EventClass::File,
                    if moved {
                        EventKind::FileMoved
                    } else {
                        EventKind::FileRenamed
                    },
                    EventDecision::Automatic,
                    StructuralReason::Exact,
                    Some(before.logical_id),
                    Some(logical_entry_id(
                        schedule,
                        after_path,
                        BaselineEntryKind::File,
                    )?),
                    Some(before_path.clone()),
                    Some(after_path.clone()),
                ),
            )?;
        }
        Ok(())
    }

    fn baseline_subtree_commitment(
        baseline: &ReviewBaseline,
        root: &BaselineEntry,
        schedule: &KeySchedule<'_>,
    ) -> Result<Option<[u8; 32]>> {
        let mut output = StreamEncoder::new(
            schedule,
            KeyPurpose::TreeCommit,
            b"safeclone/rt3/token-free-subtree-match-v1",
        )?;
        if !root.own_token_oids.is_empty() {
            return Ok(None);
        }
        encode_subtree_member(&mut output, &[], 1, root.exact_file_match.as_ref())?;
        let subtree_prefix = descendant_prefix(&root.path)?;
        for (path, entry) in baseline.entries.range(subtree_prefix.clone()..) {
            if !path.starts_with(&subtree_prefix) {
                break;
            }
            if !entry.own_token_oids.is_empty() {
                return Ok(None);
            }
            encode_subtree_member(
                &mut output,
                &entry.components[root.components.len()..],
                match entry.kind {
                    BaselineEntryKind::Directory => 1,
                    BaselineEntryKind::File => 2,
                },
                entry.exact_file_match.as_ref(),
            )?;
        }
        Ok(Some(output.finish()))
    }

    fn edited_subtree_commitment(
        edited_by_path: &BTreeMap<Vec<u8>, &EditedEntry>,
        root: &EditedEntry,
        schedule: &KeySchedule<'_>,
    ) -> Result<Option<[u8; 32]>> {
        let mut output = StreamEncoder::new(
            schedule,
            KeyPurpose::TreeCommit,
            b"safeclone/rt3/token-free-subtree-match-v1",
        )?;
        if !edited_entry_safe_for_automatic(root)
            || !root.path_form_range.is_empty()
            || !root.content_form_range.is_empty()
        {
            return Ok(None);
        }
        encode_subtree_member(&mut output, &[], 1, root.exact_file_match.as_ref())?;
        let subtree_prefix = descendant_prefix(&root.path)?;
        for (path, entry) in edited_by_path.range(subtree_prefix.clone()..) {
            if !path.starts_with(&subtree_prefix) {
                break;
            }
            if !edited_entry_safe_for_automatic(entry)
                || !entry.path_form_range.is_empty()
                || !entry.content_form_range.is_empty()
            {
                return Ok(None);
            }
            encode_subtree_member(
                &mut output,
                &entry.components[root.components.len()..],
                match entry.kind {
                    EditedEntryKind::Directory => 1,
                    EditedEntryKind::File => 2,
                    EditedEntryKind::Unsupported => 3,
                },
                entry.exact_file_match.as_ref(),
            )?;
        }
        Ok(Some(output.finish()))
    }

    fn encode_subtree_member(
        output: &mut StreamEncoder,
        relative: &[String],
        kind: u8,
        file_commitment: Option<&[u8; 32]>,
    ) -> Result<()> {
        output.u32(u32::try_from(relative.len()).map_err(|_| Error::BoundExceeded)?);
        for component in relative {
            output.bytes(component.as_bytes())?;
        }
        output.u8(kind);
        match file_commitment {
            Some(commitment) => {
                output.u8(1);
                output.bytes(commitment)?;
            }
            None => output.u8(0),
        }
        Ok(())
    }

    fn descendant_prefix(path: &[u8]) -> Result<Vec<u8>> {
        if path.is_empty() || path.last() == Some(&b'/') {
            return Err(Error::InvalidCanonicalInput);
        }
        let mut output = Vec::new();
        output
            .try_reserve_exact(path.len().checked_add(1).ok_or(Error::BoundExceeded)?)
            .map_err(|_| Error::BoundExceeded)?;
        output.extend_from_slice(path);
        output.push(b'/');
        Ok(output)
    }

    fn baseline_path_has_token(baseline: &ReviewBaseline, components: &[String]) -> bool {
        (1..=components.len()).any(|length| {
            baseline
                .token_oids_by_components
                .contains_key(&components[..length])
        })
    }

    fn edited_path_has_reserved(
        reserved_components: &BTreeSet<Vec<String>>,
        components: &[String],
    ) -> bool {
        (1..=components.len()).any(|length| reserved_components.contains(&components[..length]))
    }

    fn has_unpaired_baseline_directory_ancestor(
        baseline: &ReviewBaseline,
        entry: &BaselineEntry,
        correspondence: &Correspondence,
    ) -> Result<bool> {
        for length in 1..entry.components.len() {
            let path = canonical_path(&entry.components[..length])?;
            if baseline.entries.get(&path).is_some_and(|candidate| {
                candidate.kind == BaselineEntryKind::Directory
                    && !correspondence
                        .baseline_to_edited
                        .contains_key(&candidate.path)
            }) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn has_unpaired_edited_directory_ancestor(
        edited_by_path: &BTreeMap<Vec<u8>, &EditedEntry>,
        entry: &EditedEntry,
        correspondence: &Correspondence,
    ) -> Result<bool> {
        for length in 1..entry.components.len() {
            let path = canonical_path(&entry.components[..length])?;
            if edited_by_path.get(&path).is_some_and(|candidate| {
                candidate.kind == EditedEntryKind::Directory
                    && !correspondence.paired_edited.contains(&candidate.path)
            }) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn edited_entry_safe_for_automatic(entry: &EditedEntry) -> bool {
        !entry.protected_name
            && !entry.hard_link
            && !entry.named_stream
            && !entry.invalid_utf8
            && !entry.new_sensitive_finding
            && match entry.kind {
                EditedEntryKind::File => entry.supported_utf8_text,
                EditedEntryKind::Directory => true,
                EditedEntryKind::Unsupported => false,
            }
    }

    fn parents_differ(before: &[String], after: &[String]) -> bool {
        before.get(..before.len().saturating_sub(1)) != after.get(..after.len().saturating_sub(1))
    }

    #[allow(clippy::too_many_arguments)]
    fn entry_event(
        group: EventGroup,
        class: EventClass,
        kind: EventKind,
        decision: EventDecision,
        reason: StructuralReason,
        before_entry: Option<[u8; 32]>,
        after_entry: Option<[u8; 32]>,
        before_path: Option<Vec<u8>>,
        after_path: Option<Vec<u8>>,
    ) -> CanonicalEvent {
        CanonicalEvent {
            group,
            class,
            kind,
            decision,
            baseline_oid: None,
            expected_category: None,
            observed_category: None,
            before_entry,
            after_entry,
            before_anchor: None,
            after_anchor: None,
            observed_count: 0,
            reason,
            before_path,
            after_path,
            position: 0,
        }
    }

    fn push_event(events: &mut Vec<CanonicalEvent>, event: CanonicalEvent) -> Result<()> {
        if events.len() >= MAX_CANONICAL_EVENTS {
            return Err(Error::BoundExceeded);
        }
        events.try_reserve(1).map_err(|_| Error::BoundExceeded)?;
        events.push(event);
        Ok(())
    }

    struct CoreContext<'a, 'key> {
        attribution: &'a TokenAttribution,
        projection: &'a PathProjection,
        anchors: &'a FileAnchorResults,
        profile: ReviewProfile,
        generation: u64,
        schedule: &'a KeySchedule<'key>,
    }

    fn classify_core(
        baseline: &ReviewBaseline,
        edited: &EditedPass,
        context: CoreContext<'_, '_>,
    ) -> Result<ClassificationAuthority> {
        let CoreContext {
            attribution,
            projection,
            anchors,
            profile,
            generation,
            schedule,
        } = context;
        let mut correspondence = build_correspondence(baseline, edited, projection, schedule)?;
        let forms_by_oid = forms_by_known_oid(&edited.forms, &baseline.derivation.plan.inventory)?;
        let order_mismatch = order_mismatch_oids(baseline, anchors);
        let edited_by_path = edited
            .entries
            .iter()
            .map(|entry| (entry.path.as_slice(), entry))
            .collect::<BTreeMap<_, _>>();
        let mut events = Vec::new();
        let mut token_decisions = BTreeMap::<[u8; 16], EventDecision>::new();

        for (oid, token) in &baseline.tokens {
            let state = attribution.states.get(oid).ok_or(Error::InvalidState)?;
            let attributable = forms_by_oid.get(oid).map(Vec::as_slice).unwrap_or(&[]);
            let (kind, decision, reason, observed, observed_count, after_path) = match state {
                AttributedTokenState::Duplicated => (
                    EventKind::TokenDuplicated,
                    EventDecision::Reject,
                    StructuralReason::GlobalCount,
                    attributable.first().and_then(|form| form.category),
                    u32::try_from(attributable.len()).map_err(|_| Error::BoundExceeded)?,
                    attributable.first().map(|form| form.path.clone()),
                ),
                AttributedTokenState::CategoryMismatch => (
                    EventKind::CategoryMismatch,
                    EventDecision::Reject,
                    StructuralReason::MalformedToken,
                    attributable.first().and_then(|form| form.category),
                    1,
                    attributable.first().map(|form| form.path.clone()),
                ),
                AttributedTokenState::Modified => {
                    let form = attributable.first().ok_or(Error::InvalidState)?;
                    (
                        EventKind::TokenModified,
                        EventDecision::Reject,
                        modified_reason(form),
                        form.category,
                        1,
                        Some(form.path.clone()),
                    )
                }
                AttributedTokenState::Missing => classify_missing_token(
                    *oid,
                    token,
                    baseline,
                    &edited_by_path,
                    &correspondence,
                    projection,
                    anchors,
                )?,
                AttributedTokenState::Authentic => classify_authentic_token(
                    *oid,
                    token,
                    attributable.first().ok_or(Error::InvalidState)?,
                    baseline,
                    &correspondence,
                    projection,
                    anchors,
                    &order_mismatch,
                )?,
            };
            let mut event =
                CanonicalEvent::token(*oid, token.category, observed, kind, decision, reason);
            event.before_entry = baseline
                .entries
                .get(&token.entry_path)
                .map(|entry| entry.logical_id);
            event.after_entry = after_path
                .as_deref()
                .map(|path| logical_id_for_edited_path(schedule, path, &edited_by_path))
                .transpose()?;
            event.before_anchor = Some(token.before_anchor);
            if matches!(
                kind,
                EventKind::PreservedSameAnchor | EventKind::TokenDeleted
            ) {
                event.after_anchor = Some(token.before_anchor);
            }
            event.observed_count = observed_count;
            event.before_path = Some(token.entry_path.clone());
            event.after_path = after_path;
            if token_decisions.insert(*oid, decision).is_some() {
                return Err(Error::InvalidToken);
            }
            push_event(&mut events, event)?;
        }
        if token_decisions.len() != baseline.tokens.len() {
            return Err(Error::InvalidToken);
        }

        append_independent_reserved_events(
            &mut events,
            baseline,
            edited,
            schedule.session_id().as_bytes(),
        )?;
        for event in correspondence.relationship_events.drain(..) {
            push_event(&mut events, event)?;
        }
        append_file_and_tree_events(
            &mut events,
            baseline,
            edited,
            &correspondence,
            &token_decisions,
            profile,
            schedule,
        )?;
        append_original_only_collision_events(
            &mut events,
            baseline,
            edited,
            &correspondence,
            schedule,
        )?;

        let event_set = CanonicalEventSet::finalize(events)?;
        let event_set_commitment = event_set.commitment(schedule)?;
        let report = build_report(profile, generation, edited, &event_set)?;
        Ok(ClassificationAuthority {
            report,
            events: event_set,
            event_set_commitment,
            correspondence,
        })
    }

    #[allow(clippy::type_complexity)]
    fn classify_missing_token(
        oid: [u8; 16],
        token: &BaselineToken,
        baseline: &ReviewBaseline,
        edited_by_path: &BTreeMap<&[u8], &EditedEntry>,
        correspondence: &Correspondence,
        projection: &PathProjection,
        anchors: &FileAnchorResults,
    ) -> Result<(
        EventKind,
        EventDecision,
        StructuralReason,
        Option<TokenCategory>,
        u32,
        Option<Vec<u8>>,
    )> {
        let baseline_entry = baseline
            .entries
            .get(&token.entry_path)
            .ok_or(Error::InvalidState)?;
        let relation = correspondence.baseline_to_edited.get(&token.entry_path);
        if baseline_entry.kind == BaselineEntryKind::File
            && relation.is_none()
            && !edited_by_path.contains_key(token.entry_path.as_slice())
        {
            return Ok((
                EventKind::TokenDeleted,
                EventDecision::ApprovalRequired,
                StructuralReason::ExactDeletionProjection,
                None,
                0,
                None,
            ));
        }
        match token.location {
            BaselineTokenLocation::Path(_) => {
                if projection.deletion_eligible.contains(&oid) {
                    Ok((
                        EventKind::TokenDeleted,
                        EventDecision::ApprovalRequired,
                        StructuralReason::ExactDeletionProjection,
                        None,
                        0,
                        relation.map(|(path, _)| path.clone()),
                    ))
                } else {
                    Ok((
                        EventKind::PathMoved,
                        EventDecision::Reject,
                        StructuralReason::PathProjectionMismatch,
                        None,
                        0,
                        relation.map(|(path, _)| path.clone()),
                    ))
                }
            }
            BaselineTokenLocation::Content => {
                let Some(anchor) = anchors
                    .by_path
                    .get(&token.entry_path)
                    .and_then(|result| result.outcome(&oid))
                else {
                    return Ok((
                        EventKind::ProtectedCoreChanged,
                        EventDecision::Reject,
                        StructuralReason::DeletionProjectionMismatch,
                        None,
                        0,
                        relation.map(|(path, _)| path.clone()),
                    ));
                };
                Ok(anchor_event(
                    anchor,
                    None,
                    relation.map(|(path, _)| path.clone()),
                ))
            }
        }
    }

    #[allow(clippy::too_many_arguments, clippy::type_complexity)]
    fn classify_authentic_token(
        oid: [u8; 16],
        token: &BaselineToken,
        form: &ReservedForm,
        baseline: &ReviewBaseline,
        correspondence: &Correspondence,
        projection: &PathProjection,
        anchors: &FileAnchorResults,
        order_mismatch: &BTreeSet<[u8; 16]>,
    ) -> Result<(
        EventKind,
        EventDecision,
        StructuralReason,
        Option<TokenCategory>,
        u32,
        Option<Vec<u8>>,
    )> {
        let expected_path = correspondence
            .baseline_to_edited
            .get(&token.entry_path)
            .map(|(path, _)| path.as_slice())
            .unwrap_or(token.entry_path.as_slice());
        if form.path != expected_path {
            return Ok((
                match token.location {
                    BaselineTokenLocation::Content => EventKind::MovedToOtherFile,
                    BaselineTokenLocation::Path(_) => EventKind::PathMoved,
                },
                EventDecision::Reject,
                StructuralReason::FileCorrespondence,
                form.category,
                1,
                Some(form.path.clone()),
            ));
        }
        match token.location {
            BaselineTokenLocation::Path(boundary) => {
                let baseline_entry = baseline
                    .entries
                    .get(&token.entry_path)
                    .ok_or(Error::InvalidState)?;
                let removed_before = baseline_entry
                    .path_spans
                    .iter()
                    .filter(|span| {
                        span.start < boundary.start
                            && projection
                                .deletion_eligible
                                .contains(&span.fact.occurrence_id)
                    })
                    .try_fold(0usize, |total, span| {
                        total
                            .checked_add(span.end - span.start)
                            .ok_or(Error::BoundExceeded)
                    })?;
                let expected_start = boundary
                    .start
                    .checked_sub(removed_before)
                    .ok_or(Error::InvalidToken)?;
                let expected_end = expected_start
                    .checked_add(boundary.end - boundary.start)
                    .ok_or(Error::BoundExceeded)?;
                if form.location_kind != ReservedLocationKind::Path
                    || form.component_index != boundary.component_index
                    || usize::try_from(form.position).ok() != Some(expected_start)
                    || usize::try_from(form.end_position).ok() != Some(expected_end)
                {
                    return Ok((
                        EventKind::PathMoved,
                        EventDecision::Reject,
                        StructuralReason::PathProjectionMismatch,
                        form.category,
                        1,
                        Some(form.path.clone()),
                    ));
                }
                Ok((
                    EventKind::PreservedSameAnchor,
                    EventDecision::Automatic,
                    StructuralReason::Exact,
                    form.category,
                    1,
                    Some(form.path.clone()),
                ))
            }
            BaselineTokenLocation::Content => {
                if form.location_kind != ReservedLocationKind::Content {
                    return Ok((
                        EventKind::MovedToOtherFile,
                        EventDecision::Reject,
                        StructuralReason::FileCorrespondence,
                        form.category,
                        1,
                        Some(form.path.clone()),
                    ));
                }
                if order_mismatch.contains(&oid) {
                    return Ok((
                        EventKind::TokenOrderChanged,
                        EventDecision::Reject,
                        StructuralReason::FileLocalOrder,
                        form.category,
                        1,
                        Some(form.path.clone()),
                    ));
                }
                let Some(outcome) = anchors
                    .by_path
                    .get(&token.entry_path)
                    .and_then(|result| result.outcome(&oid))
                else {
                    return Ok((
                        EventKind::ProtectedCoreChanged,
                        EventDecision::Reject,
                        StructuralReason::FileCorrespondence,
                        form.category,
                        1,
                        Some(form.path.clone()),
                    ));
                };
                Ok(anchor_event(
                    outcome,
                    form.category,
                    Some(form.path.clone()),
                ))
            }
        }
    }

    #[allow(clippy::type_complexity)]
    fn anchor_event(
        outcome: EditedAnchorOutcome,
        observed: Option<TokenCategory>,
        after_path: Option<Vec<u8>>,
    ) -> (
        EventKind,
        EventDecision,
        StructuralReason,
        Option<TokenCategory>,
        u32,
        Option<Vec<u8>>,
    ) {
        let (kind, decision, reason) = match outcome {
            EditedAnchorOutcome::Preserved => (
                EventKind::PreservedSameAnchor,
                EventDecision::Automatic,
                StructuralReason::Exact,
            ),
            EditedAnchorOutcome::Deleted => (
                EventKind::TokenDeleted,
                EventDecision::ApprovalRequired,
                StructuralReason::ExactDeletionProjection,
            ),
            EditedAnchorOutcome::ProtectedContextChanged => (
                EventKind::ProtectedContextChanged,
                EventDecision::Reject,
                StructuralReason::ProtectedContext,
            ),
            EditedAnchorOutcome::ProtectedCoreChanged => (
                EventKind::ProtectedCoreChanged,
                EventDecision::Reject,
                StructuralReason::ProtectedCore,
            ),
            EditedAnchorOutcome::AnchorAmbiguous => (
                EventKind::AnchorAmbiguous,
                EventDecision::Reject,
                StructuralReason::EditedEnvelopeNonunique,
            ),
        };
        (
            kind,
            decision,
            reason,
            observed,
            u32::from(observed.is_some()),
            after_path,
        )
    }

    fn modified_reason(form: &ReservedForm) -> StructuralReason {
        if form.state != ReservedFormState::Canonical {
            StructuralReason::MalformedToken
        } else if !form.authentication_valid {
            StructuralReason::InvalidAuthentication
        } else if !form.authenticated_known {
            StructuralReason::ForeignSession
        } else {
            StructuralReason::NoncanonicalToken
        }
    }

    fn order_mismatch_oids(
        baseline: &ReviewBaseline,
        anchors: &FileAnchorResults,
    ) -> BTreeSet<[u8; 16]> {
        let mut output = BTreeSet::new();
        for (path, result) in &anchors.by_path {
            let Some(entry) = baseline.entries.get(path) else {
                continue;
            };
            let expected = entry
                .content_token_facts
                .iter()
                .copied()
                .filter_map(|fact| {
                    (!result.deletion_is_eligible(&fact.occurrence_id))
                        .then_some(fact.occurrence_id)
                })
                .collect::<Vec<_>>();
            if expected != result.edited_oid_order {
                output.extend(expected);
            }
        }
        output
    }

    fn logical_id_for_edited_path(
        schedule: &KeySchedule<'_>,
        path: &[u8],
        edited_by_path: &BTreeMap<&[u8], &EditedEntry>,
    ) -> Result<[u8; 32]> {
        let entry = edited_by_path.get(path).ok_or(Error::InvalidState)?;
        logical_entry_id(
            schedule,
            path,
            match entry.kind {
                EditedEntryKind::Directory => BaselineEntryKind::Directory,
                EditedEntryKind::File | EditedEntryKind::Unsupported => BaselineEntryKind::File,
            },
        )
    }

    fn append_independent_reserved_events(
        events: &mut Vec<CanonicalEvent>,
        baseline: &ReviewBaseline,
        edited: &EditedPass,
        current_sid: &[u8; 16],
    ) -> Result<()> {
        for form in &edited.forms {
            let known_oid = form
                .occurrence_id
                .is_some_and(|oid| baseline.tokens.contains_key(&oid));
            let foreign = form.session_id.is_some_and(|sid| &sid != current_sid);
            if known_oid && !foreign {
                continue;
            }
            let reason = if foreign {
                StructuralReason::ForeignSession
            } else if form.occurrence_id.is_some() {
                StructuralReason::UnknownOid
            } else {
                StructuralReason::MalformedToken
            };
            push_event(
                events,
                CanonicalEvent {
                    group: EventGroup::IndependentReserved,
                    class: EventClass::Token,
                    kind: EventKind::TokenUnknown,
                    decision: EventDecision::Reject,
                    baseline_oid: None,
                    expected_category: None,
                    observed_category: form.category,
                    before_entry: None,
                    after_entry: None,
                    before_anchor: None,
                    after_anchor: None,
                    observed_count: 1,
                    reason,
                    before_path: None,
                    after_path: Some(form.path.clone()),
                    position: form.position,
                },
            )?;
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn append_file_and_tree_events(
        events: &mut Vec<CanonicalEvent>,
        baseline: &ReviewBaseline,
        edited: &EditedPass,
        correspondence: &Correspondence,
        token_decisions: &BTreeMap<[u8; 16], EventDecision>,
        profile: ReviewProfile,
        schedule: &KeySchedule<'_>,
    ) -> Result<()> {
        let edited_by_path = edited
            .entries
            .iter()
            .map(|entry| (entry.path.as_slice(), entry))
            .collect::<BTreeMap<_, _>>();

        for after in &edited.entries {
            append_structural_events(events, after, schedule)?;
        }

        for before in baseline.entries.values() {
            match before.kind {
                BaselineEntryKind::File => {
                    let Some((after_path, relation)) =
                        correspondence.baseline_to_edited.get(&before.path)
                    else {
                        push_event(
                            events,
                            entry_event(
                                EventGroup::File,
                                EventClass::File,
                                EventKind::FileDeleted,
                                EventDecision::ApprovalRequired,
                                StructuralReason::Exact,
                                Some(before.logical_id),
                                None,
                                Some(before.path.clone()),
                                None,
                            ),
                        )?;
                        continue;
                    };
                    let after = edited_by_path
                        .get(after_path.as_slice())
                        .ok_or(Error::InvalidState)?;
                    let changed = match (before.exact_file_match, after.exact_file_match) {
                        (Some(left), Some(right)) => !constant_time_equal(&left, &right),
                        _ => true,
                    };
                    if changed {
                        push_event(
                            events,
                            entry_event(
                                EventGroup::File,
                                EventClass::File,
                                EventKind::FileModified,
                                EventDecision::Automatic,
                                StructuralReason::None,
                                Some(before.logical_id),
                                Some(logical_entry_id(
                                    schedule,
                                    after_path,
                                    BaselineEntryKind::File,
                                )?),
                                Some(before.path.clone()),
                                Some(after_path.clone()),
                            ),
                        )?;
                    }
                    let strict_path_change =
                        *relation == CorrespondenceKind::PathDeletionProjection;
                    if profile == ReviewProfile::StrictTokenFilesV2
                        && (changed || strict_path_change)
                        && baseline_path_has_token(baseline, &before.components)
                        && edited_entry_safe_for_automatic(after)
                        && standard_tokens_for_file_succeed(baseline, before, token_decisions)
                    {
                        push_event(
                            events,
                            entry_event(
                                EventGroup::File,
                                EventClass::File,
                                EventKind::StrictTokenFileModified,
                                EventDecision::ApprovalRequired,
                                StructuralReason::StrictProfile,
                                Some(before.logical_id),
                                Some(logical_entry_id(
                                    schedule,
                                    after_path,
                                    BaselineEntryKind::File,
                                )?),
                                Some(before.path.clone()),
                                Some(after_path.clone()),
                            ),
                        )?;
                    }
                }
                BaselineEntryKind::Directory => {
                    if correspondence.baseline_to_edited.contains_key(&before.path) {
                        continue;
                    }
                    let nonempty = baseline_directory_nonempty(baseline, before)?;
                    push_event(
                        events,
                        entry_event(
                            EventGroup::Directory,
                            EventClass::Directory,
                            EventKind::DirectoryDeleted,
                            if nonempty {
                                EventDecision::Derived
                            } else {
                                EventDecision::Automatic
                            },
                            StructuralReason::Exact,
                            Some(before.logical_id),
                            None,
                            Some(before.path.clone()),
                            None,
                        ),
                    )?;
                }
            }
        }

        for after in &edited.entries {
            if correspondence.paired_edited.contains(&after.path) {
                continue;
            }
            let after_kind = match after.kind {
                EditedEntryKind::Directory => BaselineEntryKind::Directory,
                EditedEntryKind::File | EditedEntryKind::Unsupported => BaselineEntryKind::File,
            };
            let after_id = logical_entry_id(schedule, &after.path, after_kind)?;
            match after.kind {
                EditedEntryKind::Directory if edited_entry_safe_for_automatic(after) => {
                    push_event(
                        events,
                        entry_event(
                            EventGroup::Directory,
                            EventClass::Directory,
                            EventKind::DirectoryAdded,
                            EventDecision::Automatic,
                            StructuralReason::Exact,
                            None,
                            Some(after_id),
                            None,
                            Some(after.path.clone()),
                        ),
                    )?;
                }
                EditedEntryKind::File
                    if edited_entry_safe_for_automatic(after)
                        && after.path_form_range.is_empty()
                        && after.content_form_range.is_empty() =>
                {
                    push_event(
                        events,
                        entry_event(
                            EventGroup::File,
                            EventClass::File,
                            EventKind::NewTextFile,
                            EventDecision::Automatic,
                            StructuralReason::Exact,
                            None,
                            Some(after_id),
                            None,
                            Some(after.path.clone()),
                        ),
                    )?;
                }
                _ => {}
            }
        }
        Ok(())
    }

    fn append_structural_events(
        events: &mut Vec<CanonicalEvent>,
        entry: &EditedEntry,
        schedule: &KeySchedule<'_>,
    ) -> Result<()> {
        validate_retained_entry_observation(entry)?;
        let kind = match entry.kind {
            EditedEntryKind::Directory => BaselineEntryKind::Directory,
            EditedEntryKind::File | EditedEntryKind::Unsupported => BaselineEntryKind::File,
        };
        let after_id = logical_entry_id(schedule, &entry.path, kind)?;
        let mut push = |event_kind, reason| {
            push_event(
                events,
                entry_event(
                    EventGroup::Global,
                    EventClass::Structural,
                    event_kind,
                    EventDecision::Reject,
                    reason,
                    None,
                    Some(after_id),
                    None,
                    Some(entry.path.clone()),
                ),
            )
        };
        if entry.protected_name {
            push(
                EventKind::ProtectedNamespace,
                StructuralReason::ProtectedName,
            )?;
        }
        if entry.kind == EditedEntryKind::Unsupported {
            push(
                EventKind::LinkLikeAddition,
                StructuralReason::UnsupportedEntry,
            )?;
        }
        if entry.hard_link {
            push(EventKind::HardLink, StructuralReason::HardLinkShape)?;
        }
        if entry.named_stream {
            push(
                EventKind::AlternateDataStream,
                StructuralReason::NamedStream,
            )?;
        }
        if entry.invalid_utf8 {
            push(EventKind::InvalidUtf8, StructuralReason::UnsupportedEntry)?;
        } else if entry.kind == EditedEntryKind::File
            && !entry.supported_utf8_text
            && !entry.protected_name
        {
            push(
                EventKind::UnsupportedAddition,
                StructuralReason::UnsupportedEntry,
            )?;
        }
        if entry.new_sensitive_finding {
            push(
                EventKind::NewUntokenizedSensitiveFinding,
                StructuralReason::NewSensitiveFinding,
            )?;
        }
        Ok(())
    }

    fn validate_retained_entry_observation(entry: &EditedEntry) -> Result<()> {
        if entry.directory_file_id64 == 0
            || entry.byte_len > 4 * 1024 * 1024
            || (entry.kind != EditedEntryKind::File && entry.byte_len != 0)
            || (!entry.protected_name
                && entry.kind != EditedEntryKind::Unsupported
                && entry.identity.is_none())
            || (entry.kind == EditedEntryKind::File
                && !entry.protected_name
                && !entry.hard_link
                && !entry.named_stream
                && entry.exact_file_match.is_none())
        {
            Err(Error::InvalidState)
        } else {
            Ok(())
        }
    }

    fn standard_tokens_for_file_succeed(
        baseline: &ReviewBaseline,
        file: &BaselineEntry,
        decisions: &BTreeMap<[u8; 16], EventDecision>,
    ) -> bool {
        (1..=file.components.len()).all(|length| {
            baseline
                .token_oids_by_components
                .get(&file.components[..length])
                .is_none_or(|oids| {
                    oids.iter()
                        .all(|oid| decisions.get(oid) != Some(&EventDecision::Reject))
                })
        })
    }

    fn baseline_directory_nonempty(
        baseline: &ReviewBaseline,
        directory: &BaselineEntry,
    ) -> Result<bool> {
        let prefix = descendant_prefix(&directory.path)?;
        Ok(baseline
            .entries
            .range(prefix.clone()..)
            .next()
            .is_some_and(|(path, _)| path.starts_with(&prefix)))
    }

    fn append_original_only_collision_events(
        events: &mut Vec<CanonicalEvent>,
        baseline: &ReviewBaseline,
        edited: &EditedPass,
        correspondence: &Correspondence,
        schedule: &KeySchedule<'_>,
    ) -> Result<()> {
        for entry in &edited.entries {
            let exact_baseline = correspondence
                .baseline_to_edited
                .get(&entry.path)
                .is_some_and(|(after, kind)| {
                    after == &entry.path && *kind == CorrespondenceKind::Exact
                });
            if exact_baseline {
                continue;
            }
            let collision = crate::roundtrip::observe::namespace_path_has_topology_collision(
                &baseline.original_only_paths,
                &entry.components,
            )?;
            if collision {
                let kind = match entry.kind {
                    EditedEntryKind::Directory => BaselineEntryKind::Directory,
                    EditedEntryKind::File | EditedEntryKind::Unsupported => BaselineEntryKind::File,
                };
                push_event(
                    events,
                    entry_event(
                        EventGroup::Global,
                        EventClass::Structural,
                        EventKind::OmittedPathCollision,
                        EventDecision::Reject,
                        StructuralReason::OriginalOnlyCollision,
                        None,
                        Some(logical_entry_id(schedule, &entry.path, kind)?),
                        None,
                        Some(entry.path.clone()),
                    ),
                )?;
            }
        }
        Ok(())
    }

    fn build_report(
        profile: ReviewProfile,
        generation: u64,
        edited: &EditedPass,
        events: &CanonicalEventSet,
    ) -> Result<ClassificationReport> {
        let mut token_events = 0u32;
        let mut file_events = 0u32;
        let mut directory_events = 0u32;
        let mut structural_events = 0u32;
        let mut primary_token_events = 0u32;
        for event in events.events() {
            let counter = match event.class {
                EventClass::Token => &mut token_events,
                EventClass::File => &mut file_events,
                EventClass::Directory => &mut directory_events,
                EventClass::Structural => &mut structural_events,
            };
            *counter = counter.checked_add(1).ok_or(Error::BoundExceeded)?;
            if event.group == EventGroup::BaselineToken {
                primary_token_events = primary_token_events
                    .checked_add(1)
                    .ok_or(Error::BoundExceeded)?;
            }
        }
        let total_events =
            u32::try_from(events.events().len()).map_err(|_| Error::BoundExceeded)?;
        let decision = if events.rejected() != 0 {
            ClassificationDecision::Reject
        } else if events.approval_required() != 0 {
            ClassificationDecision::ApprovalRequired
        } else {
            ClassificationDecision::AutomaticEligible
        };
        Ok(ClassificationReport {
            profile,
            engine_version: ENGINE_VERSION,
            policy_id: POLICY_ID,
            ruleset_id: crate::roundtrip::ruleset::ruleset_id(),
            token_suite_id: TOKEN_SUITE_ID,
            capsule_generation: generation,
            edited_tree_commitment: edited.summary.edited_tree_commitment,
            total_events,
            primary_token_events,
            token_events,
            file_events,
            directory_events,
            structural_events,
            automatic_events: events.automatic(),
            approval_required_events: events.approval_required(),
            rejected_events: events.rejected(),
            derived_events: events.derived(),
            decision,
            semantic_safety_assessed: false,
        })
    }

    fn build_review_entries(
        baseline: ReviewBaseline,
        edited: &EditedPass,
        correspondence: &Correspondence,
        mut edited_reporting_bytes: BTreeMap<Vec<u8>, Vec<u8>>,
    ) -> Result<Vec<ReviewEntryAuthority>> {
        let mut output = Vec::new();
        output
            .try_reserve_exact(
                baseline
                    .entries
                    .len()
                    .checked_add(edited.entries.len())
                    .ok_or(Error::BoundExceeded)?,
            )
            .map_err(|_| Error::BoundExceeded)?;

        for (_, entry) in baseline.entries {
            let after_path = correspondence
                .baseline_to_edited
                .get(&entry.path)
                .map(|(path, _)| path.clone());
            let after_ai_bytes = after_path
                .as_ref()
                .and_then(|path| edited_reporting_bytes.remove(path));
            let mut content_anchors = Vec::new();
            content_anchors
                .try_reserve_exact(entry.reporting_content_anchors.len())
                .map_err(|_| Error::BoundExceeded)?;
            for anchor in entry.reporting_content_anchors {
                content_anchors.push(ReviewContentAnchorAuthority {
                    occurrence_ids: anchor.occurrence_ids,
                    selected_radius: anchor.selected_radius,
                    final_anchor_commitment: anchor.final_anchor_commitment,
                    first_line: anchor.first_line,
                    end_line_exclusive: anchor.end_line_exclusive,
                });
            }
            let component_index = u32::try_from(
                entry
                    .components
                    .len()
                    .checked_sub(1)
                    .ok_or(Error::InvalidState)?,
            )
            .map_err(|_| Error::BoundExceeded)?;
            let mut path_anchors = Vec::new();
            path_anchors
                .try_reserve_exact(entry.path_spans.len())
                .map_err(|_| Error::BoundExceeded)?;
            for span in &entry.path_spans {
                path_anchors.push(ReviewPathAnchorAuthority {
                    occurrence_id: span.fact.occurrence_id,
                    category: span.fact.category,
                    component_index,
                    token_start: u64::try_from(span.start).map_err(|_| Error::BoundExceeded)?,
                    token_end: u64::try_from(span.end).map_err(|_| Error::BoundExceeded)?,
                    exact_path_anchor_commitment: entry.logical_id,
                });
            }
            output.push(ReviewEntryAuthority {
                kind: match entry.kind {
                    BaselineEntryKind::File => ReviewEntryAuthorityKind::File,
                    BaselineEntryKind::Directory => ReviewEntryAuthorityKind::Directory,
                },
                original_path: Some(entry.original_path.ok_or(Error::InvalidState)?),
                safe_path_before: Some(entry.path),
                safe_path_after: after_path,
                before_ai_safe_bytes: entry.reporting_bytes,
                after_ai_bytes,
                content_anchors,
                path_anchors,
            });
        }

        for entry in &edited.entries {
            if correspondence.paired_edited.contains(&entry.path) {
                continue;
            }
            output.push(ReviewEntryAuthority {
                kind: match entry.kind {
                    EditedEntryKind::Directory => ReviewEntryAuthorityKind::Directory,
                    EditedEntryKind::File | EditedEntryKind::Unsupported => {
                        ReviewEntryAuthorityKind::File
                    }
                },
                original_path: None,
                safe_path_before: None,
                safe_path_after: Some(entry.path.clone()),
                before_ai_safe_bytes: None,
                after_ai_bytes: edited_reporting_bytes.remove(&entry.path),
                content_anchors: Vec::new(),
                path_anchors: Vec::new(),
            });
        }
        if !edited_reporting_bytes.is_empty() {
            return Err(Error::InvalidState);
        }
        output.sort_unstable_by(|left, right| {
            let left_kind = match left.kind {
                ReviewEntryAuthorityKind::File => 1u8,
                ReviewEntryAuthorityKind::Directory => 2,
            };
            let right_kind = match right.kind {
                ReviewEntryAuthorityKind::File => 1u8,
                ReviewEntryAuthorityKind::Directory => 2,
            };
            left_kind.cmp(&right_kind).then_with(|| {
                left.safe_path_before
                    .as_deref()
                    .or(left.safe_path_after.as_deref())
                    .cmp(
                        &right
                            .safe_path_before
                            .as_deref()
                            .or(right.safe_path_after.as_deref()),
                    )
            })
        });
        Ok(output)
    }

    fn build_identity_entries(
        baseline: &ReviewBaseline,
        edited: &EditedPass,
        correspondence: &Correspondence,
    ) -> Result<Vec<ReviewEntryAuthority>> {
        let mut output = Vec::new();
        output
            .try_reserve_exact(
                baseline
                    .entries
                    .len()
                    .checked_add(edited.entries.len())
                    .ok_or(Error::BoundExceeded)?,
            )
            .map_err(|_| Error::BoundExceeded)?;
        for entry in baseline.entries.values() {
            output.push(ReviewEntryAuthority {
                kind: match entry.kind {
                    BaselineEntryKind::File => ReviewEntryAuthorityKind::File,
                    BaselineEntryKind::Directory => ReviewEntryAuthorityKind::Directory,
                },
                original_path: Some(entry.original_path.clone().ok_or(Error::InvalidState)?),
                safe_path_before: Some(entry.path.clone()),
                safe_path_after: correspondence
                    .baseline_to_edited
                    .get(&entry.path)
                    .map(|(path, _)| path.clone()),
                before_ai_safe_bytes: None,
                after_ai_bytes: None,
                content_anchors: Vec::new(),
                path_anchors: Vec::new(),
            });
        }
        for entry in &edited.entries {
            if correspondence.paired_edited.contains(&entry.path) {
                continue;
            }
            output.push(ReviewEntryAuthority {
                kind: match entry.kind {
                    EditedEntryKind::Directory => ReviewEntryAuthorityKind::Directory,
                    EditedEntryKind::File | EditedEntryKind::Unsupported => {
                        ReviewEntryAuthorityKind::File
                    }
                },
                original_path: None,
                safe_path_before: None,
                safe_path_after: Some(entry.path.clone()),
                before_ai_safe_bytes: None,
                after_ai_bytes: None,
                content_anchors: Vec::new(),
                path_anchors: Vec::new(),
            });
        }
        output.sort_unstable_by(|left, right| {
            let left_kind = match left.kind {
                ReviewEntryAuthorityKind::File => 1u8,
                ReviewEntryAuthorityKind::Directory => 2,
            };
            let right_kind = match right.kind {
                ReviewEntryAuthorityKind::File => 1u8,
                ReviewEntryAuthorityKind::Directory => 2,
            };
            left_kind.cmp(&right_kind).then_with(|| {
                left.safe_path_before
                    .as_deref()
                    .or(left.safe_path_after.as_deref())
                    .cmp(
                        &right
                            .safe_path_before
                            .as_deref()
                            .or(right.safe_path_after.as_deref()),
                    )
            })
        });
        Ok(output)
    }

    fn integrated_classify(
        original_path: &Path,
        ai_path: &Path,
        state_path: &Path,
    ) -> Result<ClassificationAuthority> {
        use crate::locality;
        use crate::roundtrip::baseline::{derive, require_same_summary as require_same_original};
        use crate::roundtrip::capsule::{GenerationStore, StoreClassification};
        use crate::roundtrip::observe::{
            qualify_roundtrip_create_volumes, NamespaceScope, QualifiedCreateVolumePaths,
        };

        let preflight =
            locality::preflight_roundtrip_create_paths(original_path, ai_path, state_path)
                .map_err(|_| Error::InvalidState)?;
        let confirmed = locality::open_and_confirm_roundtrip_volumes(preflight)
            .map_err(|_| Error::PersistentVolumeQueryFailed)?;
        let QualifiedCreateVolumePaths {
            original,
            ai_parent,
            ai_leaf,
            state_parent,
            state_leaf,
        } = qualify_roundtrip_create_volumes(confirmed)?;
        let original = original.open_directory(NamespaceScope::Workspace)?;
        let ai_parent = ai_parent.open_directory(NamespaceScope::PathSelection)?;
        let state_parent = state_parent.open_directory(NamespaceScope::PathSelection)?;
        let ai = ai_parent
            .classify_directory_leaf(&ai_leaf, NamespaceScope::Workspace)?
            .map_err(|_| Error::InvalidState)?;
        let ai_identity = ai.identity();
        let state = state_parent
            .classify_directory_leaf(&state_leaf, NamespaceScope::Workspace)?
            .map_err(|_| Error::InvalidState)?;
        let state_identity = state.identity();
        validate_existing_overlap(&original, &ai, &state)?;
        let ai = ai.into_edited_workspace_root()?;
        let store = GenerationStore::from_qualified_root(state.into_private_state_root()?);
        let mut lock = store.acquire_mutation_lock()?;
        let initial = store.read_while_locked(&mut lock)?;
        if initial.classification != StoreClassification::AuthoritativeLive
            || initial.orphan_count != 0
        {
            return Err(match initial.classification {
                StoreClassification::CreateIncomplete => Error::CreateIncomplete,
                StoreClassification::PrivateOrphansPresent => Error::PrivateOrphansPresent,
                _ => Error::InvalidState,
            });
        }
        let live = initial.live_head().ok_or(Error::InvalidState)?;
        let capsule = live.capsule();
        capsule.validate_capsule_state()?;
        if !capsule.review_profile.is_current()
            || capsule.ruleset_id != crate::roundtrip::ruleset::ruleset_id()
            || capsule.orphan_count_at_commit != 0
            || capsule.semantic_safety_assessed
        {
            return Err(Error::InvalidState);
        }
        let expected_capsule = capsule.clone();
        let expected_tag = *live.tag();
        let schedule = live.key_schedule();
        let profile = capsule.review_profile;
        let generation = capsule.generation;

        let derivation = derive_two_prepublication_passes(&original, &schedule, profile)
            .map_err(|_| Error::OriginalBaselineMismatch)?;
        if !constant_time_equal(
            &derivation.summary.original_tree_commitment,
            &capsule.original_tree_commitment,
        ) || derivation.summary.counts != capsule.baseline_counts
        {
            return Err(Error::OriginalBaselineMismatch);
        }
        let baseline =
            build_review_baseline(&original, derivation, &schedule, profile, false, false)?;
        let (edited, attribution, projection, anchors, reporting_bytes) =
            observe_edited_stably(&original, &ai, &baseline, &schedule, profile, false)?;
        if !reporting_bytes.is_empty() {
            return Err(Error::InvalidState);
        }
        let final_original = derive(&original, &schedule, profile, false)
            .map_err(|_| Error::OriginalBaselineMismatch)?;
        require_same_original(&baseline.derivation.summary, &final_original.summary)
            .map_err(|_| Error::OriginalBaselineMismatch)?;
        let authority = classify_core(
            &baseline,
            &edited,
            CoreContext {
                attribution: &attribution,
                projection: &projection,
                anchors: &anchors,
                profile,
                generation,
                schedule: &schedule,
            },
        )?;

        let final_state = store.read_while_locked(&mut lock)?;
        let final_live = final_state.live_head().ok_or(Error::InvalidState)?;
        if final_state.classification != StoreClassification::AuthoritativeLive
            || final_state.orphan_count != 0
            || final_live.capsule() != &expected_capsule
            || !constant_time_equal(final_live.tag(), &expected_tag)
        {
            return Err(Error::InvalidState);
        }
        verify_selected_root(&ai_parent, &ai_leaf, NamespaceScope::Workspace, ai_identity)?;
        verify_selected_root(
            &state_parent,
            &state_leaf,
            NamespaceScope::Workspace,
            state_identity,
        )?;
        lock.release()?;
        Ok(authority)
    }

    pub(super) fn prepare_review_authority(
        original_path: &Path,
        ai_path: &Path,
        state_path: &Path,
    ) -> Result<PreparedReviewAuthority> {
        prepare_authority(original_path, ai_path, state_path, PreparationMode::Review)
    }

    pub(super) fn prepare_approval_authority(
        original_path: &Path,
        ai_path: &Path,
        state_path: &Path,
    ) -> Result<PreparedReviewAuthority> {
        prepare_authority(
            original_path,
            ai_path,
            state_path,
            PreparationMode::Approval,
        )
    }

    pub(super) fn prepare_reconstruction_authority(
        original_path: &Path,
        ai_path: &Path,
        state_path: &Path,
    ) -> Result<PreparedReviewAuthority> {
        prepare_authority(
            original_path,
            ai_path,
            state_path,
            PreparationMode::Reconstruction,
        )
    }

    pub(super) fn prepare_apply_authority(
        original_path: &Path,
        ai_path: &Path,
        state_path: &Path,
        candidate_path: &Path,
    ) -> Result<PreparedApplyAuthority> {
        use crate::locality;
        use crate::roundtrip::observe::{
            qualify_roundtrip_apply_volumes, QualifiedApplyVolumePaths,
        };

        let preflight = locality::preflight_roundtrip_apply_paths(
            original_path,
            ai_path,
            state_path,
            candidate_path,
        )
        .map_err(|_| Error::InvalidState)?;
        let confirmed = locality::open_and_confirm_roundtrip_apply_volumes(preflight)
            .map_err(|_| Error::PersistentVolumeQueryFailed)?;
        let QualifiedApplyVolumePaths {
            original,
            ai_parent,
            ai_leaf,
            state_parent,
            state_leaf,
            candidate_parent,
            candidate_leaf,
        } = qualify_roundtrip_apply_volumes(confirmed)?;
        let (review, candidate_parent, candidate) = prepare_authority_from_paths(
            AuthorityPathInputs {
                original,
                ai_parent,
                ai_leaf,
                state_parent,
                state_leaf,
                candidate: Some((candidate_parent, candidate_leaf.clone())),
            },
            PreparationMode::Apply,
        )?;
        Ok(PreparedApplyAuthority {
            review,
            candidate_parent: candidate_parent.ok_or(Error::InvalidState)?,
            candidate_leaf,
            candidate: candidate.ok_or(Error::InvalidState)?,
        })
    }

    #[derive(Clone, Copy, Eq, PartialEq)]
    enum PreparationMode {
        Review,
        Approval,
        Reconstruction,
        Apply,
    }

    struct AuthorityPathInputs {
        original: crate::roundtrip::observe::RetainedVolumePath,
        ai_parent: crate::roundtrip::observe::RetainedVolumePath,
        ai_leaf: std::ffi::OsString,
        state_parent: crate::roundtrip::observe::RetainedVolumePath,
        state_leaf: std::ffi::OsString,
        candidate: Option<(
            crate::roundtrip::observe::RetainedVolumePath,
            std::ffi::OsString,
        )>,
    }

    fn prepare_authority(
        original_path: &Path,
        ai_path: &Path,
        state_path: &Path,
        mode: PreparationMode,
    ) -> Result<PreparedReviewAuthority> {
        use crate::locality;
        use crate::roundtrip::observe::{
            qualify_roundtrip_create_volumes, QualifiedCreateVolumePaths,
        };

        let preflight =
            locality::preflight_roundtrip_create_paths(original_path, ai_path, state_path)
                .map_err(|_| Error::InvalidState)?;
        let confirmed = locality::open_and_confirm_roundtrip_volumes(preflight)
            .map_err(|_| Error::PersistentVolumeQueryFailed)?;
        let QualifiedCreateVolumePaths {
            original,
            ai_parent,
            ai_leaf,
            state_parent,
            state_leaf,
        } = qualify_roundtrip_create_volumes(confirmed)?;
        let (authority, candidate_parent, candidate) = prepare_authority_from_paths(
            AuthorityPathInputs {
                original,
                ai_parent,
                ai_leaf,
                state_parent,
                state_leaf,
                candidate: None,
            },
            mode,
        )?;
        if candidate_parent.is_some() || candidate.is_some() {
            return Err(Error::InvalidState);
        }
        Ok(authority)
    }

    fn prepare_authority_from_paths(
        paths: AuthorityPathInputs,
        mode: PreparationMode,
    ) -> Result<(
        PreparedReviewAuthority,
        Option<crate::roundtrip::observe::QualifiedDirectory>,
        Option<CandidateSelection>,
    )> {
        use crate::roundtrip::baseline::{derive, require_same_summary as require_same_original};
        use crate::roundtrip::capsule::{GenerationStore, StoreClassification};

        let AuthorityPathInputs {
            original,
            ai_parent,
            ai_leaf,
            state_parent,
            state_leaf,
            candidate,
        } = paths;
        let original = original.open_directory(NamespaceScope::Workspace)?;
        let ai_parent = ai_parent.open_directory(NamespaceScope::PathSelection)?;
        let state_parent = state_parent.open_directory(NamespaceScope::PathSelection)?;
        let candidate_parent_and_leaf = candidate
            .map(|(parent, leaf)| Ok((parent.open_directory(NamespaceScope::PathSelection)?, leaf)))
            .transpose()?;
        let ai = ai_parent
            .classify_directory_leaf(&ai_leaf, NamespaceScope::Workspace)?
            .map_err(|_| Error::InvalidState)?;
        let ai_identity = ai.identity();
        let state = state_parent
            .classify_directory_leaf(&state_leaf, NamespaceScope::Workspace)?
            .map_err(|_| Error::InvalidState)?;
        let state_identity = state.identity();
        validate_existing_overlap(&original, &ai, &state)?;
        let candidate_leaf_for_recheck = candidate_parent_and_leaf
            .as_ref()
            .map(|(_, leaf)| leaf.clone());
        let (candidate_parent, candidate_selection) = match candidate_parent_and_leaf {
            Some((parent, leaf)) => {
                validate_candidate_parent_overlap(&original, &ai, &state, &parent)?;
                let selected =
                    match parent.classify_directory_leaf(&leaf, NamespaceScope::Workspace)? {
                        Ok(existing) => {
                            validate_existing_candidate_overlap(&original, &ai, &state, &existing)?;
                            CandidateSelection::Existing(existing.into_candidate_root()?)
                        }
                        Err(absent) => CandidateSelection::Absent(absent),
                    };
                (Some(parent), Some(selected))
            }
            None => (None, None),
        };
        let ai = ai.into_edited_workspace_root()?;
        let store = GenerationStore::from_qualified_root(state.into_private_state_root()?);
        let mut lock = store.acquire_mutation_lock()?;
        let initial = store.read_while_locked(&mut lock)?;
        let allowed_apply_orphan = mode == PreparationMode::Apply
            && initial.classification == StoreClassification::PrivateOrphansPresent
            && initial.orphan_count == 1;
        if (initial.classification != StoreClassification::AuthoritativeLive
            || initial.orphan_count != 0)
            && !allowed_apply_orphan
        {
            return Err(match initial.classification {
                StoreClassification::CreateIncomplete => Error::CreateIncomplete,
                StoreClassification::PrivateOrphansPresent => Error::PrivateOrphansPresent,
                _ => Error::InvalidState,
            });
        }
        let live = initial.live_head().ok_or(Error::InvalidState)?;
        let capsule = live.capsule();
        capsule.validate_capsule_state()?;
        if !capsule.review_profile.is_current()
            || capsule.ruleset_id != crate::roundtrip::ruleset::ruleset_id()
            || capsule.orphan_count_at_commit != 0
            || capsule.semantic_safety_assessed
        {
            return Err(Error::InvalidState);
        }
        let expected_capsule = capsule.clone();
        let expected_tag = *live.tag();
        let schedule = live.key_schedule();
        let profile = capsule.review_profile;
        let generation = capsule.generation;
        if allowed_apply_orphan
            && capsule.session_state != crate::roundtrip::schema::SessionState::ApplyIncomplete
        {
            return Err(Error::PrivateOrphansPresent);
        }

        // Approval authenticates the existing set immediately after the live
        // capsule, before any fresh Original or edited-workspace observation.
        // ACTIVE_UNREVIEWED has no authenticated review-bound set to approve.
        if matches!(
            mode,
            PreparationMode::Approval | PreparationMode::Reconstruction | PreparationMode::Apply
        ) {
            if capsule.current_review.is_none() {
                return Err(Error::InvalidState);
            }
            crate::roundtrip::approval::verify_approval_set_tag(capsule, &schedule)?;
        }
        if mode == PreparationMode::Reconstruction
            && capsule.session_state != crate::roundtrip::schema::SessionState::ReadyToApply
        {
            return Err(Error::InvalidState);
        }
        if mode == PreparationMode::Apply
            && !matches!(
                capsule.session_state,
                crate::roundtrip::schema::SessionState::ReadyToApply
                    | crate::roundtrip::schema::SessionState::ApplyArmed
                    | crate::roundtrip::schema::SessionState::ApplyIncomplete
                    | crate::roundtrip::schema::SessionState::AppliedComplete
            )
        {
            return Err(Error::InvalidState);
        }

        let derivation = derive_two_prepublication_passes(&original, &schedule, profile)
            .map_err(|_| Error::OriginalBaselineMismatch)?;
        if !constant_time_equal(
            &derivation.summary.original_tree_commitment,
            &capsule.original_tree_commitment,
        ) || derivation.summary.counts != capsule.baseline_counts
        {
            return Err(Error::OriginalBaselineMismatch);
        }
        let baseline = build_review_baseline(
            &original,
            derivation,
            &schedule,
            profile,
            mode == PreparationMode::Review,
            true,
        )?;
        let original_tree_commitment = baseline.derivation.summary.original_tree_commitment;
        let (edited, attribution, projection, anchors, reporting_bytes) = observe_edited_stably(
            &original,
            &ai,
            &baseline,
            &schedule,
            profile,
            mode == PreparationMode::Review,
        )?;
        let final_original = derive(&original, &schedule, profile, false)
            .map_err(|_| Error::OriginalBaselineMismatch)?;
        require_same_original(&baseline.derivation.summary, &final_original.summary)
            .map_err(|_| Error::OriginalBaselineMismatch)?;
        let authority = classify_core(
            &baseline,
            &edited,
            CoreContext {
                attribution: &attribution,
                projection: &projection,
                anchors: &anchors,
                profile,
                generation,
                schedule: &schedule,
            },
        )?;

        let ClassificationAuthority {
            report,
            events,
            event_set_commitment,
            correspondence,
        } = authority;
        // The accepted second edited pass is both classification authority and
        // entry-identity authority. Reconstruction retains those exact bytes
        // separately while identity derivation remains byte-independent.
        let (entries, reconstruction) = if matches!(
            mode,
            PreparationMode::Reconstruction | PreparationMode::Apply
        ) {
            if !reporting_bytes.is_empty() {
                return Err(Error::InvalidState);
            }
            let entries = build_identity_entries(&baseline, &edited, &correspondence)?;
            (
                entries,
                Some(ReconstructionInputs {
                    original,
                    ai,
                    profile,
                    baseline,
                    edited,
                    correspondence,
                    anchors,
                }),
            )
        } else {
            (
                build_review_entries(baseline, &edited, &correspondence, reporting_bytes)?,
                None,
            )
        };
        let observed_files = u32::try_from(
            entries
                .iter()
                .filter(|entry| entry.kind == ReviewEntryAuthorityKind::File)
                .count(),
        )
        .map_err(|_| Error::BoundExceeded)?;
        let observed_directories = u32::try_from(
            entries
                .iter()
                .filter(|entry| entry.kind == ReviewEntryAuthorityKind::Directory)
                .count(),
        )
        .map_err(|_| Error::BoundExceeded)?;

        let final_state = store.read_while_locked(&mut lock)?;
        let final_live = final_state.live_head().ok_or(Error::InvalidState)?;
        if final_state.classification != initial.classification
            || final_state.orphan_count != initial.orphan_count
            || final_live.capsule() != &expected_capsule
            || !constant_time_equal(final_live.tag(), &expected_tag)
        {
            return Err(Error::InvalidState);
        }
        verify_selected_root(&ai_parent, &ai_leaf, NamespaceScope::Workspace, ai_identity)?;
        verify_selected_root(
            &state_parent,
            &state_leaf,
            NamespaceScope::Workspace,
            state_identity,
        )?;
        if let (Some(parent), Some(selection), Some(leaf)) = (
            candidate_parent.as_ref(),
            candidate_selection.as_ref(),
            candidate_leaf_for_recheck.as_deref(),
        ) {
            parent.requery_policy()?;
            match selection {
                CandidateSelection::Absent(expected) => {
                    let current = parent.validate_absent_leaf(leaf)?;
                    if current.utf16() != expected.utf16() {
                        return Err(Error::WorkspaceUnstable);
                    }
                }
                CandidateSelection::Existing(expected) => {
                    let current = parent
                        .classify_directory_leaf(leaf, NamespaceScope::Workspace)?
                        .map_err(|_| Error::WorkspaceUnstable)?;
                    if current.identity() != expected.identity() {
                        return Err(Error::WorkspaceUnstable);
                    }
                    expected.requery_policy()?;
                }
            }
        }
        let owner = initial.into_live_head().ok_or(Error::InvalidState)?;
        Ok((
            PreparedReviewAuthority {
                report,
                events,
                event_set_commitment,
                original_tree_commitment,
                observed_files,
                observed_directories,
                entries,
                store,
                lock,
                owner,
                ai_parent,
                ai_leaf,
                ai_identity,
                state_parent,
                state_leaf,
                state_identity,
                reconstruction,
            },
            candidate_parent,
            candidate_selection,
        ))
    }

    fn verify_selected_root(
        parent: &crate::roundtrip::observe::QualifiedDirectory,
        leaf: &std::ffi::OsStr,
        scope: crate::roundtrip::observe::NamespaceScope,
        expected: crate::roundtrip::observe::FileIdentity,
    ) -> Result<()> {
        let current = parent
            .classify_directory_leaf(leaf, scope)?
            .map_err(|_| Error::WorkspaceUnstable)?;
        if current.identity() != expected {
            Err(Error::WorkspaceUnstable)
        } else {
            Ok(())
        }
    }

    fn validate_existing_overlap(
        original: &crate::roundtrip::observe::QualifiedDirectory,
        ai: &crate::roundtrip::observe::QualifiedDirectory,
        state: &crate::roundtrip::observe::QualifiedDirectory,
    ) -> Result<()> {
        for root in [ai, state] {
            if root.identity() == original.identity()
                || root.ancestor_identities().contains(&original.identity())
                || original.ancestor_identities().contains(&root.identity())
            {
                return Err(Error::UnsafeWorkspaceOverlap);
            }
        }
        if ai.identity() == state.identity()
            || ai.ancestor_identities().contains(&state.identity())
            || state.ancestor_identities().contains(&ai.identity())
        {
            return Err(Error::UnsafeWorkspaceOverlap);
        }
        Ok(())
    }

    fn validate_candidate_parent_overlap(
        original: &crate::roundtrip::observe::QualifiedDirectory,
        ai: &crate::roundtrip::observe::QualifiedDirectory,
        state: &crate::roundtrip::observe::QualifiedDirectory,
        candidate_parent: &crate::roundtrip::observe::QualifiedDirectory,
    ) -> Result<()> {
        if [original, ai, state].iter().any(|root| {
            candidate_parent.identity() == root.identity()
                || candidate_parent
                    .ancestor_identities()
                    .contains(&root.identity())
        }) {
            Err(Error::UnsafeWorkspaceOverlap)
        } else {
            Ok(())
        }
    }

    fn validate_existing_candidate_overlap(
        original: &crate::roundtrip::observe::QualifiedDirectory,
        ai: &crate::roundtrip::observe::QualifiedDirectory,
        state: &crate::roundtrip::observe::QualifiedDirectory,
        candidate: &crate::roundtrip::observe::QualifiedDirectory,
    ) -> Result<()> {
        if [original, ai, state].iter().any(|root| {
            candidate.identity() == root.identity()
                || candidate.ancestor_identities().contains(&root.identity())
                || root.ancestor_identities().contains(&candidate.identity())
        }) {
            Err(Error::UnsafeWorkspaceOverlap)
        } else {
            Ok(())
        }
    }

    #[cfg(test)]
    mod tests {
        use std::fs;
        use std::sync::atomic::{AtomicU64, Ordering};

        use super::*;
        use crate::roundtrip::create::create_session;

        static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

        struct Fixture(std::path::PathBuf);

        impl Fixture {
            fn create() -> (
                Self,
                std::path::PathBuf,
                std::path::PathBuf,
                std::path::PathBuf,
            ) {
                Self::from_setup(|original| {
                    fs::write(
                        original.join("main.rs"),
                        b"before\ncontact=fixture.user@example.invalid\nafter\n",
                    )
                    .expect("write stability source");
                })
            }

            fn from_setup(
                setup: impl FnOnce(&std::path::Path),
            ) -> (
                Self,
                std::path::PathBuf,
                std::path::PathBuf,
                std::path::PathBuf,
            ) {
                let serial = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
                let root = std::env::temp_dir().join(format!(
                    "safeclone-classification-stability-{}-{serial}",
                    std::process::id()
                ));
                let original = root.join("OriginalWorkspace");
                let ai = root.join("AiWorkspaceLongFixtureName");
                let state = root.join("PrivateSessionDirectoryLongFixtureName");
                fs::create_dir_all(&original).expect("create stability Original");
                setup(&original);
                create_session(&original, &ai, &state, ReviewProfile::StandardV2)
                    .expect("create stability session");
                (Self(root), original, ai, state)
            }
        }

        impl Drop for Fixture {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }

        #[test]
        fn edited_namespace_and_root_mutations_between_passes_fail_closed() {
            for mutation in 0..5 {
                let (_fixture, original, ai, state) = Fixture::create();
                let target = ai.join("main.rs");
                let root = ai.clone();
                let hook = install_test_hook(move |checkpoint| {
                    assert_eq!(checkpoint, TestCheckpoint::AfterEditedPassOne);
                    match mutation {
                        0 => fs::write(&target, b"mutated between passes\n")
                            .map_err(|_| Error::FilesystemFailure)?,
                        1 => fs::rename(&target, target.with_file_name("renamed.rs"))
                            .map_err(|_| Error::FilesystemFailure)?,
                        2 => {
                            let bytes = fs::read(&target).map_err(|_| Error::FilesystemFailure)?;
                            fs::rename(&target, target.with_file_name("old-main.rs"))
                                .map_err(|_| Error::FilesystemFailure)?;
                            fs::write(&target, bytes).map_err(|_| Error::FilesystemFailure)?;
                        }
                        3 => {
                            let moved = root.with_file_name("AiWorkspaceMovedDuringClassification");
                            fs::rename(&root, &moved).map_err(|_| Error::FilesystemFailure)?;
                            fs::create_dir(&root).map_err(|_| Error::FilesystemFailure)?;
                        }
                        4 => fs::write(root.join("namespace-added.rs"), b"added between passes\n")
                            .map_err(|_| Error::FilesystemFailure)?,
                        _ => unreachable!(),
                    }
                    Ok(())
                });
                match integrated_classify(&original, &ai, &state) {
                    Err(Error::WorkspaceUnstable) => {}
                    Err(error) => panic!("mutation {mutation} returned {error:?}"),
                    Ok(_) => panic!("mutation {mutation} was accepted"),
                }
                drop(hook);
            }
        }

        #[test]
        fn file_read_and_short_name_mode_mutations_fail_closed() {
            let (_fixture, original, ai, state) = Fixture::create();
            let target = ai.join("main.rs");
            let hook = crate::roundtrip::edited::install_after_file_read_test_hook(move || {
                fs::write(&target, b"mutated while retained handle is open\n")
                    .map_err(|_| Error::FilesystemFailure)
            });
            assert!(matches!(
                integrated_classify(&original, &ai, &state),
                Err(Error::WorkspaceUnstable)
            ));
            drop(hook);

            let (_fixture, original, ai, state) = Fixture::create();
            let hook = crate::roundtrip::edited::install_final_short_name_mode_toggle_test_hook();
            assert!(matches!(
                integrated_classify(&original, &ai, &state),
                Err(Error::WorkspaceUnstable)
            ));
            drop(hook);
        }

        #[test]
        fn edited_identity_is_not_original_identity_and_event_replay_is_exact() {
            let (_fixture, original, ai, state) = Fixture::create();
            let original_file =
                fs::File::open(original.join("main.rs")).expect("open Original identity fixture");
            let edited_file = fs::File::open(ai.join("main.rs")).expect("open AI identity fixture");
            assert_ne!(
                crate::roundtrip::observe::file_identity(&original_file)
                    .expect("Original physical identity"),
                crate::roundtrip::observe::file_identity(&edited_file)
                    .expect("AI physical identity"),
                "separately created Original and AiWorkspace files have distinct FileIds"
            );

            let first = integrated_classify(&original, &ai, &state)
                .expect("first exact classification authority");
            let second = integrated_classify(&original, &ai, &state)
                .expect("second exact classification authority");
            assert_eq!(first.report, second.report);
            assert!(constant_time_equal(
                &first.event_set_commitment,
                &second.event_set_commitment
            ));
            assert_eq!(first.events.events().len(), second.events.events().len());
        }

        fn candidate_index_with_paths(
            commitment: [u8; 32],
            label: u8,
            count: usize,
        ) -> CommitmentCandidateIndex {
            let mut index = CommitmentCandidateIndex::default();
            for ordinal in 0..count {
                index
                    .insert(
                        commitment,
                        vec![
                            label,
                            u8::try_from(ordinal).expect("synthetic ordinal is one byte"),
                        ],
                    )
                    .expect("insert bounded synthetic candidate");
            }
            index
        }

        #[test]
        fn file_and_subtree_indexes_use_full_width_confirmation_and_confirmed_cardinality() {
            for (authority_kind, commitment) in [("file", [0x4a; 32]), ("subtree", [0x75; 32])] {
                let mut same_bucket_mismatch = commitment;
                same_bucket_mismatch[COMMITMENT_INDEX_PREFIX_BYTES] ^= 1;
                assert_eq!(
                    commitment_index_prefix(&commitment),
                    commitment_index_prefix(&same_bucket_mismatch),
                    "{authority_kind} mismatch must exercise the same coarse index bucket"
                );
                assert!(!constant_time_equal(&commitment, &same_bucket_mismatch));

                let one_before = candidate_index_with_paths(commitment, b'b', 1);
                let false_positive_bucket =
                    candidate_index_with_paths(same_bucket_mismatch, b'x', 1);
                assert!(
                    unique_constant_time_confirmed_pair(
                        &one_before,
                        &false_positive_bucket,
                        &commitment,
                    )
                    .expect("reject same-bucket full-width mismatch")
                    .is_none(),
                    "{authority_kind} mismatch must not authorize correspondence"
                );
            }

            let commitment = [0x4a; 32];
            let one_before = candidate_index_with_paths(commitment, b'b', 1);
            let one_after = candidate_index_with_paths(commitment, b'a', 1);
            let exact = unique_constant_time_confirmed_pair(&one_before, &one_after, &commitment)
                .expect("confirm exact pair")
                .expect("one exact pair");
            assert_eq!(exact.0.as_slice(), &[b'b', 0]);
            assert_eq!(exact.1.as_slice(), &[b'a', 0]);

            for (before_count, after_count) in [(2, 1), (1, 2), (2, 2)] {
                let before = candidate_index_with_paths(commitment, b'b', before_count);
                let after = candidate_index_with_paths(commitment, b'a', after_count);
                assert!(
                    unique_constant_time_confirmed_pair(&before, &after, &commitment)
                        .expect("evaluate ambiguous confirmed cardinality")
                        .is_none()
                );
            }
        }

        fn assert_relationship_event(
            authority: &ClassificationAuthority,
            kind: EventKind,
            before: &[u8],
            after: &[u8],
        ) {
            assert!(authority.events.events().iter().any(|event| {
                event.kind == kind
                    && event.decision == EventDecision::Automatic
                    && event.reason == StructuralReason::Exact
                    && event.before_path.as_deref() == Some(before)
                    && event.after_path.as_deref() == Some(after)
            }));
        }

        #[test]
        fn token_free_file_correspondence_preserves_kinds_and_ambiguity() {
            {
                let (_fixture, original, ai, state) = Fixture::from_setup(|original| {
                    fs::write(original.join("source.txt"), b"unique file bytes\n")
                        .expect("write rename source");
                });
                fs::rename(ai.join("source.txt"), ai.join("renamed.txt"))
                    .expect("rename unique file");
                let authority = integrated_classify(&original, &ai, &state)
                    .expect("classify unique file rename");
                assert_eq!(
                    authority
                        .correspondence
                        .baseline_to_edited
                        .get(b"source.txt".as_slice()),
                    Some(&(b"renamed.txt".to_vec(), CorrespondenceKind::FileRenamed))
                );
                assert_relationship_event(
                    &authority,
                    EventKind::FileRenamed,
                    b"source.txt",
                    b"renamed.txt",
                );
            }

            {
                let (_fixture, original, ai, state) = Fixture::from_setup(|original| {
                    fs::create_dir_all(original.join("left")).expect("create file source parent");
                    fs::create_dir_all(original.join("right"))
                        .expect("create file destination parent");
                    fs::write(original.join("left").join("source.txt"), b"move bytes\n")
                        .expect("write move source");
                });
                fs::rename(
                    ai.join("left").join("source.txt"),
                    ai.join("right").join("source.txt"),
                )
                .expect("move unique file");
                let authority =
                    integrated_classify(&original, &ai, &state).expect("classify unique file move");
                assert_eq!(
                    authority
                        .correspondence
                        .baseline_to_edited
                        .get(b"left/source.txt".as_slice()),
                    Some(&(b"right/source.txt".to_vec(), CorrespondenceKind::FileMoved,))
                );
                assert_relationship_event(
                    &authority,
                    EventKind::FileMoved,
                    b"left/source.txt",
                    b"right/source.txt",
                );
            }

            {
                let (_fixture, original, ai, state) = Fixture::from_setup(|original| {
                    fs::write(original.join("source.txt"), b"before bytes\n")
                        .expect("write mismatch source");
                });
                fs::rename(ai.join("source.txt"), ai.join("renamed.txt"))
                    .expect("rename mismatch source");
                fs::write(ai.join("renamed.txt"), b"after bytes\n").expect("change renamed file");
                let authority =
                    integrated_classify(&original, &ai, &state).expect("classify nonmatching file");
                assert!(!authority
                    .correspondence
                    .baseline_to_edited
                    .contains_key(b"source.txt".as_slice()));
                assert!(!authority.events.events().iter().any(|event| matches!(
                    event.kind,
                    EventKind::FileRenamed | EventKind::FileMoved
                )));
            }

            for (baseline_count, edited_count) in [(2usize, 1usize), (1, 2), (2, 2)] {
                let (_fixture, original, ai, state) = Fixture::from_setup(|original| {
                    for ordinal in 0..baseline_count {
                        fs::write(
                            original.join(format!("source-{ordinal}.txt")),
                            b"duplicate file bytes\n",
                        )
                        .expect("write duplicate source file");
                    }
                });
                for ordinal in 0..baseline_count.min(edited_count) {
                    fs::rename(
                        ai.join(format!("source-{ordinal}.txt")),
                        ai.join(format!("edited-{ordinal}.txt")),
                    )
                    .expect("rename duplicate source file");
                }
                if baseline_count > edited_count {
                    for ordinal in edited_count..baseline_count {
                        fs::remove_file(ai.join(format!("source-{ordinal}.txt")))
                            .expect("remove extra edited-side file");
                    }
                } else if edited_count > baseline_count {
                    for ordinal in baseline_count..edited_count {
                        fs::copy(
                            ai.join("edited-0.txt"),
                            ai.join(format!("edited-{ordinal}.txt")),
                        )
                        .expect("add duplicate edited-side file");
                    }
                }
                let authority = integrated_classify(&original, &ai, &state)
                    .expect("classify duplicate file ambiguity");
                assert!(!authority.events.events().iter().any(|event| matches!(
                    event.kind,
                    EventKind::FileRenamed | EventKind::FileMoved
                )));
                for ordinal in 0..baseline_count {
                    assert!(!authority
                        .correspondence
                        .baseline_to_edited
                        .contains_key(format!("source-{ordinal}.txt").as_bytes()));
                }
            }

            {
                let (_fixture, original, ai, state) = Fixture::from_setup(|original| {
                    fs::write(original.join("first.txt"), b"same exact bytes\n")
                        .expect("write first exact source");
                    fs::write(original.join("second.txt"), b"same exact bytes\n")
                        .expect("write second exact source");
                });
                fs::rename(ai.join("first.txt"), ai.join("renamed-first.txt"))
                    .expect("rename unpaired twin");
                let authority = integrated_classify(&original, &ai, &state)
                    .expect("classify with exact-paired twin excluded");
                assert_eq!(
                    authority
                        .correspondence
                        .baseline_to_edited
                        .get(b"first.txt".as_slice()),
                    Some(&(
                        b"renamed-first.txt".to_vec(),
                        CorrespondenceKind::FileRenamed,
                    ))
                );
                assert_eq!(
                    authority
                        .correspondence
                        .baseline_to_edited
                        .get(b"second.txt".as_slice()),
                    Some(&(b"second.txt".to_vec(), CorrespondenceKind::Exact))
                );
            }
        }

        #[test]
        fn token_free_directory_correspondence_preserves_kinds_and_ambiguity() {
            {
                let (_fixture, original, ai, state) = Fixture::from_setup(|original| {
                    fs::create_dir_all(original.join("source")).expect("create rename subtree");
                    fs::write(
                        original.join("source").join("child.txt"),
                        b"subtree bytes\n",
                    )
                    .expect("write rename subtree child");
                });
                fs::rename(ai.join("source"), ai.join("renamed")).expect("rename unique subtree");
                let authority = integrated_classify(&original, &ai, &state)
                    .expect("classify unique subtree rename");
                assert_eq!(
                    authority
                        .correspondence
                        .baseline_to_edited
                        .get(b"source".as_slice()),
                    Some(&(b"renamed".to_vec(), CorrespondenceKind::DirectoryRenamed,))
                );
                assert_relationship_event(
                    &authority,
                    EventKind::DirectoryRenamed,
                    b"source",
                    b"renamed",
                );
            }

            {
                let (_fixture, original, ai, state) = Fixture::from_setup(|original| {
                    fs::create_dir_all(original.join("left").join("source"))
                        .expect("create move subtree");
                    fs::create_dir_all(original.join("right")).expect("create destination parent");
                    fs::write(
                        original.join("left").join("source").join("child.txt"),
                        b"movable subtree bytes\n",
                    )
                    .expect("write move subtree child");
                });
                fs::rename(
                    ai.join("left").join("source"),
                    ai.join("right").join("source"),
                )
                .expect("move unique subtree");
                let authority = integrated_classify(&original, &ai, &state)
                    .expect("classify unique subtree move");
                assert_eq!(
                    authority
                        .correspondence
                        .baseline_to_edited
                        .get(b"left/source".as_slice()),
                    Some(&(b"right/source".to_vec(), CorrespondenceKind::DirectoryMoved,))
                );
                assert_relationship_event(
                    &authority,
                    EventKind::DirectoryMoved,
                    b"left/source",
                    b"right/source",
                );
            }

            {
                let (_fixture, original, ai, state) = Fixture::from_setup(|original| {
                    fs::create_dir_all(original.join("source")).expect("create mismatch subtree");
                    fs::write(
                        original.join("source").join("child.txt"),
                        b"before subtree\n",
                    )
                    .expect("write mismatch subtree child");
                });
                fs::rename(ai.join("source"), ai.join("renamed")).expect("rename mismatch subtree");
                fs::write(ai.join("renamed").join("child.txt"), b"after subtree\n")
                    .expect("change renamed subtree");
                let authority = integrated_classify(&original, &ai, &state)
                    .expect("classify nonmatching subtree");
                assert!(!authority
                    .correspondence
                    .baseline_to_edited
                    .contains_key(b"source".as_slice()));
                assert!(!authority.events.events().iter().any(|event| matches!(
                    event.kind,
                    EventKind::DirectoryRenamed | EventKind::DirectoryMoved
                )));
            }

            for (baseline_count, edited_count) in [(2usize, 1usize), (1, 2), (2, 2)] {
                let (_fixture, original, ai, state) = Fixture::from_setup(|original| {
                    for ordinal in 0..baseline_count {
                        let directory = original.join(format!("source-{ordinal}"));
                        fs::create_dir_all(&directory).expect("create duplicate subtree");
                        fs::write(directory.join("child.txt"), b"duplicate subtree bytes\n")
                            .expect("write duplicate subtree child");
                    }
                });
                for ordinal in 0..baseline_count.min(edited_count) {
                    fs::rename(
                        ai.join(format!("source-{ordinal}")),
                        ai.join(format!("edited-{ordinal}")),
                    )
                    .expect("rename duplicate subtree");
                }
                if baseline_count > edited_count {
                    for ordinal in edited_count..baseline_count {
                        fs::remove_dir_all(ai.join(format!("source-{ordinal}")))
                            .expect("remove extra edited-side subtree");
                    }
                } else if edited_count > baseline_count {
                    for ordinal in baseline_count..edited_count {
                        let directory = ai.join(format!("edited-{ordinal}"));
                        fs::create_dir_all(&directory).expect("add duplicate edited subtree");
                        fs::copy(
                            ai.join("edited-0").join("child.txt"),
                            directory.join("child.txt"),
                        )
                        .expect("copy duplicate edited subtree child");
                    }
                }
                let authority = integrated_classify(&original, &ai, &state)
                    .expect("classify duplicate subtree ambiguity");
                assert!(!authority.events.events().iter().any(|event| matches!(
                    event.kind,
                    EventKind::DirectoryRenamed | EventKind::DirectoryMoved
                )));
                for ordinal in 0..baseline_count {
                    assert!(!authority
                        .correspondence
                        .baseline_to_edited
                        .contains_key(format!("source-{ordinal}").as_bytes()));
                }
            }
        }
    }
}
