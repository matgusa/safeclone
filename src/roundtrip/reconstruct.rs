//! Pure occurrence reconstruction kernel.
//!
//! The filesystem integration seam is added below this core.  The core never
//! accepts caller-supplied approval booleans or event-id lists: its action
//! records are private and can only be constructed from a freshly authenticated
//! `PreparedReconstructionAuthority`.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::ops::Range;
use std::path::Path;

use super::anchor::ReconstructionPlacement;
use super::approval::CompleteApprovalEvidence;
use super::baseline::{
    canonical_path, derive, read_planned_original_file, rederive_planned_directory_path,
    rederive_planned_file, require_same_summary, FileDisposition, PlannedEntry,
    RederivedOccurrenceSpan,
};
use super::candidate_model::{
    CandidateCommitmentWriter, CandidateContentAction, CandidateDisposition, CandidateEntryInput,
    CandidateEntryKind, CandidateNamespacePlan, CandidatePlanBuilder, CandidateSourceRelationship,
};
use super::classify::{
    BaselineEntry, BaselineEntryKind, BaselineTokenLocation, CandidateSelection,
    PreparedApplyAuthority, PreparedReviewAuthority, ReconstructionInputs,
};
use super::crypto::{constant_time_equal, KeySchedule, SecretVec};
use super::edited::{
    observe_pass, read_accepted_file, require_same_summary as require_same_edited_summary,
    EditedEntry, EditedEntryKind, ReservedLocationKind,
};
use super::events::{EventDecision, EventKind};
use super::reconstruction_reference::{
    project_retokenized_component, verify_reconstructed_component, ExpectedEditedEntry,
    ProjectionReference,
};
use super::review_identity::ReviewIdentityIndex;
use super::schema::SessionState;
use super::token::{authenticate_token, parse_token, ComponentKind, TokenCategory};
use super::{Error, Result};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReconstructionSummary {
    pub profile: super::token::ReviewProfile,
    pub expected_candidate_tree_commitment: [u8; 32],
    pub candidate_entries: u32,
    pub candidate_directories: u32,
    pub candidate_regular_files: u32,
    pub ai_visible_entries: u32,
    pub original_only_entries: u32,
    pub restored_occurrences: u32,
    pub deleted_occurrences: u32,
    pub canonical_path_bytes: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReconstructionFailure(Error);

impl ReconstructionFailure {
    pub const fn error(self) -> Error {
        self.0
    }
}

impl fmt::Display for ReconstructionFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "round-trip reconstruction failed: {}", self.0)
    }
}

impl std::error::Error for ReconstructionFailure {}

pub type ReconstructionResult<T> = std::result::Result<T, ReconstructionFailure>;

/// Derive and verify the complete reconstruction logical model without creating a
/// candidate root or mutating session/workspace state.  Only raw-free summary
/// evidence escapes this call.
pub fn reconstruct_session_model(
    original: &Path,
    ai_workspace: &Path,
    private_state: &Path,
) -> ReconstructionResult<ReconstructionSummary> {
    let model = prepare_reconstruction_model(original, ai_workspace, private_state)
        .map_err(ReconstructionFailure)?;
    let mut directories = 0u32;
    let mut files = 0u32;
    let mut ai_visible = 0u32;
    let mut original_only = 0u32;
    for entry in model.plan().entries() {
        match entry.kind {
            CandidateEntryKind::Directory => {
                directories = directories
                    .checked_add(1)
                    .ok_or(ReconstructionFailure(Error::BoundExceeded))?;
            }
            CandidateEntryKind::RegularFile => {
                files = files
                    .checked_add(1)
                    .ok_or(ReconstructionFailure(Error::BoundExceeded))?;
            }
        }
        match entry.disposition {
            CandidateDisposition::AiVisible => {
                ai_visible = ai_visible
                    .checked_add(1)
                    .ok_or(ReconstructionFailure(Error::BoundExceeded))?;
            }
            CandidateDisposition::OriginalOnly => {
                original_only = original_only
                    .checked_add(1)
                    .ok_or(ReconstructionFailure(Error::BoundExceeded))?;
            }
        }
    }
    let candidate_entries = directories
        .checked_add(files)
        .ok_or(ReconstructionFailure(Error::BoundExceeded))?;
    let summary = ReconstructionSummary {
        profile: model.inputs.profile,
        expected_candidate_tree_commitment: model.expected_candidate_tree_commitment(),
        candidate_entries,
        candidate_directories: directories,
        candidate_regular_files: files,
        ai_visible_entries: ai_visible,
        original_only_entries: original_only,
        restored_occurrences: model.restored_occurrences(),
        deleted_occurrences: model.deleted_occurrences(),
        canonical_path_bytes: u64::try_from(model.plan().canonical_path_bytes())
            .map_err(|_| ReconstructionFailure(Error::BoundExceeded))?,
    };
    // Keep both retained authorities alive through the summary derivation.
    let _ = (&model.authority, &model.inputs);
    Ok(summary)
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum OccurrenceAction {
    RestoreOriginalOccurrence,
    DeleteOccurrence,
}

/// File-local raw occurrence authority.  Raw bytes are never owned by the
/// node; `source_span` is borrowed from the one Original component/file only
/// while this graph is processed.
pub(crate) struct RawOccurrenceNode<'path> {
    pub(crate) occurrence_id: [u8; 16],
    pub(crate) category: TokenCategory,
    pub(crate) component_kind: ComponentKind,
    pub(crate) original_canonical_path: &'path [u8],
    pub(crate) component_index: u32,
    pub(crate) logical_file: [u8; 32],
    pub(crate) source_span: Range<usize>,
    pub(crate) occurrence_order: u32,
    pub(crate) protected_anchor: [u8; 32],
}

pub(crate) struct AuthorizedOccurrence<'path> {
    pub(crate) raw: RawOccurrenceNode<'path>,
    pub(crate) action: OccurrenceAction,
    pub(crate) edited_placement: Option<ReconstructionPlacement>,
}

/// Value-free reconstruction trace.  It deliberately has no `Debug` or
/// serialization implementation and is released with its one-file output.
pub(crate) struct ReconstructionTraceNode {
    pub(crate) occurrence_id: [u8; 16],
    pub(crate) category: TokenCategory,
    pub(crate) component_kind: ComponentKind,
    pub(crate) component_index: u32,
    pub(crate) logical_file: [u8; 32],
    pub(crate) original_span: Range<usize>,
    pub(crate) candidate_span: Range<usize>,
    pub(crate) edited_span: Range<usize>,
    pub(crate) occurrence_order: u32,
    pub(crate) protected_anchor: [u8; 32],
}

pub(crate) struct ReconstructedBuffer {
    pub(crate) bytes: SecretVec,
    pub(crate) trace: Vec<ReconstructionTraceNode>,
}

impl ReconstructedBuffer {
    pub(crate) fn bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }

    pub(crate) fn trace(&self) -> &[ReconstructionTraceNode] {
        &self.trace
    }
}

pub(crate) fn reconstruct_authorized_component(
    schedule: &KeySchedule<'_>,
    original: &[u8],
    accepted_edited: &[u8],
    occurrences: &[AuthorizedOccurrence<'_>],
) -> Result<ReconstructedBuffer> {
    validate_authorized_occurrences(schedule, original, accepted_edited, occurrences)?;
    let mut preserved = occurrences
        .iter()
        .filter(|occurrence| occurrence.action == OccurrenceAction::RestoreOriginalOccurrence)
        .collect::<Vec<_>>();
    preserved.sort_unstable_by_key(|occurrence| {
        occurrence
            .edited_placement
            .map(|placement| (placement.start, placement.end))
            .unwrap_or((usize::MAX, usize::MAX))
    });

    let restored_bytes = preserved.iter().try_fold(0usize, |total, occurrence| {
        total
            .checked_add(occurrence.raw.source_span.len())
            .ok_or(Error::BoundExceeded)
    })?;
    let token_bytes = preserved.iter().try_fold(0usize, |total, occurrence| {
        let placement = occurrence
            .edited_placement
            .ok_or(Error::ReconstructionRejected)?;
        total
            .checked_add(placement.end - placement.start)
            .ok_or(Error::BoundExceeded)
    })?;
    let capacity = accepted_edited
        .len()
        .checked_sub(token_bytes)
        .and_then(|length| length.checked_add(restored_bytes))
        .ok_or(Error::BoundExceeded)?;
    if capacity > super::baseline::MAX_FILE_BYTES {
        return Err(Error::BoundExceeded);
    }
    let mut output = Vec::new();
    output
        .try_reserve_exact(capacity)
        .map_err(|_| Error::BoundExceeded)?;
    let mut trace = Vec::new();
    trace
        .try_reserve_exact(preserved.len())
        .map_err(|_| Error::BoundExceeded)?;
    let mut edited_cursor = 0usize;
    for occurrence in preserved {
        let placement = occurrence
            .edited_placement
            .ok_or(Error::ReconstructionRejected)?;
        if placement.start < edited_cursor {
            return Err(Error::ReconstructionRejected);
        }
        output.extend_from_slice(
            accepted_edited
                .get(edited_cursor..placement.start)
                .ok_or(Error::ReconstructionRejected)?,
        );
        let candidate_start = output.len();
        output.extend_from_slice(
            original
                .get(occurrence.raw.source_span.clone())
                .ok_or(Error::ReconstructionRejected)?,
        );
        let candidate_end = output.len();
        trace.push(ReconstructionTraceNode {
            occurrence_id: occurrence.raw.occurrence_id,
            category: occurrence.raw.category,
            component_kind: occurrence.raw.component_kind,
            component_index: occurrence.raw.component_index,
            logical_file: occurrence.raw.logical_file,
            original_span: occurrence.raw.source_span.clone(),
            candidate_span: candidate_start..candidate_end,
            edited_span: placement.start..placement.end,
            occurrence_order: occurrence.raw.occurrence_order,
            protected_anchor: occurrence.raw.protected_anchor,
        });
        edited_cursor = placement.end;
    }
    output.extend_from_slice(
        accepted_edited
            .get(edited_cursor..)
            .ok_or(Error::ReconstructionRejected)?,
    );
    if output.len() != capacity {
        return Err(Error::ReconstructionRejected);
    }
    Ok(ReconstructedBuffer {
        bytes: SecretVec::new(output),
        trace,
    })
}

fn validate_authorized_occurrences(
    schedule: &KeySchedule<'_>,
    original: &[u8],
    accepted_edited: &[u8],
    occurrences: &[AuthorizedOccurrence<'_>],
) -> Result<()> {
    let mut previous_source_end = 0usize;
    let mut previous_order = None;
    let mut ids = std::collections::BTreeSet::new();
    let mut restored_edited_order = Vec::new();
    let mut restored_source_order = Vec::new();
    for occurrence in occurrences {
        if occurrence.raw.original_canonical_path.is_empty()
            || occurrence.raw.source_span.start < previous_source_end
            || occurrence.raw.source_span.start >= occurrence.raw.source_span.end
            || occurrence.raw.source_span.end > original.len()
            || previous_order.is_some_and(|order| occurrence.raw.occurrence_order <= order)
            || !ids.insert(occurrence.raw.occurrence_id)
        {
            return Err(Error::ReconstructionRejected);
        }
        previous_source_end = occurrence.raw.source_span.end;
        previous_order = Some(occurrence.raw.occurrence_order);
        match occurrence.action {
            OccurrenceAction::RestoreOriginalOccurrence => {
                let placement = occurrence
                    .edited_placement
                    .ok_or(Error::ReconstructionRejected)?;
                verify_authenticated_placement(
                    schedule,
                    accepted_edited,
                    placement,
                    occurrence.raw.occurrence_id,
                    occurrence.raw.category,
                )?;
                restored_edited_order.push((placement.start, occurrence.raw.occurrence_id));
                restored_source_order.push(occurrence.raw.occurrence_id);
            }
            OccurrenceAction::DeleteOccurrence => {
                if occurrence.edited_placement.is_some() {
                    return Err(Error::ReconstructionRejected);
                }
            }
        }
    }
    restored_edited_order.sort_unstable_by_key(|(start, _)| *start);
    if restored_edited_order
        .iter()
        .map(|(_, oid)| *oid)
        .ne(restored_source_order)
    {
        return Err(Error::ReconstructionRejected);
    }
    Ok(())
}

fn verify_authenticated_placement(
    schedule: &KeySchedule<'_>,
    edited: &[u8],
    placement: ReconstructionPlacement,
    expected_oid: [u8; 16],
    expected_category: TokenCategory,
) -> Result<()> {
    if placement.occurrence_id != expected_oid
        || placement.start >= placement.end
        || placement.end > edited.len()
    {
        return Err(Error::ReconstructionRejected);
    }
    let token = std::str::from_utf8(
        edited
            .get(placement.start..placement.end)
            .ok_or(Error::ReconstructionRejected)?,
    )
    .map_err(|_| Error::ReconstructionRejected)?;
    let parsed = parse_token(token).map_err(|_| Error::ReconstructionRejected)?;
    if parsed.category() != expected_category || *parsed.occurrence_id() != expected_oid {
        return Err(Error::ReconstructionRejected);
    }
    authenticate_token(schedule, parsed)
        .map(|_| ())
        .map_err(|_| Error::ReconstructionRejected)
}

struct ReconstructionActions {
    by_oid: BTreeMap<[u8; 16], OccurrenceAction>,
    deleted_files: BTreeSet<Vec<u8>>,
}

struct OccurrenceAccounting {
    seen: BTreeSet<[u8; 16]>,
    restored: u32,
    deleted: u32,
}

/// Full-path projection authority retained only until the expected candidate
/// commitment is verified.  It contains accepted safe paths and value-free
/// occurrence traces, never raw source values or a token-to-value map.
struct CandidatePathProjection {
    by_candidate_path: BTreeMap<Vec<u8>, PathLeafProjection>,
}

struct PathLeafProjection {
    accepted_edited_path: Vec<u8>,
    accepted_edited_leaf: Vec<u8>,
    original_planned_index: Option<usize>,
    trace: Vec<ReconstructionTraceNode>,
}

struct PlannedCandidateModel {
    plan: CandidateNamespacePlan,
    path_projection: CandidatePathProjection,
}

struct ReservedFormIndex {
    by_oid: BTreeMap<[u8; 16], usize>,
}

fn build_reserved_form_index(inputs: &ReconstructionInputs) -> Result<ReservedFormIndex> {
    let mut by_oid = BTreeMap::new();
    for (index, form) in inputs.edited.forms.iter().enumerate() {
        if let Some(oid) = form.occurrence_id {
            if by_oid.insert(oid, index).is_some() {
                return Err(Error::ReconstructionRejected);
            }
        }
    }
    Ok(ReservedFormIndex { by_oid })
}

impl OccurrenceAccounting {
    fn new() -> Self {
        Self {
            seen: BTreeSet::new(),
            restored: 0,
            deleted: 0,
        }
    }

    fn record(&mut self, oid: [u8; 16], action: OccurrenceAction) -> Result<()> {
        if !self.seen.insert(oid) {
            return Err(Error::OccurrenceGraphMismatch);
        }
        match action {
            OccurrenceAction::RestoreOriginalOccurrence => {
                self.restored = self.restored.checked_add(1).ok_or(Error::BoundExceeded)?;
            }
            OccurrenceAction::DeleteOccurrence => {
                self.deleted = self.deleted.checked_add(1).ok_or(Error::BoundExceeded)?;
            }
        }
        Ok(())
    }
}

/// reconstruction output authority.  It owns the retained fresh transaction, accepted
/// edited snapshot, content-free namespace plan, and expected commitment.  It
/// has no formatter or persistence surface and creates no candidate entries.
pub(crate) struct AuthorizedReconstructionModel {
    pub(crate) authority: PreparedReviewAuthority,
    pub(crate) inputs: ReconstructionInputs,
    plan: CandidateNamespacePlan,
    actions: ReconstructionActions,
    reserved_forms: ReservedFormIndex,
    path_projection: CandidatePathProjection,
    expected_candidate_tree_commitment: [u8; 32],
    restored_occurrences: u32,
    deleted_occurrences: u32,
}

impl AuthorizedReconstructionModel {
    pub(crate) fn plan(&self) -> &CandidateNamespacePlan {
        &self.plan
    }

    pub(crate) const fn expected_candidate_tree_commitment(&self) -> [u8; 32] {
        self.expected_candidate_tree_commitment
    }

    pub(crate) const fn restored_occurrences(&self) -> u32 {
        self.restored_occurrences
    }

    pub(crate) const fn deleted_occurrences(&self) -> u32 {
        self.deleted_occurrences
    }

    pub(crate) fn materialize_ai_file(&self, index: usize) -> Result<SecretVec> {
        process_ai_file(self, index, None)?.ok_or(Error::InvalidState)
    }

    pub(crate) fn project_actual_ai_file(&self, index: usize, actual: &[u8]) -> Result<SecretVec> {
        process_ai_file(self, index, Some(actual))?.ok_or(Error::InvalidState)
    }

    pub(crate) fn projected_ai_paths(&self) -> Result<BTreeMap<Vec<u8>, Vec<u8>>> {
        let schedule = self.authority.owner.key_schedule();
        derive_projected_ai_paths(&self.inputs, &self.plan, &self.path_projection, &schedule)
    }

    pub(crate) fn verify_final_original(&self) -> Result<()> {
        let schedule = self.authority.owner.key_schedule();
        let current = derive(&self.inputs.original, &schedule, self.inputs.profile, false)
            .map_err(|_| Error::OriginalBaselineMismatch)?;
        require_same_summary(&self.inputs.baseline.derivation.summary, &current.summary)
            .map_err(|_| Error::OriginalBaselineMismatch)
    }

    pub(crate) fn verify_final_edited(&self) -> Result<()> {
        let schedule = self.authority.owner.key_schedule();
        let current = observe_pass(
            &self.inputs.ai,
            &schedule,
            &self.inputs.baseline.derivation.plan.inventory,
            self.inputs.profile,
            |_| Ok(()),
        )
        .map_err(|_| Error::WorkspaceUnstable)?;
        require_same_edited_summary(&self.inputs.edited.summary, &current.summary)
            .map_err(|_| Error::WorkspaceUnstable)
    }
}

fn process_ai_file(
    model: &AuthorizedReconstructionModel,
    index: usize,
    actual: Option<&[u8]>,
) -> Result<Option<SecretVec>> {
    let entry = model.plan.entries().get(index).ok_or(Error::InvalidState)?;
    if entry.kind != CandidateEntryKind::RegularFile
        || entry.disposition != CandidateDisposition::AiVisible
    {
        return Err(Error::InvalidState);
    }
    let schedule = model.authority.owner.key_schedule();
    let edited_by_path = model
        .inputs
        .edited
        .entries
        .iter()
        .map(|entry| (entry.path.as_slice(), entry))
        .collect::<BTreeMap<_, _>>();
    match entry.content_action {
        CandidateContentAction::UseAcceptedEditedFile => {
            if entry.source_relationship != CandidateSourceRelationship::NewEdited {
                return Err(Error::InvalidState);
            }
            let edited = model
                .inputs
                .edited
                .entries
                .get(entry.source_index)
                .ok_or(Error::InvalidState)?;
            let bytes = read_accepted_file(&model.inputs.ai, &edited_by_path, edited, &schedule)?;
            if let Some(actual) = actual {
                if !super::crypto::constant_time_equal(actual, bytes.as_slice()) {
                    return Err(Error::CandidateVerificationFailed);
                }
                Ok(Some(SecretVec::new(actual.to_vec())))
            } else {
                Ok(Some(bytes))
            }
        }
        CandidateContentAction::ReconstructBaselineFile => {
            if entry.source_relationship != CandidateSourceRelationship::BaselineCounterpart {
                return Err(Error::InvalidState);
            }
            let baseline_by_planned = model
                .inputs
                .baseline
                .entries
                .values()
                .filter_map(|entry| entry.planned_index.map(|index| (index, entry)))
                .collect::<BTreeMap<_, _>>();
            let baseline_entry = baseline_by_planned
                .get(&entry.source_index)
                .copied()
                .ok_or(Error::InvalidState)?;
            let planned = model
                .inputs
                .baseline
                .derivation
                .plan
                .entries
                .get(entry.source_index)
                .ok_or(Error::InvalidState)?;
            let edited = projected_edited_entry(
                &model.inputs,
                entry,
                &baseline_by_planned,
                &edited_by_path,
            )?;
            let original_path = canonical_path(planned.original_components())?;
            let mut rederived = rederive_planned_file(
                &model.inputs.original,
                planned,
                &schedule,
                model.inputs.profile,
            )?;
            rederived.release_safe_output();
            let accepted =
                read_accepted_file(&model.inputs.ai, &edited_by_path, edited, &schedule)?;
            let mut accounting = OccurrenceAccounting::new();
            let authorized = authorize_occurrences(
                OccurrenceAuthorizationContext {
                    inputs: &model.inputs,
                    actions: &model.actions,
                    reserved_forms: &model.reserved_forms,
                    baseline_entry,
                    edited_entry: edited,
                    component_kind: ComponentKind::Content,
                },
                &original_path,
                &rederived.content_occurrences,
                &mut accounting,
            )?;
            let reconstructed = reconstruct_authorized_component(
                &schedule,
                rederived.original_bytes(),
                accepted.as_slice(),
                &authorized,
            )?;
            verify_reconstructed_component(
                &schedule,
                rederived.original_bytes(),
                accepted.as_slice(),
                &authorized,
                &reconstructed,
            )?;
            if let Some(actual) = actual {
                if !super::crypto::constant_time_equal(actual, reconstructed.bytes()) {
                    return Err(Error::CandidateVerificationFailed);
                }
                let projected = project_retokenized_component(
                    &schedule,
                    rederived.original_bytes(),
                    accepted.as_slice(),
                    actual,
                    reconstructed.trace(),
                )?;
                Ok(Some(SecretVec::new(projected)))
            } else {
                Ok(Some(reconstructed.bytes))
            }
        }
        CandidateContentAction::Directory | CandidateContentAction::PreserveOriginalFile => {
            Err(Error::InvalidState)
        }
    }
}

pub(crate) fn prepare_reconstruction_model(
    original: &Path,
    ai_workspace: &Path,
    private_state: &Path,
) -> Result<AuthorizedReconstructionModel> {
    let authority =
        super::classify::prepare_reconstruction_authority(original, ai_workspace, private_state)?;
    prepare_model_from_authority(authority, false)
}

pub(crate) fn prepare_apply_reconstruction_model(
    original: &Path,
    ai_workspace: &Path,
    private_state: &Path,
    candidate: &Path,
) -> Result<(
    AuthorizedReconstructionModel,
    super::observe::QualifiedDirectory,
    std::ffi::OsString,
    CandidateSelection,
)> {
    let PreparedApplyAuthority {
        review,
        candidate_parent,
        candidate_leaf,
        candidate,
    } = super::classify::prepare_apply_authority(original, ai_workspace, private_state, candidate)?;
    Ok((
        prepare_model_from_authority(review, true)?,
        candidate_parent,
        candidate_leaf,
        candidate,
    ))
}

fn prepare_model_from_authority(
    mut authority: PreparedReviewAuthority,
    apply_mode: bool,
) -> Result<AuthorizedReconstructionModel> {
    use super::capsule::StoreClassification;

    let identities = ReviewIdentityIndex::derive(&authority)?;
    let complete = {
        let schedule = authority.owner.key_schedule();
        if apply_mode {
            super::approval::authenticate_complete_apply_approval_set(
                authority.owner.capsule(),
                &schedule,
                &authority,
                &identities,
            )?
        } else {
            super::approval::authenticate_complete_approval_set(
                authority.owner.capsule(),
                &schedule,
                &authority,
                &identities,
            )?
        }
    };
    let inputs = authority.take_reconstruction_inputs()?;
    let (planned, commitment, accounting, actions, reserved_forms) = {
        let schedule = authority.owner.key_schedule();
        let actions = derive_reconstruction_actions(&authority, &inputs, complete)?;
        let reserved_forms = build_reserved_form_index(&inputs)?;
        let mut accounting = OccurrenceAccounting::new();
        account_deleted_file_occurrences(
            &inputs,
            &actions,
            &reserved_forms,
            &schedule,
            &mut accounting,
        )?;
        let planned = build_candidate_plan(
            &inputs,
            &actions,
            &reserved_forms,
            &schedule,
            &mut accounting,
        )?;
        let commitment = commit_candidate_model(
            &inputs,
            &actions,
            &reserved_forms,
            &planned.plan,
            &planned.path_projection,
            &schedule,
            &mut accounting,
        )?;
        if accounting.seen.len() != actions.by_oid.len()
            || actions
                .by_oid
                .keys()
                .any(|oid| !accounting.seen.contains(oid))
        {
            return Err(Error::OccurrenceGraphMismatch);
        }
        (planned, commitment, accounting, actions, reserved_forms)
    };

    // File-local reads above are each bound to the accepted second-pass file
    // evidence.  Re-observe the complete edited tree once more so namespace,
    // aliases, identities, forms, and bytes also remain globally stable.
    {
        let schedule = authority.owner.key_schedule();
        let final_edited = observe_pass(
            &inputs.ai,
            &schedule,
            &inputs.baseline.derivation.plan.inventory,
            inputs.profile,
            |_| Ok(()),
        )
        .map_err(|_| Error::WorkspaceUnstable)?;
        require_same_edited_summary(&inputs.edited.summary, &final_edited.summary)
            .map_err(|_| Error::WorkspaceUnstable)?;
    }

    // Original is hostile and mutable.  Recommit it after every file-local
    // reconstruction/reference read; the expected candidate is not returned
    // if the accepted fresh baseline changed during reconstruction.
    {
        let schedule = authority.owner.key_schedule();
        let final_original = derive(
            &inputs.original,
            &schedule,
            authority.owner.capsule().review_profile,
            false,
        )
        .map_err(|_| Error::OriginalBaselineMismatch)?;
        require_same_summary(&inputs.baseline.derivation.summary, &final_original.summary)
            .map_err(|_| Error::OriginalBaselineMismatch)?;
    }
    authority.verify_selected_roots()?;
    let final_state = authority.store.read_while_locked(&mut authority.lock)?;
    let final_live = final_state.live_head().ok_or(Error::InvalidState)?;
    let valid_store_shape = match final_live.capsule().session_state {
        SessionState::ApplyIncomplete if apply_mode => matches!(
            (final_state.classification, final_state.orphan_count),
            (StoreClassification::AuthoritativeLive, 0)
                | (StoreClassification::PrivateOrphansPresent, 1)
        ),
        _ => {
            final_state.classification == StoreClassification::AuthoritativeLive
                && final_state.orphan_count == 0
        }
    };
    if !valid_store_shape || final_live.capsule() != authority.owner.capsule() {
        return Err(Error::InvalidState);
    }
    require_final_capsule_tag(final_live.tag(), authority.owner.tag())?;
    if !apply_mode && final_live.capsule().session_state != SessionState::ReadyToApply {
        return Err(Error::InvalidState);
    }

    Ok(AuthorizedReconstructionModel {
        authority,
        inputs,
        plan: planned.plan,
        actions,
        reserved_forms,
        path_projection: planned.path_projection,
        expected_candidate_tree_commitment: commitment,
        restored_occurrences: accounting.restored,
        deleted_occurrences: accounting.deleted,
    })
}

fn require_final_capsule_tag(actual: &[u8; 32], expected: &[u8; 32]) -> Result<()> {
    if !constant_time_equal(actual, expected) {
        return Err(Error::InvalidState);
    }
    Ok(())
}

fn derive_reconstruction_actions(
    authority: &PreparedReviewAuthority,
    inputs: &ReconstructionInputs,
    _complete: CompleteApprovalEvidence,
) -> Result<ReconstructionActions> {
    if authority.report.rejected_events != 0 || authority.events.rejected() != 0 {
        return Err(Error::ReconstructionRejected);
    }
    let mut by_oid = BTreeMap::new();
    let mut deleted_files = BTreeSet::new();
    for event in authority.events.events() {
        match event.kind {
            EventKind::PreservedSameAnchor => {
                let oid = validate_preserved_event(event)?;
                if by_oid
                    .insert(oid, OccurrenceAction::RestoreOriginalOccurrence)
                    .is_some()
                {
                    return Err(Error::ReconstructionRejected);
                }
            }
            EventKind::TokenDeleted => {
                let oid = validate_deleted_token_event(event)?;
                if by_oid
                    .insert(oid, OccurrenceAction::DeleteOccurrence)
                    .is_some()
                {
                    return Err(Error::ReconstructionRejected);
                }
            }
            EventKind::FileDeleted => {
                if event.decision != EventDecision::ApprovalRequired
                    || event.baseline_oid.is_some()
                    || event.before_path.is_none()
                    || event.after_path.is_some()
                {
                    return Err(Error::ReconstructionRejected);
                }
                if !deleted_files.insert(
                    event
                        .before_path
                        .clone()
                        .ok_or(Error::ReconstructionRejected)?,
                ) {
                    return Err(Error::ReconstructionRejected);
                }
            }
            EventKind::StrictTokenFileModified => {
                if event.decision != EventDecision::ApprovalRequired || event.baseline_oid.is_some()
                {
                    return Err(Error::ReconstructionRejected);
                }
            }
            EventKind::FileModified
            | EventKind::FileRenamed
            | EventKind::FileMoved
            | EventKind::NewTextFile
            | EventKind::DirectoryAdded
            | EventKind::DirectoryDeleted
            | EventKind::DirectoryRenamed
            | EventKind::DirectoryMoved => {
                if event.baseline_oid.is_some()
                    || matches!(
                        event.decision,
                        EventDecision::Reject | EventDecision::ApprovalRequired
                    )
                {
                    return Err(Error::ReconstructionRejected);
                }
            }
            EventKind::ProtectedContextChanged
            | EventKind::ProtectedCoreChanged
            | EventKind::AnchorAmbiguous
            | EventKind::MovedToOtherFile
            | EventKind::PathMoved
            | EventKind::TokenDuplicated
            | EventKind::TokenModified
            | EventKind::TokenUnknown
            | EventKind::CategoryMismatch
            | EventKind::TokenOrderChanged
            | EventKind::NewUntokenizedSensitiveFinding
            | EventKind::UnsupportedAddition
            | EventKind::LinkLikeAddition
            | EventKind::HardLink
            | EventKind::AlternateDataStream
            | EventKind::ProtectedNamespace
            | EventKind::OmittedPathCollision
            | EventKind::InvalidUtf8 => return Err(Error::ReconstructionRejected),
        }
    }
    if by_oid.len() != inputs.baseline.tokens.len()
        || inputs
            .baseline
            .tokens
            .keys()
            .any(|oid| !by_oid.contains_key(oid))
    {
        return Err(Error::ReconstructionRejected);
    }
    for path in &deleted_files {
        let entry = inputs
            .baseline
            .entries
            .get(path)
            .ok_or(Error::ReconstructionRejected)?;
        if entry.kind != BaselineEntryKind::File
            || entry
                .own_token_oids
                .iter()
                .any(|oid| by_oid.get(oid) != Some(&OccurrenceAction::DeleteOccurrence))
        {
            return Err(Error::ReconstructionRejected);
        }
    }
    Ok(ReconstructionActions {
        by_oid,
        deleted_files,
    })
}

fn validate_preserved_event(event: &super::events::CanonicalEvent) -> Result<[u8; 16]> {
    if event.decision != EventDecision::Automatic
        || event.expected_category.is_none()
        || event.expected_category != event.observed_category
        || event.before_anchor.is_none()
        || event.before_anchor != event.after_anchor
        || event.observed_count != 1
        || event.before_path.is_none()
        || event.after_path.is_none()
    {
        return Err(Error::ReconstructionRejected);
    }
    event.baseline_oid.ok_or(Error::ReconstructionRejected)
}

fn validate_deleted_token_event(event: &super::events::CanonicalEvent) -> Result<[u8; 16]> {
    if event.decision != EventDecision::ApprovalRequired
        || event.expected_category.is_none()
        || event.observed_category.is_some()
        || event.before_anchor.is_none()
        || event.before_anchor != event.after_anchor
        || event.observed_count != 0
        || event.before_path.is_none()
    {
        return Err(Error::ReconstructionRejected);
    }
    event.baseline_oid.ok_or(Error::ReconstructionRejected)
}

fn account_deleted_file_occurrences(
    inputs: &ReconstructionInputs,
    actions: &ReconstructionActions,
    reserved_forms: &ReservedFormIndex,
    schedule: &KeySchedule<'_>,
    accounting: &mut OccurrenceAccounting,
) -> Result<()> {
    for path in &actions.deleted_files {
        let entry = inputs
            .baseline
            .entries
            .get(path)
            .ok_or(Error::ReconstructionRejected)?;
        let planned_index = entry.planned_index.ok_or(Error::InvalidState)?;
        let planned = inputs
            .baseline
            .derivation
            .plan
            .entries
            .get(planned_index)
            .ok_or(Error::InvalidState)?;
        let mut rederived =
            rederive_planned_file(&inputs.original, planned, schedule, inputs.profile)?;
        rederived.release_safe_output();
        let original_path = canonical_path(planned.original_components())?;
        let original_leaf = planned
            .original_components()
            .last()
            .ok_or(Error::ReconstructionRejected)?;
        account_deleted_spans(
            inputs,
            actions,
            reserved_forms,
            entry,
            &original_path,
            original_leaf.as_bytes(),
            &rederived.path_occurrences,
            ComponentKind::Filename,
            accounting,
        )?;
        account_deleted_spans(
            inputs,
            actions,
            reserved_forms,
            entry,
            &original_path,
            rederived.original_bytes(),
            &rederived.content_occurrences,
            ComponentKind::Content,
            accounting,
        )?;
        if entry
            .own_token_oids
            .iter()
            .any(|oid| !accounting.seen.contains(oid))
        {
            return Err(Error::OccurrenceGraphMismatch);
        }
    }
    Ok(())
}

struct ProtectedOccurrenceAuthority<'a> {
    component_kind: ComponentKind,
    retained_entry_path: &'a [u8],
    rederived_entry_path: &'a [u8],
    retained_category: TokenCategory,
    rederived_category: TokenCategory,
    retained_anchor: &'a [u8; 32],
    rederived_anchor: &'a [u8; 32],
}

fn verify_protected_occurrence_authority(
    authority: ProtectedOccurrenceAuthority<'_>,
    mismatch_error: Error,
) -> Result<()> {
    let anchor_matches = match authority.component_kind {
        ComponentKind::Content => {
            constant_time_equal(authority.retained_anchor, authority.rederived_anchor)
        }
        ComponentKind::Filename | ComponentKind::Path => true,
    };
    let structural_fields_match = authority.retained_entry_path == authority.rederived_entry_path
        && authority.retained_category == authority.rederived_category;

    (structural_fields_match & anchor_matches)
        .then_some(())
        .ok_or(mismatch_error)
}

#[allow(clippy::too_many_arguments)]
fn account_deleted_spans(
    inputs: &ReconstructionInputs,
    actions: &ReconstructionActions,
    reserved_forms: &ReservedFormIndex,
    baseline_entry: &BaselineEntry,
    original_path: &[u8],
    original_component: &[u8],
    spans: &[RederivedOccurrenceSpan],
    component_kind: ComponentKind,
    accounting: &mut OccurrenceAccounting,
) -> Result<()> {
    for span in spans {
        if span.start >= span.end || span.end > original_component.len() {
            return Err(Error::OccurrenceGraphMismatch);
        }
        let token = inputs
            .baseline
            .tokens
            .get(&span.fact.occurrence_id)
            .ok_or(Error::OccurrenceGraphMismatch)?;
        let component_index = match (component_kind, token.location) {
            (ComponentKind::Content, BaselineTokenLocation::Content) => 0,
            (ComponentKind::Filename, BaselineTokenLocation::Path(boundary)) => {
                boundary.component_index
            }
            (ComponentKind::Path, BaselineTokenLocation::Path(boundary)) => {
                boundary.component_index
            }
            (ComponentKind::Content, BaselineTokenLocation::Path(_))
            | (ComponentKind::Filename | ComponentKind::Path, BaselineTokenLocation::Content) => {
                return Err(Error::OccurrenceGraphMismatch)
            }
        };
        verify_protected_occurrence_authority(
            ProtectedOccurrenceAuthority {
                component_kind,
                retained_entry_path: token.entry_path.as_slice(),
                rederived_entry_path: baseline_entry.path.as_slice(),
                retained_category: token.category,
                rederived_category: span.fact.category,
                retained_anchor: &token.before_anchor,
                rederived_anchor: &span.protected_anchor,
            },
            Error::OccurrenceGraphMismatch,
        )?;
        if actions.by_oid.get(&span.fact.occurrence_id) != Some(&OccurrenceAction::DeleteOccurrence)
            || reserved_forms.by_oid.contains_key(&span.fact.occurrence_id)
        {
            return Err(Error::OccurrenceGraphMismatch);
        }
        let node = AuthorizedOccurrence {
            raw: RawOccurrenceNode {
                occurrence_id: span.fact.occurrence_id,
                category: span.fact.category,
                component_kind,
                original_canonical_path: original_path,
                component_index,
                logical_file: baseline_entry.logical_id,
                source_span: span.start..span.end,
                occurrence_order: span.order,
                protected_anchor: span.protected_anchor,
            },
            action: OccurrenceAction::DeleteOccurrence,
            edited_placement: None,
        };
        if node.raw.original_canonical_path.is_empty() {
            return Err(Error::OccurrenceGraphMismatch);
        }
        accounting.record(node.raw.occurrence_id, node.action)?;
    }
    Ok(())
}

fn build_candidate_plan(
    inputs: &ReconstructionInputs,
    actions: &ReconstructionActions,
    reserved_forms: &ReservedFormIndex,
    schedule: &KeySchedule<'_>,
    accounting: &mut OccurrenceAccounting,
) -> Result<PlannedCandidateModel> {
    let edited_by_path = inputs
        .edited
        .entries
        .iter()
        .enumerate()
        .map(|(index, entry)| (entry.path.as_slice(), (index, entry)))
        .collect::<BTreeMap<_, _>>();
    let mut ordered_baseline = inputs.baseline.entries.values().collect::<Vec<_>>();
    ordered_baseline.sort_unstable_by(|left, right| {
        left.components
            .len()
            .cmp(&right.components.len())
            .then_with(|| left.path.cmp(&right.path))
    });
    let mut reconstructed_directories = BTreeMap::<Vec<u8>, String>::new();
    let mut builder = CandidatePlanBuilder::new();
    let mut path_projection = BTreeMap::new();

    for baseline_entry in ordered_baseline {
        if actions.deleted_files.contains(&baseline_entry.path) {
            continue;
        }
        let Some((edited_path, _)) = inputs
            .correspondence
            .baseline_to_edited
            .get(&baseline_entry.path)
        else {
            if baseline_entry.kind == BaselineEntryKind::File {
                return Err(Error::ReconstructionRejected);
            }
            continue;
        };
        let (edited_index, edited_entry) = edited_by_path
            .get(edited_path.as_slice())
            .copied()
            .ok_or(Error::ReconstructionRejected)?;
        if !entry_kinds_match(baseline_entry.kind, edited_entry.kind) {
            return Err(Error::ReconstructionRejected);
        }
        let planned_index = baseline_entry.planned_index.ok_or(Error::InvalidState)?;
        let planned = inputs
            .baseline
            .derivation
            .plan
            .entries
            .get(planned_index)
            .ok_or(Error::InvalidState)?;
        let mut candidate_components = edited_entry.components.clone();
        for component_index in 0..candidate_components.len().saturating_sub(1) {
            let prefix = canonical_path(&edited_entry.components[..=component_index])?;
            if let Some(restored) = reconstructed_directories.get(&prefix) {
                candidate_components[component_index] = restored.clone();
            }
        }
        let (restored_leaf, trace) = reconstruct_path_leaf(
            PathReconstructionContext {
                inputs,
                actions,
                reserved_forms,
                schedule,
            },
            baseline_entry,
            planned,
            edited_entry,
            accounting,
        )?;
        let leaf = candidate_components
            .last_mut()
            .ok_or(Error::ReconstructionRejected)?;
        *leaf = restored_leaf.clone();
        if baseline_entry.kind == BaselineEntryKind::Directory {
            reconstructed_directories.insert(edited_entry.path.clone(), restored_leaf);
        }
        let candidate_path = canonical_path(&candidate_components)?;
        builder.insert(CandidateEntryInput {
            components: candidate_components,
            kind: match baseline_entry.kind {
                BaselineEntryKind::Directory => CandidateEntryKind::Directory,
                BaselineEntryKind::File => CandidateEntryKind::RegularFile,
            },
            disposition: CandidateDisposition::AiVisible,
            source_relationship: CandidateSourceRelationship::BaselineCounterpart,
            content_action: match baseline_entry.kind {
                BaselineEntryKind::Directory => CandidateContentAction::Directory,
                BaselineEntryKind::File => CandidateContentAction::ReconstructBaselineFile,
            },
            source_index: planned_index,
            observed_short_aliases_utf16: observed_aliases(
                planned.observed_short_alias_utf16(),
                edited_entry.observed_short_alias_utf16.as_deref(),
            )?,
        })?;
        if path_projection
            .insert(
                candidate_path,
                PathLeafProjection {
                    accepted_edited_path: edited_entry.path.clone(),
                    accepted_edited_leaf: edited_entry
                        .components
                        .last()
                        .ok_or(Error::ReconstructionRejected)?
                        .as_bytes()
                        .to_vec(),
                    original_planned_index: Some(planned_index),
                    trace,
                },
            )
            .is_some()
        {
            return Err(Error::CandidateNamespaceCollision);
        }
        let _ = edited_index;
    }

    for (edited_index, edited_entry) in inputs.edited.entries.iter().enumerate() {
        if inputs
            .correspondence
            .paired_edited
            .contains(&edited_entry.path)
        {
            continue;
        }
        validate_new_edited_entry(edited_entry)?;
        let candidate_path = canonical_path(&edited_entry.components)?;
        builder.insert(CandidateEntryInput {
            components: edited_entry.components.clone(),
            kind: match edited_entry.kind {
                EditedEntryKind::Directory => CandidateEntryKind::Directory,
                EditedEntryKind::File => CandidateEntryKind::RegularFile,
                EditedEntryKind::Unsupported => return Err(Error::ReconstructionRejected),
            },
            disposition: CandidateDisposition::AiVisible,
            source_relationship: CandidateSourceRelationship::NewEdited,
            content_action: match edited_entry.kind {
                EditedEntryKind::Directory => CandidateContentAction::Directory,
                EditedEntryKind::File => CandidateContentAction::UseAcceptedEditedFile,
                EditedEntryKind::Unsupported => return Err(Error::ReconstructionRejected),
            },
            source_index: edited_index,
            observed_short_aliases_utf16: observed_aliases(
                None,
                edited_entry.observed_short_alias_utf16.as_deref(),
            )?,
        })?;
        if path_projection
            .insert(
                candidate_path,
                PathLeafProjection {
                    accepted_edited_path: edited_entry.path.clone(),
                    accepted_edited_leaf: edited_entry
                        .components
                        .last()
                        .ok_or(Error::ReconstructionRejected)?
                        .as_bytes()
                        .to_vec(),
                    original_planned_index: None,
                    trace: Vec::new(),
                },
            )
            .is_some()
        {
            return Err(Error::CandidateNamespaceCollision);
        }
    }

    let original_directories = inputs
        .baseline
        .derivation
        .plan
        .entries
        .iter()
        .enumerate()
        .filter_map(|(index, entry)| match entry {
            PlannedEntry::Directory {
                original_components,
                ..
            } => Some((original_components.as_slice(), index)),
            PlannedEntry::File { .. } => None,
        })
        .collect::<BTreeMap<_, _>>();
    for (planned_index, planned) in inputs.baseline.derivation.plan.entries.iter().enumerate() {
        let PlannedEntry::File {
            original_components,
            disposition: FileDisposition::Omit(_),
            ..
        } = planned
        else {
            continue;
        };
        for prefix_len in 1..=original_components.len() {
            let is_file = prefix_len == original_components.len();
            let (source_index, aliases) = if is_file {
                (
                    planned_index,
                    observed_aliases(planned.observed_short_alias_utf16(), None)?,
                )
            } else {
                let directory_index = *original_directories
                    .get(&original_components[..prefix_len])
                    .ok_or(Error::InvalidState)?;
                let directory = inputs
                    .baseline
                    .derivation
                    .plan
                    .entries
                    .get(directory_index)
                    .ok_or(Error::InvalidState)?;
                (
                    directory_index,
                    observed_aliases(directory.observed_short_alias_utf16(), None)?,
                )
            };
            builder.insert(CandidateEntryInput {
                components: original_components[..prefix_len].to_vec(),
                kind: if is_file {
                    CandidateEntryKind::RegularFile
                } else {
                    CandidateEntryKind::Directory
                },
                disposition: CandidateDisposition::OriginalOnly,
                source_relationship: CandidateSourceRelationship::OriginalOnly,
                content_action: if is_file {
                    CandidateContentAction::PreserveOriginalFile
                } else {
                    CandidateContentAction::Directory
                },
                source_index,
                observed_short_aliases_utf16: aliases,
            })?;
        }
    }
    Ok(PlannedCandidateModel {
        plan: builder.finish()?,
        path_projection: CandidatePathProjection {
            by_candidate_path: path_projection,
        },
    })
}

fn observed_aliases(first: Option<&[u16]>, second: Option<&[u16]>) -> Result<Vec<Vec<u16>>> {
    let mut aliases = Vec::new();
    aliases
        .try_reserve_exact(usize::from(first.is_some()) + usize::from(second.is_some()))
        .map_err(|_| Error::BoundExceeded)?;
    for alias in [first, second].into_iter().flatten() {
        if !aliases.iter().any(|existing| existing == alias) {
            aliases.push(alias.to_vec());
        }
    }
    Ok(aliases)
}

struct PathReconstructionContext<'a, 'key> {
    inputs: &'a ReconstructionInputs,
    actions: &'a ReconstructionActions,
    reserved_forms: &'a ReservedFormIndex,
    schedule: &'a KeySchedule<'key>,
}

fn reconstruct_path_leaf(
    context: PathReconstructionContext<'_, '_>,
    baseline_entry: &BaselineEntry,
    planned: &PlannedEntry,
    edited_entry: &EditedEntry,
    accounting: &mut OccurrenceAccounting,
) -> Result<(String, Vec<ReconstructionTraceNode>)> {
    let PathReconstructionContext {
        inputs,
        actions,
        reserved_forms,
        schedule,
    } = context;
    let path_facts = match planned {
        PlannedEntry::Directory { token_facts, .. } => token_facts,
        PlannedEntry::File {
            path_token_facts, ..
        } => path_token_facts,
    };
    let accepted_leaf = edited_entry
        .components
        .last()
        .ok_or(Error::ReconstructionRejected)?;
    if path_facts.is_empty() {
        return Ok((accepted_leaf.clone(), Vec::new()));
    }
    let original_components = planned.original_components();
    let original_leaf = original_components
        .last()
        .ok_or(Error::ReconstructionRejected)?;
    let rederived = match planned {
        PlannedEntry::Directory { .. } => {
            rederive_planned_directory_path(&inputs.original, planned, schedule, inputs.profile)?
                .occurrences
        }
        PlannedEntry::File { .. } => {
            rederive_planned_file(&inputs.original, planned, schedule, inputs.profile)?
                .path_occurrences
        }
    };
    let component_kind = match planned {
        PlannedEntry::Directory { .. } => ComponentKind::Path,
        PlannedEntry::File { .. } => ComponentKind::Filename,
    };
    let original_path = canonical_path(original_components)?;
    let authorized = authorize_occurrences(
        OccurrenceAuthorizationContext {
            inputs,
            actions,
            reserved_forms,
            baseline_entry,
            edited_entry,
            component_kind,
        },
        &original_path,
        &rederived,
        accounting,
    )?;
    let reconstructed = reconstruct_authorized_component(
        schedule,
        original_leaf.as_bytes(),
        accepted_leaf.as_bytes(),
        &authorized,
    )?;
    verify_reconstructed_component(
        schedule,
        original_leaf.as_bytes(),
        accepted_leaf.as_bytes(),
        &authorized,
        &reconstructed,
    )?;
    let leaf = std::str::from_utf8(reconstructed.bytes())
        .map_err(|_| Error::ReconstructionRejected)?
        .to_owned();
    super::observe::validate_workspace_component(&leaf)?;
    Ok((leaf, reconstructed.trace))
}

struct OccurrenceAuthorizationContext<'a> {
    inputs: &'a ReconstructionInputs,
    actions: &'a ReconstructionActions,
    reserved_forms: &'a ReservedFormIndex,
    baseline_entry: &'a BaselineEntry,
    edited_entry: &'a EditedEntry,
    component_kind: ComponentKind,
}

fn authorize_occurrences<'path>(
    context: OccurrenceAuthorizationContext<'_>,
    original_path: &'path [u8],
    spans: &[RederivedOccurrenceSpan],
    accounting: &mut OccurrenceAccounting,
) -> Result<Vec<AuthorizedOccurrence<'path>>> {
    let OccurrenceAuthorizationContext {
        inputs,
        actions,
        reserved_forms,
        baseline_entry,
        edited_entry,
        component_kind,
    } = context;
    let mut output = Vec::new();
    output
        .try_reserve_exact(spans.len())
        .map_err(|_| Error::BoundExceeded)?;
    for span in spans {
        let token = inputs
            .baseline
            .tokens
            .get(&span.fact.occurrence_id)
            .ok_or(Error::ReconstructionRejected)?;
        verify_protected_occurrence_authority(
            ProtectedOccurrenceAuthority {
                component_kind,
                retained_entry_path: token.entry_path.as_slice(),
                rederived_entry_path: baseline_entry.path.as_slice(),
                retained_category: token.category,
                rederived_category: span.fact.category,
                retained_anchor: &token.before_anchor,
                rederived_anchor: &span.protected_anchor,
            },
            Error::ReconstructionRejected,
        )?;
        let component_index = match (component_kind, token.location) {
            (ComponentKind::Content, BaselineTokenLocation::Content) => 0,
            (
                ComponentKind::Filename | ComponentKind::Path,
                BaselineTokenLocation::Path(boundary),
            ) => boundary.component_index,
            (ComponentKind::Content, BaselineTokenLocation::Path(_))
            | (ComponentKind::Filename | ComponentKind::Path, BaselineTokenLocation::Content) => {
                return Err(Error::ReconstructionRejected)
            }
        };
        let action = *actions
            .by_oid
            .get(&span.fact.occurrence_id)
            .ok_or(Error::ReconstructionRejected)?;
        let placement = match action {
            OccurrenceAction::RestoreOriginalOccurrence => Some(match component_kind {
                ComponentKind::Content => inputs
                    .anchors
                    .by_path
                    .get(&baseline_entry.path)
                    .and_then(|classification| {
                        classification.reconstruction_placement(&span.fact.occurrence_id)
                    })
                    .ok_or(Error::ReconstructionRejected)?,
                ComponentKind::Path | ComponentKind::Filename => path_placement(
                    inputs,
                    reserved_forms,
                    edited_entry,
                    span.fact.occurrence_id,
                    component_index,
                )?,
            }),
            OccurrenceAction::DeleteOccurrence => {
                let unexpected = reserved_forms.by_oid.contains_key(&span.fact.occurrence_id)
                    || match component_kind {
                        ComponentKind::Content => inputs
                            .anchors
                            .by_path
                            .get(&baseline_entry.path)
                            .and_then(|classification| {
                                classification.reconstruction_placement(&span.fact.occurrence_id)
                            })
                            .is_some(),
                        ComponentKind::Path | ComponentKind::Filename => false,
                    };
                if unexpected {
                    return Err(Error::ReconstructionRejected);
                }
                None
            }
        };
        accounting.record(span.fact.occurrence_id, action)?;
        output.push(AuthorizedOccurrence {
            raw: RawOccurrenceNode {
                occurrence_id: span.fact.occurrence_id,
                category: span.fact.category,
                component_kind,
                original_canonical_path: original_path,
                component_index,
                logical_file: baseline_entry.logical_id,
                source_span: span.start..span.end,
                occurrence_order: span.order,
                protected_anchor: span.protected_anchor,
            },
            action,
            edited_placement: placement,
        });
    }
    Ok(output)
}

fn path_placement(
    inputs: &ReconstructionInputs,
    reserved_forms: &ReservedFormIndex,
    edited_entry: &EditedEntry,
    oid: [u8; 16],
    component_index: u32,
) -> Result<ReconstructionPlacement> {
    let form_index = reserved_forms
        .by_oid
        .get(&oid)
        .copied()
        .ok_or(Error::ReconstructionRejected)?;
    let form = inputs
        .edited
        .forms
        .get(form_index)
        .ok_or(Error::ReconstructionRejected)?;
    if !form.authenticated_known
        || !form.authentication_valid
        || form.location_kind != ReservedLocationKind::Path
        || form.path != edited_entry.path
        || form.component_index != component_index
    {
        return Err(Error::ReconstructionRejected);
    }
    Ok(ReconstructionPlacement {
        occurrence_id: oid,
        start: usize::try_from(form.position).map_err(|_| Error::BoundExceeded)?,
        end: usize::try_from(form.end_position).map_err(|_| Error::BoundExceeded)?,
    })
}

fn validate_new_edited_entry(entry: &EditedEntry) -> Result<()> {
    if entry.protected_name
        || entry.hard_link
        || entry.named_stream
        || entry.new_sensitive_finding
        || !entry.path_form_range.is_empty()
        || !entry.content_form_range.is_empty()
    {
        return Err(Error::ReconstructionRejected);
    }
    match entry.kind {
        EditedEntryKind::Directory => {
            if entry.identity.is_none() || entry.byte_len != 0 || entry.exact_file_match.is_some() {
                return Err(Error::ReconstructionRejected);
            }
        }
        EditedEntryKind::File => {
            if !entry.supported_utf8_text
                || entry.invalid_utf8
                || entry.identity.is_none()
                || entry.exact_file_match.is_none()
            {
                return Err(Error::ReconstructionRejected);
            }
        }
        EditedEntryKind::Unsupported => return Err(Error::ReconstructionRejected),
    }
    Ok(())
}

fn entry_kinds_match(before: BaselineEntryKind, after: EditedEntryKind) -> bool {
    matches!(
        (before, after),
        (BaselineEntryKind::Directory, EditedEntryKind::Directory)
            | (BaselineEntryKind::File, EditedEntryKind::File)
    )
}

fn commit_candidate_model(
    inputs: &ReconstructionInputs,
    actions: &ReconstructionActions,
    reserved_forms: &ReservedFormIndex,
    plan: &CandidateNamespacePlan,
    path_projection: &CandidatePathProjection,
    schedule: &KeySchedule<'_>,
    accounting: &mut OccurrenceAccounting,
) -> Result<[u8; 32]> {
    let expected_entries = inputs
        .edited
        .entries
        .iter()
        .map(|entry| {
            let kind = match entry.kind {
                EditedEntryKind::Directory => CandidateEntryKind::Directory,
                EditedEntryKind::File => CandidateEntryKind::RegularFile,
                EditedEntryKind::Unsupported => return Err(Error::ReconstructionRejected),
            };
            Ok(ExpectedEditedEntry {
                path: entry.path.as_slice(),
                kind,
                byte_len: entry.byte_len,
                exact_file_match: entry.exact_file_match,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let mut projection = ProjectionReference::new(schedule, expected_entries)?;
    let projected_paths = derive_projected_ai_paths(inputs, plan, path_projection, schedule)?;
    let baseline_by_planned = inputs
        .baseline
        .entries
        .values()
        .filter_map(|entry| entry.planned_index.map(|index| (index, entry)))
        .collect::<BTreeMap<_, _>>();
    let edited_by_path = inputs
        .edited
        .entries
        .iter()
        .map(|entry| (entry.path.as_slice(), entry))
        .collect::<BTreeMap<_, _>>();
    let mut writer = CandidateCommitmentWriter::new(schedule, inputs.profile, plan)?;
    for (index, entry) in plan.entries().iter().enumerate() {
        match entry.content_action {
            CandidateContentAction::Directory => {
                if entry.kind != CandidateEntryKind::Directory {
                    return Err(Error::InvalidState);
                }
                writer.directory(plan, index)?;
                if entry.disposition == CandidateDisposition::AiVisible {
                    let _ = projected_edited_entry(
                        inputs,
                        entry,
                        &baseline_by_planned,
                        &edited_by_path,
                    )?;
                    projection.observe(
                        entry.disposition,
                        projected_paths
                            .get(&entry.canonical_path)
                            .ok_or(Error::ProjectedRetokenizationMismatch)?,
                        CandidateEntryKind::Directory,
                        None,
                    )?;
                }
            }
            CandidateContentAction::UseAcceptedEditedFile => {
                if entry.kind != CandidateEntryKind::RegularFile
                    || entry.source_relationship != CandidateSourceRelationship::NewEdited
                    || entry.disposition != CandidateDisposition::AiVisible
                {
                    return Err(Error::InvalidState);
                }
                let edited = inputs
                    .edited
                    .entries
                    .get(entry.source_index)
                    .ok_or(Error::InvalidState)?;
                let bytes = read_accepted_file(&inputs.ai, &edited_by_path, edited, schedule)?;
                write_file(&mut writer, plan, index, bytes.as_slice())?;
                projection.observe(
                    entry.disposition,
                    projected_paths
                        .get(&entry.canonical_path)
                        .ok_or(Error::ProjectedRetokenizationMismatch)?,
                    CandidateEntryKind::RegularFile,
                    Some(bytes.as_slice()),
                )?;
            }
            CandidateContentAction::ReconstructBaselineFile => {
                if entry.kind != CandidateEntryKind::RegularFile
                    || entry.source_relationship != CandidateSourceRelationship::BaselineCounterpart
                    || entry.disposition != CandidateDisposition::AiVisible
                {
                    return Err(Error::InvalidState);
                }
                let baseline_entry = baseline_by_planned
                    .get(&entry.source_index)
                    .copied()
                    .ok_or(Error::InvalidState)?;
                let planned = inputs
                    .baseline
                    .derivation
                    .plan
                    .entries
                    .get(entry.source_index)
                    .ok_or(Error::InvalidState)?;
                let edited =
                    projected_edited_entry(inputs, entry, &baseline_by_planned, &edited_by_path)?;
                let original_path = canonical_path(planned.original_components())?;
                let mut rederived =
                    rederive_planned_file(&inputs.original, planned, schedule, inputs.profile)?;
                rederived.release_safe_output();
                let accepted = read_accepted_file(&inputs.ai, &edited_by_path, edited, schedule)?;
                let authorized = authorize_occurrences(
                    OccurrenceAuthorizationContext {
                        inputs,
                        actions,
                        reserved_forms,
                        baseline_entry,
                        edited_entry: edited,
                        component_kind: ComponentKind::Content,
                    },
                    &original_path,
                    &rederived.content_occurrences,
                    accounting,
                )?;
                let reconstructed = reconstruct_authorized_component(
                    schedule,
                    rederived.original_bytes(),
                    accepted.as_slice(),
                    &authorized,
                )?;
                verify_reconstructed_component(
                    schedule,
                    rederived.original_bytes(),
                    accepted.as_slice(),
                    &authorized,
                    &reconstructed,
                )?;
                write_file(&mut writer, plan, index, reconstructed.bytes())?;
                projection.observe(
                    entry.disposition,
                    projected_paths
                        .get(&entry.canonical_path)
                        .ok_or(Error::ProjectedRetokenizationMismatch)?,
                    CandidateEntryKind::RegularFile,
                    Some(accepted.as_slice()),
                )?;
            }
            CandidateContentAction::PreserveOriginalFile => {
                if entry.kind != CandidateEntryKind::RegularFile
                    || entry.source_relationship != CandidateSourceRelationship::OriginalOnly
                    || entry.disposition != CandidateDisposition::OriginalOnly
                {
                    return Err(Error::InvalidState);
                }
                let planned = inputs
                    .baseline
                    .derivation
                    .plan
                    .entries
                    .get(entry.source_index)
                    .ok_or(Error::InvalidState)?;
                let bytes = read_planned_original_file(&inputs.original, planned, schedule)?;
                write_file(&mut writer, plan, index, bytes.as_slice())?;
            }
        }
    }
    projection.finish()?;
    writer.finish(plan)
}

fn derive_projected_ai_paths(
    inputs: &ReconstructionInputs,
    plan: &CandidateNamespacePlan,
    authority: &CandidatePathProjection,
    schedule: &KeySchedule<'_>,
) -> Result<BTreeMap<Vec<u8>, Vec<u8>>> {
    let mut entries = plan
        .entries()
        .iter()
        .filter(|entry| entry.disposition == CandidateDisposition::AiVisible)
        .collect::<Vec<_>>();
    if entries.len() != authority.by_candidate_path.len() {
        return Err(Error::ProjectedRetokenizationMismatch);
    }
    entries.sort_unstable_by(|left, right| {
        left.components
            .len()
            .cmp(&right.components.len())
            .then_with(|| left.canonical_path.cmp(&right.canonical_path))
    });
    let mut projected_directories = BTreeMap::<Vec<u8>, Vec<u8>>::new();
    let mut projected_entries = BTreeMap::new();
    for entry in entries {
        let fact = authority
            .by_candidate_path
            .get(&entry.canonical_path)
            .ok_or(Error::ProjectedRetokenizationMismatch)?;
        match (entry.source_relationship, fact.original_planned_index) {
            (CandidateSourceRelationship::BaselineCounterpart, Some(index))
                if index == entry.source_index => {}
            (CandidateSourceRelationship::NewEdited, None) => {}
            _ => return Err(Error::ProjectedRetokenizationMismatch),
        }
        let candidate_leaf = entry
            .components
            .last()
            .ok_or(Error::ProjectedRetokenizationMismatch)?
            .as_bytes();
        let original_leaf = match fact.original_planned_index {
            Some(index) => inputs
                .baseline
                .derivation
                .plan
                .entries
                .get(index)
                .and_then(|planned| planned.original_components().last())
                .map(String::as_bytes)
                .ok_or(Error::ProjectedRetokenizationMismatch)?,
            None => &[],
        };
        let projected_leaf = project_retokenized_component(
            schedule,
            original_leaf,
            &fact.accepted_edited_leaf,
            candidate_leaf,
            &fact.trace,
        )?;
        let projected_parent = if entry.components.len() == 1 {
            &[][..]
        } else {
            let parent = canonical_path(&entry.components[..entry.components.len() - 1])?;
            projected_directories
                .get(&parent)
                .map(Vec::as_slice)
                .ok_or(Error::ProjectedRetokenizationMismatch)?
        };
        let separator = usize::from(!projected_parent.is_empty());
        let capacity = projected_parent
            .len()
            .checked_add(separator)
            .and_then(|length| length.checked_add(projected_leaf.len()))
            .ok_or(Error::BoundExceeded)?;
        let mut projected = Vec::new();
        projected
            .try_reserve_exact(capacity)
            .map_err(|_| Error::BoundExceeded)?;
        projected.extend_from_slice(projected_parent);
        if separator != 0 {
            projected.push(b'/');
        }
        projected.extend_from_slice(&projected_leaf);
        if projected != fact.accepted_edited_path {
            return Err(Error::ProjectedRetokenizationMismatch);
        }
        if entry.kind == CandidateEntryKind::Directory
            && projected_directories
                .insert(entry.canonical_path.clone(), projected.clone())
                .is_some()
        {
            return Err(Error::ProjectedRetokenizationMismatch);
        }
        if projected_entries
            .insert(entry.canonical_path.clone(), projected)
            .is_some()
        {
            return Err(Error::ProjectedRetokenizationMismatch);
        }
    }
    Ok(projected_entries)
}

fn projected_edited_entry<'a>(
    inputs: &'a ReconstructionInputs,
    candidate: &super::candidate_model::CandidateNamespaceEntry,
    baseline_by_planned: &BTreeMap<usize, &'a BaselineEntry>,
    edited_by_path: &BTreeMap<&'a [u8], &'a EditedEntry>,
) -> Result<&'a EditedEntry> {
    match candidate.source_relationship {
        CandidateSourceRelationship::BaselineCounterpart => {
            let baseline = baseline_by_planned
                .get(&candidate.source_index)
                .copied()
                .ok_or(Error::InvalidState)?;
            let edited_path = inputs
                .correspondence
                .baseline_to_edited
                .get(&baseline.path)
                .map(|(path, _)| path)
                .ok_or(Error::InvalidState)?;
            edited_by_path
                .get(edited_path.as_slice())
                .copied()
                .ok_or(Error::InvalidState)
        }
        CandidateSourceRelationship::NewEdited => inputs
            .edited
            .entries
            .get(candidate.source_index)
            .ok_or(Error::InvalidState),
        CandidateSourceRelationship::OriginalOnly => Err(Error::InvalidState),
    }
}

fn write_file(
    writer: &mut CandidateCommitmentWriter,
    plan: &CandidateNamespacePlan,
    index: usize,
    bytes: &[u8],
) -> Result<()> {
    writer.begin_file(
        plan,
        index,
        u64::try_from(bytes.len()).map_err(|_| Error::BoundExceeded)?,
    )?;
    for chunk in bytes.chunks(64 * 1024) {
        writer.file_chunk(chunk)?;
    }
    writer.end_file()
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;
    use crate::roundtrip::approve::approve_review_event;
    use crate::roundtrip::create::create_session;
    use crate::roundtrip::crypto::{SessionId, SessionMasterSecret};
    use crate::roundtrip::review::review_session;
    use crate::roundtrip::token::{
        decode_base32_128, generate_token, EntryKind, OccurrenceDescriptor, ReviewProfile,
        TOKEN_PREFIX,
    };

    static NEXT_SESSION_FIXTURE: AtomicU64 = AtomicU64::new(0);

    fn assert_protected_occurrence_authority_is_field_aware(mismatch_error: Error) {
        let retained_anchor = [0x31; 32];
        let mut rederived_anchor = retained_anchor;
        verify_protected_occurrence_authority(
            ProtectedOccurrenceAuthority {
                component_kind: ComponentKind::Content,
                retained_entry_path: b"src/main.txt",
                rederived_entry_path: b"src/main.txt",
                retained_category: TokenCategory::Email,
                rederived_category: TokenCategory::Email,
                retained_anchor: &retained_anchor,
                rederived_anchor: &rederived_anchor,
            },
            mismatch_error,
        )
        .expect("exact protected occurrence authority");

        assert_eq!(
            verify_protected_occurrence_authority(
                ProtectedOccurrenceAuthority {
                    component_kind: ComponentKind::Content,
                    retained_entry_path: b"src/main.txt",
                    rederived_entry_path: b"src/other.txt",
                    retained_category: TokenCategory::Email,
                    rederived_category: TokenCategory::Email,
                    retained_anchor: &retained_anchor,
                    rederived_anchor: &rederived_anchor,
                },
                mismatch_error,
            ),
            Err(mismatch_error)
        );

        rederived_anchor[18] ^= 1;
        assert_eq!(
            verify_protected_occurrence_authority(
                ProtectedOccurrenceAuthority {
                    component_kind: ComponentKind::Content,
                    retained_entry_path: b"src/main.txt",
                    rederived_entry_path: b"src/main.txt",
                    retained_category: TokenCategory::Email,
                    rederived_category: TokenCategory::Email,
                    retained_anchor: &retained_anchor,
                    rederived_anchor: &rederived_anchor,
                },
                mismatch_error,
            ),
            Err(mismatch_error)
        );
    }

    #[test]
    fn deleted_span_protected_authority_is_field_aware() {
        assert_protected_occurrence_authority_is_field_aware(Error::OccurrenceGraphMismatch);
    }

    #[test]
    fn authorized_occurrence_protected_authority_is_field_aware() {
        assert_protected_occurrence_authority_is_field_aware(Error::ReconstructionRejected);
    }

    #[test]
    fn path_occurrence_has_no_content_anchor_authority() {
        let retained_anchor = [0x31; 32];
        let mut rederived_anchor = retained_anchor;
        rederived_anchor[18] ^= 1;
        verify_protected_occurrence_authority(
            ProtectedOccurrenceAuthority {
                component_kind: ComponentKind::Path,
                retained_entry_path: b"src/main.txt",
                rederived_entry_path: b"src/main.txt",
                retained_category: TokenCategory::Email,
                rederived_category: TokenCategory::Email,
                retained_anchor: &retained_anchor,
                rederived_anchor: &rederived_anchor,
            },
            Error::ReconstructionRejected,
        )
        .expect("path occurrences have no content protected-anchor authority");
    }

    #[test]
    fn final_capsule_authority_mismatch_remains_invalid_state() {
        let tag = [0x41; 32];
        let mut mismatch = tag;
        mismatch[23] ^= 1;
        assert!(require_final_capsule_tag(&tag, &tag).is_ok());
        assert_eq!(
            require_final_capsule_tag(&tag, &mismatch),
            Err(Error::InvalidState)
        );
    }

    struct SessionFixture {
        root: PathBuf,
        original: PathBuf,
        ai: PathBuf,
        state: PathBuf,
    }

    impl SessionFixture {
        fn new(profile: ReviewProfile, setup: impl FnOnce(&Path)) -> Self {
            let serial = NEXT_SESSION_FIXTURE.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir().join(format!(
                "safeclone-reconstruction-{}-{serial}",
                std::process::id()
            ));
            let original = root.join("OriginalWorkspaceLongName");
            let ai = root.join("AiWorkspaceLongName");
            let state = root.join("PrivateSessionLongName");
            fs::create_dir_all(&original).expect("create Original fixture");
            setup(&original);
            create_session(&original, &ai, &state, profile).expect("create reconstruction session");
            Self {
                root,
                original,
                ai,
                state,
            }
        }

        fn review_and_approve_all(&self) {
            let reviewed = review_session(&self.original, &self.ai, &self.state)
                .expect("fresh reconstruction review");
            let review_id = decode_base32_128(&reviewed.report().review_id).expect("review id");
            let approvals = reviewed.report().approval_events.clone();
            for approval in approvals {
                if approval.approved {
                    continue;
                }
                approve_review_event(
                    &self.original,
                    &self.ai,
                    &self.state,
                    review_id,
                    decode_base32_128(&approval.event_id).expect("event id"),
                    approval.required_reason,
                )
                .expect("approve reconstruction event");
            }
            let ready =
                review_session(&self.original, &self.ai, &self.state).expect("replay ready review");
            assert_eq!(ready.report().session_state, SessionState::ReadyToApply);
            assert_eq!(ready.report().remaining_approval_events, 0);
            assert_eq!(ready.report().unconditional_rejects, 0);
        }
    }

    impl Drop for SessionFixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn snapshot_tree(root: &Path) -> Vec<(PathBuf, Option<Vec<u8>>)> {
        fn visit(root: &Path, current: &Path, output: &mut Vec<(PathBuf, Option<Vec<u8>>)>) {
            let mut children = fs::read_dir(current)
                .expect("read snapshot directory")
                .map(|entry| entry.expect("snapshot entry").path())
                .collect::<Vec<_>>();
            children.sort();
            for child in children {
                let relative = child
                    .strip_prefix(root)
                    .expect("relative snapshot path")
                    .to_path_buf();
                if child.is_dir() {
                    output.push((relative, None));
                    visit(root, &child, output);
                } else {
                    output.push((relative, Some(fs::read(&child).expect("snapshot bytes"))));
                }
            }
        }
        let mut output = Vec::new();
        visit(root, root, &mut output);
        output
    }

    fn first_token_range(bytes: &[u8]) -> Range<usize> {
        let prefix = TOKEN_PREFIX.as_bytes();
        let start = bytes
            .windows(prefix.len())
            .position(|window| window == prefix)
            .expect("fixture token");
        let body = start + prefix.len();
        let suffix = bytes[body..]
            .windows(2)
            .position(|window| window == b"__")
            .expect("token suffix");
        start..body + suffix + 2
    }

    fn token_file(email: &str) -> Vec<u8> {
        let mut value = Vec::new();
        for line in 0..12 {
            value.extend_from_slice(format!("before-{line:02}\n").as_bytes());
        }
        value.extend_from_slice(format!("contact={email}\n").as_bytes());
        for line in 0..12 {
            value.extend_from_slice(format!("after-{line:02}\n").as_bytes());
        }
        value
    }

    struct FixtureToken {
        oid: [u8; 16],
        category: TokenCategory,
        token: Vec<u8>,
        anchor: [u8; 32],
    }

    fn fixture_token(
        schedule: &KeySchedule<'_>,
        path: &[u8],
        raw: &[u8],
        source_start: usize,
        ordinal: u32,
    ) -> FixtureToken {
        let anchor = [ordinal as u8 + 1; 32];
        let descriptor = OccurrenceDescriptor {
            session_id: schedule.session_id(),
            ruleset_id: crate::roundtrip::ruleset::ruleset_id(),
            review_profile: ReviewProfile::StandardV2,
            entry_kind: EntryKind::RegularFile,
            canonical_original_relative_path: path,
            component_index: 0,
            component_kind: ComponentKind::Content,
            byte_span_start: source_start as u64,
            byte_span_end: (source_start + raw.len()) as u64,
            category: TokenCategory::Email,
            occurrence_ordinal_within_component: ordinal,
            pre_token_anchor_commitment: anchor,
        };
        let token = generate_token(schedule, &descriptor)
            .expect("token")
            .into_bytes();
        let parsed = parse_token(std::str::from_utf8(&token).expect("utf8")).expect("parse");
        FixtureToken {
            oid: *parsed.occurrence_id(),
            category: TokenCategory::Email,
            token,
            anchor,
        }
    }

    fn authorized<'a>(
        path: &'a [u8],
        original_spans: &[(usize, usize)],
        edited_spans: &[(usize, usize)],
        tokens: &[FixtureToken],
        deleted: &[bool],
    ) -> Vec<AuthorizedOccurrence<'a>> {
        tokens
            .iter()
            .enumerate()
            .map(|(index, token)| AuthorizedOccurrence {
                raw: RawOccurrenceNode {
                    occurrence_id: token.oid,
                    category: token.category,
                    component_kind: ComponentKind::Content,
                    original_canonical_path: path,
                    component_index: 0,
                    logical_file: [0x44; 32],
                    source_span: original_spans[index].0..original_spans[index].1,
                    occurrence_order: index as u32,
                    protected_anchor: token.anchor,
                },
                action: if deleted[index] {
                    OccurrenceAction::DeleteOccurrence
                } else {
                    OccurrenceAction::RestoreOriginalOccurrence
                },
                edited_placement: (!deleted[index]).then_some(ReconstructionPlacement {
                    occurrence_id: token.oid,
                    start: edited_spans[index].0,
                    end: edited_spans[index].1,
                }),
            })
            .collect()
    }

    #[test]
    fn exact_reconstruction_handles_multiple_same_value_and_deletion_with_far_edits() {
        let master = SessionMasterSecret::from_bytes([0x91; 32]);
        let schedule = KeySchedule::new(&master, SessionId::from_bytes([0x92; 16]));
        let path = b"src/main.txt";
        let first = fixture_token(&schedule, path, b"same@example.invalid", 2, 0);
        let second = fixture_token(&schedule, path, b"same@example.invalid", 25, 1);
        assert_ne!(first.oid, second.oid);
        let original = b"A=same@example.invalid\nB=same@example.invalid\n";
        let mut edited = b"far edit before\nA=".to_vec();
        let first_start = edited.len();
        edited.extend_from_slice(&first.token);
        let first_end = edited.len();
        edited.extend_from_slice(b"\nfar edit after\n");
        let occurrences = authorized(
            path,
            &[(2, 22), (25, 45)],
            &[(first_start, first_end), (0, 0)],
            &[first, second],
            &[false, true],
        );
        let reconstructed =
            reconstruct_authorized_component(&schedule, original, &edited, &occurrences)
                .expect("reconstruct");
        assert_eq!(
            reconstructed.bytes(),
            b"far edit before\nA=same@example.invalid\nfar edit after\n"
        );
        assert_eq!(reconstructed.trace().len(), 1);
    }

    #[test]
    fn two_preserved_tokens_on_one_line_round_trip_through_independent_reference() {
        let master = SessionMasterSecret::from_bytes([0x96; 32]);
        let schedule = KeySchedule::new(&master, SessionId::from_bytes([0x97; 16]));
        let path = b"src/pair.txt";
        let raw = b"same@example.invalid";
        let original = b"first=same@example.invalid second=same@example.invalid\n";
        let first = fixture_token(&schedule, path, raw, 6, 0);
        let second = fixture_token(&schedule, path, raw, 34, 1);
        assert_ne!(first.oid, second.oid);

        let mut edited = b"ordinary edit before ".to_vec();
        let first_start = edited.len();
        edited.extend_from_slice(&first.token);
        let first_end = edited.len();
        edited.extend_from_slice(b" and ");
        let second_start = edited.len();
        edited.extend_from_slice(&second.token);
        let second_end = edited.len();
        edited.extend_from_slice(b" ordinary edit after\n");
        let occurrences = authorized(
            path,
            &[(6, 26), (34, 54)],
            &[(first_start, first_end), (second_start, second_end)],
            &[first, second],
            &[false, false],
        );
        let reconstructed =
            reconstruct_authorized_component(&schedule, original, &edited, &occurrences)
                .expect("reconstruct two preserved occurrences");
        assert_eq!(
            reconstructed.bytes(),
            b"ordinary edit before same@example.invalid and same@example.invalid ordinary edit after\n"
        );
        verify_reconstructed_component(&schedule, original, &edited, &occurrences, &reconstructed)
            .expect("independent projected retokenization");
    }

    #[test]
    fn action_and_order_fail_closed() {
        let master = SessionMasterSecret::from_bytes([0xa1; 32]);
        let schedule = KeySchedule::new(&master, SessionId::from_bytes([0xa2; 16]));
        let path = b"main.txt";
        let first = fixture_token(&schedule, path, b"a@example.invalid", 0, 0);
        let second = fixture_token(&schedule, path, b"b@example.invalid", 18, 1);
        let mut edited = second.token.clone();
        let boundary = edited.len();
        edited.extend_from_slice(&first.token);
        let occurrences = authorized(
            path,
            &[(0, 17), (18, 35)],
            &[(boundary, edited.len()), (0, boundary)],
            &[first, second],
            &[false, false],
        );
        assert_eq!(
            reconstruct_authorized_component(
                &schedule,
                b"a@example.invalid b@example.invalid",
                &edited,
                &occurrences
            )
            .err(),
            Some(Error::ReconstructionRejected)
        );
    }

    #[test]
    fn standard_v2_fresh_authority_reconstructs_without_any_state_publication() {
        let fixture = SessionFixture::new(ReviewProfile::StandardV2, |original| {
            fs::create_dir(original.join("shared")).expect("shared directory");
            fs::write(
                original.join("shared").join("main.txt"),
                token_file("standard.user@example.invalid"),
            )
            .expect("standard token file");
            fs::write(
                original.join("shared").join("opaque.bin"),
                b"opaque\0fixture",
            )
            .expect("binary original-only");
            fs::write(original.join("invalid.txt"), b"invalid\xffutf8")
                .expect("invalid UTF-8 original-only");
            fs::write(
                original.join("credentials.txt"),
                b"filename policy omission\n",
            )
            .expect("sensitive filename original-only");
        });
        fs::rename(fixture.ai.join("shared"), fixture.ai.join("renamed-shared"))
            .expect("accepted ancestor rename");
        let edited_path = fixture.ai.join("renamed-shared").join("main.txt");
        let bytes = fs::read(&edited_path).expect("read AI file");
        let token = first_token_range(&bytes);
        let mut edited = b"ordinary far edit\n".to_vec();
        edited.extend_from_slice(&bytes[b"before-00\n".len()..token.start]);
        edited.extend_from_slice(&bytes[token.end..]);
        fs::write(&edited_path, edited).expect("delete exact token");
        fixture.review_and_approve_all();

        let before = snapshot_tree(&fixture.root);
        let summary = reconstruct_session_model(&fixture.original, &fixture.ai, &fixture.state)
            .expect("reconstruction Standard model");
        let after = snapshot_tree(&fixture.root);
        assert_eq!(before, after, "reconstruction must be entirely read-only");
        assert_eq!(summary.profile, ReviewProfile::StandardV2);
        assert_eq!(summary.deleted_occurrences, 1);
        assert_eq!(summary.restored_occurrences, 0);
        assert!(summary.original_only_entries >= 4);
        assert_ne!(summary.expected_candidate_tree_commitment, [0; 32]);
    }

    #[test]
    fn standard_v2_multiple_runs_accept_intact_relocation_and_token_free_edit() {
        let fixture = SessionFixture::new(ReviewProfile::StandardV2, |original| {
            fs::write(
                original.join("multiple-runs.txt"),
                b"top-a\ntop-b\ncontext-left-a\ncredential=first.run@example.invalid;\ncontext-right-a\nbottom-a\nbottom-b\nseparator-a\nseparator-b\ntop-c\ntop-d\ncontext-left-b\ncredential=second.run@example.invalid;\ncontext-right-b\nbottom-c\nbottom-d\n",
            )
            .expect("multiple StandardV2 runs");
            fs::write(original.join("ordinary.txt"), b"token-free before\n")
                .expect("token-free baseline file");
        });

        let path = fixture.ai.join("multiple-runs.txt");
        let baseline = fs::read(&path).expect("read multiple-run AI baseline");
        let block_start = baseline
            .windows(b"context-left-a\n".len())
            .position(|window| window == b"context-left-a\n")
            .expect("relocated block start");
        let block_tail = b"context-right-a\n";
        let block_end = baseline[block_start..]
            .windows(block_tail.len())
            .position(|window| window == block_tail)
            .and_then(|offset| {
                block_start
                    .checked_add(offset)
                    .and_then(|value| value.checked_add(block_tail.len()))
            })
            .expect("relocated block end");
        let mut without_block = Vec::new();
        without_block.extend_from_slice(&baseline[..block_start]);
        without_block.extend_from_slice(&baseline[block_end..]);
        let insertion = without_block
            .windows(b"bottom-a\n".len())
            .position(|window| window == b"bottom-a\n")
            .and_then(|offset| offset.checked_add(b"bottom-a\n".len()))
            .expect("relocation insertion point");
        let mut edited = b"ordinary edit before\n".to_vec();
        edited.extend_from_slice(&without_block[..insertion]);
        edited.extend_from_slice(&baseline[block_start..block_end]);
        edited.extend_from_slice(&without_block[insertion..]);
        edited.extend_from_slice(b"ordinary edit after\n");
        fs::write(path, edited).expect("move intact logical block");
        fs::write(
            fixture.ai.join("ordinary.txt"),
            b"token-free modified after create\n",
        )
        .expect("modify token-free file");
        fixture.review_and_approve_all();

        let before = snapshot_tree(&fixture.root);
        let summary = reconstruct_session_model(&fixture.original, &fixture.ai, &fixture.state)
            .expect("multiple-run reconstruction model");
        assert_eq!(before, snapshot_tree(&fixture.root));
        assert_eq!(summary.restored_occurrences, 2);
        assert_eq!(summary.deleted_occurrences, 0);
    }

    #[test]
    fn strict_v2_approval_authorizes_standard_reconstruction_bytes_only() {
        let fixture = SessionFixture::new(ReviewProfile::StrictTokenFilesV2, |original| {
            fs::write(
                original.join("strict.txt"),
                token_file("strict.user@example.invalid"),
            )
            .expect("strict token file");
        });
        let path = fixture.ai.join("strict.txt");
        let bytes = fs::read(&path).expect("read strict AI file");
        let mut edited = b"strict ordinary far edit\n".to_vec();
        edited.extend_from_slice(&bytes[b"before-00\n".len()..]);
        fs::write(&path, edited).expect("strict ordinary edit");
        fixture.review_and_approve_all();

        let before = snapshot_tree(&fixture.root);
        let summary = reconstruct_session_model(&fixture.original, &fixture.ai, &fixture.state)
            .expect("reconstruction Strict model");
        assert_eq!(before, snapshot_tree(&fixture.root));
        assert_eq!(summary.profile, ReviewProfile::StrictTokenFilesV2);
        assert_eq!(summary.restored_occurrences, 1);
        assert_eq!(summary.deleted_occurrences, 0);
        assert_ne!(summary.expected_candidate_tree_commitment, [0; 32]);
    }

    #[test]
    fn preserved_directory_and_filename_tokens_restore_exact_original_paths() {
        let fixture = SessionFixture::new(ReviewProfile::StandardV2, |original| {
            let directory = original.join("fixture.user+test@example.invalid");
            fs::create_dir(&directory).expect("token directory");
            fs::write(
                directory.join("address-192.0.2.10.txt"),
                b"ordinary token-free content\n",
            )
            .expect("path-token file");
        });
        fixture.review_and_approve_all();
        let before = snapshot_tree(&fixture.root);
        let model = prepare_reconstruction_model(&fixture.original, &fixture.ai, &fixture.state)
            .expect("preserved path model");
        let paths = model
            .plan()
            .entries()
            .iter()
            .map(|entry| {
                std::str::from_utf8(&entry.canonical_path)
                    .expect("candidate UTF-8")
                    .to_owned()
            })
            .collect::<Vec<_>>();
        assert!(paths.contains(&"fixture.user+test@example.invalid".to_owned()));
        assert!(
            paths.contains(&"fixture.user+test@example.invalid/address-192.0.2.10.txt".to_owned())
        );
        assert_eq!(model.restored_occurrences(), 2);
        drop(model);
        assert_eq!(before, snapshot_tree(&fixture.root));
    }

    #[test]
    fn path_deletion_and_token_free_move_use_the_exact_accepted_topology() {
        let fixture = SessionFixture::new(ReviewProfile::StandardV2, |original| {
            fs::write(
                original.join("address-192.0.2.10.txt"),
                b"ordinary path deletion content\n",
            )
            .expect("path-token file");
            fs::write(original.join("plain.txt"), b"token-free counterpart\n")
                .expect("token-free file");
        });
        let token_file = fs::read_dir(&fixture.ai)
            .expect("AI root")
            .map(|entry| entry.expect("AI entry"))
            .find(|entry| entry.file_name().to_string_lossy().contains(TOKEN_PREFIX))
            .expect("token filename");
        let token_name = token_file
            .file_name()
            .into_string()
            .expect("token filename UTF-8");
        let token = first_token_range(token_name.as_bytes());
        let projected_name = format!("{}{}", &token_name[..token.start], &token_name[token.end..]);
        fs::rename(token_file.path(), fixture.ai.join(&projected_name))
            .expect("exact path-token deletion");
        fs::create_dir(fixture.ai.join("moved")).expect("new safe directory");
        fs::rename(
            fixture.ai.join("plain.txt"),
            fixture.ai.join("moved").join("renamed.txt"),
        )
        .expect("token-free rename and move");
        fs::write(fixture.ai.join("new.txt"), b"new safe text\n").expect("new safe text file");
        fixture.review_and_approve_all();

        let model = prepare_reconstruction_model(&fixture.original, &fixture.ai, &fixture.state)
            .expect("accepted path topology model");
        let paths = model
            .plan()
            .entries()
            .iter()
            .map(|entry| entry.canonical_path.clone())
            .collect::<Vec<_>>();
        assert!(paths.contains(&projected_name.as_bytes().to_vec()));
        assert!(paths.contains(&b"moved/renamed.txt".to_vec()));
        assert!(paths.contains(&b"new.txt".to_vec()));
        assert!(!paths.iter().any(|path| {
            path.windows(b"192.0.2.10".len())
                .any(|window| window == b"192.0.2.10")
        }));
        assert_eq!(model.deleted_occurrences(), 1);
    }

    #[test]
    fn approved_file_deletion_requires_file_and_every_constituent_token_approval() {
        let fixture = SessionFixture::new(ReviewProfile::StandardV2, |original| {
            fs::write(
                original.join("token.txt"),
                token_file("deleted.user@example.invalid"),
            )
            .expect("token-bearing file");
            fs::write(original.join("plain.txt"), b"plain deleted file\n")
                .expect("token-free file");
        });
        fs::remove_file(fixture.ai.join("token.txt")).expect("delete token file");
        fs::remove_file(fixture.ai.join("plain.txt")).expect("delete plain file");
        fixture.review_and_approve_all();
        let model = prepare_reconstruction_model(&fixture.original, &fixture.ai, &fixture.state)
            .expect("approved file deletion model");
        assert!(model.plan().entries().is_empty());
        assert_eq!(model.deleted_occurrences(), 1);
        assert_eq!(model.restored_occurrences(), 0);

        for approve_file_event in [false, true] {
            let incomplete = SessionFixture::new(ReviewProfile::StandardV2, |original| {
                fs::write(
                    original.join("token.txt"),
                    token_file("partial.user@example.invalid"),
                )
                .expect("partial token file");
            });
            fs::remove_file(incomplete.ai.join("token.txt")).expect("delete partial file");
            let reviewed = review_session(&incomplete.original, &incomplete.ai, &incomplete.state)
                .expect("partial review");
            let review_id =
                decode_base32_128(&reviewed.report().review_id).expect("partial review id");
            let selected = reviewed
                .report()
                .approval_events
                .iter()
                .find(|event| {
                    let is_file = event.event_type
                        == crate::roundtrip::schema::ApprovalEventType::FileDeleted;
                    is_file == approve_file_event
                })
                .expect("selected constituent approval");
            let outcome = approve_review_event(
                &incomplete.original,
                &incomplete.ai,
                &incomplete.state,
                review_id,
                decode_base32_128(&selected.event_id).expect("partial event id"),
                selected.required_reason,
            )
            .expect("single partial approval");
            assert_eq!(outcome.session_state, SessionState::ApprovedPartial);
            assert_eq!(
                reconstruct_session_model(&incomplete.original, &incomplete.ai, &incomplete.state)
                    .expect_err("incomplete approvals reject")
                    .error(),
                Error::InvalidState
            );
        }
    }
}
