//! One-way classification authority to ChangedManifestV1 reporting projection.
//!
//! This module consumes the complete fresh classification event authority. Reporting
//! regions are derived independently from AI-safe bytes and never feed back
//! into classification, identifiers, anchors, approvals, or reconstruction.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

use super::classify::{PreparedReviewAuthority, ReviewEntryAuthority, ReviewEntryAuthorityKind};
use super::events::{CanonicalEvent, EventDecision, EventKind, StructuralReason};
use super::manifest::{
    required_manifest_event_state, sorted_reasons, AnchorKindV1, AnchorStatusV1, AnchorV1,
    ApprovalStateV1, ChangedManifestPhaseV1, ChangedManifestV1, ContentEventV1, DirectoryChangeV1,
    DirectoryEventV1, FileChangeV1, FileEventV1, ManifestApprovalSemanticV1, ManifestDecisionV1,
    ManifestSummaryV1, OriginalTreeConsistencyV1, ReasonCodeV1, ReconstructionStatusV1,
    TokenEventKindV1, TokenEventV1,
};
use super::report_diff::{
    ContentChangeRegionV1, DiffLimits, ReportingFile, ReviewDiffBudget, StrictLineDiff,
};
use super::review_identity::ReviewIdentityIndex;
use super::review_ids::{content_anchor_id, path_anchor_id};
use super::{Error, Result};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EventProjectionTarget {
    Token,
    File,
    Directory,
    StructuralOwner,
    PreservedOrSuppressed,
}

/// Exhaustive mechanical registry gate for all current classification event kinds.
pub(crate) const fn event_projection_target(kind: EventKind) -> EventProjectionTarget {
    match kind {
        EventKind::PreservedSameAnchor => EventProjectionTarget::PreservedOrSuppressed,
        EventKind::TokenDeleted
        | EventKind::ProtectedContextChanged
        | EventKind::ProtectedCoreChanged
        | EventKind::AnchorAmbiguous
        | EventKind::MovedToOtherFile
        | EventKind::PathMoved
        | EventKind::TokenDuplicated
        | EventKind::TokenModified
        | EventKind::TokenUnknown
        | EventKind::CategoryMismatch
        | EventKind::TokenOrderChanged => EventProjectionTarget::Token,
        EventKind::FileModified
        | EventKind::FileDeleted
        | EventKind::FileRenamed
        | EventKind::FileMoved
        | EventKind::NewTextFile
        | EventKind::StrictTokenFileModified => EventProjectionTarget::File,
        EventKind::DirectoryAdded
        | EventKind::DirectoryDeleted
        | EventKind::DirectoryRenamed
        | EventKind::DirectoryMoved => EventProjectionTarget::Directory,
        EventKind::NewUntokenizedSensitiveFinding
        | EventKind::UnsupportedAddition
        | EventKind::LinkLikeAddition
        | EventKind::HardLink
        | EventKind::AlternateDataStream
        | EventKind::ProtectedNamespace
        | EventKind::OmittedPathCollision
        | EventKind::InvalidUtf8 => EventProjectionTarget::StructuralOwner,
    }
}

pub(crate) struct ProjectedReview {
    pub(crate) manifest: ChangedManifestV1,
    pub(crate) review_id: [u8; 16],
}

pub(crate) fn project_apply_result(
    review: &ChangedManifestV1,
    owning_generation: u64,
    preserved_original_only_files: u32,
    preserved_original_only_bytes: u64,
) -> Result<ChangedManifestV1> {
    super::manifest::validate_changed_manifest_v1(review)?;
    if review.manifest_phase != ChangedManifestPhaseV1::Review
        || review.summary.unconditional_rejects != 0
        || owning_generation == 0
    {
        return Err(Error::InvalidState);
    }
    let mut result = review.clone();
    result.manifest_phase = ChangedManifestPhaseV1::ApplyResult;
    result.capsule_generation = owning_generation;
    result.original_tree_consistency = OriginalTreeConsistencyV1::Match;
    result.reconstruction_status = ReconstructionStatusV1::Pass;
    result.semantic_safety_assessed = false;
    result.summary.approved_events = result.summary.approval_eligible_events;
    result.summary.unapproved_events = 0;
    result.summary.preserved_original_only_files = preserved_original_only_files;
    result.summary.preserved_original_only_bytes = preserved_original_only_bytes;
    result.failure_reason_codes.clear();
    for file in &mut result.files {
        approve_manifest_decision(
            &mut file.decision,
            &mut file.approval_state,
            ManifestApprovalSemanticV1::ApprovalBearingEntry,
        )?;
        for event in &mut file.token_events {
            approve_manifest_decision(
                &mut event.decision,
                &mut event.approval_state,
                token_approval_semantic(event.event),
            )?;
        }
    }
    for directory in &mut result.directories {
        approve_manifest_decision(
            &mut directory.decision,
            &mut directory.approval_state,
            ManifestApprovalSemanticV1::ApprovalBearingEntry,
        )?;
        for event in &mut directory.token_events {
            approve_manifest_decision(
                &mut event.decision,
                &mut event.approval_state,
                token_approval_semantic(event.event),
            )?;
        }
    }
    super::manifest::validate_changed_manifest_v1(&result)?;
    Ok(result)
}

const fn token_approval_semantic(event: TokenEventKindV1) -> ManifestApprovalSemanticV1 {
    match event {
        TokenEventKindV1::TokenDeleted => ManifestApprovalSemanticV1::TokenDeleted,
        TokenEventKindV1::PreservedSameAnchor
        | TokenEventKindV1::TokenMovedWithinFile
        | TokenEventKindV1::TokenMovedToOtherFile
        | TokenEventKindV1::TokenDuplicated
        | TokenEventKindV1::TokenModified
        | TokenEventKindV1::TokenUnknown
        | TokenEventKindV1::CategoryMismatch
        | TokenEventKindV1::TokenOrderChanged
        | TokenEventKindV1::ProtectedContextChanged
        | TokenEventKindV1::ProtectedCoreChanged
        | TokenEventKindV1::AnchorAmbiguous
        | TokenEventKindV1::PathMoved => ManifestApprovalSemanticV1::ApprovalBearingEntry,
    }
}

fn approve_manifest_decision(
    decision: &mut ManifestDecisionV1,
    approval: &mut ApprovalStateV1,
    semantic: ManifestApprovalSemanticV1,
) -> Result<()> {
    if *decision == ManifestDecisionV1::ApprovalRequired && *approval == ApprovalStateV1::Required {
        let (target_decision, target_approval) =
            required_manifest_event_state(ChangedManifestPhaseV1::ApplyResult, semantic)
                .ok_or(Error::InvalidState)?;
        *decision = target_decision;
        *approval = target_approval;
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum DecisionStrength {
    Automatic,
    ApprovalRequired,
    Reject,
}

impl DecisionStrength {
    const fn manifest(self) -> ManifestDecisionV1 {
        match self {
            Self::Automatic => ManifestDecisionV1::Automatic,
            Self::ApprovalRequired => ManifestDecisionV1::ApprovalRequired,
            Self::Reject => ManifestDecisionV1::Reject,
        }
    }
}

struct EntryState<'a> {
    authority: &'a ReviewEntryAuthority,
    id: [u8; 16],
    needed: bool,
    strict: bool,
    decision: DecisionStrength,
    has_token_approval: bool,
    has_other_approval: bool,
    reasons: BTreeSet<ReasonCodeV1>,
    token_events: Vec<TokenEventV1>,
    anchors: BTreeMap<[u8; 16], AnchorV1>,
    anchor_by_oid: BTreeMap<[u8; 16], [u8; 16]>,
}

impl EntryState<'_> {
    fn apply_decision(&mut self, event: &CanonicalEvent) {
        if event.decision == EventDecision::Reject {
            self.decision = DecisionStrength::Reject;
        } else if event.decision == EventDecision::ApprovalRequired
            && self.decision != DecisionStrength::Reject
        {
            self.decision = DecisionStrength::ApprovalRequired;
            if event.kind == EventKind::TokenDeleted {
                self.has_token_approval = true;
            } else {
                self.has_other_approval = true;
            }
        }
    }

    fn apply_event(&mut self, event: &CanonicalEvent) -> Result<()> {
        self.apply_decision(event);
        self.reasons.extend(reason_codes(event)?);
        Ok(())
    }

    fn inherit(&mut self, child: &Self) {
        self.decision = self.decision.max(child.decision);
        self.has_token_approval |= child.has_token_approval;
        self.has_other_approval |= child.has_other_approval;
    }
}

pub(crate) fn project_review(
    authority: &PreparedReviewAuthority,
    identities: &ReviewIdentityIndex,
    owning_generation: u64,
) -> Result<ProjectedReview> {
    if owning_generation == 0 || authority.report.semantic_safety_assessed {
        return Err(Error::InvalidState);
    }
    let schedule = authority.owner.key_schedule();
    let review_id = identities.review_id();

    let mut states = Vec::new();
    states
        .try_reserve_exact(authority.entries.len())
        .map_err(|_| Error::BoundExceeded)?;
    for (index, entry) in authority.entries.iter().enumerate() {
        let id = identities.entry_id(index)?;
        let needed = entry.safe_path_before != entry.safe_path_after
            || match entry.kind {
                ReviewEntryAuthorityKind::File => file_bytes_changed(entry),
                ReviewEntryAuthorityKind::Directory => false,
            };
        states.push(EntryState {
            authority: entry,
            id,
            needed,
            strict: false,
            decision: DecisionStrength::Automatic,
            has_token_approval: false,
            has_other_approval: false,
            reasons: BTreeSet::new(),
            token_events: Vec::new(),
            anchors: BTreeMap::new(),
            anchor_by_oid: BTreeMap::new(),
        });
    }
    // Establish all changed/relevant owners before deciding whether an exact
    // PRESERVED_SAME_ANCHOR record is explanatory or suppressible.
    for (event_index, event) in authority.events.events().iter().enumerate() {
        let target = event_projection_target(event.kind);
        if target != EventProjectionTarget::PreservedOrSuppressed {
            let identity = identities.event(event_index)?;
            if identity.event_index != event_index {
                return Err(Error::InvalidState);
            }
            states
                .get_mut(identity.owner_index)
                .ok_or(Error::InvalidState)?
                .needed = true;
        }
    }

    for state in &mut states {
        derive_anchor_registry(state, &schedule, &authority.original_tree_commitment)?;
    }

    let mut accounted = 0usize;
    let mut preserved_tokens = 0u32;
    let mut deleted_tokens = 0u32;
    let mut new_sensitive_findings = 0u32;
    for (event_index, event) in authority.events.events().iter().enumerate() {
        let target = event_projection_target(event.kind);
        let identity = identities.event(event_index)?;
        if identity.event_index != event_index {
            return Err(Error::InvalidState);
        }
        let before_id = identities.before_entry_id(event.before_path.as_deref());
        let after_id = identities.after_entry_id(event.after_path.as_deref());
        let state = states
            .get_mut(identity.owner_index)
            .ok_or(Error::InvalidState)?;
        match target {
            EventProjectionTarget::PreservedOrSuppressed => {
                preserved_tokens = preserved_tokens
                    .checked_add(1)
                    .ok_or(Error::BoundExceeded)?;
                if state.needed {
                    state.token_events.push(project_token_event(
                        event,
                        state,
                        &before_id,
                        &after_id,
                        identity.event_id,
                    )?);
                    update_anchor_status(state, event)?;
                }
            }
            EventProjectionTarget::Token => {
                if event.kind == EventKind::TokenDeleted {
                    deleted_tokens = deleted_tokens.checked_add(1).ok_or(Error::BoundExceeded)?;
                }
                let token =
                    project_token_event(event, state, &before_id, &after_id, identity.event_id)?;
                state.token_events.push(token);
                update_anchor_status(state, event)?;
                // The token record owns its exact reasons. The parent keeps
                // only the decision lattice so child approval/reject cannot
                // be hidden or double-counted as a parent event.
                state.apply_decision(event);
            }
            EventProjectionTarget::File => {
                if state.authority.kind != ReviewEntryAuthorityKind::File {
                    return Err(Error::InvalidState);
                }
                if event.kind == EventKind::StrictTokenFileModified {
                    state.strict = true;
                }
                state.apply_event(event)?;
            }
            EventProjectionTarget::Directory => {
                if state.authority.kind != ReviewEntryAuthorityKind::Directory {
                    return Err(Error::InvalidState);
                }
                state.apply_event(event)?;
            }
            EventProjectionTarget::StructuralOwner => {
                if !structural_owner_is_representable(event.kind, state.authority.kind) {
                    return Err(Error::InvalidState);
                }
                if event.kind == EventKind::NewUntokenizedSensitiveFinding {
                    new_sensitive_findings = new_sensitive_findings
                        .checked_add(1)
                        .ok_or(Error::BoundExceeded)?;
                }
                state.apply_event(event)?;
            }
        }
        accounted = accounted.checked_add(1).ok_or(Error::BoundExceeded)?;
    }
    if accounted != authority.events.events().len() {
        return Err(Error::InvalidState);
    }

    propagate_directory_decisions(&mut states)?;
    let mut budget = ReviewDiffBudget::start().map_err(|_| Error::ChangeReportBoundExceeded)?;
    let mut files = Vec::new();
    let mut directories = Vec::new();
    for mut state in states {
        if !state.needed {
            if !state.token_events.is_empty() || !state.reasons.is_empty() {
                return Err(Error::InvalidState);
            }
            continue;
        }
        state
            .token_events
            .sort_unstable_by_key(|event| event.event_id);
        let anchors = std::mem::take(&mut state.anchors)
            .into_values()
            .collect::<Vec<_>>();
        match state.authority.kind {
            ReviewEntryAuthorityKind::File => {
                let regions = project_regions(state.authority, &mut budget)?;
                let file = project_file(state, anchors, regions)?;
                files.try_reserve(1).map_err(|_| Error::BoundExceeded)?;
                files.push(file);
            }
            ReviewEntryAuthorityKind::Directory => {
                // DirectoryChangeV1 deliberately has no AnchorV1 array. Its
                // path-token events still carry the derived opaque anchor ID;
                // the value-free path-anchor records are transaction-local.
                if anchors
                    .iter()
                    .any(|anchor| anchor.anchor_kind != AnchorKindV1::PathComponentV1)
                {
                    return Err(Error::InvalidState);
                }
                directories
                    .try_reserve(1)
                    .map_err(|_| Error::BoundExceeded)?;
                directories.push(project_directory(state)?);
            }
        }
    }
    files.sort_unstable_by_key(|entry| entry.file_id);
    directories.sort_unstable_by_key(|entry| entry.directory_id);

    let summary = ManifestSummaryV1 {
        observed_files: authority.observed_files,
        changed_files: u32::try_from(files.len()).map_err(|_| Error::BoundExceeded)?,
        automatic_events: authority.events.automatic(),
        approval_eligible_events: authority.events.approval_required(),
        approved_events: 0,
        unapproved_events: authority.events.approval_required(),
        unconditional_rejects: authority.events.rejected(),
        preserved_tokens,
        deleted_tokens,
        new_sensitive_findings,
        observed_directories: authority.observed_directories,
        changed_directories: u32::try_from(directories.len()).map_err(|_| Error::BoundExceeded)?,
        preserved_original_only_files: 0,
        preserved_original_only_bytes: 0,
    };
    let manifest = ChangedManifestV1 {
        manifest_phase: ChangedManifestPhaseV1::Review,
        session_id: *schedule.session_id().as_bytes(),
        review_id,
        capsule_generation: owning_generation,
        review_profile: authority.report.profile,
        ruleset_id: authority.report.ruleset_id.to_owned(),
        original_tree_consistency: OriginalTreeConsistencyV1::Match,
        edited_tree_commitment: authority.report.edited_tree_commitment,
        event_set_commitment: authority.event_set_commitment,
        reconstruction_status: ReconstructionStatusV1::NotRun,
        semantic_safety_assessed: false,
        summary,
        files,
        failure_reason_codes: Vec::new(),
        directories,
    };
    super::manifest::validate_changed_manifest_v1(&manifest)?;
    Ok(ProjectedReview {
        manifest,
        review_id,
    })
}

const fn structural_owner_is_representable(
    event: EventKind,
    owner: ReviewEntryAuthorityKind,
) -> bool {
    match event {
        EventKind::NewUntokenizedSensitiveFinding
        | EventKind::ProtectedNamespace
        | EventKind::OmittedPathCollision => true,
        EventKind::UnsupportedAddition
        | EventKind::LinkLikeAddition
        | EventKind::HardLink
        | EventKind::AlternateDataStream
        | EventKind::InvalidUtf8 => matches!(owner, ReviewEntryAuthorityKind::File),
        EventKind::PreservedSameAnchor
        | EventKind::TokenDeleted
        | EventKind::ProtectedContextChanged
        | EventKind::ProtectedCoreChanged
        | EventKind::AnchorAmbiguous
        | EventKind::MovedToOtherFile
        | EventKind::PathMoved
        | EventKind::TokenDuplicated
        | EventKind::TokenModified
        | EventKind::TokenUnknown
        | EventKind::CategoryMismatch
        | EventKind::TokenOrderChanged
        | EventKind::FileModified
        | EventKind::FileDeleted
        | EventKind::FileRenamed
        | EventKind::FileMoved
        | EventKind::NewTextFile
        | EventKind::DirectoryAdded
        | EventKind::DirectoryDeleted
        | EventKind::DirectoryRenamed
        | EventKind::DirectoryMoved
        | EventKind::StrictTokenFileModified => false,
    }
}

fn file_bytes_changed(entry: &ReviewEntryAuthority) -> bool {
    match (
        entry.before_ai_safe_bytes.as_deref(),
        entry.after_ai_bytes.as_deref(),
    ) {
        (Some(before), Some(after)) => before != after,
        (Some(_), None) => entry.safe_path_after.is_none(),
        (None, Some(_)) => entry.safe_path_before.is_none(),
        (None, None) => false,
    }
}

fn derive_anchor_registry(
    state: &mut EntryState<'_>,
    schedule: &super::crypto::KeySchedule<'_>,
    original_tree_commitment: &[u8; 32],
) -> Result<()> {
    let Some(original_path) = state.authority.original_path.as_deref() else {
        return Ok(());
    };
    for anchor in &state.authority.content_anchors {
        let id = content_anchor_id(
            schedule,
            anchor.selected_radius,
            &anchor.final_anchor_commitment,
        )?;
        let record = AnchorV1 {
            anchor_id: id,
            anchor_kind: AnchorKindV1::ContentExactContextV2,
            line_range: Some(super::report_diff::LineRangeV1 {
                start_line: anchor.first_line,
                end_line_exclusive: anchor.end_line_exclusive,
            }),
            component_index: None,
            before_status: AnchorStatusV1::Present,
            after_status: AnchorStatusV1::Present,
        };
        if state.anchors.insert(id, record).is_some() {
            return Err(Error::InvalidState);
        }
        for oid in &anchor.occurrence_ids {
            if state.anchor_by_oid.insert(*oid, id).is_some() {
                return Err(Error::InvalidState);
            }
        }
    }
    for anchor in &state.authority.path_anchors {
        let id = path_anchor_id(
            schedule,
            original_tree_commitment,
            &state.id,
            original_path,
            anchor.component_index,
            anchor.token_start,
            anchor.token_end,
            &anchor.occurrence_id,
            anchor.category,
            &anchor.exact_path_anchor_commitment,
        )?;
        if state
            .anchors
            .insert(
                id,
                AnchorV1 {
                    anchor_id: id,
                    anchor_kind: AnchorKindV1::PathComponentV1,
                    line_range: None,
                    component_index: Some(anchor.component_index),
                    before_status: AnchorStatusV1::Present,
                    after_status: AnchorStatusV1::Present,
                },
            )
            .is_some()
            || state
                .anchor_by_oid
                .insert(anchor.occurrence_id, id)
                .is_some()
        {
            return Err(Error::InvalidState);
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn project_token_event(
    event: &CanonicalEvent,
    owner: &EntryState<'_>,
    file_id_before: &Option<[u8; 16]>,
    file_id_after: &Option<[u8; 16]>,
    event_id: [u8; 16],
) -> Result<TokenEventV1> {
    let kind = token_event_kind(event.kind)?;
    let (decision, approval_state) = event_decision(event.decision)?;
    if kind == TokenEventKindV1::TokenUnknown {
        if event.baseline_oid.is_some()
            || event.expected_category.is_some()
            || decision != ManifestDecisionV1::Reject
        {
            return Err(Error::InvalidState);
        }
    } else if event.baseline_oid.is_none() || event.expected_category.is_none() {
        return Err(Error::InvalidState);
    }
    let anchor_before = event
        .baseline_oid
        .as_ref()
        .and_then(|oid| owner.anchor_by_oid.get(oid))
        .copied();
    let anchor_after = if kind == TokenEventKindV1::PreservedSameAnchor {
        anchor_before
    } else {
        None
    };
    Ok(TokenEventV1 {
        event_id,
        // This is exclusively the freshly re-derived baseline OID. An OID
        // observed in an unknown/foreign form is intentionally discarded.
        token_id: event.baseline_oid,
        category_expected: event.expected_category,
        category_observed: event.observed_category,
        event: kind,
        file_id_before: *file_id_before,
        file_id_after: *file_id_after,
        anchor_id_before: anchor_before,
        anchor_id_after: anchor_after,
        observed_count: event.observed_count,
        approval_state,
        decision,
        reason_codes: sorted_reasons(reason_codes(event)?)?,
    })
}

fn token_event_kind(kind: EventKind) -> Result<TokenEventKindV1> {
    let value = match kind {
        EventKind::PreservedSameAnchor => TokenEventKindV1::PreservedSameAnchor,
        EventKind::TokenDeleted => TokenEventKindV1::TokenDeleted,
        EventKind::ProtectedContextChanged => TokenEventKindV1::ProtectedContextChanged,
        EventKind::ProtectedCoreChanged => TokenEventKindV1::ProtectedCoreChanged,
        EventKind::AnchorAmbiguous => TokenEventKindV1::AnchorAmbiguous,
        EventKind::MovedToOtherFile => TokenEventKindV1::TokenMovedToOtherFile,
        EventKind::PathMoved => TokenEventKindV1::PathMoved,
        EventKind::TokenDuplicated => TokenEventKindV1::TokenDuplicated,
        EventKind::TokenModified => TokenEventKindV1::TokenModified,
        EventKind::TokenUnknown => TokenEventKindV1::TokenUnknown,
        EventKind::CategoryMismatch => TokenEventKindV1::CategoryMismatch,
        EventKind::TokenOrderChanged => TokenEventKindV1::TokenOrderChanged,
        EventKind::FileModified
        | EventKind::FileDeleted
        | EventKind::FileRenamed
        | EventKind::FileMoved
        | EventKind::NewTextFile
        | EventKind::DirectoryAdded
        | EventKind::DirectoryDeleted
        | EventKind::DirectoryRenamed
        | EventKind::DirectoryMoved
        | EventKind::StrictTokenFileModified
        | EventKind::NewUntokenizedSensitiveFinding
        | EventKind::UnsupportedAddition
        | EventKind::LinkLikeAddition
        | EventKind::HardLink
        | EventKind::AlternateDataStream
        | EventKind::ProtectedNamespace
        | EventKind::OmittedPathCollision
        | EventKind::InvalidUtf8 => return Err(Error::InvalidState),
    };
    Ok(value)
}

fn event_decision(value: EventDecision) -> Result<(ManifestDecisionV1, ApprovalStateV1)> {
    match value {
        EventDecision::Automatic => {
            Ok((ManifestDecisionV1::Automatic, ApprovalStateV1::NotEligible))
        }
        EventDecision::ApprovalRequired => Ok((
            ManifestDecisionV1::ApprovalRequired,
            ApprovalStateV1::Required,
        )),
        EventDecision::Reject => Ok((ManifestDecisionV1::Reject, ApprovalStateV1::NotEligible)),
        EventDecision::Derived => Err(Error::InvalidState),
    }
}

fn update_anchor_status(state: &mut EntryState<'_>, event: &CanonicalEvent) -> Result<()> {
    let Some(id) = event
        .baseline_oid
        .as_ref()
        .and_then(|oid| state.anchor_by_oid.get(oid))
        .copied()
    else {
        return Ok(());
    };
    let status = match event.kind {
        EventKind::PreservedSameAnchor => AnchorStatusV1::Present,
        EventKind::TokenDeleted => AnchorStatusV1::Absent,
        EventKind::AnchorAmbiguous => AnchorStatusV1::Ambiguous,
        EventKind::ProtectedContextChanged
        | EventKind::ProtectedCoreChanged
        | EventKind::MovedToOtherFile
        | EventKind::PathMoved
        | EventKind::TokenDuplicated
        | EventKind::TokenModified
        | EventKind::CategoryMismatch
        | EventKind::TokenOrderChanged => AnchorStatusV1::Mismatch,
        EventKind::TokenUnknown => return Ok(()),
        EventKind::FileModified
        | EventKind::FileDeleted
        | EventKind::FileRenamed
        | EventKind::FileMoved
        | EventKind::NewTextFile
        | EventKind::DirectoryAdded
        | EventKind::DirectoryDeleted
        | EventKind::DirectoryRenamed
        | EventKind::DirectoryMoved
        | EventKind::StrictTokenFileModified
        | EventKind::NewUntokenizedSensitiveFinding
        | EventKind::UnsupportedAddition
        | EventKind::LinkLikeAddition
        | EventKind::HardLink
        | EventKind::AlternateDataStream
        | EventKind::ProtectedNamespace
        | EventKind::OmittedPathCollision
        | EventKind::InvalidUtf8 => return Err(Error::InvalidState),
    };
    let anchor = state.anchors.get_mut(&id).ok_or(Error::InvalidState)?;
    if anchor_status_strength(status) > anchor_status_strength(anchor.after_status) {
        anchor.after_status = status;
    }
    Ok(())
}

const fn anchor_status_strength(value: AnchorStatusV1) -> u8 {
    match value {
        AnchorStatusV1::Present => 0,
        AnchorStatusV1::Absent => 1,
        AnchorStatusV1::Mismatch => 2,
        AnchorStatusV1::Ambiguous => 3,
    }
}

fn reason_codes(event: &CanonicalEvent) -> Result<Vec<ReasonCodeV1>> {
    let primary = match event.kind {
        EventKind::PreservedSameAnchor => Some(ReasonCodeV1::PreservedSameAnchor),
        EventKind::TokenDeleted => Some(ReasonCodeV1::TokenDeleted),
        EventKind::ProtectedContextChanged => Some(ReasonCodeV1::ProtectedContextChanged),
        EventKind::ProtectedCoreChanged => Some(ReasonCodeV1::ProtectedCoreChanged),
        EventKind::AnchorAmbiguous => Some(ReasonCodeV1::AnchorAmbiguous),
        EventKind::MovedToOtherFile => Some(ReasonCodeV1::TokenMovedToOtherFile),
        EventKind::PathMoved => Some(ReasonCodeV1::PathMoved),
        EventKind::TokenDuplicated => Some(ReasonCodeV1::TokenDuplicated),
        EventKind::TokenModified => Some(ReasonCodeV1::TokenModified),
        EventKind::TokenUnknown => Some(ReasonCodeV1::UnknownToken),
        EventKind::CategoryMismatch => Some(ReasonCodeV1::CategoryMismatch),
        EventKind::TokenOrderChanged => Some(ReasonCodeV1::TokenOrderChanged),
        EventKind::FileModified => None,
        EventKind::FileDeleted => Some(ReasonCodeV1::FileDeleted),
        EventKind::FileRenamed => Some(ReasonCodeV1::FileRenamed),
        EventKind::FileMoved => Some(ReasonCodeV1::FileMoved),
        EventKind::NewTextFile => Some(ReasonCodeV1::NewTextFile),
        EventKind::DirectoryAdded => Some(ReasonCodeV1::DirectoryAdded),
        EventKind::DirectoryDeleted => Some(ReasonCodeV1::DirectoryDeleted),
        EventKind::DirectoryRenamed => Some(ReasonCodeV1::DirectoryRenamed),
        EventKind::DirectoryMoved => Some(ReasonCodeV1::DirectoryMoved),
        EventKind::StrictTokenFileModified => Some(ReasonCodeV1::StrictTokenFileModified),
        EventKind::NewUntokenizedSensitiveFinding => {
            Some(ReasonCodeV1::NewUntokenizedSensitiveFinding)
        }
        EventKind::UnsupportedAddition => Some(ReasonCodeV1::UnsupportedAddition),
        EventKind::LinkLikeAddition => Some(ReasonCodeV1::LinkLikeAddition),
        EventKind::HardLink => Some(ReasonCodeV1::HardLink),
        EventKind::AlternateDataStream => Some(ReasonCodeV1::AlternateDataStream),
        EventKind::ProtectedNamespace => Some(ReasonCodeV1::ReservedWindowsName),
        EventKind::OmittedPathCollision => Some(ReasonCodeV1::OmittedPathCollision),
        EventKind::InvalidUtf8 => Some(ReasonCodeV1::InvalidUtf8),
    };
    let mut values = Vec::new();
    if let Some(primary) = primary {
        values.push(primary);
    }
    if event.reason == StructuralReason::MalformedToken
        && !values.contains(&ReasonCodeV1::MalformedToken)
    {
        values.push(ReasonCodeV1::MalformedToken);
    }
    Ok(values)
}

fn propagate_directory_decisions(states: &mut [EntryState<'_>]) -> Result<()> {
    let mut directories = states
        .iter()
        .enumerate()
        .filter(|(_, state)| state.authority.kind == ReviewEntryAuthorityKind::Directory)
        .map(|(index, state)| (entry_depth(state.authority), index))
        .collect::<Vec<_>>();
    directories.sort_unstable_by_key(|value| std::cmp::Reverse(value.0));
    for (_, parent_index) in directories {
        if !states[parent_index].needed {
            continue;
        }
        for child_index in 0..states.len() {
            if child_index == parent_index || !states[child_index].needed {
                continue;
            }
            if is_direct_child_authority(
                states[parent_index].authority,
                states[child_index].authority,
            ) {
                let (parent, child) = two_mut(states, parent_index, child_index)?;
                parent.inherit(child);
            }
        }
    }
    Ok(())
}

fn entry_depth(entry: &ReviewEntryAuthority) -> usize {
    entry
        .safe_path_before
        .as_deref()
        .or(entry.safe_path_after.as_deref())
        .map_or(0, |path| {
            path.iter().filter(|byte| **byte == b'/').count() + 1
        })
}

fn is_direct_child_authority(parent: &ReviewEntryAuthority, child: &ReviewEntryAuthority) -> bool {
    is_direct_child(
        parent.safe_path_before.as_deref(),
        child.safe_path_before.as_deref(),
    ) || is_direct_child(
        parent.safe_path_after.as_deref(),
        child.safe_path_after.as_deref(),
    )
}

fn is_direct_child(parent: Option<&[u8]>, child: Option<&[u8]>) -> bool {
    let (Some(parent), Some(child)) = (parent, child) else {
        return false;
    };
    child
        .strip_prefix(parent)
        .and_then(|suffix| suffix.strip_prefix(b"/"))
        .is_some_and(|suffix| !suffix.is_empty() && !suffix.contains(&b'/'))
}

fn two_mut<T>(values: &mut [T], left: usize, right: usize) -> Result<(&mut T, &mut T)> {
    if left == right || left >= values.len() || right >= values.len() {
        return Err(Error::InvalidState);
    }
    match left.cmp(&right) {
        Ordering::Less => {
            let (prefix, suffix) = values.split_at_mut(right);
            Ok((&mut prefix[left], &mut suffix[0]))
        }
        Ordering::Greater => {
            let (prefix, suffix) = values.split_at_mut(left);
            Ok((&mut suffix[0], &mut prefix[right]))
        }
        Ordering::Equal => Err(Error::InvalidState),
    }
}

fn project_regions(
    entry: &ReviewEntryAuthority,
    budget: &mut ReviewDiffBudget,
) -> Result<Vec<ContentChangeRegionV1>> {
    let content_changed = file_bytes_changed(entry);
    if !content_changed {
        return Ok(Vec::new());
    }
    let before = match entry.before_ai_safe_bytes.as_deref() {
        Some(bytes) => ReportingFile::AiSafe(bytes),
        None if entry.safe_path_before.is_none() => ReportingFile::Absent,
        None => return Err(Error::ChangeReportBoundExceeded),
    };
    let after = match entry.after_ai_bytes.as_deref() {
        Some(bytes) => ReportingFile::AiSafe(bytes),
        None if entry.safe_path_after.is_none() => ReportingFile::Absent,
        None => return Err(Error::ChangeReportBoundExceeded),
    };
    let deadlines = budget
        .begin_file()
        .map_err(|_| Error::ChangeReportBoundExceeded)?;
    let regions = StrictLineDiff::regions(before, after, DiffLimits::accepted(), deadlines)
        .map_err(|_| Error::ChangeReportBoundExceeded)?;
    budget
        .accept_regions(regions.len())
        .map_err(|_| Error::ChangeReportBoundExceeded)?;
    if regions.is_empty() {
        return Err(Error::ChangeReportBoundExceeded);
    }
    Ok(regions)
}

fn project_file(
    state: EntryState<'_>,
    anchors: Vec<AnchorV1>,
    regions: Vec<ContentChangeRegionV1>,
) -> Result<FileChangeV1> {
    let file_event = path_file_event(state.authority)?;
    let content_event = if state.strict {
        ContentEventV1::StrictReviewRequired
    } else if state.authority.safe_path_before.is_none() && state.authority.after_ai_bytes.is_some()
    {
        ContentEventV1::Added
    } else if state.authority.safe_path_after.is_none()
        && state.authority.before_ai_safe_bytes.is_some()
    {
        ContentEventV1::Deleted
    } else if file_bytes_changed(state.authority) {
        ContentEventV1::Edited
    } else {
        ContentEventV1::Unchanged
    };
    let approval_state = match state.decision {
        DecisionStrength::ApprovalRequired => ApprovalStateV1::Required,
        DecisionStrength::Automatic | DecisionStrength::Reject => ApprovalStateV1::NotEligible,
    };
    Ok(FileChangeV1 {
        file_id: state.id,
        original_relative_path: private_path(state.authority.original_path.as_deref())?,
        safe_path_before: private_path(state.authority.safe_path_before.as_deref())?,
        safe_path_after: private_path(state.authority.safe_path_after.as_deref())?,
        file_event,
        content_event,
        content_change_regions: regions,
        anchors,
        token_events: state.token_events,
        decision: state.decision.manifest(),
        reason_codes: state.reasons.into_iter().collect(),
        approval_state,
    })
}

fn project_directory(state: EntryState<'_>) -> Result<DirectoryChangeV1> {
    let approval_state = match state.decision {
        DecisionStrength::ApprovalRequired
            if state.has_token_approval && !state.has_other_approval =>
        {
            ApprovalStateV1::Required
        }
        DecisionStrength::Automatic
        | DecisionStrength::ApprovalRequired
        | DecisionStrength::Reject => ApprovalStateV1::NotEligible,
    };
    Ok(DirectoryChangeV1 {
        directory_id: state.id,
        original_relative_path: private_path(state.authority.original_path.as_deref())?,
        safe_path_before: private_path(state.authority.safe_path_before.as_deref())?,
        safe_path_after: private_path(state.authority.safe_path_after.as_deref())?,
        directory_event: path_directory_event(state.authority)?,
        token_events: state.token_events,
        decision: state.decision.manifest(),
        approval_state,
        reason_codes: state.reasons.into_iter().collect(),
    })
}

fn path_file_event(entry: &ReviewEntryAuthority) -> Result<FileEventV1> {
    match (
        entry.safe_path_before.as_deref(),
        entry.safe_path_after.as_deref(),
    ) {
        (None, Some(_)) => Ok(FileEventV1::Added),
        (Some(_), None) => Ok(FileEventV1::Deleted),
        (Some(before), Some(after)) if before == after => Ok(FileEventV1::UnchangedPath),
        (Some(before), Some(after)) if parents(before) == parents(after) => {
            Ok(FileEventV1::Renamed)
        }
        (Some(_), Some(_)) => Ok(FileEventV1::Moved),
        (None, None) => Err(Error::InvalidState),
    }
}

fn path_directory_event(entry: &ReviewEntryAuthority) -> Result<DirectoryEventV1> {
    match (
        entry.safe_path_before.as_deref(),
        entry.safe_path_after.as_deref(),
    ) {
        (None, Some(_)) => Ok(DirectoryEventV1::Added),
        (Some(_), None) => Ok(DirectoryEventV1::Deleted),
        (Some(before), Some(after)) if before != after && parents(before) == parents(after) => {
            Ok(DirectoryEventV1::Renamed)
        }
        (Some(before), Some(after)) if before != after => Ok(DirectoryEventV1::Moved),
        _ => Err(Error::InvalidState),
    }
}

fn parents(path: &[u8]) -> &[u8] {
    path.iter()
        .rposition(|byte| *byte == b'/')
        .map_or(&[], |index| &path[..index])
}

fn private_path(path: Option<&[u8]>) -> Result<Option<String>> {
    path.map(|value| {
        std::str::from_utf8(value)
            .map(str::to_owned)
            .map_err(|_| Error::InvalidState)
    })
    .transpose()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_thirty_event_kinds_have_one_projection_class() {
        assert_eq!(EventKind::ALL.len(), 30);
        let expected = [
            (
                EventKind::PreservedSameAnchor,
                EventProjectionTarget::PreservedOrSuppressed,
            ),
            (EventKind::TokenDeleted, EventProjectionTarget::Token),
            (
                EventKind::ProtectedContextChanged,
                EventProjectionTarget::Token,
            ),
            (
                EventKind::ProtectedCoreChanged,
                EventProjectionTarget::Token,
            ),
            (EventKind::AnchorAmbiguous, EventProjectionTarget::Token),
            (EventKind::MovedToOtherFile, EventProjectionTarget::Token),
            (EventKind::PathMoved, EventProjectionTarget::Token),
            (EventKind::TokenDuplicated, EventProjectionTarget::Token),
            (EventKind::TokenModified, EventProjectionTarget::Token),
            (EventKind::TokenUnknown, EventProjectionTarget::Token),
            (EventKind::CategoryMismatch, EventProjectionTarget::Token),
            (EventKind::TokenOrderChanged, EventProjectionTarget::Token),
            (EventKind::FileModified, EventProjectionTarget::File),
            (EventKind::FileDeleted, EventProjectionTarget::File),
            (EventKind::FileRenamed, EventProjectionTarget::File),
            (EventKind::FileMoved, EventProjectionTarget::File),
            (EventKind::NewTextFile, EventProjectionTarget::File),
            (EventKind::DirectoryAdded, EventProjectionTarget::Directory),
            (
                EventKind::DirectoryDeleted,
                EventProjectionTarget::Directory,
            ),
            (
                EventKind::DirectoryRenamed,
                EventProjectionTarget::Directory,
            ),
            (EventKind::DirectoryMoved, EventProjectionTarget::Directory),
            (
                EventKind::StrictTokenFileModified,
                EventProjectionTarget::File,
            ),
            (
                EventKind::NewUntokenizedSensitiveFinding,
                EventProjectionTarget::StructuralOwner,
            ),
            (
                EventKind::UnsupportedAddition,
                EventProjectionTarget::StructuralOwner,
            ),
            (
                EventKind::LinkLikeAddition,
                EventProjectionTarget::StructuralOwner,
            ),
            (EventKind::HardLink, EventProjectionTarget::StructuralOwner),
            (
                EventKind::AlternateDataStream,
                EventProjectionTarget::StructuralOwner,
            ),
            (
                EventKind::ProtectedNamespace,
                EventProjectionTarget::StructuralOwner,
            ),
            (
                EventKind::OmittedPathCollision,
                EventProjectionTarget::StructuralOwner,
            ),
            (
                EventKind::InvalidUtf8,
                EventProjectionTarget::StructuralOwner,
            ),
        ];
        assert_eq!(EventKind::ALL, expected.map(|(kind, _)| kind));
        for (kind, target) in expected {
            assert_eq!(event_projection_target(kind), target, "{kind:?}");
        }
        let mut counts = [0usize; 5];
        for kind in EventKind::ALL {
            let index = match event_projection_target(kind) {
                EventProjectionTarget::Token => 0,
                EventProjectionTarget::File => 1,
                EventProjectionTarget::Directory => 2,
                EventProjectionTarget::StructuralOwner => 3,
                EventProjectionTarget::PreservedOrSuppressed => 4,
            };
            counts[index] += 1;
        }
        assert_eq!(counts, [11, 6, 4, 8, 1]);
    }

    #[test]
    fn parent_path_classification_is_byte_exact() {
        assert_eq!(parents(b"a/one.txt"), b"a");
        assert_eq!(parents(b"one.txt"), b"");
        assert!(is_direct_child(Some(b"a"), Some(b"a/b")));
        assert!(!is_direct_child(Some(b"a"), Some(b"a/b/c")));
    }
}
