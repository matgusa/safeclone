//! Changed-only private review transaction and presentations.
//!
//! The CLI is intentionally not wired here. The default presentation is an
//! explicit path-free allowlist. Confidential relative paths are available
//! only through the warning-acknowledgement type state below.

use std::fmt;
use std::path::Path;

use super::schema::{ApprovalEventType, ApprovalReason, SessionState};
use super::token::{ReviewProfile, ENGINE_VERSION, POLICY_ID, TOKEN_SUITE_ID};
use super::Error;

pub const CONFIDENTIAL_REVIEW_WARNING: &str =
    "warning=confidential review output; do not send to AI or persist in public logs";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReviewReport {
    pub review_id: String,
    pub profile: ReviewProfile,
    pub engine_version: &'static str,
    pub policy_id: &'static str,
    pub ruleset_id: String,
    pub token_suite_id: u16,
    pub capsule_generation: u64,
    pub session_state: SessionState,
    pub changed_files: u32,
    pub changed_directories: u32,
    pub automatic_events: u32,
    pub approval_eligible_events: u32,
    pub approved_events: u32,
    pub remaining_approval_events: u32,
    pub unconditional_rejects: u32,
    pub approval_events: Vec<ReviewApprovalEvent>,
    pub semantic_safety_assessed: bool,
    pub replayed: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReviewApprovalEvent {
    pub event_id: String,
    pub event_type: ApprovalEventType,
    pub required_reason: ApprovalReason,
    pub approved: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReviewFailure {
    DefiniteFailure(Error),
    ManualInspectionRequired(Error),
}

impl ReviewFailure {
    pub const fn error(self) -> Error {
        match self {
            Self::DefiniteFailure(error) | Self::ManualInspectionRequired(error) => error,
        }
    }
}

impl fmt::Display for ReviewFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DefiniteFailure(error) => write!(formatter, "round-trip review failed: {error}"),
            Self::ManualInspectionRequired(error) => write!(
                formatter,
                "round-trip review requires manual inspection: {error}"
            ),
        }
    }
}

impl std::error::Error for ReviewFailure {}

pub type ReviewResult<T> = std::result::Result<T, ReviewFailure>;

/// Opaque review result. It deliberately has no `Debug` or `Display`
/// implementation because it owns the decrypted confidential manifest.
pub struct ReviewOutcome {
    report: ReviewReport,
    #[cfg(windows)]
    manifest: super::manifest::ChangedManifestV1,
}

impl ReviewOutcome {
    pub const fn report(&self) -> &ReviewReport {
        &self.report
    }

    /// Renders only the path-free public allowlist.
    pub fn render_default(&self) -> String {
        #[cfg(windows)]
        {
            render_default_manifest(&self.manifest, &self.report)
        }
        #[cfg(not(windows))]
        {
            String::new()
        }
    }

    /// Begins the confidential rendering type-state. No private path is
    /// returned by this operation.
    pub const fn prepare_private_review(&self) -> WarningRequired<'_> {
        WarningRequired { outcome: self }
    }

    #[cfg(all(test, windows))]
    pub(crate) const fn manifest(&self) -> &super::manifest::ChangedManifestV1 {
        &self.manifest
    }
}

pub struct WarningRequired<'review> {
    outcome: &'review ReviewOutcome,
}

impl<'review> WarningRequired<'review> {
    pub const fn warning(&self) -> &'static str {
        CONFIDENTIAL_REVIEW_WARNING
    }

    /// Consumes the warning gate only when the caller acknowledges the exact
    /// stable contract. A boolean cannot bypass this step.
    pub fn acknowledge_warning(
        self,
        acknowledgement: &str,
    ) -> std::result::Result<PrivateReviewPermit<'review>, Self> {
        if acknowledgement == CONFIDENTIAL_REVIEW_WARNING {
            Ok(PrivateReviewPermit {
                outcome: self.outcome,
            })
        } else {
            Err(self)
        }
    }
}

pub struct PrivateReviewPermit<'review> {
    outcome: &'review ReviewOutcome,
}

impl PrivateReviewPermit<'_> {
    /// Renders the same allowlist as the default representation plus only the
    /// three accepted confidential relative-path fields.
    pub fn render_private_paths(&self) -> String {
        #[cfg(windows)]
        {
            render_private_manifest(&self.outcome.manifest, &self.outcome.report)
        }
        #[cfg(not(windows))]
        {
            String::new()
        }
    }
}

#[cfg(not(windows))]
pub fn review_session(
    _original: &Path,
    _ai_workspace: &Path,
    _private_state: &Path,
) -> ReviewResult<ReviewOutcome> {
    Err(ReviewFailure::DefiniteFailure(Error::UnsupportedPlatform))
}

#[cfg(windows)]
pub fn review_session(
    original: &Path,
    ai_workspace: &Path,
    private_state: &Path,
) -> ReviewResult<ReviewOutcome> {
    windows::review_session(original, ai_workspace, private_state)
}

#[cfg(windows)]
fn render_default_manifest(
    manifest: &super::manifest::ChangedManifestV1,
    report: &ReviewReport,
) -> String {
    use std::fmt::Write as _;

    use super::token::encode_base32_128;

    let mut output = String::new();
    let _ = writeln!(
        output,
        "review id={} generation={} state={} profile={} engine={} policy={} ruleset={} token_suite={}",
        report.review_id,
        report.capsule_generation,
        state_label(report.session_state),
        report.profile.external_label(),
        report.engine_version,
        report.policy_id,
        report.ruleset_id,
        report.token_suite_id,
    );
    let _ = writeln!(
        output,
        "summary observed_files={} changed_files={} observed_directories={} changed_directories={} automatic={} approval_required={} approved={} remaining={} rejected={} preserved_tokens={} deleted_tokens={} new_sensitive_findings={} semantic_safety_assessed=false",
        manifest.summary.observed_files,
        manifest.summary.changed_files,
        manifest.summary.observed_directories,
        manifest.summary.changed_directories,
        manifest.summary.automatic_events,
        manifest.summary.approval_eligible_events,
        report.approved_events,
        report.remaining_approval_events,
        manifest.summary.unconditional_rejects,
        manifest.summary.preserved_tokens,
        manifest.summary.deleted_tokens,
        manifest.summary.new_sensitive_findings,
    );
    for file in &manifest.files {
        let _ = writeln!(
            output,
            "file id={} event={} content={} decision={}",
            encode_base32_128(&file.file_id),
            file.file_event.code(),
            file.content_event.code(),
            file.decision.code(),
        );
        render_reasons(&mut output, "file-reason", &file.reason_codes);
        for region in &file.content_change_regions {
            let kind = match region.kind {
                super::report_diff::ContentChangeKindV1::Insert => "INSERT",
                super::report_diff::ContentChangeKindV1::Delete => "DELETE",
                super::report_diff::ContentChangeKindV1::Replace => "REPLACE",
            };
            let _ = writeln!(
                output,
                "region kind={} before={}:{} after={}:{}",
                kind,
                region.before_range.start_line,
                region.before_range.end_line_exclusive,
                region.after_range.start_line,
                region.after_range.end_line_exclusive,
            );
        }
        for anchor in &file.anchors {
            let _ = writeln!(
                output,
                "anchor id={} kind={} before={} after={} line_start={} line_end={} component={}",
                encode_base32_128(&anchor.anchor_id),
                anchor.anchor_kind.code(),
                anchor.before_status.code(),
                anchor.after_status.code(),
                optional_u32(anchor.line_range.map(|range| range.start_line)),
                optional_u32(anchor.line_range.map(|range| range.end_line_exclusive)),
                optional_u32(anchor.component_index),
            );
        }
        render_token_events(&mut output, &file.token_events);
    }
    for directory in &manifest.directories {
        let _ = writeln!(
            output,
            "directory id={} event={} decision={}",
            encode_base32_128(&directory.directory_id),
            directory.directory_event.code(),
            directory.decision.code(),
        );
        render_reasons(&mut output, "directory-reason", &directory.reason_codes);
        render_token_events(&mut output, &directory.token_events);
    }
    for event in &report.approval_events {
        let _ = writeln!(
            output,
            "approval-event id={} type={} reason={} approved={}",
            event.event_id,
            approval_event_type_label(event.event_type),
            approval_reason_label(event.required_reason),
            event.approved,
        );
    }
    output
}

#[cfg(windows)]
fn render_token_events(output: &mut String, events: &[super::manifest::TokenEventV1]) {
    use std::fmt::Write as _;

    use super::token::encode_base32_128;

    for event in events {
        let _ = writeln!(
            output,
            "token-event id={} token_id={} event={} expected={} observed={} decision={} observed_count={} before_entry={} after_entry={} before_anchor={} after_anchor={}",
            encode_base32_128(&event.event_id),
            optional_id(event.token_id.as_ref()),
            event.event.code(),
            event.category_expected.map_or("null", |value| value.as_str()),
            event.category_observed.map_or("null", |value| value.as_str()),
            event.decision.code(),
            event.observed_count,
            optional_id(event.file_id_before.as_ref()),
            optional_id(event.file_id_after.as_ref()),
            optional_id(event.anchor_id_before.as_ref()),
            optional_id(event.anchor_id_after.as_ref()),
        );
        render_reasons(output, "token-reason", &event.reason_codes);
    }
}

const fn approval_event_type_label(value: ApprovalEventType) -> &'static str {
    match value {
        ApprovalEventType::Deleted => "DELETED",
        ApprovalEventType::FileDeleted => "FILE_DELETED",
        ApprovalEventType::StrictTokenFileModified => "STRICT_TOKEN_FILE_MODIFIED",
    }
}

const fn approval_reason_label(value: ApprovalReason) -> &'static str {
    match value {
        ApprovalReason::IntentionalTokenRemoval => "INTENTIONAL_TOKEN_REMOVAL",
        ApprovalReason::IntentionalFileDelete => "INTENTIONAL_FILE_DELETE",
        ApprovalReason::StrictTokenFileEditReviewed => "STRICT_TOKEN_FILE_EDIT_REVIEWED",
    }
}

#[cfg(windows)]
fn optional_id(value: Option<&[u8; 16]>) -> String {
    value.map_or_else(|| "null".to_owned(), super::token::encode_base32_128)
}

#[cfg(windows)]
fn optional_u32(value: Option<u32>) -> String {
    value.map_or_else(|| "null".to_owned(), |value| value.to_string())
}

#[cfg(windows)]
fn render_reasons(output: &mut String, label: &str, reasons: &[super::manifest::ReasonCodeV1]) {
    use std::fmt::Write as _;
    for reason in reasons {
        let _ = writeln!(output, "{} code={}", label, reason.code());
    }
}

#[cfg(windows)]
fn render_private_manifest(
    manifest: &super::manifest::ChangedManifestV1,
    report: &ReviewReport,
) -> String {
    use std::fmt::Write as _;

    use super::token::encode_base32_128;

    let mut output = render_default_manifest(manifest, report);
    for file in &manifest.files {
        let _ = writeln!(
            output,
            "private-file-paths id={} original={} safe_before={} safe_after={}",
            encode_base32_128(&file.file_id),
            escaped_optional_path(file.original_relative_path.as_deref()),
            escaped_optional_path(file.safe_path_before.as_deref()),
            escaped_optional_path(file.safe_path_after.as_deref()),
        );
    }
    for directory in &manifest.directories {
        let _ = writeln!(
            output,
            "private-directory-paths id={} original={} safe_before={} safe_after={}",
            encode_base32_128(&directory.directory_id),
            escaped_optional_path(directory.original_relative_path.as_deref()),
            escaped_optional_path(directory.safe_path_before.as_deref()),
            escaped_optional_path(directory.safe_path_after.as_deref()),
        );
    }
    output
}

#[cfg(windows)]
fn escaped_optional_path(value: Option<&str>) -> String {
    let Some(value) = value else {
        return "null".to_owned();
    };
    let mut output = String::new();
    output.push('"');
    for character in value.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            value if value.is_control() => {
                use std::fmt::Write as _;
                let _ = write!(output, "\\u{{{:x}}}", u32::from(value));
            }
            value => output.push(value),
        }
    }
    output.push('"');
    output
}

fn state_label(value: SessionState) -> &'static str {
    match value {
        SessionState::ActiveUnreviewed => "ACTIVE_UNREVIEWED",
        SessionState::ReviewedRejected => "REVIEWED_REJECTED",
        SessionState::Reviewed => "REVIEWED",
        SessionState::ApprovedPartial => "APPROVED_PARTIAL",
        SessionState::ReadyToApply => "READY_TO_APPLY",
        SessionState::ApplyArmed => "APPLY_ARMED",
        SessionState::ApplyIncomplete => "APPLY_INCOMPLETE",
        SessionState::AppliedComplete => "APPLIED_COMPLETE",
    }
}

#[cfg(windows)]
mod windows {
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;
    use crate::roundtrip::approval::{
        approval_requirements, authenticate_approval_set, empty_review_approval_set,
        verify_approval_set_tag,
    };
    use crate::roundtrip::capsule::StoreClassification;
    use crate::roundtrip::crypto::constant_time_equal;
    use crate::roundtrip::dpapi::{protect_next_live_capsule, protect_next_review_manifest};
    use crate::roundtrip::manifest::ChangedManifestV1;
    use crate::roundtrip::manifest_projection::project_review;
    use crate::roundtrip::review_identity::ReviewIdentityIndex;
    use crate::roundtrip::schema::{CapsuleV1, ManifestPhase, ReviewAuthorityV1};
    use crate::roundtrip::token::encode_base32_128;
    #[cfg(test)]
    use crate::roundtrip::Result;

    #[cfg(test)]
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(crate) enum TestCheckpoint {
        AfterManifestCommit,
    }

    #[cfg(test)]
    type TestHook = Box<dyn FnMut(TestCheckpoint) -> Result<()>>;

    #[cfg(test)]
    std::thread_local! {
        static TEST_HOOK: std::cell::RefCell<Option<TestHook>> =
            std::cell::RefCell::new(None);
    }

    #[cfg(test)]
    pub(crate) struct TestHookGuard;

    #[cfg(test)]
    impl Drop for TestHookGuard {
        fn drop(&mut self) {
            TEST_HOOK.with(|slot| *slot.borrow_mut() = None);
        }
    }

    #[cfg(test)]
    pub(crate) fn install_test_hook(
        hook: impl FnMut(TestCheckpoint) -> Result<()> + 'static,
    ) -> TestHookGuard {
        TEST_HOOK.with(|slot| {
            let prior = slot.borrow_mut().replace(Box::new(hook));
            assert!(prior.is_none(), "nested review test hook");
        });
        TestHookGuard
    }

    #[cfg(test)]
    fn checkpoint(value: TestCheckpoint) -> Result<()> {
        TEST_HOOK.with(|slot| match slot.borrow_mut().as_mut() {
            Some(hook) => hook(value),
            None => Ok(()),
        })
    }

    pub(super) fn review_session(
        original: &Path,
        ai_workspace: &Path,
        private_state: &Path,
    ) -> ReviewResult<ReviewOutcome> {
        let mut authority = crate::roundtrip::classify::prepare_review_authority(
            original,
            ai_workspace,
            private_state,
        )
        .map_err(initial_failure)?;
        let identities = ReviewIdentityIndex::derive(&authority).map_err(definite)?;
        let review_id = identities.review_id();
        let current = authority.owner.capsule();
        if current.current_review.is_some() {
            verify_approval_set_tag(current, &authority.owner.key_schedule()).map_err(definite)?;
        }
        let replay = current
            .current_review
            .as_ref()
            .is_some_and(|review| review.review_id == review_id);
        if replay {
            return replay_review(authority, identities, review_id);
        }
        if matches!(
            current.session_state,
            SessionState::ApplyArmed
                | SessionState::ApplyIncomplete
                | SessionState::AppliedComplete
        ) {
            return Err(definite(Error::InvalidState));
        }
        let next_generation = current
            .generation
            .checked_add(1)
            .ok_or_else(|| definite(Error::InvalidState))?;
        let projected =
            project_review(&authority, &identities, next_generation).map_err(definite)?;
        if projected.review_id != review_id {
            return Err(definite(Error::InvalidState));
        }
        authority.verify_selected_roots().map_err(definite)?;
        let payload = projected.manifest.encode_canonical().map_err(definite)?;
        let protected =
            protect_next_review_manifest(&authority.owner, &payload).map_err(definite)?;
        let manifest_commitment = *protected.commitment();

        // From this call onward an immutable manifest leaf may exist. Any
        // failure is manual; no cleanup, retry, or adoption occurs.
        let evidence = authority
            .store
            .persist_next_review_manifest(
                &mut authority.lock,
                &authority.owner,
                review_id,
                manifest_commitment,
                protected.as_bytes(),
            )
            .map_err(manual)?;
        #[cfg(test)]
        checkpoint(TestCheckpoint::AfterManifestCommit).map_err(manual)?;
        let (owning_generation, authenticated) = authority
            .store
            .read_review_manifest(
                &mut authority.lock,
                &authority.owner,
                review_id,
                ManifestPhase::Review,
            )
            .map_err(manual)?;
        if owning_generation != next_generation
            || !constant_time_equal(authenticated.commitment(), &manifest_commitment)
            || authenticated.as_bytes() != payload
        {
            return Err(manual(Error::PrivateOrphansPresent));
        }
        let decoded = ChangedManifestV1::decode_canonical(authenticated.as_bytes())
            .map_err(|_| manual(Error::PrivateOrphansPresent))?;
        if decoded != projected.manifest {
            return Err(manual(Error::PrivateOrphansPresent));
        }
        drop(authenticated);

        let reviewed_epoch_seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| manual(Error::InvalidState))?
            .as_secs();
        let session_state = review_state(
            authority.events.rejected(),
            authority.events.approval_required(),
        );
        let schedule = authority.owner.key_schedule();
        let approval_set = empty_review_approval_set(
            &schedule,
            review_id,
            authority.report.profile,
            authority.report.ruleset_id,
        )
        .map_err(manual)?;
        let mut next: CapsuleV1 = authority.owner.capsule().clone();
        next.generation = next_generation;
        next.session_state = session_state;
        next.current_review = Some(ReviewAuthorityV1 {
            review_id,
            edited_tree_commitment: authority.report.edited_tree_commitment,
            event_set_commitment: authority.event_set_commitment,
            manifest_commitment,
            manifest_phase: ManifestPhase::Review,
            automatic_event_count: authority.events.automatic(),
            approval_eligible_count: authority.events.approval_required(),
            unconditional_reject_count: authority.events.rejected(),
            reviewed_epoch_seconds,
        });
        next.approval_set = approval_set;
        next.apply_authority = None;
        next.orphan_count_at_commit = 0;
        next.semantic_safety_assessed = false;
        next.validate_capsule_state().map_err(manual)?;
        authority.verify_selected_roots().map_err(manual)?;
        let protected_capsule =
            protect_next_live_capsule(&authority.owner, &next).map_err(manual)?;
        let committed = authority
            .store
            .append_review_capsule_generation(&mut authority.lock, &protected_capsule, &evidence)
            .map_err(manual)?;
        if committed.generation != next_generation
            || committed.root_identity != authority.store.root_identity()
        {
            return Err(manual(Error::StateCommitUncertain));
        }
        let fresh = authority
            .store
            .read_while_locked(&mut authority.lock)
            .map_err(manual)?;
        let fresh_head = fresh
            .live_head()
            .ok_or_else(|| manual(Error::StateCommitUncertain))?;
        if fresh.classification != StoreClassification::AuthoritativeLive
            || fresh.orphan_count != 0
            || fresh_head.capsule() != &next
        {
            return Err(manual(Error::StateCommitUncertain));
        }
        let authenticated = authenticate_approval_set(
            fresh_head.capsule(),
            &fresh_head.key_schedule(),
            &authority,
            &identities,
        )
        .map_err(manual)?;
        let approval_events = approval_event_reports(
            &authority,
            &identities,
            fresh_head.capsule().approval_set.records.as_slice(),
        )
        .map_err(manual)?;
        let approved_events = authenticated.approved_count().map_err(manual)?;
        let remaining_approval_events = authenticated.remaining_count().map_err(manual)?;
        authority.lock.release().map_err(manual)?;
        Ok(outcome(
            projected.manifest,
            session_state,
            next_generation,
            approved_events,
            remaining_approval_events,
            approval_events,
            false,
        ))
    }

    fn replay_review(
        mut authority: crate::roundtrip::classify::PreparedReviewAuthority,
        identities: ReviewIdentityIndex,
        review_id: [u8; 16],
    ) -> ReviewResult<ReviewOutcome> {
        let current = authority
            .owner
            .capsule()
            .current_review
            .as_ref()
            .ok_or_else(|| definite(Error::InvalidState))?;
        require_fresh_review_commitments(
            &current.edited_tree_commitment,
            &current.event_set_commitment,
            &authority.report.edited_tree_commitment,
            &authority.event_set_commitment,
        )
        .map_err(definite)?;
        if current.manifest_phase != ManifestPhase::Review
            || current.automatic_event_count != authority.events.automatic()
            || current.approval_eligible_count != authority.events.approval_required()
            || current.unconditional_reject_count != authority.events.rejected()
        {
            return Err(definite(Error::InvalidState));
        }
        let (owning_generation, authenticated) = authority
            .store
            .read_review_manifest(
                &mut authority.lock,
                &authority.owner,
                review_id,
                ManifestPhase::Review,
            )
            .map_err(manual)?;
        if owning_generation == 0
            || owning_generation > authority.owner.capsule().generation
            || !constant_time_equal(authenticated.commitment(), &current.manifest_commitment)
        {
            return Err(manual(Error::CorruptState));
        }
        let projected =
            project_review(&authority, &identities, owning_generation).map_err(definite)?;
        let payload = projected.manifest.encode_canonical().map_err(definite)?;
        if authenticated.as_bytes() != payload {
            return Err(manual(Error::CorruptState));
        }
        let decoded = ChangedManifestV1::decode_canonical(authenticated.as_bytes())
            .map_err(|_| manual(Error::CorruptState))?;
        if decoded != projected.manifest {
            return Err(manual(Error::CorruptState));
        }
        let authenticated_set = authenticate_approval_set(
            authority.owner.capsule(),
            &authority.owner.key_schedule(),
            &authority,
            &identities,
        )
        .map_err(definite)?;
        let approved_events = authenticated_set.approved_count().map_err(definite)?;
        let remaining_approval_events = authenticated_set.remaining_count().map_err(definite)?;
        let expected_state = approval_state(
            authority.events.rejected(),
            authority.events.approval_required(),
            approved_events,
        )
        .map_err(definite)?;
        if authority.owner.capsule().session_state != expected_state {
            return Err(definite(Error::InvalidState));
        }
        let approval_events = approval_event_reports(
            &authority,
            &identities,
            &authority.owner.capsule().approval_set.records,
        )
        .map_err(definite)?;
        authority.verify_selected_roots().map_err(definite)?;
        let fresh = authority
            .store
            .read_while_locked(&mut authority.lock)
            .map_err(manual)?;
        let fresh_head = fresh
            .live_head()
            .ok_or_else(|| manual(Error::CorruptState))?;
        if fresh.classification != StoreClassification::AuthoritativeLive
            || fresh.orphan_count != 0
            || fresh_head.capsule() != authority.owner.capsule()
            || !constant_time_equal(fresh_head.tag(), authority.owner.tag())
        {
            return Err(manual(Error::CorruptState));
        }
        let generation = authority.owner.capsule().generation;
        authority.lock.release().map_err(manual)?;
        Ok(outcome(
            projected.manifest,
            expected_state,
            generation,
            approved_events,
            remaining_approval_events,
            approval_events,
            true,
        ))
    }

    pub(super) fn require_fresh_review_commitments(
        stored_edited: &[u8; 32],
        stored_events: &[u8; 32],
        fresh_edited: &[u8; 32],
        fresh_events: &[u8; 32],
    ) -> crate::roundtrip::Result<()> {
        if !constant_time_equal(stored_edited, fresh_edited)
            || !constant_time_equal(stored_events, fresh_events)
        {
            return Err(Error::InvalidState);
        }
        Ok(())
    }

    const fn review_state(rejected: u32, approval_required: u32) -> SessionState {
        if rejected != 0 {
            SessionState::ReviewedRejected
        } else if approval_required != 0 {
            SessionState::Reviewed
        } else {
            SessionState::ReadyToApply
        }
    }

    fn approval_state(
        rejected: u32,
        approval_required: u32,
        approved: u32,
    ) -> crate::roundtrip::Result<SessionState> {
        if rejected != 0 {
            return if approved == 0 {
                Ok(SessionState::ReviewedRejected)
            } else {
                Err(Error::CorruptState)
            };
        }
        match approved.cmp(&approval_required) {
            std::cmp::Ordering::Greater => Err(Error::CorruptState),
            std::cmp::Ordering::Equal => Ok(SessionState::ReadyToApply),
            std::cmp::Ordering::Less if approved == 0 => Ok(SessionState::Reviewed),
            std::cmp::Ordering::Less => Ok(SessionState::ApprovedPartial),
        }
    }

    fn approval_event_reports(
        authority: &crate::roundtrip::classify::PreparedReviewAuthority,
        identities: &ReviewIdentityIndex,
        records: &[crate::roundtrip::schema::ApprovalRecordV1],
    ) -> crate::roundtrip::Result<Vec<ReviewApprovalEvent>> {
        let requirements = approval_requirements(authority, identities)?;
        let mut output = Vec::new();
        output
            .try_reserve_exact(requirements.len())
            .map_err(|_| Error::BoundExceeded)?;
        for requirement in requirements {
            let approved = records
                .binary_search_by_key(&requirement.event_id, |record| record.event_id)
                .is_ok();
            output.push(ReviewApprovalEvent {
                event_id: encode_base32_128(&requirement.event_id),
                event_type: requirement.event_type,
                required_reason: requirement.reason,
                approved,
            });
        }
        Ok(output)
    }

    fn outcome(
        manifest: ChangedManifestV1,
        session_state: SessionState,
        capsule_generation: u64,
        approved_events: u32,
        remaining_approval_events: u32,
        approval_events: Vec<ReviewApprovalEvent>,
        replayed: bool,
    ) -> ReviewOutcome {
        ReviewOutcome {
            report: ReviewReport {
                review_id: encode_base32_128(&manifest.review_id),
                profile: manifest.review_profile,
                engine_version: ENGINE_VERSION,
                policy_id: POLICY_ID,
                ruleset_id: manifest.ruleset_id.clone(),
                token_suite_id: TOKEN_SUITE_ID,
                capsule_generation,
                session_state,
                changed_files: manifest.summary.changed_files,
                changed_directories: manifest.summary.changed_directories,
                automatic_events: manifest.summary.automatic_events,
                approval_eligible_events: manifest.summary.approval_eligible_events,
                approved_events,
                remaining_approval_events,
                unconditional_rejects: manifest.summary.unconditional_rejects,
                approval_events,
                semantic_safety_assessed: false,
                replayed,
            },
            manifest,
        }
    }

    fn initial_failure(error: Error) -> ReviewFailure {
        match error {
            Error::CreateIncomplete
            | Error::PrivateOrphansPresent
            | Error::StateCommitUncertain
            | Error::CorruptState => manual(error),
            _ => definite(error),
        }
    }

    const fn definite(error: Error) -> ReviewFailure {
        ReviewFailure::DefiniteFailure(error)
    }

    const fn manual(error: Error) -> ReviewFailure {
        ReviewFailure::ManualInspectionRequired(error)
    }
}

#[cfg(all(test, windows))]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Mutex;

    use super::*;
    use crate::roundtrip::create::create_session;
    use crate::roundtrip::manifest::{
        ApprovalStateV1, ContentEventV1, DirectoryEventV1, FileEventV1, ManifestDecisionV1,
        ReasonCodeV1, TokenEventKindV1,
    };
    use crate::roundtrip::token::{ReviewProfile, TOKEN_PREFIX, TOKEN_SUFFIX};

    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);
    static REVIEW_TEST_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn fresh_review_authority_mismatches_remain_invalid_state() {
        let edited = [0x31; 32];
        let events = [0x32; 32];
        assert!(
            windows::require_fresh_review_commitments(&edited, &events, &edited, &events,).is_ok()
        );

        let mut edited_mismatch = edited;
        edited_mismatch[9] ^= 1;
        assert_eq!(
            windows::require_fresh_review_commitments(&edited, &events, &edited_mismatch, &events,),
            Err(Error::InvalidState)
        );
        let mut event_mismatch = events;
        event_mismatch[29] ^= 1;
        assert_eq!(
            windows::require_fresh_review_commitments(&edited, &events, &edited, &event_mismatch,),
            Err(Error::InvalidState)
        );
    }

    struct Fixture {
        root: PathBuf,
        original: PathBuf,
        ai: PathBuf,
        state: PathBuf,
    }

    impl Fixture {
        fn create(name: &str, bytes: &[u8], profile: ReviewProfile) -> Self {
            let serial = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir().join(format!(
                "safeclone-review-{name}-{}-{serial}",
                std::process::id()
            ));
            let original = root.join("OriginalWorkspace");
            let ai = root.join("AiWorkspaceLongFixtureName");
            let state = root.join("PrivateSessionDirectoryLongFixtureName");
            fs::create_dir_all(&original).expect("create Original");
            fs::write(original.join("main.txt"), bytes).expect("write Original file");
            create_session(&original, &ai, &state, profile).expect("create RT session");
            Self {
                root,
                original,
                ai,
                state,
            }
        }

        fn review(&self) -> ReviewResult<ReviewOutcome> {
            review_session(&self.original, &self.ai, &self.state)
        }

        fn create_tree(
            name: &str,
            files: &[(&str, &[u8])],
            directories: &[&str],
            profile: ReviewProfile,
        ) -> Self {
            let serial = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir().join(format!(
                "safeclone-review-{name}-{}-{serial}",
                std::process::id()
            ));
            let original = root.join("OriginalWorkspace");
            let ai = root.join("AiWorkspaceLongFixtureName");
            let state = root.join("PrivateSessionDirectoryLongFixtureName");
            fs::create_dir_all(&original).expect("create Original");
            for directory in directories {
                fs::create_dir_all(original.join(directory)).expect("create Original directory");
            }
            for (path, bytes) in files {
                let path = original.join(path);
                if let Some(parent) = path.parent() {
                    fs::create_dir_all(parent).expect("create Original file parent");
                }
                fs::write(path, bytes).expect("write Original file");
            }
            create_session(&original, &ai, &state, profile).expect("create RT session");
            Self {
                root,
                original,
                ai,
                state,
            }
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn zero_change_and_automatic_add_commit_ready_and_replay_exactly() {
        let _serial = REVIEW_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let fixture = Fixture::create("zero", b"ordinary baseline\n", ReviewProfile::StandardV2);
        let first = fixture.review().expect("zero-change review");
        assert_eq!(first.report().session_state, SessionState::ReadyToApply);
        assert_eq!(first.report().capsule_generation, 2);
        assert!(!first.report().replayed);
        assert!(first.manifest().files.is_empty());
        assert!(first.manifest().directories.is_empty());
        let first_default = first.render_default();
        let first_artifact_count = fs::read_dir(&fixture.state)
            .expect("read state after first review")
            .count();

        let replay = fixture.review().expect("exact review replay");
        assert_eq!(replay.report().capsule_generation, 2);
        assert!(replay.report().replayed);
        assert_eq!(replay.render_default(), first_default);
        assert_eq!(
            fs::read_dir(&fixture.state)
                .expect("read state after exact replay")
                .count(),
            first_artifact_count,
            "exact replay must append neither manifest nor capsule"
        );

        fs::write(fixture.ai.join("new.txt"), b"new safe text\n").expect("add edited file");
        let added = fixture.review().expect("automatic added-file review");
        assert_eq!(added.report().session_state, SessionState::ReadyToApply);
        assert_eq!(added.report().capsule_generation, 3);
        assert_eq!(added.manifest().files.len(), 1);
        assert_eq!(
            added.manifest().files[0].content_event,
            ContentEventV1::Added
        );
        assert!(!added.manifest().files[0].content_change_regions.is_empty());
        let added_default = added.render_default();
        let added_private = match added
            .prepare_private_review()
            .acknowledge_warning(CONFIDENTIAL_REVIEW_WARNING)
        {
            Ok(permit) => permit.render_private_paths(),
            Err(_) => panic!("exact warning acknowledgement rejected"),
        };
        let added_artifact_count = fs::read_dir(&fixture.state)
            .expect("read state after changed review")
            .count();
        let added_replay = fixture.review().expect("changed review replay");
        assert!(added_replay.report().replayed);
        assert_eq!(added_replay.report().capsule_generation, 3);
        assert_eq!(added_replay.render_default(), added_default);
        let replay_private = match added_replay
            .prepare_private_review()
            .acknowledge_warning(CONFIDENTIAL_REVIEW_WARNING)
        {
            Ok(permit) => permit.render_private_paths(),
            Err(_) => panic!("exact warning acknowledgement rejected"),
        };
        assert_eq!(replay_private, added_private);
        assert_eq!(
            fs::read_dir(&fixture.state)
                .expect("read state after changed replay")
                .count(),
            added_artifact_count,
            "changed exact replay must remain read-only"
        );
    }

    #[test]
    fn token_deletion_and_unknown_reject_choose_the_required_states() {
        let _serial = REVIEW_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let deletion = Fixture::create(
            "token-delete",
            b"before\ncontact=fixture.user@example.invalid\nafter\n",
            ReviewProfile::StandardV2,
        );
        let tokenized =
            fs::read_to_string(deletion.ai.join("main.txt")).expect("read tokenized AI");
        let start = tokenized.find(TOKEN_PREFIX).expect("token prefix");
        let suffix = tokenized[start + TOKEN_PREFIX.len()..]
            .find(TOKEN_SUFFIX)
            .expect("token suffix")
            + start
            + TOKEN_PREFIX.len();
        let mut edited = tokenized;
        edited.replace_range(start..suffix + TOKEN_SUFFIX.len(), "");
        fs::write(deletion.ai.join("main.txt"), edited).expect("delete exact token atom");
        let reviewed = deletion.review().expect("token deletion review");
        assert_eq!(reviewed.report().session_state, SessionState::Reviewed);
        assert_eq!(reviewed.report().approval_eligible_events, 1);
        assert_eq!(reviewed.report().unconditional_rejects, 0);

        let unknown = Fixture::create(
            "token-unknown",
            b"ordinary baseline\n",
            ReviewProfile::StandardV2,
        );
        fs::write(
            unknown.ai.join("main.txt"),
            b"ordinary baseline\n__SAFECLONE_RT1_MALFORMED__\n__SAFECLONE_RT1_MALFORMED__\n",
        )
        .expect("write unknown reserved form");
        let rejected = unknown.review().expect("unknown-token review");
        assert_eq!(
            rejected.report().session_state,
            SessionState::ReviewedRejected
        );
        let events = rejected.manifest().files[0]
            .token_events
            .iter()
            .filter(|event| event.event == TokenEventKindV1::TokenUnknown)
            .collect::<Vec<_>>();
        assert_eq!(events.len(), 2);
        assert_ne!(events[0].event_id, events[1].event_id);
        for event in events {
            assert!(event.token_id.is_none());
            assert!(event.category_expected.is_none());
            assert_eq!(event.decision, ManifestDecisionV1::Reject);
        }
    }

    #[test]
    fn strict_edit_file_deletion_and_tree_moves_use_fixed_projection_precedence() {
        let _serial = REVIEW_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let strict = Fixture::create(
            "strict",
            b"stable before\ncontact=strict.fixture@example.invalid\nstable after\n",
            ReviewProfile::StrictTokenFilesV2,
        );
        let tokenized = fs::read(strict.ai.join("main.txt")).expect("read strict AI file");
        let mut changed = b"unrelated inserted line\n".to_vec();
        changed.extend_from_slice(&tokenized);
        fs::write(strict.ai.join("main.txt"), changed).expect("edit strict AI file");
        let strict_review = strict.review().expect("strict review");
        assert_eq!(strict_review.report().session_state, SessionState::Reviewed);
        assert_eq!(strict_review.report().approval_eligible_events, 1);
        assert_eq!(strict_review.manifest().files.len(), 1);
        let strict_file = &strict_review.manifest().files[0];
        assert_eq!(
            strict_file.content_event,
            ContentEventV1::StrictReviewRequired
        );
        assert_eq!(strict_file.decision, ManifestDecisionV1::ApprovalRequired);
        assert!(!strict_file.content_change_regions.is_empty());
        assert!(!strict_file.anchors.is_empty());
        assert!(strict_file
            .token_events
            .iter()
            .any(|event| event.event == TokenEventKindV1::PreservedSameAnchor));

        let deleted = Fixture::create(
            "delete-file",
            b"ordinary deleted file\n",
            ReviewProfile::StandardV2,
        );
        fs::remove_file(deleted.ai.join("main.txt")).expect("delete AI file");
        let deleted_review = deleted.review().expect("deleted-file review");
        assert_eq!(
            deleted_review.report().session_state,
            SessionState::Reviewed
        );
        assert_eq!(deleted_review.manifest().files.len(), 1);
        let deleted_file = &deleted_review.manifest().files[0];
        assert_eq!(deleted_file.file_event, FileEventV1::Deleted);
        assert_eq!(deleted_file.content_event, ContentEventV1::Deleted);
        assert_eq!(deleted_file.content_change_regions.len(), 1);

        let tree = Fixture::create_tree(
            "tree-move",
            &[("folder/sub/main.txt", b"ordinary moved file\n")],
            &["folder/empty"],
            ReviewProfile::StandardV2,
        );
        fs::rename(tree.ai.join("folder"), tree.ai.join("renamed"))
            .expect("rename AI directory tree");
        let tree_review = tree.review().expect("directory-tree review");
        assert_eq!(
            tree_review.report().session_state,
            SessionState::ReadyToApply
        );
        assert_eq!(tree_review.manifest().directories.len(), 3);
        assert_eq!(tree_review.manifest().files.len(), 1);
        assert!(tree_review
            .manifest()
            .directories
            .iter()
            .any(|entry| entry.directory_event == DirectoryEventV1::Renamed));
        assert!(tree_review
            .manifest()
            .directories
            .iter()
            .any(|entry| entry.directory_event == DirectoryEventV1::Moved));
        assert_eq!(
            tree_review.manifest().files[0].file_event,
            FileEventV1::Moved
        );
        assert!(tree_review.manifest().files[0]
            .content_change_regions
            .is_empty());
    }

    #[test]
    fn standard_path_projection_and_directory_add_delete_are_changed_only() {
        let _serial = REVIEW_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let standard = Fixture::create(
            "standard-token-edit",
            b"top-a\ntop-b\ncontext-left\ncredential=standard.fixture@example.invalid;\ncontext-right\nbottom-a\nbottom-b\n",
            ReviewProfile::StandardV2,
        );
        let baseline = fs::read(standard.ai.join("main.txt")).expect("read Standard AI file");
        let mut edited = b"unrelated insertion\n".to_vec();
        edited.extend_from_slice(&baseline);
        fs::write(standard.ai.join("main.txt"), edited).expect("edit Standard AI file");
        let standard_review = standard.review().expect("Standard review");
        assert_eq!(
            standard_review.report().session_state,
            SessionState::ReadyToApply
        );
        let file = &standard_review.manifest().files[0];
        assert_eq!(file.content_event, ContentEventV1::Edited);
        assert!(!file.content_change_regions.is_empty());
        assert!(file
            .token_events
            .iter()
            .any(|event| event.event == TokenEventKindV1::PreservedSameAnchor));

        let path = Fixture::create_tree(
            "path-token-projection",
            &[("endpoint-192.0.2.10.txt", b"ordinary body\n")],
            &[],
            ReviewProfile::StandardV2,
        );
        let tokenized = fs::read_dir(&path.ai)
            .expect("read path-token AI")
            .next()
            .expect("path-token entry")
            .expect("path-token entry result")
            .path();
        let tokenized_name = tokenized
            .file_name()
            .and_then(|name| name.to_str())
            .expect("UTF-8 tokenized filename");
        let token_start = tokenized_name
            .find(TOKEN_PREFIX)
            .expect("path token prefix");
        let token_end = tokenized_name[token_start + TOKEN_PREFIX.len()..]
            .find(TOKEN_SUFFIX)
            .expect("path token suffix")
            + token_start
            + TOKEN_PREFIX.len()
            + TOKEN_SUFFIX.len();
        let projected_name = format!(
            "{}{}",
            &tokenized_name[..token_start],
            &tokenized_name[token_end..]
        );
        fs::rename(&tokenized, path.ai.join(&projected_name))
            .expect("exact path-token deletion projection");
        let path_review = path.review().expect("path-token review");
        assert_eq!(path_review.report().session_state, SessionState::Reviewed);
        assert_eq!(path_review.report().approval_eligible_events, 1);
        assert_eq!(path_review.manifest().files.len(), 1);
        let path_file = &path_review.manifest().files[0];
        assert_eq!(path_file.file_event, FileEventV1::Renamed);
        assert_eq!(path_file.content_event, ContentEventV1::Unchanged);
        assert!(path_file.content_change_regions.is_empty());
        assert!(path_file
            .token_events
            .iter()
            .any(|event| event.event == TokenEventKindV1::TokenDeleted));

        let directory_path = Fixture::create_tree(
            "directory-path-token-projection",
            &[("endpoint-192.0.2.10/main.txt", b"ordinary body\n")],
            &[],
            ReviewProfile::StandardV2,
        );
        let tokenized_directory = fs::read_dir(&directory_path.ai)
            .expect("read path-token directory AI")
            .next()
            .expect("path-token directory entry")
            .expect("path-token directory entry result")
            .path();
        assert!(tokenized_directory.is_dir());
        let tokenized_directory_name = tokenized_directory
            .file_name()
            .and_then(|name| name.to_str())
            .expect("UTF-8 tokenized directory name");
        let token_start = tokenized_directory_name
            .find(TOKEN_PREFIX)
            .expect("directory path token prefix");
        let token_end = tokenized_directory_name[token_start + TOKEN_PREFIX.len()..]
            .find(TOKEN_SUFFIX)
            .expect("directory path token suffix")
            + token_start
            + TOKEN_PREFIX.len()
            + TOKEN_SUFFIX.len();
        let projected_directory_name = format!(
            "{}{}",
            &tokenized_directory_name[..token_start],
            &tokenized_directory_name[token_end..]
        );
        fs::rename(
            &tokenized_directory,
            directory_path.ai.join(projected_directory_name),
        )
        .expect("exact directory path-token deletion projection");
        let directory_path_review = directory_path
            .review()
            .expect("directory path-token review");
        assert_eq!(
            directory_path_review.report().session_state,
            SessionState::Reviewed
        );
        assert_eq!(directory_path_review.report().approval_eligible_events, 1);
        let renamed_directory = directory_path_review
            .manifest()
            .directories
            .iter()
            .find(|entry| entry.directory_event == DirectoryEventV1::Renamed)
            .expect("renamed directory projection");
        assert_eq!(
            renamed_directory.decision,
            ManifestDecisionV1::ApprovalRequired
        );
        assert_eq!(renamed_directory.approval_state, ApprovalStateV1::Required);
        let directory_token = renamed_directory
            .token_events
            .iter()
            .find(|event| event.event == TokenEventKindV1::TokenDeleted)
            .expect("directory constituent token deletion");
        assert!(directory_token.anchor_id_before.is_some());
        assert!(directory_token.anchor_id_after.is_none());

        let directories = Fixture::create_tree(
            "directory-add-delete",
            &[("main.txt", b"ordinary baseline\n")],
            &["deleted-empty"],
            ReviewProfile::StandardV2,
        );
        fs::remove_dir(directories.ai.join("deleted-empty")).expect("delete empty AI directory");
        // Two identical additions deliberately prevent classification's exact unique
        // empty-directory correspondence from classifying this as a rename.
        fs::create_dir(directories.ai.join("added-empty-a")).expect("add first empty directory");
        fs::create_dir(directories.ai.join("added-empty-b")).expect("add second empty directory");
        let directory_review = directories.review().expect("directory add/delete review");
        assert_eq!(
            directory_review.report().session_state,
            SessionState::ReadyToApply
        );
        assert!(directory_review.manifest().files.is_empty());
        assert_eq!(directory_review.manifest().directories.len(), 3);
        assert!(directory_review
            .manifest()
            .directories
            .iter()
            .any(|entry| entry.directory_event == DirectoryEventV1::Added));
        assert!(directory_review
            .manifest()
            .directories
            .iter()
            .any(|entry| entry.directory_event == DirectoryEventV1::Deleted));
    }

    #[test]
    fn sensitive_duplicate_context_and_core_rejects_remain_explicit() {
        let _serial = REVIEW_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let sensitive = Fixture::create(
            "new-sensitive",
            b"ordinary baseline\n",
            ReviewProfile::StandardV2,
        );
        fs::write(
            sensitive.ai.join("new-sensitive.txt"),
            b"new.sensitive.fixture@example.invalid\n",
        )
        .expect("add new sensitive file");
        let sensitive_review = sensitive.review().expect("new-sensitive review");
        assert_eq!(
            sensitive_review.report().session_state,
            SessionState::ReviewedRejected
        );
        assert!(sensitive_review.manifest().files.iter().any(|file| file
            .reason_codes
            .contains(&ReasonCodeV1::NewUntokenizedSensitiveFinding)));

        let duplicate = Fixture::create(
            "token-duplicate",
            b"top-a\ntop-b\ncontext-left\ncredential=duplicate.fixture@example.invalid;\ncontext-right\nbottom-a\nbottom-b\n",
            ReviewProfile::StandardV2,
        );
        let duplicate_baseline =
            fs::read(duplicate.ai.join("main.txt")).expect("read duplicate baseline");
        let token_start = duplicate_baseline
            .windows(TOKEN_PREFIX.len())
            .position(|window| window == TOKEN_PREFIX.as_bytes())
            .expect("duplicate token prefix");
        let token_body = token_start + TOKEN_PREFIX.len();
        let token_end = duplicate_baseline[token_body..]
            .windows(TOKEN_SUFFIX.len())
            .position(|window| window == TOKEN_SUFFIX.as_bytes())
            .expect("duplicate token suffix")
            + token_body
            + TOKEN_SUFFIX.len();
        let mut duplicate_bytes = duplicate_baseline.clone();
        duplicate_bytes.extend_from_slice(b"duplicate=");
        duplicate_bytes.extend_from_slice(&duplicate_baseline[token_start..token_end]);
        duplicate_bytes.push(b'\n');
        fs::write(duplicate.ai.join("main.txt"), duplicate_bytes).expect("duplicate token");
        let duplicate_review = duplicate.review().expect("duplicate review");
        assert_eq!(
            duplicate_review.report().session_state,
            SessionState::ReviewedRejected
        );
        assert!(duplicate_review.manifest().files[0]
            .token_events
            .iter()
            .any(|event| event.event == TokenEventKindV1::TokenDuplicated));

        for (name, expected) in [
            ("context-reject", TokenEventKindV1::ProtectedContextChanged),
            ("core-reject", TokenEventKindV1::ProtectedCoreChanged),
        ] {
            let fixture = Fixture::create(
                name,
                b"top-a\ntop-b\ncontext-left\ncredential=anchor.fixture@example.invalid;\ncontext-right\nbottom-a\nbottom-b\n",
                ReviewProfile::StandardV2,
            );
            let baseline = fs::read(fixture.ai.join("main.txt")).expect("read anchor baseline");
            let changed = if name == "context-reject" {
                let from = b"context-left";
                let position = baseline
                    .windows(from.len())
                    .position(|window| window == from)
                    .expect("context mutation input");
                let mut changed = Vec::new();
                changed.extend_from_slice(&baseline[..position]);
                changed.extend_from_slice(b"context-changed");
                changed.extend_from_slice(&baseline[position + from.len()..]);
                changed
            } else {
                let position = baseline
                    .windows(TOKEN_PREFIX.len())
                    .position(|window| window == TOKEN_PREFIX.as_bytes())
                    .expect("core token boundary");
                let mut changed = Vec::new();
                changed.extend_from_slice(&baseline[..position]);
                changed.push(b' ');
                changed.extend_from_slice(&baseline[position..]);
                changed
            };
            fs::write(fixture.ai.join("main.txt"), changed).expect("write anchor mutation");
            let outcome = fixture.review().expect("anchor reject review");
            assert_eq!(
                outcome.report().session_state,
                SessionState::ReviewedRejected
            );
            assert!(outcome.manifest().files[0]
                .token_events
                .iter()
                .any(|event| event.event == expected));
        }
    }

    #[test]
    fn exact_replay_cross_session_and_unknown_position_separation_are_keyed() {
        let _serial = REVIEW_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        fn unknown_ids(outcome: &ReviewOutcome) -> Vec<[u8; 16]> {
            outcome
                .manifest()
                .files
                .iter()
                .flat_map(|file| file.token_events.iter())
                .filter(|event| event.event == TokenEventKindV1::TokenUnknown)
                .map(|event| event.event_id)
                .collect()
        }

        let first = Fixture::create(
            "unknown-id-a",
            b"ordinary baseline\n",
            ReviewProfile::StandardV2,
        );
        fs::write(
            first.ai.join("main.txt"),
            b"ordinary baseline\n__SAFECLONE_RT1_MALFORMED__\n__SAFECLONE_RT1_MALFORMED__\n",
        )
        .expect("write two unknown forms");
        let first_review = first.review().expect("first unknown review");
        let first_review_id = first_review.manifest().review_id;
        let first_event_ids = unknown_ids(&first_review);
        assert_eq!(first_event_ids.len(), 2);
        assert_ne!(first_event_ids[0], first_event_ids[1]);

        let replay = first.review().expect("unknown exact replay");
        assert!(replay.report().replayed);
        assert_eq!(replay.manifest().review_id, first_review_id);
        assert_eq!(unknown_ids(&replay), first_event_ids);

        fs::write(
            first.ai.join("main.txt"),
            b"moved one line\nordinary baseline\n__SAFECLONE_RT1_MALFORMED__\n__SAFECLONE_RT1_MALFORMED__\n",
        )
        .expect("move unknown forms");
        let moved = first.review().expect("moved unknown review");
        assert_ne!(moved.manifest().review_id, first_review_id);
        assert_ne!(unknown_ids(&moved), first_event_ids);

        let second = Fixture::create(
            "unknown-id-b",
            b"ordinary baseline\n",
            ReviewProfile::StandardV2,
        );
        fs::write(
            second.ai.join("main.txt"),
            b"ordinary baseline\n__SAFECLONE_RT1_MALFORMED__\n__SAFECLONE_RT1_MALFORMED__\n",
        )
        .expect("write same cross-session forms");
        let second_review = second.review().expect("cross-session unknown review");
        assert_ne!(second_review.manifest().review_id, first_review_id);
        assert_ne!(unknown_ids(&second_review), first_event_ids);
    }

    #[test]
    fn reporting_bound_failure_commits_neither_manifest_nor_review_capsule() {
        let _serial = REVIEW_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let fixture = Fixture::create(
            "report-bound",
            b"ordinary baseline\n",
            ReviewProfile::StandardV2,
        );
        let too_many_lines = b"x\n".repeat(65_537);
        fs::write(fixture.ai.join("too-many-lines.txt"), too_many_lines)
            .expect("write line-bound file");
        assert_eq!(
            fixture.review().err(),
            Some(ReviewFailure::DefiniteFailure(
                Error::ChangeReportBoundExceeded
            ))
        );
        fs::remove_file(fixture.ai.join("too-many-lines.txt")).expect("remove bound fixture");
        let clean = fixture.review().expect("review after reporting failure");
        assert_eq!(clean.report().capsule_generation, 2);
        assert!(clean.manifest().files.is_empty());
        assert!(clean.manifest().directories.is_empty());
    }

    #[test]
    fn structural_hard_link_reject_is_value_free_and_never_enters_reporting_diff() {
        let _serial = REVIEW_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let fixture = Fixture::create(
            "hard-link-report",
            b"ordinary baseline\n",
            ReviewProfile::StandardV2,
        );
        let secret = b"EXTERNAL-HARD-LINK-SECRET-CANARY-RT4";
        let outside = fixture.root.join("outside-secret.txt");
        fs::write(&outside, secret).expect("write external hard-link source");
        fs::hard_link(&outside, fixture.ai.join("linked.txt"))
            .expect("create hostile edited hard link");

        let review = fixture.review().expect("commit structural reject review");
        assert_eq!(
            review.report().session_state,
            SessionState::ReviewedRejected
        );
        assert_eq!(review.manifest().files.len(), 1);
        let file = &review.manifest().files[0];
        assert_eq!(file.file_event, FileEventV1::Added);
        assert_eq!(file.content_event, ContentEventV1::Unchanged);
        assert!(file.content_change_regions.is_empty());
        assert_eq!(file.decision, ManifestDecisionV1::Reject);
        assert!(file.reason_codes.contains(&ReasonCodeV1::HardLink));
        let plaintext = review
            .manifest()
            .encode_canonical()
            .expect("encode decrypted manifest");
        assert!(!plaintext
            .windows(secret.len())
            .any(|window| window == secret));
        assert!(!review.render_default().contains("linked.txt"));
    }

    #[test]
    fn foreign_observed_oid_is_never_persisted_as_baseline_identity() {
        let _serial = REVIEW_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let source = Fixture::create(
            "foreign-token-source",
            b"foreign.source@example.invalid\n",
            ReviewProfile::StandardV2,
        );
        let foreign_text =
            fs::read_to_string(source.ai.join("main.txt")).expect("read foreign token source");
        let start = foreign_text
            .find(TOKEN_PREFIX)
            .expect("foreign token prefix");
        let end = foreign_text[start + TOKEN_PREFIX.len()..]
            .find(TOKEN_SUFFIX)
            .expect("foreign token suffix")
            + start
            + TOKEN_PREFIX.len()
            + TOKEN_SUFFIX.len();
        let foreign_token = &foreign_text[start..end];
        let observed_oid = *crate::roundtrip::token::parse_token(foreign_token)
            .expect("parse foreign token")
            .occurrence_id();

        let target = Fixture::create(
            "foreign-token-target",
            b"ordinary baseline\n",
            ReviewProfile::StandardV2,
        );
        fs::write(
            target.ai.join("main.txt"),
            format!("ordinary baseline\n{foreign_token}\n"),
        )
        .expect("write foreign token into target");
        let outcome = target.review().expect("foreign-token review");
        let unknown = outcome.manifest().files[0]
            .token_events
            .iter()
            .find(|event| event.event == TokenEventKindV1::TokenUnknown)
            .expect("foreign token unknown event");
        assert!(unknown.token_id.is_none());
        assert!(unknown.category_expected.is_none());
        assert!(unknown.category_observed.is_some());
        let encoded = outcome
            .manifest()
            .encode_canonical()
            .expect("foreign manifest encoding");
        assert!(!encoded
            .windows(observed_oid.len())
            .any(|window| window == observed_oid));
        assert!(!String::from_utf8_lossy(&encoded).contains(foreign_token));
    }

    #[test]
    #[ignore = "requires an actual ordinary-user local NTFS volume with 8.3 creation enabled"]
    fn enabled_ntfs_generated_alias_is_observation_only_for_review() {
        use crate::roundtrip::observe::{
            qualify_roundtrip_create_volumes, NamespaceScope, QualifiedCreateVolumePaths,
        };

        fn observed_alias(parent: &Path, exact_leaf: &str) -> String {
            let preflight = crate::locality::preflight_roundtrip_create_paths(
                parent,
                &parent.join("UnusedAiLeafForRt4AliasObservation"),
                &parent.join("UnusedStateLeafForRt4AliasObservation"),
            )
            .expect("alias observation preflight");
            let confirmed = crate::locality::open_and_confirm_roundtrip_volumes(preflight)
                .expect("alias observation volumes");
            let QualifiedCreateVolumePaths { original, .. } =
                qualify_roundtrip_create_volumes(confirmed).expect("alias policy");
            let parent = original
                .open_directory(NamespaceScope::PathSelection)
                .expect("open alias parent");
            let observation = parent.observe().expect("observe alias parent");
            let entry = observation
                .find_exact_long(exact_leaf)
                .expect("find exact canonical long leaf");
            String::from_utf16(
                entry
                    .short_alias_utf16()
                    .expect("enabled NTFS fixture generated a short alias"),
            )
            .expect("short alias UTF-16")
        }

        let _serial = REVIEW_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let long_leaf = "ordinary-long-filename-for-private-review-fixture.txt";
        let fixture = Fixture::create_tree(
            "generated-alias",
            &[(long_leaf, b"ordinary baseline\n")],
            &[],
            ReviewProfile::StandardV2,
        );
        let alias = observed_alias(&fixture.ai, long_leaf);
        assert_ne!(alias, long_leaf);
        fs::write(
            fixture.ai.join(long_leaf),
            b"ordinary baseline\nchanged reporting line\n",
        )
        .expect("change canonical long file");
        let outcome = fixture.review().expect("alias-bearing NTFS review");
        let encoded = outcome
            .manifest()
            .encode_canonical()
            .expect("alias manifest encoding");
        assert!(String::from_utf8_lossy(&encoded).contains(long_leaf));
        assert!(!String::from_utf8_lossy(&encoded).contains(&alias));
        assert!(!outcome.render_default().contains(&alias));
        let gate = outcome.prepare_private_review();
        let permit = match gate.acknowledge_warning(CONFIDENTIAL_REVIEW_WARNING) {
            Ok(permit) => permit,
            Err(_) => panic!("exact warning acknowledgement rejected"),
        };
        let private = permit.render_private_paths();
        assert!(private.contains(long_leaf));
        assert!(!private.contains(&alias));
    }

    #[test]
    fn default_and_private_rendering_enforce_the_warning_and_path_allowlist() {
        let _serial = REVIEW_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let original_name = "confidential-original-path-canary.txt";
        let safe_path_canary = "safe-path-canary.txt";
        let raw_content = "raw-original-content-canary";
        let raw_edited_content = "raw-edited-changed-content-canary";
        let raw_secret = "renderer.secret@example.invalid";
        let raw_context = "raw-context-line-canary";
        let alias_canary = "CONFIDENTIALORIGINALPATHCANARY~1.TXT";
        let fixture = Fixture::create_tree(
            "render-private",
            &[(
                original_name,
                format!("{raw_content}\n{raw_context}\n{raw_secret}\n").as_bytes(),
            )],
            &[],
            ReviewProfile::StandardV2,
        );
        let generated_safe = fs::read_dir(&fixture.ai)
            .expect("read AI")
            .next()
            .expect("AI entry")
            .expect("AI entry result")
            .file_name();
        fs::rename(
            fixture.ai.join(&generated_safe),
            fixture.ai.join(safe_path_canary),
        )
        .expect("rename safe path");
        fs::write(
            fixture.ai.join(safe_path_canary),
            format!("{raw_edited_content}\n{raw_secret}\n{raw_context}\n{alias_canary}\n"),
        )
        .expect("write changed AI canaries");
        let absolute_root = fixture.root.to_string_lossy().into_owned();
        let outcome = fixture.review().expect("private rendering review");
        let encoded = outcome
            .manifest()
            .encode_canonical()
            .expect("manifest bytes");
        let encoded_text = String::from_utf8_lossy(&encoded);
        assert!(encoded_text.contains(original_name));
        assert!(encoded_text.contains(safe_path_canary));
        for canary in [
            raw_content,
            raw_edited_content,
            raw_secret,
            raw_context,
            alias_canary,
            absolute_root.as_str(),
        ] {
            assert!(!encoded_text.contains(canary), "manifest leaked {canary}");
        }

        let default = outcome.render_default();
        for canary in [
            original_name,
            safe_path_canary,
            raw_content,
            raw_edited_content,
            raw_secret,
            raw_context,
            alias_canary,
            absolute_root.as_str(),
        ] {
            assert!(!default.contains(canary), "default leaked {canary}");
        }
        let gate = outcome.prepare_private_review();
        assert_eq!(gate.warning(), CONFIDENTIAL_REVIEW_WARNING);
        let gate = match gate.acknowledge_warning("warning=wrong") {
            Ok(_) => panic!("wrong warning issued a permit"),
            Err(gate) => gate,
        };
        let permit = match gate.acknowledge_warning(CONFIDENTIAL_REVIEW_WARNING) {
            Ok(permit) => permit,
            Err(_) => panic!("exact warning acknowledgement rejected"),
        };
        let private = permit.render_private_paths();
        assert!(private.contains(original_name));
        assert!(private.contains(safe_path_canary));
        for canary in [
            raw_content,
            raw_edited_content,
            raw_secret,
            raw_context,
            alias_canary,
            absolute_root.as_str(),
        ] {
            assert!(
                !private.contains(canary),
                "private renderer leaked {canary}"
            );
        }

        fn collect_files(root: &Path, output: &mut Vec<PathBuf>) {
            for entry in fs::read_dir(root).expect("read private artifact directory") {
                let path = entry.expect("private artifact entry").path();
                if path.is_dir() {
                    collect_files(&path, output);
                } else {
                    output.push(path);
                }
            }
        }
        let mut artifacts = Vec::new();
        collect_files(&fixture.state, &mut artifacts);
        assert!(!artifacts.is_empty());
        for artifact in artifacts {
            let bytes = fs::read(&artifact).expect("read encrypted private artifact");
            let view = String::from_utf8_lossy(&bytes);
            for canary in [
                original_name,
                safe_path_canary,
                raw_content,
                raw_edited_content,
                raw_secret,
                raw_context,
                alias_canary,
                absolute_root.as_str(),
            ] {
                assert!(
                    !view.contains(canary),
                    "private artifact plaintext leaked {canary}"
                );
            }
        }
    }

    #[test]
    fn interruption_after_manifest_commit_is_a_non_adoptable_private_orphan() {
        let _serial = REVIEW_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let fixture = Fixture::create(
            "split-commit",
            b"ordinary baseline\n",
            ReviewProfile::StandardV2,
        );
        fs::write(fixture.ai.join("new.txt"), b"new safe text\n").expect("add file");
        let _hook = windows::install_test_hook(|checkpoint| {
            assert_eq!(checkpoint, windows::TestCheckpoint::AfterManifestCommit);
            Err(Error::FilesystemFailure)
        });
        assert_eq!(
            fixture.review().err(),
            Some(ReviewFailure::ManualInspectionRequired(
                Error::FilesystemFailure
            ))
        );
        drop(_hook);
        assert_eq!(
            fixture.review().err(),
            Some(ReviewFailure::ManualInspectionRequired(
                Error::PrivateOrphansPresent
            ))
        );
    }
}
