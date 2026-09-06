//! One-event approval transaction.
//!
//! CLI parsing is separate. Each invocation accepts exactly one review
//! ID, one event ID, and one typed reason, then either appends one immutable
//! capsule generation or returns an exact duplicate as a read-only success.

use std::fmt;
use std::path::Path;

use super::schema::{ApprovalReason, SessionState};
use super::Error;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApprovalOutcome {
    pub session_id: String,
    pub review_id: String,
    pub event_id: String,
    pub reason: ApprovalReason,
    pub capsule_generation: u64,
    pub session_state: SessionState,
    pub approved_count: u32,
    pub remaining_required_count: u32,
    pub duplicate: bool,
    pub semantic_safety_assessed: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApprovalFailure {
    DefiniteFailure(Error),
    ManualInspectionRequired(Error),
}

impl ApprovalFailure {
    pub const fn error(self) -> Error {
        match self {
            Self::DefiniteFailure(error) | Self::ManualInspectionRequired(error) => error,
        }
    }
}

impl fmt::Display for ApprovalFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DefiniteFailure(error) => {
                write!(formatter, "round-trip approval failed: {error}")
            }
            Self::ManualInspectionRequired(error) => write!(
                formatter,
                "round-trip approval requires manual inspection: {error}"
            ),
        }
    }
}

impl std::error::Error for ApprovalFailure {}

pub type ApprovalResult<T> = std::result::Result<T, ApprovalFailure>;

#[cfg(not(windows))]
pub fn approve_review_event(
    _original: &Path,
    _ai_workspace: &Path,
    _private_state: &Path,
    _review_id: [u8; 16],
    _event_id: [u8; 16],
    _reason: ApprovalReason,
) -> ApprovalResult<ApprovalOutcome> {
    Err(ApprovalFailure::DefiniteFailure(Error::UnsupportedPlatform))
}

#[cfg(windows)]
pub fn approve_review_event(
    original: &Path,
    ai_workspace: &Path,
    private_state: &Path,
    review_id: [u8; 16],
    event_id: [u8; 16],
    reason: ApprovalReason,
) -> ApprovalResult<ApprovalOutcome> {
    windows::approve_review_event(
        original,
        ai_workspace,
        private_state,
        review_id,
        event_id,
        reason,
    )
}

#[cfg(windows)]
mod windows {
    use super::*;
    use crate::roundtrip::approval::{
        authenticate_approval_set, insert_new_approval, require_approval_operation_state,
        requirement_by_id,
    };
    use crate::roundtrip::capsule::StoreClassification;
    use crate::roundtrip::crypto::constant_time_equal;
    use crate::roundtrip::dpapi::protect_next_live_capsule;
    use crate::roundtrip::review_identity::ReviewIdentityIndex;
    use crate::roundtrip::schema::CapsuleV1;
    use crate::roundtrip::token::encode_base32_128;

    pub(super) fn approve_review_event(
        original: &Path,
        ai_workspace: &Path,
        private_state: &Path,
        input_review_id: [u8; 16],
        input_event_id: [u8; 16],
        input_reason: ApprovalReason,
    ) -> ApprovalResult<ApprovalOutcome> {
        let mut authority = crate::roundtrip::classify::prepare_approval_authority(
            original,
            ai_workspace,
            private_state,
        )
        .map_err(initial_failure)?;
        let identities = ReviewIdentityIndex::derive(&authority).map_err(definite)?;
        let current = authority.owner.capsule();
        current.validate_capsule_state().map_err(definite)?;

        let current_review = current
            .current_review
            .as_ref()
            .ok_or_else(|| definite(Error::InvalidState))?;
        let authenticated = authenticate_approval_set(
            current,
            &authority.owner.key_schedule(),
            &authority,
            &identities,
        )
        .map_err(definite)?;
        if !constant_time_equal(&input_review_id, &current_review.review_id)
            || !constant_time_equal(&input_review_id, &identities.review_id())
        {
            return Err(definite(Error::ApprovalStale));
        }
        let requirement =
            requirement_by_id(&authority, &identities, &input_event_id).map_err(definite)?;
        if input_reason != requirement.reason {
            return Err(definite(Error::ApprovalReasonMismatch));
        }

        if let Some(record) = authenticated.find(&input_event_id) {
            if record.event_type != requirement.event_type
                || record.reason_code != input_reason
                || record.edited_tree_commitment != current_review.edited_tree_commitment
            {
                return Err(definite(Error::ApprovalConflict));
            }
            require_approval_operation_state(current.session_state, true).map_err(definite)?;
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
                || fresh_head.capsule() != current
                || !constant_time_equal(fresh_head.tag(), authority.owner.tag())
            {
                return Err(manual(Error::CorruptState));
            }
            authenticate_approval_set(
                fresh_head.capsule(),
                &fresh_head.key_schedule(),
                &authority,
                &identities,
            )
            .map_err(manual)?;
            let outcome = outcome(
                fresh_head.capsule(),
                input_event_id,
                input_reason,
                authenticated.approved_count().map_err(definite)?,
                authenticated.remaining_count().map_err(definite)?,
                true,
            )?;
            authority.lock.release().map_err(manual)?;
            return Ok(outcome);
        }

        if require_approval_operation_state(current.session_state, false).is_err()
            || current_review.unconditional_reject_count != 0
            || current.apply_authority.is_some()
        {
            return Err(definite(Error::InvalidState));
        }

        let next_generation = current
            .generation
            .checked_add(1)
            .ok_or_else(|| definite(Error::InvalidState))?;
        let schedule = authority.owner.key_schedule();
        let (next_set, next_state) = insert_new_approval(
            &schedule,
            current,
            &authenticated,
            requirement,
            next_generation,
        )
        .map_err(definite)?;
        let mut next: CapsuleV1 = current.clone();
        next.generation = next_generation;
        next.session_state = next_state;
        next.approval_set = next_set;
        next.apply_authority = None;
        next.orphan_count_at_commit = 0;
        next.semantic_safety_assessed = false;
        next.validate_capsule_state().map_err(definite)?;
        if next.current_review.as_ref() != Some(current_review) {
            return Err(definite(Error::InvalidState));
        }
        authority.verify_selected_roots().map_err(definite)?;
        let protected = protect_next_live_capsule(&authority.owner, &next).map_err(definite)?;

        let append = authority
            .store
            .append_capsule_generation(&mut authority.lock, &protected);
        let committed = match append {
            Ok(committed) => committed,
            Err(error) => {
                let result = resolve_failed_append(
                    &mut authority,
                    &identities,
                    &next,
                    input_event_id,
                    input_reason,
                    error,
                )?;
                authority.lock.release().map_err(manual)?;
                return Ok(result);
            }
        };
        if committed.generation != next_generation
            || committed.root_identity != authority.store.root_identity()
        {
            return Err(manual(Error::StateCommitUncertain));
        }
        let result = finish_committed(
            &mut authority,
            &identities,
            &next,
            input_event_id,
            input_reason,
        )?;
        authority.lock.release().map_err(manual)?;
        Ok(result)
    }

    fn resolve_failed_append(
        authority: &mut crate::roundtrip::classify::PreparedReviewAuthority,
        identities: &ReviewIdentityIndex,
        next: &CapsuleV1,
        event_id: [u8; 16],
        reason: ApprovalReason,
        append_error: Error,
    ) -> ApprovalResult<ApprovalOutcome> {
        let observation = match authority.store.read_while_locked(&mut authority.lock) {
            Ok(observation) => observation,
            Err(_) => return Err(manual(Error::StateCommitUncertain)),
        };
        if observation.classification == StoreClassification::AuthoritativeLive
            && observation.orphan_count == 0
        {
            if let Some(head) = observation.live_head() {
                if head.capsule() == next {
                    return finish_observed_head(
                        authority, identities, head, next, event_id, reason,
                    );
                }
                if head.capsule() == authority.owner.capsule()
                    && constant_time_equal(head.tag(), authority.owner.tag())
                {
                    return Err(definite(append_error));
                }
            }
        }
        Err(manual(match append_error {
            Error::StateCommitUncertain | Error::CorruptState => Error::StateCommitUncertain,
            Error::PrivateOrphansPresent => Error::PrivateOrphansPresent,
            _ => Error::StateCommitUncertain,
        }))
    }

    fn finish_committed(
        authority: &mut crate::roundtrip::classify::PreparedReviewAuthority,
        identities: &ReviewIdentityIndex,
        next: &CapsuleV1,
        event_id: [u8; 16],
        reason: ApprovalReason,
    ) -> ApprovalResult<ApprovalOutcome> {
        let observation = authority
            .store
            .read_while_locked(&mut authority.lock)
            .map_err(|_| manual(Error::StateCommitUncertain))?;
        let head = observation
            .live_head()
            .ok_or_else(|| manual(Error::StateCommitUncertain))?;
        if observation.classification != StoreClassification::AuthoritativeLive
            || observation.orphan_count != 0
            || head.capsule() != next
        {
            return Err(manual(Error::StateCommitUncertain));
        }
        finish_observed_head(authority, identities, head, next, event_id, reason)
    }

    fn finish_observed_head(
        authority: &mut crate::roundtrip::classify::PreparedReviewAuthority,
        identities: &ReviewIdentityIndex,
        head: &crate::roundtrip::dpapi::AuthenticatedLiveCapsule,
        next: &CapsuleV1,
        event_id: [u8; 16],
        reason: ApprovalReason,
    ) -> ApprovalResult<ApprovalOutcome> {
        if head.capsule() != next {
            return Err(manual(Error::StateCommitUncertain));
        }
        let authenticated =
            authenticate_approval_set(head.capsule(), &head.key_schedule(), authority, identities)
                .map_err(|_| manual(Error::StateCommitUncertain))?;
        let record = authenticated
            .find(&event_id)
            .ok_or_else(|| manual(Error::StateCommitUncertain))?;
        if record.reason_code != reason || record.approved_in_generation != next.generation {
            return Err(manual(Error::StateCommitUncertain));
        }
        authority
            .verify_selected_roots()
            .map_err(|_| manual(Error::StateCommitUncertain))?;
        let result = outcome(
            head.capsule(),
            event_id,
            reason,
            authenticated
                .approved_count()
                .map_err(|_| manual(Error::StateCommitUncertain))?,
            authenticated
                .remaining_count()
                .map_err(|_| manual(Error::StateCommitUncertain))?,
            false,
        )?;
        Ok(result)
    }

    fn outcome(
        capsule: &CapsuleV1,
        event_id: [u8; 16],
        reason: ApprovalReason,
        approved_count: u32,
        remaining_required_count: u32,
        duplicate: bool,
    ) -> ApprovalResult<ApprovalOutcome> {
        let review = capsule
            .current_review
            .as_ref()
            .ok_or_else(|| definite(Error::InvalidState))?;
        Ok(ApprovalOutcome {
            session_id: encode_base32_128(capsule.session_id.as_bytes()),
            review_id: encode_base32_128(&review.review_id),
            event_id: encode_base32_128(&event_id),
            reason,
            capsule_generation: capsule.generation,
            session_state: capsule.session_state,
            approved_count,
            remaining_required_count,
            duplicate,
            semantic_safety_assessed: false,
        })
    }

    fn initial_failure(error: Error) -> ApprovalFailure {
        match error {
            Error::OriginalBaselineMismatch => definite(Error::ApprovalStale),
            Error::CreateIncomplete
            | Error::PrivateOrphansPresent
            | Error::StateCommitUncertain
            | Error::CorruptState => manual(error),
            _ => definite(error),
        }
    }

    const fn definite(error: Error) -> ApprovalFailure {
        ApprovalFailure::DefiniteFailure(error)
    }

    const fn manual(error: Error) -> ApprovalFailure {
        ApprovalFailure::ManualInspectionRequired(error)
    }
}

#[cfg(all(test, windows))]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Mutex;

    use super::*;
    use crate::roundtrip::approval::approval_set_tag;
    use crate::roundtrip::create::create_session;
    use crate::roundtrip::dpapi::protect_next_live_capsule;
    use crate::roundtrip::events::{EventDecision, EventKind};
    use crate::roundtrip::review::{review_session, ReviewApprovalEvent, ReviewOutcome};
    use crate::roundtrip::review_identity::ReviewIdentityIndex;
    use crate::roundtrip::schema::ApprovalEventType;
    use crate::roundtrip::token::{decode_base32_128, ReviewProfile, TOKEN_PREFIX, TOKEN_SUFFIX};

    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);
    static APPROVAL_TEST_LOCK: Mutex<()> = Mutex::new(());
    const CHILD_MODE_ENV: &str = "SAFECLONE_TEST_APPROVAL_CHILD_MODE";
    const CHILD_ORIGINAL_ENV: &str = "SAFECLONE_TEST_APPROVAL_CHILD_ORIGINAL";
    const CHILD_AI_ENV: &str = "SAFECLONE_TEST_APPROVAL_CHILD_AI";
    const CHILD_STATE_ENV: &str = "SAFECLONE_TEST_APPROVAL_CHILD_STATE";
    const CHILD_REVIEW_ENV: &str = "SAFECLONE_TEST_APPROVAL_CHILD_REVIEW";
    const CHILD_EVENT_ENV: &str = "SAFECLONE_TEST_APPROVAL_CHILD_EVENT";
    const CHILD_CHECKPOINT_ENV: &str = "SAFECLONE_TEST_APPROVAL_COMMIT_CHECKPOINT";
    const CHILD_TEST_NAME: &str = "roundtrip::approve::tests::approval_checkpoint_child";

    struct Fixture {
        root: PathBuf,
        original: PathBuf,
        ai: PathBuf,
        state: PathBuf,
    }

    impl Fixture {
        fn create(name: &str, bytes: &[u8], profile: ReviewProfile) -> Self {
            Self::create_tree(name, &[("main.txt", bytes)], &[], profile)
        }

        fn create_tree(
            name: &str,
            files: &[(&str, &[u8])],
            directories: &[&str],
            profile: ReviewProfile,
        ) -> Self {
            let serial = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir().join(format!(
                "safeclone-approval-{name}-{}-{serial}",
                std::process::id()
            ));
            let original = root.join("OriginalWorkspace");
            let ai = root.join("AiWorkspaceLongFixtureName");
            let state = root.join("PrivateSessionDirectoryLongFixtureName");
            fs::create_dir_all(&original).expect("create synthetic Original");
            for directory in directories {
                fs::create_dir_all(original.join(directory))
                    .expect("create synthetic Original directory");
            }
            for (path, bytes) in files {
                let target = original.join(path);
                if let Some(parent) = target.parent() {
                    fs::create_dir_all(parent).expect("create synthetic file parent");
                }
                fs::write(target, bytes).expect("write synthetic Original file");
            }
            create_session(&original, &ai, &state, profile).expect("create approval session");
            Self {
                root,
                original,
                ai,
                state,
            }
        }

        fn review(&self) -> ReviewOutcome {
            review_session(&self.original, &self.ai, &self.state).expect("review approval fixture")
        }

        fn approve(
            &self,
            review: &ReviewOutcome,
            event: &ReviewApprovalEvent,
        ) -> ApprovalResult<ApprovalOutcome> {
            approve_review_event(
                &self.original,
                &self.ai,
                &self.state,
                decode_base32_128(&review.report().review_id).expect("decode review ID"),
                decode_base32_128(&event.event_id).expect("decode event ID"),
                event.required_reason,
            )
        }

        fn artifact_count(&self) -> usize {
            fs::read_dir(&self.state)
                .expect("read private state")
                .count()
        }

        fn manifest_count(&self) -> usize {
            fs::read_dir(&self.state)
                .expect("read private state")
                .filter_map(std::result::Result::ok)
                .filter(|entry| {
                    entry.file_name().to_str().is_some_and(|name| {
                        name.starts_with("manifest-") && name.ends_with("-review.scdp")
                    })
                })
                .count()
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn event(report: &ReviewOutcome, event_type: ApprovalEventType) -> ReviewApprovalEvent {
        report
            .report()
            .approval_events
            .iter()
            .find(|event| event.event_type == event_type)
            .cloned()
            .expect("approval event type")
    }

    fn remove_first_token(path: &Path) {
        let mut text = fs::read_to_string(path).expect("read token-bearing file");
        let start = text.find(TOKEN_PREFIX).expect("token prefix");
        let end = text[start + TOKEN_PREFIX.len()..]
            .find(TOKEN_SUFFIX)
            .expect("token suffix")
            + start
            + TOKEN_PREFIX.len()
            + TOKEN_SUFFIX.len();
        text.replace_range(start..end, "");
        fs::write(path, text).expect("remove exact token");
    }

    fn fresh_event_id(
        fixture: &Fixture,
        predicate: impl Fn(EventKind, EventDecision) -> bool,
    ) -> [u8; 16] {
        let authority = crate::roundtrip::classify::prepare_approval_authority(
            &fixture.original,
            &fixture.ai,
            &fixture.state,
        )
        .expect("fresh event authority");
        let identities = ReviewIdentityIndex::derive(&authority).expect("identity index");
        let value = authority
            .events
            .events()
            .iter()
            .enumerate()
            .find(|(_, event)| predicate(event.kind, event.decision))
            .map(|(index, _)| identities.event(index).expect("event identity").event_id)
            .expect("matching fresh event");
        authority.lock.release().expect("release authority lock");
        value
    }

    fn assert_definite_error(result: ApprovalResult<ApprovalOutcome>, expected: Error) {
        assert_eq!(
            result.expect_err("approval must reject"),
            ApprovalFailure::DefiniteFailure(expected)
        );
    }

    #[test]
    fn all_three_classes_require_their_exact_typed_reason() {
        let _serial = APPROVAL_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let token = Fixture::create(
            "token-class",
            b"before\ncontact=rt5.token@example.invalid\nafter\n",
            ReviewProfile::StandardV2,
        );
        remove_first_token(&token.ai.join("main.txt"));
        let token_review = token.review();
        let token_event = event(&token_review, ApprovalEventType::Deleted);
        let before = token.artifact_count();
        assert_definite_error(
            approve_review_event(
                &token.original,
                &token.ai,
                &token.state,
                decode_base32_128(&token_review.report().review_id).expect("review ID"),
                decode_base32_128(&token_event.event_id).expect("event ID"),
                ApprovalReason::IntentionalFileDelete,
            ),
            Error::ApprovalReasonMismatch,
        );
        assert_eq!(token.artifact_count(), before);
        let approved = token
            .approve(&token_review, &token_event)
            .expect("approve token delete");
        assert_eq!(approved.session_state, SessionState::ReadyToApply);
        assert_eq!(approved.capsule_generation, 3);
        assert!(!approved.semantic_safety_assessed);
        let raw_free = format!("{approved:?}");
        assert!(!raw_free.contains("main.txt"));
        assert!(!raw_free.contains("rt5.token@example.invalid"));

        let file = Fixture::create(
            "file-class",
            b"ordinary file deletion\n",
            ReviewProfile::StandardV2,
        );
        fs::remove_file(file.ai.join("main.txt")).expect("delete token-free file");
        let file_review = file.review();
        let file_event = event(&file_review, ApprovalEventType::FileDeleted);
        assert_definite_error(
            approve_review_event(
                &file.original,
                &file.ai,
                &file.state,
                decode_base32_128(&file_review.report().review_id).expect("review ID"),
                decode_base32_128(&file_event.event_id).expect("event ID"),
                ApprovalReason::IntentionalTokenRemoval,
            ),
            Error::ApprovalReasonMismatch,
        );
        assert_eq!(
            file.approve(&file_review, &file_event)
                .expect("approve file delete")
                .session_state,
            SessionState::ReadyToApply
        );

        let strict = Fixture::create(
            "strict-class",
            b"before\ncontact=rt5.strict@example.invalid\nafter\n",
            ReviewProfile::StrictTokenFilesV2,
        );
        let baseline = fs::read(strict.ai.join("main.txt")).expect("read strict file");
        fs::write(
            strict.ai.join("main.txt"),
            [b"safe insertion\n".as_slice(), baseline.as_slice()].concat(),
        )
        .expect("edit strict token file");
        let strict_review = strict.review();
        let strict_event = event(&strict_review, ApprovalEventType::StrictTokenFileModified);
        assert_definite_error(
            approve_review_event(
                &strict.original,
                &strict.ai,
                &strict.state,
                decode_base32_128(&strict_review.report().review_id).expect("review ID"),
                decode_base32_128(&strict_event.event_id).expect("event ID"),
                ApprovalReason::IntentionalFileDelete,
            ),
            Error::ApprovalReasonMismatch,
        );
        assert_eq!(
            strict
                .approve(&strict_review, &strict_event)
                .expect("approve strict edit")
                .session_state,
            SessionState::ReadyToApply
        );
    }

    #[test]
    fn token_bearing_file_delete_is_independent_partial_then_ready_and_idempotent() {
        let _serial = APPROVAL_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let fixture = Fixture::create(
            "constituents",
            b"first=first.rt5@example.invalid\nsecond=second.rt5@example.invalid\n",
            ReviewProfile::StandardV2,
        );
        fs::remove_file(fixture.ai.join("main.txt")).expect("delete token-bearing file");
        let original_snapshot = snapshot_tree(&fixture.original);
        let ai_snapshot = snapshot_tree(&fixture.ai);
        let reviewed = fixture.review();
        assert_eq!(reviewed.report().approval_eligible_events, 3);
        assert_eq!(reviewed.report().approved_events, 0);
        assert_eq!(reviewed.report().remaining_approval_events, 3);
        assert_eq!(
            reviewed
                .report()
                .approval_events
                .iter()
                .filter(|event| event.event_type == ApprovalEventType::Deleted)
                .count(),
            2
        );
        assert_eq!(
            reviewed
                .report()
                .approval_events
                .iter()
                .filter(|event| event.event_type == ApprovalEventType::FileDeleted)
                .count(),
            1
        );
        let manifest_count = fixture.manifest_count();
        let artifact_after_review = fixture.artifact_count();

        let first = reviewed.report().approval_events[0].clone();
        let first_outcome = fixture
            .approve(&reviewed, &first)
            .expect("first constituent");
        assert_eq!(first_outcome.session_state, SessionState::ApprovedPartial);
        assert_eq!(first_outcome.approved_count, 1);
        assert_eq!(first_outcome.remaining_required_count, 2);
        assert_eq!(first_outcome.capsule_generation, 3);
        assert_eq!(fixture.manifest_count(), manifest_count);
        assert_eq!(fixture.artifact_count(), artifact_after_review + 1);

        let after_first = fixture.artifact_count();
        let replay_partial = fixture.review();
        assert!(replay_partial.report().replayed);
        assert_eq!(replay_partial.report().capsule_generation, 3);
        assert_eq!(
            replay_partial.report().session_state,
            SessionState::ApprovedPartial
        );
        assert_eq!(replay_partial.report().approved_events, 1);
        assert_eq!(replay_partial.report().remaining_approval_events, 2);
        assert_eq!(
            replay_partial
                .report()
                .approval_events
                .iter()
                .filter(|event| event.approved)
                .count(),
            1
        );
        assert_eq!(fixture.artifact_count(), after_first);

        for (offset, approval_event) in reviewed.report().approval_events[1..].iter().enumerate() {
            let outcome = fixture
                .approve(&reviewed, approval_event)
                .expect("remaining constituent");
            assert_eq!(
                outcome.capsule_generation,
                4 + u64::try_from(offset).expect("offset")
            );
        }
        let ready_artifacts = fixture.artifact_count();
        let ready = fixture.review();
        assert_eq!(ready.report().session_state, SessionState::ReadyToApply);
        assert_eq!(ready.report().approved_events, 3);
        assert_eq!(ready.report().remaining_approval_events, 0);
        assert!(ready
            .report()
            .approval_events
            .iter()
            .all(|event| event.approved));
        assert_eq!(ready.report().capsule_generation, 5);
        assert_eq!(fixture.artifact_count(), ready_artifacts);
        assert_eq!(fixture.manifest_count(), manifest_count);

        let private_state_before_duplicate = snapshot_tree(&fixture.state);
        let private_times_before_duplicate = modification_snapshot(&fixture.state);
        let duplicate = fixture
            .approve(&reviewed, &first)
            .expect("ready duplicate no-op");
        assert!(duplicate.duplicate);
        assert_eq!(duplicate.capsule_generation, 5);
        assert_eq!(duplicate.session_state, SessionState::ReadyToApply);
        assert_eq!(fixture.artifact_count(), ready_artifacts);
        assert_eq!(
            snapshot_tree(&fixture.state),
            private_state_before_duplicate
        );
        assert_eq!(
            modification_snapshot(&fixture.state),
            private_times_before_duplicate
        );
        let conflicting_reason = match first.required_reason {
            ApprovalReason::IntentionalTokenRemoval => ApprovalReason::IntentionalFileDelete,
            ApprovalReason::IntentionalFileDelete | ApprovalReason::StrictTokenFileEditReviewed => {
                ApprovalReason::IntentionalTokenRemoval
            }
        };
        assert_definite_error(
            approve_review_event(
                &fixture.original,
                &fixture.ai,
                &fixture.state,
                decode_base32_128(&reviewed.report().review_id).expect("review ID"),
                decode_base32_128(&first.event_id).expect("event ID"),
                conflicting_reason,
            ),
            Error::ApprovalReasonMismatch,
        );
        assert_eq!(fixture.artifact_count(), ready_artifacts);
        assert_eq!(
            snapshot_tree(&fixture.state),
            private_state_before_duplicate
        );
        assert_eq!(
            modification_snapshot(&fixture.state),
            private_times_before_duplicate
        );
        assert_eq!(snapshot_tree(&fixture.original), original_snapshot);
        assert_eq!(snapshot_tree(&fixture.ai), ai_snapshot);
    }

    #[test]
    fn strict_token_deletion_and_strict_file_event_remain_independent() {
        let _serial = APPROVAL_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let fixture = Fixture::create(
            "strict-independent",
            b"top-a\ntop-b\ncontext-left\ncontact=strict.delete@example.invalid\ncontext-right\nbottom-a\nbottom-b\n",
            ReviewProfile::StrictTokenFilesV2,
        );
        remove_first_token(&fixture.ai.join("main.txt"));
        let reviewed = fixture.review();
        assert_eq!(reviewed.report().approval_events.len(), 2);
        assert!(reviewed
            .report()
            .approval_events
            .iter()
            .any(|event| event.event_type == ApprovalEventType::Deleted));
        assert!(reviewed
            .report()
            .approval_events
            .iter()
            .any(|event| { event.event_type == ApprovalEventType::StrictTokenFileModified }));
        let deleted = event(&reviewed, ApprovalEventType::Deleted);
        let partial = fixture
            .approve(&reviewed, &deleted)
            .expect("approve deletion");
        assert_eq!(partial.session_state, SessionState::ApprovedPartial);
        assert_eq!(partial.remaining_required_count, 1);
        let strict = event(&reviewed, ApprovalEventType::StrictTokenFileModified);
        let ready = fixture
            .approve(&reviewed, &strict)
            .expect("approve strict event");
        assert_eq!(ready.session_state, SessionState::ReadyToApply);
    }

    #[test]
    fn automatic_reject_derived_unknown_and_active_inputs_are_never_approvable() {
        let _serial = APPROVAL_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let active = Fixture::create(
            "active",
            b"ordinary active session\n",
            ReviewProfile::StandardV2,
        );
        assert_definite_error(
            approve_review_event(
                &active.original,
                &active.ai,
                &active.state,
                [1; 16],
                [2; 16],
                ApprovalReason::IntentionalTokenRemoval,
            ),
            Error::InvalidState,
        );

        let automatic = Fixture::create(
            "automatic",
            b"ordinary automatic baseline\n",
            ReviewProfile::StandardV2,
        );
        fs::write(automatic.ai.join("new.txt"), b"safe addition\n").expect("add automatic file");
        let automatic_review = automatic.review();
        let automatic_id = fresh_event_id(&automatic, |_, decision| {
            decision == EventDecision::Automatic
        });
        assert_definite_error(
            approve_review_event(
                &automatic.original,
                &automatic.ai,
                &automatic.state,
                decode_base32_128(&automatic_review.report().review_id).expect("review ID"),
                automatic_id,
                ApprovalReason::IntentionalFileDelete,
            ),
            Error::ApprovalEventIneligible,
        );
        assert_definite_error(
            approve_review_event(
                &automatic.original,
                &automatic.ai,
                &automatic.state,
                decode_base32_128(&automatic_review.report().review_id).expect("review ID"),
                [0xEE; 16],
                ApprovalReason::IntentionalFileDelete,
            ),
            Error::ApprovalEventInvalid,
        );

        let rejected = Fixture::create(
            "rejected",
            b"ordinary rejected baseline\n",
            ReviewProfile::StandardV2,
        );
        fs::write(
            rejected.ai.join("main.txt"),
            b"ordinary rejected baseline\n__SAFECLONE_RT1_MALFORMED__\n",
        )
        .expect("write rejected form");
        let rejected_review = rejected.review();
        assert_eq!(
            rejected_review.report().session_state,
            SessionState::ReviewedRejected
        );
        let reject_id = fresh_event_id(&rejected, |_, decision| decision == EventDecision::Reject);
        let reject_artifacts = rejected.artifact_count();
        assert_definite_error(
            approve_review_event(
                &rejected.original,
                &rejected.ai,
                &rejected.state,
                decode_base32_128(&rejected_review.report().review_id).expect("review ID"),
                reject_id,
                ApprovalReason::IntentionalTokenRemoval,
            ),
            Error::ApprovalEventIneligible,
        );
        assert_eq!(rejected.artifact_count(), reject_artifacts);

        let derived = Fixture::create_tree(
            "derived",
            &[(
                "folder/main.txt",
                b"contact=derived.rt5@example.invalid\n".as_slice(),
            )],
            &[],
            ReviewProfile::StandardV2,
        );
        fs::remove_dir_all(derived.ai.join("folder")).expect("delete nonempty tree");
        let derived_review = derived.review();
        let derived_id = fresh_event_id(&derived, |_, decision| decision == EventDecision::Derived);
        assert_definite_error(
            approve_review_event(
                &derived.original,
                &derived.ai,
                &derived.state,
                decode_base32_128(&derived_review.report().review_id).expect("review ID"),
                derived_id,
                ApprovalReason::IntentionalFileDelete,
            ),
            Error::ApprovalEventIneligible,
        );
    }

    #[test]
    fn stale_and_cross_session_authority_reject_without_mutation() {
        let _serial = APPROVAL_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let make_reviewed = |name: &str| {
            let fixture = Fixture::create(
                name,
                b"before\ncontact=stale.rt5@example.invalid\nafter\n",
                ReviewProfile::StandardV2,
            );
            remove_first_token(&fixture.ai.join("main.txt"));
            let review = fixture.review();
            (fixture, review)
        };

        let (wrong_review, reviewed) = make_reviewed("wrong-review");
        let approval_event = event(&reviewed, ApprovalEventType::Deleted);
        let mut bad_review = decode_base32_128(&reviewed.report().review_id).expect("review ID");
        bad_review[0] ^= 1;
        let count = wrong_review.artifact_count();
        assert_definite_error(
            approve_review_event(
                &wrong_review.original,
                &wrong_review.ai,
                &wrong_review.state,
                bad_review,
                decode_base32_128(&approval_event.event_id).expect("event ID"),
                approval_event.required_reason,
            ),
            Error::ApprovalStale,
        );
        assert_eq!(wrong_review.artifact_count(), count);

        let (edited_bytes, reviewed) = make_reviewed("edited-byte");
        let approval_event = event(&reviewed, ApprovalEventType::Deleted);
        fs::write(
            edited_bytes.ai.join("main.txt"),
            b"changed after reviewed token deletion\n",
        )
        .expect("change edited bytes");
        assert_definite_error(
            edited_bytes.approve(&reviewed, &approval_event),
            Error::ApprovalStale,
        );

        let (edited_path, reviewed) = make_reviewed("edited-path");
        let approval_event = event(&reviewed, ApprovalEventType::Deleted);
        fs::rename(
            edited_path.ai.join("main.txt"),
            edited_path.ai.join("renamed.txt"),
        )
        .expect("change edited path");
        assert_definite_error(
            edited_path.approve(&reviewed, &approval_event),
            Error::ApprovalStale,
        );

        let (original, reviewed) = make_reviewed("original-change");
        let approval_event = event(&reviewed, ApprovalEventType::Deleted);
        fs::write(
            original.original.join("main.txt"),
            b"changed Original authority\n",
        )
        .expect("change Original");
        assert_definite_error(
            original.approve(&reviewed, &approval_event),
            Error::ApprovalStale,
        );

        let (new_review, old) = make_reviewed("new-review");
        let old_event = event(&old, ApprovalEventType::Deleted);
        let mut changed = fs::read(new_review.ai.join("main.txt")).expect("read edited");
        changed.extend_from_slice(b"new review input\n");
        fs::write(new_review.ai.join("main.txt"), changed).expect("change for new review");
        let replacement = new_review.review();
        assert_ne!(old.report().review_id, replacement.report().review_id);
        assert_definite_error(new_review.approve(&old, &old_event), Error::ApprovalStale);

        let (first, first_review) = make_reviewed("cross-first");
        let (second, second_review) = make_reviewed("cross-second");
        let first_event = event(&first_review, ApprovalEventType::Deleted);
        let second_event = event(&second_review, ApprovalEventType::Deleted);
        assert_definite_error(
            approve_review_event(
                &first.original,
                &first.ai,
                &first.state,
                decode_base32_128(&second_review.report().review_id).expect("other review ID"),
                decode_base32_128(&second_event.event_id).expect("other event ID"),
                second_event.required_reason,
            ),
            Error::ApprovalStale,
        );
        assert_definite_error(
            approve_review_event(
                &first.original,
                &first.ai,
                &first.state,
                decode_base32_128(&first_review.report().review_id).expect("review ID"),
                decode_base32_128(&second_event.event_id).expect("other event ID"),
                first_event.required_reason,
            ),
            Error::ApprovalEventInvalid,
        );
        drop(second);
    }

    #[test]
    fn approval_does_not_consume_reporting_diff_or_write_a_manifest() {
        let _serial = APPROVAL_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let fixture = Fixture::create(
            "no-reporting-authority",
            b"before\ncontact=deadline.rt5@example.invalid\nafter\n",
            ReviewProfile::StandardV2,
        );
        remove_first_token(&fixture.ai.join("main.txt"));
        let reviewed = fixture.review();
        let approval_event = event(&reviewed, ApprovalEventType::Deleted);
        let manifests = fixture.manifest_count();
        let _guard = crate::roundtrip::report_diff::install_review_start_failure();
        let approved = fixture
            .approve(&reviewed, &approval_event)
            .expect("approval must not invoke reporting diff");
        assert_eq!(approved.session_state, SessionState::ReadyToApply);
        assert_eq!(fixture.manifest_count(), manifests);
    }

    #[test]
    fn stored_set_tag_and_fresh_record_authority_are_both_enforced() {
        let _serial = APPROVAL_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let bad_tag = Fixture::create(
            "bad-set-tag",
            b"before\ncontact=bad.tag@example.invalid\nafter\n",
            ReviewProfile::StandardV2,
        );
        remove_first_token(&bad_tag.ai.join("main.txt"));
        let reviewed = bad_tag.review();
        let approval_event = event(&reviewed, ApprovalEventType::Deleted);
        let mut authority = crate::roundtrip::classify::prepare_approval_authority(
            &bad_tag.original,
            &bad_tag.ai,
            &bad_tag.state,
        )
        .expect("prepare bad-tag authority");
        let mut corrupted = authority.owner.capsule().clone();
        corrupted.generation += 1;
        corrupted.approval_set.approval_set_tag[0] ^= 1;
        corrupted
            .validate_capsule_state()
            .expect("structural bad-tag capsule");
        let protected = protect_next_live_capsule(&authority.owner, &corrupted)
            .expect("protect bad-tag capsule");
        authority
            .store
            .append_capsule_generation(&mut authority.lock, &protected)
            .expect("commit bad-tag capsule");
        authority.lock.release().expect("release bad-tag lock");
        fs::write(
            bad_tag.original.join("main.txt"),
            b"Original changed after authenticated-set corruption\n",
        )
        .expect("change Original behind corrupt set");
        assert_definite_error(
            bad_tag.approve(&reviewed, &approval_event),
            Error::AuthenticationFailed,
        );

        let wrong_record = Fixture::create(
            "wrong-record",
            b"first=first.record@example.invalid\nsecond=second.record@example.invalid\n",
            ReviewProfile::StandardV2,
        );
        fs::remove_file(wrong_record.ai.join("main.txt")).expect("delete record file");
        let reviewed = wrong_record.review();
        let first = reviewed.report().approval_events[0].clone();
        wrong_record
            .approve(&reviewed, &first)
            .expect("commit first valid record");
        let mut authority = crate::roundtrip::classify::prepare_approval_authority(
            &wrong_record.original,
            &wrong_record.ai,
            &wrong_record.state,
        )
        .expect("prepare wrong-record authority");
        let mut corrupted = authority.owner.capsule().clone();
        corrupted.generation += 1;
        let record = corrupted
            .approval_set
            .records
            .first_mut()
            .expect("existing approval record");
        let (event_type, reason) = match record.event_type {
            ApprovalEventType::Deleted => (
                ApprovalEventType::FileDeleted,
                ApprovalReason::IntentionalFileDelete,
            ),
            ApprovalEventType::FileDeleted | ApprovalEventType::StrictTokenFileModified => (
                ApprovalEventType::Deleted,
                ApprovalReason::IntentionalTokenRemoval,
            ),
        };
        record.event_type = event_type;
        record.reason_code = reason;
        let review_id = corrupted
            .current_review
            .as_ref()
            .expect("current review")
            .review_id;
        corrupted.approval_set.approval_set_tag = approval_set_tag(
            &authority.owner.key_schedule(),
            corrupted.review_profile,
            &corrupted.ruleset_id,
            review_id,
            &corrupted.approval_set.records,
        )
        .expect("authenticate structurally valid wrong record");
        corrupted
            .validate_capsule_state()
            .expect("structural wrong-record capsule");
        let protected = protect_next_live_capsule(&authority.owner, &corrupted)
            .expect("protect wrong-record capsule");
        authority
            .store
            .append_capsule_generation(&mut authority.lock, &protected)
            .expect("commit wrong-record capsule");
        authority.lock.release().expect("release wrong-record lock");
        let next = reviewed.report().approval_events[1].clone();
        assert_definite_error(wrong_record.approve(&reviewed, &next), Error::CorruptState);
    }

    #[test]
    fn capsule_interruption_matrix_and_committed_reinvoke_are_fail_closed() {
        let _serial = APPROVAL_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for checkpoint in ["P0", "P1", "P2", "P3", "P4", "P5", "P6", "P7"] {
            let fixture = Fixture::create(
                &format!("checkpoint-{checkpoint}"),
                b"before\ncontact=checkpoint.rt5@example.invalid\nafter\n",
                ReviewProfile::StandardV2,
            );
            remove_first_token(&fixture.ai.join("main.txt"));
            let reviewed = fixture.review();
            let approval_event = event(&reviewed, ApprovalEventType::Deleted);
            let baseline_artifacts = fixture.artifact_count();
            let status = Command::new(std::env::current_exe().expect("current test executable"))
                .arg(CHILD_TEST_NAME)
                .arg("--exact")
                .arg("--nocapture")
                .env(CHILD_MODE_ENV, "checkpoint")
                .env(CHILD_ORIGINAL_ENV, &fixture.original)
                .env(CHILD_AI_ENV, &fixture.ai)
                .env(CHILD_STATE_ENV, &fixture.state)
                .env(CHILD_REVIEW_ENV, &reviewed.report().review_id)
                .env(CHILD_EVENT_ENV, &approval_event.event_id)
                .env(CHILD_CHECKPOINT_ENV, checkpoint)
                .env("RUST_TEST_THREADS", "1")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .expect("run approval checkpoint child");
            assert!(
                !status.success(),
                "checkpoint child must abort at {checkpoint}"
            );

            match checkpoint {
                "P0" => {
                    assert_eq!(fixture.artifact_count(), baseline_artifacts);
                    let replay = fixture.review();
                    assert_eq!(replay.report().capsule_generation, 2);
                    assert_eq!(replay.report().session_state, SessionState::Reviewed);
                }
                "P1" | "P2" | "P3" | "P4" => {
                    assert_eq!(fixture.artifact_count(), baseline_artifacts + 1);
                    assert_eq!(
                        fixture
                            .approve(&reviewed, &approval_event)
                            .expect_err("pending approval must require manual inspection"),
                        ApprovalFailure::ManualInspectionRequired(Error::PrivateOrphansPresent)
                    );
                }
                "P5" | "P6" | "P7" => {
                    assert_eq!(fixture.artifact_count(), baseline_artifacts + 1);
                    let duplicate = fixture
                        .approve(&reviewed, &approval_event)
                        .expect("committed uncertain approval reinvoke");
                    assert!(duplicate.duplicate);
                    assert_eq!(duplicate.capsule_generation, 3);
                    assert_eq!(duplicate.session_state, SessionState::ReadyToApply);
                    assert_eq!(fixture.artifact_count(), baseline_artifacts + 1);
                }
                _ => unreachable!(),
            }
        }
    }

    #[test]
    fn approval_checkpoint_child() {
        if std::env::var(CHILD_MODE_ENV).as_deref() != Ok("checkpoint") {
            return;
        }
        let original =
            PathBuf::from(std::env::var_os(CHILD_ORIGINAL_ENV).expect("approval child Original"));
        let ai = PathBuf::from(std::env::var_os(CHILD_AI_ENV).expect("approval child AI"));
        let state = PathBuf::from(std::env::var_os(CHILD_STATE_ENV).expect("approval child state"));
        let review_id =
            decode_base32_128(&std::env::var(CHILD_REVIEW_ENV).expect("approval child review ID"))
                .expect("decode child review ID");
        let event_id =
            decode_base32_128(&std::env::var(CHILD_EVENT_ENV).expect("approval child event ID"))
                .expect("decode child event ID");
        let _ = approve_review_event(
            &original,
            &ai,
            &state,
            review_id,
            event_id,
            ApprovalReason::IntentionalTokenRemoval,
        );
        panic!("checkpoint hook did not abort");
    }

    fn snapshot_tree(root: &Path) -> Vec<(String, Option<Vec<u8>>)> {
        fn walk(root: &Path, current: &Path, output: &mut Vec<(String, Option<Vec<u8>>)>) {
            let mut entries = fs::read_dir(current)
                .expect("read snapshot directory")
                .map(|entry| entry.expect("snapshot entry"))
                .collect::<Vec<_>>();
            entries.sort_unstable_by_key(std::fs::DirEntry::file_name);
            for entry in entries {
                let path = entry.path();
                let relative = path
                    .strip_prefix(root)
                    .expect("snapshot relative")
                    .to_string_lossy()
                    .replace('\\', "/");
                let kind = entry.file_type().expect("snapshot file type");
                if kind.is_dir() {
                    output.push((relative, None));
                    walk(root, &path, output);
                } else {
                    output.push((relative, Some(fs::read(path).expect("snapshot file"))));
                }
            }
        }
        let mut output = Vec::new();
        walk(root, root, &mut output);
        output
    }

    fn modification_snapshot(root: &Path) -> Vec<(String, u64, std::time::SystemTime)> {
        let mut output = fs::read_dir(root)
            .expect("read modification snapshot")
            .map(|entry| {
                let entry = entry.expect("modification snapshot entry");
                let metadata = entry.metadata().expect("modification metadata");
                (
                    entry.file_name().to_string_lossy().into_owned(),
                    metadata.len(),
                    metadata.modified().expect("modification time"),
                )
            })
            .collect::<Vec<_>>();
        output.sort_unstable_by(|left, right| left.0.cmp(&right.0));
        output
    }
}
