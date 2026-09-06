//! Library orchestration for roundtrip-v3 session creation.
//!
//! CLI parsing is separate; the CLI calls this raw-free API.

use std::fmt;
use std::path::Path;

use super::schema::{SessionState, TreeCountsV1};
use super::token::{ReviewProfile, ENGINE_VERSION, POLICY_ID, TOKEN_SUITE_ID};
use super::Error;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AiPublicationState {
    Published,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreateReport {
    pub session_id: String,
    pub profile: ReviewProfile,
    pub engine_version: &'static str,
    pub policy_id: &'static str,
    pub ruleset_id: &'static str,
    pub token_suite_id: u16,
    pub capsule_generation: u64,
    pub session_state: SessionState,
    pub ai_publication: AiPublicationState,
    pub baseline_counts: TreeCountsV1,
    pub semantic_safety_assessed: bool,
    pub replayed: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CreateFailure {
    DefiniteFailure(Error),
    ManualInspectionRequired(Error),
}

impl fmt::Display for CreateFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DefiniteFailure(error) => {
                write!(
                    formatter,
                    "round-trip create failed before publication: {error}"
                )
            }
            Self::ManualInspectionRequired(error) => {
                write!(
                    formatter,
                    "round-trip create requires manual inspection: {error}"
                )
            }
        }
    }
}

impl std::error::Error for CreateFailure {}

pub type CreateResult<T> = std::result::Result<T, CreateFailure>;

#[cfg(all(test, windows))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TestCheckpoint {
    AfterOriginalPassOne,
    AfterOriginalPassTwo,
    WorkspaceDirectoryCreated,
    WorkspaceFileCreatedEmpty,
    WorkspaceFileWritten,
    AfterAiPassOne,
    AfterAiStablePasses,
}

#[cfg(all(test, windows))]
std::thread_local! {
    static TEST_HOOK: std::cell::RefCell<Option<TestHook>> =
        std::cell::RefCell::new(None);
}

#[cfg(all(test, windows))]
type TestHook = Box<dyn FnMut(TestCheckpoint) -> super::Result<()>>;

#[cfg(all(test, windows))]
pub(crate) fn test_checkpoint(checkpoint: TestCheckpoint) -> super::Result<()> {
    TEST_HOOK.with(|slot| {
        let mut slot = slot.try_borrow_mut().map_err(|_| Error::InvalidState)?;
        match slot.as_mut() {
            Some(hook) => hook(checkpoint),
            None => Ok(()),
        }
    })
}

#[cfg(all(test, windows))]
struct TestHookGuard;

#[cfg(all(test, windows))]
impl Drop for TestHookGuard {
    fn drop(&mut self) {
        TEST_HOOK.with(|slot| *slot.borrow_mut() = None);
    }
}

#[cfg(all(test, windows))]
fn install_test_hook(
    hook: impl FnMut(TestCheckpoint) -> super::Result<()> + 'static,
) -> TestHookGuard {
    TEST_HOOK.with(|slot| {
        let replaced = slot.borrow_mut().replace(Box::new(hook));
        assert!(replaced.is_none(), "nested create test hook");
    });
    TestHookGuard
}

#[cfg(not(windows))]
pub fn create_session(
    _original: &Path,
    _ai_workspace: &Path,
    _private_state: &Path,
    profile: ReviewProfile,
) -> CreateResult<CreateReport> {
    if profile.is_current() {
        Err(CreateFailure::DefiniteFailure(Error::UnsupportedPlatform))
    } else {
        Err(CreateFailure::DefiniteFailure(Error::InvalidState))
    }
}

#[cfg(windows)]
pub fn create_session(
    original: &Path,
    ai_workspace: &Path,
    private_state: &Path,
    profile: ReviewProfile,
) -> CreateResult<CreateReport> {
    windows::create_session(original, ai_workspace, private_state, profile)
}

#[cfg(windows)]
mod windows {
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;
    use crate::locality;
    use crate::roundtrip::baseline::{
        derive, derive_two_prepublication_passes, require_same_summary, BaselineSummary,
        StreamEncoder,
    };
    use crate::roundtrip::capsule::{GenerationStore, StoreClassification};
    use crate::roundtrip::crypto::{
        constant_time_equal, KeyPurpose, KeySchedule, SessionId, SessionMasterSecret,
    };
    use crate::roundtrip::dpapi::protect_initial_live_capsule;
    use crate::roundtrip::observe::{
        qualify_roundtrip_create_volumes, validate_virtual_sibling_names,
        QualifiedCreateVolumePaths, QualifiedDirectory, ValidatedLeaf,
    };
    use crate::roundtrip::ruleset::ruleset_id;
    use crate::roundtrip::schema::{ApprovalSetV1, CapsuleV1};
    use crate::roundtrip::token::encode_base32_128;
    use crate::roundtrip::workspace::{
        self, verify_against, verify_two_stable_passes, WorkspaceSummary,
    };
    use crate::roundtrip::Result;

    enum RootState {
        Existing(QualifiedDirectory),
        Absent(ValidatedLeaf),
    }

    pub(super) fn create_session(
        original_path: &Path,
        ai_path: &Path,
        state_path: &Path,
        profile: ReviewProfile,
    ) -> CreateResult<CreateReport> {
        if !profile.is_current() {
            return Err(definite(Error::InvalidState));
        }
        let preflight =
            locality::preflight_roundtrip_create_paths(original_path, ai_path, state_path)
                .map_err(|_| definite(Error::OriginalWorkspaceRejected))?;
        let confirmed = locality::open_and_confirm_roundtrip_volumes(preflight)
            .map_err(|_| definite(Error::OriginalWorkspaceRejected))?;
        // Construction performs both stable read-only policy queries for all
        // three volumes before any component-opening method is available.
        let QualifiedCreateVolumePaths {
            original,
            ai_parent,
            ai_leaf,
            state_parent,
            state_leaf,
        } = qualify_roundtrip_create_volumes(confirmed)
            .map_err(|_| definite(Error::PersistentVolumeQueryFailed))?;
        use crate::roundtrip::observe::NamespaceScope;
        let original = original
            .open_directory(NamespaceScope::Workspace)
            .map_err(|error| namespace_definite(error, Error::OriginalWorkspaceRejected))?;
        let ai_parent = ai_parent
            .open_directory(NamespaceScope::PathSelection)
            .map_err(|error| namespace_definite(error, Error::CreateConflict))?;
        let state_parent = state_parent
            .open_directory(NamespaceScope::PathSelection)
            .map_err(|error| namespace_definite(error, Error::CreateConflict))?;
        let ai = match ai_parent
            .classify_directory_leaf(&ai_leaf, NamespaceScope::Workspace)
            .map_err(|error| namespace_definite(error, Error::CreateConflict))?
        {
            Ok(root) => RootState::Existing(root.into_workspace_root().map_err(definite)?),
            Err(leaf) => RootState::Absent(leaf),
        };
        let state = match state_parent
            .classify_directory_leaf(&state_leaf, NamespaceScope::Workspace)
            .map_err(|error| namespace_definite(error, Error::CreateConflict))?
        {
            Ok(root) => RootState::Existing(root),
            Err(leaf) => RootState::Absent(leaf),
        };
        validate_overlap(&original, &ai_parent, &ai, &state_parent, &state).map_err(definite)?;

        match (ai, state) {
            (RootState::Absent(ai_leaf), RootState::Absent(state_leaf)) => create_new(
                original,
                ai_parent,
                ai_leaf,
                state_parent,
                state_leaf,
                profile,
            ),
            (RootState::Existing(ai), RootState::Existing(state)) => {
                replay(original, ai, state, profile)
            }
            (RootState::Existing(_), RootState::Absent(_)) => Err(definite(Error::CreateConflict)),
            (RootState::Absent(_), RootState::Existing(state)) => {
                let store = GenerationStore::from_qualified_root(
                    state.into_private_state_root().map_err(manual)?,
                );
                let observation = store.read().map_err(manual)?;
                match observation.classification {
                    StoreClassification::CreateIncomplete => Err(manual(Error::CreateIncomplete)),
                    StoreClassification::PrivateOrphansPresent => {
                        Err(manual(Error::PrivateOrphansPresent))
                    }
                    _ => Err(definite(Error::CreateConflict)),
                }
            }
        }
    }

    fn create_new(
        original: QualifiedDirectory,
        ai_parent: QualifiedDirectory,
        ai_leaf: ValidatedLeaf,
        state_parent: QualifiedDirectory,
        state_leaf: ValidatedLeaf,
        profile: ReviewProfile,
    ) -> CreateResult<CreateReport> {
        // Session authority exists only in memory until both complete original
        // passes have succeeded.
        let session_id = SessionId::generate().map_err(definite)?;
        let master = SessionMasterSecret::generate().map_err(definite)?;
        let schedule = KeySchedule::new(&master, session_id);
        let first = derive(&original, &schedule, profile, false).map_err(original_definite)?;
        #[cfg(test)]
        super::test_checkpoint(super::TestCheckpoint::AfterOriginalPassOne)
            .map_err(|_| definite(Error::OriginalWorkspaceRejected))?;
        let baseline = derive(&original, &schedule, profile, false).map_err(original_definite)?;
        require_same_summary(&first.summary, &baseline.summary)
            .map_err(|_| definite(Error::OriginalWorkspaceRejected))?;
        drop(first);
        #[cfg(test)]
        super::test_checkpoint(super::TestCheckpoint::AfterOriginalPassTwo)
            .map_err(|_| definite(Error::OriginalWorkspaceRejected))?;

        // From this call onward the state root may have been created. Every
        // inability to prove an exact result is therefore manual.
        let state_root = state_parent.create_directory(state_leaf).map_err(manual)?;
        let store = GenerationStore::from_qualified_root(
            state_root.into_private_state_root().map_err(manual)?,
        );
        store.initialize_lock().map_err(manual)?;
        let mut lock = store.acquire_mutation_lock().map_err(manual)?;

        let ai_root = ai_parent.create_workspace_root(ai_leaf).map_err(manual)?;
        let current = derive(&original, &schedule, profile, true).map_err(original_manual)?;
        require_same_summary(&baseline.summary, &current.summary)
            .map_err(|_| manual(Error::OriginalWorkspaceRejected))?;
        let ai_root = workspace::build(ai_root, &original, &current.plan, &schedule, profile)
            .map_err(|_| manual(Error::WorkspaceVerificationFailed))?;
        let ai_summary = verify_two_stable_passes(
            &ai_root,
            &current.plan,
            &baseline.summary,
            &schedule,
            profile,
        )
        .map_err(|_| manual(Error::WorkspaceVerificationFailed))?;
        #[cfg(test)]
        super::test_checkpoint(super::TestCheckpoint::AfterAiStablePasses)
            .map_err(|_| manual(Error::WorkspaceVerificationFailed))?;

        let final_original =
            derive(&original, &schedule, profile, false).map_err(original_manual)?;
        require_same_summary(&baseline.summary, &final_original.summary)
            .map_err(|_| manual(Error::OriginalWorkspaceRejected))?;
        // This final AI observation closes the mutation window between the
        // required two stable AI passes and generation-1 commit.
        verify_against(&ai_root, &current.plan, &ai_summary, &schedule, profile)
            .map_err(|_| manual(Error::WorkspaceVerificationFailed))?;
        drop(current);
        drop(final_original);

        let capsule = initial_capsule(&store, &schedule, profile, &baseline.summary, &ai_summary)
            .map_err(manual)?;
        let protected = protect_initial_live_capsule(&master, &capsule).map_err(manual)?;
        let evidence = store
            .append_capsule_generation(&mut lock, &protected)
            .map_err(manual)?;
        if evidence.generation != 1 || evidence.root_identity != store.root_identity() {
            return Err(manual(Error::StateCommitUncertain));
        }
        let committed = store
            .read_while_locked(&mut lock)
            .map_err(committed_read_failure)?;
        let head = committed
            .live_head()
            .ok_or_else(|| manual(Error::StateCommitUncertain))?;
        if committed.classification != StoreClassification::AuthoritativeLive
            || committed.orphan_count != 0
            || committed.manifest_count != 0
            || head.capsule() != &capsule
        {
            return Err(manual(Error::CorruptState));
        }
        lock.release().map_err(manual)?;
        Ok(report(&capsule, false))
    }

    fn replay(
        original: QualifiedDirectory,
        ai: QualifiedDirectory,
        state: QualifiedDirectory,
        profile: ReviewProfile,
    ) -> CreateResult<CreateReport> {
        let store = GenerationStore::from_qualified_root(
            state.into_private_state_root().map_err(definite)?,
        );
        // Replay performs no write, but it holds the existing generation-store
        // byte-range lock so a cooperating writer cannot change the
        // authenticated head while Original and AI are being re-observed.
        let mut lock = store.acquire_mutation_lock().map_err(|error| match error {
            Error::CreateIncomplete | Error::PrivateOrphansPresent => manual(error),
            _ => definite(error),
        })?;
        let observation = store
            .read_while_locked(&mut lock)
            .map_err(|error| match error {
                Error::CreateIncomplete
                | Error::PrivateOrphansPresent
                | Error::StateCommitUncertain => manual(error),
                _ => definite(error),
            })?;
        match observation.classification {
            StoreClassification::CreateIncomplete => {
                return Err(manual(Error::CreateIncomplete));
            }
            StoreClassification::PrivateOrphansPresent => {
                return Err(manual(Error::PrivateOrphansPresent));
            }
            _ => {}
        }
        if observation.classification != StoreClassification::AuthoritativeLive
            || observation.orphan_count != 0
            || observation.manifest_count != 0
        {
            return Err(definite(Error::CreateConflict));
        }
        let live = observation
            .live_head()
            .ok_or_else(|| definite(Error::CreateConflict))?;
        let capsule = live.capsule();
        validate_replay_capsule(capsule, profile).map_err(definite)?;
        let schedule = live.key_schedule();
        let baseline = derive_two_prepublication_passes(&original, &schedule, profile)
            .map_err(original_definite)?;
        if !constant_time_equal(
            &baseline.summary.original_tree_commitment,
            &capsule.original_tree_commitment,
        ) || baseline.summary.counts != capsule.baseline_counts
        {
            return Err(definite(Error::OriginalWorkspaceRejected));
        }
        let ai_summary =
            verify_two_stable_passes(&ai, &baseline.plan, &baseline.summary, &schedule, profile)
                .map_err(|_| definite(Error::WorkspaceVerificationFailed))?;
        if !constant_time_equal(
            &ai_summary.actual_tree_commitment,
            &capsule.baseline_ai_tree_commitment,
        ) {
            return Err(definite(Error::WorkspaceVerificationFailed));
        }
        let final_original =
            derive(&original, &schedule, profile, false).map_err(original_definite)?;
        require_same_summary(&baseline.summary, &final_original.summary)
            .map_err(|_| definite(Error::OriginalWorkspaceRejected))?;
        verify_against(&ai, &baseline.plan, &ai_summary, &schedule, profile)
            .map_err(|_| definite(Error::WorkspaceVerificationFailed))?;
        let report = report(capsule, true);
        lock.release().map_err(definite)?;
        Ok(report)
    }

    fn initial_capsule(
        store: &GenerationStore,
        schedule: &KeySchedule<'_>,
        profile: ReviewProfile,
        baseline: &BaselineSummary,
        ai: &WorkspaceSummary,
    ) -> Result<CapsuleV1> {
        let capsule = CapsuleV1 {
            session_id: schedule.session_id(),
            generation: 1,
            session_state: SessionState::ActiveUnreviewed,
            review_profile: profile,
            ruleset_id: ruleset_id().to_owned(),
            original_tree_commitment: baseline.original_tree_commitment,
            baseline_ai_tree_commitment: ai.actual_tree_commitment,
            baseline_counts: baseline.counts.clone(),
            current_review: None,
            approval_set: ApprovalSetV1 {
                review_id: None,
                records: Vec::new(),
                approval_set_tag: empty_approval_tag(schedule, profile)?,
            },
            apply_authority: None,
            created_epoch_seconds: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| Error::InvalidState)?
                .as_secs(),
            orphan_count_at_commit: 0,
            semantic_safety_assessed: false,
            state_root_identity_commitment: store.state_root_identity_commitment(schedule)?,
        };
        capsule.validate_capsule_state()?;
        Ok(capsule)
    }

    fn empty_approval_tag(schedule: &KeySchedule<'_>, profile: ReviewProfile) -> Result<[u8; 32]> {
        let mut value = StreamEncoder::new(
            schedule,
            KeyPurpose::ApprovalMac,
            b"safeclone/rt1/approval-set-v1",
        )?;
        value.bytes(schedule.session_id().as_bytes())?;
        value.u8(profile as u8);
        value.bytes(ENGINE_VERSION.as_bytes())?;
        value.bytes(POLICY_ID.as_bytes())?;
        value.bytes(ruleset_id().as_bytes())?;
        value.u16(TOKEN_SUITE_ID);
        value.u8(0); // null review ID
        value.u32(0); // empty canonical record array
        Ok(value.finish())
    }

    fn validate_replay_capsule(capsule: &CapsuleV1, profile: ReviewProfile) -> Result<()> {
        if capsule.generation != 1
            || capsule.session_state != SessionState::ActiveUnreviewed
            || capsule.review_profile != profile
            || capsule.ruleset_id != ruleset_id()
            || capsule.current_review.is_some()
            || capsule.approval_set.review_id.is_some()
            || !capsule.approval_set.records.is_empty()
            || capsule.apply_authority.is_some()
            || capsule.orphan_count_at_commit != 0
            || capsule.semantic_safety_assessed
        {
            return Err(Error::CreateConflict);
        }
        capsule.validate_capsule_state()
    }

    fn validate_overlap(
        original: &QualifiedDirectory,
        ai_parent: &QualifiedDirectory,
        ai: &RootState,
        state_parent: &QualifiedDirectory,
        state: &RootState,
    ) -> Result<()> {
        if ai_parent
            .ancestor_identities()
            .contains(&original.identity())
            || state_parent
                .ancestor_identities()
                .contains(&original.identity())
        {
            return Err(Error::UnsafeWorkspaceOverlap);
        }
        let ai_root = match ai {
            RootState::Existing(root) => Some(root),
            RootState::Absent(_) => None,
        };
        let state_root = match state {
            RootState::Existing(root) => Some(root),
            RootState::Absent(_) => None,
        };
        for root in [ai_root, state_root].into_iter().flatten() {
            if root.identity() == original.identity()
                || root.ancestor_identities().contains(&original.identity())
                || original.ancestor_identities().contains(&root.identity())
            {
                return Err(Error::UnsafeWorkspaceOverlap);
            }
        }
        if let (Some(ai), Some(state)) = (ai_root, state_root) {
            if ai.identity() == state.identity()
                || ai.ancestor_identities().contains(&state.identity())
                || state.ancestor_identities().contains(&ai.identity())
            {
                return Err(Error::UnsafeWorkspaceOverlap);
            }
        }
        if ai_parent.identity() == state_parent.identity() {
            match (ai, state) {
                (RootState::Absent(ai), RootState::Absent(state)) => {
                    if ai.utf16() == state.utf16() {
                        return Err(Error::UnsafeWorkspaceOverlap);
                    }
                    validate_virtual_sibling_names(&[
                        (ai.utf16().to_vec(), 0),
                        (state.utf16().to_vec(), 1),
                    ])?;
                }
                (RootState::Existing(ai), RootState::Existing(state))
                    if ai.identity() == state.identity() =>
                {
                    return Err(Error::UnsafeWorkspaceOverlap);
                }
                _ => {}
            }
        }
        Ok(())
    }

    fn report(capsule: &CapsuleV1, replayed: bool) -> CreateReport {
        CreateReport {
            session_id: encode_base32_128(capsule.session_id.as_bytes()),
            profile: capsule.review_profile,
            engine_version: ENGINE_VERSION,
            policy_id: POLICY_ID,
            ruleset_id: ruleset_id(),
            token_suite_id: TOKEN_SUITE_ID,
            capsule_generation: capsule.generation,
            session_state: capsule.session_state,
            ai_publication: AiPublicationState::Published,
            baseline_counts: capsule.baseline_counts.clone(),
            semantic_safety_assessed: false,
            replayed,
        }
    }

    const fn definite(error: Error) -> CreateFailure {
        CreateFailure::DefiniteFailure(error)
    }

    const fn manual(error: Error) -> CreateFailure {
        CreateFailure::ManualInspectionRequired(error)
    }

    const fn original_error(error: Error) -> Error {
        match error {
            Error::AnchorAmbiguous
            | Error::AnchorResourceLimitExceeded
            | Error::AnchorEncodingInvalid
            | Error::CaseSensitiveDirectoryUnsupported => error,
            _ => Error::OriginalWorkspaceRejected,
        }
    }

    const fn original_definite(error: Error) -> CreateFailure {
        definite(original_error(error))
    }

    const fn original_manual(error: Error) -> CreateFailure {
        manual(original_error(error))
    }

    const fn namespace_definite(error: Error, fallback: Error) -> CreateFailure {
        // Preserve the already accepted case-mode diagnostic for every initial
        // participating root/parent. Rejection, sequencing, and all other error
        // classifications remain unchanged; this never rescues a failed open.
        match error {
            Error::CaseSensitiveDirectoryUnsupported => definite(error),
            _ => definite(fallback),
        }
    }

    const fn committed_read_failure(error: Error) -> CreateFailure {
        match error {
            Error::CorruptState
            | Error::UnsupportedAliasNamespace
            | Error::AliasNamespaceAmbiguous
            | Error::AliasIdentityMismatch => manual(Error::CorruptState),
            Error::CaseSensitiveDirectoryUnsupported
            | Error::PersistentVolumeQueryFailed
            | Error::PersistentVolumeStateAmbiguous
            | Error::FilesystemFailure
            | Error::BoundExceeded => manual(Error::StateCommitUncertain),
            _ => manual(Error::StateCommitUncertain),
        }
    }

    #[cfg(test)]
    mod namespace_error_tests {
        use super::*;

        #[test]
        fn case_mode_diagnostic_survives_root_and_descendant_rejection() {
            let case = Error::CaseSensitiveDirectoryUnsupported;
            for fallback in [Error::OriginalWorkspaceRejected, Error::CreateConflict] {
                assert_eq!(namespace_definite(case, fallback), definite(case));
            }
            assert_eq!(original_definite(case), definite(case));
            assert_eq!(original_manual(case), manual(case));
        }

        #[test]
        fn unrelated_namespace_errors_keep_existing_failure_classes() {
            for error in [
                Error::FilesystemFailure,
                Error::UnsupportedAliasNamespace,
                Error::AliasNamespaceAmbiguous,
                Error::AliasIdentityMismatch,
                Error::PersistentVolumeQueryFailed,
                Error::BoundExceeded,
            ] {
                for fallback in [Error::OriginalWorkspaceRejected, Error::CreateConflict] {
                    assert_eq!(namespace_definite(error, fallback), definite(fallback));
                }
                assert_eq!(
                    original_definite(error),
                    definite(Error::OriginalWorkspaceRejected)
                );
                assert_eq!(
                    original_manual(error),
                    manual(Error::OriginalWorkspaceRejected)
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(windows)]
    use std::fs;
    #[cfg(windows)]
    use std::path::PathBuf;
    #[cfg(windows)]
    use std::sync::atomic::{AtomicU64, Ordering};

    #[test]
    fn failures_and_report_debug_are_raw_free() {
        let failure = CreateFailure::ManualInspectionRequired(Error::CreateIncomplete);
        let rendered = failure.to_string();
        assert!(rendered.contains("manual inspection"));
        for forbidden in ["C:\\", "\\\\?\\", "~1", "token ->"] {
            assert!(!rendered.contains(forbidden));
        }
    }

    #[cfg(windows)]
    struct Fixture(PathBuf);

    #[cfg(windows)]
    impl Fixture {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let root = std::env::temp_dir().join(format!(
                "safeclone-create-mutation-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&root).expect("create create mutation fixture");
            Self(root)
        }

        fn paths(&self) -> (PathBuf, PathBuf, PathBuf) {
            (
                self.0.join("OriginalWorkspace"),
                self.0.join("AiWorkspaceLongFixtureName"),
                self.0.join("PrivateSessionDirectoryLongFixtureName"),
            )
        }
    }

    #[cfg(windows)]
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[cfg(windows)]
    fn mutation_fixture() -> (Fixture, PathBuf, PathBuf, PathBuf) {
        let fixture = Fixture::new();
        let (original, ai, state) = fixture.paths();
        fs::create_dir(&original).expect("create mutation original");
        fs::write(original.join("ordinary.txt"), b"ordinary synthetic text\n")
            .expect("write mutation original");
        (fixture, original, ai, state)
    }

    #[cfg(windows)]
    fn capsule_count(state: &Path) -> usize {
        fs::read_dir(state)
            .expect("read mutation state")
            .map(|entry| {
                entry
                    .expect("mutation state entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .filter(|name| name.starts_with("capsule-") && name.ends_with(".scdp"))
            .count()
    }

    #[cfg(windows)]
    fn capsule_file(state: &Path) -> PathBuf {
        fs::read_dir(state)
            .expect("read mutation state")
            .map(|entry| entry.expect("state entry").path())
            .find(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with("capsule-") && name.ends_with(".scdp"))
            })
            .expect("one capsule generation")
    }

    #[cfg(windows)]
    fn observed_alias(parent: &Path, exact_leaf: &str) -> (String, u64, usize) {
        use crate::roundtrip::observe::{
            qualify_roundtrip_create_volumes, NamespaceScope, QualifiedCreateVolumePaths,
        };

        let preflight = crate::locality::preflight_roundtrip_create_paths(
            parent,
            &parent.join("UnusedAiLeafForObservation"),
            &parent.join("UnusedStateLeafForObservation"),
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
            .expect("find exact canonical leaf");
        let alias = String::from_utf16(
            entry
                .short_alias_utf16()
                .expect("enabled NTFS fixture generated a short alias"),
        )
        .expect("short alias UTF-16");
        let file_id = entry.directory_file_id64();
        let identity_records = observation
            .entries()
            .iter()
            .filter(|candidate| candidate.directory_file_id64() == file_id)
            .count();
        (alias, file_id, identity_records)
    }

    #[cfg(windows)]
    #[test]
    #[ignore = "requires an actual ordinary-user local NTFS volume with 8.3 creation enabled"]
    fn enabled_ntfs_uses_canonical_long_input_and_one_record_per_generated_alias() {
        let fixture = Fixture::new();
        let original = fixture.0.join("OriginalWorkspaceLongFixtureName");
        let ai = fixture.0.join("AiWorkspaceLongFixtureName");
        let state = fixture.0.join("PrivateSessionDirectoryLongFixtureName");
        fs::create_dir(&original).expect("create alias original");
        let directory = original.join("SanitizedDirectoryLongFixtureName");
        fs::create_dir(&directory).expect("create long source directory");
        fs::write(
            directory.join("ordinary-long-filename-fixture.txt"),
            b"ordinary synthetic text\n",
        )
        .expect("write long source file");

        let (source_alias, _, source_records) = observed_alias(
            &fixture.0,
            original
                .file_name()
                .and_then(|name| name.to_str())
                .expect("source leaf"),
        );
        assert_eq!(source_records, 1);

        let alias_input = fixture.0.join(&source_alias);
        assert_eq!(
            create_session(&alias_input, &ai, &state, ReviewProfile::StandardV2),
            Err(CreateFailure::DefiniteFailure(
                Error::OriginalWorkspaceRejected
            ))
        );
        assert!(!ai.exists() && !state.exists());

        let case_only_input = fixture.0.join("originalworkspacelongfixturename");
        assert_eq!(
            create_session(&case_only_input, &ai, &state, ReviewProfile::StandardV2),
            Err(CreateFailure::DefiniteFailure(
                Error::OriginalWorkspaceRejected
            ))
        );
        assert!(!ai.exists() && !state.exists());

        let report = create_session(&original, &ai, &state, ReviewProfile::StandardV2)
            .expect("canonical long input succeeds");
        let (_ai_alias, _, ai_records) = observed_alias(
            &fixture.0,
            ai.file_name()
                .and_then(|name| name.to_str())
                .expect("AI leaf"),
        );
        assert_eq!(ai_records, 1);
        let rendered = format!("{report:?}");
        assert!(!rendered.contains('~'));
        assert!(!rendered.contains("OriginalWorkspaceLongFixtureName"));
        assert!(!rendered.contains("AiWorkspaceLongFixtureName"));
    }

    #[cfg(windows)]
    #[test]
    fn deterministic_original_mutation_gates_fail_at_each_create_boundary() {
        for (checkpoint, expected, roots_exist) in [
            (
                TestCheckpoint::AfterOriginalPassOne,
                Error::OriginalWorkspaceRejected,
                false,
            ),
            (
                TestCheckpoint::AfterOriginalPassTwo,
                Error::OriginalWorkspaceRejected,
                true,
            ),
            (
                TestCheckpoint::WorkspaceFileCreatedEmpty,
                Error::OriginalWorkspaceRejected,
                true,
            ),
            (
                TestCheckpoint::AfterAiStablePasses,
                Error::OriginalWorkspaceRejected,
                true,
            ),
        ] {
            let (_fixture, original, ai, state) = mutation_fixture();
            let target = original.join("ordinary.txt");
            let mut fired = false;
            let _hook = install_test_hook(move |observed| {
                if observed == checkpoint && !fired {
                    fired = true;
                    fs::write(&target, b"mutated synthetic original\n")
                        .map_err(|_| Error::FilesystemFailure)?;
                }
                Ok(())
            });
            let result = create_session(&original, &ai, &state, ReviewProfile::StandardV2);
            let expected = if roots_exist {
                CreateFailure::ManualInspectionRequired(expected)
            } else {
                CreateFailure::DefiniteFailure(expected)
            };
            assert_eq!(result, Err(expected), "{checkpoint:?}");
            assert_eq!(ai.exists(), roots_exist, "{checkpoint:?}");
            assert_eq!(state.exists(), roots_exist, "{checkpoint:?}");
            if roots_exist {
                assert_eq!(capsule_count(&state), 0, "{checkpoint:?}");
            }
        }
    }

    #[cfg(windows)]
    #[test]
    fn deterministic_ai_mutation_gates_prevent_generation_one_commit() {
        for checkpoint in [
            TestCheckpoint::WorkspaceFileCreatedEmpty,
            TestCheckpoint::AfterAiPassOne,
            TestCheckpoint::AfterAiStablePasses,
        ] {
            let (_fixture, original, ai, state) = mutation_fixture();
            let target = ai.join("ordinary.txt");
            let mut fired = false;
            let _hook = install_test_hook(move |observed| {
                if observed == checkpoint && !fired {
                    fired = true;
                    fs::write(&target, vec![b'X'; 128]).map_err(|_| Error::FilesystemFailure)?;
                }
                Ok(())
            });
            assert_eq!(
                create_session(&original, &ai, &state, ReviewProfile::StandardV2),
                Err(CreateFailure::ManualInspectionRequired(
                    Error::WorkspaceVerificationFailed
                )),
                "{checkpoint:?}"
            );
            assert!(ai.exists() && state.exists(), "{checkpoint:?}");
            assert_eq!(capsule_count(&state), 0, "{checkpoint:?}");
        }
    }

    #[cfg(windows)]
    #[test]
    fn created_private_authority_and_raw_free_surfaces_do_not_persist_context_canary() {
        let fixture = Fixture::new();
        let (original, ai, state) = fixture.paths();
        fs::create_dir(&original).expect("create canary original");
        let canary = "RT2R-RELATIVE-CONTEXT-CANARY-6F02D9";
        fs::write(
            original.join("canary.txt"),
            format!("{canary}\nendpoint = 192.0.2.77\nafter\n"),
        )
        .expect("write canary fixture");

        let report = create_session(&original, &ai, &state, ReviewProfile::StandardV2)
            .expect("create canary session");
        assert_eq!(capsule_count(&state), 1);
        assert_eq!(
            fs::read_dir(&state)
                .expect("enumerate created private state")
                .filter_map(Result::ok)
                .filter(|entry| entry.file_name().to_string_lossy().starts_with("manifest-"))
                .count(),
            0,
            "session create emits no manifest"
        );
        let protected = fs::read(capsule_file(&state)).expect("read capsule generation");
        let live = crate::roundtrip::dpapi::unprotect_live_capsule(&protected, None)
            .expect("authenticate and decrypt generation");
        let typed = live
            .capsule()
            .encode_canonical()
            .expect("canonical typed capsule");
        let utf16le = canary
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>();
        assert!(!contains_subslice(&typed, canary.as_bytes()));
        assert!(!contains_subslice(&typed, &utf16le));
        for rendered in [
            format!("{report:?}"),
            Error::AnchorAmbiguous.to_string(),
            Error::AnchorResourceLimitExceeded.to_string(),
            Error::AnchorEncodingInvalid.to_string(),
        ] {
            assert!(!rendered.contains(canary));
        }

        let lock = fs::read(state.join("session.lock")).expect("read fixed lock record");
        assert!(!contains_subslice(&lock, canary.as_bytes()));
        assert!(!contains_subslice(&lock, &utf16le));
    }

    #[cfg(windows)]
    fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
        !needle.is_empty()
            && haystack
                .windows(needle.len())
                .any(|window| window == needle)
    }

    #[cfg(not(windows))]
    #[test]
    fn unsupported_platform_fails_before_io() {
        assert_eq!(
            create_session(
                Path::new("original"),
                Path::new("ai"),
                Path::new("state"),
                ReviewProfile::StandardV2,
            ),
            Err(CreateFailure::DefiniteFailure(Error::UnsupportedPlatform))
        );
    }
}
