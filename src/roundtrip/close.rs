//! Logical and cryptographic private-session retirement.

use std::fmt;
use std::path::Path;

use super::schema::{SensitiveCandidateState, SessionState};
use super::Error;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CloseDisposalGuidance {
    RetainedArtifactsRequireUserDisposition,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CloseReport {
    pub session_id: String,
    pub generation: u64,
    pub last_nonclosed_state: SessionState,
    pub retained_capsule_generations: u32,
    pub retained_manifests: u32,
    pub retained_private_orphans: u32,
    pub sensitive_candidate_state: SensitiveCandidateState,
    pub incomplete_apply_acknowledged: bool,
    pub semantic_safety_assessed: bool,
    pub secure_erase_performed: bool,
    pub artifacts_deleted: bool,
    pub disposal_guidance: CloseDisposalGuidance,
    pub replayed: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CloseFailure {
    DefiniteFailure(Error),
    AcknowledgementRequired,
    AcknowledgementMismatch,
    AcknowledgementNotAllowed,
    ManualInspectionRequired(Error),
}

impl CloseFailure {
    pub const fn error(self) -> Option<Error> {
        match self {
            Self::DefiniteFailure(error) | Self::ManualInspectionRequired(error) => Some(error),
            Self::AcknowledgementRequired
            | Self::AcknowledgementMismatch
            | Self::AcknowledgementNotAllowed => None,
        }
    }

    pub const fn requires_manual_exit(self) -> bool {
        matches!(
            self,
            Self::AcknowledgementRequired | Self::ManualInspectionRequired(_)
        )
    }
}

impl fmt::Display for CloseFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::DefiniteFailure(_) => "round-trip close failed",
            Self::AcknowledgementRequired => {
                "round-trip close requires incomplete-apply acknowledgement"
            }
            Self::AcknowledgementMismatch => "round-trip close acknowledgement does not match",
            Self::AcknowledgementNotAllowed => {
                "round-trip close acknowledgement is not allowed in this state"
            }
            Self::ManualInspectionRequired(_) => {
                "round-trip close commit requires manual inspection"
            }
        })
    }
}

impl std::error::Error for CloseFailure {}

pub type CloseResult<T> = std::result::Result<T, CloseFailure>;

#[cfg(not(windows))]
pub fn close_session(
    _private_state: &Path,
    _acknowledgement: Option<[u8; 16]>,
) -> CloseResult<CloseReport> {
    Err(CloseFailure::DefiniteFailure(Error::UnsupportedPlatform))
}

#[cfg(windows)]
pub fn close_session(
    private_state: &Path,
    acknowledgement: Option<[u8; 16]>,
) -> CloseResult<CloseReport> {
    windows::close_session(private_state, acknowledgement)
}

#[cfg(windows)]
mod windows {
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;
    use crate::roundtrip::capsule::{StoreClassification, StoreObservation};
    use crate::roundtrip::crypto::constant_time_equal;
    use crate::roundtrip::dpapi::protect_closed_tombstone;
    use crate::roundtrip::schema::{ApplyState, ClosedTombstoneV1};
    use crate::roundtrip::token::encode_base32_128;

    pub(super) fn close_session(
        private_state: &Path,
        acknowledgement: Option<[u8; 16]>,
    ) -> CloseResult<CloseReport> {
        let store = super::super::status::windows::open_store(private_state)
            .map_err(CloseFailure::DefiniteFailure)?;
        let initial = store.read().map_err(CloseFailure::DefiniteFailure)?;
        if let Some(closed) = initial.closed_head() {
            if acknowledgement.is_some() {
                return Err(CloseFailure::AcknowledgementNotAllowed);
            }
            return report(closed.tombstone(), true).map_err(CloseFailure::DefiniteFailure);
        }
        require_prelock_live(&initial)?;

        let mut lock = store
            .acquire_mutation_lock()
            .map_err(CloseFailure::DefiniteFailure)?;
        let observation = store
            .read_while_locked(&mut lock)
            .map_err(CloseFailure::DefiniteFailure)?;
        if let Some(closed) = observation.closed_head() {
            if acknowledgement.is_some() {
                return Err(CloseFailure::AcknowledgementNotAllowed);
            }
            let output = report(closed.tombstone(), true).map_err(CloseFailure::DefiniteFailure)?;
            let _ = lock.release();
            return Ok(output);
        }
        require_prelock_live(&observation)?;
        let prior = observation
            .live_head()
            .ok_or(CloseFailure::ManualInspectionRequired(
                Error::CreateIncomplete,
            ))?;
        let capsule = prior.capsule();
        capsule
            .validate_capsule_state()
            .map_err(CloseFailure::DefiniteFailure)?;

        let (acknowledged, acknowledged_apply_id) = match capsule.session_state {
            SessionState::ApplyArmed | SessionState::ApplyIncomplete => {
                let authority = capsule
                    .apply_authority
                    .as_ref()
                    .ok_or(CloseFailure::DefiniteFailure(Error::CorruptState))?;
                let expected_state = if capsule.session_state == SessionState::ApplyArmed {
                    ApplyState::Armed
                } else {
                    ApplyState::Incomplete
                };
                if authority.state != expected_state {
                    return Err(CloseFailure::DefiniteFailure(Error::CorruptState));
                }
                let supplied = acknowledgement.ok_or(CloseFailure::AcknowledgementRequired)?;
                if !constant_time_equal(&supplied, &authority.apply_id) {
                    return Err(CloseFailure::AcknowledgementMismatch);
                }
                (true, Some(authority.apply_id))
            }
            _ => {
                if acknowledgement.is_some() {
                    return Err(CloseFailure::AcknowledgementNotAllowed);
                }
                (false, None)
            }
        };

        let generation = capsule
            .generation
            .checked_add(1)
            .ok_or(CloseFailure::DefiniteFailure(Error::InvalidState))?;
        let retained_capsule_generation_count = u32::try_from(generation)
            .map_err(|_| CloseFailure::DefiniteFailure(Error::BoundExceeded))?;
        let tombstone = ClosedTombstoneV1 {
            session_id: capsule.session_id,
            generation,
            review_profile: capsule.review_profile,
            ruleset_id: capsule.ruleset_id.clone(),
            last_nonclosed_state: capsule.session_state,
            closed_epoch_seconds: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| CloseFailure::DefiniteFailure(Error::InvalidState))?
                .as_secs(),
            retained_capsule_generation_count,
            retained_manifest_count: observation.manifest_count,
            retained_private_orphan_count: observation.orphan_count,
            ai_workspace_retained: true,
            sensitive_candidate_state: candidate_state(capsule.session_state),
            incomplete_apply_acknowledged: acknowledged,
            acknowledged_apply_id,
            semantic_safety_assessed: false,
        };
        tombstone
            .validate()
            .map_err(CloseFailure::DefiniteFailure)?;
        let protected =
            protect_closed_tombstone(prior, &tombstone).map_err(CloseFailure::DefiniteFailure)?;
        let evidence = store
            .append_capsule_generation(&mut lock, &protected)
            .map_err(classify_append_failure)?;
        if evidence.generation != generation || evidence.root_identity != store.root_identity() {
            return Err(CloseFailure::ManualInspectionRequired(
                Error::StateCommitUncertain,
            ));
        }
        let committed = store
            .read_while_locked(&mut lock)
            .map_err(|_| CloseFailure::ManualInspectionRequired(Error::StateCommitUncertain))?;
        let actual = committed
            .closed_head()
            .ok_or(CloseFailure::ManualInspectionRequired(
                Error::StateCommitUncertain,
            ))?
            .tombstone();
        if committed.classification != StoreClassification::Closed || actual != &tombstone {
            return Err(CloseFailure::ManualInspectionRequired(
                Error::StateCommitUncertain,
            ));
        }
        let output = report(actual, false)
            .map_err(|_| CloseFailure::ManualInspectionRequired(Error::StateCommitUncertain))?;
        let _ = lock.release();
        Ok(output)
    }

    fn require_prelock_live(observation: &StoreObservation) -> CloseResult<()> {
        if observation.live_head().is_some() {
            return Ok(());
        }
        Err(CloseFailure::ManualInspectionRequired(
            match observation.classification {
                StoreClassification::PrivateOrphansPresent => Error::PrivateOrphansPresent,
                _ => Error::CreateIncomplete,
            },
        ))
    }

    const fn candidate_state(state: SessionState) -> SensitiveCandidateState {
        match state {
            SessionState::ApplyArmed => SensitiveCandidateState::ArmedUnknown,
            SessionState::ApplyIncomplete => SensitiveCandidateState::Incomplete,
            SessionState::AppliedComplete => SensitiveCandidateState::Complete,
            SessionState::ActiveUnreviewed
            | SessionState::ReviewedRejected
            | SessionState::Reviewed
            | SessionState::ApprovedPartial
            | SessionState::ReadyToApply => SensitiveCandidateState::None,
        }
    }

    fn classify_append_failure(error: Error) -> CloseFailure {
        match error {
            Error::PrivateOrphansPresent
            | Error::StateCommitUncertain
            | Error::CorruptState
            | Error::UnsupportedAliasNamespace
            | Error::AliasNamespaceAmbiguous
            | Error::AliasIdentityMismatch
            | Error::CaseSensitiveDirectoryUnsupported
            | Error::PersistentVolumeQueryFailed
            | Error::PersistentVolumeStateAmbiguous
            | Error::FilesystemFailure
            | Error::BoundExceeded => CloseFailure::ManualInspectionRequired(error),
            _ => CloseFailure::DefiniteFailure(error),
        }
    }

    fn report(tombstone: &ClosedTombstoneV1, replayed: bool) -> Result<CloseReport, Error> {
        tombstone.validate()?;
        Ok(CloseReport {
            session_id: encode_base32_128(tombstone.session_id.as_bytes()),
            generation: tombstone.generation,
            last_nonclosed_state: tombstone.last_nonclosed_state,
            retained_capsule_generations: tombstone.retained_capsule_generation_count,
            retained_manifests: tombstone.retained_manifest_count,
            retained_private_orphans: tombstone.retained_private_orphan_count,
            sensitive_candidate_state: tombstone.sensitive_candidate_state,
            incomplete_apply_acknowledged: tombstone.incomplete_apply_acknowledged,
            semantic_safety_assessed: false,
            secure_erase_performed: false,
            artifacts_deleted: false,
            disposal_guidance: CloseDisposalGuidance::RetainedArtifactsRequireUserDisposition,
            replayed,
        })
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
    use crate::roundtrip::apply::{
        apply_session, install_test_hook, ApplyCheckpoint, ApplyFailureState,
    };
    use crate::roundtrip::approve::approve_review_event;
    use crate::roundtrip::create::create_session;
    use crate::roundtrip::review::review_session;
    use crate::roundtrip::status::{status_session, StatusManualAction, StatusState};
    use crate::roundtrip::token::{decode_base32_128, encode_base32_128, ReviewProfile};

    static NEXT: AtomicU64 = AtomicU64::new(0);
    static SERIAL: Mutex<()> = Mutex::new(());
    const CLOSE_CHILD_TEST_NAME: &str = "roundtrip::close::tests::close_checkpoint_child";
    const CLOSE_CHILD_STATE_ENV: &str = "SAFECLONE_TEST_CLOSE_CHILD_STATE";
    const GENERATION_CHECKPOINT_ENV: &str = "SAFECLONE_TEST_APPROVAL_COMMIT_CHECKPOINT";

    struct Fixture {
        root: PathBuf,
        original: PathBuf,
        ai: PathBuf,
        state: PathBuf,
        candidate: PathBuf,
    }

    impl Fixture {
        fn new(profile: ReviewProfile, setup: impl FnOnce(&Path)) -> Self {
            let serial = NEXT.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir()
                .join(format!("safeclone-close-{}-{serial}", std::process::id()));
            let original = root.join("OriginalWorkspaceLongName");
            let ai = root.join("AiWorkspaceLongName");
            let state = root.join("PrivateSessionLongName");
            let candidate = root.join("SensitiveCandidateWorkspaceLongName");
            fs::create_dir_all(&original).expect("create close Original fixture");
            setup(&original);
            create_session(&original, &ai, &state, profile).expect("create close session");
            Self {
                root,
                original,
                ai,
                state,
                candidate,
            }
        }

        fn review(&self) -> crate::roundtrip::review::ReviewOutcome {
            review_session(&self.original, &self.ai, &self.state).expect("review close fixture")
        }

        fn ready(&self) {
            let review = self.review();
            let review_id = decode_base32_128(&review.report().review_id).expect("review id");
            for event in &review.report().approval_events {
                if !event.approved {
                    approve_review_event(
                        &self.original,
                        &self.ai,
                        &self.state,
                        review_id,
                        decode_base32_128(&event.event_id).expect("event id"),
                        event.required_reason,
                    )
                    .expect("approve close event");
                }
            }
            assert_eq!(
                self.review().report().session_state,
                SessionState::ReadyToApply
            );
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn token_file(values: &[&str]) -> Vec<u8> {
        let mut bytes = Vec::new();
        for index in 0..12 {
            bytes.extend_from_slice(format!("before-{index:02}\n").as_bytes());
        }
        for (index, value) in values.iter().enumerate() {
            bytes.extend_from_slice(format!("contact-{index}={value}\n").as_bytes());
        }
        for index in 0..12 {
            bytes.extend_from_slice(format!("after-{index:02}\n").as_bytes());
        }
        bytes
    }

    fn remove_all_tokens(mut bytes: Vec<u8>) -> Vec<u8> {
        const PREFIX: &[u8] = b"__SAFECLONE_RT1_";
        loop {
            let Some(start) = bytes
                .windows(PREFIX.len())
                .position(|window| window == PREFIX)
            else {
                return bytes;
            };
            let search = start + PREFIX.len();
            let end = bytes[search..]
                .windows(2)
                .position(|window| window == b"__")
                .map(|offset| search + offset + 2)
                .expect("generated token terminator");
            bytes.drain(start..end);
        }
    }

    fn private_snapshot(path: &Path) -> Vec<(String, Vec<u8>)> {
        let mut entries = fs::read_dir(path)
            .expect("read private state")
            .map(|entry| {
                let entry = entry.expect("private entry");
                (
                    entry.file_name().to_string_lossy().into_owned(),
                    fs::read(entry.path()).expect("read private artifact"),
                )
            })
            .collect::<Vec<_>>();
        entries.sort_by(|left, right| left.0.cmp(&right.0));
        entries
    }

    fn spawn_close_checkpoint_child(
        state: &Path,
        checkpoint: &str,
    ) -> std::io::Result<std::process::ExitStatus> {
        Command::new(std::env::current_exe()?)
            .arg(CLOSE_CHILD_TEST_NAME)
            .arg("--exact")
            .arg("--nocapture")
            .env(CLOSE_CHILD_STATE_ENV, state)
            .env(GENERATION_CHECKPOINT_ENV, checkpoint)
            .env("RUST_TEST_THREADS", "1")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
    }

    #[test]
    fn close_checkpoint_child() {
        let Some(state) = std::env::var_os(CLOSE_CHILD_STATE_ENV) else {
            return;
        };
        let result = close_session(Path::new(&state), None);
        panic!("close checkpoint did not abort: {result:?}");
    }

    #[test]
    fn tombstone_interruptions_are_classified_and_only_close_or_replay() {
        let _serial = SERIAL
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for checkpoint in ["P0", "P1", "P2", "P3", "P4", "P5", "P6", "P7"] {
            let fixture = Fixture::new(ReviewProfile::StandardV2, |original| {
                fs::write(original.join("main.txt"), b"ordinary\n")
                    .expect("write close checkpoint source");
            });
            let status = spawn_close_checkpoint_child(&fixture.state, checkpoint)
                .expect("spawn close checkpoint child");
            assert!(!status.success(), "{checkpoint} must abort");

            let observed = status_session(&fixture.state).expect("classify close interruption");
            match checkpoint {
                "P0" => {
                    assert_eq!(observed.session_state, StatusState::ActiveUnreviewed);
                    assert_eq!(observed.private_orphan_count, 0);
                }
                "P1" | "P2" | "P3" | "P4" => {
                    assert_eq!(observed.session_state, StatusState::PrivateOrphansPresent);
                    assert_eq!(observed.private_orphan_count, 1);
                }
                "P5" | "P6" | "P7" => {
                    assert_eq!(observed.session_state, StatusState::Closed);
                    assert_eq!(observed.private_orphan_count, 0);
                }
                _ => unreachable!(),
            }

            let closed = close_session(&fixture.state, None)
                .expect("close or replay after classified interruption");
            assert_eq!(closed.replayed, matches!(checkpoint, "P5" | "P6" | "P7"));
            assert_eq!(
                closed.retained_private_orphans,
                u32::from(matches!(checkpoint, "P1" | "P2" | "P3" | "P4"))
            );
            let replay = close_session(&fixture.state, None).expect("closed replay");
            assert!(replay.replayed);
            assert_eq!(replay.generation, closed.generation);
        }
    }

    #[test]
    fn status_is_read_only_and_close_is_terminal_idempotent_retirement() {
        let _serial = SERIAL
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let fixture = Fixture::new(ReviewProfile::StandardV2, |original| {
            fs::write(original.join("main.txt"), b"ordinary\n").expect("write Original");
        });
        let before = private_snapshot(&fixture.state);
        let first = status_session(&fixture.state).expect("status live session");
        let second = status_session(&fixture.state).expect("repeat status live session");
        assert_eq!(first, second);
        assert_eq!(first.session_state, StatusState::ActiveUnreviewed);
        assert_eq!(first.manual_action, StatusManualAction::None);
        assert_eq!(private_snapshot(&fixture.state), before);

        let closed = close_session(&fixture.state, None).expect("close live session");
        assert!(!closed.replayed);
        assert_eq!(closed.last_nonclosed_state, SessionState::ActiveUnreviewed);
        assert_eq!(
            closed.sensitive_candidate_state,
            SensitiveCandidateState::None
        );
        assert!(!closed.incomplete_apply_acknowledged);
        assert!(!closed.secure_erase_performed);
        assert!(!closed.artifacts_deleted);
        let after_close = private_snapshot(&fixture.state);
        assert_eq!(after_close.len(), before.len() + 1);
        for prior in before {
            assert!(
                after_close.contains(&prior),
                "close must retain every prior artifact"
            );
        }
        let closed_status = status_session(&fixture.state).expect("status CLOSED");
        assert_eq!(closed_status.session_state, StatusState::Closed);
        let replay = close_session(&fixture.state, None).expect("close replay");
        assert!(replay.replayed);
        assert_eq!(private_snapshot(&fixture.state), after_close);

        let copied = fixture.root.join("CopiedClosedPrivateState");
        fs::create_dir(&copied).expect("create copied CLOSED root");
        for entry in fs::read_dir(&fixture.state).expect("read CLOSED state") {
            let entry = entry.expect("closed entry");
            fs::copy(entry.path(), copied.join(entry.file_name())).expect("copy CLOSED artifact");
        }
        assert_eq!(
            status_session(&copied)
                .expect("copied CLOSED remains terminal")
                .session_state,
            StatusState::Closed
        );
        let copied_replay = close_session(&copied, None).expect("copied CLOSED close replay");
        assert!(copied_replay.replayed);
        assert_eq!(copied_replay.generation, closed.generation);
    }

    #[test]
    fn create_incomplete_absent_or_corrupt_state_never_mutates() {
        let _serial = SERIAL
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let serial = NEXT.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "safeclone-close-incomplete-{}-{serial}",
            std::process::id()
        ));
        let state = root.join("PrivateSessionLongName");
        assert!(status_session(&state).is_err());
        fs::create_dir_all(&state).expect("create incomplete state root");
        let before = private_snapshot(&state);
        let status = status_session(&state).expect("recognize CREATE_INCOMPLETE");
        assert_eq!(status.session_state, StatusState::CreateIncomplete);
        assert!(status.session_id.is_none());
        assert!(status.requires_manual_exit());
        assert!(matches!(
            close_session(&state, None),
            Err(CloseFailure::ManualInspectionRequired(
                Error::CreateIncomplete
            ))
        ));
        assert_eq!(private_snapshot(&state), before);
        fs::write(state.join("unrelated.txt"), b"unrelated state")
            .expect("write unrelated state leaf");
        let unrelated = private_snapshot(&state);
        assert!(status_session(&state).is_err());
        assert!(matches!(
            close_session(&state, None),
            Err(CloseFailure::DefiniteFailure(_))
        ));
        assert_eq!(private_snapshot(&state), unrelated);
        fs::remove_dir_all(&root).expect("remove incomplete test fixture");

        let fixture = Fixture::new(ReviewProfile::StandardV2, |original| {
            fs::write(original.join("main.txt"), b"ordinary\n").expect("write Original");
        });
        let capsule = fixture.state.join("capsule-0000000000000001.scdp");
        let mut bytes = fs::read(&capsule).expect("read capsule");
        let last = bytes.last_mut().expect("nonempty capsule");
        *last ^= 1;
        fs::write(&capsule, bytes).expect("corrupt synthetic capsule");
        assert!(status_session(&fixture.state).is_err());
        assert!(matches!(
            close_session(&fixture.state, None),
            Err(CloseFailure::DefiniteFailure(_))
        ));
    }

    #[test]
    fn private_orphans_are_reported_and_retained_through_close() {
        let _serial = SERIAL
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let fixture = Fixture::new(ReviewProfile::StandardV2, |original| {
            fs::write(original.join("main.txt"), b"ordinary\n").expect("write Original");
        });
        let pending = fixture
            .state
            .join(format!(".pending-{}.scdp", encode_base32_128(&[0x55; 16])));
        fs::write(&pending, b"synthetic retained orphan").expect("create private orphan");
        let status = status_session(&fixture.state).expect("status private orphan");
        assert_eq!(status.session_state, StatusState::PrivateOrphansPresent);
        assert_eq!(status.private_orphan_count, 1);
        assert_eq!(
            status.manual_action,
            StatusManualAction::PrivateOrphansPresent
        );
        let closed = close_session(&fixture.state, None).expect("close with retained orphan");
        assert_eq!(closed.retained_private_orphans, 1);
        assert!(pending.is_file());
        assert_eq!(
            status_session(&fixture.state)
                .expect("status closed orphan state")
                .session_state,
            StatusState::Closed
        );
    }

    #[test]
    fn close_lock_contention_is_definite_and_nonmutating() {
        let _serial = SERIAL
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let fixture = Fixture::new(ReviewProfile::StandardV2, |original| {
            fs::write(original.join("main.txt"), b"ordinary\n").expect("write Original");
        });
        let store = crate::roundtrip::status::windows::open_store(&fixture.state)
            .expect("open status store");
        let before = private_snapshot(&fixture.state);
        let held = store.acquire_mutation_lock().expect("hold mutation lock");
        assert_eq!(
            close_session(&fixture.state, None),
            Err(CloseFailure::DefiniteFailure(Error::LockContention))
        );
        held.release().expect("release held lock");
        assert_eq!(private_snapshot(&fixture.state), before);
    }

    #[test]
    fn ordinary_authenticated_state_matrix_closes_without_acknowledgement() {
        let _serial = SERIAL
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let reviewed_rejected = Fixture::new(ReviewProfile::StandardV2, |original| {
            fs::write(
                original.join("main.txt"),
                token_file(&["rt8.rejected@example.invalid"]),
            )
            .expect("write rejected Original");
        });
        fs::write(
            reviewed_rejected.ai.join("NewSensitiveFindingLongName.txt"),
            b"rt8.close.new-sensitive@example.invalid\n",
        )
        .expect("write rejected new sensitive finding");
        assert_eq!(
            reviewed_rejected.review().report().session_state,
            SessionState::ReviewedRejected
        );
        assert_eq!(
            status_session(&reviewed_rejected.state)
                .expect("status rejected")
                .session_state,
            StatusState::ReviewedRejected
        );
        close_session(&reviewed_rejected.state, None).expect("close rejected");

        let reviewed = Fixture::new(ReviewProfile::StandardV2, |original| {
            fs::write(
                original.join("main.txt"),
                token_file(&["rt8.reviewed@example.invalid"]),
            )
            .expect("write reviewed Original");
        });
        let ai = reviewed.ai.join("main.txt");
        fs::write(&ai, remove_all_tokens(fs::read(&ai).expect("read AI"))).expect("delete token");
        assert_eq!(
            reviewed.review().report().session_state,
            SessionState::Reviewed
        );
        close_session(&reviewed.state, None).expect("close reviewed");

        let partial = Fixture::new(ReviewProfile::StandardV2, |original| {
            fs::write(
                original.join("main.txt"),
                token_file(&[
                    "rt8.partial.one@example.invalid",
                    "rt8.partial.two@example.invalid",
                ]),
            )
            .expect("write partial Original");
        });
        let ai = partial.ai.join("main.txt");
        fs::write(&ai, remove_all_tokens(fs::read(&ai).expect("read AI")))
            .expect("delete two tokens");
        let review = partial.review();
        assert!(review.report().approval_events.len() >= 2);
        let first = &review.report().approval_events[0];
        approve_review_event(
            &partial.original,
            &partial.ai,
            &partial.state,
            decode_base32_128(&review.report().review_id).expect("review id"),
            decode_base32_128(&first.event_id).expect("event id"),
            first.required_reason,
        )
        .expect("approve one event");
        assert_eq!(
            status_session(&partial.state)
                .expect("status partial")
                .session_state,
            StatusState::ApprovedPartial
        );
        close_session(&partial.state, None).expect("close partial");

        let ready = Fixture::new(ReviewProfile::StandardV2, |original| {
            fs::write(original.join("main.txt"), b"ordinary\n").expect("write ready Original");
        });
        assert_eq!(
            ready.review().report().session_state,
            SessionState::ReadyToApply
        );
        close_session(&ready.state, None).expect("close ready");
    }

    #[test]
    fn incomplete_apply_requires_exact_current_acknowledgement() {
        let _serial = SERIAL
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for checkpoint in [
            ApplyCheckpoint::AfterApplyArmedCommit,
            ApplyCheckpoint::AfterApplyIncompleteCommit,
        ] {
            let fixture = Fixture::new(ReviewProfile::StandardV2, |original| {
                fs::write(original.join("main.txt"), b"ordinary\n").expect("write apply Original");
            });
            fixture.ready();
            let hook = install_test_hook(move |observed| {
                if observed == checkpoint {
                    Err(Error::FilesystemFailure)
                } else {
                    Ok(())
                }
            });
            let interrupted = apply_session(
                &fixture.original,
                &fixture.ai,
                &fixture.state,
                &fixture.candidate,
            )
            .expect_err("interrupt apply state");
            assert!(matches!(
                interrupted.state(),
                ApplyFailureState::ManualIncomplete | ApplyFailureState::StateCommitUncertain
            ));
            drop(hook);
            let retained_orphan = if checkpoint == ApplyCheckpoint::AfterApplyIncompleteCommit {
                let pending = fixture
                    .state
                    .join(format!(".pending-{}.scdp", encode_base32_128(&[0x66; 16])));
                fs::write(&pending, b"synthetic incomplete-apply orphan")
                    .expect("create incomplete-apply orphan");
                Some(pending)
            } else {
                None
            };
            let status = status_session(&fixture.state).expect("status incomplete apply");
            assert!(matches!(
                status.authenticated_live_state,
                Some(SessionState::ApplyArmed | SessionState::ApplyIncomplete)
            ));
            assert_eq!(
                status.private_orphan_count,
                u32::from(retained_orphan.is_some())
            );
            let apply_id = decode_base32_128(status.apply_id.as_deref().expect("apply id"))
                .expect("decode apply id");
            assert_eq!(
                close_session(&fixture.state, None),
                Err(CloseFailure::AcknowledgementRequired)
            );
            let mut wrong = apply_id;
            wrong[0] ^= 1;
            assert_eq!(
                close_session(&fixture.state, Some(wrong)),
                Err(CloseFailure::AcknowledgementMismatch)
            );
            let closed = close_session(&fixture.state, Some(apply_id)).expect("acknowledged close");
            assert!(closed.incomplete_apply_acknowledged);
            assert_eq!(
                closed.retained_private_orphans,
                u32::from(retained_orphan.is_some())
            );
            if let Some(pending) = retained_orphan {
                assert!(pending.is_file(), "close must retain the private orphan");
            }
            assert_eq!(
                closed.sensitive_candidate_state,
                if checkpoint == ApplyCheckpoint::AfterApplyArmedCommit {
                    SensitiveCandidateState::ArmedUnknown
                } else {
                    SensitiveCandidateState::Incomplete
                }
            );
        }
    }

    #[test]
    fn applied_complete_closes_without_ack_and_unnecessary_ack_rejects() {
        let _serial = SERIAL
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let fixture = Fixture::new(ReviewProfile::StandardV2, |original| {
            fs::write(original.join("main.txt"), b"ordinary\n").expect("write Original");
        });
        assert_eq!(
            close_session(&fixture.state, Some([0x44; 16])),
            Err(CloseFailure::AcknowledgementNotAllowed)
        );
        fixture.ready();
        apply_session(
            &fixture.original,
            &fixture.ai,
            &fixture.state,
            &fixture.candidate,
        )
        .expect("complete apply");
        assert_eq!(
            status_session(&fixture.state)
                .expect("status applied")
                .session_state,
            StatusState::AppliedComplete
        );
        let closed = close_session(&fixture.state, None).expect("close complete apply");
        assert_eq!(
            closed.sensitive_candidate_state,
            SensitiveCandidateState::Complete
        );
        assert!(!closed.incomplete_apply_acknowledged);
    }
}
