//! Read-only authenticated private-session status orchestration.

use std::fmt;
use std::path::Path;

use super::schema::{ApplyState, SensitiveCandidateState, SessionState};
use super::token::{ReviewProfile, ENGINE_VERSION, POLICY_ID, TOKEN_SUITE_ID};
use super::Error;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StatusState {
    CreateIncomplete,
    ActiveUnreviewed,
    ReviewedRejected,
    Reviewed,
    ApprovedPartial,
    ReadyToApply,
    ApplyArmed,
    ApplyIncomplete,
    AppliedComplete,
    PrivateOrphansPresent,
    Closed,
}

impl StatusState {
    const fn from_live(state: SessionState) -> Self {
        match state {
            SessionState::ActiveUnreviewed => Self::ActiveUnreviewed,
            SessionState::ReviewedRejected => Self::ReviewedRejected,
            SessionState::Reviewed => Self::Reviewed,
            SessionState::ApprovedPartial => Self::ApprovedPartial,
            SessionState::ReadyToApply => Self::ReadyToApply,
            SessionState::ApplyArmed => Self::ApplyArmed,
            SessionState::ApplyIncomplete => Self::ApplyIncomplete,
            SessionState::AppliedComplete => Self::AppliedComplete,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StatusManualAction {
    None,
    CreateIncomplete,
    PrivateOrphansPresent,
    ApplyArmed,
    ApplyIncomplete,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionStatusReport {
    pub session_id: Option<String>,
    pub session_state: StatusState,
    pub authenticated_live_state: Option<SessionState>,
    pub review_profile: Option<ReviewProfile>,
    pub capsule_generation: Option<u64>,
    pub engine_version: Option<&'static str>,
    pub policy_id: Option<&'static str>,
    pub ruleset_id: Option<String>,
    pub token_suite_id: Option<u16>,
    pub current_review_id: Option<String>,
    pub approved_event_count: u32,
    pub approval_required_count: u32,
    pub private_orphan_count: u32,
    pub manifest_count: u32,
    pub apply_id: Option<String>,
    pub apply_state: Option<ApplyState>,
    pub last_nonclosed_state: Option<SessionState>,
    pub retained_capsule_generation_count: Option<u32>,
    pub retained_manifest_count: Option<u32>,
    pub retained_private_orphan_count: Option<u32>,
    pub sensitive_candidate_state: Option<SensitiveCandidateState>,
    pub incomplete_apply_acknowledged: Option<bool>,
    pub semantic_safety_assessed: bool,
    pub manual_action: StatusManualAction,
}

impl SessionStatusReport {
    pub const fn requires_manual_exit(&self) -> bool {
        !matches!(self.manual_action, StatusManualAction::None)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StatusFailure {
    DefiniteFailure(Error),
}

impl StatusFailure {
    pub const fn error(self) -> Error {
        match self {
            Self::DefiniteFailure(error) => error,
        }
    }
}

impl fmt::Display for StatusFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("round-trip status could not authenticate private state")
    }
}

impl std::error::Error for StatusFailure {}

pub type StatusResult<T> = std::result::Result<T, StatusFailure>;

#[cfg(not(windows))]
pub fn status_session(_private_state: &Path) -> StatusResult<SessionStatusReport> {
    Err(StatusFailure::DefiniteFailure(Error::UnsupportedPlatform))
}

#[cfg(windows)]
pub fn status_session(private_state: &Path) -> StatusResult<SessionStatusReport> {
    windows::status_session(private_state)
}

#[cfg(windows)]
pub(crate) mod windows {
    use super::*;
    use crate::roundtrip::capsule::{GenerationStore, StoreClassification, StoreObservation};
    use crate::roundtrip::token::encode_base32_128;

    pub(crate) fn open_store(private_state: &Path) -> Result<GenerationStore, Error> {
        let preflight = crate::locality::preflight_roundtrip_state_path(private_state)
            .map_err(map_locality_error)?;
        let confirmed = crate::locality::open_and_confirm_roundtrip_state_volume(preflight)
            .map_err(map_locality_error)?;
        let authority = super::super::observe::qualify_roundtrip_state_volume(confirmed)?;
        Ok(GenerationStore::from_qualified_root(authority))
    }

    pub(super) fn status_session(private_state: &Path) -> StatusResult<SessionStatusReport> {
        let store = open_store(private_state).map_err(StatusFailure::DefiniteFailure)?;
        let observation = store.read().map_err(StatusFailure::DefiniteFailure)?;
        report(&observation).map_err(StatusFailure::DefiniteFailure)
    }

    pub(crate) fn report(observation: &StoreObservation) -> Result<SessionStatusReport, Error> {
        if let Some(closed) = observation.closed_head() {
            let tombstone = closed.tombstone();
            tombstone.validate()?;
            return Ok(SessionStatusReport {
                session_id: Some(encode_base32_128(tombstone.session_id.as_bytes())),
                session_state: StatusState::Closed,
                authenticated_live_state: None,
                review_profile: Some(tombstone.review_profile),
                capsule_generation: Some(tombstone.generation),
                engine_version: Some(ENGINE_VERSION),
                policy_id: Some(POLICY_ID),
                ruleset_id: Some(tombstone.ruleset_id.clone()),
                token_suite_id: Some(TOKEN_SUITE_ID),
                current_review_id: None,
                approved_event_count: 0,
                approval_required_count: 0,
                private_orphan_count: observation.orphan_count,
                manifest_count: observation.manifest_count,
                apply_id: None,
                apply_state: None,
                last_nonclosed_state: Some(tombstone.last_nonclosed_state),
                retained_capsule_generation_count: Some(
                    tombstone.retained_capsule_generation_count,
                ),
                retained_manifest_count: Some(tombstone.retained_manifest_count),
                retained_private_orphan_count: Some(tombstone.retained_private_orphan_count),
                sensitive_candidate_state: Some(tombstone.sensitive_candidate_state),
                incomplete_apply_acknowledged: Some(tombstone.incomplete_apply_acknowledged),
                semantic_safety_assessed: false,
                manual_action: StatusManualAction::None,
            });
        }

        if let Some(live) = observation.live_head() {
            let capsule = live.capsule();
            capsule.validate_capsule_state()?;
            let approved_event_count = u32::try_from(capsule.approval_set.records.len())
                .map_err(|_| Error::BoundExceeded)?;
            let approval_required_count = capsule
                .current_review
                .as_ref()
                .map_or(0, |review| review.approval_eligible_count);
            let apply = capsule.apply_authority.as_ref();
            let orphaned = observation.classification == StoreClassification::PrivateOrphansPresent;
            let manual_action = if orphaned {
                StatusManualAction::PrivateOrphansPresent
            } else {
                match capsule.session_state {
                    SessionState::ApplyArmed => StatusManualAction::ApplyArmed,
                    SessionState::ApplyIncomplete => StatusManualAction::ApplyIncomplete,
                    _ => StatusManualAction::None,
                }
            };
            return Ok(SessionStatusReport {
                session_id: Some(encode_base32_128(capsule.session_id.as_bytes())),
                session_state: if orphaned {
                    StatusState::PrivateOrphansPresent
                } else {
                    StatusState::from_live(capsule.session_state)
                },
                authenticated_live_state: Some(capsule.session_state),
                review_profile: Some(capsule.review_profile),
                capsule_generation: Some(capsule.generation),
                engine_version: Some(ENGINE_VERSION),
                policy_id: Some(POLICY_ID),
                ruleset_id: Some(capsule.ruleset_id.clone()),
                token_suite_id: Some(TOKEN_SUITE_ID),
                current_review_id: capsule
                    .current_review
                    .as_ref()
                    .map(|review| encode_base32_128(&review.review_id)),
                approved_event_count,
                approval_required_count,
                private_orphan_count: observation.orphan_count,
                manifest_count: observation.manifest_count,
                apply_id: apply.map(|authority| encode_base32_128(&authority.apply_id)),
                apply_state: apply.map(|authority| authority.state),
                last_nonclosed_state: None,
                retained_capsule_generation_count: None,
                retained_manifest_count: None,
                retained_private_orphan_count: None,
                sensitive_candidate_state: None,
                incomplete_apply_acknowledged: None,
                semantic_safety_assessed: false,
                manual_action,
            });
        }

        let (session_state, manual_action) = match observation.classification {
            StoreClassification::CreateIncomplete => (
                StatusState::CreateIncomplete,
                StatusManualAction::CreateIncomplete,
            ),
            StoreClassification::PrivateOrphansPresent => (
                StatusState::PrivateOrphansPresent,
                StatusManualAction::PrivateOrphansPresent,
            ),
            StoreClassification::AuthoritativeLive | StoreClassification::Closed => {
                return Err(Error::CorruptState);
            }
        };
        Ok(SessionStatusReport {
            session_id: None,
            session_state,
            authenticated_live_state: None,
            review_profile: None,
            capsule_generation: None,
            engine_version: None,
            policy_id: None,
            ruleset_id: None,
            token_suite_id: None,
            current_review_id: None,
            approved_event_count: 0,
            approval_required_count: 0,
            private_orphan_count: observation.orphan_count,
            manifest_count: observation.manifest_count,
            apply_id: None,
            apply_state: None,
            last_nonclosed_state: None,
            retained_capsule_generation_count: None,
            retained_manifest_count: None,
            retained_private_orphan_count: None,
            sensitive_candidate_state: None,
            incomplete_apply_acknowledged: None,
            semantic_safety_assessed: false,
            manual_action,
        })
    }

    fn map_locality_error(error: crate::LocalityError) -> Error {
        match error {
            crate::LocalityError::UnsupportedPlatform => Error::UnsupportedPlatform,
            crate::LocalityError::UnsupportedPathClass
            | crate::LocalityError::GitMetadataBoundaryRejected => Error::InvalidState,
            crate::LocalityError::LocalityUnavailable
            | crate::LocalityError::LocalVolumeNotProven
            | crate::LocalityError::PreflightChanged
            | crate::LocalityError::CapabilityOpenFailed
            | crate::LocalityError::RemoteFilesystem
            | crate::LocalityError::UnsupportedFilesystem
            | crate::LocalityError::HandleVolumeMismatch => Error::FilesystemFailure,
        }
    }
}
