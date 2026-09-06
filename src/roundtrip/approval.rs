//! Approval policy and authenticated ApprovalSet authority.
//!
//! This module is deliberately independent of ChangedManifestV1 and the
//! reporting diff. It consumes only the authenticated capsule plus a fresh
//! classification identity/event authority.

use super::baseline::StreamEncoder;
use super::classify::PreparedReviewAuthority;
use super::crypto::{constant_time_equal, KeyPurpose, KeySchedule};
use super::events::{CanonicalEvent, EventDecision, EventKind};
use super::review_identity::ReviewIdentityIndex;
use super::schema::{
    ApprovalEventType, ApprovalReason, ApprovalRecordV1, ApprovalSetV1, CapsuleV1, SessionState,
    MAX_APPROVAL_RECORDS,
};
use super::token::{ReviewProfile, ENGINE_VERSION, POLICY_ID, TOKEN_SUITE_ID};
use super::{Error, Result};

const APPROVAL_SET_SCHEMA_VERSION: u8 = 1;
const APPROVAL_SET_DOMAIN: &[u8] = b"safeclone/rt1/approval-set-v1";

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct ApprovalRequirement {
    pub(crate) event_id: [u8; 16],
    pub(crate) event_type: ApprovalEventType,
    pub(crate) reason: ApprovalReason,
}

/// Proof that the stored set tag and every record have been checked against
/// the fresh current review. No `Debug`: it borrows private capsule authority.
pub(crate) struct AuthenticatedApprovalSet<'set> {
    set: &'set ApprovalSetV1,
    eligible_count: u32,
}

/// Owned, non-forgeable proof that approval authenticated the complete current
/// approval set for a fresh classification authority.  The seal intentionally exposes
/// neither approval booleans nor an event-id list to reconstruction callers.
pub(crate) struct CompleteApprovalEvidence {
    _seal: (),
}

impl<'set> AuthenticatedApprovalSet<'set> {
    pub(crate) fn find(&self, event_id: &[u8; 16]) -> Option<&'set ApprovalRecordV1> {
        self.set
            .records
            .binary_search_by_key(event_id, |record| record.event_id)
            .ok()
            .and_then(|index| self.set.records.get(index))
    }

    pub(crate) fn approved_count(&self) -> Result<u32> {
        u32::try_from(self.set.records.len()).map_err(|_| Error::BoundExceeded)
    }

    pub(crate) fn remaining_count(&self) -> Result<u32> {
        self.eligible_count
            .checked_sub(self.approved_count()?)
            .ok_or(Error::CorruptState)
    }
}

pub(crate) fn requirement_for_event(
    event_id: [u8; 16],
    event: &CanonicalEvent,
) -> Option<ApprovalRequirement> {
    if event.decision != EventDecision::ApprovalRequired {
        return None;
    }
    let event_type = match event.kind {
        EventKind::TokenDeleted => ApprovalEventType::Deleted,
        EventKind::FileDeleted => ApprovalEventType::FileDeleted,
        EventKind::StrictTokenFileModified => ApprovalEventType::StrictTokenFileModified,
        _ => return None,
    };
    Some(ApprovalRequirement {
        event_id,
        event_type,
        reason: event_type.required_reason(),
    })
}

pub(crate) fn requirement_by_id(
    authority: &PreparedReviewAuthority,
    identities: &ReviewIdentityIndex,
    event_id: &[u8; 16],
) -> Result<ApprovalRequirement> {
    let identity = identities
        .event_by_id(event_id)
        .ok_or(Error::ApprovalEventInvalid)?;
    let event = authority
        .events
        .events()
        .get(identity.event_index)
        .ok_or(Error::CorruptState)?;
    requirement_for_event(identity.event_id, event).ok_or(Error::ApprovalEventIneligible)
}

pub(crate) fn approval_requirements(
    authority: &PreparedReviewAuthority,
    identities: &ReviewIdentityIndex,
) -> Result<Vec<ApprovalRequirement>> {
    let expected =
        usize::try_from(authority.events.approval_required()).map_err(|_| Error::BoundExceeded)?;
    if expected > MAX_APPROVAL_RECORDS {
        return Err(Error::BoundExceeded);
    }
    let mut requirements = Vec::new();
    requirements
        .try_reserve_exact(expected)
        .map_err(|_| Error::BoundExceeded)?;
    for (index, event) in authority.events.events().iter().enumerate() {
        if event.decision != EventDecision::ApprovalRequired {
            continue;
        }
        let identity = identities.event(index)?;
        let requirement =
            requirement_for_event(identity.event_id, event).ok_or(Error::CorruptState)?;
        requirements.push(requirement);
    }
    if requirements.len() != expected {
        return Err(Error::CorruptState);
    }
    requirements.sort_unstable_by_key(|requirement| requirement.event_id);
    if requirements
        .windows(2)
        .any(|pair| pair[0].event_id >= pair[1].event_id)
    {
        return Err(Error::CorruptState);
    }
    Ok(requirements)
}

pub(crate) fn empty_review_approval_set(
    schedule: &KeySchedule<'_>,
    review_id: [u8; 16],
    profile: ReviewProfile,
    ruleset_id: &str,
) -> Result<ApprovalSetV1> {
    let mut set = ApprovalSetV1 {
        review_id: Some(review_id),
        records: Vec::new(),
        approval_set_tag: [0; 32],
    };
    set.approval_set_tag = approval_set_tag(schedule, profile, ruleset_id, review_id, &[])?;
    Ok(set)
}

pub(crate) fn approval_set_tag(
    schedule: &KeySchedule<'_>,
    profile: ReviewProfile,
    ruleset_id: &str,
    review_id: [u8; 16],
    records: &[ApprovalRecordV1],
) -> Result<[u8; 32]> {
    approval_set_tag_with_contract(
        schedule,
        profile,
        ENGINE_VERSION,
        POLICY_ID,
        ruleset_id,
        TOKEN_SUITE_ID,
        APPROVAL_SET_SCHEMA_VERSION,
        review_id,
        records,
    )
}

#[allow(clippy::too_many_arguments)]
fn approval_set_tag_with_contract(
    schedule: &KeySchedule<'_>,
    profile: ReviewProfile,
    engine_version: &str,
    policy_id: &str,
    ruleset_id: &str,
    token_suite_id: u16,
    schema_version: u8,
    review_id: [u8; 16],
    records: &[ApprovalRecordV1],
) -> Result<[u8; 32]> {
    if !profile.is_current()
        || engine_version.is_empty()
        || policy_id.is_empty()
        || ruleset_id.is_empty()
        || schema_version == 0
        || records.len() > MAX_APPROVAL_RECORDS
    {
        return Err(Error::InvalidState);
    }
    let mut value = StreamEncoder::new(schedule, KeyPurpose::ApprovalMac, APPROVAL_SET_DOMAIN)?;
    value.bytes(schedule.session_id().as_bytes())?;
    value.u8(profile as u8);
    value.bytes(engine_version.as_bytes())?;
    value.bytes(policy_id.as_bytes())?;
    value.bytes(ruleset_id.as_bytes())?;
    value.u16(token_suite_id);
    value.u8(schema_version);
    value.bytes(&review_id)?;
    value.u32(u32::try_from(records.len()).map_err(|_| Error::BoundExceeded)?);
    for record in records {
        value.bytes(&record.event_id)?;
        value.u8(record.event_type as u8);
        value.u8(record.reason_code as u8);
        value.bytes(&record.edited_tree_commitment)?;
        value.u64(record.approved_in_generation);
    }
    Ok(value.finish())
}

pub(crate) fn verify_approval_set_tag(
    capsule: &CapsuleV1,
    schedule: &KeySchedule<'_>,
) -> Result<()> {
    capsule
        .approval_set
        .validate()
        .map_err(|_| Error::CorruptState)?;
    let review = capsule.current_review.as_ref().ok_or(Error::InvalidState)?;
    if capsule.approval_set.review_id != Some(review.review_id) {
        return Err(Error::CorruptState);
    }
    let expected = approval_set_tag(
        schedule,
        capsule.review_profile,
        &capsule.ruleset_id,
        review.review_id,
        &capsule.approval_set.records,
    )?;
    if !constant_time_equal(&expected, &capsule.approval_set.approval_set_tag) {
        return Err(Error::AuthenticationFailed);
    }
    Ok(())
}

pub(crate) fn authenticate_approval_set<'set>(
    capsule: &'set CapsuleV1,
    schedule: &KeySchedule<'_>,
    authority: &PreparedReviewAuthority,
    identities: &ReviewIdentityIndex,
) -> Result<AuthenticatedApprovalSet<'set>> {
    verify_approval_set_tag(capsule, schedule)?;
    let review = capsule.current_review.as_ref().ok_or(Error::InvalidState)?;
    require_fresh_approval_commitments(
        &review.edited_tree_commitment,
        &review.event_set_commitment,
        &capsule.original_tree_commitment,
        &authority.report.edited_tree_commitment,
        &authority.event_set_commitment,
        &authority.original_tree_commitment,
    )?;
    if review.review_id != identities.review_id()
        || review.automatic_event_count != authority.events.automatic()
        || review.approval_eligible_count != authority.events.approval_required()
        || review.unconditional_reject_count != authority.events.rejected()
        || capsule.review_profile != authority.report.profile
        || capsule.ruleset_id != authority.report.ruleset_id
    {
        return Err(Error::ApprovalStale);
    }

    let requirements = approval_requirements(authority, identities)?;
    if requirements.len()
        != usize::try_from(review.approval_eligible_count).map_err(|_| Error::BoundExceeded)?
        || capsule.approval_set.records.len() > requirements.len()
    {
        return Err(Error::CorruptState);
    }
    for record in &capsule.approval_set.records {
        let position = requirements
            .binary_search_by_key(&record.event_id, |requirement| requirement.event_id)
            .map_err(|_| Error::CorruptState)?;
        let requirement = requirements.get(position).ok_or(Error::CorruptState)?;
        if record.event_type != requirement.event_type
            || record.reason_code != requirement.reason
            || record.edited_tree_commitment != review.edited_tree_commitment
            || record.approved_in_generation == 0
            || record.approved_in_generation > capsule.generation
        {
            return Err(Error::CorruptState);
        }
    }
    Ok(AuthenticatedApprovalSet {
        set: &capsule.approval_set,
        eligible_count: review.approval_eligible_count,
    })
}

fn require_fresh_approval_commitments(
    review_edited: &[u8; 32],
    review_events: &[u8; 32],
    capsule_original: &[u8; 32],
    fresh_edited: &[u8; 32],
    fresh_events: &[u8; 32],
    fresh_original: &[u8; 32],
) -> Result<()> {
    if !constant_time_equal(review_edited, fresh_edited)
        || !constant_time_equal(review_events, fresh_events)
        || !constant_time_equal(capsule_original, fresh_original)
    {
        return Err(Error::ApprovalStale);
    }
    Ok(())
}

pub(crate) fn authenticate_complete_approval_set(
    capsule: &CapsuleV1,
    schedule: &KeySchedule<'_>,
    authority: &PreparedReviewAuthority,
    identities: &ReviewIdentityIndex,
) -> Result<CompleteApprovalEvidence> {
    authenticate_complete_approval_set_in_states(
        capsule,
        schedule,
        authority,
        identities,
        &[SessionState::ReadyToApply],
    )
}

pub(crate) fn authenticate_complete_apply_approval_set(
    capsule: &CapsuleV1,
    schedule: &KeySchedule<'_>,
    authority: &PreparedReviewAuthority,
    identities: &ReviewIdentityIndex,
) -> Result<CompleteApprovalEvidence> {
    authenticate_complete_approval_set_in_states(
        capsule,
        schedule,
        authority,
        identities,
        &[
            SessionState::ReadyToApply,
            SessionState::ApplyArmed,
            SessionState::ApplyIncomplete,
            SessionState::AppliedComplete,
        ],
    )
}

fn authenticate_complete_approval_set_in_states(
    capsule: &CapsuleV1,
    schedule: &KeySchedule<'_>,
    authority: &PreparedReviewAuthority,
    identities: &ReviewIdentityIndex,
    accepted_states: &[SessionState],
) -> Result<CompleteApprovalEvidence> {
    let authenticated = authenticate_approval_set(capsule, schedule, authority, identities)?;
    let review = capsule.current_review.as_ref().ok_or(Error::InvalidState)?;
    if !accepted_states.contains(&capsule.session_state)
        || review.unconditional_reject_count != 0
        || authority.events.rejected() != 0
        || authenticated.remaining_count()? != 0
        || authenticated.approved_count()? != review.approval_eligible_count
        || authenticated.approved_count()? != authority.events.approval_required()
    {
        return Err(Error::InvalidState);
    }
    Ok(CompleteApprovalEvidence { _seal: () })
}

pub(crate) fn insert_new_approval(
    schedule: &KeySchedule<'_>,
    capsule: &CapsuleV1,
    authenticated: &AuthenticatedApprovalSet<'_>,
    requirement: ApprovalRequirement,
    next_generation: u64,
) -> Result<(ApprovalSetV1, SessionState)> {
    let review = capsule.current_review.as_ref().ok_or(Error::InvalidState)?;
    if review.unconditional_reject_count != 0
        || next_generation
            != capsule
                .generation
                .checked_add(1)
                .ok_or(Error::InvalidState)?
    {
        return Err(Error::InvalidState);
    }
    let mut records = authenticated.set.records.clone();
    if records.len() >= MAX_APPROVAL_RECORDS {
        return Err(Error::BoundExceeded);
    }
    let position = records
        .binary_search_by_key(&requirement.event_id, |record| record.event_id)
        .unwrap_or_else(|position| position);
    if records
        .get(position)
        .is_some_and(|record| record.event_id == requirement.event_id)
    {
        return Err(Error::ApprovalConflict);
    }
    records.try_reserve(1).map_err(|_| Error::BoundExceeded)?;
    records.insert(
        position,
        ApprovalRecordV1 {
            event_id: requirement.event_id,
            event_type: requirement.event_type,
            reason_code: requirement.reason,
            edited_tree_commitment: review.edited_tree_commitment,
            approved_in_generation: next_generation,
        },
    );
    let record_count = u32::try_from(records.len()).map_err(|_| Error::BoundExceeded)?;
    let state = match record_count.cmp(&review.approval_eligible_count) {
        std::cmp::Ordering::Less => SessionState::ApprovedPartial,
        std::cmp::Ordering::Equal => SessionState::ReadyToApply,
        std::cmp::Ordering::Greater => return Err(Error::CorruptState),
    };
    let mut set = ApprovalSetV1 {
        review_id: Some(review.review_id),
        records,
        approval_set_tag: [0; 32],
    };
    set.approval_set_tag = approval_set_tag(
        schedule,
        capsule.review_profile,
        &capsule.ruleset_id,
        review.review_id,
        &set.records,
    )?;
    set.validate()?;
    Ok((set, state))
}

pub(crate) fn require_approval_operation_state(state: SessionState, duplicate: bool) -> Result<()> {
    match (state, duplicate) {
        (SessionState::Reviewed | SessionState::ApprovedPartial, _) => Ok(()),
        (SessionState::ReadyToApply, true) => Ok(()),
        (
            SessionState::ActiveUnreviewed
            | SessionState::ReviewedRejected
            | SessionState::ReadyToApply
            | SessionState::ApplyArmed
            | SessionState::ApplyIncomplete
            | SessionState::AppliedComplete,
            _,
        ) => Err(Error::InvalidState),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::roundtrip::crypto::{SessionId, SessionMasterSecret};

    fn schedule() -> (SessionMasterSecret, SessionId) {
        (
            SessionMasterSecret::from_bytes([0x11; 32]),
            SessionId::from_bytes([0x21; 16]),
        )
    }

    fn record(event: u8, reason: ApprovalReason, generation: u64) -> ApprovalRecordV1 {
        let event_type = match reason {
            ApprovalReason::IntentionalTokenRemoval => ApprovalEventType::Deleted,
            ApprovalReason::IntentionalFileDelete => ApprovalEventType::FileDeleted,
            ApprovalReason::StrictTokenFileEditReviewed => {
                ApprovalEventType::StrictTokenFileModified
            }
        };
        ApprovalRecordV1 {
            event_id: [event; 16],
            event_type,
            reason_code: reason,
            edited_tree_commitment: [0x31; 32],
            approved_in_generation: generation,
        }
    }

    #[test]
    fn empty_tag_preserves_the_approval_contract() {
        let (master, session_id) = schedule();
        let schedule = KeySchedule::new(&master, session_id);
        let set = empty_review_approval_set(
            &schedule,
            [0x41; 16],
            ReviewProfile::StandardV2,
            crate::roundtrip::ruleset::ruleset_id(),
        )
        .expect("empty approval set");
        assert_eq!(set.review_id, Some([0x41; 16]));
        assert!(set.records.is_empty());
        assert_eq!(
            set.approval_set_tag,
            [
                26, 114, 26, 28, 226, 230, 246, 34, 123, 102, 116, 209, 53, 66, 98, 6, 139, 127,
                151, 209, 28, 193, 41, 84, 57, 221, 176, 170, 248, 81, 77, 146,
            ]
        );
    }

    #[test]
    fn fresh_approval_authority_mismatches_remain_stale() {
        let edited = [0x31; 32];
        let events = [0x32; 32];
        let original = [0x33; 32];
        assert!(require_fresh_approval_commitments(
            &edited, &events, &original, &edited, &events, &original,
        )
        .is_ok());

        for index in 0..3 {
            let mut fresh_edited = edited;
            let mut fresh_events = events;
            let mut fresh_original = original;
            match index {
                0 => fresh_edited[31] ^= 1,
                1 => fresh_events[17] ^= 1,
                2 => fresh_original[0] ^= 1,
                _ => unreachable!(),
            }
            assert_eq!(
                require_fresh_approval_commitments(
                    &edited,
                    &events,
                    &original,
                    &fresh_edited,
                    &fresh_events,
                    &fresh_original,
                ),
                Err(Error::ApprovalStale)
            );
        }
    }

    #[test]
    fn tag_binds_order_and_every_record_and_review_field() {
        let (master, session_id) = schedule();
        let schedule = KeySchedule::new(&master, session_id);
        let records = vec![
            record(1, ApprovalReason::IntentionalTokenRemoval, 3),
            record(2, ApprovalReason::IntentionalFileDelete, 4),
        ];
        let one = approval_set_tag(
            &schedule,
            ReviewProfile::StandardV2,
            crate::roundtrip::ruleset::ruleset_id(),
            [0x41; 16],
            &records[..1],
        )
        .expect("one-record tag");
        let baseline = approval_set_tag(
            &schedule,
            ReviewProfile::StandardV2,
            crate::roundtrip::ruleset::ruleset_id(),
            [0x41; 16],
            &records,
        )
        .expect("baseline tag");
        assert_ne!(one, baseline);

        let mut mutations = Vec::new();
        let mut reordered = records.clone();
        reordered.swap(0, 1);
        mutations.push(reordered);
        let mut event = records.clone();
        event[0].event_id[0] ^= 1;
        mutations.push(event);
        let mut reason = records.clone();
        reason[0].reason_code = ApprovalReason::IntentionalFileDelete;
        mutations.push(reason);
        let mut commitment = records.clone();
        commitment[0].edited_tree_commitment[0] ^= 1;
        mutations.push(commitment);
        let mut generation = records.clone();
        generation[0].approved_in_generation += 1;
        mutations.push(generation);
        for mutation in mutations {
            assert_ne!(
                baseline,
                approval_set_tag(
                    &schedule,
                    ReviewProfile::StandardV2,
                    crate::roundtrip::ruleset::ruleset_id(),
                    [0x41; 16],
                    &mutation,
                )
                .expect("mutated tag")
            );
        }

        for changed in [
            approval_set_tag(
                &schedule,
                ReviewProfile::StrictTokenFilesV2,
                crate::roundtrip::ruleset::ruleset_id(),
                [0x41; 16],
                &records,
            )
            .expect("profile mutation"),
            approval_set_tag_with_contract(
                &schedule,
                ReviewProfile::StandardV2,
                "changed-engine",
                POLICY_ID,
                crate::roundtrip::ruleset::ruleset_id(),
                TOKEN_SUITE_ID,
                APPROVAL_SET_SCHEMA_VERSION,
                [0x41; 16],
                &records,
            )
            .expect("engine mutation"),
            approval_set_tag_with_contract(
                &schedule,
                ReviewProfile::StandardV2,
                ENGINE_VERSION,
                "changed-policy",
                crate::roundtrip::ruleset::ruleset_id(),
                TOKEN_SUITE_ID,
                APPROVAL_SET_SCHEMA_VERSION,
                [0x41; 16],
                &records,
            )
            .expect("policy mutation"),
            approval_set_tag_with_contract(
                &schedule,
                ReviewProfile::StandardV2,
                ENGINE_VERSION,
                POLICY_ID,
                "sha256:changed",
                TOKEN_SUITE_ID,
                APPROVAL_SET_SCHEMA_VERSION,
                [0x41; 16],
                &records,
            )
            .expect("ruleset mutation"),
            approval_set_tag_with_contract(
                &schedule,
                ReviewProfile::StandardV2,
                ENGINE_VERSION,
                POLICY_ID,
                crate::roundtrip::ruleset::ruleset_id(),
                TOKEN_SUITE_ID + 1,
                APPROVAL_SET_SCHEMA_VERSION,
                [0x41; 16],
                &records,
            )
            .expect("suite mutation"),
            approval_set_tag_with_contract(
                &schedule,
                ReviewProfile::StandardV2,
                ENGINE_VERSION,
                POLICY_ID,
                crate::roundtrip::ruleset::ruleset_id(),
                TOKEN_SUITE_ID,
                APPROVAL_SET_SCHEMA_VERSION + 1,
                [0x41; 16],
                &records,
            )
            .expect("schema mutation"),
            approval_set_tag(
                &schedule,
                ReviewProfile::StandardV2,
                crate::roundtrip::ruleset::ruleset_id(),
                [0x42; 16],
                &records,
            )
            .expect("review mutation"),
        ] {
            assert_ne!(baseline, changed);
        }
        let other = KeySchedule::new(&master, SessionId::from_bytes([0x22; 16]));
        assert_ne!(
            baseline,
            approval_set_tag(
                &other,
                ReviewProfile::StandardV2,
                crate::roundtrip::ruleset::ruleset_id(),
                [0x41; 16],
                &records,
            )
            .expect("session mutation")
        );
    }

    #[test]
    fn state_gate_allows_only_new_reviewed_or_partial_and_ready_duplicate() {
        for state in [SessionState::Reviewed, SessionState::ApprovedPartial] {
            assert!(require_approval_operation_state(state, false).is_ok());
            assert!(require_approval_operation_state(state, true).is_ok());
        }
        assert_eq!(
            require_approval_operation_state(SessionState::ReadyToApply, false),
            Err(Error::InvalidState)
        );
        assert!(require_approval_operation_state(SessionState::ReadyToApply, true).is_ok());
        for state in [
            SessionState::ActiveUnreviewed,
            SessionState::ReviewedRejected,
            SessionState::ApplyArmed,
            SessionState::ApplyIncomplete,
            SessionState::AppliedComplete,
        ] {
            assert_eq!(
                require_approval_operation_state(state, false),
                Err(Error::InvalidState)
            );
            assert_eq!(
                require_approval_operation_state(state, true),
                Err(Error::InvalidState)
            );
        }
    }
}
