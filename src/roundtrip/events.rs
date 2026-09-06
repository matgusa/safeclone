//! Transient canonical classification event authority.
//!
//! These classification tags are transient. They are separate from the
//! ChangedManifest registry and are never serialized to disk.

use std::cmp::Ordering;

use super::baseline::StreamEncoder;
use super::crypto::{leftmost_16, KeyPurpose, KeySchedule};
use super::token::{ReviewProfile, TokenCategory, ENGINE_VERSION, POLICY_ID, TOKEN_SUITE_ID};
use super::{Error, Result};

pub(crate) const CANONICAL_EVENT_SET_VERSION: u8 = 1;
pub(crate) const MAX_CANONICAL_EVENTS: usize = 300_000;
pub(crate) const MAX_APPROVAL_ELIGIBLE_EVENTS: usize = 32_768;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum EventDecision {
    Automatic = 1,
    ApprovalRequired = 2,
    Reject = 3,
    Derived = 4,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum EventClass {
    Token = 1,
    File = 2,
    Directory = 3,
    Structural = 4,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub(crate) enum EventKind {
    PreservedSameAnchor = 1,
    TokenDeleted = 2,
    ProtectedContextChanged = 3,
    ProtectedCoreChanged = 4,
    AnchorAmbiguous = 5,
    MovedToOtherFile = 6,
    PathMoved = 7,
    TokenDuplicated = 8,
    TokenModified = 9,
    TokenUnknown = 10,
    CategoryMismatch = 11,
    TokenOrderChanged = 12,
    FileModified = 32,
    FileDeleted = 33,
    FileRenamed = 34,
    FileMoved = 35,
    NewTextFile = 36,
    DirectoryAdded = 48,
    DirectoryDeleted = 49,
    DirectoryRenamed = 50,
    DirectoryMoved = 51,
    StrictTokenFileModified = 52,
    NewUntokenizedSensitiveFinding = 64,
    UnsupportedAddition = 65,
    LinkLikeAddition = 66,
    HardLink = 67,
    AlternateDataStream = 68,
    ProtectedNamespace = 69,
    OmittedPathCollision = 70,
    InvalidUtf8 = 71,
}

impl EventKind {
    #[cfg(test)]
    pub(crate) const ALL: [Self; 30] = [
        Self::PreservedSameAnchor,
        Self::TokenDeleted,
        Self::ProtectedContextChanged,
        Self::ProtectedCoreChanged,
        Self::AnchorAmbiguous,
        Self::MovedToOtherFile,
        Self::PathMoved,
        Self::TokenDuplicated,
        Self::TokenModified,
        Self::TokenUnknown,
        Self::CategoryMismatch,
        Self::TokenOrderChanged,
        Self::FileModified,
        Self::FileDeleted,
        Self::FileRenamed,
        Self::FileMoved,
        Self::NewTextFile,
        Self::DirectoryAdded,
        Self::DirectoryDeleted,
        Self::DirectoryRenamed,
        Self::DirectoryMoved,
        Self::StrictTokenFileModified,
        Self::NewUntokenizedSensitiveFinding,
        Self::UnsupportedAddition,
        Self::LinkLikeAddition,
        Self::HardLink,
        Self::AlternateDataStream,
        Self::ProtectedNamespace,
        Self::OmittedPathCollision,
        Self::InvalidUtf8,
    ];
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub(crate) enum StructuralReason {
    None = 0,
    Exact = 1,
    MalformedToken = 2,
    ForeignSession = 3,
    UnknownOid = 4,
    InvalidAuthentication = 5,
    NoncanonicalToken = 6,
    GlobalCount = 7,
    FileCorrespondence = 8,
    ProtectedCore = 9,
    ProtectedContext = 10,
    EditedEnvelopeNonunique = 11,
    FileLocalOrder = 12,
    ExactDeletionProjection = 13,
    DeletionProjectionMismatch = 14,
    PathProjectionMismatch = 15,
    NewSensitiveFinding = 16,
    UnsupportedEntry = 17,
    HardLinkShape = 18,
    NamedStream = 19,
    ProtectedName = 20,
    OriginalOnlyCollision = 21,
    StrictProfile = 22,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum EventGroup {
    BaselineToken = 1,
    IndependentReserved = 2,
    File = 3,
    Directory = 4,
    Global = 5,
}

/// Paths are transient canonical safe-path inputs. This type intentionally has
/// no ordinary `Debug` implementation.
pub(crate) struct CanonicalEvent {
    pub(crate) group: EventGroup,
    pub(crate) class: EventClass,
    pub(crate) kind: EventKind,
    pub(crate) decision: EventDecision,
    pub(crate) baseline_oid: Option<[u8; 16]>,
    pub(crate) expected_category: Option<TokenCategory>,
    pub(crate) observed_category: Option<TokenCategory>,
    pub(crate) before_entry: Option<[u8; 32]>,
    pub(crate) after_entry: Option<[u8; 32]>,
    pub(crate) before_anchor: Option<[u8; 32]>,
    pub(crate) after_anchor: Option<[u8; 32]>,
    pub(crate) observed_count: u32,
    pub(crate) reason: StructuralReason,
    pub(crate) before_path: Option<Vec<u8>>,
    pub(crate) after_path: Option<Vec<u8>>,
    pub(crate) position: u64,
}

impl CanonicalEvent {
    pub(crate) fn token(
        oid: [u8; 16],
        expected: TokenCategory,
        observed: Option<TokenCategory>,
        kind: EventKind,
        decision: EventDecision,
        reason: StructuralReason,
    ) -> Self {
        Self {
            group: EventGroup::BaselineToken,
            class: EventClass::Token,
            kind,
            decision,
            baseline_oid: Some(oid),
            expected_category: Some(expected),
            observed_category: observed,
            before_entry: None,
            after_entry: None,
            before_anchor: None,
            after_anchor: None,
            observed_count: 0,
            reason,
            before_path: None,
            after_path: None,
            position: 0,
        }
    }

    fn compare(&self, other: &Self) -> Ordering {
        (self.group as u8)
            .cmp(&(other.group as u8))
            .then_with(|| self.baseline_oid.cmp(&other.baseline_oid))
            .then_with(|| self.after_path.cmp(&other.after_path))
            .then_with(|| self.before_path.cmp(&other.before_path))
            .then_with(|| self.position.cmp(&other.position))
            .then_with(|| (self.kind as u16).cmp(&(other.kind as u16)))
            .then_with(|| (self.reason as u16).cmp(&(other.reason as u16)))
            .then_with(|| (self.class as u8).cmp(&(other.class as u8)))
            .then_with(|| (self.decision as u8).cmp(&(other.decision as u8)))
            .then_with(|| self.expected_category.cmp(&other.expected_category))
            .then_with(|| self.observed_category.cmp(&other.observed_category))
            .then_with(|| self.before_entry.cmp(&other.before_entry))
            .then_with(|| self.after_entry.cmp(&other.after_entry))
            .then_with(|| self.before_anchor.cmp(&other.before_anchor))
            .then_with(|| self.after_anchor.cmp(&other.after_anchor))
            .then_with(|| self.observed_count.cmp(&other.observed_count))
    }

    fn encode(&self, output: &mut StreamEncoder) -> Result<()> {
        output.u8(self.group as u8);
        output.u8(self.class as u8);
        output.u16(self.kind as u16);
        output.u8(self.decision as u8);
        encode_optional_fixed(output, self.baseline_oid.as_ref())?;
        encode_optional_category(output, self.expected_category);
        encode_optional_category(output, self.observed_category);
        encode_optional_fixed(output, self.before_entry.as_ref())?;
        encode_optional_fixed(output, self.after_entry.as_ref())?;
        encode_optional_fixed(output, self.before_anchor.as_ref())?;
        encode_optional_fixed(output, self.after_anchor.as_ref())?;
        output.u32(self.observed_count);
        output.u16(self.reason as u16);
        encode_optional_bytes(output, self.before_path.as_deref())?;
        encode_optional_bytes(output, self.after_path.as_deref())?;
        output.u64(self.position);
        Ok(())
    }

    /// Derives the review/approval opaque event ID from the exact classification record encoder.
    /// Manifest fields and reporting regions never enter this input.
    pub(crate) fn event_id(
        &self,
        schedule: &KeySchedule<'_>,
        review_id: &[u8; 16],
        owning_entry_id: &[u8; 16],
    ) -> Result<[u8; 16]> {
        let mut output =
            StreamEncoder::new(schedule, KeyPurpose::EventId, b"safeclone/rt1/event-id")?;
        output.bytes(review_id)?;
        output.bytes(owning_entry_id)?;
        output.u8(CANONICAL_EVENT_SET_VERSION);
        self.encode(&mut output)?;
        Ok(leftmost_16(&output.finish()))
    }
}

pub(crate) struct CanonicalEventSet {
    events: Vec<CanonicalEvent>,
    automatic: u32,
    approval_required: u32,
    rejected: u32,
    derived: u32,
}

impl CanonicalEventSet {
    pub(crate) fn finalize(mut events: Vec<CanonicalEvent>) -> Result<Self> {
        if events.len() > MAX_CANONICAL_EVENTS {
            return Err(Error::BoundExceeded);
        }
        events.sort_unstable_by(CanonicalEvent::compare);
        let mut automatic = 0u32;
        let mut approval_required = 0u32;
        let mut rejected = 0u32;
        let mut derived = 0u32;
        for event in &events {
            let counter = match event.decision {
                EventDecision::Automatic => &mut automatic,
                EventDecision::ApprovalRequired => &mut approval_required,
                EventDecision::Reject => &mut rejected,
                EventDecision::Derived => &mut derived,
            };
            *counter = counter.checked_add(1).ok_or(Error::BoundExceeded)?;
        }
        if usize::try_from(approval_required).map_err(|_| Error::BoundExceeded)?
            > MAX_APPROVAL_ELIGIBLE_EVENTS
        {
            return Err(Error::BoundExceeded);
        }
        Ok(Self {
            events,
            automatic,
            approval_required,
            rejected,
            derived,
        })
    }

    pub(crate) fn events(&self) -> &[CanonicalEvent] {
        &self.events
    }

    pub(crate) const fn automatic(&self) -> u32 {
        self.automatic
    }

    pub(crate) const fn approval_required(&self) -> u32 {
        self.approval_required
    }

    pub(crate) const fn rejected(&self) -> u32 {
        self.rejected
    }

    pub(crate) const fn derived(&self) -> u32 {
        self.derived
    }

    pub(crate) fn commitment(&self, schedule: &KeySchedule<'_>) -> Result<[u8; 32]> {
        let mut output = StreamEncoder::new(
            schedule,
            KeyPurpose::TreeCommit,
            b"safeclone/rt3/canonical-event-authority-v1",
        )?;
        output.u8(CANONICAL_EVENT_SET_VERSION);
        output.u32(u32::try_from(self.events.len()).map_err(|_| Error::BoundExceeded)?);
        for event in &self.events {
            event.encode(&mut output)?;
        }
        Ok(output.finish())
    }

    /// Review identity binds the complete, exact classification authority rather than
    /// its later changed-only/report-diff projection.
    pub(crate) fn review_id(
        &self,
        schedule: &KeySchedule<'_>,
        original_tree_commitment: &[u8; 32],
        edited_tree_commitment: &[u8; 32],
        profile: ReviewProfile,
        ruleset_id: &str,
    ) -> Result<[u8; 16]> {
        if !profile.is_current() || ruleset_id.is_empty() {
            return Err(Error::InvalidState);
        }
        let mut output =
            StreamEncoder::new(schedule, KeyPurpose::EventId, b"safeclone/rt1/review-id")?;
        output.bytes(schedule.session_id().as_bytes())?;
        output.bytes(original_tree_commitment)?;
        output.bytes(edited_tree_commitment)?;
        output.u8(profile as u8);
        output.bytes(ENGINE_VERSION.as_bytes())?;
        output.bytes(POLICY_ID.as_bytes())?;
        output.bytes(ruleset_id.as_bytes())?;
        output.u16(TOKEN_SUITE_ID);
        output.u8(CANONICAL_EVENT_SET_VERSION);
        output.u32(u32::try_from(self.events.len()).map_err(|_| Error::BoundExceeded)?);
        for event in &self.events {
            event.encode(&mut output)?;
        }
        Ok(leftmost_16(&output.finish()))
    }
}

fn encode_optional_category(output: &mut StreamEncoder, value: Option<TokenCategory>) {
    match value {
        Some(value) => {
            output.u8(1);
            output.u8(value as u8);
        }
        None => output.u8(0),
    }
}

fn encode_optional_fixed<const N: usize>(
    output: &mut StreamEncoder,
    value: Option<&[u8; N]>,
) -> Result<()> {
    match value {
        Some(value) => {
            output.u8(1);
            output.bytes(value)
        }
        None => {
            output.u8(0);
            Ok(())
        }
    }
}

fn encode_optional_bytes(output: &mut StreamEncoder, value: Option<&[u8]>) -> Result<()> {
    match value {
        Some(value) => {
            output.u8(1);
            output.bytes(value)
        }
        None => {
            output.u8(0);
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::roundtrip::crypto::{SessionId, SessionMasterSecret};

    fn event(oid: u8, decision: EventDecision, path: &[u8]) -> CanonicalEvent {
        let mut value = CanonicalEvent::token(
            [oid; 16],
            TokenCategory::Secret,
            Some(TokenCategory::Secret),
            EventKind::PreservedSameAnchor,
            decision,
            StructuralReason::Exact,
        );
        value.after_path = Some(path.to_vec());
        value
    }

    #[test]
    fn canonical_event_authority_is_order_independent_and_counted() {
        let master = SessionMasterSecret::from_bytes([0x31; 32]);
        let schedule = KeySchedule::new(&master, SessionId::from_bytes([0x22; 16]));
        let first = CanonicalEventSet::finalize(vec![
            event(2, EventDecision::ApprovalRequired, b"b"),
            event(1, EventDecision::Automatic, b"a"),
            event(3, EventDecision::Reject, b"c"),
            event(4, EventDecision::Derived, b"d"),
        ])
        .expect("finalize first event order");
        let second = CanonicalEventSet::finalize(vec![
            event(4, EventDecision::Derived, b"d"),
            event(3, EventDecision::Reject, b"c"),
            event(1, EventDecision::Automatic, b"a"),
            event(2, EventDecision::ApprovalRequired, b"b"),
        ])
        .expect("finalize second event order");
        assert_eq!(first.commitment(&schedule), second.commitment(&schedule));
        assert_eq!(first.automatic(), 1);
        assert_eq!(first.approval_required(), 1);
        assert_eq!(first.rejected(), 1);
        assert_eq!(first.derived(), 1);
        assert_eq!(first.events()[0].baseline_oid, Some([1; 16]));

        let mut low_anchor = event(9, EventDecision::Automatic, b"same");
        low_anchor.before_anchor = Some([0x10; 32]);
        low_anchor.observed_count = 1;
        let mut high_anchor = event(9, EventDecision::Automatic, b"same");
        high_anchor.before_anchor = Some([0x20; 32]);
        high_anchor.observed_count = 2;
        let tied_first = CanonicalEventSet::finalize(vec![low_anchor, high_anchor])
            .expect("finalize encoded-field tie order");
        let mut low_anchor = event(9, EventDecision::Automatic, b"same");
        low_anchor.before_anchor = Some([0x10; 32]);
        low_anchor.observed_count = 1;
        let mut high_anchor = event(9, EventDecision::Automatic, b"same");
        high_anchor.before_anchor = Some([0x20; 32]);
        high_anchor.observed_count = 2;
        let tied_second = CanonicalEventSet::finalize(vec![high_anchor, low_anchor])
            .expect("finalize reverse encoded-field tie order");
        assert_eq!(
            tied_first.commitment(&schedule),
            tied_second.commitment(&schedule)
        );
    }

    #[test]
    fn canonical_and_approval_event_bounds_fail_without_truncation() {
        let mut approvals = Vec::new();
        approvals
            .try_reserve_exact(MAX_APPROVAL_ELIGIBLE_EVENTS + 1)
            .expect("bounded approval fixture");
        for index in 0..=MAX_APPROVAL_ELIGIBLE_EVENTS {
            approvals.push(event(
                u8::try_from(index % 251).expect("small remainder"),
                EventDecision::ApprovalRequired,
                &u64::try_from(index).expect("bounded index").to_be_bytes(),
            ));
        }
        assert!(matches!(
            CanonicalEventSet::finalize(approvals),
            Err(Error::BoundExceeded)
        ));

        let mut complete = Vec::new();
        complete
            .try_reserve_exact(MAX_CANONICAL_EVENTS + 1)
            .expect("bounded complete fixture");
        for index in 0..=MAX_CANONICAL_EVENTS {
            complete.push(event(
                u8::try_from(index % 251).expect("small remainder"),
                EventDecision::Automatic,
                &u64::try_from(index).expect("bounded index").to_be_bytes(),
            ));
        }
        assert!(matches!(
            CanonicalEventSet::finalize(complete),
            Err(Error::BoundExceeded)
        ));
    }

    #[test]
    fn review_and_event_ids_bind_exact_authority_but_never_report_diff() {
        let master = SessionMasterSecret::from_bytes([0x41; 32]);
        let schedule = KeySchedule::new(&master, SessionId::from_bytes([0x42; 16]));
        let replay = KeySchedule::new(&master, SessionId::from_bytes([0x42; 16]));
        let other_master = SessionMasterSecret::from_bytes([0x43; 32]);
        let other_session = KeySchedule::new(&other_master, SessionId::from_bytes([0x44; 16]));
        let original = [0x51; 32];
        let edited = [0x52; 32];
        let ruleset = crate::roundtrip::ruleset::ruleset_id();

        let set =
            CanonicalEventSet::finalize(vec![event(1, EventDecision::Automatic, b"safe/path.txt")])
                .expect("canonical event set");
        let review = set
            .review_id(
                &schedule,
                &original,
                &edited,
                ReviewProfile::StandardV2,
                ruleset,
            )
            .expect("review ID");
        assert_eq!(
            review,
            set.review_id(
                &replay,
                &original,
                &edited,
                ReviewProfile::StandardV2,
                ruleset,
            )
            .expect("exact review replay")
        );
        assert_ne!(
            review,
            set.review_id(
                &other_session,
                &original,
                &edited,
                ReviewProfile::StandardV2,
                ruleset,
            )
            .expect("cross-session review")
        );
        assert_ne!(
            review,
            set.review_id(
                &schedule,
                &[0x61; 32],
                &edited,
                ReviewProfile::StandardV2,
                ruleset,
            )
            .expect("changed Original review")
        );
        assert_ne!(
            review,
            set.review_id(
                &schedule,
                &original,
                &[0x62; 32],
                ReviewProfile::StandardV2,
                ruleset,
            )
            .expect("changed edited review")
        );
        assert_ne!(
            review,
            set.review_id(
                &schedule,
                &original,
                &edited,
                ReviewProfile::StrictTokenFilesV2,
                ruleset,
            )
            .expect("changed profile review")
        );

        let owner = [0x71; 16];
        let event_id = set.events()[0]
            .event_id(&schedule, &review, &owner)
            .expect("event ID");
        assert_eq!(
            event_id,
            set.events()[0]
                .event_id(&replay, &review, &owner)
                .expect("exact event replay")
        );
        assert_ne!(
            event_id,
            set.events()[0]
                .event_id(&schedule, &review, &[0x72; 16])
                .expect("changed owner event")
        );
        assert_ne!(
            event_id,
            set.events()[0]
                .event_id(&other_session, &review, &owner)
                .expect("cross-session event")
        );

        let mut moved_event = event(1, EventDecision::Automatic, b"safe/path.txt");
        moved_event.position = 9;
        assert_ne!(
            event_id,
            moved_event
                .event_id(&schedule, &review, &owner)
                .expect("moved event")
        );
        // The ID functions accept only classification authority inputs. There is no
        // manifest byte, DiffOp, or ContentChangeRegion parameter to vary.
    }
}
