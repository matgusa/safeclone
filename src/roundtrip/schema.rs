//! Deterministic, schema-specific CBOR for session private authority.

use std::convert::Infallible;
use std::fmt;

use cbor4ii::core::dec::{Decode, Read, Reference};
use cbor4ii::core::enc::{Encode, Write};
use cbor4ii::core::types;

use super::crypto::SessionId;
use super::token::{valid_ruleset_id, ReviewProfile, ENGINE_VERSION, POLICY_ID, TOKEN_SUITE_ID};
use super::{Error, Result};

pub const CAPSULE_SCHEMA_VERSION: u16 = 1;
pub const MANIFEST_SCHEMA_VERSION: u16 = 1;
pub const MAX_APPROVAL_RECORDS: usize = 32_768;
pub const MAX_SCHEMA_CBOR_BYTES: usize = 8 * 1024 * 1024;
const MAX_PRIVATE_CBOR_BYTES: usize = 128 * 1024 * 1024;
const MAX_TEXT_BYTES: usize = 128;

#[derive(Debug)]
struct EncodeBoundError;

impl fmt::Display for EncodeBoundError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("bounded CBOR write failed")
    }
}

impl std::error::Error for EncodeBoundError {}

struct BoundedWriter {
    bytes: Vec<u8>,
    limit: usize,
}

impl BoundedWriter {
    fn new(limit: usize) -> Result<Self> {
        if limit > MAX_PRIVATE_CBOR_BYTES {
            return Err(Error::BoundExceeded);
        }
        Ok(Self {
            bytes: Vec::new(),
            limit,
        })
    }

    fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

impl Write for BoundedWriter {
    type Error = EncodeBoundError;

    fn push(&mut self, input: &[u8]) -> std::result::Result<(), Self::Error> {
        let next = self
            .bytes
            .len()
            .checked_add(input.len())
            .ok_or(EncodeBoundError)?;
        if next > self.limit {
            return Err(EncodeBoundError);
        }
        self.bytes
            .try_reserve(input.len())
            .map_err(|_| EncodeBoundError)?;
        self.bytes.extend_from_slice(input);
        Ok(())
    }
}

pub(crate) struct CborEncoder {
    writer: BoundedWriter,
}

impl CborEncoder {
    pub(crate) fn new(limit: usize) -> Result<Self> {
        Ok(Self {
            writer: BoundedWriter::new(limit)?,
        })
    }

    pub(crate) fn map(&mut self, length: usize) -> Result<()> {
        types::Map::bounded(length, &mut self.writer).map_err(|_| Error::BoundExceeded)
    }

    pub(crate) fn array(&mut self, length: usize) -> Result<()> {
        types::Array::bounded(length, &mut self.writer).map_err(|_| Error::BoundExceeded)
    }

    pub(crate) fn value<T: Encode>(&mut self, value: &T) -> Result<()> {
        value
            .encode(&mut self.writer)
            .map_err(|_| Error::BoundExceeded)
    }

    pub(crate) fn bytes(&mut self, value: &[u8]) -> Result<()> {
        self.value(&types::Bytes(value))
    }

    pub(crate) fn null(&mut self) -> Result<()> {
        self.value(&types::Null)
    }

    pub(crate) fn finish(self) -> Vec<u8> {
        self.writer.finish()
    }
}

pub(crate) struct CborReader<'a> {
    input: &'a [u8],
    position: usize,
    depth: usize,
}

impl<'a> CborReader<'a> {
    pub(crate) fn new(input: &'a [u8]) -> Result<Self> {
        Self::new_bounded(input, MAX_SCHEMA_CBOR_BYTES)
    }

    pub(crate) fn new_bounded(input: &'a [u8], maximum: usize) -> Result<Self> {
        if input.len() > maximum {
            return Err(Error::BoundExceeded);
        }
        Ok(Self {
            input,
            position: 0,
            depth: 64,
        })
    }

    pub(crate) fn decode<T: Decode<'a>>(&mut self) -> Result<T> {
        T::decode(self).map_err(|_| Error::InvalidSchema)
    }

    pub(crate) fn map_exact(&mut self, expected: usize) -> Result<()> {
        match types::Map::len(self).map_err(|_| Error::InvalidSchema)? {
            Some(actual) if actual == expected => Ok(()),
            _ => Err(Error::InvalidSchema),
        }
    }

    pub(crate) fn array_bounded(&mut self, maximum: usize) -> Result<usize> {
        match types::Array::len(self).map_err(|_| Error::InvalidSchema)? {
            Some(actual) if actual <= maximum => Ok(actual),
            _ => Err(Error::InvalidSchema),
        }
    }

    pub(crate) fn key(&mut self, expected: u8) -> Result<()> {
        let actual: u64 = self.decode()?;
        if actual == u64::from(expected) {
            Ok(())
        } else {
            Err(Error::InvalidSchema)
        }
    }

    pub(crate) fn fixed<const N: usize>(&mut self) -> Result<[u8; N]> {
        let types::Bytes(value): types::Bytes<&[u8]> = self.decode()?;
        value.try_into().map_err(|_| Error::InvalidSchema)
    }

    pub(crate) fn text(&mut self) -> Result<String> {
        self.text_bounded(MAX_TEXT_BYTES)
    }

    pub(crate) fn text_bounded(&mut self, maximum: usize) -> Result<String> {
        let value: &str = self.decode()?;
        if value.len() > maximum {
            return Err(Error::BoundExceeded);
        }
        Ok(value.to_owned())
    }

    pub(crate) fn is_null(&self) -> bool {
        self.input.get(self.position) == Some(&0xf6)
    }

    pub(crate) fn null(&mut self) -> Result<()> {
        if self.is_null() {
            self.position += 1;
            Ok(())
        } else {
            Err(Error::InvalidSchema)
        }
    }

    pub(crate) fn finished(&self) -> bool {
        self.position == self.input.len()
    }
}

impl<'de> Read<'de> for CborReader<'de> {
    type Error = Infallible;

    fn fill<'short>(
        &'short mut self,
        want: usize,
    ) -> std::result::Result<Reference<'de, 'short>, Self::Error> {
        let remaining = &self.input[self.position..];
        Ok(Reference::Long(&remaining[..remaining.len().min(want)]))
    }

    fn advance(&mut self, count: usize) {
        self.position = self.position.saturating_add(count).min(self.input.len());
    }

    fn step_in(&mut self) -> bool {
        if let Some(next) = self.depth.checked_sub(1) {
            self.depth = next;
            true
        } else {
            false
        }
    }

    fn step_out(&mut self) {
        self.depth = self.depth.saturating_add(1);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum SessionState {
    ActiveUnreviewed = 1,
    ReviewedRejected = 2,
    Reviewed = 3,
    ApprovedPartial = 4,
    ReadyToApply = 5,
    ApplyArmed = 6,
    ApplyIncomplete = 7,
    AppliedComplete = 8,
}

impl SessionState {
    fn parse(value: u64) -> Option<Self> {
        match value {
            1 => Some(Self::ActiveUnreviewed),
            2 => Some(Self::ReviewedRejected),
            3 => Some(Self::Reviewed),
            4 => Some(Self::ApprovedPartial),
            5 => Some(Self::ReadyToApply),
            6 => Some(Self::ApplyArmed),
            7 => Some(Self::ApplyIncomplete),
            8 => Some(Self::AppliedComplete),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ManifestPhase {
    Review = 1,
    ApplyResult = 2,
}

impl ManifestPhase {
    fn parse(value: u64) -> Option<Self> {
        match value {
            1 => Some(Self::Review),
            2 => Some(Self::ApplyResult),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ApprovalEventType {
    Deleted = 1,
    FileDeleted = 2,
    StrictTokenFileModified = 3,
}

impl ApprovalEventType {
    fn parse(value: u64) -> Option<Self> {
        match value {
            1 => Some(Self::Deleted),
            2 => Some(Self::FileDeleted),
            3 => Some(Self::StrictTokenFileModified),
            _ => None,
        }
    }

    pub(crate) const fn required_reason(self) -> ApprovalReason {
        match self {
            Self::Deleted => ApprovalReason::IntentionalTokenRemoval,
            Self::FileDeleted => ApprovalReason::IntentionalFileDelete,
            Self::StrictTokenFileModified => ApprovalReason::StrictTokenFileEditReviewed,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ApprovalReason {
    IntentionalTokenRemoval = 1,
    IntentionalFileDelete = 2,
    StrictTokenFileEditReviewed = 3,
}

impl ApprovalReason {
    fn parse(value: u64) -> Option<Self> {
        match value {
            1 => Some(Self::IntentionalTokenRemoval),
            2 => Some(Self::IntentionalFileDelete),
            3 => Some(Self::StrictTokenFileEditReviewed),
            _ => None,
        }
    }

    pub(crate) const fn valid_for(self, event: ApprovalEventType) -> bool {
        matches!(
            (self, event),
            (Self::IntentionalTokenRemoval, ApprovalEventType::Deleted)
                | (Self::IntentionalFileDelete, ApprovalEventType::FileDeleted)
                | (
                    Self::StrictTokenFileEditReviewed,
                    ApprovalEventType::StrictTokenFileModified
                )
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ApplyState {
    Armed = 1,
    Incomplete = 2,
    Complete = 3,
}

impl ApplyState {
    fn parse(value: u64) -> Option<Self> {
        match value {
            1 => Some(Self::Armed),
            2 => Some(Self::Incomplete),
            3 => Some(Self::Complete),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ManualReasonCode {
    PrivateOrphansPresent = 1,
    CandidateCollision = 2,
    CandidateIncomplete = 3,
    PostcheckFailed = 4,
    StateCommitUncertain = 5,
}

impl ManualReasonCode {
    fn parse(value: u64) -> Option<Self> {
        match value {
            1 => Some(Self::PrivateOrphansPresent),
            2 => Some(Self::CandidateCollision),
            3 => Some(Self::CandidateIncomplete),
            4 => Some(Self::PostcheckFailed),
            5 => Some(Self::StateCommitUncertain),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum SensitiveCandidateState {
    None = 0,
    ArmedUnknown = 1,
    Incomplete = 2,
    Complete = 3,
}

impl SensitiveCandidateState {
    fn parse(value: u64) -> Option<Self> {
        match value {
            0 => Some(Self::None),
            1 => Some(Self::ArmedUnknown),
            2 => Some(Self::Incomplete),
            3 => Some(Self::Complete),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TreeCountsV1 {
    pub entries: u32,
    pub directories: u32,
    pub regular_files: u32,
    pub total_file_bytes: u64,
    pub ai_visible_files: u32,
    pub omitted_files: u32,
    pub token_occurrences: u32,
    pub token_bearing_files: u32,
    pub canonical_path_bytes: u64,
}

impl TreeCountsV1 {
    pub fn validate(&self) -> Result<()> {
        if self
            .directories
            .checked_add(self.regular_files)
            .is_none_or(|count| count != self.entries)
            || self
                .ai_visible_files
                .checked_add(self.omitted_files)
                .is_none_or(|count| count != self.regular_files)
            || self.token_bearing_files > self.ai_visible_files
            || (self.token_bearing_files != 0 && self.token_occurrences == 0)
        {
            return Err(Error::InvalidState);
        }
        Ok(())
    }

    fn encode(&self, encoder: &mut CborEncoder) -> Result<()> {
        encoder.map(9)?;
        for (key, value) in [
            (1, u64::from(self.entries)),
            (2, u64::from(self.directories)),
            (3, u64::from(self.regular_files)),
            (4, self.total_file_bytes),
            (5, u64::from(self.ai_visible_files)),
            (6, u64::from(self.omitted_files)),
            (7, u64::from(self.token_occurrences)),
            (8, u64::from(self.token_bearing_files)),
            (9, self.canonical_path_bytes),
        ] {
            encoder.value(&key)?;
            encoder.value(&value)?;
        }
        Ok(())
    }

    fn decode(reader: &mut CborReader<'_>) -> Result<Self> {
        reader.map_exact(9)?;
        let entries = read_u32(reader, 1)?;
        let directories = read_u32(reader, 2)?;
        let regular_files = read_u32(reader, 3)?;
        reader.key(4)?;
        let total_file_bytes = reader.decode()?;
        let ai_visible_files = read_u32(reader, 5)?;
        let omitted_files = read_u32(reader, 6)?;
        let token_occurrences = read_u32(reader, 7)?;
        let token_bearing_files = read_u32(reader, 8)?;
        reader.key(9)?;
        let canonical_path_bytes = reader.decode()?;
        let value = Self {
            entries,
            directories,
            regular_files,
            total_file_bytes,
            ai_visible_files,
            omitted_files,
            token_occurrences,
            token_bearing_files,
            canonical_path_bytes,
        };
        value.validate()?;
        Ok(value)
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ReviewAuthorityV1 {
    pub review_id: [u8; 16],
    pub edited_tree_commitment: [u8; 32],
    pub event_set_commitment: [u8; 32],
    pub manifest_commitment: [u8; 32],
    pub manifest_phase: ManifestPhase,
    pub automatic_event_count: u32,
    pub approval_eligible_count: u32,
    pub unconditional_reject_count: u32,
    pub reviewed_epoch_seconds: u64,
}

impl ReviewAuthorityV1 {
    fn encode(&self, encoder: &mut CborEncoder) -> Result<()> {
        encoder.map(9)?;
        encoder.value(&1u8)?;
        encoder.bytes(&self.review_id)?;
        encoder.value(&2u8)?;
        encoder.bytes(&self.edited_tree_commitment)?;
        encoder.value(&3u8)?;
        encoder.bytes(&self.event_set_commitment)?;
        encoder.value(&4u8)?;
        encoder.bytes(&self.manifest_commitment)?;
        encoder.value(&5u8)?;
        encoder.value(&(self.manifest_phase as u8))?;
        for (key, value) in [
            (6, self.automatic_event_count),
            (7, self.approval_eligible_count),
            (8, self.unconditional_reject_count),
        ] {
            encoder.value(&key)?;
            encoder.value(&value)?;
        }
        encoder.value(&9u8)?;
        encoder.value(&self.reviewed_epoch_seconds)
    }

    fn decode(reader: &mut CborReader<'_>) -> Result<Self> {
        reader.map_exact(9)?;
        reader.key(1)?;
        let review_id = reader.fixed()?;
        reader.key(2)?;
        let edited_tree_commitment = reader.fixed()?;
        reader.key(3)?;
        let event_set_commitment = reader.fixed()?;
        reader.key(4)?;
        let manifest_commitment = reader.fixed()?;
        reader.key(5)?;
        let manifest_phase = ManifestPhase::parse(reader.decode()?).ok_or(Error::InvalidSchema)?;
        let automatic_event_count = read_u32(reader, 6)?;
        let approval_eligible_count = read_u32(reader, 7)?;
        let unconditional_reject_count = read_u32(reader, 8)?;
        reader.key(9)?;
        let reviewed_epoch_seconds = reader.decode()?;
        Ok(Self {
            review_id,
            edited_tree_commitment,
            event_set_commitment,
            manifest_commitment,
            manifest_phase,
            automatic_event_count,
            approval_eligible_count,
            unconditional_reject_count,
            reviewed_epoch_seconds,
        })
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ApprovalRecordV1 {
    pub event_id: [u8; 16],
    pub event_type: ApprovalEventType,
    pub reason_code: ApprovalReason,
    pub edited_tree_commitment: [u8; 32],
    pub approved_in_generation: u64,
}

impl ApprovalRecordV1 {
    fn validate(&self) -> Result<()> {
        if self.approved_in_generation == 0 || !self.reason_code.valid_for(self.event_type) {
            return Err(Error::InvalidState);
        }
        Ok(())
    }

    fn encode(&self, encoder: &mut CborEncoder) -> Result<()> {
        self.validate()?;
        encoder.map(5)?;
        encoder.value(&1u8)?;
        encoder.bytes(&self.event_id)?;
        encoder.value(&2u8)?;
        encoder.value(&(self.event_type as u8))?;
        encoder.value(&3u8)?;
        encoder.value(&(self.reason_code as u8))?;
        encoder.value(&4u8)?;
        encoder.bytes(&self.edited_tree_commitment)?;
        encoder.value(&5u8)?;
        encoder.value(&self.approved_in_generation)
    }

    fn decode(reader: &mut CborReader<'_>) -> Result<Self> {
        reader.map_exact(5)?;
        reader.key(1)?;
        let event_id = reader.fixed()?;
        reader.key(2)?;
        let event_type = ApprovalEventType::parse(reader.decode()?).ok_or(Error::InvalidSchema)?;
        reader.key(3)?;
        let reason_code = ApprovalReason::parse(reader.decode()?).ok_or(Error::InvalidSchema)?;
        reader.key(4)?;
        let edited_tree_commitment = reader.fixed()?;
        reader.key(5)?;
        let approved_in_generation = reader.decode()?;
        let value = Self {
            event_id,
            event_type,
            reason_code,
            edited_tree_commitment,
            approved_in_generation,
        };
        value.validate()?;
        Ok(value)
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ApprovalSetV1 {
    pub review_id: Option<[u8; 16]>,
    pub records: Vec<ApprovalRecordV1>,
    pub approval_set_tag: [u8; 32],
}

impl ApprovalSetV1 {
    pub fn validate(&self) -> Result<()> {
        if self.records.len() > MAX_APPROVAL_RECORDS
            || (self.review_id.is_none() && !self.records.is_empty())
        {
            return Err(Error::InvalidState);
        }
        let mut previous = None;
        for record in &self.records {
            record.validate()?;
            if previous.is_some_and(|event_id: &[u8; 16]| event_id >= &record.event_id) {
                return Err(Error::InvalidState);
            }
            previous = Some(&record.event_id);
        }
        Ok(())
    }

    fn encode(&self, encoder: &mut CborEncoder) -> Result<()> {
        self.validate()?;
        encoder.map(3)?;
        encoder.value(&1u8)?;
        encode_optional_fixed(encoder, self.review_id.as_ref())?;
        encoder.value(&2u8)?;
        encoder.array(self.records.len())?;
        for record in &self.records {
            record.encode(encoder)?;
        }
        encoder.value(&3u8)?;
        encoder.bytes(&self.approval_set_tag)
    }

    fn decode(reader: &mut CborReader<'_>) -> Result<Self> {
        reader.map_exact(3)?;
        reader.key(1)?;
        let review_id = decode_optional_fixed(reader)?;
        reader.key(2)?;
        let length = reader.array_bounded(MAX_APPROVAL_RECORDS)?;
        let mut records = Vec::new();
        records
            .try_reserve_exact(length)
            .map_err(|_| Error::BoundExceeded)?;
        for _ in 0..length {
            records.push(ApprovalRecordV1::decode(reader)?);
        }
        reader.key(3)?;
        let approval_set_tag = reader.fixed()?;
        let value = Self {
            review_id,
            records,
            approval_set_tag,
        };
        value.validate()?;
        Ok(value)
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ApplyAuthorityV1 {
    pub apply_id: [u8; 16],
    pub state: ApplyState,
    pub review_id: [u8; 16],
    pub edited_tree_commitment: [u8; 32],
    pub candidate_tree_commitment: Option<[u8; 32]>,
    pub candidate_volume_identity: Option<[u8; 32]>,
    pub candidate_root_file_id: Option<[u8; 32]>,
    pub final_manifest_commitment: Option<[u8; 32]>,
    pub manual_reason_code: Option<ManualReasonCode>,
    pub semantic_safety_assessed: bool,
}

impl ApplyAuthorityV1 {
    pub fn validate(&self) -> Result<()> {
        if self.semantic_safety_assessed {
            return Err(Error::InvalidState);
        }
        let valid = match self.state {
            ApplyState::Armed => {
                self.candidate_tree_commitment.is_none()
                    && self.candidate_volume_identity.is_none()
                    && self.candidate_root_file_id.is_none()
                    && self.final_manifest_commitment.is_none()
                    && self.manual_reason_code.is_none()
            }
            ApplyState::Incomplete => {
                self.candidate_tree_commitment.is_none()
                    && self.candidate_volume_identity.is_some()
                    && self.candidate_root_file_id.is_some()
                    && self.final_manifest_commitment.is_none()
            }
            ApplyState::Complete => {
                self.candidate_tree_commitment.is_some()
                    && self.candidate_volume_identity.is_some()
                    && self.candidate_root_file_id.is_some()
                    && self.final_manifest_commitment.is_some()
                    && self.manual_reason_code.is_none()
            }
        };
        if valid {
            Ok(())
        } else {
            Err(Error::InvalidState)
        }
    }

    fn encode(&self, encoder: &mut CborEncoder) -> Result<()> {
        self.validate()?;
        encoder.map(10)?;
        encoder.value(&1u8)?;
        encoder.bytes(&self.apply_id)?;
        encoder.value(&2u8)?;
        encoder.value(&(self.state as u8))?;
        encoder.value(&3u8)?;
        encoder.bytes(&self.review_id)?;
        encoder.value(&4u8)?;
        encoder.bytes(&self.edited_tree_commitment)?;
        encoder.value(&5u8)?;
        encode_optional_fixed(encoder, self.candidate_tree_commitment.as_ref())?;
        encoder.value(&6u8)?;
        encode_optional_fixed(encoder, self.candidate_volume_identity.as_ref())?;
        encoder.value(&7u8)?;
        encode_optional_fixed(encoder, self.candidate_root_file_id.as_ref())?;
        encoder.value(&8u8)?;
        encode_optional_fixed(encoder, self.final_manifest_commitment.as_ref())?;
        encoder.value(&9u8)?;
        if let Some(reason) = self.manual_reason_code {
            encoder.value(&(reason as u8))?;
        } else {
            encoder.null()?;
        }
        encoder.value(&10u8)?;
        encoder.value(&self.semantic_safety_assessed)
    }

    fn decode(reader: &mut CborReader<'_>) -> Result<Self> {
        reader.map_exact(10)?;
        reader.key(1)?;
        let apply_id = reader.fixed()?;
        reader.key(2)?;
        let state = ApplyState::parse(reader.decode()?).ok_or(Error::InvalidSchema)?;
        reader.key(3)?;
        let review_id = reader.fixed()?;
        reader.key(4)?;
        let edited_tree_commitment = reader.fixed()?;
        reader.key(5)?;
        let candidate_tree_commitment = decode_optional_fixed(reader)?;
        reader.key(6)?;
        let candidate_volume_identity = decode_optional_fixed(reader)?;
        reader.key(7)?;
        let candidate_root_file_id = decode_optional_fixed(reader)?;
        reader.key(8)?;
        let final_manifest_commitment = decode_optional_fixed(reader)?;
        reader.key(9)?;
        let manual_reason_code = if reader.is_null() {
            reader.null()?;
            None
        } else {
            Some(ManualReasonCode::parse(reader.decode()?).ok_or(Error::InvalidSchema)?)
        };
        reader.key(10)?;
        let semantic_safety_assessed = reader.decode()?;
        let value = Self {
            apply_id,
            state,
            review_id,
            edited_tree_commitment,
            candidate_tree_commitment,
            candidate_volume_identity,
            candidate_root_file_id,
            final_manifest_commitment,
            manual_reason_code,
            semantic_safety_assessed,
        };
        value.validate()?;
        Ok(value)
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct CapsuleV1 {
    pub session_id: SessionId,
    pub generation: u64,
    pub session_state: SessionState,
    pub review_profile: ReviewProfile,
    pub ruleset_id: String,
    pub original_tree_commitment: [u8; 32],
    pub baseline_ai_tree_commitment: [u8; 32],
    pub baseline_counts: TreeCountsV1,
    pub current_review: Option<ReviewAuthorityV1>,
    pub approval_set: ApprovalSetV1,
    pub apply_authority: Option<ApplyAuthorityV1>,
    pub created_epoch_seconds: u64,
    pub orphan_count_at_commit: u32,
    pub semantic_safety_assessed: bool,
    pub state_root_identity_commitment: [u8; 32],
}

impl CapsuleV1 {
    pub fn validate_capsule_state(&self) -> Result<()> {
        if self.generation == 0
            || !self.review_profile.is_current()
            || !valid_ruleset_id(&self.ruleset_id)
            || self.semantic_safety_assessed
        {
            return Err(Error::InvalidState);
        }
        self.baseline_counts.validate()?;
        self.approval_set.validate()?;
        match (&self.current_review, self.approval_set.review_id) {
            (None, None) => {}
            (Some(review), Some(approval_review)) if review.review_id == approval_review => {}
            _ => return Err(Error::InvalidState),
        }
        if let (Some(review), Some(apply)) = (&self.current_review, &self.apply_authority) {
            if review.review_id != apply.review_id
                || review.edited_tree_commitment != apply.edited_tree_commitment
            {
                return Err(Error::InvalidState);
            }
        }
        if let Some(apply) = &self.apply_authority {
            apply.validate()?;
        }
        for record in &self.approval_set.records {
            if record.edited_tree_commitment
                != self
                    .current_review
                    .as_ref()
                    .ok_or(Error::InvalidState)?
                    .edited_tree_commitment
                || record.approved_in_generation > self.generation
            {
                return Err(Error::InvalidState);
            }
        }
        let review = self.current_review.as_ref();
        let approvals_complete = review.is_some_and(|review| {
            review.unconditional_reject_count == 0
                && usize::try_from(review.approval_eligible_count)
                    .is_ok_and(|count| count == self.approval_set.records.len())
        });
        let valid = match self.session_state {
            SessionState::ActiveUnreviewed => {
                self.current_review.is_none()
                    && self.approval_set.review_id.is_none()
                    && self.approval_set.records.is_empty()
                    && self.apply_authority.is_none()
            }
            SessionState::ReviewedRejected => review.is_some_and(|review| {
                review.unconditional_reject_count != 0
                    && self.approval_set.records.is_empty()
                    && self.apply_authority.is_none()
            }),
            SessionState::Reviewed => review.is_some_and(|review| {
                review.unconditional_reject_count == 0
                    && self.approval_set.records.is_empty()
                    && self.apply_authority.is_none()
            }),
            SessionState::ApprovedPartial => {
                review.is_some_and(|review| {
                    review.unconditional_reject_count == 0
                        && usize::try_from(review.approval_eligible_count)
                            .is_ok_and(|count| self.approval_set.records.len() < count)
                }) && !self.approval_set.records.is_empty()
                    && self.apply_authority.is_none()
            }
            SessionState::ReadyToApply => approvals_complete && self.apply_authority.is_none(),
            SessionState::ApplyArmed => self
                .apply_authority
                .as_ref()
                .is_some_and(|apply| approvals_complete && apply.state == ApplyState::Armed),
            SessionState::ApplyIncomplete => self
                .apply_authority
                .as_ref()
                .is_some_and(|apply| approvals_complete && apply.state == ApplyState::Incomplete),
            SessionState::AppliedComplete => self.apply_authority.as_ref().is_some_and(|apply| {
                approvals_complete
                    && apply.state == ApplyState::Complete
                    && review
                        .is_some_and(|review| review.manifest_phase == ManifestPhase::ApplyResult)
            }),
        };
        if valid {
            Ok(())
        } else {
            Err(Error::InvalidState)
        }
    }

    pub fn encode_canonical(&self) -> Result<Vec<u8>> {
        self.validate_capsule_state()?;
        let mut encoder = CborEncoder::new(MAX_SCHEMA_CBOR_BYTES)?;
        encoder.map(20)?;
        encoder.value(&1u8)?;
        encoder.value(&CAPSULE_SCHEMA_VERSION)?;
        encoder.value(&2u8)?;
        encoder.bytes(self.session_id.as_bytes())?;
        encoder.value(&3u8)?;
        encoder.value(&self.generation)?;
        encoder.value(&4u8)?;
        encoder.value(&(self.session_state as u8))?;
        encoder.value(&5u8)?;
        encoder.value(&(self.review_profile as u8))?;
        encoder.value(&6u8)?;
        encoder.value(&ENGINE_VERSION)?;
        encoder.value(&7u8)?;
        encoder.value(&POLICY_ID)?;
        encoder.value(&8u8)?;
        encoder.value(&self.ruleset_id.as_str())?;
        encoder.value(&9u8)?;
        encoder.value(&TOKEN_SUITE_ID)?;
        encoder.value(&10u8)?;
        encoder.value(&MANIFEST_SCHEMA_VERSION)?;
        encoder.value(&11u8)?;
        encoder.bytes(&self.original_tree_commitment)?;
        encoder.value(&12u8)?;
        encoder.bytes(&self.baseline_ai_tree_commitment)?;
        encoder.value(&13u8)?;
        self.baseline_counts.encode(&mut encoder)?;
        encoder.value(&14u8)?;
        if let Some(review) = &self.current_review {
            review.encode(&mut encoder)?;
        } else {
            encoder.null()?;
        }
        encoder.value(&15u8)?;
        self.approval_set.encode(&mut encoder)?;
        encoder.value(&16u8)?;
        if let Some(apply) = &self.apply_authority {
            apply.encode(&mut encoder)?;
        } else {
            encoder.null()?;
        }
        encoder.value(&17u8)?;
        encoder.value(&self.created_epoch_seconds)?;
        encoder.value(&18u8)?;
        encoder.value(&self.orphan_count_at_commit)?;
        encoder.value(&19u8)?;
        encoder.value(&self.semantic_safety_assessed)?;
        encoder.value(&20u8)?;
        encoder.bytes(&self.state_root_identity_commitment)?;
        Ok(encoder.finish())
    }

    pub fn decode_canonical(input: &[u8]) -> Result<Self> {
        let mut reader = CborReader::new(input)?;
        reader.map_exact(20)?;
        reader.key(1)?;
        let schema_version: u64 = reader.decode()?;
        if schema_version != u64::from(CAPSULE_SCHEMA_VERSION) {
            return Err(Error::InvalidSchema);
        }
        reader.key(2)?;
        let session_id = SessionId::from_bytes(reader.fixed()?);
        reader.key(3)?;
        let generation = reader.decode()?;
        reader.key(4)?;
        let session_state = SessionState::parse(reader.decode()?).ok_or(Error::InvalidSchema)?;
        reader.key(5)?;
        let review_profile = ReviewProfile::parse(reader.decode()?).ok_or(Error::InvalidSchema)?;
        reader.key(6)?;
        if reader.text()? != ENGINE_VERSION {
            return Err(Error::InvalidSchema);
        }
        reader.key(7)?;
        if reader.text()? != POLICY_ID {
            return Err(Error::InvalidSchema);
        }
        reader.key(8)?;
        let ruleset_id = reader.text()?;
        reader.key(9)?;
        let token_suite: u64 = reader.decode()?;
        if token_suite != u64::from(TOKEN_SUITE_ID) {
            return Err(Error::InvalidSchema);
        }
        reader.key(10)?;
        let manifest_schema: u64 = reader.decode()?;
        if manifest_schema != u64::from(MANIFEST_SCHEMA_VERSION) {
            return Err(Error::InvalidSchema);
        }
        reader.key(11)?;
        let original_tree_commitment = reader.fixed()?;
        reader.key(12)?;
        let baseline_ai_tree_commitment = reader.fixed()?;
        reader.key(13)?;
        let baseline_counts = TreeCountsV1::decode(&mut reader)?;
        reader.key(14)?;
        let current_review = if reader.is_null() {
            reader.null()?;
            None
        } else {
            Some(ReviewAuthorityV1::decode(&mut reader)?)
        };
        reader.key(15)?;
        let approval_set = ApprovalSetV1::decode(&mut reader)?;
        reader.key(16)?;
        let apply_authority = if reader.is_null() {
            reader.null()?;
            None
        } else {
            Some(ApplyAuthorityV1::decode(&mut reader)?)
        };
        reader.key(17)?;
        let created_epoch_seconds = reader.decode()?;
        let orphan_count_at_commit = read_u32(&mut reader, 18)?;
        reader.key(19)?;
        let semantic_safety_assessed = reader.decode()?;
        reader.key(20)?;
        let state_root_identity_commitment = reader.fixed()?;
        if !reader.finished() {
            return Err(Error::InvalidSchema);
        }
        let value = Self {
            session_id,
            generation,
            session_state,
            review_profile,
            ruleset_id,
            original_tree_commitment,
            baseline_ai_tree_commitment,
            baseline_counts,
            current_review,
            approval_set,
            apply_authority,
            created_epoch_seconds,
            orphan_count_at_commit,
            semantic_safety_assessed,
            state_root_identity_commitment,
        };
        value.validate_capsule_state()?;
        if value.encode_canonical()?.as_slice() != input {
            return Err(Error::InvalidSchema);
        }
        Ok(value)
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ClosedTombstoneV1 {
    pub session_id: SessionId,
    pub generation: u64,
    pub review_profile: ReviewProfile,
    pub ruleset_id: String,
    pub last_nonclosed_state: SessionState,
    pub closed_epoch_seconds: u64,
    pub retained_capsule_generation_count: u32,
    pub retained_manifest_count: u32,
    pub retained_private_orphan_count: u32,
    pub ai_workspace_retained: bool,
    pub sensitive_candidate_state: SensitiveCandidateState,
    pub incomplete_apply_acknowledged: bool,
    pub acknowledged_apply_id: Option<[u8; 16]>,
    pub semantic_safety_assessed: bool,
}

impl ClosedTombstoneV1 {
    pub fn validate(&self) -> Result<()> {
        if self.generation < 2
            || !self.review_profile.is_current()
            || !valid_ruleset_id(&self.ruleset_id)
            || u32::try_from(self.generation).ok() != Some(self.retained_capsule_generation_count)
            || !self.ai_workspace_retained
            || self.semantic_safety_assessed
            || self.incomplete_apply_acknowledged != self.acknowledged_apply_id.is_some()
        {
            return Err(Error::InvalidState);
        }
        Ok(())
    }

    pub fn encode_canonical(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut encoder = CborEncoder::new(MAX_SCHEMA_CBOR_BYTES)?;
        encoder.map(20)?;
        encoder.value(&1u8)?;
        encoder.value(&CAPSULE_SCHEMA_VERSION)?;
        encoder.value(&2u8)?;
        encoder.bytes(self.session_id.as_bytes())?;
        encoder.value(&3u8)?;
        encoder.value(&self.generation)?;
        encoder.value(&4u8)?;
        encoder.value(&9u8)?;
        encoder.value(&5u8)?;
        encoder.value(&(self.review_profile as u8))?;
        encoder.value(&6u8)?;
        encoder.value(&ENGINE_VERSION)?;
        encoder.value(&7u8)?;
        encoder.value(&POLICY_ID)?;
        encoder.value(&8u8)?;
        encoder.value(&self.ruleset_id.as_str())?;
        encoder.value(&9u8)?;
        encoder.value(&TOKEN_SUITE_ID)?;
        encoder.value(&10u8)?;
        encoder.value(&MANIFEST_SCHEMA_VERSION)?;
        encoder.value(&11u8)?;
        encoder.value(&(self.last_nonclosed_state as u8))?;
        encoder.value(&12u8)?;
        encoder.value(&self.closed_epoch_seconds)?;
        for (key, value) in [
            (13, self.retained_capsule_generation_count),
            (14, self.retained_manifest_count),
            (15, self.retained_private_orphan_count),
        ] {
            encoder.value(&key)?;
            encoder.value(&value)?;
        }
        encoder.value(&16u8)?;
        encoder.value(&self.ai_workspace_retained)?;
        encoder.value(&17u8)?;
        encoder.value(&(self.sensitive_candidate_state as u8))?;
        encoder.value(&18u8)?;
        encoder.value(&self.incomplete_apply_acknowledged)?;
        encoder.value(&19u8)?;
        encode_optional_fixed(&mut encoder, self.acknowledged_apply_id.as_ref())?;
        encoder.value(&20u8)?;
        encoder.value(&self.semantic_safety_assessed)?;
        Ok(encoder.finish())
    }

    pub fn decode_canonical(input: &[u8]) -> Result<Self> {
        let mut reader = CborReader::new(input)?;
        reader.map_exact(20)?;
        reader.key(1)?;
        if reader.decode::<u64>()? != u64::from(CAPSULE_SCHEMA_VERSION) {
            return Err(Error::InvalidSchema);
        }
        reader.key(2)?;
        let session_id = SessionId::from_bytes(reader.fixed()?);
        reader.key(3)?;
        let generation = reader.decode()?;
        reader.key(4)?;
        if reader.decode::<u64>()? != 9 {
            return Err(Error::InvalidSchema);
        }
        reader.key(5)?;
        let review_profile = ReviewProfile::parse(reader.decode()?).ok_or(Error::InvalidSchema)?;
        reader.key(6)?;
        if reader.text()? != ENGINE_VERSION {
            return Err(Error::InvalidSchema);
        }
        reader.key(7)?;
        if reader.text()? != POLICY_ID {
            return Err(Error::InvalidSchema);
        }
        reader.key(8)?;
        let ruleset_id = reader.text()?;
        reader.key(9)?;
        if reader.decode::<u64>()? != u64::from(TOKEN_SUITE_ID) {
            return Err(Error::InvalidSchema);
        }
        reader.key(10)?;
        if reader.decode::<u64>()? != u64::from(MANIFEST_SCHEMA_VERSION) {
            return Err(Error::InvalidSchema);
        }
        reader.key(11)?;
        let last_nonclosed_state =
            SessionState::parse(reader.decode()?).ok_or(Error::InvalidSchema)?;
        reader.key(12)?;
        let closed_epoch_seconds = reader.decode()?;
        let retained_capsule_generation_count = read_u32(&mut reader, 13)?;
        let retained_manifest_count = read_u32(&mut reader, 14)?;
        let retained_private_orphan_count = read_u32(&mut reader, 15)?;
        reader.key(16)?;
        let ai_workspace_retained = reader.decode()?;
        reader.key(17)?;
        let sensitive_candidate_state =
            SensitiveCandidateState::parse(reader.decode()?).ok_or(Error::InvalidSchema)?;
        reader.key(18)?;
        let incomplete_apply_acknowledged = reader.decode()?;
        reader.key(19)?;
        let acknowledged_apply_id = decode_optional_fixed(&mut reader)?;
        reader.key(20)?;
        let semantic_safety_assessed = reader.decode()?;
        if !reader.finished() {
            return Err(Error::InvalidSchema);
        }
        let value = Self {
            session_id,
            generation,
            review_profile,
            ruleset_id,
            last_nonclosed_state,
            closed_epoch_seconds,
            retained_capsule_generation_count,
            retained_manifest_count,
            retained_private_orphan_count,
            ai_workspace_retained,
            sensitive_candidate_state,
            incomplete_apply_acknowledged,
            acknowledged_apply_id,
            semantic_safety_assessed,
        };
        value.validate()?;
        if value.encode_canonical()?.as_slice() != input {
            return Err(Error::InvalidSchema);
        }
        Ok(value)
    }
}

fn read_u32(reader: &mut CborReader<'_>, key: u8) -> Result<u32> {
    reader.key(key)?;
    u32::try_from(reader.decode::<u64>()?).map_err(|_| Error::InvalidSchema)
}

fn encode_optional_fixed<const N: usize>(
    encoder: &mut CborEncoder,
    value: Option<&[u8; N]>,
) -> Result<()> {
    if let Some(value) = value {
        encoder.bytes(value)
    } else {
        encoder.null()
    }
}

fn decode_optional_fixed<const N: usize>(reader: &mut CborReader<'_>) -> Result<Option<[u8; N]>> {
    if reader.is_null() {
        reader.null()?;
        Ok(None)
    } else {
        reader.fixed().map(Some)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    fn vector_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn replace_first(bytes: &mut Vec<u8>, needle: &[u8], replacement: &[u8]) {
        let offset = bytes
            .windows(needle.len())
            .position(|window| window == needle)
            .expect("fixture subsequence");
        bytes.splice(offset..offset + needle.len(), replacement.iter().copied());
    }

    const RULESET: &str =
        "ruleset-sha256-db05d116f06728ef64c5cdf7cc087df2f2f799459d2845a15e32479a1e8d1825";

    pub(crate) fn active_capsule(generation: u64) -> CapsuleV1 {
        CapsuleV1 {
            session_id: SessionId::from_bytes([0x11; 16]),
            generation,
            session_state: SessionState::ActiveUnreviewed,
            review_profile: ReviewProfile::StandardV2,
            ruleset_id: RULESET.to_owned(),
            original_tree_commitment: [0x22; 32],
            baseline_ai_tree_commitment: [0x33; 32],
            baseline_counts: TreeCountsV1 {
                entries: 2,
                directories: 1,
                regular_files: 1,
                total_file_bytes: 7,
                ai_visible_files: 1,
                omitted_files: 0,
                token_occurrences: 1,
                token_bearing_files: 1,
                canonical_path_bytes: 18,
            },
            current_review: None,
            approval_set: ApprovalSetV1 {
                review_id: None,
                records: Vec::new(),
                approval_set_tag: [0x44; 32],
            },
            apply_authority: None,
            created_epoch_seconds: 1_700_000_000,
            orphan_count_at_commit: 0,
            semantic_safety_assessed: false,
            state_root_identity_commitment: [0x55; 32],
        }
    }

    pub(crate) fn tombstone(generation: u64) -> ClosedTombstoneV1 {
        ClosedTombstoneV1 {
            session_id: SessionId::from_bytes([0x11; 16]),
            generation,
            review_profile: ReviewProfile::StandardV2,
            ruleset_id: RULESET.to_owned(),
            last_nonclosed_state: SessionState::ActiveUnreviewed,
            closed_epoch_seconds: 1_700_000_100,
            retained_capsule_generation_count: generation as u32,
            retained_manifest_count: 0,
            retained_private_orphan_count: 0,
            ai_workspace_retained: true,
            sensitive_candidate_state: SensitiveCandidateState::None,
            incomplete_apply_acknowledged: false,
            acknowledged_apply_id: None,
            semantic_safety_assessed: false,
        }
    }

    #[test]
    fn representative_capsule_and_tombstone_are_canonical() {
        let capsule = active_capsule(1);
        let encoded = capsule.encode_canonical().expect("encode capsule");
        assert!(CapsuleV1::decode_canonical(&encoded).is_ok_and(|value| value == capsule));

        let tombstone = tombstone(2);
        let encoded = tombstone.encode_canonical().expect("encode tombstone");
        assert!(ClosedTombstoneV1::decode_canonical(&encoded).is_ok_and(|value| value == tombstone));
    }

    #[test]
    fn noncanonical_and_structural_mutations_fail_closed() {
        let canonical = active_capsule(1).encode_canonical().expect("canonical");
        let mut trailing = canonical.clone();
        trailing.push(0);
        assert_eq!(
            CapsuleV1::decode_canonical(&trailing).err(),
            Some(Error::InvalidSchema)
        );

        let mut indefinite = canonical.clone();
        indefinite[0] = 0xbf;
        assert_eq!(
            CapsuleV1::decode_canonical(&indefinite).err(),
            Some(Error::InvalidSchema)
        );

        let mut reordered = canonical.clone();
        reordered[1] = 2;
        assert_eq!(
            CapsuleV1::decode_canonical(&reordered).err(),
            Some(Error::InvalidSchema)
        );

        let mut nonshortest = canonical.clone();
        nonshortest.splice(1..2, [0x18, 0x01]);
        assert_eq!(
            CapsuleV1::decode_canonical(&nonshortest).err(),
            Some(Error::InvalidSchema)
        );
    }

    #[test]
    fn complete_cbor_adversarial_classes_fail_closed() {
        let canonical = active_capsule(1).encode_canonical().expect("canonical");
        let mut mutations = Vec::new();

        let mut duplicate_key = canonical.clone();
        duplicate_key[3] = 1;
        mutations.push(duplicate_key);

        let mut unknown_key = canonical.clone();
        unknown_key[1] = 0;
        mutations.push(unknown_key);

        let mut missing_key = canonical[..canonical.len() - 35].to_vec();
        missing_key[0] = 0xb3;
        mutations.push(missing_key);

        let mut indefinite_map = canonical.clone();
        indefinite_map[0] = 0xbf;
        mutations.push(indefinite_map);

        let mut indefinite_array = canonical.clone();
        replace_first(
            &mut indefinite_array,
            &[0x0f, 0xa3, 0x01, 0xf6, 0x02, 0x80, 0x03],
            &[0x0f, 0xa3, 0x01, 0xf6, 0x02, 0x9f, 0x03],
        );
        mutations.push(indefinite_array);

        let mut indefinite_string = canonical.clone();
        replace_first(
            &mut indefinite_string,
            &[0x06, 0x78, 0x1d],
            &[0x06, 0x7f, 0x1d],
        );
        mutations.push(indefinite_string);

        let mut wrong_type = canonical.clone();
        replace_first(&mut wrong_type, &[0x03, 0x01, 0x04], &[0x03, 0xf5, 0x04]);
        mutations.push(wrong_type);

        let mut huge_declared_length = canonical.clone();
        replace_first(
            &mut huge_declared_length,
            &[0x06, 0x78, 0x1d],
            &[0x06, 0x7a, 0xff, 0xff, 0xff, 0xff],
        );
        mutations.push(huge_declared_length);

        let mut oversized_collection = canonical.clone();
        replace_first(
            &mut oversized_collection,
            &[0x02, 0x80, 0x03, 0x58, 0x20],
            &[0x02, 0x99, 0x80, 0x01, 0x03, 0x58, 0x20],
        );
        mutations.push(oversized_collection);

        let mut invalid_utf8 = canonical.clone();
        let engine = invalid_utf8
            .windows(3)
            .position(|window| window == [0x06, 0x78, 0x1d])
            .expect("engine field");
        invalid_utf8[engine + 3] = 0xff;
        mutations.push(invalid_utf8);

        let mut float = canonical.clone();
        replace_first(
            &mut float,
            &[0x03, 0x01, 0x04],
            &[0x03, 0xf9, 0x00, 0x00, 0x04],
        );
        mutations.push(float);

        let mut tag = canonical.clone();
        replace_first(&mut tag, &[0x03, 0x01, 0x04], &[0x03, 0xc0, 0x01, 0x04]);
        mutations.push(tag);

        let mut unknown_enum = canonical.clone();
        replace_first(&mut unknown_enum, &[0x04, 0x01, 0x05], &[0x04, 0x00, 0x05]);
        mutations.push(unknown_enum);

        for mutation in mutations {
            assert!(CapsuleV1::decode_canonical(&mutation).is_err());
        }

        assert_eq!(
            CapsuleV1::decode_canonical(&vec![0; MAX_SCHEMA_CBOR_BYTES + 1]).err(),
            Some(Error::BoundExceeded)
        );
    }

    #[test]
    fn state_invariants_are_separate_from_decode() {
        let mut capsule = active_capsule(1);
        capsule.semantic_safety_assessed = true;
        assert_eq!(capsule.validate_capsule_state(), Err(Error::InvalidState));

        let mut tombstone = tombstone(2);
        tombstone.ai_workspace_retained = false;
        assert_eq!(tombstone.validate(), Err(Error::InvalidState));
    }

    #[test]
    fn historical_v2_and_v1_profiles_are_not_migrated_or_reinterpreted() {
        let current_capsule = active_capsule(1).encode_canonical().expect("v3 capsule");
        let mut capsule_engine = current_capsule.clone();
        replace_first(
            &mut capsule_engine,
            b"safeclone-roundtrip-engine-v3",
            b"safeclone-roundtrip-engine-v2",
        );
        assert!(CapsuleV1::decode_canonical(&capsule_engine).is_err());
        let mut capsule_policy = current_capsule.clone();
        replace_first(&mut capsule_policy, b"roundtrip-v3", b"roundtrip-v2");
        assert!(CapsuleV1::decode_canonical(&capsule_policy).is_err());
        for historical in [1u8, 2] {
            let mut capsule_profile = current_capsule.clone();
            replace_first(
                &mut capsule_profile,
                &[5, ReviewProfile::StandardV2 as u8, 6],
                &[5, historical, 6],
            );
            assert!(CapsuleV1::decode_canonical(&capsule_profile).is_err());
        }
        let mut unknown_profile = current_capsule.clone();
        replace_first(
            &mut unknown_profile,
            &[5, ReviewProfile::StandardV2 as u8, 6],
            &[5, 5, 6],
        );
        assert!(CapsuleV1::decode_canonical(&unknown_profile).is_err());
        let mut strict = active_capsule(1);
        strict.review_profile = ReviewProfile::StrictTokenFilesV2;
        let strict = strict.encode_canonical().expect("v3 strict capsule");
        assert!(CapsuleV1::decode_canonical(&strict).is_ok());
        let mut strict_v2_engine = strict.clone();
        replace_first(
            &mut strict_v2_engine,
            b"safeclone-roundtrip-engine-v3",
            b"safeclone-roundtrip-engine-v2",
        );
        assert!(CapsuleV1::decode_canonical(&strict_v2_engine).is_err());

        let current_tombstone = tombstone(2).encode_canonical().expect("v3 tombstone");
        let mut tombstone_engine = current_tombstone.clone();
        replace_first(
            &mut tombstone_engine,
            b"safeclone-roundtrip-engine-v3",
            b"safeclone-roundtrip-engine-v2",
        );
        assert!(ClosedTombstoneV1::decode_canonical(&tombstone_engine).is_err());
        let mut tombstone_policy = current_tombstone.clone();
        replace_first(&mut tombstone_policy, b"roundtrip-v3", b"roundtrip-v2");
        assert!(ClosedTombstoneV1::decode_canonical(&tombstone_policy).is_err());
        for invalid_profile in [1u8, 2, 5] {
            let mut historical = current_tombstone.clone();
            replace_first(
                &mut historical,
                &[5, ReviewProfile::StandardV2 as u8, 6],
                &[5, invalid_profile, 6],
            );
            assert!(ClosedTombstoneV1::decode_canonical(&historical).is_err());
        }
    }

    #[test]
    fn approval_records_are_bounded_sorted_and_reason_typed() {
        let record = ApprovalRecordV1 {
            event_id: [1; 16],
            event_type: ApprovalEventType::Deleted,
            reason_code: ApprovalReason::IntentionalTokenRemoval,
            edited_tree_commitment: [2; 32],
            approved_in_generation: 2,
        };
        let mut set = ApprovalSetV1 {
            review_id: Some([3; 16]),
            records: vec![record.clone(), record],
            approval_set_tag: [4; 32],
        };
        assert_eq!(set.validate(), Err(Error::InvalidState));
        set.records.truncate(1);
        set.records[0].reason_code = ApprovalReason::IntentionalFileDelete;
        assert_eq!(set.validate(), Err(Error::InvalidState));
    }

    #[test]
    fn cross_primitive_golden_vectors_are_exact() {
        use crate::roundtrip::crypto::{KeyPurpose, KeySchedule, SessionMasterSecret};
        use crate::roundtrip::ruleset;
        use crate::roundtrip::token::{
            generate_token, ComponentKind, EntryKind, OccurrenceDescriptor, TokenCategory,
        };

        let master = SessionMasterSecret::from_bytes([0x42; 32]);
        let session = SessionId::from_bytes([0x11; 16]);
        let schedule = KeySchedule::new(&master, session);
        let purposes = [
            KeyPurpose::TokenId,
            KeyPurpose::TokenAuth,
            KeyPurpose::TreeCommit,
            KeyPurpose::AnchorCommit,
            KeyPurpose::EventId,
            KeyPurpose::CapsuleMac,
            KeyPurpose::ManifestMac,
            KeyPurpose::ApprovalMac,
            KeyPurpose::CandidateMarker,
            KeyPurpose::TombstoneMac,
        ];
        let expected_keys = [
            "dfc2b1a7f62d2aef6892b445dc33ccda77baa552327429c8025ee16bda1dffca",
            "1a54e76abcad7e3d1c694508f551b26d8910b076e337fd18e3ca663edfdf93fa",
            "d195094b0a1df2ae27be28b01e9c08ddfc40c117f86337e3c7f00a9dd547c75b",
            "09dfee732874f5cce3a0b596623212c9e2a36519b6a040935267cad5030bc98b",
            "6ef60c59d2ed2ba7444a180e43cec1472fede8e5e9becf179786916c12a864f2",
            "0ec460aaafd6d3c77cacd7912c23afcdfff2be3e0ced2ec8462f1204e6bd1f23",
            "11463f86a38e34573afcfd4186eeb225a925664bffb31e45d349927c1b50b450",
            "55e9e033d71b10e568e1ad2e5109d92dfbe366e0b16495bd10ca391e8443a3ef",
            "0a6d1a435e888705dc5431033dd46a3a85b533e1edcc95868981166ee29d2a14",
            "0bf93afc4c5221c9255dd8711a46e6a26891c64d627a4de2b43d62d2dc17856c",
        ];
        for (purpose, expected) in purposes.into_iter().zip(expected_keys) {
            assert_eq!(
                vector_hex(schedule.derive(purpose).expect("derive").expose()),
                expected
            );
        }
        let descriptor = OccurrenceDescriptor {
            session_id: session,
            ruleset_id: ruleset::ruleset_id(),
            review_profile: ReviewProfile::StandardV2,
            entry_kind: EntryKind::RegularFile,
            canonical_original_relative_path: b"synthetic/file.txt",
            component_index: 0,
            component_kind: ComponentKind::Content,
            byte_span_start: 4,
            byte_span_end: 12,
            category: TokenCategory::Secret,
            occurrence_ordinal_within_component: 0,
            pre_token_anchor_commitment: [0x55; 32],
        };
        assert_eq!(
            vector_hex(&descriptor.canonical_bytes().expect("descriptor")),
            concat!(
                "0000002373616665636c6f6e652f7274312f6f6363757272656e63652d64657363726970746f72",
                "000100000010111111111111111111111111111111110000001d73616665636c6f6e652d726f756e",
                "64747269702d656e67696e652d76330000000c726f756e64747269702d76330000004f72756c6573",
                "65742d7368613235362d64623035643131366630363732386566363463356364663763633038376466",
                "3266326637393934353964323834356131356533323437396131653864313832350301000000127379",
                "6e7468657469632f66696c652e74787400000000010000000000000004000000000000000c010000",
                "0000000000205555555555555555555555555555555555555555555555555555555555555555"
            )
        );
        assert_eq!(
            generate_token(&schedule, &descriptor).expect("token"),
            "__SAFECLONE_RT1_SECRET_CEIRCEIRCEIRCEIRCEIRCEIRCE_BXU5Z2H7H3KVAMXZZUUMEUTJB4_UPBIEINIQ27NVLH2B3S2M7VP74__"
        );
        assert_eq!(
            vector_hex(&active_capsule(1).encode_canonical().expect("capsule")),
            "b4010102501111111111111111111111111111111103010401050306781d73616665636c6f6e652d726f756e64747269702d656e67696e652d7633076c726f756e64747269702d763308784f72756c657365742d7368613235362d6462303564313136663036373238656636346335636466376363303837646632663266373939343539643238343561313565333234373961316538643138323509010a010b582022222222222222222222222222222222222222222222222222222222222222220c582033333333333333333333333333333333333333333333333333333333333333330da90102020103010407050106000701080109120ef60fa301f60280035820444444444444444444444444444444444444444444444444444444444444444410f6111a6553f100120013f41458205555555555555555555555555555555555555555555555555555555555555555"
        );
        assert_eq!(
            vector_hex(&tombstone(2).encode_canonical().expect("tombstone")),
            concat!(
                "b4010102501111111111111111111111111111111103020409050306781d73616665636c6f6e652d",
                "726f756e64747269702d656e67696e652d7633076c726f756e64747269702d763308784f72756c65",
                "7365742d7368613235362d646230356431313666303637323865663634633563646637636330383764",
                "6632663266373939343539643238343561313565333234373961316538643138323509010a010b010c",
                "1a6553f1640d020e000f0010f5110012f413f614f4"
            )
        );
        assert_eq!(
            ruleset::canonical_descriptor().expect("ruleset").len(),
            7_926
        );
    }
}
