//! First implemented ChangedManifestV1 wire contract.
//!
//! This module is intentionally report-only. It contains no classifier,
//! approval, reconstruction, filesystem, DPAPI, or rendering authority.

use std::collections::BTreeSet;

use super::events::MAX_CANONICAL_EVENTS;
use super::report_diff::{
    ContentChangeKindV1, ContentChangeRegionV1, LineRangeV1, MAX_LOGICAL_LINES_PER_SIDE,
    MAX_REGIONS_PER_FILE, MAX_REGIONS_PER_REVIEW,
};
use super::schema::{CborEncoder, CborReader, MANIFEST_SCHEMA_VERSION};
use super::token::{
    valid_ruleset_id, ReviewProfile, TokenCategory, ENGINE_VERSION, POLICY_ID, TOKEN_SUITE_ID,
};
use super::{Error, Result};

pub(crate) const MAX_CHANGED_ENTRIES: usize = 100_000;
pub(crate) const MAX_MANIFEST_PATH_BYTES: usize = 128 * 1024;
pub(crate) const MAX_MANIFEST_PLAINTEXT_BYTES: usize = 128 * 1024 * 1024 - 78 - 32;
const MAX_REASON_CODES: usize = 64;
const MAX_ANCHORS_PER_ENTRY: usize = 16_640;
const MAX_TOKEN_EVENTS_PER_ENTRY: usize = 100_000;

macro_rules! closed_enum {
    ($name:ident { $($variant:ident = $code:literal),+ $(,)? }) => {
        #[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
        pub(crate) enum $name { $($variant),+ }

        impl $name {
            #[cfg(test)]
            pub(crate) const ALL: &'static [Self] = &[$(Self::$variant),+];

            pub(crate) const fn code(self) -> u8 {
                match self { $(Self::$variant => $code),+ }
            }

            pub(crate) const fn parse(value: u64) -> Option<Self> {
                match value { $($code => Some(Self::$variant),)+ _ => None }
            }
        }
    };
}

closed_enum!(OriginalTreeConsistencyV1 {
    Match = 1,
    Mismatch = 2,
    Unstable = 3,
});

closed_enum!(ChangedManifestPhaseV1 {
    Review = 1,
    ApplyResult = 2,
    ApplyFailure = 3,
});

closed_enum!(ReconstructionStatusV1 {
    NotRun = 1,
    Pass = 2,
    Failed = 3,
});

closed_enum!(FileEventV1 {
    Added = 1,
    Deleted = 2,
    UnchangedPath = 3,
    Renamed = 4,
    Moved = 5,
});

closed_enum!(ContentEventV1 {
    Unchanged = 1,
    Edited = 2,
    Added = 3,
    Deleted = 4,
    StrictReviewRequired = 5,
});

closed_enum!(DirectoryEventV1 {
    Added = 1,
    Deleted = 2,
    Renamed = 3,
    Moved = 4,
});

closed_enum!(ManifestDecisionV1 {
    Automatic = 1,
    ApprovalRequired = 2,
    Approved = 3,
    Reject = 4,
});

closed_enum!(ApprovalStateV1 {
    NotEligible = 1,
    Required = 2,
    Approved = 3,
    Stale = 4,
});

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ManifestApprovalSemanticV1 {
    TokenDeleted,
    ApprovalBearingEntry,
}

pub(crate) const fn required_manifest_event_state(
    phase: ChangedManifestPhaseV1,
    semantic: ManifestApprovalSemanticV1,
) -> Option<(ManifestDecisionV1, ApprovalStateV1)> {
    match (phase, semantic) {
        (
            ChangedManifestPhaseV1::Review,
            ManifestApprovalSemanticV1::TokenDeleted
            | ManifestApprovalSemanticV1::ApprovalBearingEntry,
        ) => Some((
            ManifestDecisionV1::ApprovalRequired,
            ApprovalStateV1::Required,
        )),
        (
            ChangedManifestPhaseV1::ApplyResult,
            ManifestApprovalSemanticV1::TokenDeleted
            | ManifestApprovalSemanticV1::ApprovalBearingEntry,
        ) => Some((ManifestDecisionV1::Approved, ApprovalStateV1::Approved)),
        (
            ChangedManifestPhaseV1::ApplyFailure,
            ManifestApprovalSemanticV1::TokenDeleted
            | ManifestApprovalSemanticV1::ApprovalBearingEntry,
        ) => None,
    }
}

// Value 3 is the historical absolute-line movement concept. Engine v3 never
// emits it and the distinct StandardV2 failures use values 10 through 13.
closed_enum!(TokenEventKindV1 {
    PreservedSameAnchor = 1,
    TokenDeleted = 2,
    TokenMovedWithinFile = 3,
    TokenMovedToOtherFile = 4,
    TokenDuplicated = 5,
    TokenModified = 6,
    TokenUnknown = 7,
    CategoryMismatch = 8,
    TokenOrderChanged = 9,
    ProtectedContextChanged = 10,
    ProtectedCoreChanged = 11,
    AnchorAmbiguous = 12,
    PathMoved = 13,
});

closed_enum!(AnchorKindV1 {
    ContentLineBlockV1 = 1,
    PathComponentV1 = 2,
    ContentExactContextV2 = 3,
});

closed_enum!(AnchorStatusV1 {
    Present = 1,
    Absent = 2,
    Mismatch = 3,
    Ambiguous = 4,
});

// Values 1..44 retain the accepted historical registry. Values 45..49 are
// new, non-reused StandardV2 distinctions allocated by the first v1 writer.
closed_enum!(ReasonCodeV1 {
    TokenDeleted = 1,
    TokenMovedWithinFile = 2,
    TokenMovedToOtherFile = 3,
    TokenDuplicated = 4,
    TokenModified = 5,
    MalformedToken = 6,
    UnknownToken = 7,
    CategoryMismatch = 8,
    AnchorMismatch = 9,
    TokenOrderChanged = 10,
    FileDeleted = 11,
    FileRenamed = 12,
    FileMoved = 13,
    DirectoryAdded = 14,
    DirectoryDeleted = 15,
    DirectoryRenamed = 16,
    DirectoryMoved = 17,
    StrictTokenFileModified = 18,
    NewTextFile = 19,
    UnsupportedAddition = 20,
    LinkLikeAddition = 21,
    GitMetadataEntry = 22,
    HardLink = 23,
    AlternateDataStream = 24,
    ShortNameAlias = 25,
    NonUnicodeComponent = 26,
    OmittedPathCollision = 27,
    CaseInsensitiveCollision = 28,
    NormalizationCollision = 29,
    ReservedWindowsName = 30,
    InvalidUtf8 = 31,
    BoundExceeded = 32,
    ChangeReportBoundExceeded = 33,
    OriginalMismatch = 34,
    WorkspaceUnstable = 35,
    CapsuleAuthFailed = 36,
    VersionIncompatible = 37,
    ApprovalStale = 38,
    NewUntokenizedSensitiveFinding = 39,
    PrivateOrphansPresent = 40,
    CandidateCollision = 41,
    CandidateIncomplete = 42,
    PostcheckFailed = 43,
    StateCommitUncertain = 44,
    PreservedSameAnchor = 45,
    ProtectedContextChanged = 46,
    ProtectedCoreChanged = 47,
    AnchorAmbiguous = 48,
    PathMoved = 49,
});

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct ManifestSummaryV1 {
    pub(crate) observed_files: u32,
    pub(crate) changed_files: u32,
    pub(crate) automatic_events: u32,
    pub(crate) approval_eligible_events: u32,
    pub(crate) approved_events: u32,
    pub(crate) unapproved_events: u32,
    pub(crate) unconditional_rejects: u32,
    pub(crate) preserved_tokens: u32,
    pub(crate) deleted_tokens: u32,
    pub(crate) new_sensitive_findings: u32,
    pub(crate) observed_directories: u32,
    pub(crate) changed_directories: u32,
    pub(crate) preserved_original_only_files: u32,
    pub(crate) preserved_original_only_bytes: u64,
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct AnchorV1 {
    pub(crate) anchor_id: [u8; 16],
    pub(crate) anchor_kind: AnchorKindV1,
    pub(crate) line_range: Option<LineRangeV1>,
    pub(crate) component_index: Option<u32>,
    pub(crate) before_status: AnchorStatusV1,
    pub(crate) after_status: AnchorStatusV1,
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct TokenEventV1 {
    pub(crate) event_id: [u8; 16],
    pub(crate) token_id: Option<[u8; 16]>,
    pub(crate) category_expected: Option<TokenCategory>,
    pub(crate) category_observed: Option<TokenCategory>,
    pub(crate) event: TokenEventKindV1,
    pub(crate) file_id_before: Option<[u8; 16]>,
    pub(crate) file_id_after: Option<[u8; 16]>,
    pub(crate) anchor_id_before: Option<[u8; 16]>,
    pub(crate) anchor_id_after: Option<[u8; 16]>,
    pub(crate) observed_count: u32,
    pub(crate) approval_state: ApprovalStateV1,
    pub(crate) decision: ManifestDecisionV1,
    pub(crate) reason_codes: Vec<ReasonCodeV1>,
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct FileChangeV1 {
    pub(crate) file_id: [u8; 16],
    pub(crate) original_relative_path: Option<String>,
    pub(crate) safe_path_before: Option<String>,
    pub(crate) safe_path_after: Option<String>,
    pub(crate) file_event: FileEventV1,
    pub(crate) content_event: ContentEventV1,
    pub(crate) content_change_regions: Vec<ContentChangeRegionV1>,
    pub(crate) anchors: Vec<AnchorV1>,
    pub(crate) token_events: Vec<TokenEventV1>,
    pub(crate) decision: ManifestDecisionV1,
    pub(crate) reason_codes: Vec<ReasonCodeV1>,
    pub(crate) approval_state: ApprovalStateV1,
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct DirectoryChangeV1 {
    pub(crate) directory_id: [u8; 16],
    pub(crate) original_relative_path: Option<String>,
    pub(crate) safe_path_before: Option<String>,
    pub(crate) safe_path_after: Option<String>,
    pub(crate) directory_event: DirectoryEventV1,
    pub(crate) token_events: Vec<TokenEventV1>,
    pub(crate) decision: ManifestDecisionV1,
    pub(crate) approval_state: ApprovalStateV1,
    pub(crate) reason_codes: Vec<ReasonCodeV1>,
}

/// Contains confidential relative paths and deliberately has no `Debug` or
/// `Display` implementation.
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct ChangedManifestV1 {
    pub(crate) manifest_phase: ChangedManifestPhaseV1,
    pub(crate) session_id: [u8; 16],
    pub(crate) review_id: [u8; 16],
    pub(crate) capsule_generation: u64,
    pub(crate) review_profile: ReviewProfile,
    pub(crate) ruleset_id: String,
    pub(crate) original_tree_consistency: OriginalTreeConsistencyV1,
    pub(crate) edited_tree_commitment: [u8; 32],
    pub(crate) event_set_commitment: [u8; 32],
    pub(crate) reconstruction_status: ReconstructionStatusV1,
    pub(crate) semantic_safety_assessed: bool,
    pub(crate) summary: ManifestSummaryV1,
    pub(crate) files: Vec<FileChangeV1>,
    pub(crate) failure_reason_codes: Vec<ReasonCodeV1>,
    pub(crate) directories: Vec<DirectoryChangeV1>,
}

impl ChangedManifestV1 {
    pub(crate) fn encode_canonical(&self) -> Result<Vec<u8>> {
        validate_changed_manifest_v1(self)?;
        self.encode_canonical_unchecked()
    }

    fn encode_canonical_unchecked(&self) -> Result<Vec<u8>> {
        let mut encoder = CborEncoder::new(MAX_MANIFEST_PLAINTEXT_BYTES)?;
        encoder.map(19)?;
        encoder.value(&1u8)?;
        encoder.value(&MANIFEST_SCHEMA_VERSION)?;
        encoder.value(&2u8)?;
        encoder.value(&self.manifest_phase.code())?;
        encoder.value(&3u8)?;
        encoder.bytes(&self.session_id)?;
        encoder.value(&4u8)?;
        encoder.bytes(&self.review_id)?;
        encoder.value(&5u8)?;
        encoder.value(&self.capsule_generation)?;
        encoder.value(&6u8)?;
        encoder.value(&review_profile_code(self.review_profile))?;
        encoder.value(&7u8)?;
        encoder.value(&ENGINE_VERSION)?;
        encoder.value(&8u8)?;
        encoder.value(&POLICY_ID)?;
        encoder.value(&9u8)?;
        encoder.value(&self.ruleset_id.as_str())?;
        encoder.value(&10u8)?;
        encoder.value(&TOKEN_SUITE_ID)?;
        encoder.value(&11u8)?;
        encoder.value(&self.original_tree_consistency.code())?;
        encoder.value(&12u8)?;
        encoder.bytes(&self.edited_tree_commitment)?;
        encoder.value(&13u8)?;
        encoder.bytes(&self.event_set_commitment)?;
        encoder.value(&14u8)?;
        encoder.value(&self.reconstruction_status.code())?;
        encoder.value(&15u8)?;
        encoder.value(&self.semantic_safety_assessed)?;
        encoder.value(&16u8)?;
        encode_summary(&mut encoder, &self.summary)?;
        encoder.value(&17u8)?;
        encoder.array(self.files.len())?;
        for file in &self.files {
            encode_file(&mut encoder, file)?;
        }
        encoder.value(&18u8)?;
        encode_reasons(&mut encoder, &self.failure_reason_codes)?;
        encoder.value(&19u8)?;
        encoder.array(self.directories.len())?;
        for directory in &self.directories {
            encode_directory(&mut encoder, directory)?;
        }
        Ok(encoder.finish())
    }

    pub(crate) fn decode_canonical(input: &[u8]) -> Result<Self> {
        let mut reader = CborReader::new_bounded(input, MAX_MANIFEST_PLAINTEXT_BYTES)?;
        reader.map_exact(19)?;
        reader.key(1)?;
        let schema: u64 = reader.decode()?;
        if schema != u64::from(MANIFEST_SCHEMA_VERSION) {
            return Err(Error::InvalidSchema);
        }
        reader.key(2)?;
        let manifest_phase =
            ChangedManifestPhaseV1::parse(reader.decode()?).ok_or(Error::InvalidSchema)?;
        reader.key(3)?;
        let session_id = reader.fixed()?;
        reader.key(4)?;
        let review_id = reader.fixed()?;
        reader.key(5)?;
        let capsule_generation = reader.decode()?;
        reader.key(6)?;
        let review_profile = ReviewProfile::parse(reader.decode()?).ok_or(Error::InvalidSchema)?;
        reader.key(7)?;
        if reader.text()? != ENGINE_VERSION {
            return Err(Error::InvalidSchema);
        }
        reader.key(8)?;
        if reader.text()? != POLICY_ID {
            return Err(Error::InvalidSchema);
        }
        reader.key(9)?;
        let ruleset_id = reader.text()?;
        reader.key(10)?;
        let suite: u64 = reader.decode()?;
        if suite != u64::from(TOKEN_SUITE_ID) {
            return Err(Error::InvalidSchema);
        }
        reader.key(11)?;
        let original_tree_consistency =
            OriginalTreeConsistencyV1::parse(reader.decode()?).ok_or(Error::InvalidSchema)?;
        reader.key(12)?;
        let edited_tree_commitment = reader.fixed()?;
        reader.key(13)?;
        let event_set_commitment = reader.fixed()?;
        reader.key(14)?;
        let reconstruction_status =
            ReconstructionStatusV1::parse(reader.decode()?).ok_or(Error::InvalidSchema)?;
        reader.key(15)?;
        let semantic_safety_assessed = reader.decode()?;
        reader.key(16)?;
        let summary = decode_summary(&mut reader)?;
        reader.key(17)?;
        let file_count = reader.array_bounded(MAX_CHANGED_ENTRIES)?;
        let mut files = Vec::new();
        files
            .try_reserve_exact(file_count)
            .map_err(|_| Error::BoundExceeded)?;
        for _ in 0..file_count {
            files.push(decode_file(&mut reader)?);
        }
        reader.key(18)?;
        let failure_reason_codes = decode_reasons(&mut reader)?;
        reader.key(19)?;
        let remaining = MAX_CHANGED_ENTRIES
            .checked_sub(file_count)
            .ok_or(Error::BoundExceeded)?;
        let directory_count = reader.array_bounded(remaining)?;
        let mut directories = Vec::new();
        directories
            .try_reserve_exact(directory_count)
            .map_err(|_| Error::BoundExceeded)?;
        for _ in 0..directory_count {
            directories.push(decode_directory(&mut reader)?);
        }
        if !reader.finished() {
            return Err(Error::InvalidSchema);
        }
        let value = Self {
            manifest_phase,
            session_id,
            review_id,
            capsule_generation,
            review_profile,
            ruleset_id,
            original_tree_consistency,
            edited_tree_commitment,
            event_set_commitment,
            reconstruction_status,
            semantic_safety_assessed,
            summary,
            files,
            failure_reason_codes,
            directories,
        };
        validate_changed_manifest_v1(&value)?;
        if value.encode_canonical_unchecked()?.as_slice() != input {
            return Err(Error::InvalidSchema);
        }
        Ok(value)
    }
}

pub(crate) fn validate_changed_manifest_v1(value: &ChangedManifestV1) -> Result<()> {
    let maximum_events = u32::try_from(MAX_CANONICAL_EVENTS).map_err(|_| Error::BoundExceeded)?;
    let counted_events = value
        .summary
        .automatic_events
        .checked_add(value.summary.approval_eligible_events)
        .and_then(|count| count.checked_add(value.summary.unconditional_rejects))
        .ok_or(Error::BoundExceeded)?;
    if value.capsule_generation == 0
        || !value.review_profile.is_current()
        || !valid_ruleset_id(&value.ruleset_id)
        || value.semantic_safety_assessed
        || value
            .files
            .len()
            .checked_add(value.directories.len())
            .is_none_or(|count| count > MAX_CHANGED_ENTRIES)
        || value.summary.approval_eligible_events > 32_768
        || counted_events > maximum_events
        || value.summary.preserved_tokens > value.summary.automatic_events
        || value.summary.deleted_tokens > value.summary.approval_eligible_events
        || value.summary.new_sensitive_findings > value.summary.unconditional_rejects
    {
        return Err(Error::InvalidState);
    }
    validate_sorted_reasons(&value.failure_reason_codes)?;
    match value.manifest_phase {
        ChangedManifestPhaseV1::Review => {
            if value.original_tree_consistency != OriginalTreeConsistencyV1::Match
                || value.reconstruction_status != ReconstructionStatusV1::NotRun
                || !value.failure_reason_codes.is_empty()
                || value.summary.approved_events != 0
                || value.summary.unapproved_events != value.summary.approval_eligible_events
                || value.summary.preserved_original_only_files != 0
                || value.summary.preserved_original_only_bytes != 0
            {
                return Err(Error::InvalidState);
            }
        }
        ChangedManifestPhaseV1::ApplyResult => {
            if value.original_tree_consistency != OriginalTreeConsistencyV1::Match
                || value.reconstruction_status != ReconstructionStatusV1::Pass
                || !value.failure_reason_codes.is_empty()
            {
                return Err(Error::InvalidState);
            }
        }
        ChangedManifestPhaseV1::ApplyFailure => {
            if value.reconstruction_status != ReconstructionStatusV1::Failed
                || value.failure_reason_codes.is_empty()
            {
                return Err(Error::InvalidState);
            }
        }
    }
    if usize::try_from(value.summary.changed_files).ok() != Some(value.files.len())
        || usize::try_from(value.summary.changed_directories).ok() != Some(value.directories.len())
        || value.summary.changed_files > value.summary.observed_files
        || value.summary.changed_directories > value.summary.observed_directories
        || value.summary.approved_events > value.summary.approval_eligible_events
        || value.summary.unapproved_events > value.summary.approval_eligible_events
        || value
            .summary
            .approved_events
            .checked_add(value.summary.unapproved_events)
            != Some(value.summary.approval_eligible_events)
    {
        return Err(Error::InvalidState);
    }

    let mut prior_file = None;
    let mut prior_directory = None;
    let mut entry_ids = BTreeSet::new();
    let mut event_ids = BTreeSet::new();
    let mut token_ids = BTreeSet::new();
    let mut anchor_ids = BTreeSet::new();
    let mut total_regions = 0usize;
    let mut deleted_tokens = 0u32;
    let mut projected_preserved = 0u32;
    let mut projected_sensitive = 0u32;
    let mut projected_automatic_token_events = 0u32;
    let mut projected_reject_token_events = 0u32;
    let mut has_automatic_entry = false;
    let mut has_approval_entry = false;
    let mut has_reject_entry = false;
    for file in &value.files {
        if prior_file.is_some_and(|prior: [u8; 16]| prior >= file.file_id)
            || !entry_ids.insert(file.file_id)
        {
            return Err(Error::InvalidState);
        }
        prior_file = Some(file.file_id);
        validate_file(file, value.manifest_phase)?;
        match file.decision {
            ManifestDecisionV1::Automatic => has_automatic_entry = true,
            ManifestDecisionV1::ApprovalRequired | ManifestDecisionV1::Approved => {
                has_approval_entry = true;
            }
            ManifestDecisionV1::Reject => has_reject_entry = true,
        }
        total_regions = total_regions
            .checked_add(file.content_change_regions.len())
            .ok_or(Error::BoundExceeded)?;
        for event in &file.token_events {
            if !event_ids.insert(event.event_id)
                || event
                    .token_id
                    .is_some_and(|token_id| !token_ids.insert(token_id))
            {
                return Err(Error::InvalidState);
            }
            match event.decision {
                ManifestDecisionV1::Automatic => {
                    projected_automatic_token_events = projected_automatic_token_events
                        .checked_add(1)
                        .ok_or(Error::BoundExceeded)?;
                }
                ManifestDecisionV1::ApprovalRequired | ManifestDecisionV1::Approved => {}
                ManifestDecisionV1::Reject => {
                    projected_reject_token_events = projected_reject_token_events
                        .checked_add(1)
                        .ok_or(Error::BoundExceeded)?;
                }
            }
            match event.event {
                TokenEventKindV1::TokenDeleted => {
                    deleted_tokens = deleted_tokens.checked_add(1).ok_or(Error::BoundExceeded)?;
                }
                TokenEventKindV1::PreservedSameAnchor => {
                    projected_preserved = projected_preserved
                        .checked_add(1)
                        .ok_or(Error::BoundExceeded)?;
                }
                _ => {}
            }
        }
        for anchor in &file.anchors {
            if !anchor_ids.insert(anchor.anchor_id) {
                return Err(Error::InvalidState);
            }
        }
        if file
            .reason_codes
            .contains(&ReasonCodeV1::NewUntokenizedSensitiveFinding)
        {
            projected_sensitive = projected_sensitive
                .checked_add(1)
                .ok_or(Error::BoundExceeded)?;
        }
    }
    for directory in &value.directories {
        if prior_directory.is_some_and(|prior: [u8; 16]| prior >= directory.directory_id)
            || !entry_ids.insert(directory.directory_id)
        {
            return Err(Error::InvalidState);
        }
        prior_directory = Some(directory.directory_id);
        validate_directory(directory, value.manifest_phase)?;
        match directory.decision {
            ManifestDecisionV1::Automatic => has_automatic_entry = true,
            ManifestDecisionV1::ApprovalRequired | ManifestDecisionV1::Approved => {
                has_approval_entry = true;
            }
            ManifestDecisionV1::Reject => has_reject_entry = true,
        }
        for event in &directory.token_events {
            if !event_ids.insert(event.event_id)
                || event
                    .token_id
                    .is_some_and(|token_id| !token_ids.insert(token_id))
            {
                return Err(Error::InvalidState);
            }
            match event.decision {
                ManifestDecisionV1::Automatic => {
                    projected_automatic_token_events = projected_automatic_token_events
                        .checked_add(1)
                        .ok_or(Error::BoundExceeded)?;
                }
                ManifestDecisionV1::ApprovalRequired | ManifestDecisionV1::Approved => {}
                ManifestDecisionV1::Reject => {
                    projected_reject_token_events = projected_reject_token_events
                        .checked_add(1)
                        .ok_or(Error::BoundExceeded)?;
                }
            }
            match event.event {
                TokenEventKindV1::TokenDeleted => {
                    deleted_tokens = deleted_tokens.checked_add(1).ok_or(Error::BoundExceeded)?;
                }
                TokenEventKindV1::PreservedSameAnchor => {
                    projected_preserved = projected_preserved
                        .checked_add(1)
                        .ok_or(Error::BoundExceeded)?;
                }
                _ => {}
            }
        }
        if directory
            .reason_codes
            .contains(&ReasonCodeV1::NewUntokenizedSensitiveFinding)
        {
            projected_sensitive = projected_sensitive
                .checked_add(1)
                .ok_or(Error::BoundExceeded)?;
        }
    }
    if total_regions > MAX_REGIONS_PER_REVIEW
        || deleted_tokens != value.summary.deleted_tokens
        || projected_preserved > value.summary.preserved_tokens
        || projected_sensitive != value.summary.new_sensitive_findings
        || projected_automatic_token_events > value.summary.automatic_events
        || projected_reject_token_events > value.summary.unconditional_rejects
        || (has_automatic_entry && value.summary.automatic_events == 0)
        || (has_approval_entry && value.summary.approval_eligible_events == 0)
        || (has_reject_entry && value.summary.unconditional_rejects == 0)
    {
        return Err(Error::InvalidState);
    }
    validate_approval_summary_reconciliation(value)
}

fn file_represents_approval_target(value: &FileChangeV1) -> bool {
    value.file_event == FileEventV1::Deleted
        || value.content_event == ContentEventV1::StrictReviewRequired
}

fn token_represents_approval_target(value: &TokenEventV1) -> bool {
    value.event == TokenEventKindV1::TokenDeleted
}

fn represented_approval_target_count(value: &ChangedManifestV1) -> Result<u32> {
    // This is report reconciliation only. The closed whitelist mirrors the
    // three classification/approval approval classes without deriving authority from parent
    // presentation decisions: FileDeleted, StrictTokenFileModified, and every
    // individually identified TokenDeleted event.
    let mut count = 0u32;
    for file in &value.files {
        if file_represents_approval_target(file) {
            count = count.checked_add(1).ok_or(Error::BoundExceeded)?;
        }
        for event in &file.token_events {
            if token_represents_approval_target(event) {
                count = count.checked_add(1).ok_or(Error::BoundExceeded)?;
            }
        }
    }
    for directory in &value.directories {
        for event in &directory.token_events {
            if token_represents_approval_target(event) {
                count = count.checked_add(1).ok_or(Error::BoundExceeded)?;
            }
        }
    }
    Ok(count)
}

fn validate_approval_summary_reconciliation(value: &ChangedManifestV1) -> Result<()> {
    let summary = &value.summary;
    let reconciled = match value.manifest_phase {
        ChangedManifestPhaseV1::Review => {
            let exact_targets = represented_approval_target_count(value)?;
            summary.approval_eligible_events == exact_targets
                && summary.approved_events == 0
                && summary.unapproved_events == exact_targets
        }
        ChangedManifestPhaseV1::ApplyResult => {
            let exact_targets = represented_approval_target_count(value)?;
            summary.approval_eligible_events == exact_targets
                && summary.approved_events == exact_targets
                && summary.unapproved_events == 0
        }
        // Preserve the already accepted v1 APPLY_FAILURE summary contract. The
        // current apply runtime does not emit this manifest phase.
        ChangedManifestPhaseV1::ApplyFailure => return Ok(()),
    };
    reconciled.then_some(()).ok_or(Error::InvalidState)
}

fn validate_file(value: &FileChangeV1, phase: ChangedManifestPhaseV1) -> Result<()> {
    validate_path_shape(value.original_relative_path.as_deref())?;
    validate_path_shape(value.safe_path_before.as_deref())?;
    validate_path_shape(value.safe_path_after.as_deref())?;
    validate_sorted_reasons(&value.reason_codes)?;
    if phase == ChangedManifestPhaseV1::Review
        && value
            .reason_codes
            .iter()
            .any(|reason| !review_file_reason(*reason))
    {
        return Err(Error::InvalidState);
    }
    if value.content_change_regions.len() > MAX_REGIONS_PER_FILE
        || value.anchors.len() > MAX_ANCHORS_PER_ENTRY
        || value.token_events.len() > MAX_TOKEN_EVENTS_PER_ENTRY
    {
        return Err(Error::BoundExceeded);
    }
    match value.file_event {
        FileEventV1::Added => {
            if value.original_relative_path.is_some()
                || value.safe_path_before.is_some()
                || value.safe_path_after.is_none()
            {
                return Err(Error::InvalidState);
            }
        }
        FileEventV1::Deleted => {
            if value.original_relative_path.is_none()
                || value.safe_path_before.is_none()
                || value.safe_path_after.is_some()
            {
                return Err(Error::InvalidState);
            }
        }
        FileEventV1::UnchangedPath => {
            if value.original_relative_path.is_none()
                || value.safe_path_before.is_none()
                || value.safe_path_before != value.safe_path_after
            {
                return Err(Error::InvalidState);
            }
        }
        FileEventV1::Renamed | FileEventV1::Moved => {
            if value.original_relative_path.is_none()
                || value.safe_path_before.is_none()
                || value.safe_path_after.is_none()
                || value.safe_path_before == value.safe_path_after
            {
                return Err(Error::InvalidState);
            }
        }
    }
    let regions_valid = match value.content_event {
        ContentEventV1::Unchanged => value.content_change_regions.is_empty(),
        ContentEventV1::Edited => !value.content_change_regions.is_empty(),
        ContentEventV1::Added => matches!(
            value.content_change_regions.as_slice(),
            [region]
                if region.kind == ContentChangeKindV1::Insert
                    && region.before_range.start_line == 1
                    && region.before_range.end_line_exclusive == 1
                    && region.after_range.start_line == 1
        ),
        ContentEventV1::Deleted => matches!(
            value.content_change_regions.as_slice(),
            [region]
                if region.kind == ContentChangeKindV1::Delete
                    && region.before_range.start_line == 1
                    && region.after_range.start_line == 1
                    && region.after_range.end_line_exclusive == 1
        ),
        // Strict may be triggered by either a byte edit or an accepted exact
        // path-token deletion projection, so its reporting region list is
        // independently empty or nonempty.
        ContentEventV1::StrictReviewRequired => true,
    };
    let path_content_valid = match value.file_event {
        FileEventV1::Added => {
            value.content_event == ContentEventV1::Added
                || (value.content_event == ContentEventV1::Unchanged
                    && value.decision == ManifestDecisionV1::Reject
                    && value.reason_codes.iter().any(|reason| {
                        matches!(
                            reason,
                            ReasonCodeV1::LinkLikeAddition
                                | ReasonCodeV1::HardLink
                                | ReasonCodeV1::AlternateDataStream
                                | ReasonCodeV1::ReservedWindowsName
                        )
                    }))
        }
        FileEventV1::Deleted => value.content_event == ContentEventV1::Deleted,
        FileEventV1::UnchangedPath | FileEventV1::Renamed | FileEventV1::Moved => !matches!(
            value.content_event,
            ContentEventV1::Added | ContentEventV1::Deleted
        ),
    };
    if !regions_valid
        || !path_content_valid
        || (value.file_event == FileEventV1::UnchangedPath
            && value.content_event == ContentEventV1::Unchanged
            && value
                .token_events
                .iter()
                .all(|event| event.event == TokenEventKindV1::PreservedSameAnchor)
            && value.reason_codes.is_empty())
    {
        return Err(Error::InvalidState);
    }
    validate_regions(&value.content_change_regions)?;
    validate_anchors(&value.anchors)?;
    validate_token_events(&value.token_events, phase)?;
    if file_represents_approval_target(value)
        && required_manifest_event_state(phase, ManifestApprovalSemanticV1::ApprovalBearingEntry)
            .is_some_and(|required| required != (value.decision, value.approval_state))
    {
        return Err(Error::InvalidState);
    }
    validate_decision(value.decision, value.approval_state, phase)
}

fn validate_directory(value: &DirectoryChangeV1, phase: ChangedManifestPhaseV1) -> Result<()> {
    validate_path_shape(value.original_relative_path.as_deref())?;
    validate_path_shape(value.safe_path_before.as_deref())?;
    validate_path_shape(value.safe_path_after.as_deref())?;
    validate_sorted_reasons(&value.reason_codes)?;
    if phase == ChangedManifestPhaseV1::Review
        && value
            .reason_codes
            .iter()
            .any(|reason| !review_directory_reason(*reason))
    {
        return Err(Error::InvalidState);
    }
    if value.token_events.len() > MAX_TOKEN_EVENTS_PER_ENTRY {
        return Err(Error::BoundExceeded);
    }
    match value.directory_event {
        DirectoryEventV1::Added => {
            if value.original_relative_path.is_some()
                || value.safe_path_before.is_some()
                || value.safe_path_after.is_none()
            {
                return Err(Error::InvalidState);
            }
        }
        DirectoryEventV1::Deleted => {
            if value.original_relative_path.is_none()
                || value.safe_path_before.is_none()
                || value.safe_path_after.is_some()
            {
                return Err(Error::InvalidState);
            }
        }
        DirectoryEventV1::Renamed | DirectoryEventV1::Moved => {
            if value.original_relative_path.is_none()
                || value.safe_path_before.is_none()
                || value.safe_path_after.is_none()
                || value.safe_path_before == value.safe_path_after
            {
                return Err(Error::InvalidState);
            }
        }
    }
    validate_token_events(&value.token_events, phase)?;
    if value.decision == ManifestDecisionV1::ApprovalRequired
        && value.approval_state == ApprovalStateV1::NotEligible
    {
        // A directory may inherit an approval requirement from a child file
        // without becoming a directory-wide approval target.
        Ok(())
    } else {
        validate_decision(value.decision, value.approval_state, phase)
    }
}

const fn review_file_reason(value: ReasonCodeV1) -> bool {
    matches!(
        value,
        ReasonCodeV1::FileDeleted
            | ReasonCodeV1::FileRenamed
            | ReasonCodeV1::FileMoved
            | ReasonCodeV1::StrictTokenFileModified
            | ReasonCodeV1::NewTextFile
            | ReasonCodeV1::UnsupportedAddition
            | ReasonCodeV1::LinkLikeAddition
            | ReasonCodeV1::HardLink
            | ReasonCodeV1::AlternateDataStream
            | ReasonCodeV1::OmittedPathCollision
            | ReasonCodeV1::ReservedWindowsName
            | ReasonCodeV1::InvalidUtf8
            | ReasonCodeV1::NewUntokenizedSensitiveFinding
    )
}

const fn review_directory_reason(value: ReasonCodeV1) -> bool {
    matches!(
        value,
        ReasonCodeV1::DirectoryAdded
            | ReasonCodeV1::DirectoryDeleted
            | ReasonCodeV1::DirectoryRenamed
            | ReasonCodeV1::DirectoryMoved
            | ReasonCodeV1::OmittedPathCollision
            | ReasonCodeV1::ReservedWindowsName
            | ReasonCodeV1::NewUntokenizedSensitiveFinding
    )
}

fn validate_decision(
    decision: ManifestDecisionV1,
    approval: ApprovalStateV1,
    phase: ChangedManifestPhaseV1,
) -> Result<()> {
    let tuple = (decision, approval);
    let structural = matches!(
        tuple,
        (ManifestDecisionV1::Automatic, ApprovalStateV1::NotEligible)
            | (ManifestDecisionV1::Reject, ApprovalStateV1::NotEligible)
    );
    let approval_bearing = match phase {
        ChangedManifestPhaseV1::Review | ChangedManifestPhaseV1::ApplyResult => {
            required_manifest_event_state(phase, ManifestApprovalSemanticV1::ApprovalBearingEntry)
                == Some(tuple)
        }
        // APPLY_FAILURE is not emitted by the current apply runtime. Preserve
        // its accepted v1 record tuples; TokenDeleted has a separate closed
        // phase contract below and remains forbidden in this phase.
        ChangedManifestPhaseV1::ApplyFailure => matches!(
            tuple,
            (
                ManifestDecisionV1::ApprovalRequired,
                ApprovalStateV1::Required
            ) | (ManifestDecisionV1::Approved, ApprovalStateV1::Approved)
        ),
    };
    let valid = structural || approval_bearing;
    valid.then_some(()).ok_or(Error::InvalidState)
}

fn validate_token_events(values: &[TokenEventV1], phase: ChangedManifestPhaseV1) -> Result<()> {
    let mut prior = None;
    for value in values {
        if prior.is_some_and(|prior: [u8; 16]| prior >= value.event_id) {
            return Err(Error::InvalidState);
        }
        prior = Some(value.event_id);
        validate_token_event(value, phase)?;
    }
    Ok(())
}

fn validate_token_event(value: &TokenEventV1, phase: ChangedManifestPhaseV1) -> Result<()> {
    validate_sorted_reasons(&value.reason_codes)?;
    if value.token_id.is_none() != value.category_expected.is_none() {
        return Err(Error::InvalidState);
    }
    if value.event == TokenEventKindV1::TokenUnknown {
        if value.token_id.is_some()
            || value.category_expected.is_some()
            || value.decision != ManifestDecisionV1::Reject
            || value.approval_state != ApprovalStateV1::NotEligible
        {
            return Err(Error::InvalidState);
        }
    } else if value.token_id.is_none() || value.category_expected.is_none() {
        return Err(Error::InvalidState);
    }
    if matches!(value.event, TokenEventKindV1::TokenMovedWithinFile) {
        return Err(Error::InvalidState);
    }
    let expected = match value.event {
        TokenEventKindV1::PreservedSameAnchor => {
            (ManifestDecisionV1::Automatic, ApprovalStateV1::NotEligible)
        }
        TokenEventKindV1::TokenDeleted => {
            required_manifest_event_state(phase, ManifestApprovalSemanticV1::TokenDeleted)
                .ok_or(Error::InvalidState)?
        }
        TokenEventKindV1::TokenUnknown
        | TokenEventKindV1::TokenMovedToOtherFile
        | TokenEventKindV1::TokenDuplicated
        | TokenEventKindV1::TokenModified
        | TokenEventKindV1::CategoryMismatch
        | TokenEventKindV1::TokenOrderChanged
        | TokenEventKindV1::ProtectedContextChanged
        | TokenEventKindV1::ProtectedCoreChanged
        | TokenEventKindV1::AnchorAmbiguous
        | TokenEventKindV1::PathMoved => (ManifestDecisionV1::Reject, ApprovalStateV1::NotEligible),
        TokenEventKindV1::TokenMovedWithinFile => return Err(Error::InvalidState),
    };
    if (value.decision, value.approval_state) != expected {
        return Err(Error::InvalidState);
    }
    if value.event == TokenEventKindV1::CategoryMismatch && value.category_expected.is_none() {
        return Err(Error::InvalidState);
    }
    validate_token_reason_codes(value)?;
    validate_decision(value.decision, value.approval_state, phase)
}

fn validate_token_reason_codes(value: &TokenEventV1) -> Result<()> {
    let primary = match value.event {
        TokenEventKindV1::PreservedSameAnchor => ReasonCodeV1::PreservedSameAnchor,
        TokenEventKindV1::TokenDeleted => ReasonCodeV1::TokenDeleted,
        TokenEventKindV1::TokenMovedWithinFile => return Err(Error::InvalidState),
        TokenEventKindV1::TokenMovedToOtherFile => ReasonCodeV1::TokenMovedToOtherFile,
        TokenEventKindV1::TokenDuplicated => ReasonCodeV1::TokenDuplicated,
        TokenEventKindV1::TokenModified => ReasonCodeV1::TokenModified,
        TokenEventKindV1::TokenUnknown => ReasonCodeV1::UnknownToken,
        TokenEventKindV1::CategoryMismatch => ReasonCodeV1::CategoryMismatch,
        TokenEventKindV1::TokenOrderChanged => ReasonCodeV1::TokenOrderChanged,
        TokenEventKindV1::ProtectedContextChanged => ReasonCodeV1::ProtectedContextChanged,
        TokenEventKindV1::ProtectedCoreChanged => ReasonCodeV1::ProtectedCoreChanged,
        TokenEventKindV1::AnchorAmbiguous => ReasonCodeV1::AnchorAmbiguous,
        TokenEventKindV1::PathMoved => ReasonCodeV1::PathMoved,
    };
    let malformed_allowed = matches!(
        value.event,
        TokenEventKindV1::TokenModified | TokenEventKindV1::TokenUnknown
    );
    if !value.reason_codes.contains(&primary)
        || value.reason_codes.iter().any(|reason| {
            *reason != primary && !(malformed_allowed && *reason == ReasonCodeV1::MalformedToken)
        })
        || value.reason_codes.len() > usize::from(malformed_allowed) + 1
    {
        return Err(Error::InvalidState);
    }
    Ok(())
}

fn validate_anchors(values: &[AnchorV1]) -> Result<()> {
    let mut prior = None;
    for value in values {
        if prior.is_some_and(|prior: [u8; 16]| prior >= value.anchor_id)
            || value.before_status == AnchorStatusV1::Mismatch
            || value.before_status == AnchorStatusV1::Ambiguous
        {
            return Err(Error::InvalidState);
        }
        prior = Some(value.anchor_id);
        match value.anchor_kind {
            AnchorKindV1::ContentExactContextV2 => {
                if value.line_range.is_none() || value.component_index.is_some() {
                    return Err(Error::InvalidState);
                }
            }
            AnchorKindV1::PathComponentV1 => {
                if value.line_range.is_some() || value.component_index.is_none() {
                    return Err(Error::InvalidState);
                }
            }
            AnchorKindV1::ContentLineBlockV1 => return Err(Error::InvalidState),
        }
        if let Some(range) = value.line_range {
            validate_line_range(range)?;
        }
    }
    Ok(())
}

fn validate_regions(values: &[ContentChangeRegionV1]) -> Result<()> {
    let mut prior: Option<&ContentChangeRegionV1> = None;
    for value in values {
        validate_line_range(value.before_range)?;
        validate_line_range(value.after_range)?;
        let before_empty = value.before_range.start_line == value.before_range.end_line_exclusive;
        let after_empty = value.after_range.start_line == value.after_range.end_line_exclusive;
        let valid = match value.kind {
            ContentChangeKindV1::Insert => before_empty && !after_empty,
            ContentChangeKindV1::Delete => !before_empty && after_empty,
            ContentChangeKindV1::Replace => !before_empty && !after_empty,
        };
        if !valid {
            return Err(Error::InvalidState);
        }
        if prior.is_some_and(|previous| {
            value.before_range.start_line <= previous.before_range.end_line_exclusive
                || value.after_range.start_line <= previous.after_range.end_line_exclusive
        }) {
            return Err(Error::InvalidState);
        }
        prior = Some(value);
    }
    Ok(())
}

fn validate_line_range(value: LineRangeV1) -> Result<()> {
    let maximum_endpoint = u32::try_from(
        MAX_LOGICAL_LINES_PER_SIDE
            .checked_add(1)
            .ok_or(Error::BoundExceeded)?,
    )
    .map_err(|_| Error::BoundExceeded)?;
    if value.start_line == 0
        || value.start_line > value.end_line_exclusive
        || value.end_line_exclusive > maximum_endpoint
    {
        Err(Error::InvalidState)
    } else {
        Ok(())
    }
}

fn validate_path_shape(path: Option<&str>) -> Result<()> {
    let Some(path) = path else {
        return Ok(());
    };
    if path.is_empty()
        || path.len() > MAX_MANIFEST_PATH_BYTES
        || path.starts_with('/')
        || path.ends_with('/')
        || path.chars().any(|character| {
            character <= '\u{1f}'
                || matches!(
                    character,
                    '\\' | '\0' | ':' | '*' | '?' | '"' | '<' | '>' | '|'
                )
        })
    {
        return Err(Error::InvalidState);
    }
    let mut utf16_total = 0usize;
    for component in path.split('/') {
        let utf16 = component.encode_utf16().count();
        utf16_total = utf16_total
            .checked_add(utf16)
            .and_then(|total| total.checked_add(usize::from(utf16_total != 0)))
            .ok_or(Error::BoundExceeded)?;
        if component.is_empty()
            || matches!(component, "." | "..")
            || component.ends_with(['.', ' '])
            || utf16 == 0
            || utf16 > 255
            || is_dos_device_basename(component)
        {
            return Err(Error::InvalidState);
        }
    }
    if utf16_total > 32_000 {
        return Err(Error::InvalidState);
    }
    Ok(())
}

fn is_dos_device_basename(component: &str) -> bool {
    let basename = component
        .split('.')
        .next()
        .unwrap_or(component)
        .trim_end_matches(['.', ' ']);
    if basename.eq_ignore_ascii_case("CON")
        || basename.eq_ignore_ascii_case("PRN")
        || basename.eq_ignore_ascii_case("AUX")
        || basename.eq_ignore_ascii_case("NUL")
    {
        return true;
    }
    let bytes = basename.as_bytes();
    if bytes.len() >= 4
        && bytes[..3].is_ascii()
        && (bytes[..3].eq_ignore_ascii_case(b"COM") || bytes[..3].eq_ignore_ascii_case(b"LPT"))
    {
        return matches!(
            &basename[3..],
            "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
        );
    }
    false
}

fn validate_sorted_reasons(values: &[ReasonCodeV1]) -> Result<()> {
    if values.len() > MAX_REASON_CODES || values.windows(2).any(|pair| pair[0] >= pair[1]) {
        Err(Error::InvalidState)
    } else {
        Ok(())
    }
}

fn review_profile_code(value: ReviewProfile) -> u8 {
    match value {
        ReviewProfile::StandardV1 => 1,
        ReviewProfile::StrictTokenFileV1 => 2,
        ReviewProfile::StandardV2 => 3,
        ReviewProfile::StrictTokenFilesV2 => 4,
    }
}

fn encode_optional_text(encoder: &mut CborEncoder, value: Option<&str>) -> Result<()> {
    if let Some(value) = value {
        encoder.value(&value)
    } else {
        encoder.null()
    }
}

fn decode_optional_text(reader: &mut CborReader<'_>) -> Result<Option<String>> {
    if reader.is_null() {
        reader.null()?;
        Ok(None)
    } else {
        Ok(Some(reader.text_bounded(MAX_MANIFEST_PATH_BYTES)?))
    }
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
        Ok(Some(reader.fixed()?))
    }
}

fn encode_optional_category(encoder: &mut CborEncoder, value: Option<TokenCategory>) -> Result<()> {
    if let Some(value) = value {
        encoder.value(&token_category_code(value))
    } else {
        encoder.null()
    }
}

fn decode_optional_category(reader: &mut CborReader<'_>) -> Result<Option<TokenCategory>> {
    if reader.is_null() {
        reader.null()?;
        Ok(None)
    } else {
        Ok(Some(
            TokenCategory::from_code(reader.decode()?).ok_or(Error::InvalidSchema)?,
        ))
    }
}

fn token_category_code(value: TokenCategory) -> u8 {
    match value {
        TokenCategory::Secret => 1,
        TokenCategory::Email => 2,
        TokenCategory::Phone => 3,
        TokenCategory::JapanesePhone => 4,
        TokenCategory::Ip => 5,
        TokenCategory::JapanesePostal => 6,
        TokenCategory::MyNumber => 7,
        TokenCategory::CorporateNumber => 8,
        TokenCategory::Multiple => 9,
    }
}

fn encode_summary(encoder: &mut CborEncoder, value: &ManifestSummaryV1) -> Result<()> {
    encoder.map(14)?;
    for (key, item) in [
        (1u8, u64::from(value.observed_files)),
        (2, u64::from(value.changed_files)),
        (3, u64::from(value.automatic_events)),
        (4, u64::from(value.approval_eligible_events)),
        (5, u64::from(value.approved_events)),
        (6, u64::from(value.unapproved_events)),
        (7, u64::from(value.unconditional_rejects)),
        (8, u64::from(value.preserved_tokens)),
        (9, u64::from(value.deleted_tokens)),
        (10, u64::from(value.new_sensitive_findings)),
        (11, u64::from(value.observed_directories)),
        (12, u64::from(value.changed_directories)),
        (13, u64::from(value.preserved_original_only_files)),
        (14, value.preserved_original_only_bytes),
    ] {
        encoder.value(&key)?;
        encoder.value(&item)?;
    }
    Ok(())
}

fn decode_summary(reader: &mut CborReader<'_>) -> Result<ManifestSummaryV1> {
    reader.map_exact(14)?;
    let mut next_u32 = |key| -> Result<u32> {
        reader.key(key)?;
        u32::try_from(reader.decode::<u64>()?).map_err(|_| Error::InvalidSchema)
    };
    let observed_files = next_u32(1)?;
    let changed_files = next_u32(2)?;
    let automatic_events = next_u32(3)?;
    let approval_eligible_events = next_u32(4)?;
    let approved_events = next_u32(5)?;
    let unapproved_events = next_u32(6)?;
    let unconditional_rejects = next_u32(7)?;
    let preserved_tokens = next_u32(8)?;
    let deleted_tokens = next_u32(9)?;
    let new_sensitive_findings = next_u32(10)?;
    let observed_directories = next_u32(11)?;
    let changed_directories = next_u32(12)?;
    let preserved_original_only_files = next_u32(13)?;
    reader.key(14)?;
    let preserved_original_only_bytes = reader.decode()?;
    Ok(ManifestSummaryV1 {
        observed_files,
        changed_files,
        automatic_events,
        approval_eligible_events,
        approved_events,
        unapproved_events,
        unconditional_rejects,
        preserved_tokens,
        deleted_tokens,
        new_sensitive_findings,
        observed_directories,
        changed_directories,
        preserved_original_only_files,
        preserved_original_only_bytes,
    })
}

fn encode_line_range(encoder: &mut CborEncoder, value: LineRangeV1) -> Result<()> {
    encoder.map(2)?;
    encoder.value(&1u8)?;
    encoder.value(&value.start_line)?;
    encoder.value(&2u8)?;
    encoder.value(&value.end_line_exclusive)
}

fn decode_line_range(reader: &mut CborReader<'_>) -> Result<LineRangeV1> {
    reader.map_exact(2)?;
    reader.key(1)?;
    let start_line = u32::try_from(reader.decode::<u64>()?).map_err(|_| Error::InvalidSchema)?;
    reader.key(2)?;
    let end_line_exclusive =
        u32::try_from(reader.decode::<u64>()?).map_err(|_| Error::InvalidSchema)?;
    Ok(LineRangeV1 {
        start_line,
        end_line_exclusive,
    })
}

const fn content_change_kind_code(value: ContentChangeKindV1) -> u8 {
    match value {
        ContentChangeKindV1::Insert => 1,
        ContentChangeKindV1::Delete => 2,
        ContentChangeKindV1::Replace => 3,
    }
}

const fn parse_content_change_kind(value: u64) -> Option<ContentChangeKindV1> {
    match value {
        1 => Some(ContentChangeKindV1::Insert),
        2 => Some(ContentChangeKindV1::Delete),
        3 => Some(ContentChangeKindV1::Replace),
        _ => None,
    }
}

fn encode_region(encoder: &mut CborEncoder, value: &ContentChangeRegionV1) -> Result<()> {
    encoder.map(3)?;
    encoder.value(&1u8)?;
    encoder.value(&content_change_kind_code(value.kind))?;
    encoder.value(&2u8)?;
    encode_line_range(encoder, value.before_range)?;
    encoder.value(&3u8)?;
    encode_line_range(encoder, value.after_range)
}

fn decode_region(reader: &mut CborReader<'_>) -> Result<ContentChangeRegionV1> {
    reader.map_exact(3)?;
    reader.key(1)?;
    let kind = parse_content_change_kind(reader.decode()?).ok_or(Error::InvalidSchema)?;
    reader.key(2)?;
    let before_range = decode_line_range(reader)?;
    reader.key(3)?;
    let after_range = decode_line_range(reader)?;
    Ok(ContentChangeRegionV1 {
        kind,
        before_range,
        after_range,
    })
}

fn encode_anchor(encoder: &mut CborEncoder, value: &AnchorV1) -> Result<()> {
    encoder.map(6)?;
    encoder.value(&1u8)?;
    encoder.bytes(&value.anchor_id)?;
    encoder.value(&2u8)?;
    encoder.value(&value.anchor_kind.code())?;
    encoder.value(&3u8)?;
    if let Some(range) = value.line_range {
        encode_line_range(encoder, range)?;
    } else {
        encoder.null()?;
    }
    encoder.value(&4u8)?;
    if let Some(component) = value.component_index {
        encoder.value(&component)?;
    } else {
        encoder.null()?;
    }
    encoder.value(&5u8)?;
    encoder.value(&value.before_status.code())?;
    encoder.value(&6u8)?;
    encoder.value(&value.after_status.code())
}

fn decode_anchor(reader: &mut CborReader<'_>) -> Result<AnchorV1> {
    reader.map_exact(6)?;
    reader.key(1)?;
    let anchor_id = reader.fixed()?;
    reader.key(2)?;
    let anchor_kind = AnchorKindV1::parse(reader.decode()?).ok_or(Error::InvalidSchema)?;
    reader.key(3)?;
    let line_range = if reader.is_null() {
        reader.null()?;
        None
    } else {
        Some(decode_line_range(reader)?)
    };
    reader.key(4)?;
    let component_index = if reader.is_null() {
        reader.null()?;
        None
    } else {
        Some(u32::try_from(reader.decode::<u64>()?).map_err(|_| Error::InvalidSchema)?)
    };
    reader.key(5)?;
    let before_status = AnchorStatusV1::parse(reader.decode()?).ok_or(Error::InvalidSchema)?;
    reader.key(6)?;
    let after_status = AnchorStatusV1::parse(reader.decode()?).ok_or(Error::InvalidSchema)?;
    Ok(AnchorV1 {
        anchor_id,
        anchor_kind,
        line_range,
        component_index,
        before_status,
        after_status,
    })
}

fn encode_token_event(encoder: &mut CborEncoder, value: &TokenEventV1) -> Result<()> {
    encoder.map(13)?;
    encoder.value(&1u8)?;
    encoder.bytes(&value.event_id)?;
    encoder.value(&2u8)?;
    encode_optional_fixed(encoder, value.token_id.as_ref())?;
    encoder.value(&3u8)?;
    encode_optional_category(encoder, value.category_expected)?;
    encoder.value(&4u8)?;
    encode_optional_category(encoder, value.category_observed)?;
    encoder.value(&5u8)?;
    encoder.value(&value.event.code())?;
    encoder.value(&6u8)?;
    encode_optional_fixed(encoder, value.file_id_before.as_ref())?;
    encoder.value(&7u8)?;
    encode_optional_fixed(encoder, value.file_id_after.as_ref())?;
    encoder.value(&8u8)?;
    encode_optional_fixed(encoder, value.anchor_id_before.as_ref())?;
    encoder.value(&9u8)?;
    encode_optional_fixed(encoder, value.anchor_id_after.as_ref())?;
    encoder.value(&10u8)?;
    encoder.value(&value.observed_count)?;
    encoder.value(&11u8)?;
    encoder.value(&value.approval_state.code())?;
    encoder.value(&12u8)?;
    encoder.value(&value.decision.code())?;
    encoder.value(&13u8)?;
    encode_reasons(encoder, &value.reason_codes)
}

fn decode_token_event(reader: &mut CborReader<'_>) -> Result<TokenEventV1> {
    reader.map_exact(13)?;
    reader.key(1)?;
    let event_id = reader.fixed()?;
    reader.key(2)?;
    let token_id = decode_optional_fixed(reader)?;
    reader.key(3)?;
    let category_expected = decode_optional_category(reader)?;
    reader.key(4)?;
    let category_observed = decode_optional_category(reader)?;
    reader.key(5)?;
    let event = TokenEventKindV1::parse(reader.decode()?).ok_or(Error::InvalidSchema)?;
    reader.key(6)?;
    let file_id_before = decode_optional_fixed(reader)?;
    reader.key(7)?;
    let file_id_after = decode_optional_fixed(reader)?;
    reader.key(8)?;
    let anchor_id_before = decode_optional_fixed(reader)?;
    reader.key(9)?;
    let anchor_id_after = decode_optional_fixed(reader)?;
    reader.key(10)?;
    let observed_count =
        u32::try_from(reader.decode::<u64>()?).map_err(|_| Error::InvalidSchema)?;
    reader.key(11)?;
    let approval_state = ApprovalStateV1::parse(reader.decode()?).ok_or(Error::InvalidSchema)?;
    reader.key(12)?;
    let decision = ManifestDecisionV1::parse(reader.decode()?).ok_or(Error::InvalidSchema)?;
    reader.key(13)?;
    let reason_codes = decode_reasons(reader)?;
    Ok(TokenEventV1 {
        event_id,
        token_id,
        category_expected,
        category_observed,
        event,
        file_id_before,
        file_id_after,
        anchor_id_before,
        anchor_id_after,
        observed_count,
        approval_state,
        decision,
        reason_codes,
    })
}

fn encode_file(encoder: &mut CborEncoder, value: &FileChangeV1) -> Result<()> {
    encoder.map(12)?;
    encoder.value(&1u8)?;
    encoder.bytes(&value.file_id)?;
    encoder.value(&2u8)?;
    encode_optional_text(encoder, value.original_relative_path.as_deref())?;
    encoder.value(&3u8)?;
    encode_optional_text(encoder, value.safe_path_before.as_deref())?;
    encoder.value(&4u8)?;
    encode_optional_text(encoder, value.safe_path_after.as_deref())?;
    encoder.value(&5u8)?;
    encoder.value(&value.file_event.code())?;
    encoder.value(&6u8)?;
    encoder.value(&value.content_event.code())?;
    encoder.value(&7u8)?;
    encoder.array(value.content_change_regions.len())?;
    for region in &value.content_change_regions {
        encode_region(encoder, region)?;
    }
    encoder.value(&8u8)?;
    encoder.array(value.anchors.len())?;
    for anchor in &value.anchors {
        encode_anchor(encoder, anchor)?;
    }
    encoder.value(&9u8)?;
    encoder.array(value.token_events.len())?;
    for event in &value.token_events {
        encode_token_event(encoder, event)?;
    }
    encoder.value(&10u8)?;
    encoder.value(&value.decision.code())?;
    encoder.value(&11u8)?;
    encode_reasons(encoder, &value.reason_codes)?;
    encoder.value(&12u8)?;
    encoder.value(&value.approval_state.code())
}

fn decode_file(reader: &mut CborReader<'_>) -> Result<FileChangeV1> {
    reader.map_exact(12)?;
    reader.key(1)?;
    let file_id = reader.fixed()?;
    reader.key(2)?;
    let original_relative_path = decode_optional_text(reader)?;
    reader.key(3)?;
    let safe_path_before = decode_optional_text(reader)?;
    reader.key(4)?;
    let safe_path_after = decode_optional_text(reader)?;
    reader.key(5)?;
    let file_event = FileEventV1::parse(reader.decode()?).ok_or(Error::InvalidSchema)?;
    reader.key(6)?;
    let content_event = ContentEventV1::parse(reader.decode()?).ok_or(Error::InvalidSchema)?;
    reader.key(7)?;
    let region_count = reader.array_bounded(MAX_REGIONS_PER_FILE)?;
    let mut content_change_regions = Vec::new();
    content_change_regions
        .try_reserve_exact(region_count)
        .map_err(|_| Error::BoundExceeded)?;
    for _ in 0..region_count {
        content_change_regions.push(decode_region(reader)?);
    }
    reader.key(8)?;
    let anchor_count = reader.array_bounded(MAX_ANCHORS_PER_ENTRY)?;
    let mut anchors = Vec::new();
    anchors
        .try_reserve_exact(anchor_count)
        .map_err(|_| Error::BoundExceeded)?;
    for _ in 0..anchor_count {
        anchors.push(decode_anchor(reader)?);
    }
    reader.key(9)?;
    let token_count = reader.array_bounded(MAX_TOKEN_EVENTS_PER_ENTRY)?;
    let mut token_events = Vec::new();
    token_events
        .try_reserve_exact(token_count)
        .map_err(|_| Error::BoundExceeded)?;
    for _ in 0..token_count {
        token_events.push(decode_token_event(reader)?);
    }
    reader.key(10)?;
    let decision = ManifestDecisionV1::parse(reader.decode()?).ok_or(Error::InvalidSchema)?;
    reader.key(11)?;
    let reason_codes = decode_reasons(reader)?;
    reader.key(12)?;
    let approval_state = ApprovalStateV1::parse(reader.decode()?).ok_or(Error::InvalidSchema)?;
    Ok(FileChangeV1 {
        file_id,
        original_relative_path,
        safe_path_before,
        safe_path_after,
        file_event,
        content_event,
        content_change_regions,
        anchors,
        token_events,
        decision,
        reason_codes,
        approval_state,
    })
}

fn encode_directory(encoder: &mut CborEncoder, value: &DirectoryChangeV1) -> Result<()> {
    encoder.map(9)?;
    encoder.value(&1u8)?;
    encoder.bytes(&value.directory_id)?;
    encoder.value(&2u8)?;
    encode_optional_text(encoder, value.original_relative_path.as_deref())?;
    encoder.value(&3u8)?;
    encode_optional_text(encoder, value.safe_path_before.as_deref())?;
    encoder.value(&4u8)?;
    encode_optional_text(encoder, value.safe_path_after.as_deref())?;
    encoder.value(&5u8)?;
    encoder.value(&value.directory_event.code())?;
    encoder.value(&6u8)?;
    encoder.array(value.token_events.len())?;
    for event in &value.token_events {
        encode_token_event(encoder, event)?;
    }
    encoder.value(&7u8)?;
    encoder.value(&value.decision.code())?;
    encoder.value(&8u8)?;
    encoder.value(&value.approval_state.code())?;
    encoder.value(&9u8)?;
    encode_reasons(encoder, &value.reason_codes)
}

fn decode_directory(reader: &mut CborReader<'_>) -> Result<DirectoryChangeV1> {
    reader.map_exact(9)?;
    reader.key(1)?;
    let directory_id = reader.fixed()?;
    reader.key(2)?;
    let original_relative_path = decode_optional_text(reader)?;
    reader.key(3)?;
    let safe_path_before = decode_optional_text(reader)?;
    reader.key(4)?;
    let safe_path_after = decode_optional_text(reader)?;
    reader.key(5)?;
    let directory_event = DirectoryEventV1::parse(reader.decode()?).ok_or(Error::InvalidSchema)?;
    reader.key(6)?;
    let token_count = reader.array_bounded(MAX_TOKEN_EVENTS_PER_ENTRY)?;
    let mut token_events = Vec::new();
    token_events
        .try_reserve_exact(token_count)
        .map_err(|_| Error::BoundExceeded)?;
    for _ in 0..token_count {
        token_events.push(decode_token_event(reader)?);
    }
    reader.key(7)?;
    let decision = ManifestDecisionV1::parse(reader.decode()?).ok_or(Error::InvalidSchema)?;
    reader.key(8)?;
    let approval_state = ApprovalStateV1::parse(reader.decode()?).ok_or(Error::InvalidSchema)?;
    reader.key(9)?;
    let reason_codes = decode_reasons(reader)?;
    Ok(DirectoryChangeV1 {
        directory_id,
        original_relative_path,
        safe_path_before,
        safe_path_after,
        directory_event,
        token_events,
        decision,
        approval_state,
        reason_codes,
    })
}

fn encode_reasons(encoder: &mut CborEncoder, values: &[ReasonCodeV1]) -> Result<()> {
    encoder.array(values.len())?;
    for value in values {
        encoder.value(&value.code())?;
    }
    Ok(())
}

fn decode_reasons(reader: &mut CborReader<'_>) -> Result<Vec<ReasonCodeV1>> {
    let count = reader.array_bounded(MAX_REASON_CODES)?;
    let mut output = Vec::new();
    output
        .try_reserve_exact(count)
        .map_err(|_| Error::BoundExceeded)?;
    for _ in 0..count {
        output.push(ReasonCodeV1::parse(reader.decode()?).ok_or(Error::InvalidSchema)?);
    }
    Ok(output)
}

pub(crate) fn sorted_reasons(
    values: impl IntoIterator<Item = ReasonCodeV1>,
) -> Result<Vec<ReasonCodeV1>> {
    let set = values.into_iter().collect::<BTreeSet<_>>();
    if set.len() > MAX_REASON_CODES {
        return Err(Error::BoundExceeded);
    }
    Ok(set.into_iter().collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::roundtrip::report_diff::ContentChangeKindV1;

    fn unknown_event() -> TokenEventV1 {
        TokenEventV1 {
            event_id: [0x11; 16],
            token_id: None,
            category_expected: None,
            category_observed: Some(TokenCategory::Secret),
            event: TokenEventKindV1::TokenUnknown,
            file_id_before: None,
            file_id_after: Some([0x22; 16]),
            anchor_id_before: None,
            anchor_id_after: None,
            observed_count: 1,
            approval_state: ApprovalStateV1::NotEligible,
            decision: ManifestDecisionV1::Reject,
            reason_codes: vec![ReasonCodeV1::UnknownToken],
        }
    }

    fn manifest() -> ChangedManifestV1 {
        ChangedManifestV1 {
            manifest_phase: ChangedManifestPhaseV1::Review,
            session_id: [0x31; 16],
            review_id: [0x32; 16],
            capsule_generation: 2,
            review_profile: ReviewProfile::StandardV2,
            ruleset_id: crate::roundtrip::ruleset::ruleset_id().to_owned(),
            original_tree_consistency: OriginalTreeConsistencyV1::Match,
            edited_tree_commitment: [0x33; 32],
            event_set_commitment: [0x34; 32],
            reconstruction_status: ReconstructionStatusV1::NotRun,
            semantic_safety_assessed: false,
            summary: ManifestSummaryV1 {
                observed_files: 1,
                changed_files: 1,
                automatic_events: 0,
                approval_eligible_events: 0,
                approved_events: 0,
                unapproved_events: 0,
                unconditional_rejects: 1,
                preserved_tokens: 0,
                deleted_tokens: 0,
                new_sensitive_findings: 0,
                observed_directories: 0,
                changed_directories: 0,
                preserved_original_only_files: 0,
                preserved_original_only_bytes: 0,
            },
            files: vec![FileChangeV1 {
                file_id: [0x22; 16],
                original_relative_path: None,
                safe_path_before: None,
                safe_path_after: Some("safe.txt".to_owned()),
                file_event: FileEventV1::Added,
                content_event: ContentEventV1::Added,
                content_change_regions: vec![ContentChangeRegionV1 {
                    kind: ContentChangeKindV1::Insert,
                    before_range: LineRangeV1 {
                        start_line: 1,
                        end_line_exclusive: 1,
                    },
                    after_range: LineRangeV1 {
                        start_line: 1,
                        end_line_exclusive: 2,
                    },
                }],
                anchors: Vec::new(),
                token_events: vec![unknown_event()],
                decision: ManifestDecisionV1::Reject,
                reason_codes: Vec::new(),
                approval_state: ApprovalStateV1::NotEligible,
            }],
            failure_reason_codes: Vec::new(),
            directories: Vec::new(),
        }
    }

    fn baseline_event() -> TokenEventV1 {
        TokenEventV1 {
            event_id: [0x41; 16],
            token_id: Some([0x42; 16]),
            category_expected: Some(TokenCategory::Secret),
            category_observed: Some(TokenCategory::Secret),
            event: TokenEventKindV1::TokenModified,
            file_id_before: Some([0x22; 16]),
            file_id_after: Some([0x22; 16]),
            anchor_id_before: None,
            anchor_id_after: None,
            observed_count: 1,
            approval_state: ApprovalStateV1::NotEligible,
            decision: ManifestDecisionV1::Reject,
            reason_codes: vec![ReasonCodeV1::TokenModified],
        }
    }

    fn deleted_token_event(
        decision: ManifestDecisionV1,
        approval_state: ApprovalStateV1,
    ) -> TokenEventV1 {
        TokenEventV1 {
            event_id: [0x41; 16],
            token_id: Some([0x42; 16]),
            category_expected: Some(TokenCategory::Email),
            category_observed: None,
            event: TokenEventKindV1::TokenDeleted,
            file_id_before: Some([0x22; 16]),
            file_id_after: Some([0x22; 16]),
            anchor_id_before: Some([0x43; 16]),
            anchor_id_after: None,
            observed_count: 0,
            approval_state,
            decision,
            reason_codes: vec![ReasonCodeV1::TokenDeleted],
        }
    }

    fn token_deleted_manifest(
        phase: ChangedManifestPhaseV1,
        decision: ManifestDecisionV1,
        approval_state: ApprovalStateV1,
    ) -> ChangedManifestV1 {
        let mut value = manifest();
        value.manifest_phase = phase;
        value.reconstruction_status = match phase {
            ChangedManifestPhaseV1::Review => ReconstructionStatusV1::NotRun,
            ChangedManifestPhaseV1::ApplyResult => ReconstructionStatusV1::Pass,
            ChangedManifestPhaseV1::ApplyFailure => ReconstructionStatusV1::Failed,
        };
        value.summary.approval_eligible_events = 1;
        value.summary.approved_events = u32::from(phase == ChangedManifestPhaseV1::ApplyResult);
        value.summary.unapproved_events = u32::from(phase != ChangedManifestPhaseV1::ApplyResult);
        value.summary.unconditional_rejects = 0;
        value.summary.deleted_tokens = 1;
        let file = &mut value.files[0];
        file.original_relative_path = Some("main.txt".to_owned());
        file.safe_path_before = Some("main.txt".to_owned());
        file.safe_path_after = Some("main.txt".to_owned());
        file.file_event = FileEventV1::UnchangedPath;
        file.content_event = ContentEventV1::Edited;
        file.token_events = vec![deleted_token_event(decision, approval_state)];
        file.decision = decision;
        file.approval_state = approval_state;
        file.reason_codes.clear();
        value
    }

    fn multiple_token_deleted_review() -> ChangedManifestV1 {
        let mut value = token_deleted_manifest(
            ChangedManifestPhaseV1::Review,
            ManifestDecisionV1::ApprovalRequired,
            ApprovalStateV1::Required,
        );
        let mut second = deleted_token_event(
            ManifestDecisionV1::ApprovalRequired,
            ApprovalStateV1::Required,
        );
        second.event_id = [0x44; 16];
        second.token_id = Some([0x45; 16]);
        second.anchor_id_before = Some([0x46; 16]);
        value.files[0].token_events.push(second);
        value.summary.approval_eligible_events = 2;
        value.summary.unapproved_events = 2;
        value.summary.deleted_tokens = 2;
        value
    }

    fn file_deleted_review(include_token: bool) -> ChangedManifestV1 {
        let mut value = token_deleted_manifest(
            ChangedManifestPhaseV1::Review,
            ManifestDecisionV1::ApprovalRequired,
            ApprovalStateV1::Required,
        );
        let file = &mut value.files[0];
        file.safe_path_after = None;
        file.file_event = FileEventV1::Deleted;
        file.content_event = ContentEventV1::Deleted;
        file.content_change_regions = vec![ContentChangeRegionV1 {
            kind: ContentChangeKindV1::Delete,
            before_range: LineRangeV1 {
                start_line: 1,
                end_line_exclusive: 2,
            },
            after_range: LineRangeV1 {
                start_line: 1,
                end_line_exclusive: 1,
            },
        }];
        file.reason_codes = vec![ReasonCodeV1::FileDeleted];
        if include_token {
            value.summary.approval_eligible_events = 2;
            value.summary.unapproved_events = 2;
        } else {
            file.token_events.clear();
            value.summary.deleted_tokens = 0;
        }
        value
    }

    fn strict_review(include_token: bool) -> ChangedManifestV1 {
        let mut value = token_deleted_manifest(
            ChangedManifestPhaseV1::Review,
            ManifestDecisionV1::ApprovalRequired,
            ApprovalStateV1::Required,
        );
        value.review_profile = ReviewProfile::StrictTokenFilesV2;
        value.files[0].content_event = ContentEventV1::StrictReviewRequired;
        value.files[0].reason_codes = vec![ReasonCodeV1::StrictTokenFileModified];
        if include_token {
            value.summary.approval_eligible_events = 2;
            value.summary.unapproved_events = 2;
        } else {
            value.files[0].token_events.clear();
            value.summary.deleted_tokens = 0;
        }
        value
    }

    fn mixed_approval_review() -> ChangedManifestV1 {
        let mut value = file_deleted_review(true);
        value.review_profile = ReviewProfile::StrictTokenFilesV2;
        let mut strict_file = strict_review(false).files.remove(0);
        strict_file.file_id = [0x23; 16];
        strict_file.original_relative_path = Some("strict.txt".to_owned());
        strict_file.safe_path_before = Some("strict.txt".to_owned());
        strict_file.safe_path_after = Some("strict.txt".to_owned());
        value.files.push(strict_file);
        value.summary.observed_files = 2;
        value.summary.changed_files = 2;
        value.summary.approval_eligible_events = 3;
        value.summary.unapproved_events = 3;
        value
    }

    fn assert_semantic_decode_reject(value: &ChangedManifestV1) {
        let bytes = value
            .encode_canonical_unchecked()
            .expect("encode canonical invalid semantic fixture");
        assert!(ChangedManifestV1::decode_canonical(&bytes).is_err());
    }

    fn assert_all_semantic_entry_points_reject(value: &ChangedManifestV1) {
        assert!(validate_changed_manifest_v1(value).is_err());
        assert!(value.encode_canonical().is_err());
        assert_semantic_decode_reject(value);
    }

    fn assert_canonical_semantics(value: &ChangedManifestV1) {
        validate_changed_manifest_v1(value).expect("validate manifest semantics");
        let bytes = value.encode_canonical().expect("encode canonical manifest");
        assert!(
            ChangedManifestV1::decode_canonical(&bytes).expect("decode canonical manifest")
                == *value
        );
    }

    fn rv2_independent_two_deletion_manifest(phase: ChangedManifestPhaseV1) -> ChangedManifestV1 {
        let (decision, approval_state, reconstruction_status, approved_events, unapproved_events) =
            match phase {
                ChangedManifestPhaseV1::Review => (
                    ManifestDecisionV1::ApprovalRequired,
                    ApprovalStateV1::Required,
                    ReconstructionStatusV1::NotRun,
                    0,
                    2,
                ),
                ChangedManifestPhaseV1::ApplyResult => (
                    ManifestDecisionV1::Approved,
                    ApprovalStateV1::Approved,
                    ReconstructionStatusV1::Pass,
                    2,
                    0,
                ),
                ChangedManifestPhaseV1::ApplyFailure => {
                    panic!("summary-mutation summary probe does not synthesize APPLY_FAILURE")
                }
            };
        let token_event = |id: u8, token_id: u8, anchor_id: u8| TokenEventV1 {
            event_id: [id; 16],
            token_id: Some([token_id; 16]),
            category_expected: Some(TokenCategory::Secret),
            category_observed: None,
            event: TokenEventKindV1::TokenDeleted,
            file_id_before: Some([0x71; 16]),
            file_id_after: Some([0x71; 16]),
            anchor_id_before: Some([anchor_id; 16]),
            anchor_id_after: None,
            observed_count: 0,
            approval_state,
            decision,
            reason_codes: vec![ReasonCodeV1::TokenDeleted],
        };

        ChangedManifestV1 {
            manifest_phase: phase,
            session_id: [0x61; 16],
            review_id: [0x62; 16],
            capsule_generation: 7,
            review_profile: ReviewProfile::StandardV2,
            ruleset_id: crate::roundtrip::ruleset::ruleset_id().to_owned(),
            original_tree_consistency: OriginalTreeConsistencyV1::Match,
            edited_tree_commitment: [0x63; 32],
            event_set_commitment: [0x64; 32],
            reconstruction_status,
            semantic_safety_assessed: false,
            summary: ManifestSummaryV1 {
                observed_files: 1,
                changed_files: 1,
                automatic_events: 0,
                approval_eligible_events: 2,
                approved_events,
                unapproved_events,
                unconditional_rejects: 0,
                preserved_tokens: 0,
                deleted_tokens: 2,
                new_sensitive_findings: 0,
                observed_directories: 0,
                changed_directories: 0,
                preserved_original_only_files: 0,
                preserved_original_only_bytes: 0,
            },
            files: vec![FileChangeV1 {
                file_id: [0x71; 16],
                original_relative_path: Some("rv2.txt".to_owned()),
                safe_path_before: Some("rv2.txt".to_owned()),
                safe_path_after: Some("rv2.txt".to_owned()),
                file_event: FileEventV1::UnchangedPath,
                content_event: ContentEventV1::Edited,
                content_change_regions: vec![ContentChangeRegionV1 {
                    kind: ContentChangeKindV1::Replace,
                    before_range: LineRangeV1 {
                        start_line: 1,
                        end_line_exclusive: 2,
                    },
                    after_range: LineRangeV1 {
                        start_line: 1,
                        end_line_exclusive: 2,
                    },
                }],
                anchors: Vec::new(),
                token_events: vec![token_event(0x81, 0x91, 0xa1), token_event(0x82, 0x92, 0xa2)],
                decision,
                reason_codes: Vec::new(),
                approval_state,
            }],
            failure_reason_codes: Vec::new(),
            directories: Vec::new(),
        }
    }

    fn assert_rv2_summary_only_mutation_rejected(
        canonical: &ChangedManifestV1,
        mutate: impl FnOnce(&mut ManifestSummaryV1),
    ) {
        let mut malformed = canonical.clone();
        mutate(&mut malformed.summary);
        assert!(malformed.summary != canonical.summary);
        assert!(malformed.files == canonical.files);
        assert!(malformed.directories == canonical.directories);
        assert!(validate_changed_manifest_v1(&malformed).is_err());
        assert!(malformed.encode_canonical().is_err());
        let bytes = malformed
            .encode_canonical_unchecked()
            .expect("encode independently malformed summary-mutation fixture");
        assert!(ChangedManifestV1::decode_canonical(&bytes).is_err());
    }

    #[test]
    fn closed_enum_registry_is_exact_and_non_reused() {
        fn codes<T: Copy>(values: &[T], code: impl Fn(T) -> u8) -> Vec<u8> {
            values.iter().copied().map(code).collect()
        }
        assert_eq!(
            codes(OriginalTreeConsistencyV1::ALL, |value| value.code()),
            [1, 2, 3]
        );
        assert_eq!(
            codes(ChangedManifestPhaseV1::ALL, |value| value.code()),
            [1, 2, 3]
        );
        assert_eq!(
            codes(ReconstructionStatusV1::ALL, |value| value.code()),
            [1, 2, 3]
        );
        assert_eq!(
            codes(FileEventV1::ALL, |value| value.code()),
            [1, 2, 3, 4, 5]
        );
        assert_eq!(
            codes(ContentEventV1::ALL, |value| value.code()),
            [1, 2, 3, 4, 5]
        );
        assert_eq!(
            codes(DirectoryEventV1::ALL, |value| value.code()),
            [1, 2, 3, 4]
        );
        assert_eq!(
            codes(ManifestDecisionV1::ALL, |value| value.code()),
            [1, 2, 3, 4]
        );
        assert_eq!(
            codes(ApprovalStateV1::ALL, |value| value.code()),
            [1, 2, 3, 4]
        );
        assert_eq!(
            codes(TokenEventKindV1::ALL, |value| value.code()),
            (1..=13).collect::<Vec<_>>()
        );
        assert_eq!(codes(AnchorKindV1::ALL, |value| value.code()), [1, 2, 3]);
        assert_eq!(
            codes(AnchorStatusV1::ALL, |value| value.code()),
            [1, 2, 3, 4]
        );
        assert_eq!(
            codes(ReasonCodeV1::ALL, |value| value.code()),
            (1..=49).collect::<Vec<_>>()
        );
        assert_eq!(TokenEventKindV1::TokenMovedWithinFile.code(), 3);
        assert_eq!(AnchorKindV1::ContentLineBlockV1.code(), 1);
        assert_eq!(AnchorKindV1::ContentExactContextV2.code(), 3);
        assert_eq!(ReasonCodeV1::ShortNameAlias.code(), 25);
        let region_kinds = [
            ContentChangeKindV1::Insert,
            ContentChangeKindV1::Delete,
            ContentChangeKindV1::Replace,
        ];
        assert_eq!(region_kinds.map(content_change_kind_code), [1, 2, 3]);
        for value in region_kinds {
            assert_eq!(
                parse_content_change_kind(content_change_kind_code(value).into()),
                Some(value)
            );
        }
        for value in OriginalTreeConsistencyV1::ALL {
            assert_eq!(
                OriginalTreeConsistencyV1::parse(value.code().into()),
                Some(*value)
            );
        }
        for value in ChangedManifestPhaseV1::ALL {
            assert_eq!(
                ChangedManifestPhaseV1::parse(value.code().into()),
                Some(*value)
            );
        }
        for value in ReconstructionStatusV1::ALL {
            assert_eq!(
                ReconstructionStatusV1::parse(value.code().into()),
                Some(*value)
            );
        }
        for value in FileEventV1::ALL {
            assert_eq!(FileEventV1::parse(value.code().into()), Some(*value));
        }
        for value in ContentEventV1::ALL {
            assert_eq!(ContentEventV1::parse(value.code().into()), Some(*value));
        }
        for value in DirectoryEventV1::ALL {
            assert_eq!(DirectoryEventV1::parse(value.code().into()), Some(*value));
        }
        for value in ManifestDecisionV1::ALL {
            assert_eq!(ManifestDecisionV1::parse(value.code().into()), Some(*value));
        }
        for value in ApprovalStateV1::ALL {
            assert_eq!(ApprovalStateV1::parse(value.code().into()), Some(*value));
        }
        for value in TokenEventKindV1::ALL {
            assert_eq!(TokenEventKindV1::parse(value.code().into()), Some(*value));
        }
        for value in AnchorKindV1::ALL {
            assert_eq!(AnchorKindV1::parse(value.code().into()), Some(*value));
        }
        for value in AnchorStatusV1::ALL {
            assert_eq!(AnchorStatusV1::parse(value.code().into()), Some(*value));
        }
        for value in ReasonCodeV1::ALL {
            assert_eq!(ReasonCodeV1::parse(value.code().into()), Some(*value));
        }
        assert!(OriginalTreeConsistencyV1::parse(0).is_none());
        assert!(ChangedManifestPhaseV1::parse(255).is_none());
        assert!(ReconstructionStatusV1::parse(255).is_none());
        assert!(FileEventV1::parse(255).is_none());
        assert!(ContentEventV1::parse(255).is_none());
        assert!(DirectoryEventV1::parse(255).is_none());
        assert!(ManifestDecisionV1::parse(255).is_none());
        assert!(ApprovalStateV1::parse(255).is_none());
        assert!(TokenEventKindV1::parse(255).is_none());
        assert!(AnchorKindV1::parse(255).is_none());
        assert!(AnchorStatusV1::parse(255).is_none());
        assert!(ReasonCodeV1::parse(255).is_none());
        assert!(parse_content_change_kind(255).is_none());
    }

    #[test]
    fn canonical_round_trip_and_adversarial_shape_rejection() {
        let value = manifest();
        let encoded = value.encode_canonical().expect("encode manifest");
        assert!(ChangedManifestV1::decode_canonical(&encoded).is_ok());
        assert_eq!(MANIFEST_SCHEMA_VERSION, 1);

        let mut missing = encoded.clone();
        missing[0] = 0xb2;
        assert!(ChangedManifestV1::decode_canonical(&missing).is_err());
        let mut unknown_key = encoded.clone();
        unknown_key[1] = 20;
        assert!(ChangedManifestV1::decode_canonical(&unknown_key).is_err());
        let mut duplicate_key = encoded.clone();
        duplicate_key[3] = 1;
        assert!(ChangedManifestV1::decode_canonical(&duplicate_key).is_err());
        let mut unknown_phase = encoded.clone();
        unknown_phase[4] = 23;
        assert!(ChangedManifestV1::decode_canonical(&unknown_phase).is_err());
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(ChangedManifestV1::decode_canonical(&trailing).is_err());
        let mut noncanonical = encoded;
        // The schema version is the first small integer after a 19-entry map
        // and key 1. Replacing it with a non-shortest uint encoding must fail.
        let schema = noncanonical
            .windows(3)
            .position(|window| window == [1, 1, 2])
            .expect("schema prefix");
        noncanonical.splice(schema + 1..schema + 2, [0x18, 0x01]);
        assert!(ChangedManifestV1::decode_canonical(&noncanonical).is_err());
    }

    #[test]
    fn token_deleted_phase_contract_is_exact_and_canonical() {
        let review = token_deleted_manifest(
            ChangedManifestPhaseV1::Review,
            ManifestDecisionV1::ApprovalRequired,
            ApprovalStateV1::Required,
        );
        let review_bytes = review.encode_canonical().expect("encode REVIEW deletion");
        assert!(
            ChangedManifestV1::decode_canonical(&review_bytes).expect("decode REVIEW deletion")
                == review
        );

        let apply = token_deleted_manifest(
            ChangedManifestPhaseV1::ApplyResult,
            ManifestDecisionV1::Approved,
            ApprovalStateV1::Approved,
        );
        let apply_bytes = apply
            .encode_canonical()
            .expect("encode APPLY_RESULT deletion");
        assert!(
            ChangedManifestV1::decode_canonical(&apply_bytes)
                .expect("decode APPLY_RESULT deletion")
                == apply
        );

        for (phase, decision, approval_state) in [
            (
                ChangedManifestPhaseV1::Review,
                ManifestDecisionV1::Approved,
                ApprovalStateV1::Approved,
            ),
            (
                ChangedManifestPhaseV1::Review,
                ManifestDecisionV1::Automatic,
                ApprovalStateV1::NotEligible,
            ),
            (
                ChangedManifestPhaseV1::ApplyResult,
                ManifestDecisionV1::ApprovalRequired,
                ApprovalStateV1::Required,
            ),
            (
                ChangedManifestPhaseV1::ApplyResult,
                ManifestDecisionV1::Approved,
                ApprovalStateV1::Required,
            ),
            (
                ChangedManifestPhaseV1::ApplyResult,
                ManifestDecisionV1::Approved,
                ApprovalStateV1::NotEligible,
            ),
        ] {
            let event = deleted_token_event(decision, approval_state);
            assert!(
                validate_token_event(&event, phase).is_err(),
                "phase={phase:?} decision={decision:?} approval={approval_state:?}"
            );
        }

        let apply_failure =
            deleted_token_event(ManifestDecisionV1::Approved, ApprovalStateV1::Approved);
        assert!(
            validate_token_event(&apply_failure, ChangedManifestPhaseV1::ApplyFailure).is_err()
        );

        let unapproved_apply = token_deleted_manifest(
            ChangedManifestPhaseV1::ApplyResult,
            ManifestDecisionV1::ApprovalRequired,
            ApprovalStateV1::Required,
        );
        assert_semantic_decode_reject(&unapproved_apply);
    }

    #[test]
    fn summary_must_reconcile_with_exact_projected_approval_targets() {
        let apply = token_deleted_manifest(
            ChangedManifestPhaseV1::ApplyResult,
            ManifestDecisionV1::Approved,
            ApprovalStateV1::Approved,
        );
        let mut malformed = apply.clone();
        malformed.summary.approved_events = 0;
        malformed.summary.unapproved_events = malformed.summary.approval_eligible_events;
        assert_all_semantic_entry_points_reject(&malformed);

        let multiple_review = multiple_token_deleted_review();
        let multiple_apply =
            crate::roundtrip::manifest_projection::project_apply_result(&multiple_review, 4, 0, 0)
                .expect("project multiple token deletions");
        let mut malformed = multiple_apply.clone();
        malformed.summary.approved_events = malformed.summary.approval_eligible_events - 1;
        malformed.summary.unapproved_events = 1;
        assert_all_semantic_entry_points_reject(&malformed);

        let mut malformed = apply.clone();
        malformed.summary.unapproved_events = 1;
        assert_all_semantic_entry_points_reject(&malformed);

        let mut malformed = apply.clone();
        malformed.summary.approved_events = malformed.summary.approval_eligible_events + 1;
        assert_all_semantic_entry_points_reject(&malformed);

        let mut malformed = apply;
        malformed.summary.approval_eligible_events = 2;
        malformed.summary.approved_events = 2;
        assert_all_semantic_entry_points_reject(&malformed);

        let review = token_deleted_manifest(
            ChangedManifestPhaseV1::Review,
            ManifestDecisionV1::ApprovalRequired,
            ApprovalStateV1::Required,
        );
        let mut malformed = review.clone();
        malformed.summary.approved_events = 1;
        assert_all_semantic_entry_points_reject(&malformed);

        let mut malformed = review.clone();
        malformed.summary.unapproved_events = 0;
        assert_all_semantic_entry_points_reject(&malformed);

        let mut malformed = review;
        malformed.summary.approval_eligible_events = 2;
        malformed.summary.unapproved_events = 2;
        assert_all_semantic_entry_points_reject(&malformed);
    }

    #[test]
    fn summary_only_mutations_fail_every_canonical_boundary() {
        let review = rv2_independent_two_deletion_manifest(ChangedManifestPhaseV1::Review);
        assert_canonical_semantics(&review);
        assert_rv2_summary_only_mutation_rejected(&review, |summary| {
            summary.approved_events = 1;
        });
        assert_rv2_summary_only_mutation_rejected(&review, |summary| {
            summary.unapproved_events = summary.approval_eligible_events - 1;
        });
        assert_rv2_summary_only_mutation_rejected(&review, |summary| {
            summary.unapproved_events = summary.approval_eligible_events + 1;
        });
        assert_rv2_summary_only_mutation_rejected(&review, |summary| {
            summary.approval_eligible_events -= 1;
            summary.unapproved_events = summary.approval_eligible_events;
        });
        assert_rv2_summary_only_mutation_rejected(&review, |summary| {
            summary.approval_eligible_events += 1;
            summary.unapproved_events = summary.approval_eligible_events;
        });

        let apply = rv2_independent_two_deletion_manifest(ChangedManifestPhaseV1::ApplyResult);
        assert_canonical_semantics(&apply);
        assert_rv2_summary_only_mutation_rejected(&apply, |summary| {
            summary.approved_events = 0;
            summary.unapproved_events = summary.approval_eligible_events;
        });
        assert_rv2_summary_only_mutation_rejected(&apply, |summary| {
            summary.approved_events = summary.approval_eligible_events - 1;
            summary.unapproved_events = 1;
        });
        assert_rv2_summary_only_mutation_rejected(&apply, |summary| {
            summary.unapproved_events = 1;
        });
        assert_rv2_summary_only_mutation_rejected(&apply, |summary| {
            summary.approved_events = summary.approval_eligible_events + 1;
        });
        assert_rv2_summary_only_mutation_rejected(&apply, |summary| {
            summary.approval_eligible_events -= 1;
            summary.approved_events = summary.approval_eligible_events;
        });
        assert_rv2_summary_only_mutation_rejected(&apply, |summary| {
            summary.approval_eligible_events += 1;
            summary.approved_events = summary.approval_eligible_events;
        });
    }

    #[test]
    fn canonical_summary_uses_only_current_approval_targets() {
        let mut zero_approval = manifest();
        zero_approval.files.clear();
        zero_approval.summary.observed_files = 0;
        zero_approval.summary.changed_files = 0;
        zero_approval.summary.unconditional_rejects = 0;
        assert_canonical_semantics(&zero_approval);

        let one_token = token_deleted_manifest(
            ChangedManifestPhaseV1::Review,
            ManifestDecisionV1::ApprovalRequired,
            ApprovalStateV1::Required,
        );
        assert_canonical_semantics(&one_token);

        let multiple_tokens = multiple_token_deleted_review();
        assert_canonical_semantics(&multiple_tokens);

        let file_deleted = file_deleted_review(false);
        assert_canonical_semantics(&file_deleted);

        let strict = strict_review(false);
        assert_canonical_semantics(&strict);

        let whole_file = file_deleted_review(true);
        assert_canonical_semantics(&whole_file);

        let mixed = mixed_approval_review();
        assert_canonical_semantics(&mixed);

        for (generation, review) in [
            (3, one_token),
            (4, multiple_tokens),
            (5, file_deleted),
            (6, strict),
            (7, whole_file),
            (8, mixed),
        ] {
            let apply = crate::roundtrip::manifest_projection::project_apply_result(
                &review, generation, 0, 0,
            )
            .expect("project approved manifest");
            assert_eq!(
                apply.summary.approved_events,
                apply.summary.approval_eligible_events
            );
            assert_eq!(apply.summary.unapproved_events, 0);
            assert_canonical_semantics(&apply);
        }
    }

    #[test]
    fn file_approval_targets_require_the_exact_phase_state() {
        let mut review_deleted = file_deleted_review(false);
        review_deleted.files[0].decision = ManifestDecisionV1::Automatic;
        review_deleted.files[0].approval_state = ApprovalStateV1::NotEligible;
        review_deleted.summary.automatic_events = 1;
        assert_all_semantic_entry_points_reject(&review_deleted);

        let strict_review = strict_review(false);
        let mut apply_strict =
            crate::roundtrip::manifest_projection::project_apply_result(&strict_review, 3, 0, 0)
                .expect("project strict manifest");
        apply_strict.files[0].decision = ManifestDecisionV1::Automatic;
        apply_strict.files[0].approval_state = ApprovalStateV1::NotEligible;
        apply_strict.summary.automatic_events = 1;
        assert_all_semantic_entry_points_reject(&apply_strict);
    }

    #[test]
    fn token_deleted_review_projects_to_a_reconciled_apply_result() {
        let review = token_deleted_manifest(
            ChangedManifestPhaseV1::Review,
            ManifestDecisionV1::ApprovalRequired,
            ApprovalStateV1::Required,
        );
        let apply = crate::roundtrip::manifest_projection::project_apply_result(&review, 4, 0, 0)
            .expect("project approved deletion");
        assert_eq!(apply.manifest_phase, ChangedManifestPhaseV1::ApplyResult);
        assert_eq!(apply.summary.approval_eligible_events, 1);
        assert_eq!(apply.summary.approved_events, 1);
        assert_eq!(apply.summary.unapproved_events, 0);
        assert_eq!(apply.files[0].decision, ManifestDecisionV1::Approved);
        assert_eq!(apply.files[0].approval_state, ApprovalStateV1::Approved);
        assert_eq!(
            apply.files[0].token_events[0].decision,
            ManifestDecisionV1::Approved
        );
        assert_eq!(
            apply.files[0].token_events[0].approval_state,
            ApprovalStateV1::Approved
        );
        let bytes = apply
            .encode_canonical()
            .expect("encode projected APPLY_RESULT");
        assert!(
            ChangedManifestV1::decode_canonical(&bytes).expect("decode projected APPLY_RESULT")
                == apply
        );
    }

    #[test]
    fn whole_file_and_strict_approval_projection_reconcile_exact_states() {
        let mut deleted = token_deleted_manifest(
            ChangedManifestPhaseV1::Review,
            ManifestDecisionV1::ApprovalRequired,
            ApprovalStateV1::Required,
        );
        deleted.summary.approval_eligible_events = 2;
        deleted.summary.unapproved_events = 2;
        let deleted_file = &mut deleted.files[0];
        deleted_file.safe_path_after = None;
        deleted_file.file_event = FileEventV1::Deleted;
        deleted_file.content_event = ContentEventV1::Deleted;
        deleted_file.content_change_regions = vec![ContentChangeRegionV1 {
            kind: ContentChangeKindV1::Delete,
            before_range: LineRangeV1 {
                start_line: 1,
                end_line_exclusive: 2,
            },
            after_range: LineRangeV1 {
                start_line: 1,
                end_line_exclusive: 1,
            },
        }];
        deleted_file.reason_codes = vec![ReasonCodeV1::FileDeleted];
        deleted
            .encode_canonical()
            .expect("encode REVIEW file deletion");
        let deleted_apply =
            crate::roundtrip::manifest_projection::project_apply_result(&deleted, 4, 0, 0)
                .expect("project whole-file deletion");
        assert_eq!(deleted_apply.summary.approval_eligible_events, 2);
        assert_eq!(deleted_apply.summary.approved_events, 2);
        assert_eq!(deleted_apply.summary.unapproved_events, 0);
        assert_eq!(
            deleted_apply.files[0].decision,
            ManifestDecisionV1::Approved
        );
        assert_eq!(
            deleted_apply.files[0].token_events[0].decision,
            ManifestDecisionV1::Approved
        );
        deleted_apply
            .encode_canonical()
            .expect("encode APPLY_RESULT file deletion");

        let mut unapproved_file = deleted_apply.clone();
        unapproved_file.files[0].decision = ManifestDecisionV1::ApprovalRequired;
        unapproved_file.files[0].approval_state = ApprovalStateV1::Required;
        assert_semantic_decode_reject(&unapproved_file);

        let mut strict = token_deleted_manifest(
            ChangedManifestPhaseV1::Review,
            ManifestDecisionV1::ApprovalRequired,
            ApprovalStateV1::Required,
        );
        strict.summary.approval_eligible_events = 2;
        strict.summary.unapproved_events = 2;
        strict.files[0].content_event = ContentEventV1::StrictReviewRequired;
        strict.files[0].reason_codes = vec![ReasonCodeV1::StrictTokenFileModified];
        strict
            .encode_canonical()
            .expect("encode Strict REVIEW deletion");
        let strict_apply =
            crate::roundtrip::manifest_projection::project_apply_result(&strict, 5, 0, 0)
                .expect("project Strict deletion");
        assert_eq!(strict_apply.summary.approved_events, 2);
        assert_eq!(strict_apply.files[0].decision, ManifestDecisionV1::Approved);
        assert_eq!(
            strict_apply.files[0].token_events[0].decision,
            ManifestDecisionV1::Approved
        );
        strict_apply
            .encode_canonical()
            .expect("encode Strict APPLY_RESULT deletion");
    }

    #[test]
    fn path_token_deletion_projection_is_phase_closed() {
        let mut review = token_deleted_manifest(
            ChangedManifestPhaseV1::Review,
            ManifestDecisionV1::ApprovalRequired,
            ApprovalStateV1::Required,
        );
        let token_events = std::mem::take(&mut review.files[0].token_events);
        review.files.clear();
        review.summary.observed_files = 0;
        review.summary.changed_files = 0;
        review.summary.observed_directories = 1;
        review.summary.changed_directories = 1;
        review.directories = vec![DirectoryChangeV1 {
            directory_id: [0x22; 16],
            original_relative_path: Some("private-name".to_owned()),
            safe_path_before: Some("tokenized-name".to_owned()),
            safe_path_after: Some("name".to_owned()),
            directory_event: DirectoryEventV1::Renamed,
            token_events,
            decision: ManifestDecisionV1::ApprovalRequired,
            approval_state: ApprovalStateV1::Required,
            reason_codes: Vec::new(),
        }];
        review
            .encode_canonical()
            .expect("encode path-token REVIEW deletion");
        let apply = crate::roundtrip::manifest_projection::project_apply_result(&review, 4, 0, 0)
            .expect("project path-token deletion");
        assert_eq!(apply.summary.approved_events, 1);
        assert_eq!(apply.summary.unapproved_events, 0);
        assert_eq!(apply.directories[0].decision, ManifestDecisionV1::Approved);
        assert_eq!(
            apply.directories[0].approval_state,
            ApprovalStateV1::Approved
        );
        assert_eq!(
            apply.directories[0].token_events[0].decision,
            ManifestDecisionV1::Approved
        );
        apply
            .encode_canonical()
            .expect("encode path-token APPLY_RESULT deletion");
    }

    #[test]
    fn unknown_null_pair_and_every_invalid_combination_are_rejected() {
        let valid = manifest();
        valid.encode_canonical().expect("valid unknown event");
        for mutation in 0..7 {
            let mut value = manifest();
            let event = &mut value.files[0].token_events[0];
            match mutation {
                0 => event.token_id = Some([1; 16]),
                1 => event.category_expected = Some(TokenCategory::Secret),
                2 => {
                    event.token_id = Some([1; 16]);
                    event.category_expected = Some(TokenCategory::Secret);
                }
                3 => event.decision = ManifestDecisionV1::ApprovalRequired,
                4 => event.approval_state = ApprovalStateV1::Required,
                5 => {
                    event.decision = ManifestDecisionV1::Approved;
                    event.approval_state = ApprovalStateV1::Approved;
                }
                6 => event.event = TokenEventKindV1::TokenModified,
                _ => unreachable!(),
            }
            assert!(value.encode_canonical().is_err(), "mutation {mutation}");
        }

        for mutation in 0..3 {
            let mut value = manifest();
            value.files[0].token_events[0] = baseline_event();
            let event = &mut value.files[0].token_events[0];
            match mutation {
                0 => event.token_id = None,
                1 => event.category_expected = None,
                2 => {
                    event.token_id = None;
                    event.category_expected = None;
                }
                _ => unreachable!(),
            }
            assert!(
                value.encode_canonical().is_err(),
                "baseline mutation {mutation}"
            );
            assert_semantic_decode_reject(&value);
        }

        let mut value = manifest();
        value.files[0].token_events[0] = baseline_event();
        value.files[0].token_events[0].event = TokenEventKindV1::CategoryMismatch;
        value.files[0].token_events[0].category_expected = None;
        value.files[0].token_events[0].reason_codes = vec![ReasonCodeV1::CategoryMismatch];
        assert_semantic_decode_reject(&value);
    }

    #[test]
    fn region_and_summary_semantics_reject_contradictions() {
        let mut value = manifest();
        value.files[0].content_change_regions.clear();
        assert!(value.encode_canonical().is_err());
        value.files[0].content_event = ContentEventV1::Unchanged;
        assert!(value.encode_canonical().is_err());
        value.files[0].content_event = ContentEventV1::Added;
        value.files[0].content_change_regions = vec![ContentChangeRegionV1 {
            kind: ContentChangeKindV1::Insert,
            before_range: LineRangeV1 {
                start_line: 1,
                end_line_exclusive: 1,
            },
            after_range: LineRangeV1 {
                start_line: 1,
                end_line_exclusive: 2,
            },
        }];
        value.encode_canonical().expect("consistent added content");
        value.files[0].content_event = ContentEventV1::Edited;
        assert!(value.encode_canonical().is_err());
        value.files[0].content_event = ContentEventV1::Added;
        value.summary.changed_files = 0;
        assert!(value.encode_canonical().is_err());
    }

    #[test]
    fn decoder_rejects_semantic_state_path_order_id_and_reason_adversaries() {
        let mut value = manifest();
        value.semantic_safety_assessed = true;
        assert_semantic_decode_reject(&value);

        let mut value = manifest();
        value.original_tree_consistency = OriginalTreeConsistencyV1::Mismatch;
        assert_semantic_decode_reject(&value);

        let mut value = manifest();
        value.reconstruction_status = ReconstructionStatusV1::Pass;
        assert_semantic_decode_reject(&value);

        let mut value = manifest();
        value.files[0].safe_path_after = Some("C:/confidential.txt".to_owned());
        assert_semantic_decode_reject(&value);

        let mut value = manifest();
        value.files[0].safe_path_after = Some("NUL.txt".to_owned());
        assert_semantic_decode_reject(&value);

        let mut value = manifest();
        value.files[0].reason_codes = vec![ReasonCodeV1::CandidateCollision];
        assert_semantic_decode_reject(&value);

        let mut value = manifest();
        value.summary.unconditional_rejects = 0;
        assert_semantic_decode_reject(&value);

        let mut value = manifest();
        value.files[0].original_relative_path = Some("safe.txt".to_owned());
        value.files[0].safe_path_before = Some("safe.txt".to_owned());
        value.files[0].file_event = FileEventV1::UnchangedPath;
        value.files[0].content_event = ContentEventV1::Unchanged;
        value.files[0].content_change_regions.clear();
        value.files[0].decision = ManifestDecisionV1::Automatic;
        value.files[0].approval_state = ApprovalStateV1::NotEligible;
        value.files[0].token_events[0] = TokenEventV1 {
            event_id: [0x11; 16],
            token_id: Some([0x42; 16]),
            category_expected: Some(TokenCategory::Secret),
            category_observed: Some(TokenCategory::Secret),
            event: TokenEventKindV1::PreservedSameAnchor,
            file_id_before: Some([0x22; 16]),
            file_id_after: Some([0x22; 16]),
            anchor_id_before: Some([0x52; 16]),
            anchor_id_after: Some([0x52; 16]),
            observed_count: 1,
            approval_state: ApprovalStateV1::NotEligible,
            decision: ManifestDecisionV1::Automatic,
            reason_codes: vec![ReasonCodeV1::PreservedSameAnchor],
        };
        value.summary.automatic_events = 1;
        value.summary.unconditional_rejects = 0;
        value.summary.preserved_tokens = 1;
        assert_semantic_decode_reject(&value);

        let mut value = manifest();
        value.files[0].token_events.push(unknown_event());
        value.summary.unconditional_rejects = 2;
        assert_semantic_decode_reject(&value);

        let mut value = manifest();
        value.directories.push(DirectoryChangeV1 {
            directory_id: value.files[0].file_id,
            original_relative_path: None,
            safe_path_before: None,
            safe_path_after: Some("safe-dir".to_owned()),
            directory_event: DirectoryEventV1::Added,
            token_events: Vec::new(),
            decision: ManifestDecisionV1::Automatic,
            approval_state: ApprovalStateV1::NotEligible,
            reason_codes: vec![ReasonCodeV1::DirectoryAdded],
        });
        value.summary.observed_directories = 1;
        value.summary.changed_directories = 1;
        value.summary.automatic_events = 1;
        assert_semantic_decode_reject(&value);
    }

    #[test]
    fn decoder_rejects_unsorted_overlapping_and_duplicate_nested_ids() {
        let mut value = manifest();
        let mut second = value.files[0].clone();
        second.file_id = [0x21; 16];
        second.safe_path_after = Some("other.txt".to_owned());
        second.token_events[0].event_id = [0x12; 16];
        second.token_events[0].file_id_after = Some(second.file_id);
        value.files.push(second);
        value.summary.observed_files = 2;
        value.summary.changed_files = 2;
        value.summary.unconditional_rejects = 2;
        assert_semantic_decode_reject(&value);

        let mut value = manifest();
        value.files[0].content_event = ContentEventV1::Added;
        value.files[0].content_change_regions = vec![
            ContentChangeRegionV1 {
                kind: ContentChangeKindV1::Insert,
                before_range: LineRangeV1 {
                    start_line: 1,
                    end_line_exclusive: 1,
                },
                after_range: LineRangeV1 {
                    start_line: 1,
                    end_line_exclusive: 3,
                },
            },
            ContentChangeRegionV1 {
                kind: ContentChangeKindV1::Replace,
                before_range: LineRangeV1 {
                    start_line: 1,
                    end_line_exclusive: 2,
                },
                after_range: LineRangeV1 {
                    start_line: 2,
                    end_line_exclusive: 4,
                },
            },
        ];
        assert_semantic_decode_reject(&value);

        let mut value = manifest();
        value.files[0].token_events[0] = baseline_event();
        let mut second = value.files[0].clone();
        second.file_id = [0x23; 16];
        second.safe_path_after = Some("z-safe.txt".to_owned());
        second.token_events[0].event_id = [0x43; 16];
        second.token_events[0].file_id_before = Some(second.file_id);
        second.token_events[0].file_id_after = Some(second.file_id);
        value.files.push(second);
        value.summary.observed_files = 2;
        value.summary.changed_files = 2;
        value.summary.unconditional_rejects = 2;
        assert_semantic_decode_reject(&value);
    }
}
