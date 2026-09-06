//! Complete deterministic OriginalWorkspace observation for roundtrip-v3.

use std::ffi::OsStr;
use std::io::Read;
use std::path::Path;

use cap_fs_ext::MetadataExt;

use crate::content::ContentOutcome;
use crate::detection::{classify_path, ComponentInspectability, DetectedKind};
use crate::filename;
use crate::path_transform::split_transformable_file_component;
use crate::policy::{effective_decision, Decision, FileDispositionInput, FilenameEvidence};

use super::anchor::{
    finalize_content_anchors, ContentAnchorFact, ContentFileRole, DetectedContentOccurrence,
    PROTECTED_ANCHOR_VERSION, RELATIVE_CONTEXT_VERSION,
};
use super::crypto::{constant_time_equal, HmacStream, KeyPurpose, KeySchedule, SecretVec};
use super::observe::{
    file_identity, sort_utf16_indices, validate_regular_one_link_stream_clean,
    validate_virtual_sibling_names, validate_workspace_component, EntryKind, FileIdentity,
    ObservedNamespaceEntry, QualifiedDirectory,
};
use super::ruleset::ruleset_id;
use super::schema::TreeCountsV1;
use super::token::{
    ComponentKind as TokenComponentKind, EntryKind as TokenEntryKind, ReviewProfile,
    ENGINE_VERSION, POLICY_ID, TOKEN_SUITE_ID,
};
use super::tokenize::{
    contains_reserved_introducer, EvidenceRegion, PathTokenContext, TokenFact, TokenInventory,
    Tokenizer, MAX_TRANSFORMED_FILE_BYTES,
};
use super::{Error, Result};

pub(super) const MAX_DEPTH: usize = 64;
pub(super) const MAX_ENTRIES: usize = 100_000;
pub(super) const MAX_FILE_BYTES: usize = 4 * 1024 * 1024;
pub(super) const MAX_TOTAL_FILE_BYTES: usize = 64 * 1024 * 1024;
pub(super) const MAX_TOTAL_AI_FILE_BYTES: usize = 64 * 1024 * 1024;
pub(super) const MAX_PATH_UTF16: usize = 32_000;
pub(super) const MAX_PATH_UTF8: usize = 128 * 1024;
pub(super) const MAX_CANONICAL_PATH_BYTES: usize = 8 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum OmissionReason {
    None,
    Binary,
    InvalidUtf8,
    Unsupported,
    Unknown,
    FilenamePolicy,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum FileDisposition {
    Transform,
    Omit(OmissionReason),
}

#[derive(Clone, Eq, PartialEq)]
pub(super) enum PlannedEntry {
    Directory {
        original_components: Vec<String>,
        safe_components: Vec<String>,
        token_facts: Vec<TokenFact>,
        observed_short_alias_utf16: Option<Vec<u16>>,
    },
    File {
        original_components: Vec<String>,
        safe_components: Option<Vec<String>>,
        disposition: FileDisposition,
        expected_output_commitment: Option<[u8; 32]>,
        expected_output_bytes: Option<u64>,
        path_token_facts: Vec<TokenFact>,
        content_token_facts: Vec<TokenFact>,
        content_anchor_facts: Vec<ContentAnchorFact>,
        observed_short_alias_utf16: Option<Vec<u16>>,
        observed_identity: FileIdentity,
        original_file_reference_commitment: [u8; 32],
    },
}

impl PlannedEntry {
    pub(super) fn safe_components(&self) -> Option<&[String]> {
        match self {
            Self::Directory {
                safe_components, ..
            } => Some(safe_components),
            Self::File {
                safe_components, ..
            } => safe_components.as_deref(),
        }
    }

    pub(super) fn original_components(&self) -> &[String] {
        match self {
            Self::Directory {
                original_components,
                ..
            }
            | Self::File {
                original_components,
                ..
            } => original_components,
        }
    }

    pub(super) fn observed_short_alias_utf16(&self) -> Option<&[u16]> {
        match self {
            Self::Directory {
                observed_short_alias_utf16,
                ..
            }
            | Self::File {
                observed_short_alias_utf16,
                ..
            } => observed_short_alias_utf16.as_deref(),
        }
    }
}

pub(super) struct BaselinePlan {
    pub(super) entries: Vec<PlannedEntry>,
    pub(super) inventory: TokenInventory,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct BaselineSummary {
    pub(super) original_tree_commitment: [u8; 32],
    pub(super) expected_ai_projection_commitment: [u8; 32],
    pub(super) counts: TreeCountsV1,
}

pub(crate) struct BaselineDerivation {
    pub(super) summary: BaselineSummary,
    pub(super) plan: BaselinePlan,
}

/// One freshly rederived Original occurrence.  The node binds only an OID,
/// category, source span, order, and protected anchor; matched bytes remain in
/// the enclosing one-file buffer and are borrowed only by reconstruction.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) struct RederivedOccurrenceSpan {
    pub(super) fact: TokenFact,
    pub(super) start: usize,
    pub(super) end: usize,
    pub(super) order: u32,
    pub(super) protected_anchor: [u8; 32],
}

/// File-local Original authority.  It deliberately has no `Clone`, `Debug`,
/// serialization, or OID-to-value accessor.
pub(super) struct RederivedOriginalFile {
    original_bytes: SecretVec,
    safe_bytes: Vec<u8>,
    pub(super) path_occurrences: Vec<RederivedOccurrenceSpan>,
    pub(super) content_occurrences: Vec<RederivedOccurrenceSpan>,
}

impl RederivedOriginalFile {
    pub(super) fn original_bytes(&self) -> &[u8] {
        self.original_bytes.as_slice()
    }

    pub(super) fn release_safe_output(&mut self) {
        self.safe_bytes = Vec::new();
    }
}

/// Directory-component counterpart of `RederivedOriginalFile`.  Its raw
/// component is borrowed from `PlannedEntry::original_components` by callers.
pub(super) struct RederivedDirectoryPath {
    pub(super) occurrences: Vec<RederivedOccurrenceSpan>,
}

pub(super) fn derive_two_prepublication_passes(
    root: &QualifiedDirectory,
    schedule: &KeySchedule<'_>,
    profile: ReviewProfile,
) -> Result<BaselineDerivation> {
    let first = derive(root, schedule, profile, false)?;
    let second = derive(root, schedule, profile, true)?;
    require_same_summary(&first.summary, &second.summary)?;
    Ok(second)
}

pub(super) fn derive(
    root: &QualifiedDirectory,
    schedule: &KeySchedule<'_>,
    profile: ReviewProfile,
    retain_plan: bool,
) -> Result<BaselineDerivation> {
    let mut scanner = Scanner::new(schedule, profile, retain_plan)?;
    root.verify()?;
    scanner.walk_directory(root, &[], &[], false, 0)?;
    root.verify()?;
    scanner.finish()
}

pub(super) fn require_same_summary(
    accepted: &BaselineSummary,
    observed: &BaselineSummary,
) -> Result<()> {
    if !constant_time_equal(
        &accepted.original_tree_commitment,
        &observed.original_tree_commitment,
    ) || !constant_time_equal(
        &accepted.expected_ai_projection_commitment,
        &observed.expected_ai_projection_commitment,
    ) || accepted.counts != observed.counts
    {
        return Err(Error::InvalidState);
    }
    Ok(())
}

struct Scanner<'a> {
    schedule: &'a KeySchedule<'a>,
    profile: ReviewProfile,
    tokenizer: Tokenizer<'a>,
    original: TreeEncoder,
    expected_ai: ProjectionAccumulator,
    counts: MutableCounts,
    retain_plan: bool,
    entries: Vec<PlannedEntry>,
}

struct DirectoryCommitContext<'a> {
    canonical_original_path: &'a [u8],
    safe_path: &'a [u8],
    evidence: &'a [EvidenceRegion],
    facts: &'a [TokenFact],
}

impl<'a> Scanner<'a> {
    fn new(
        schedule: &'a KeySchedule<'a>,
        profile: ReviewProfile,
        retain_plan: bool,
    ) -> Result<Self> {
        Ok(Self {
            schedule,
            profile,
            tokenizer: Tokenizer::new(schedule, profile)?,
            original: TreeEncoder::new(schedule, b"ORIGINAL", profile)?,
            expected_ai: ProjectionAccumulator::new(schedule, profile)?,
            counts: MutableCounts::default(),
            retain_plan,
            entries: Vec::new(),
        })
    }

    fn walk_directory(
        &mut self,
        directory: &QualifiedDirectory,
        original_parent: &[String],
        safe_parent: &[String],
        ancestor_has_token: bool,
        depth: usize,
    ) -> Result<()> {
        if depth > MAX_DEPTH {
            return Err(Error::BoundExceeded);
        }
        let before = directory.observe()?;
        // Charge the complete retained-parent page set before descending into
        // any child. Without this reservation, a hostile first-child chain
        // could keep one maximum-size sibling vector alive at every depth
        // before the per-entry counter reached its global limit.
        self.counts.add_entries(before.entries().len())?;
        let mut virtual_names = Vec::new();
        virtual_names
            .try_reserve_exact(before.entries().len())
            .map_err(|_| Error::BoundExceeded)?;
        for (owner, entry) in before.entries().iter().enumerate() {
            if depth >= MAX_DEPTH {
                return Err(Error::BoundExceeded);
            }
            let name = entry.canonical_long_name();
            if contains_reserved_introducer(name.as_bytes()) {
                return Err(Error::InvalidToken);
            }
            let original_components = appended(original_parent, name)?;
            validate_relative_path(&original_components)?;
            let original_path = canonical_path(&original_components)?;
            self.counts.add_canonical_path(original_path.len())?;
            match entry.entry_kind() {
                EntryKind::Directory => {
                    self.counts.add_directory()?;
                    let child = directory.open_exact_child_directory(OsStr::new(name))?;
                    let transformed = self.tokenizer.transform_path(
                        name,
                        name.len(),
                        PathTokenContext {
                            canonical_original_path: &original_path,
                            parent_identity: directory.identity(),
                            component_index: u32::try_from(original_components.len() - 1)
                                .map_err(|_| Error::BoundExceeded)?,
                            entry_kind: TokenEntryKind::DirectoryComponent,
                            component_kind: TokenComponentKind::Path,
                            protected_suffix: "",
                        },
                    )?;
                    let safe_utf16 = validate_workspace_component(&transformed.name)?;
                    virtual_names.push((safe_utf16, owner));
                    let safe_components = appended(safe_parent, &transformed.name)?;
                    validate_relative_path(&safe_components)?;
                    let safe_path = canonical_path(&safe_components)?;
                    self.counts.add_ai_canonical_path(safe_path.len())?;
                    self.commit_directory(
                        entry,
                        child.identity(),
                        child.link_count()?,
                        DirectoryCommitContext {
                            canonical_original_path: &original_path,
                            safe_path: &safe_path,
                            evidence: &transformed.evidence,
                            facts: &transformed.facts,
                        },
                    )?;
                    if self.retain_plan {
                        self.entries.push(PlannedEntry::Directory {
                            original_components: original_components.clone(),
                            safe_components: safe_components.clone(),
                            token_facts: transformed.facts.clone(),
                            observed_short_alias_utf16: entry
                                .short_alias_utf16()
                                .map(<[u16]>::to_vec),
                        });
                    }
                    self.walk_directory(
                        &child,
                        &original_components,
                        &safe_components,
                        ancestor_has_token || !transformed.facts.is_empty(),
                        depth + 1,
                    )?;
                }
                EntryKind::File => {
                    self.counts.add_regular_file()?;
                    self.process_file(
                        directory,
                        entry,
                        owner,
                        original_components,
                        safe_parent,
                        original_path,
                        ancestor_has_token,
                        &mut virtual_names,
                    )?;
                }
                EntryKind::Unsupported => return Err(Error::UnsupportedAliasNamespace),
            }
        }
        validate_virtual_sibling_names(&virtual_names)?;
        let after = directory.observe()?;
        if before != after {
            return Err(Error::InvalidState);
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn process_file(
        &mut self,
        directory: &QualifiedDirectory,
        entry: &ObservedNamespaceEntry,
        owner: usize,
        original_components: Vec<String>,
        safe_parent: &[String],
        original_path: Vec<u8>,
        ancestor_has_token: bool,
        virtual_names: &mut Vec<(Vec<u16>, usize)>,
    ) -> Result<()> {
        let name = entry.canonical_long_name();
        let mut file = directory.open_observed_regular(entry)?;
        let before_identity = file_identity(&file)?;
        let before_metadata = file.metadata().map_err(|_| Error::FilesystemFailure)?;
        let before_modified = before_metadata
            .modified()
            .map_err(|_| Error::FilesystemFailure)?;
        let length = usize::try_from(before_metadata.len()).map_err(|_| Error::BoundExceeded)?;
        if length > MAX_FILE_BYTES {
            return Err(Error::BoundExceeded);
        }
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(length)
            .map_err(|_| Error::BoundExceeded)?;
        file.by_ref()
            .take(u64::try_from(MAX_FILE_BYTES + 1).map_err(|_| Error::BoundExceeded)?)
            .read_to_end(&mut bytes)
            .map_err(|_| Error::FilesystemFailure)?;
        if bytes.len() != length || bytes.len() > MAX_FILE_BYTES {
            return Err(Error::InvalidState);
        }
        if contains_reserved_introducer(&bytes) {
            return Err(Error::InvalidToken);
        }
        validate_regular_one_link_stream_clean(&file)?;
        let after_metadata = file.metadata().map_err(|_| Error::FilesystemFailure)?;
        let after_modified = after_metadata
            .modified()
            .map_err(|_| Error::FilesystemFailure)?;
        if file_identity(&file)? != before_identity
            || after_metadata.len() != before_metadata.len()
            || after_metadata.nlink() != before_metadata.nlink()
            || after_modified != before_modified
        {
            return Err(Error::InvalidState);
        }
        self.counts.add_file_bytes(bytes.len())?;

        let text = std::str::from_utf8(&bytes).ok();
        let outcome = if bytes.contains(&0) {
            ContentOutcome::BinaryLike
        } else if text.is_some() {
            ContentOutcome::ReadableText
        } else {
            ContentOutcome::InvalidUtf8
        };
        let detected = classify_path(Path::new(name), false);
        let (filename_evidence, filename_finding_count) = filename_evidence(name)?;
        let decision = effective_decision(FileDispositionInput {
            detected_kind: detected,
            content_outcome: Some(outcome),
            filename: filename_evidence,
            path_component: ComponentInspectability::Inspectable,
        })
        .map_err(|_| Error::InvalidState)?;
        let omission = omission_reason(decision, detected, outcome, filename_finding_count)?;

        let path_evidence = self.tokenizer.observe_evidence(name)?;
        let content_evidence = match text {
            Some(text) => self.tokenizer.observe_evidence(text)?,
            None => Vec::new(),
        };
        let mut safe_components = None;
        let mut path_facts = Vec::new();
        let mut content_facts = Vec::new();
        let mut expected_output_commitment = None;
        let mut expected_output_bytes = None;
        let mut content_anchor_facts = Vec::new();

        let disposition = if omission == OmissionReason::None {
            let text = text.ok_or(Error::InvalidState)?;
            let (stem, suffix) =
                split_transformable_file_component(name).map_err(|_| Error::InvalidState)?;
            let path = self.tokenizer.transform_path(
                name,
                stem.len(),
                PathTokenContext {
                    canonical_original_path: &original_path,
                    parent_identity: directory.identity(),
                    component_index: u32::try_from(original_components.len() - 1)
                        .map_err(|_| Error::BoundExceeded)?,
                    entry_kind: TokenEntryKind::RegularFile,
                    component_kind: TokenComponentKind::Filename,
                    protected_suffix: suffix,
                },
            )?;
            let content = self.tokenizer.transform_content(text, &original_path)?;
            let safe_utf16 = validate_workspace_component(&path.name)?;
            virtual_names.push((safe_utf16, owner));
            let full_safe = appended(safe_parent, &path.name)?;
            validate_relative_path(&full_safe)?;
            let safe_path = canonical_path(&full_safe)?;
            self.counts.add_ai_canonical_path(safe_path.len())?;
            let anchors = finalize_content_anchors(
                self.schedule,
                self.profile,
                ContentFileRole {
                    volume_serial: before_identity.volume_serial,
                    file_id: before_identity.file_id,
                    safe_canonical_path: &safe_path,
                },
                &bytes,
                &content.prepared_content_anchors,
                &content.facts,
            )?;
            let output_commitment = file_output_commitment(
                self.schedule,
                &full_safe,
                &content.bytes,
                &path.facts,
                &content.facts,
                &anchors,
            )?;
            self.expected_ai.push(safe_path, output_commitment)?;
            self.counts.add_visible_file(
                ancestor_has_token || !path.facts.is_empty() || !content.facts.is_empty(),
                content.bytes.len(),
            )?;
            expected_output_bytes =
                Some(u64::try_from(content.bytes.len()).map_err(|_| Error::BoundExceeded)?);
            expected_output_commitment = Some(output_commitment);
            path_facts = path.facts;
            content_facts = content.facts;
            content_anchor_facts = anchors;
            safe_components = Some(full_safe);
            FileDisposition::Transform
        } else {
            self.counts.add_omitted_file()?;
            FileDisposition::Omit(omission)
        };

        self.original.file_original(
            &original_path,
            entry,
            before_identity,
            before_metadata.nlink(),
            &bytes,
            disposition,
            &path_evidence,
            &content_evidence,
            &path_facts,
            &content_facts,
            &content_anchor_facts,
        )?;
        let original_file_reference_commitment = original_file_reference_commitment(
            self.schedule,
            &original_path,
            before_identity,
            &bytes,
        )?;
        drop(bytes);
        if self.retain_plan {
            self.entries.push(PlannedEntry::File {
                original_components,
                safe_components,
                disposition,
                expected_output_commitment,
                expected_output_bytes,
                path_token_facts: path_facts,
                content_token_facts: content_facts,
                content_anchor_facts,
                observed_short_alias_utf16: entry.short_alias_utf16().map(<[u16]>::to_vec),
                observed_identity: before_identity,
                original_file_reference_commitment,
            });
        }
        Ok(())
    }

    fn commit_directory(
        &mut self,
        entry: &ObservedNamespaceEntry,
        identity: FileIdentity,
        link_count: u64,
        context: DirectoryCommitContext<'_>,
    ) -> Result<()> {
        self.original.directory_original(
            context.canonical_original_path,
            entry,
            identity,
            link_count,
            context.evidence,
            context.facts,
        )?;
        let commitment =
            directory_output_commitment(self.schedule, context.safe_path, context.facts)?;
        self.expected_ai
            .push(context.safe_path.to_vec(), commitment)
    }

    fn finish(mut self) -> Result<BaselineDerivation> {
        let token_count = self.tokenizer.inventory().len();
        self.counts.token_occurrences = token_count;
        let counts = self.counts.finish()?;
        let original_tree_commitment = self.original.finish();
        let expected_ai_projection_commitment = self.expected_ai.finish()?;
        let inventory = self.tokenizer.into_inventory();
        if inventory.len()
            != usize::try_from(counts.token_occurrences).map_err(|_| Error::BoundExceeded)?
        {
            return Err(Error::InvalidState);
        }
        let inventory = if self.retain_plan {
            inventory
        } else {
            TokenInventory::new()
        };
        Ok(BaselineDerivation {
            summary: BaselineSummary {
                original_tree_commitment,
                expected_ai_projection_commitment,
                counts,
            },
            plan: BaselinePlan {
                entries: std::mem::take(&mut self.entries),
                inventory,
            },
        })
    }
}

#[derive(Default)]
struct MutableCounts {
    entries: usize,
    directories: usize,
    regular_files: usize,
    total_file_bytes: usize,
    ai_visible_files: usize,
    omitted_files: usize,
    token_occurrences: usize,
    token_bearing_files: usize,
    canonical_path_bytes: usize,
    ai_total_file_bytes: usize,
    ai_canonical_path_bytes: usize,
}

impl MutableCounts {
    fn add_entries(&mut self, count: usize) -> Result<()> {
        self.entries = checked_add(self.entries, count)?;
        if self.entries > MAX_ENTRIES {
            return Err(Error::BoundExceeded);
        }
        Ok(())
    }
    fn add_directory(&mut self) -> Result<()> {
        self.directories = checked_add(self.directories, 1)?;
        Ok(())
    }
    fn add_regular_file(&mut self) -> Result<()> {
        self.regular_files = checked_add(self.regular_files, 1)?;
        Ok(())
    }
    fn add_file_bytes(&mut self, bytes: usize) -> Result<()> {
        self.total_file_bytes = checked_add(self.total_file_bytes, bytes)?;
        if self.total_file_bytes > MAX_TOTAL_FILE_BYTES {
            return Err(Error::BoundExceeded);
        }
        Ok(())
    }
    fn add_canonical_path(&mut self, bytes: usize) -> Result<()> {
        self.canonical_path_bytes = checked_add(self.canonical_path_bytes, bytes)?;
        if self.canonical_path_bytes > MAX_CANONICAL_PATH_BYTES {
            return Err(Error::BoundExceeded);
        }
        Ok(())
    }
    fn add_ai_canonical_path(&mut self, bytes: usize) -> Result<()> {
        self.ai_canonical_path_bytes = checked_add(self.ai_canonical_path_bytes, bytes)?;
        if self.ai_canonical_path_bytes > MAX_CANONICAL_PATH_BYTES {
            return Err(Error::BoundExceeded);
        }
        Ok(())
    }
    fn add_visible_file(&mut self, token_bearing: bool, output_bytes: usize) -> Result<()> {
        if output_bytes > MAX_TRANSFORMED_FILE_BYTES {
            return Err(Error::BoundExceeded);
        }
        self.ai_total_file_bytes = checked_add(self.ai_total_file_bytes, output_bytes)?;
        if self.ai_total_file_bytes > MAX_TOTAL_AI_FILE_BYTES {
            return Err(Error::BoundExceeded);
        }
        self.ai_visible_files = checked_add(self.ai_visible_files, 1)?;
        if token_bearing {
            self.token_bearing_files = checked_add(self.token_bearing_files, 1)?;
        }
        Ok(())
    }
    fn add_omitted_file(&mut self) -> Result<()> {
        self.omitted_files = checked_add(self.omitted_files, 1)?;
        Ok(())
    }
    fn finish(self) -> Result<TreeCountsV1> {
        let value = TreeCountsV1 {
            entries: to_u32(self.entries)?,
            directories: to_u32(self.directories)?,
            regular_files: to_u32(self.regular_files)?,
            total_file_bytes: u64::try_from(self.total_file_bytes)
                .map_err(|_| Error::BoundExceeded)?,
            ai_visible_files: to_u32(self.ai_visible_files)?,
            omitted_files: to_u32(self.omitted_files)?,
            token_occurrences: to_u32(self.token_occurrences)?,
            token_bearing_files: to_u32(self.token_bearing_files)?,
            canonical_path_bytes: u64::try_from(self.canonical_path_bytes)
                .map_err(|_| Error::BoundExceeded)?,
        };
        value.validate()?;
        Ok(value)
    }
}

fn omission_reason(
    decision: Decision,
    detected: DetectedKind,
    outcome: ContentOutcome,
    filename_findings: usize,
) -> Result<OmissionReason> {
    match decision {
        Decision::Transform => Ok(OmissionReason::None),
        Decision::Omit if filename_findings != 0 => Ok(OmissionReason::FilenamePolicy),
        Decision::Omit => match detected {
            DetectedKind::Unsupported => Ok(OmissionReason::Unsupported),
            DetectedKind::Unknown => Ok(OmissionReason::Unknown),
            DetectedKind::TextOrCodeCandidate => match outcome {
                ContentOutcome::BinaryLike => Ok(OmissionReason::Binary),
                ContentOutcome::InvalidUtf8 => Ok(OmissionReason::InvalidUtf8),
                _ => Err(Error::InvalidState),
            },
            _ => Err(Error::InvalidState),
        },
        _ => Err(Error::InvalidState),
    }
}

fn filename_evidence(name: &str) -> Result<(FilenameEvidence, usize)> {
    let mut session = filename::Session::new(filename::Limits::default());
    let mut findings = Vec::new();
    let count = session
        .scan_basename(OsStr::new(name), |observed| {
            findings.extend_from_slice(observed)
        })
        .map_err(|_| Error::BoundExceeded)?;
    session.finish().map_err(|_| Error::InvalidState)?;
    Ok((FilenameEvidence::from_findings(&findings), count))
}

/// Independently re-apply the existing file classification and filename
/// policy to an actual readable UTF-8 AiWorkspace leaf. Expected-plan
/// membership is not a substitute for this verifier-side eligibility gate.
pub(super) fn require_ai_visible_file_policy(name: &str) -> Result<()> {
    let detected = classify_path(Path::new(name), false);
    let (filename, finding_count) = filename_evidence(name)?;
    let decision = effective_decision(FileDispositionInput {
        detected_kind: detected,
        content_outcome: Some(ContentOutcome::ReadableText),
        filename,
        path_component: ComponentInspectability::Inspectable,
    })
    .map_err(|_| Error::InvalidState)?;
    if detected != DetectedKind::TextOrCodeCandidate
        || finding_count != 0
        || decision != Decision::Transform
    {
        return Err(Error::InvalidState);
    }
    Ok(())
}

fn appended(parent: &[String], leaf: &str) -> Result<Vec<String>> {
    let mut value = parent.to_vec();
    value
        .try_reserve_exact(1)
        .map_err(|_| Error::BoundExceeded)?;
    value.push(leaf.to_owned());
    Ok(value)
}

pub(super) fn canonical_path(components: &[String]) -> Result<Vec<u8>> {
    if components.is_empty() {
        return Err(Error::InvalidCanonicalInput);
    }
    let total = components
        .iter()
        .try_fold(components.len() - 1, |total, item| {
            total.checked_add(item.len()).ok_or(Error::BoundExceeded)
        })?;
    if total > MAX_PATH_UTF8 {
        return Err(Error::BoundExceeded);
    }
    let mut output = Vec::new();
    output
        .try_reserve_exact(total)
        .map_err(|_| Error::BoundExceeded)?;
    for (index, component) in components.iter().enumerate() {
        if index != 0 {
            output.push(b'/');
        }
        output.extend_from_slice(component.as_bytes());
    }
    Ok(output)
}

pub(super) fn validate_relative_path(components: &[String]) -> Result<()> {
    let utf16 = components
        .iter()
        .try_fold(components.len().saturating_sub(1), |total, item| {
            total
                .checked_add(item.encode_utf16().count())
                .ok_or(Error::BoundExceeded)
        })?;
    if utf16 > MAX_PATH_UTF16 {
        return Err(Error::BoundExceeded);
    }
    canonical_path(components).map(drop)
}

fn checked_add(left: usize, right: usize) -> Result<usize> {
    left.checked_add(right).ok_or(Error::BoundExceeded)
}

fn to_u32(value: usize) -> Result<u32> {
    u32::try_from(value).map_err(|_| Error::BoundExceeded)
}

pub(super) fn file_output_commitment(
    schedule: &KeySchedule<'_>,
    safe_components: &[String],
    bytes: &[u8],
    path_facts: &[TokenFact],
    content_facts: &[TokenFact],
    content_anchors: &[ContentAnchorFact],
) -> Result<[u8; 32]> {
    let mut encoder = StreamEncoder::new(
        schedule,
        KeyPurpose::TreeCommit,
        b"safeclone/rt2/expected-file-output",
    )?;
    encoder.bytes(&canonical_path(safe_components)?)?;
    encoder.bytes(bytes)?;
    encoder.token_facts(path_facts)?;
    encoder.token_facts(content_facts)?;
    encoder.content_anchors(content_anchors)?;
    Ok(encoder.finish())
}

fn verify_content_anchor_facts(
    observed: &[ContentAnchorFact],
    expected: &[ContentAnchorFact],
) -> Result<()> {
    if observed.len() != expected.len() {
        return Err(Error::InvalidState);
    }

    let mut all_match = true;
    for (observed, expected) in observed.iter().zip(expected) {
        let structural_fields_match = observed.anchor_version == expected.anchor_version
            && observed.context_version == expected.context_version
            && observed.selected_radius == expected.selected_radius;
        let keyed_commitments_match = constant_time_equal(
            &observed.pre_token_anchor_commitment,
            &expected.pre_token_anchor_commitment,
        ) & constant_time_equal(
            &observed.final_anchor_commitment,
            &expected.final_anchor_commitment,
        );
        all_match &= structural_fields_match & keyed_commitments_match;
    }

    all_match.then_some(()).ok_or(Error::InvalidState)
}

pub(super) fn rederive_planned_file_output(
    original_root: &QualifiedDirectory,
    entry: &PlannedEntry,
    schedule: &KeySchedule<'_>,
    profile: ReviewProfile,
) -> Result<Vec<u8>> {
    let rederived = rederive_planned_file(original_root, entry, schedule, profile)?;
    Ok(rederived.safe_bytes)
}

pub(super) fn rederive_planned_file(
    original_root: &QualifiedDirectory,
    entry: &PlannedEntry,
    schedule: &KeySchedule<'_>,
    profile: ReviewProfile,
) -> Result<RederivedOriginalFile> {
    let PlannedEntry::File {
        original_components,
        safe_components: Some(expected_safe),
        disposition: FileDisposition::Transform,
        expected_output_commitment: Some(expected_commitment),
        expected_output_bytes: Some(expected_bytes),
        content_anchor_facts: expected_anchors,
        observed_identity: expected_identity,
        original_file_reference_commitment: expected_original_commitment,
        ..
    } = entry
    else {
        return Err(Error::InvalidState);
    };
    let (leaf, parent_components) = original_components
        .split_last()
        .ok_or(Error::InvalidCanonicalInput)?;
    let retained = open_directory_components(original_root, parent_components)?;
    let parent = retained.as_ref().unwrap_or(original_root);
    let mut file = parent.open_exact_regular(OsStr::new(leaf))?;
    let identity = file_identity(&file)?;
    let before = file.metadata().map_err(|_| Error::FilesystemFailure)?;
    let before_modified = before.modified().map_err(|_| Error::FilesystemFailure)?;
    let length = usize::try_from(before.len()).map_err(|_| Error::BoundExceeded)?;
    if length > MAX_FILE_BYTES {
        return Err(Error::BoundExceeded);
    }
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| Error::BoundExceeded)?;
    file.by_ref()
        .take(u64::try_from(MAX_FILE_BYTES + 1).map_err(|_| Error::BoundExceeded)?)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::FilesystemFailure)?;
    validate_regular_one_link_stream_clean(&file)?;
    let after = file.metadata().map_err(|_| Error::FilesystemFailure)?;
    let after_modified = after.modified().map_err(|_| Error::FilesystemFailure)?;
    if bytes.len() != length
        || file_identity(&file)? != identity
        || after.len() != before.len()
        || after.nlink() != before.nlink()
        || after_modified != before_modified
        || contains_reserved_introducer(&bytes)
    {
        return Err(Error::InvalidState);
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| Error::InvalidState)?;
    if bytes.contains(&0)
        || classify_path(Path::new(leaf), false) != DetectedKind::TextOrCodeCandidate
    {
        return Err(Error::InvalidState);
    }
    let (filename, finding_count) = filename_evidence(leaf)?;
    if finding_count != 0
        || effective_decision(FileDispositionInput {
            detected_kind: DetectedKind::TextOrCodeCandidate,
            content_outcome: Some(ContentOutcome::ReadableText),
            filename,
            path_component: ComponentInspectability::Inspectable,
        })
        .map_err(|_| Error::InvalidState)?
            != Decision::Transform
    {
        return Err(Error::InvalidState);
    }
    let canonical_original = canonical_path(original_components)?;
    if identity != *expected_identity
        || !constant_time_equal(
            &original_file_reference_commitment(schedule, &canonical_original, identity, &bytes)?,
            expected_original_commitment,
        )
    {
        return Err(Error::InvalidState);
    }
    let (stem, suffix) =
        split_transformable_file_component(leaf).map_err(|_| Error::InvalidState)?;
    let mut tokenizer = Tokenizer::new(schedule, profile)?;
    let path = tokenizer.transform_path(
        leaf,
        stem.len(),
        PathTokenContext {
            canonical_original_path: &canonical_original,
            parent_identity: parent.identity(),
            component_index: u32::try_from(original_components.len() - 1)
                .map_err(|_| Error::BoundExceeded)?,
            entry_kind: TokenEntryKind::RegularFile,
            component_kind: TokenComponentKind::Filename,
            protected_suffix: suffix,
        },
    )?;
    let content = tokenizer.transform_content(text, &canonical_original)?;
    let safe_path = canonical_path(expected_safe)?;
    let content_anchors = finalize_content_anchors(
        schedule,
        profile,
        ContentFileRole {
            volume_serial: identity.volume_serial,
            file_id: identity.file_id,
            safe_canonical_path: &safe_path,
        },
        &bytes,
        &content.prepared_content_anchors,
        &content.facts,
    )?;
    if expected_safe.last() != Some(&path.name)
        || u64::try_from(content.bytes.len()).map_err(|_| Error::BoundExceeded)? != *expected_bytes
    {
        return Err(Error::InvalidState);
    }
    verify_content_anchor_facts(&content_anchors, expected_anchors)?;
    if !constant_time_equal(
        &file_output_commitment(
            schedule,
            expected_safe,
            &content.bytes,
            &path.facts,
            &content.facts,
            &content_anchors,
        )?,
        expected_commitment,
    ) {
        return Err(Error::InvalidState);
    }
    let path_occurrences =
        rederived_occurrence_spans(&path.facts, &path.evidence, &path.pre_token_anchors)?;
    let content_occurrences = rederived_content_occurrence_spans(
        &content.facts,
        content.prepared_content_anchors.occurrences(),
        content.prepared_content_anchors.pre_token_commitments(),
    )?;
    Ok(RederivedOriginalFile {
        original_bytes: SecretVec::new(bytes),
        safe_bytes: content.bytes,
        path_occurrences,
        content_occurrences,
    })
}

fn rederived_content_occurrence_spans(
    facts: &[TokenFact],
    occurrences: &[DetectedContentOccurrence],
    protected_anchors: &[[u8; 32]],
) -> Result<Vec<RederivedOccurrenceSpan>> {
    if facts.len() != occurrences.len() || facts.len() != protected_anchors.len() {
        return Err(Error::InvalidToken);
    }
    let mut output = Vec::new();
    output
        .try_reserve_exact(facts.len())
        .map_err(|_| Error::BoundExceeded)?;
    for (order, ((fact, occurrence), protected_anchor)) in facts
        .iter()
        .zip(occurrences)
        .zip(protected_anchors)
        .enumerate()
    {
        if fact.category != occurrence.category
            || occurrence.start >= occurrence.end
            || occurrence.ordinal != u32::try_from(order).map_err(|_| Error::BoundExceeded)?
        {
            return Err(Error::InvalidToken);
        }
        output.push(RederivedOccurrenceSpan {
            fact: *fact,
            start: occurrence.start,
            end: occurrence.end,
            order: occurrence.ordinal,
            protected_anchor: *protected_anchor,
        });
    }
    Ok(output)
}

fn rederived_occurrence_spans(
    facts: &[TokenFact],
    evidence: &[EvidenceRegion],
    protected_anchors: &[[u8; 32]],
) -> Result<Vec<RederivedOccurrenceSpan>> {
    if facts.len() != evidence.len() || facts.len() != protected_anchors.len() {
        return Err(Error::InvalidToken);
    }
    let mut output = Vec::new();
    output
        .try_reserve_exact(facts.len())
        .map_err(|_| Error::BoundExceeded)?;
    for (order, ((fact, region), protected_anchor)) in facts
        .iter()
        .zip(evidence)
        .zip(protected_anchors)
        .enumerate()
    {
        if fact.category != region.category || region.start >= region.end {
            return Err(Error::InvalidToken);
        }
        output.push(RederivedOccurrenceSpan {
            fact: *fact,
            start: usize::try_from(region.start).map_err(|_| Error::BoundExceeded)?,
            end: usize::try_from(region.end).map_err(|_| Error::BoundExceeded)?,
            order: u32::try_from(order).map_err(|_| Error::BoundExceeded)?,
            protected_anchor: *protected_anchor,
        });
    }
    Ok(output)
}

pub(super) fn rederive_planned_directory_path(
    original_root: &QualifiedDirectory,
    entry: &PlannedEntry,
    schedule: &KeySchedule<'_>,
    profile: ReviewProfile,
) -> Result<RederivedDirectoryPath> {
    let PlannedEntry::Directory {
        original_components,
        safe_components,
        token_facts,
        ..
    } = entry
    else {
        return Err(Error::InvalidState);
    };
    let (leaf, parent_components) = original_components
        .split_last()
        .ok_or(Error::InvalidCanonicalInput)?;
    let retained = open_directory_components(original_root, parent_components)?;
    let parent = retained.as_ref().unwrap_or(original_root);
    let observed = parent.observe()?;
    let observed_entry = observed.find_exact_long(leaf)?;
    if observed_entry.entry_kind() != EntryKind::Directory {
        return Err(Error::InvalidState);
    }
    let child = parent.open_exact_child_directory(OsStr::new(leaf))?;
    child.verify()?;
    let canonical_original = canonical_path(original_components)?;
    let mut tokenizer = Tokenizer::new(schedule, profile)?;
    let path = tokenizer.transform_path(
        leaf,
        leaf.len(),
        PathTokenContext {
            canonical_original_path: &canonical_original,
            parent_identity: parent.identity(),
            component_index: u32::try_from(original_components.len() - 1)
                .map_err(|_| Error::BoundExceeded)?,
            entry_kind: TokenEntryKind::DirectoryComponent,
            component_kind: TokenComponentKind::Path,
            protected_suffix: "",
        },
    )?;
    if safe_components.last() != Some(&path.name) || path.facts != *token_facts {
        return Err(Error::InvalidState);
    }
    Ok(RederivedDirectoryPath {
        occurrences: rederived_occurrence_spans(
            &path.facts,
            &path.evidence,
            &path.pre_token_anchors,
        )?,
    })
}

pub(super) fn read_planned_original_file(
    original_root: &QualifiedDirectory,
    entry: &PlannedEntry,
    schedule: &KeySchedule<'_>,
) -> Result<SecretVec> {
    let PlannedEntry::File {
        original_components,
        observed_identity,
        original_file_reference_commitment: expected_commitment,
        ..
    } = entry
    else {
        return Err(Error::InvalidState);
    };
    let (leaf, parent_components) = original_components
        .split_last()
        .ok_or(Error::InvalidCanonicalInput)?;
    let retained = open_directory_components(original_root, parent_components)?;
    let parent = retained.as_ref().unwrap_or(original_root);
    let mut file = parent.open_exact_regular(OsStr::new(leaf))?;
    let identity = file_identity(&file)?;
    let before = file.metadata().map_err(|_| Error::FilesystemFailure)?;
    let before_modified = before.modified().map_err(|_| Error::FilesystemFailure)?;
    let length = usize::try_from(before.len()).map_err(|_| Error::BoundExceeded)?;
    if length > MAX_FILE_BYTES {
        return Err(Error::BoundExceeded);
    }
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| Error::BoundExceeded)?;
    file.by_ref()
        .take(u64::try_from(MAX_FILE_BYTES + 1).map_err(|_| Error::BoundExceeded)?)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::FilesystemFailure)?;
    validate_regular_one_link_stream_clean(&file)?;
    let after = file.metadata().map_err(|_| Error::FilesystemFailure)?;
    if bytes.len() != length
        || identity != *observed_identity
        || file_identity(&file)? != identity
        || after.len() != before.len()
        || after.nlink() != before.nlink()
        || after.modified().map_err(|_| Error::FilesystemFailure)? != before_modified
    {
        return Err(Error::InvalidState);
    }
    let original_path = canonical_path(original_components)?;
    if !constant_time_equal(
        &original_file_reference_commitment(schedule, &original_path, identity, &bytes)?,
        expected_commitment,
    ) {
        return Err(Error::OriginalBaselineMismatch);
    }
    Ok(SecretVec::new(bytes))
}

/// File-local candidate construction original-only stream. The callback sees at most 64 KiB at
/// a time, while the accepted reconstruction reference commitment and hostile-file
/// before/after observations are recomputed on the same retained handle.
pub(super) fn stream_planned_original_file(
    original_root: &QualifiedDirectory,
    entry: &PlannedEntry,
    schedule: &KeySchedule<'_>,
    mut consume: impl FnMut(&[u8]) -> Result<()>,
) -> Result<u64> {
    const BUFFER_BYTES: usize = 64 * 1024;
    let PlannedEntry::File {
        original_components,
        observed_identity,
        original_file_reference_commitment: expected_commitment,
        ..
    } = entry
    else {
        return Err(Error::InvalidState);
    };
    let (leaf, parent_components) = original_components
        .split_last()
        .ok_or(Error::InvalidCanonicalInput)?;
    let retained = open_directory_components(original_root, parent_components)?;
    let parent = retained.as_ref().unwrap_or(original_root);
    let mut file = parent.open_exact_regular(OsStr::new(leaf))?;
    let identity = file_identity(&file)?;
    let before = file.metadata().map_err(|_| Error::FilesystemFailure)?;
    let before_modified = before.modified().map_err(|_| Error::FilesystemFailure)?;
    let length = usize::try_from(before.len()).map_err(|_| Error::BoundExceeded)?;
    if length > MAX_FILE_BYTES || identity != *observed_identity {
        return Err(Error::OriginalBaselineMismatch);
    }
    let original_path = canonical_path(original_components)?;
    let mut reference = StreamEncoder::new(
        schedule,
        KeyPurpose::TreeCommit,
        b"safeclone/rt6/original-file-reference-v1",
    )?;
    reference.u8(2);
    reference.bytes(&original_path)?;
    reference.identity(identity);
    reference.u32(u32::try_from(length).map_err(|_| Error::BoundExceeded)?);

    let mut buffer = [0u8; BUFFER_BYTES];
    let mut remaining = length;
    while remaining != 0 {
        let requested = remaining.min(buffer.len());
        let read = file
            .read(&mut buffer[..requested])
            .map_err(|_| Error::FilesystemFailure)?;
        if read == 0 {
            return Err(Error::OriginalBaselineMismatch);
        }
        reference.raw(&buffer[..read]);
        consume(&buffer[..read])?;
        remaining -= read;
    }
    if file
        .read(&mut buffer[..1])
        .map_err(|_| Error::FilesystemFailure)?
        != 0
    {
        return Err(Error::OriginalBaselineMismatch);
    }
    validate_regular_one_link_stream_clean(&file)?;
    let after = file.metadata().map_err(|_| Error::FilesystemFailure)?;
    if file_identity(&file)? != identity
        || after.len() != before.len()
        || after.nlink() != before.nlink()
        || after.modified().map_err(|_| Error::FilesystemFailure)? != before_modified
        || !constant_time_equal(&reference.finish(), expected_commitment)
    {
        return Err(Error::OriginalBaselineMismatch);
    }
    u64::try_from(length).map_err(|_| Error::BoundExceeded)
}

fn original_file_reference_commitment(
    schedule: &KeySchedule<'_>,
    canonical_original_path: &[u8],
    identity: FileIdentity,
    bytes: &[u8],
) -> Result<[u8; 32]> {
    let mut encoder = StreamEncoder::new(
        schedule,
        KeyPurpose::TreeCommit,
        b"safeclone/rt6/original-file-reference-v1",
    )?;
    encoder.u8(2); // ordinary default-stream regular file
    encoder.bytes(canonical_original_path)?;
    encoder.identity(identity);
    encoder.bytes(bytes)?;
    Ok(encoder.finish())
}

fn open_directory_components(
    root: &QualifiedDirectory,
    components: &[String],
) -> Result<Option<QualifiedDirectory>> {
    let Some((first, rest)) = components.split_first() else {
        return Ok(None);
    };
    let mut current = root.open_exact_child_directory(OsStr::new(first))?;
    for component in rest {
        current = current.open_exact_child_directory(OsStr::new(component))?;
    }
    Ok(Some(current))
}

pub(super) fn directory_output_commitment(
    schedule: &KeySchedule<'_>,
    safe_path: &[u8],
    facts: &[TokenFact],
) -> Result<[u8; 32]> {
    let mut encoder = StreamEncoder::new(
        schedule,
        KeyPurpose::TreeCommit,
        b"safeclone/rt2/expected-directory-output",
    )?;
    encoder.bytes(safe_path)?;
    encoder.token_facts(facts)?;
    Ok(encoder.finish())
}

pub(super) struct ProjectionAccumulator {
    context: StreamEncoder,
    records: Vec<(Vec<u8>, Vec<u16>, [u8; 32])>,
}

impl ProjectionAccumulator {
    pub(super) fn new(schedule: &KeySchedule<'_>, profile: ReviewProfile) -> Result<Self> {
        let mut context = StreamEncoder::new(
            schedule,
            KeyPurpose::TreeCommit,
            b"safeclone/rt2/expected-ai-projection",
        )?;
        context.bytes(ENGINE_VERSION.as_bytes())?;
        context.bytes(POLICY_ID.as_bytes())?;
        context.bytes(ruleset_id().as_bytes())?;
        context.u16(TOKEN_SUITE_ID);
        context.u8(profile as u8);
        Ok(Self {
            context,
            records: Vec::new(),
        })
    }

    pub(super) fn push(&mut self, path: Vec<u8>, commitment: [u8; 32]) -> Result<()> {
        if self.records.len() >= MAX_ENTRIES {
            return Err(Error::BoundExceeded);
        }
        let text = std::str::from_utf8(&path).map_err(|_| Error::InvalidCanonicalInput)?;
        let sort_key = text.encode_utf16().collect::<Vec<_>>();
        self.records.push((path, sort_key, commitment));
        Ok(())
    }

    pub(super) fn finish(mut self) -> Result<[u8; 32]> {
        let keys = self
            .records
            .iter()
            .map(|(_, key, _)| key.clone())
            .collect::<Vec<_>>();
        let order = sort_utf16_indices(&keys)?;
        self.context
            .u32(u32::try_from(order.len()).map_err(|_| Error::BoundExceeded)?);
        for index in order {
            let (path, _, commitment) = &self.records[index];
            self.context.bytes(path)?;
            self.context.0.update(commitment);
        }
        Ok(self.context.finish())
    }
}

struct TreeEncoder(StreamEncoder);

impl TreeEncoder {
    fn new(schedule: &KeySchedule<'_>, role: &[u8], profile: ReviewProfile) -> Result<Self> {
        let mut value = StreamEncoder::new(
            schedule,
            KeyPurpose::TreeCommit,
            b"safeclone/rt2/tree-stream",
        )?;
        value.bytes(role)?;
        value.bytes(ENGINE_VERSION.as_bytes())?;
        value.bytes(POLICY_ID.as_bytes())?;
        value.bytes(ruleset_id().as_bytes())?;
        value.u16(TOKEN_SUITE_ID);
        value.u8(profile as u8);
        Ok(Self(value))
    }

    fn directory_original(
        &mut self,
        path: &[u8],
        entry: &ObservedNamespaceEntry,
        identity: FileIdentity,
        link_count: u64,
        evidence: &[EvidenceRegion],
        facts: &[TokenFact],
    ) -> Result<()> {
        self.0.u8(1);
        self.0.bytes(path)?;
        self.0.utf16(entry.canonical_long_name_utf16())?;
        self.0.optional_utf16(entry.short_alias_utf16())?;
        self.0.identity(identity);
        self.0.u64(entry.directory_file_id64());
        self.0.u64(link_count);
        self.0.bytes(&[])?; // no default data stream on a directory
        self.0.u8(1); // included directory topology
        self.0.u8(OmissionReason::None as u8);
        self.0.evidence(evidence)?;
        self.0.token_facts(facts)?;
        self.0.u8(0); // no reparse
        self.0.u8(0); // no named data stream
        self.0.u8(0); // no hard-link shape
        self.0.u8(0); // no special entry
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn file_original(
        &mut self,
        path: &[u8],
        entry: &ObservedNamespaceEntry,
        identity: FileIdentity,
        link_count: u64,
        bytes: &[u8],
        disposition: FileDisposition,
        path_evidence: &[EvidenceRegion],
        content_evidence: &[EvidenceRegion],
        path_facts: &[TokenFact],
        content_facts: &[TokenFact],
        content_anchors: &[ContentAnchorFact],
    ) -> Result<()> {
        self.0.u8(2);
        self.0.bytes(path)?;
        self.0.utf16(entry.canonical_long_name_utf16())?;
        self.0.optional_utf16(entry.short_alias_utf16())?;
        self.0.identity(identity);
        self.0.u64(entry.directory_file_id64());
        self.0.u64(link_count);
        self.0.bytes(bytes)?;
        match disposition {
            FileDisposition::Transform => {
                self.0.u8(1);
                self.0.u8(OmissionReason::None as u8);
            }
            FileDisposition::Omit(reason) => {
                self.0.u8(2);
                self.0.u8(reason as u8);
            }
        }
        self.0.evidence(path_evidence)?;
        self.0.evidence(content_evidence)?;
        self.0.token_facts(path_facts)?;
        self.0.token_facts(content_facts)?;
        self.0.content_anchors(content_anchors)?;
        self.0.u8(0); // no reparse
        self.0.u8(0); // no ADS
        self.0.u8(0); // no hard link
        self.0.u8(0); // no special entry
        Ok(())
    }

    fn finish(self) -> [u8; 32] {
        self.0.finish()
    }
}

pub(super) struct StreamEncoder(HmacStream);

impl StreamEncoder {
    pub(super) fn new(
        schedule: &KeySchedule<'_>,
        purpose: KeyPurpose,
        domain: &[u8],
    ) -> Result<Self> {
        let mut value = Self(HmacStream::new(schedule, purpose)?);
        value.bytes(domain)?;
        Ok(value)
    }
    pub(super) fn u8(&mut self, value: u8) {
        self.0.update(&[value]);
    }
    pub(super) fn u16(&mut self, value: u16) {
        self.0.update(&value.to_be_bytes());
    }
    pub(super) fn u32(&mut self, value: u32) {
        self.0.update(&value.to_be_bytes());
    }
    pub(super) fn u64(&mut self, value: u64) {
        self.0.update(&value.to_be_bytes());
    }
    pub(super) fn bytes(&mut self, bytes: &[u8]) -> Result<()> {
        self.u32(u32::try_from(bytes.len()).map_err(|_| Error::BoundExceeded)?);
        self.0.update(bytes);
        Ok(())
    }
    pub(super) fn raw(&mut self, bytes: &[u8]) {
        self.0.update(bytes);
    }
    pub(super) fn utf16(&mut self, units: &[u16]) -> Result<()> {
        self.u32(u32::try_from(units.len()).map_err(|_| Error::BoundExceeded)?);
        for unit in units {
            self.0.update(&unit.to_be_bytes());
        }
        Ok(())
    }
    fn optional_utf16(&mut self, units: Option<&[u16]>) -> Result<()> {
        match units {
            Some(units) => {
                self.u8(1);
                self.utf16(units)
            }
            None => {
                self.u8(0);
                Ok(())
            }
        }
    }
    fn identity(&mut self, identity: FileIdentity) {
        self.u64(identity.volume_serial);
        self.0.update(&identity.file_id);
    }
    fn evidence(&mut self, regions: &[EvidenceRegion]) -> Result<()> {
        self.u32(u32::try_from(regions.len()).map_err(|_| Error::BoundExceeded)?);
        for region in regions {
            self.u64(region.start);
            self.u64(region.end);
            self.u8(region.category as u8);
        }
        Ok(())
    }
    pub(super) fn token_facts(&mut self, facts: &[TokenFact]) -> Result<()> {
        self.u32(u32::try_from(facts.len()).map_err(|_| Error::BoundExceeded)?);
        for fact in facts {
            self.u8(fact.category as u8);
            self.0.update(&fact.occurrence_id);
        }
        Ok(())
    }
    pub(super) fn content_anchors(&mut self, anchors: &[ContentAnchorFact]) -> Result<()> {
        self.u32(u32::try_from(anchors.len()).map_err(|_| Error::BoundExceeded)?);
        for anchor in anchors {
            if anchor.anchor_version != PROTECTED_ANCHOR_VERSION
                || anchor.context_version != RELATIVE_CONTEXT_VERSION
                || !(1..=super::anchor::MAX_CONTEXT_LINES_PER_SIDE)
                    .contains(&usize::from(anchor.selected_radius))
            {
                return Err(Error::AnchorEncodingInvalid);
            }
            // Engine-v3 Original tree stream ordering for each content run:
            // anchor version, context version, selected radius, pre-token
            // commitment, then OID-bearing final commitment.
            self.u8(anchor.anchor_version);
            self.u8(anchor.context_version);
            self.u8(anchor.selected_radius);
            self.bytes(&anchor.pre_token_anchor_commitment)?;
            self.bytes(&anchor.final_anchor_commitment)?;
        }
        Ok(())
    }
    pub(super) fn finish(self) -> [u8; 32] {
        self.0.finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::roundtrip::crypto::{SessionId, SessionMasterSecret};
    use crate::roundtrip::token::TokenCategory;

    fn schedule<'a>(master: &'a SessionMasterSecret) -> KeySchedule<'a> {
        KeySchedule::new(master, SessionId::from_bytes([0x42; 16]))
    }

    fn content_anchor(radius: u8, pre_token: u8, final_anchor: u8) -> ContentAnchorFact {
        ContentAnchorFact {
            anchor_version: PROTECTED_ANCHOR_VERSION,
            context_version: RELATIVE_CONTEXT_VERSION,
            selected_radius: radius,
            pre_token_anchor_commitment: [pre_token; 32],
            final_anchor_commitment: [final_anchor; 32],
        }
    }

    #[test]
    fn content_anchor_verification_is_ordered_and_field_aware() {
        let expected = [content_anchor(2, 0x11, 0x21), content_anchor(3, 0x12, 0x22)];
        verify_content_anchor_facts(&expected, &expected).expect("exact anchor sequence");

        assert_eq!(
            verify_content_anchor_facts(&expected[..1], &expected),
            Err(Error::InvalidState)
        );

        let mut structural_mismatch = expected.clone();
        structural_mismatch[0].selected_radius += 1;
        assert_eq!(
            verify_content_anchor_facts(&structural_mismatch, &expected),
            Err(Error::InvalidState)
        );

        let mut reordered = expected.clone();
        reordered.swap(0, 1);
        assert_eq!(
            verify_content_anchor_facts(&reordered, &expected),
            Err(Error::InvalidState)
        );

        let mut pre_token_mismatch = expected.clone();
        pre_token_mismatch[0].pre_token_anchor_commitment[9] ^= 1;
        assert_eq!(
            verify_content_anchor_facts(&pre_token_mismatch, &expected),
            Err(Error::InvalidState)
        );

        let mut final_anchor_mismatch = expected.clone();
        final_anchor_mismatch[1].final_anchor_commitment[27] ^= 1;
        assert_eq!(
            verify_content_anchor_facts(&final_anchor_mismatch, &expected),
            Err(Error::InvalidState)
        );
    }

    #[test]
    fn root_is_excluded_and_count_invariants_are_checked() {
        let mut counts = MutableCounts::default();
        counts.add_entries(1).expect("entry");
        counts.add_directory().expect("directory");
        let value = counts.finish().expect("valid counts");
        assert_eq!(value.entries, 1);
        assert_eq!(value.directories, 1);
        assert_eq!(value.regular_files, 0);
    }

    #[test]
    fn canonical_paths_are_slash_separated_and_bounded() {
        assert_eq!(
            canonical_path(&["one".into(), "two.txt".into()]).expect("path"),
            b"one/two.txt"
        );
        assert_eq!(canonical_path(&[]), Err(Error::InvalidCanonicalInput));
    }

    #[test]
    fn disposition_matrix_distinguishes_omission_from_session_rejection() {
        assert_eq!(
            omission_reason(
                Decision::Transform,
                DetectedKind::TextOrCodeCandidate,
                ContentOutcome::ReadableText,
                0,
            ),
            Ok(OmissionReason::None)
        );
        assert_eq!(
            omission_reason(
                Decision::Omit,
                DetectedKind::TextOrCodeCandidate,
                ContentOutcome::ReadableText,
                1,
            ),
            Ok(OmissionReason::FilenamePolicy)
        );
        for (detected, outcome, expected) in [
            (
                DetectedKind::TextOrCodeCandidate,
                ContentOutcome::BinaryLike,
                OmissionReason::Binary,
            ),
            (
                DetectedKind::TextOrCodeCandidate,
                ContentOutcome::InvalidUtf8,
                OmissionReason::InvalidUtf8,
            ),
            (
                DetectedKind::Unsupported,
                ContentOutcome::ReadableText,
                OmissionReason::Unsupported,
            ),
            (
                DetectedKind::Unknown,
                ContentOutcome::ReadableText,
                OmissionReason::Unknown,
            ),
        ] {
            assert_eq!(
                omission_reason(Decision::Omit, detected, outcome, 0),
                Ok(expected)
            );
        }
        assert_eq!(
            omission_reason(
                Decision::Omit,
                DetectedKind::TextOrCodeCandidate,
                ContentOutcome::ReadableText,
                0,
            ),
            Err(Error::InvalidState)
        );
    }

    #[test]
    fn actual_ai_file_policy_rejects_unsupported_and_high_risk_leaves() {
        require_ai_visible_file_policy("ordinary.txt").expect("supported readable leaf");
        for rejected in ["unsupported.png", "credentials.txt", ".env"] {
            assert_eq!(
                require_ai_visible_file_policy(rejected),
                Err(Error::InvalidState),
                "{rejected}"
            );
        }
    }

    #[test]
    fn roundtrip_bounds_fail_before_integer_or_memory_growth() {
        let mut entries = MutableCounts {
            entries: MAX_ENTRIES,
            ..MutableCounts::default()
        };
        assert_eq!(entries.add_entries(1), Err(Error::BoundExceeded));

        let mut bytes = MutableCounts {
            total_file_bytes: MAX_TOTAL_FILE_BYTES,
            ..MutableCounts::default()
        };
        assert_eq!(bytes.add_file_bytes(1), Err(Error::BoundExceeded));

        let mut ai_bytes = MutableCounts {
            ai_total_file_bytes: MAX_TOTAL_AI_FILE_BYTES,
            ..MutableCounts::default()
        };
        assert_eq!(
            ai_bytes.add_visible_file(false, 1),
            Err(Error::BoundExceeded)
        );
        assert_eq!(
            MutableCounts::default().add_visible_file(false, MAX_TRANSFORMED_FILE_BYTES + 1),
            Err(Error::BoundExceeded)
        );

        let mut ai_paths = MutableCounts {
            ai_canonical_path_bytes: MAX_CANONICAL_PATH_BYTES,
            ..MutableCounts::default()
        };
        assert_eq!(ai_paths.add_ai_canonical_path(1), Err(Error::BoundExceeded));

        let oversized = "a".repeat(MAX_PATH_UTF8 + 1);
        assert_eq!(canonical_path(&[oversized]), Err(Error::BoundExceeded));
    }

    #[test]
    fn projection_commitment_is_order_independent_but_content_sensitive() {
        let master = SessionMasterSecret::from_bytes([0x33; 32]);
        let schedule = schedule(&master);
        let mut first =
            ProjectionAccumulator::new(&schedule, ReviewProfile::StandardV2).expect("first");
        first.push(b"b.txt".to_vec(), [2; 32]).expect("first b");
        first.push(b"A.txt".to_vec(), [1; 32]).expect("first a");
        let mut second =
            ProjectionAccumulator::new(&schedule, ReviewProfile::StandardV2).expect("second");
        second.push(b"A.txt".to_vec(), [1; 32]).expect("second a");
        second.push(b"b.txt".to_vec(), [2; 32]).expect("second b");
        assert_eq!(
            first.finish().expect("finish first"),
            second.finish().expect("finish second")
        );

        let mut changed =
            ProjectionAccumulator::new(&schedule, ReviewProfile::StandardV2).expect("changed");
        changed.push(b"A.txt".to_vec(), [9; 32]).expect("changed a");
        changed.push(b"b.txt".to_vec(), [2; 32]).expect("changed b");
        assert_ne!(
            second_finish_for_test(&schedule),
            changed.finish().expect("finish changed")
        );
    }

    fn second_finish_for_test(schedule: &KeySchedule<'_>) -> [u8; 32] {
        let mut value =
            ProjectionAccumulator::new(schedule, ReviewProfile::StandardV2).expect("comparison");
        value
            .push(b"A.txt".to_vec(), [1; 32])
            .expect("comparison a");
        value
            .push(b"b.txt".to_vec(), [2; 32])
            .expect("comparison b");
        value.finish().expect("comparison finish")
    }

    #[test]
    fn engine_v3_original_and_ai_projection_commitment_vectors_are_exact() {
        let master = SessionMasterSecret::from_bytes([0x33; 32]);
        let schedule = schedule(&master);
        let entry = ObservedNamespaceEntry::synthetic_file_for_commitment(
            "config.txt",
            Some("CONFIG~1.TXT"),
            9,
        );
        let identity = FileIdentity {
            volume_serial: 7,
            file_id: [8; 16],
        };
        let path_evidence = [EvidenceRegion {
            start: 1,
            end: 2,
            category: TokenCategory::Email,
        }];
        let content_evidence = [EvidenceRegion {
            start: 7,
            end: 10,
            category: TokenCategory::Secret,
        }];
        let path_facts = [TokenFact {
            category: TokenCategory::Email,
            occurrence_id: [1; 16],
        }];
        let content_facts = [
            TokenFact {
                category: TokenCategory::Secret,
                occurrence_id: [2; 16],
            },
            TokenFact {
                category: TokenCategory::Ip,
                occurrence_id: [3; 16],
            },
        ];
        let anchor = ContentAnchorFact {
            anchor_version: PROTECTED_ANCHOR_VERSION,
            context_version: RELATIVE_CONTEXT_VERSION,
            selected_radius: 5,
            pre_token_anchor_commitment: [4; 32],
            final_anchor_commitment: [5; 32],
        };
        let original = representative_original_commitment(
            &schedule,
            &entry,
            identity,
            b"before\napi=synthetic\nafter\n",
            &path_evidence,
            &content_evidence,
            &path_facts,
            &content_facts,
            std::slice::from_ref(&anchor),
        );
        let output = file_output_commitment(
            &schedule,
            &["config.txt".to_owned()],
            b"before\napi=__SAFECLONE_RT1_SYNTHETIC__\nafter\n",
            &path_facts,
            &content_facts,
            std::slice::from_ref(&anchor),
        )
        .expect("output commitment");
        let mut projection =
            ProjectionAccumulator::new(&schedule, ReviewProfile::StandardV2).expect("projection");
        projection
            .push(b"config.txt".to_vec(), output)
            .expect("projection record");
        let projection = projection.finish().expect("projection finish");

        assert_eq!(
            vector_hex(&original),
            "6eeb14f9a91f2a2ef21f21e9241675b03b5c7c26031fd8182f45f7cd6237399f"
        );
        assert_eq!(
            vector_hex(&projection),
            "c2029e1752bac7a1c2e904c85a398a33d7a1a5dc2dbd593fda0287232bf621e3"
        );

        let mut changed_radius = anchor.clone();
        changed_radius.selected_radius = 6;
        let mut changed_pre = anchor.clone();
        changed_pre.pre_token_anchor_commitment[0] ^= 1;
        let mut changed_final = anchor.clone();
        changed_final.final_anchor_commitment[0] ^= 1;
        for changed in [changed_radius, changed_pre, changed_final] {
            assert_ne!(
                original,
                representative_original_commitment(
                    &schedule,
                    &entry,
                    identity,
                    b"before\napi=synthetic\nafter\n",
                    &path_evidence,
                    &content_evidence,
                    &path_facts,
                    &content_facts,
                    std::slice::from_ref(&changed),
                )
            );
        }
        assert_ne!(
            original,
            representative_original_commitment(
                &schedule,
                &entry,
                identity,
                b"before\napi=changed!!\nafter\n",
                &path_evidence,
                &content_evidence,
                &path_facts,
                &content_facts,
                std::slice::from_ref(&anchor),
            )
        );
        assert_ne!(
            original,
            representative_original_commitment(
                &schedule,
                &entry,
                identity,
                b"before\napi=synthetic\nafter\n",
                &path_evidence,
                &content_evidence,
                &path_facts,
                &[content_facts[1], content_facts[0]],
                std::slice::from_ref(&anchor),
            )
        );
    }

    #[allow(clippy::too_many_arguments)]
    fn representative_original_commitment(
        schedule: &KeySchedule<'_>,
        entry: &ObservedNamespaceEntry,
        identity: FileIdentity,
        bytes: &[u8],
        path_evidence: &[EvidenceRegion],
        content_evidence: &[EvidenceRegion],
        path_facts: &[TokenFact],
        content_facts: &[TokenFact],
        anchors: &[ContentAnchorFact],
    ) -> [u8; 32] {
        let mut encoder =
            TreeEncoder::new(schedule, b"ORIGINAL", ReviewProfile::StandardV2).expect("tree");
        encoder
            .file_original(
                b"config.txt",
                entry,
                identity,
                1,
                bytes,
                FileDisposition::Transform,
                path_evidence,
                content_evidence,
                path_facts,
                content_facts,
                anchors,
            )
            .expect("file record");
        encoder.finish()
    }

    fn vector_hex(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut output = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            output.push(char::from(HEX[usize::from(byte >> 4)]));
            output.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        output
    }
}
