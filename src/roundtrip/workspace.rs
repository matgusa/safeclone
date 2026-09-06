//! Empty-first AiWorkspace construction and independent retained observation.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::io::{Read, Seek, SeekFrom, Write};

use cap_fs_ext::MetadataExt;

use super::baseline::{
    canonical_path, directory_output_commitment, file_output_commitment,
    rederive_planned_file_output, require_ai_visible_file_policy, validate_relative_path,
    BaselinePlan, BaselineSummary, FileDisposition, PlannedEntry, ProjectionAccumulator,
    StreamEncoder, MAX_CANONICAL_PATH_BYTES, MAX_TOTAL_AI_FILE_BYTES,
};
use super::crypto::{constant_time_equal, KeyPurpose, KeySchedule};
use super::observe::{
    file_identity, validate_regular_one_link_stream_clean, validate_workspace_component, EntryKind,
    FileIdentity, QualifiedDirectory,
};
use super::token::ReviewProfile;
use super::tokenize::{
    scan_authentic_tokens, DetectorSet, TokenFact, TokenInventory, MAX_TRANSFORMED_FILE_BYTES,
};
use super::{Error, Result};

pub(super) fn build(
    root: QualifiedDirectory,
    original: &QualifiedDirectory,
    plan: &BaselinePlan,
    schedule: &KeySchedule<'_>,
    profile: ReviewProfile,
) -> Result<QualifiedDirectory> {
    let mut stack = Vec::new();
    stack.push((Vec::<String>::new(), root));
    for entry in &plan.entries {
        let Some(safe) = entry.safe_components() else {
            continue;
        };
        let (leaf, parent_path) = safe.split_last().ok_or(Error::InvalidState)?;
        while stack
            .last()
            .is_some_and(|(path, _)| path.as_slice() != parent_path)
        {
            if stack.len() == 1 {
                return Err(Error::InvalidState);
            }
            stack.pop();
        }
        let parent = &stack.last().ok_or(Error::InvalidState)?.1;
        match entry {
            PlannedEntry::Directory { .. } => {
                let leaf = parent.validate_absent_leaf(OsStr::new(leaf))?;
                let created = parent.create_directory(leaf)?;
                #[cfg(test)]
                crate::roundtrip::create::test_checkpoint(
                    crate::roundtrip::create::TestCheckpoint::WorkspaceDirectoryCreated,
                )?;
                stack.push((safe.to_vec(), created));
            }
            PlannedEntry::File {
                disposition: FileDisposition::Transform,
                expected_output_bytes: Some(expected_bytes),
                ..
            } => {
                // Re-derive and bound the exact output before creating its
                // namespace entry. The bytes remain transient in memory.
                let bytes = rederive_planned_file_output(original, entry, schedule, profile)?;
                if bytes.len() > MAX_TRANSFORMED_FILE_BYTES {
                    return Err(Error::BoundExceeded);
                }
                if u64::try_from(bytes.len()).map_err(|_| Error::BoundExceeded)? != *expected_bytes
                {
                    return Err(Error::InvalidState);
                }
                let leaf = parent.validate_absent_leaf(OsStr::new(leaf))?;
                let mut created = parent.create_empty_file(leaf)?;
                #[cfg(test)]
                crate::roundtrip::create::test_checkpoint(
                    crate::roundtrip::create::TestCheckpoint::WorkspaceFileCreatedEmpty,
                )?;
                // The created entry has passed its alias/identity gate while
                // still empty. Only now may the already-bounded AI-safe bytes
                // be written through that retained handle.
                let before = created.identity();
                created
                    .file_mut()
                    .write_all(&bytes)
                    .map_err(|_| Error::FilesystemFailure)?;
                created
                    .file()
                    .sync_all()
                    .map_err(|_| Error::FilesystemFailure)?;
                created
                    .file_mut()
                    .seek(SeekFrom::Start(0))
                    .map_err(|_| Error::FilesystemFailure)?;
                let mut readback = Vec::new();
                readback
                    .try_reserve_exact(bytes.len())
                    .map_err(|_| Error::BoundExceeded)?;
                created
                    .file_mut()
                    .read_to_end(&mut readback)
                    .map_err(|_| Error::FilesystemFailure)?;
                validate_regular_one_link_stream_clean(created.file())?;
                if readback != bytes || file_identity(created.file())? != before {
                    return Err(Error::InvalidState);
                }
                #[cfg(test)]
                crate::roundtrip::create::test_checkpoint(
                    crate::roundtrip::create::TestCheckpoint::WorkspaceFileWritten,
                )?;
                parent.verify()?;
                parent.requery_policy()?;
            }
            PlannedEntry::File {
                disposition: FileDisposition::Omit(_),
                ..
            } => {}
            PlannedEntry::File { .. } => return Err(Error::InvalidState),
        }
    }
    while stack.len() > 1 {
        stack.pop();
    }
    let (_, root) = stack.pop().ok_or(Error::InvalidState)?;
    root.verify()?;
    Ok(root)
}

#[derive(Clone, Debug)]
pub(super) struct WorkspaceSummary {
    pub(super) actual_tree_commitment: [u8; 32],
    pub(super) expected_projection_commitment: [u8; 32],
    pub(super) entries: u32,
    pub(super) directories: u32,
    pub(super) regular_files: u32,
    pub(super) total_file_bytes: u64,
    pub(super) token_occurrences: u32,
}

fn verify_workspace_summary(
    observed: &WorkspaceSummary,
    expected: &WorkspaceSummary,
) -> Result<()> {
    let keyed_commitments_match = constant_time_equal(
        &observed.actual_tree_commitment,
        &expected.actual_tree_commitment,
    ) & constant_time_equal(
        &observed.expected_projection_commitment,
        &expected.expected_projection_commitment,
    );
    let structural_fields_match = observed.entries == expected.entries
        && observed.directories == expected.directories
        && observed.regular_files == expected.regular_files
        && observed.total_file_bytes == expected.total_file_bytes
        && observed.token_occurrences == expected.token_occurrences;

    (keyed_commitments_match && structural_fields_match)
        .then_some(())
        .ok_or(Error::InvalidState)
}

pub(super) fn verify_two_stable_passes(
    root: &QualifiedDirectory,
    plan: &BaselinePlan,
    baseline: &BaselineSummary,
    schedule: &KeySchedule<'_>,
    profile: ReviewProfile,
) -> Result<WorkspaceSummary> {
    let first = observe(root, plan, schedule, profile)?;
    #[cfg(test)]
    crate::roundtrip::create::test_checkpoint(
        crate::roundtrip::create::TestCheckpoint::AfterAiPassOne,
    )?;
    let second = observe(root, plan, schedule, profile)?;
    verify_workspace_summary(&first, &second)?;
    if !constant_time_equal(
        &first.expected_projection_commitment,
        &baseline.expected_ai_projection_commitment,
    ) || first.directories != baseline.counts.directories
        || first.regular_files != baseline.counts.ai_visible_files
        || first.entries
            != baseline
                .counts
                .directories
                .checked_add(baseline.counts.ai_visible_files)
                .ok_or(Error::BoundExceeded)?
        || first.token_occurrences != baseline.counts.token_occurrences
    {
        return Err(Error::InvalidState);
    }
    Ok(first)
}

pub(super) fn verify_against(
    root: &QualifiedDirectory,
    plan: &BaselinePlan,
    expected: &WorkspaceSummary,
    schedule: &KeySchedule<'_>,
    profile: ReviewProfile,
) -> Result<()> {
    let observed = observe(root, plan, schedule, profile)?;
    verify_workspace_summary(&observed, expected)
}

fn observe(
    root: &QualifiedDirectory,
    plan: &BaselinePlan,
    schedule: &KeySchedule<'_>,
    profile: ReviewProfile,
) -> Result<WorkspaceSummary> {
    let expected = expected_entries(plan)?;
    let mut state = VerificationState::new(
        root.identity(),
        plan.inventory
            .iter()
            .map(|(oid, category)| (*oid, *category)),
        schedule,
        profile,
    )?;
    walk(root, &[], &expected, &plan.inventory, schedule, &mut state)?;
    root.verify()?;
    if state.seen_paths.len() != expected.len()
        || state.seen_oids.len() != plan.inventory.len()
        || state
            .expected_inventory
            .iter()
            .any(|(oid, category)| plan.inventory.category_for(oid) != Some(*category))
    {
        return Err(Error::InvalidState);
    }
    Ok(WorkspaceSummary {
        actual_tree_commitment: state.actual.finish()?,
        expected_projection_commitment: state.projection.finish()?,
        entries: u32::try_from(state.seen_paths.len()).map_err(|_| Error::BoundExceeded)?,
        directories: u32::try_from(state.directories).map_err(|_| Error::BoundExceeded)?,
        regular_files: u32::try_from(state.files).map_err(|_| Error::BoundExceeded)?,
        total_file_bytes: u64::try_from(state.total_bytes).map_err(|_| Error::BoundExceeded)?,
        token_occurrences: u32::try_from(state.seen_oids.len())
            .map_err(|_| Error::BoundExceeded)?,
    })
}

fn expected_entries(plan: &BaselinePlan) -> Result<BTreeMap<Vec<String>, &PlannedEntry>> {
    let mut expected = BTreeMap::new();
    for entry in &plan.entries {
        if let Some(path) = entry.safe_components() {
            if expected.insert(path.to_vec(), entry).is_some() {
                return Err(Error::InvalidState);
            }
        }
    }
    Ok(expected)
}

fn walk(
    directory: &QualifiedDirectory,
    parent: &[String],
    expected: &BTreeMap<Vec<String>, &PlannedEntry>,
    inventory: &TokenInventory,
    schedule: &KeySchedule<'_>,
    state: &mut VerificationState,
) -> Result<()> {
    let before = directory.observe()?;
    for entry in before.entries() {
        let path = append(parent, entry.canonical_long_name())?;
        validate_relative_path(&path)?;
        state.canonical_path_bytes =
            checked_add(state.canonical_path_bytes, canonical_path(&path)?.len())?;
        if state.canonical_path_bytes > MAX_CANONICAL_PATH_BYTES {
            return Err(Error::BoundExceeded);
        }
        let planned = expected.get(&path).ok_or(Error::InvalidState)?;
        if !state.seen_paths.insert(path.clone()) {
            return Err(Error::InvalidState);
        }
        validate_workspace_component(entry.canonical_long_name())?;
        let (path_facts, masked_name) = scan_authentic_tokens(
            schedule,
            entry.canonical_long_name(),
            inventory,
            &state.detectors,
        )?;
        record_oids(&path_facts, &mut state.seen_oids)?;
        match (entry.entry_kind(), *planned) {
            (EntryKind::Directory, PlannedEntry::Directory { token_facts, .. })
                if path_facts == *token_facts =>
            {
                if masked_name.is_empty() {
                    return Err(Error::InvalidState);
                }
                let child = directory
                    .open_exact_child_directory(OsStr::new(entry.canonical_long_name()))?;
                let projection =
                    directory_output_commitment(schedule, &canonical_path(&path)?, &path_facts)?;
                state.projection.push(canonical_path(&path)?, projection)?;
                let actual = actual_directory_commitment(
                    schedule,
                    &path,
                    entry,
                    child.identity(),
                    child.link_count()?,
                    &path_facts,
                )?;
                state.actual.push(canonical_path(&path)?, actual)?;
                state.directories = checked_add(state.directories, 1)?;
                walk(&child, &path, expected, inventory, schedule, state)?;
            }
            (
                EntryKind::File,
                PlannedEntry::File {
                    disposition: FileDisposition::Transform,
                    expected_output_commitment: Some(expected_commitment),
                    expected_output_bytes: Some(expected_bytes),
                    path_token_facts,
                    content_token_facts,
                    content_anchor_facts,
                    ..
                },
            ) if path_facts == *path_token_facts => {
                let mut file = directory.open_observed_regular(entry)?;
                let identity = file_identity(&file)?;
                let metadata = file.metadata().map_err(|_| Error::FilesystemFailure)?;
                let modified = metadata.modified().map_err(|_| Error::FilesystemFailure)?;
                let length = usize::try_from(metadata.len()).map_err(|_| Error::BoundExceeded)?;
                if length > MAX_TRANSFORMED_FILE_BYTES
                    || u64::try_from(length).map_err(|_| Error::BoundExceeded)? != *expected_bytes
                {
                    return Err(Error::BoundExceeded);
                }
                let mut bytes = Vec::new();
                bytes
                    .try_reserve_exact(length)
                    .map_err(|_| Error::BoundExceeded)?;
                Read::by_ref(&mut file)
                    .take(
                        u64::try_from(MAX_TRANSFORMED_FILE_BYTES + 1)
                            .map_err(|_| Error::BoundExceeded)?,
                    )
                    .read_to_end(&mut bytes)
                    .map_err(|_| Error::FilesystemFailure)?;
                validate_regular_one_link_stream_clean(&file)?;
                let after = file.metadata().map_err(|_| Error::FilesystemFailure)?;
                if bytes.len() != length
                    || file_identity(&file)? != identity
                    || after.len() != metadata.len()
                    || after.nlink() != metadata.nlink()
                    || after.modified().map_err(|_| Error::FilesystemFailure)? != modified
                {
                    return Err(Error::InvalidState);
                }
                let text = std::str::from_utf8(&bytes).map_err(|_| Error::InvalidState)?;
                if bytes.contains(&0) {
                    return Err(Error::InvalidState);
                }
                require_ai_visible_file_policy(entry.canonical_long_name())?;
                let (content_facts, _) =
                    scan_authentic_tokens(schedule, text, inventory, &state.detectors)?;
                if content_facts != *content_token_facts {
                    return Err(Error::InvalidToken);
                }
                record_oids(&content_facts, &mut state.seen_oids)?;
                let commitment = file_output_commitment(
                    schedule,
                    &path,
                    &bytes,
                    &path_facts,
                    &content_facts,
                    content_anchor_facts,
                )?;
                if !constant_time_equal(&commitment, expected_commitment) {
                    return Err(Error::InvalidState);
                }
                state.projection.push(canonical_path(&path)?, commitment)?;
                let actual = actual_file_commitment(
                    schedule,
                    &path,
                    entry,
                    identity,
                    metadata.nlink(),
                    &bytes,
                    &path_facts,
                    &content_facts,
                    content_anchor_facts,
                )?;
                state.actual.push(canonical_path(&path)?, actual)?;
                state.files = checked_add(state.files, 1)?;
                state.total_bytes = checked_add(state.total_bytes, bytes.len())?;
                if state.total_bytes > MAX_TOTAL_AI_FILE_BYTES {
                    return Err(Error::BoundExceeded);
                }
            }
            _ => return Err(Error::InvalidState),
        }
    }
    let after = directory.observe()?;
    if before != after {
        return Err(Error::InvalidState);
    }
    Ok(())
}

struct VerificationState {
    actual: PhysicalAccumulator,
    projection: ProjectionAccumulator,
    detectors: DetectorSet,
    seen_paths: BTreeSet<Vec<String>>,
    seen_oids: BTreeSet<[u8; 16]>,
    expected_inventory: BTreeMap<[u8; 16], super::token::TokenCategory>,
    directories: usize,
    files: usize,
    total_bytes: usize,
    canonical_path_bytes: usize,
}

impl VerificationState {
    fn new(
        root_identity: FileIdentity,
        inventory: impl Iterator<Item = ([u8; 16], super::token::TokenCategory)>,
        schedule: &KeySchedule<'_>,
        profile: ReviewProfile,
    ) -> Result<Self> {
        Ok(Self {
            actual: PhysicalAccumulator::new(schedule, profile, root_identity)?,
            projection: ProjectionAccumulator::new(schedule, profile)?,
            detectors: DetectorSet::compile()?,
            seen_paths: BTreeSet::new(),
            seen_oids: BTreeSet::new(),
            expected_inventory: inventory.collect(),
            directories: 0,
            files: 0,
            total_bytes: 0,
            canonical_path_bytes: 0,
        })
    }
}

struct PhysicalAccumulator(ProjectionAccumulator);

impl PhysicalAccumulator {
    fn new(
        schedule: &KeySchedule<'_>,
        profile: ReviewProfile,
        root_identity: FileIdentity,
    ) -> Result<Self> {
        let mut value = ProjectionAccumulator::new(schedule, profile)?;
        let mut root = StreamEncoder::new(
            schedule,
            KeyPurpose::TreeCommit,
            b"safeclone/rt2/actual-ai-root",
        )?;
        root.u64(root_identity.volume_serial);
        root.bytes(&root_identity.file_id)?;
        value.push(Vec::from(b"."), root.finish())?;
        Ok(Self(value))
    }

    fn push(&mut self, path: Vec<u8>, commitment: [u8; 32]) -> Result<()> {
        self.0.push(path, commitment)
    }

    fn finish(self) -> Result<[u8; 32]> {
        self.0.finish()
    }
}

fn actual_directory_commitment(
    schedule: &KeySchedule<'_>,
    path: &[String],
    entry: &super::observe::ObservedNamespaceEntry,
    identity: FileIdentity,
    link_count: u64,
    facts: &[TokenFact],
) -> Result<[u8; 32]> {
    let mut value = actual_entry_prefix(schedule, path, entry, identity, 1)?;
    value.u64(link_count);
    value.bytes(&[])?;
    value.u8(1); // included directory topology
    value.u8(super::baseline::OmissionReason::None as u8);
    value.token_facts(facts)?;
    for _ in 0..4 {
        value.u8(0); // reparse / named stream / hard-link / special absent
    }
    Ok(value.finish())
}

#[allow(clippy::too_many_arguments)]
fn actual_file_commitment(
    schedule: &KeySchedule<'_>,
    path: &[String],
    entry: &super::observe::ObservedNamespaceEntry,
    identity: FileIdentity,
    link_count: u64,
    bytes: &[u8],
    path_facts: &[TokenFact],
    content_facts: &[TokenFact],
    content_anchors: &[super::anchor::ContentAnchorFact],
) -> Result<[u8; 32]> {
    let mut value = actual_entry_prefix(schedule, path, entry, identity, 2)?;
    value.u64(link_count);
    value.bytes(bytes)?;
    value.u8(1); // transformed AI-visible file
    value.u8(super::baseline::OmissionReason::None as u8);
    value.token_facts(path_facts)?;
    value.token_facts(content_facts)?;
    value.content_anchors(content_anchors)?;
    for _ in 0..4 {
        value.u8(0); // reparse / named stream / hard-link / special absent
    }
    Ok(value.finish())
}

fn actual_entry_prefix(
    schedule: &KeySchedule<'_>,
    path: &[String],
    entry: &super::observe::ObservedNamespaceEntry,
    identity: FileIdentity,
    kind: u8,
) -> Result<StreamEncoder> {
    let mut value = StreamEncoder::new(
        schedule,
        KeyPurpose::TreeCommit,
        b"safeclone/rt2/actual-ai-entry",
    )?;
    value.u8(kind);
    value.bytes(&canonical_path(path)?)?;
    encode_utf16(&mut value, entry.canonical_long_name_utf16())?;
    match entry.short_alias_utf16() {
        Some(alias) => {
            value.u8(1);
            encode_utf16(&mut value, alias)?;
        }
        None => value.u8(0),
    }
    value.u64(identity.volume_serial);
    value.bytes(&identity.file_id)?;
    value.u64(entry.directory_file_id64());
    Ok(value)
}

fn encode_utf16(value: &mut StreamEncoder, units: &[u16]) -> Result<()> {
    value.u32(u32::try_from(units.len()).map_err(|_| Error::BoundExceeded)?);
    for unit in units {
        value.u16(*unit);
    }
    Ok(())
}

fn append(parent: &[String], leaf: &str) -> Result<Vec<String>> {
    let mut path = parent.to_vec();
    path.try_reserve_exact(1)
        .map_err(|_| Error::BoundExceeded)?;
    path.push(leaf.to_owned());
    Ok(path)
}

fn record_oids(facts: &[TokenFact], seen: &mut BTreeSet<[u8; 16]>) -> Result<()> {
    for fact in facts {
        if !seen.insert(fact.occurrence_id) {
            return Err(Error::InvalidToken);
        }
    }
    Ok(())
}

fn checked_add(left: usize, right: usize) -> Result<usize> {
    left.checked_add(right).ok_or(Error::BoundExceeded)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn workspace_summary() -> WorkspaceSummary {
        WorkspaceSummary {
            actual_tree_commitment: [0x11; 32],
            expected_projection_commitment: [0x22; 32],
            entries: 3,
            directories: 1,
            regular_files: 2,
            total_file_bytes: 41,
            token_occurrences: 4,
        }
    }

    #[test]
    fn workspace_summary_verification_is_field_aware() {
        let expected = workspace_summary();
        verify_workspace_summary(&expected, &expected).expect("exact summary");

        let mut structural_mismatch = expected.clone();
        structural_mismatch.total_file_bytes += 1;
        assert_eq!(
            verify_workspace_summary(&structural_mismatch, &expected),
            Err(Error::InvalidState)
        );

        let mut actual_tree_mismatch = expected.clone();
        actual_tree_mismatch.actual_tree_commitment[7] ^= 1;
        assert_eq!(
            verify_workspace_summary(&actual_tree_mismatch, &expected),
            Err(Error::InvalidState)
        );

        let mut projection_mismatch = expected.clone();
        projection_mismatch.expected_projection_commitment[29] ^= 1;
        assert_eq!(
            verify_workspace_summary(&projection_mismatch, &expected),
            Err(Error::InvalidState)
        );
    }

    #[test]
    fn omitted_files_do_not_enter_expected_workspace_index() {
        let plan = BaselinePlan {
            entries: vec![PlannedEntry::File {
                original_components: vec!["binary.bin".into()],
                safe_components: None,
                disposition: FileDisposition::Omit(super::super::baseline::OmissionReason::Binary),
                expected_output_commitment: None,
                expected_output_bytes: None,
                path_token_facts: Vec::new(),
                content_token_facts: Vec::new(),
                content_anchor_facts: Vec::new(),
                observed_short_alias_utf16: None,
                observed_identity: FileIdentity {
                    volume_serial: 1,
                    file_id: [2; 16],
                },
                original_file_reference_commitment: [3; 32],
            }],
            inventory: TokenInventory::new(),
        };
        assert!(expected_entries(&plan).expect("index").is_empty());
    }
}
