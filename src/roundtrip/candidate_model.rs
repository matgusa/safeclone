//! Pure, transient reconstruction candidate namespace and logical-tree commitment.
//!
//! No type in this module creates a filesystem object or implements an
//! artifact schema.  Candidate long paths may contain restored Original
//! names, so plan and writer types deliberately have no ordinary formatter.

use std::collections::BTreeMap;

use super::baseline::{
    canonical_path, validate_relative_path, StreamEncoder, MAX_CANONICAL_PATH_BYTES, MAX_DEPTH,
    MAX_ENTRIES, MAX_FILE_BYTES, MAX_TOTAL_FILE_BYTES,
};
use super::crypto::{KeyPurpose, KeySchedule};
use super::observe::{
    sort_utf16_indices, validate_virtual_sibling_names, validate_workspace_component,
};
use super::ruleset::ruleset_id;
use super::token::{ReviewProfile, ENGINE_VERSION, POLICY_ID, TOKEN_SUITE_ID};
use super::{Error, Result};

const CANDIDATE_ROLE: &[u8] = b"CANDIDATE";
const TREE_STREAM_DOMAIN: &[u8] = b"safeclone/rt2/tree-stream";

#[derive(Clone, Copy, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum CandidateDisposition {
    AiVisible = 1,
    OriginalOnly = 2,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum CandidateSourceRelationship {
    BaselineCounterpart,
    NewEdited,
    OriginalOnly,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum CandidateContentAction {
    Directory,
    ReconstructBaselineFile,
    UseAcceptedEditedFile,
    PreserveOriginalFile,
}

#[derive(Clone, Copy, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum CandidateEntryKind {
    Directory = 1,
    RegularFile = 2,
}

/// Content-free namespace authority.  Alias evidence is transient collision
/// input only and is not an instruction to reproduce an alias in candidate construction.
pub(crate) struct CandidateNamespaceEntry {
    pub(crate) components: Vec<String>,
    pub(crate) canonical_path: Vec<u8>,
    pub(crate) kind: CandidateEntryKind,
    pub(crate) disposition: CandidateDisposition,
    pub(crate) source_relationship: CandidateSourceRelationship,
    pub(crate) content_action: CandidateContentAction,
    pub(crate) source_index: usize,
    observed_short_aliases_utf16: Vec<Vec<u16>>,
}

pub(crate) struct CandidateNamespacePlan {
    entries: Vec<CandidateNamespaceEntry>,
    canonical_path_bytes: usize,
}

impl CandidateNamespacePlan {
    pub(crate) fn entries(&self) -> &[CandidateNamespaceEntry] {
        &self.entries
    }

    pub(crate) fn canonical_path_bytes(&self) -> usize {
        self.canonical_path_bytes
    }
}

pub(crate) struct CandidatePlanBuilder {
    by_exact_path: BTreeMap<Vec<u8>, CandidateNamespaceEntry>,
}

pub(crate) struct CandidateEntryInput {
    pub(crate) components: Vec<String>,
    pub(crate) kind: CandidateEntryKind,
    pub(crate) disposition: CandidateDisposition,
    pub(crate) source_relationship: CandidateSourceRelationship,
    pub(crate) content_action: CandidateContentAction,
    pub(crate) source_index: usize,
    pub(crate) observed_short_aliases_utf16: Vec<Vec<u16>>,
}

impl CandidatePlanBuilder {
    pub(crate) fn new() -> Self {
        Self {
            by_exact_path: BTreeMap::new(),
        }
    }

    pub(crate) fn insert(&mut self, input: CandidateEntryInput) -> Result<()> {
        if input.components.is_empty() || input.components.len() > MAX_DEPTH {
            return Err(Error::BoundExceeded);
        }
        validate_relative_path(&input.components)?;
        for component in &input.components {
            validate_workspace_component(component)?;
        }
        let path = canonical_path(&input.components)?;
        if let Some(existing) = self.by_exact_path.get_mut(&path) {
            if existing.kind != CandidateEntryKind::Directory
                || input.kind != CandidateEntryKind::Directory
                || !is_same_original_directory(existing, &input)
            {
                return Err(Error::CandidateNamespaceCollision);
            }
            // A directory shared by the edited projection and preserved
            // Original-only lineage is represented exactly once.  Its visible
            // relationship wins because that directory was AI-visible.
            if input.disposition == CandidateDisposition::AiVisible {
                existing.disposition = CandidateDisposition::AiVisible;
                existing.source_relationship = input.source_relationship;
                existing.content_action = CandidateContentAction::Directory;
                existing.source_index = input.source_index;
            }
            merge_aliases(
                &mut existing.observed_short_aliases_utf16,
                input.observed_short_aliases_utf16,
            )?;
            return Ok(());
        }
        if self.by_exact_path.len() >= MAX_ENTRIES {
            return Err(Error::BoundExceeded);
        }
        self.by_exact_path.insert(
            path.clone(),
            CandidateNamespaceEntry {
                components: input.components,
                canonical_path: path,
                kind: input.kind,
                disposition: input.disposition,
                source_relationship: input.source_relationship,
                content_action: input.content_action,
                source_index: input.source_index,
                observed_short_aliases_utf16: input.observed_short_aliases_utf16,
            },
        );
        Ok(())
    }

    pub(crate) fn finish(self) -> Result<CandidateNamespacePlan> {
        let mut entries = self.by_exact_path.into_values().collect::<Vec<_>>();
        if entries.len() > MAX_ENTRIES {
            return Err(Error::BoundExceeded);
        }
        let keys = entries
            .iter()
            .map(|entry| {
                std::str::from_utf8(&entry.canonical_path)
                    .map(|path| path.encode_utf16().collect::<Vec<_>>())
                    .map_err(|_| Error::InvalidCanonicalInput)
            })
            .collect::<Result<Vec<_>>>()?;
        let order = sort_utf16_indices(&keys)?;
        let mut slots = entries.drain(..).map(Some).collect::<Vec<_>>();
        let mut sorted = Vec::new();
        sorted
            .try_reserve_exact(order.len())
            .map_err(|_| Error::BoundExceeded)?;
        for index in order {
            sorted.push(slots[index].take().ok_or(Error::InvalidState)?);
        }
        reject_topology_and_namespace_collisions(&sorted)?;
        let canonical_path_bytes = sorted.iter().try_fold(0usize, |total, entry| {
            total
                .checked_add(entry.canonical_path.len())
                .ok_or(Error::BoundExceeded)
        })?;
        if canonical_path_bytes > MAX_CANONICAL_PATH_BYTES {
            return Err(Error::BoundExceeded);
        }
        Ok(CandidateNamespacePlan {
            entries: sorted,
            canonical_path_bytes,
        })
    }
}

fn is_same_original_directory(
    existing: &CandidateNamespaceEntry,
    incoming: &CandidateEntryInput,
) -> bool {
    if existing.source_index != incoming.source_index {
        return false;
    }
    matches!(
        (existing.source_relationship, incoming.source_relationship),
        (
            CandidateSourceRelationship::OriginalOnly,
            CandidateSourceRelationship::OriginalOnly
        ) | (
            CandidateSourceRelationship::BaselineCounterpart,
            CandidateSourceRelationship::OriginalOnly
        ) | (
            CandidateSourceRelationship::OriginalOnly,
            CandidateSourceRelationship::BaselineCounterpart
        )
    )
}

fn merge_aliases(existing: &mut Vec<Vec<u16>>, incoming: Vec<Vec<u16>>) -> Result<()> {
    existing
        .try_reserve_exact(incoming.len())
        .map_err(|_| Error::BoundExceeded)?;
    for alias in incoming {
        if !existing.contains(&alias) {
            existing.push(alias);
        }
    }
    Ok(())
}

fn reject_topology_and_namespace_collisions(entries: &[CandidateNamespaceEntry]) -> Result<()> {
    let exact = entries
        .iter()
        .enumerate()
        .map(|(index, entry)| (entry.components.as_slice(), (index, entry.kind)))
        .collect::<BTreeMap<_, _>>();
    let mut siblings = BTreeMap::<Vec<String>, Vec<(Vec<u16>, usize)>>::new();
    for (owner, entry) in entries.iter().enumerate() {
        let (leaf, parent) = entry
            .components
            .split_last()
            .ok_or(Error::InvalidCanonicalInput)?;
        for prefix_len in 1..entry.components.len() {
            match exact.get(&entry.components[..prefix_len]) {
                Some((_, CandidateEntryKind::Directory)) => {}
                Some((_, CandidateEntryKind::RegularFile)) | None => {
                    return Err(Error::CandidateNamespaceCollision)
                }
            }
        }
        let names = siblings.entry(parent.to_vec()).or_default();
        names
            .try_reserve_exact(
                1usize
                    .checked_add(entry.observed_short_aliases_utf16.len())
                    .ok_or(Error::BoundExceeded)?,
            )
            .map_err(|_| Error::BoundExceeded)?;
        names.push((validate_workspace_component(leaf)?, owner));
        for alias in &entry.observed_short_aliases_utf16 {
            names.push((alias.clone(), owner));
        }
    }
    for names in siblings.values() {
        validate_virtual_sibling_names(names).map_err(|error| match error {
            Error::AliasNamespaceAmbiguous | Error::UnsupportedAliasNamespace => {
                Error::CandidateNamespaceCollision
            }
            other => other,
        })?;
    }
    Ok(())
}

/// Incremental canonical logical CANDIDATE tree encoder.  The plan fixes
/// deterministic entry order; each regular file is then supplied in bounded
/// chunks without materializing the complete candidate tree.
pub(crate) struct CandidateCommitmentWriter {
    stream: StreamEncoder,
    next_entry: usize,
    active_file_remaining: Option<u64>,
    total_file_bytes: u64,
}

impl CandidateCommitmentWriter {
    pub(crate) fn new(
        schedule: &KeySchedule<'_>,
        profile: ReviewProfile,
        plan: &CandidateNamespacePlan,
    ) -> Result<Self> {
        let mut stream = StreamEncoder::new(schedule, KeyPurpose::TreeCommit, TREE_STREAM_DOMAIN)?;
        stream.bytes(CANDIDATE_ROLE)?;
        stream.bytes(ENGINE_VERSION.as_bytes())?;
        stream.bytes(POLICY_ID.as_bytes())?;
        stream.bytes(ruleset_id().as_bytes())?;
        stream.u16(TOKEN_SUITE_ID);
        stream.u8(profile as u8);
        stream.u32(u32::try_from(plan.entries.len()).map_err(|_| Error::BoundExceeded)?);
        Ok(Self {
            stream,
            next_entry: 0,
            active_file_remaining: None,
            total_file_bytes: 0,
        })
    }

    pub(crate) fn directory(&mut self, plan: &CandidateNamespacePlan, index: usize) -> Result<()> {
        self.begin_entry(plan, index, CandidateEntryKind::Directory)?;
        self.stream.u64(0);
        self.next_entry = self.next_entry.checked_add(1).ok_or(Error::BoundExceeded)?;
        Ok(())
    }

    pub(crate) fn begin_file(
        &mut self,
        plan: &CandidateNamespacePlan,
        index: usize,
        byte_len: u64,
    ) -> Result<()> {
        if byte_len > u64::try_from(MAX_FILE_BYTES).map_err(|_| Error::BoundExceeded)? {
            return Err(Error::BoundExceeded);
        }
        let _ = self.begin_entry(plan, index, CandidateEntryKind::RegularFile)?;
        self.total_file_bytes = self
            .total_file_bytes
            .checked_add(byte_len)
            .ok_or(Error::BoundExceeded)?;
        if self.total_file_bytes
            > u64::try_from(MAX_TOTAL_FILE_BYTES).map_err(|_| Error::BoundExceeded)?
        {
            return Err(Error::BoundExceeded);
        }
        self.stream.u64(byte_len);
        self.active_file_remaining = Some(byte_len);
        Ok(())
    }

    pub(crate) fn file_chunk(&mut self, bytes: &[u8]) -> Result<()> {
        let remaining = self.active_file_remaining.ok_or(Error::InvalidState)?;
        let length = u64::try_from(bytes.len()).map_err(|_| Error::BoundExceeded)?;
        if length > remaining {
            return Err(Error::InvalidState);
        }
        self.stream.raw(bytes);
        self.active_file_remaining = Some(remaining - length);
        Ok(())
    }

    pub(crate) fn end_file(&mut self) -> Result<()> {
        if self.active_file_remaining != Some(0) {
            return Err(Error::InvalidState);
        }
        self.active_file_remaining = None;
        self.next_entry = self.next_entry.checked_add(1).ok_or(Error::BoundExceeded)?;
        Ok(())
    }

    pub(crate) fn finish(self, plan: &CandidateNamespacePlan) -> Result<[u8; 32]> {
        if self.active_file_remaining.is_some() || self.next_entry != plan.entries.len() {
            return Err(Error::InvalidState);
        }
        Ok(self.stream.finish())
    }

    fn begin_entry<'a>(
        &mut self,
        plan: &'a CandidateNamespacePlan,
        index: usize,
        expected_kind: CandidateEntryKind,
    ) -> Result<&'a CandidateNamespaceEntry> {
        if self.active_file_remaining.is_some() || index != self.next_entry {
            return Err(Error::InvalidState);
        }
        let entry = plan.entries.get(index).ok_or(Error::InvalidState)?;
        if entry.kind != expected_kind {
            return Err(Error::InvalidState);
        }
        self.stream.bytes(&entry.canonical_path)?;
        self.stream
            .u32(u32::try_from(entry.components.len()).map_err(|_| Error::BoundExceeded)?);
        for component in &entry.components {
            let units = component.encode_utf16().collect::<Vec<_>>();
            self.stream.utf16(&units)?;
        }
        self.stream.u8(entry.kind as u8);
        self.stream.u8(entry.disposition as u8);
        Ok(entry)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::roundtrip::crypto::{SessionId, SessionMasterSecret};

    fn schedule() -> (SessionMasterSecret, SessionId) {
        (
            SessionMasterSecret::from_bytes([0x81; 32]),
            SessionId::from_bytes([0x82; 16]),
        )
    }

    fn entry(
        path: &[&str],
        kind: CandidateEntryKind,
        disposition: CandidateDisposition,
    ) -> CandidateEntryInput {
        CandidateEntryInput {
            components: path.iter().map(|value| (*value).to_owned()).collect(),
            kind,
            disposition,
            source_relationship: if disposition == CandidateDisposition::AiVisible {
                CandidateSourceRelationship::BaselineCounterpart
            } else {
                CandidateSourceRelationship::OriginalOnly
            },
            content_action: if kind == CandidateEntryKind::Directory {
                CandidateContentAction::Directory
            } else if disposition == CandidateDisposition::AiVisible {
                CandidateContentAction::UseAcceptedEditedFile
            } else {
                CandidateContentAction::PreserveOriginalFile
            },
            source_index: 0,
            observed_short_aliases_utf16: Vec::new(),
        }
    }

    fn plan(inputs: Vec<CandidateEntryInput>) -> CandidateNamespacePlan {
        let mut builder = CandidatePlanBuilder::new();
        for input in inputs {
            builder.insert(input).expect("insert candidate entry");
        }
        builder.finish().expect("finish candidate plan")
    }

    fn commitment(plan: &CandidateNamespacePlan, files: &BTreeMap<Vec<u8>, Vec<u8>>) -> [u8; 32] {
        let (master, session_id) = schedule();
        let schedule = KeySchedule::new(&master, session_id);
        let mut writer = CandidateCommitmentWriter::new(&schedule, ReviewProfile::StandardV2, plan)
            .expect("writer");
        for (index, entry) in plan.entries().iter().enumerate() {
            match entry.kind {
                CandidateEntryKind::Directory => writer.directory(plan, index).expect("directory"),
                CandidateEntryKind::RegularFile => {
                    let bytes = files.get(&entry.canonical_path).expect("file bytes");
                    writer
                        .begin_file(plan, index, bytes.len() as u64)
                        .expect("begin file");
                    writer.file_chunk(bytes).expect("file bytes");
                    writer.end_file().expect("end file");
                }
            }
        }
        writer.finish(plan).expect("commitment")
    }

    #[test]
    fn merged_plan_is_order_independent_and_shared_directories_are_unique() {
        let first = plan(vec![
            entry(
                &["shared", "visible.txt"],
                CandidateEntryKind::RegularFile,
                CandidateDisposition::AiVisible,
            ),
            entry(
                &["shared"],
                CandidateEntryKind::Directory,
                CandidateDisposition::OriginalOnly,
            ),
            entry(
                &["shared"],
                CandidateEntryKind::Directory,
                CandidateDisposition::AiVisible,
            ),
        ]);
        let second = plan(vec![
            entry(
                &["shared"],
                CandidateEntryKind::Directory,
                CandidateDisposition::AiVisible,
            ),
            entry(
                &["shared"],
                CandidateEntryKind::Directory,
                CandidateDisposition::OriginalOnly,
            ),
            entry(
                &["shared", "visible.txt"],
                CandidateEntryKind::RegularFile,
                CandidateDisposition::AiVisible,
            ),
        ]);
        assert_eq!(first.entries().len(), 2);
        assert_eq!(
            first
                .entries()
                .iter()
                .map(|entry| entry.canonical_path.as_slice())
                .collect::<Vec<_>>(),
            second
                .entries()
                .iter()
                .map(|entry| entry.canonical_path.as_slice())
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn merged_namespace_rejects_topology_case_nfc_and_reserved_collisions() {
        let mut topology = CandidatePlanBuilder::new();
        topology
            .insert(entry(
                &["node"],
                CandidateEntryKind::RegularFile,
                CandidateDisposition::AiVisible,
            ))
            .expect("file");
        topology
            .insert(entry(
                &["node", "child"],
                CandidateEntryKind::RegularFile,
                CandidateDisposition::OriginalOnly,
            ))
            .expect("child");
        assert_eq!(
            topology.finish().err(),
            Some(Error::CandidateNamespaceCollision)
        );

        let mut missing_ancestor = CandidatePlanBuilder::new();
        missing_ancestor
            .insert(entry(
                &["missing", "child"],
                CandidateEntryKind::RegularFile,
                CandidateDisposition::AiVisible,
            ))
            .expect("orphan child is rejected at full-plan validation");
        assert_eq!(
            missing_ancestor.finish().err(),
            Some(Error::CandidateNamespaceCollision)
        );

        for pair in [("Readme", "README"), ("\u{00e9}.txt", "e\u{301}.txt")] {
            let mut builder = CandidatePlanBuilder::new();
            builder
                .insert(entry(
                    &[pair.0],
                    CandidateEntryKind::RegularFile,
                    CandidateDisposition::AiVisible,
                ))
                .expect("first");
            builder
                .insert(entry(
                    &[pair.1],
                    CandidateEntryKind::RegularFile,
                    CandidateDisposition::OriginalOnly,
                ))
                .expect("second");
            assert_eq!(
                builder.finish().err(),
                Some(Error::CandidateNamespaceCollision)
            );
        }

        let mut reserved = CandidatePlanBuilder::new();
        assert_eq!(
            reserved.insert(entry(
                &[".safeclone-sensitive-output-v1.complete"],
                CandidateEntryKind::RegularFile,
                CandidateDisposition::AiVisible
            )),
            Err(Error::UnsupportedAliasNamespace)
        );

        let mut visible_original_only = CandidatePlanBuilder::new();
        let mut new_edited = entry(
            &["preserved"],
            CandidateEntryKind::Directory,
            CandidateDisposition::AiVisible,
        );
        new_edited.source_relationship = CandidateSourceRelationship::NewEdited;
        visible_original_only
            .insert(new_edited)
            .expect("new edited directory");
        assert_eq!(
            visible_original_only.insert(entry(
                &["preserved"],
                CandidateEntryKind::Directory,
                CandidateDisposition::OriginalOnly,
            )),
            Err(Error::CandidateNamespaceCollision)
        );
    }

    #[test]
    fn merged_namespace_rejects_current_alias_collision_and_depth_overflow() {
        let mut aliases = CandidatePlanBuilder::new();
        let mut visible = entry(
            &["visible.txt"],
            CandidateEntryKind::RegularFile,
            CandidateDisposition::AiVisible,
        );
        visible
            .observed_short_aliases_utf16
            .push("ORIGINAL.TXT".encode_utf16().collect::<Vec<_>>());
        aliases.insert(visible).expect("visible alias evidence");
        aliases
            .insert(entry(
                &["original.txt"],
                CandidateEntryKind::RegularFile,
                CandidateDisposition::OriginalOnly,
            ))
            .expect("original-only long name");
        assert_eq!(
            aliases.finish().err(),
            Some(Error::CandidateNamespaceCollision)
        );

        let mut depth = CandidatePlanBuilder::new();
        let components = (0..=MAX_DEPTH)
            .map(|index| format!("d{index}"))
            .collect::<Vec<_>>();
        assert_eq!(
            depth.insert(CandidateEntryInput {
                components,
                kind: CandidateEntryKind::Directory,
                disposition: CandidateDisposition::AiVisible,
                source_relationship: CandidateSourceRelationship::NewEdited,
                content_action: CandidateContentAction::Directory,
                source_index: 0,
                observed_short_aliases_utf16: Vec::new(),
            }),
            Err(Error::BoundExceeded)
        );
    }

    #[test]
    fn candidate_commitment_binds_bytes_path_disposition_kind_and_is_order_stable() {
        let base = plan(vec![
            entry(
                &["dir"],
                CandidateEntryKind::Directory,
                CandidateDisposition::AiVisible,
            ),
            entry(
                &["dir", "file.txt"],
                CandidateEntryKind::RegularFile,
                CandidateDisposition::AiVisible,
            ),
            entry(
                &["opaque.bin"],
                CandidateEntryKind::RegularFile,
                CandidateDisposition::OriginalOnly,
            ),
        ]);
        let mut files = BTreeMap::from([
            (b"dir/file.txt".to_vec(), b"visible".to_vec()),
            (b"opaque.bin".to_vec(), vec![0xff, 0x00]),
        ]);
        let reference = commitment(&base, &files);
        files.insert(b"dir/file.txt".to_vec(), b"changed".to_vec());
        assert_ne!(reference, commitment(&base, &files));
        files.insert(b"dir/file.txt".to_vec(), b"visible".to_vec());
        files.insert(b"opaque.bin".to_vec(), vec![0xfe, 0x00]);
        assert_ne!(reference, commitment(&base, &files));

        let disposition = plan(vec![
            entry(
                &["dir"],
                CandidateEntryKind::Directory,
                CandidateDisposition::AiVisible,
            ),
            entry(
                &["dir", "file.txt"],
                CandidateEntryKind::RegularFile,
                CandidateDisposition::OriginalOnly,
            ),
            entry(
                &["opaque.bin"],
                CandidateEntryKind::RegularFile,
                CandidateDisposition::OriginalOnly,
            ),
        ]);
        files.insert(b"opaque.bin".to_vec(), vec![0xff, 0x00]);
        assert_ne!(reference, commitment(&disposition, &files));

        let renamed = plan(vec![
            entry(
                &["dir"],
                CandidateEntryKind::Directory,
                CandidateDisposition::AiVisible,
            ),
            entry(
                &["dir", "renamed.txt"],
                CandidateEntryKind::RegularFile,
                CandidateDisposition::AiVisible,
            ),
            entry(
                &["opaque.bin"],
                CandidateEntryKind::RegularFile,
                CandidateDisposition::OriginalOnly,
            ),
        ]);
        files.remove(b"dir/file.txt".as_slice());
        files.insert(b"dir/renamed.txt".to_vec(), b"visible".to_vec());
        assert_ne!(reference, commitment(&renamed, &files));

        let reordered = plan(vec![
            entry(
                &["opaque.bin"],
                CandidateEntryKind::RegularFile,
                CandidateDisposition::OriginalOnly,
            ),
            entry(
                &["dir", "file.txt"],
                CandidateEntryKind::RegularFile,
                CandidateDisposition::AiVisible,
            ),
            entry(
                &["dir"],
                CandidateEntryKind::Directory,
                CandidateDisposition::AiVisible,
            ),
        ]);
        files.remove(b"dir/renamed.txt".as_slice());
        files.insert(b"dir/file.txt".to_vec(), b"visible".to_vec());
        assert_eq!(reference, commitment(&reordered, &files));

        let directory = plan(vec![entry(
            &["kind"],
            CandidateEntryKind::Directory,
            CandidateDisposition::AiVisible,
        )]);
        let regular = plan(vec![entry(
            &["kind"],
            CandidateEntryKind::RegularFile,
            CandidateDisposition::AiVisible,
        )]);
        let no_files = BTreeMap::new();
        let regular_files = BTreeMap::from([(b"kind".to_vec(), Vec::new())]);
        assert_ne!(
            commitment(&directory, &no_files),
            commitment(&regular, &regular_files)
        );

        let flat = plan(vec![
            entry(
                &["parent"],
                CandidateEntryKind::Directory,
                CandidateDisposition::AiVisible,
            ),
            entry(
                &["parent", "leaf"],
                CandidateEntryKind::RegularFile,
                CandidateDisposition::AiVisible,
            ),
        ]);
        let nested = plan(vec![
            entry(
                &["parent"],
                CandidateEntryKind::Directory,
                CandidateDisposition::AiVisible,
            ),
            entry(
                &["parent", "nested"],
                CandidateEntryKind::Directory,
                CandidateDisposition::AiVisible,
            ),
            entry(
                &["parent", "nested", "leaf"],
                CandidateEntryKind::RegularFile,
                CandidateDisposition::AiVisible,
            ),
        ]);
        assert_ne!(
            commitment(
                &flat,
                &BTreeMap::from([(b"parent/leaf".to_vec(), Vec::new())])
            ),
            commitment(
                &nested,
                &BTreeMap::from([(b"parent/nested/leaf".to_vec(), Vec::new())])
            )
        );
    }
}
