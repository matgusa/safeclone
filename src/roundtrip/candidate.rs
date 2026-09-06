//! Retained-handle candidate construction candidate construction and independent verification.

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::io::{Read, Write};
use std::marker::PhantomData;

use cap_std::fs::File;

use super::apply::{
    checkpoint, ApplyCheckpoint, ApplyIncompleteAuthorization, ApplyResultAuthorization,
};
use super::baseline::{
    canonical_path, stream_planned_original_file, MAX_DEPTH, MAX_ENTRIES, MAX_FILE_BYTES,
    MAX_TOTAL_FILE_BYTES,
};
use super::candidate_marker::{self, CandidateMarkerState};
use super::candidate_model::{
    CandidateCommitmentWriter, CandidateContentAction, CandidateDisposition, CandidateEntryKind,
    CandidateNamespacePlan,
};
use super::crypto::{constant_time_equal, KeySchedule};
use super::observe::{
    file_identity, validate_regular_one_link_stream_clean, EntryKind, FileIdentity, NamespaceScope,
    QualifiedDirectory, CANDIDATE_COMPLETE_LEAF, CANDIDATE_INCOMPLETE_LEAF,
};
use super::reconstruct::AuthorizedReconstructionModel;
use super::reconstruction_reference::{ExpectedEditedEntry, ProjectionReference};
use super::{Error, Result};

const STREAM_BUFFER_BYTES: usize = 64 * 1024;

pub(super) struct EmptyCandidate;
pub(super) struct IncompleteMarkerAuthenticated;
pub(super) struct PopulationAuthorized;
pub(super) struct CandidatePopulated;
pub(super) struct CandidateVerified;
pub(super) struct CompleteMarkerAuthenticated;

/// No formatter: the transient ledger contains confidential relative names.
pub(super) struct CandidateRoot<State> {
    root: QualifiedDirectory,
    selection_parent: QualifiedDirectory,
    selection_leaf: OsString,
    identities: BTreeMap<Vec<u8>, FileIdentity>,
    _state: PhantomData<State>,
}

pub(super) struct VerifiedCandidateFacts {
    pub(super) candidate_commitment: [u8; 32],
    pub(super) candidate_entries: u32,
    pub(super) preserved_original_only_files: u32,
    pub(super) preserved_original_only_bytes: u64,
}

struct ActualEntry {
    components: Vec<String>,
    canonical_path: Vec<u8>,
    kind: CandidateEntryKind,
    identity: FileIdentity,
    byte_len: u64,
}

struct ActualTree {
    entries: Vec<ActualEntry>,
}

impl CandidateRoot<EmptyCandidate> {
    pub(super) fn from_created(
        root: QualifiedDirectory,
        selection_parent: QualifiedDirectory,
        selection_leaf: OsString,
    ) -> Result<Self> {
        root.requery_policy()?;
        if !root.observe()?.entries().is_empty() {
            return Err(Error::CandidateVerificationFailed);
        }
        let candidate = Self {
            root,
            selection_parent,
            selection_leaf,
            identities: BTreeMap::new(),
            _state: PhantomData,
        };
        candidate.verify_selection()?;
        Ok(candidate)
    }

    pub(super) fn create_incomplete_marker(
        self,
        schedule: &KeySchedule<'_>,
        apply_id: [u8; 16],
        ruleset_id: &str,
    ) -> Result<CandidateRoot<IncompleteMarkerAuthenticated>> {
        self.verify_selection()?;
        checkpoint(ApplyCheckpoint::IncompleteMarkerCreate)?;
        create_and_authenticate_marker(
            &self.root,
            schedule,
            apply_id,
            ruleset_id,
            CandidateMarkerState::Incomplete,
            ApplyCheckpoint::IncompleteMarkerWrite,
        )?;
        self.verify_selection()?;
        Ok(CandidateRoot {
            root: self.root,
            selection_parent: self.selection_parent,
            selection_leaf: self.selection_leaf,
            identities: self.identities,
            _state: PhantomData,
        })
    }
}

impl CandidateRoot<IncompleteMarkerAuthenticated> {
    pub(super) fn root(&self) -> &QualifiedDirectory {
        &self.root
    }

    /// The caller may cross this type-state only after freshly authenticating
    /// the committed APPLY_INCOMPLETE capsule head.
    pub(super) fn authorize_population(
        self,
        _authorization: ApplyIncompleteAuthorization,
    ) -> CandidateRoot<PopulationAuthorized> {
        CandidateRoot {
            root: self.root,
            selection_parent: self.selection_parent,
            selection_leaf: self.selection_leaf,
            identities: self.identities,
            _state: PhantomData,
        }
    }
}

impl CandidateRoot<PopulationAuthorized> {
    pub(super) fn materialize(
        mut self,
        model: &AuthorizedReconstructionModel,
    ) -> Result<CandidateRoot<CandidatePopulated>> {
        self.verify_selection()?;
        self.root.requery_policy()?;
        authenticate_marker(
            &self.root,
            &model.authority.owner.key_schedule(),
            model
                .authority
                .owner
                .capsule()
                .apply_authority
                .as_ref()
                .ok_or(Error::InvalidState)?
                .apply_id,
            &model.authority.owner.capsule().ruleset_id,
            CandidateMarkerState::Incomplete,
        )?;
        let children = plan_children(model.plan())?;
        let authority = MaterializationAuthority {
            root: &self.root,
            selection_parent: &self.selection_parent,
            selection_leaf: &self.selection_leaf,
            children: &children,
            model,
        };
        let mut first_sensitive_write = true;
        materialize_children(
            &self.root,
            &[],
            &authority,
            &mut self.identities,
            &mut first_sensitive_write,
        )?;
        if first_sensitive_write
            && model
                .plan()
                .entries()
                .iter()
                .any(|entry| entry.kind == CandidateEntryKind::RegularFile)
        {
            return Err(Error::CandidateVerificationFailed);
        }
        self.verify_selection()?;
        Ok(CandidateRoot {
            root: self.root,
            selection_parent: self.selection_parent,
            selection_leaf: self.selection_leaf,
            identities: self.identities,
            _state: PhantomData,
        })
    }
}

impl CandidateRoot<CandidatePopulated> {
    pub(super) fn verify_six(
        self,
        model: &AuthorizedReconstructionModel,
    ) -> Result<(CandidateRoot<CandidateVerified>, VerifiedCandidateFacts)> {
        checkpoint(ApplyCheckpoint::PostcheckRawOccurrenceGraph)?;
        self.verify_selection()?;
        self.root.requery_policy()?;
        verify_actual_ai_occurrence_graph(&self.root, model)?;

        checkpoint(ApplyCheckpoint::PostcheckProjectedRetokenization)?;
        self.verify_selection()?;
        verify_projected_actual_ai(&self.root, model)?;
        model.verify_final_edited()?;

        checkpoint(ApplyCheckpoint::PostcheckOriginalOnly)?;
        self.verify_selection()?;
        let (original_only_files, original_only_bytes) = verify_original_only(&self.root, model)?;

        checkpoint(ApplyCheckpoint::PostcheckFullCandidate)?;
        self.verify_selection()?;
        let actual = collect_actual_tree(&self.root)?;
        let commitment =
            verify_full_actual_candidate(&self.root, model, &actual, Some(&self.identities))?;

        checkpoint(ApplyCheckpoint::PostcheckCompletePrecondition)?;
        self.verify_selection()?;
        require_marker_precondition(&self.root, false)?;

        checkpoint(ApplyCheckpoint::PostcheckFinalOriginal)?;
        model.verify_final_original()?;
        self.verify_selection()?;

        let facts = VerifiedCandidateFacts {
            candidate_commitment: commitment,
            candidate_entries: u32::try_from(actual.entries.len())
                .map_err(|_| Error::BoundExceeded)?,
            preserved_original_only_files: original_only_files,
            preserved_original_only_bytes: original_only_bytes,
        };
        Ok((
            CandidateRoot {
                root: self.root,
                selection_parent: self.selection_parent,
                selection_leaf: self.selection_leaf,
                identities: self.identities,
                _state: PhantomData,
            },
            facts,
        ))
    }
}

impl CandidateRoot<CandidateVerified> {
    pub(super) fn create_complete_marker(
        self,
        schedule: &KeySchedule<'_>,
        apply_id: [u8; 16],
        ruleset_id: &str,
        commitment: [u8; 32],
        _manifest: ApplyResultAuthorization,
    ) -> Result<CandidateRoot<CompleteMarkerAuthenticated>> {
        checkpoint(ApplyCheckpoint::CompleteMarkerCreate)?;
        self.verify_selection()?;
        self.root.requery_policy()?;
        create_and_authenticate_marker(
            &self.root,
            schedule,
            apply_id,
            ruleset_id,
            CandidateMarkerState::Complete {
                candidate_commitment: commitment,
            },
            ApplyCheckpoint::CompleteMarkerWrite,
        )?;
        self.root.requery_policy()?;
        self.verify_selection()?;
        checkpoint(ApplyCheckpoint::CompleteMarkerCommit)?;
        Ok(CandidateRoot {
            root: self.root,
            selection_parent: self.selection_parent,
            selection_leaf: self.selection_leaf,
            identities: self.identities,
            _state: PhantomData,
        })
    }
}

impl CandidateRoot<CompleteMarkerAuthenticated> {
    pub(super) fn root(&self) -> &QualifiedDirectory {
        &self.root
    }

    pub(super) fn verify_selected_root(&self) -> Result<()> {
        self.verify_selection()
    }
}

impl<State> CandidateRoot<State> {
    fn verify_selection(&self) -> Result<()> {
        verify_candidate_root_binding(&self.root, &self.selection_parent, &self.selection_leaf)
    }
}

pub(super) fn verify_existing_complete(
    root: &QualifiedDirectory,
    model: &AuthorizedReconstructionModel,
    apply_id: [u8; 16],
    expected_commitment: [u8; 32],
) -> Result<VerifiedCandidateFacts> {
    let schedule = model.authority.owner.key_schedule();
    root.requery_policy()?;
    authenticate_marker(
        root,
        &schedule,
        apply_id,
        &model.authority.owner.capsule().ruleset_id,
        CandidateMarkerState::Incomplete,
    )?;
    authenticate_marker(
        root,
        &schedule,
        apply_id,
        &model.authority.owner.capsule().ruleset_id,
        CandidateMarkerState::Complete {
            candidate_commitment: expected_commitment,
        },
    )?;
    checkpoint(ApplyCheckpoint::PostcheckRawOccurrenceGraph)?;
    verify_actual_ai_occurrence_graph(root, model)?;
    checkpoint(ApplyCheckpoint::PostcheckProjectedRetokenization)?;
    verify_projected_actual_ai(root, model)?;
    model.verify_final_edited()?;
    checkpoint(ApplyCheckpoint::PostcheckOriginalOnly)?;
    let (files, bytes) = verify_original_only(root, model)?;
    checkpoint(ApplyCheckpoint::PostcheckFullCandidate)?;
    let actual = collect_actual_tree(root)?;
    let commitment = verify_full_actual_candidate(root, model, &actual, None)?;
    if !constant_time_equal(&commitment, &expected_commitment) {
        return Err(Error::CandidateVerificationFailed);
    }
    require_marker_precondition(root, true)?;
    checkpoint(ApplyCheckpoint::PostcheckFinalOriginal)?;
    model.verify_final_original()?;
    Ok(VerifiedCandidateFacts {
        candidate_commitment: commitment,
        candidate_entries: u32::try_from(actual.entries.len()).map_err(|_| Error::BoundExceeded)?,
        preserved_original_only_files: files,
        preserved_original_only_bytes: bytes,
    })
}

fn create_and_authenticate_marker(
    root: &QualifiedDirectory,
    schedule: &KeySchedule<'_>,
    apply_id: [u8; 16],
    ruleset_id: &str,
    state: CandidateMarkerState,
    write_checkpoint: ApplyCheckpoint,
) -> Result<()> {
    let bytes = candidate_marker::encode(schedule, apply_id, ruleset_id, state)?;
    let leaf = root.validate_absent_leaf(OsStr::new(state.leaf()))?;
    let mut created = root.create_empty_file(leaf)?;
    let identity = created.identity();
    checkpoint(write_checkpoint)?;
    created
        .file_mut()
        .write_all(&bytes)
        .map_err(|_| Error::CandidateIncomplete)?;
    created
        .file()
        .sync_all()
        .map_err(|_| Error::CandidateIncomplete)?;
    drop(created);
    let mut reopened = root.open_exact_regular(OsStr::new(state.leaf()))?;
    if file_identity(&reopened)? != identity {
        return Err(Error::CandidateMarkerAuthenticationFailed);
    }
    let actual = read_bounded(&mut reopened, 1_024)?;
    candidate_marker::authenticate_exact(&actual, schedule, apply_id, ruleset_id, state)
}

fn authenticate_marker(
    root: &QualifiedDirectory,
    schedule: &KeySchedule<'_>,
    apply_id: [u8; 16],
    ruleset_id: &str,
    state: CandidateMarkerState,
) -> Result<()> {
    let mut file = root
        .open_exact_regular(OsStr::new(state.leaf()))
        .map_err(|_| Error::CandidateMarkerAuthenticationFailed)?;
    let before = file_identity(&file)?;
    let actual = read_bounded(&mut file, 1_024)?;
    if file_identity(&file)? != before {
        return Err(Error::CandidateMarkerAuthenticationFailed);
    }
    candidate_marker::authenticate_exact(&actual, schedule, apply_id, ruleset_id, state)
}

fn plan_children(plan: &CandidateNamespacePlan) -> Result<BTreeMap<Vec<u8>, Vec<usize>>> {
    let mut output = BTreeMap::<Vec<u8>, Vec<usize>>::new();
    for (index, entry) in plan.entries().iter().enumerate() {
        let parent = entry
            .canonical_path
            .iter()
            .rposition(|byte| *byte == b'/')
            .map_or_else(Vec::new, |position| {
                entry.canonical_path[..position].to_vec()
            });
        let siblings = output.entry(parent).or_default();
        siblings.try_reserve(1).map_err(|_| Error::BoundExceeded)?;
        siblings.push(index);
    }
    Ok(output)
}

struct MaterializationAuthority<'a> {
    root: &'a QualifiedDirectory,
    selection_parent: &'a QualifiedDirectory,
    selection_leaf: &'a OsStr,
    children: &'a BTreeMap<Vec<u8>, Vec<usize>>,
    model: &'a AuthorizedReconstructionModel,
}

fn materialize_children(
    parent: &QualifiedDirectory,
    parent_path: &[u8],
    authority: &MaterializationAuthority<'_>,
    identities: &mut BTreeMap<Vec<u8>, FileIdentity>,
    first_sensitive_write: &mut bool,
) -> Result<()> {
    let Some(indices) = authority.children.get(parent_path) else {
        return Ok(());
    };
    for index in indices {
        verify_candidate_root_binding(
            authority.root,
            authority.selection_parent,
            authority.selection_leaf,
        )?;
        authority.root.requery_policy()?;
        parent.requery_policy()?;
        let entry = authority
            .model
            .plan()
            .entries()
            .get(*index)
            .ok_or(Error::InvalidState)?;
        let leaf_name = entry.components.last().ok_or(Error::InvalidState)?;
        let leaf = parent.validate_absent_leaf(OsStr::new(leaf_name))?;
        match entry.kind {
            CandidateEntryKind::Directory => {
                checkpoint(ApplyCheckpoint::CandidateDirectoryCreate)?;
                let directory = parent.create_candidate_directory(leaf)?;
                if identities
                    .insert(entry.canonical_path.clone(), directory.identity())
                    .is_some()
                {
                    return Err(Error::CandidateVerificationFailed);
                }
                authority.root.requery_policy()?;
                materialize_children(
                    &directory,
                    &entry.canonical_path,
                    authority,
                    identities,
                    first_sensitive_write,
                )?;
            }
            CandidateEntryKind::RegularFile => {
                checkpoint(ApplyCheckpoint::CandidateFileCreate)?;
                let mut file = parent.create_empty_file(leaf)?;
                let identity = file.identity();
                authority.root.requery_policy()?;
                if *first_sensitive_write {
                    checkpoint(ApplyCheckpoint::FirstSensitiveWrite)?;
                    *first_sensitive_write = false;
                }
                match entry.content_action {
                    CandidateContentAction::UseAcceptedEditedFile
                    | CandidateContentAction::ReconstructBaselineFile => {
                        checkpoint(ApplyCheckpoint::ReconstructedWrite)?;
                        let bytes = authority.model.materialize_ai_file(*index)?;
                        file.file_mut()
                            .write_all(bytes.as_slice())
                            .map_err(|_| Error::CandidateIncomplete)?;
                    }
                    CandidateContentAction::PreserveOriginalFile => {
                        checkpoint(ApplyCheckpoint::OriginalOnlyStreamingWrite)?;
                        let planned = authority
                            .model
                            .inputs
                            .baseline
                            .derivation
                            .plan
                            .entries
                            .get(entry.source_index)
                            .ok_or(Error::InvalidState)?;
                        let schedule = authority.model.authority.owner.key_schedule();
                        stream_planned_original_file(
                            &authority.model.inputs.original,
                            planned,
                            &schedule,
                            |chunk| {
                                file.file_mut()
                                    .write_all(chunk)
                                    .map_err(|_| Error::CandidateIncomplete)
                            },
                        )?;
                    }
                    CandidateContentAction::Directory => return Err(Error::InvalidState),
                }
                file.file()
                    .sync_all()
                    .map_err(|_| Error::CandidateIncomplete)?;
                drop(file);
                checkpoint(ApplyCheckpoint::PerFileVerify)?;
                verify_written_file(parent, authority.model, *index, identity)?;
                authority.root.requery_policy()?;
                if identities
                    .insert(entry.canonical_path.clone(), identity)
                    .is_some()
                {
                    return Err(Error::CandidateVerificationFailed);
                }
            }
        }
        verify_candidate_root_binding(
            authority.root,
            authority.selection_parent,
            authority.selection_leaf,
        )?;
    }
    Ok(())
}

fn verify_candidate_root_binding(
    root: &QualifiedDirectory,
    selection_parent: &QualifiedDirectory,
    selection_leaf: &OsStr,
) -> Result<()> {
    selection_parent.requery_policy()?;
    root.requery_policy()?;
    let selected = selection_parent
        .classify_directory_leaf(selection_leaf, NamespaceScope::Workspace)?
        .map_err(|_| Error::CandidateVerificationFailed)?;
    if selected.identity() != root.identity() {
        return Err(Error::CandidateVerificationFailed);
    }
    selected.requery_policy()?;
    selection_parent.requery_policy()?;
    root.requery_policy()
}

fn verify_written_file(
    parent: &QualifiedDirectory,
    model: &AuthorizedReconstructionModel,
    index: usize,
    expected_identity: FileIdentity,
) -> Result<()> {
    let entry = model
        .plan()
        .entries()
        .get(index)
        .ok_or(Error::InvalidState)?;
    let leaf = entry.components.last().ok_or(Error::InvalidState)?;
    let mut file = parent.open_exact_regular(OsStr::new(leaf))?;
    let before_identity = file_identity(&file)?;
    if before_identity != expected_identity {
        return Err(Error::CandidateVerificationFailed);
    }
    match entry.content_action {
        CandidateContentAction::UseAcceptedEditedFile
        | CandidateContentAction::ReconstructBaselineFile => {
            let actual = read_bounded(&mut file, MAX_FILE_BYTES)?;
            model.project_actual_ai_file(index, &actual)?;
        }
        CandidateContentAction::PreserveOriginalFile => {
            let planned = model
                .inputs
                .baseline
                .derivation
                .plan
                .entries
                .get(entry.source_index)
                .ok_or(Error::InvalidState)?;
            let schedule = model.authority.owner.key_schedule();
            stream_planned_original_file(&model.inputs.original, planned, &schedule, |chunk| {
                let mut candidate = vec![0u8; chunk.len()];
                file.read_exact(&mut candidate)
                    .map_err(|_| Error::CandidateVerificationFailed)?;
                if constant_time_equal(&candidate, chunk) {
                    Ok(())
                } else {
                    Err(Error::CandidateVerificationFailed)
                }
            })?;
            let mut extra = [0u8; 1];
            if file
                .read(&mut extra)
                .map_err(|_| Error::CandidateVerificationFailed)?
                != 0
            {
                return Err(Error::CandidateVerificationFailed);
            }
        }
        CandidateContentAction::Directory => return Err(Error::InvalidState),
    }
    validate_regular_one_link_stream_clean(&file)?;
    if file_identity(&file)? != before_identity {
        return Err(Error::CandidateVerificationFailed);
    }
    Ok(())
}

fn verify_actual_ai_occurrence_graph(
    root: &QualifiedDirectory,
    model: &AuthorizedReconstructionModel,
) -> Result<()> {
    for (index, entry) in model.plan().entries().iter().enumerate() {
        if entry.disposition == CandidateDisposition::AiVisible
            && entry.kind == CandidateEntryKind::RegularFile
        {
            let mut file = open_plan_file(root, entry)?;
            let bytes = read_bounded(&mut file, MAX_FILE_BYTES)?;
            model.project_actual_ai_file(index, &bytes)?;
        }
    }
    Ok(())
}

fn verify_projected_actual_ai(
    root: &QualifiedDirectory,
    model: &AuthorizedReconstructionModel,
) -> Result<()> {
    let schedule = model.authority.owner.key_schedule();
    let expected = model
        .inputs
        .edited
        .entries
        .iter()
        .map(|entry| {
            let kind = match entry.kind {
                super::edited::EditedEntryKind::Directory => CandidateEntryKind::Directory,
                super::edited::EditedEntryKind::File => CandidateEntryKind::RegularFile,
                super::edited::EditedEntryKind::Unsupported => {
                    return Err(Error::CandidateVerificationFailed)
                }
            };
            Ok(ExpectedEditedEntry {
                path: entry.path.as_slice(),
                kind,
                byte_len: entry.byte_len,
                exact_file_match: entry.exact_file_match,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let mut reference = ProjectionReference::new(&schedule, expected)?;
    let projected_paths = model.projected_ai_paths()?;
    for (index, entry) in model.plan().entries().iter().enumerate() {
        if entry.disposition != CandidateDisposition::AiVisible {
            continue;
        }
        let path = projected_paths
            .get(&entry.canonical_path)
            .ok_or(Error::ProjectedRetokenizationMismatch)?;
        match entry.kind {
            CandidateEntryKind::Directory => {
                reference.observe(entry.disposition, path, entry.kind, None)?;
            }
            CandidateEntryKind::RegularFile => {
                let mut file = open_plan_file(root, entry)?;
                let actual = read_bounded(&mut file, MAX_FILE_BYTES)?;
                let projected = model.project_actual_ai_file(index, &actual)?;
                reference.observe(
                    entry.disposition,
                    path,
                    entry.kind,
                    Some(projected.as_slice()),
                )?;
            }
        }
    }
    reference.finish()
}

fn verify_original_only(
    root: &QualifiedDirectory,
    model: &AuthorizedReconstructionModel,
) -> Result<(u32, u64)> {
    let mut files = 0u32;
    let mut bytes = 0u64;
    for entry in model.plan().entries() {
        if entry.disposition != CandidateDisposition::OriginalOnly
            || entry.kind != CandidateEntryKind::RegularFile
        {
            continue;
        }
        let mut candidate = open_plan_file(root, entry)?;
        let identity = file_identity(&candidate)?;
        let planned = model
            .inputs
            .baseline
            .derivation
            .plan
            .entries
            .get(entry.source_index)
            .ok_or(Error::InvalidState)?;
        let schedule = model.authority.owner.key_schedule();
        let length =
            stream_planned_original_file(&model.inputs.original, planned, &schedule, |chunk| {
                let mut actual = vec![0u8; chunk.len()];
                candidate
                    .read_exact(&mut actual)
                    .map_err(|_| Error::CandidateVerificationFailed)?;
                if constant_time_equal(&actual, chunk) {
                    Ok(())
                } else {
                    Err(Error::CandidateVerificationFailed)
                }
            })?;
        let mut extra = [0u8; 1];
        if candidate
            .read(&mut extra)
            .map_err(|_| Error::CandidateVerificationFailed)?
            != 0
            || file_identity(&candidate)? != identity
        {
            return Err(Error::CandidateVerificationFailed);
        }
        files = files.checked_add(1).ok_or(Error::BoundExceeded)?;
        bytes = bytes.checked_add(length).ok_or(Error::BoundExceeded)?;
    }
    Ok((files, bytes))
}

fn collect_actual_tree(root: &QualifiedDirectory) -> Result<ActualTree> {
    let mut entries = Vec::new();
    let mut total_file_bytes = 0u64;
    collect_directory(root, &[], true, &mut entries, &mut total_file_bytes)?;
    Ok(ActualTree { entries })
}

fn collect_directory(
    parent: &QualifiedDirectory,
    prefix: &[String],
    is_root: bool,
    output: &mut Vec<ActualEntry>,
    total_file_bytes: &mut u64,
) -> Result<()> {
    if prefix.len() > MAX_DEPTH {
        return Err(Error::BoundExceeded);
    }
    for entry in parent.observe()?.entries() {
        if is_root
            && matches!(
                entry.canonical_long_name(),
                CANDIDATE_INCOMPLETE_LEAF | CANDIDATE_COMPLETE_LEAF
            )
        {
            if entry.entry_kind() != EntryKind::File {
                return Err(Error::CandidateVerificationFailed);
            }
            continue;
        }
        if output.len() >= MAX_ENTRIES {
            return Err(Error::BoundExceeded);
        }
        let mut components = prefix.to_vec();
        components
            .try_reserve(1)
            .map_err(|_| Error::BoundExceeded)?;
        components.push(entry.canonical_long_name().to_owned());
        let path = canonical_path(&components)?;
        match entry.entry_kind() {
            EntryKind::Directory => {
                let child =
                    parent.open_exact_child_directory(OsStr::new(entry.canonical_long_name()))?;
                let identity = child.identity();
                output.try_reserve(1).map_err(|_| Error::BoundExceeded)?;
                output.push(ActualEntry {
                    components: components.clone(),
                    canonical_path: path,
                    kind: CandidateEntryKind::Directory,
                    identity,
                    byte_len: 0,
                });
                collect_directory(&child, &components, false, output, total_file_bytes)?;
            }
            EntryKind::File => {
                let file = parent.open_observed_regular(entry)?;
                let identity = file_identity(&file)?;
                let byte_len = file.metadata().map_err(|_| Error::FilesystemFailure)?.len();
                if byte_len > u64::try_from(MAX_FILE_BYTES).map_err(|_| Error::BoundExceeded)? {
                    return Err(Error::BoundExceeded);
                }
                *total_file_bytes = total_file_bytes
                    .checked_add(byte_len)
                    .ok_or(Error::BoundExceeded)?;
                if *total_file_bytes
                    > u64::try_from(MAX_TOTAL_FILE_BYTES).map_err(|_| Error::BoundExceeded)?
                {
                    return Err(Error::BoundExceeded);
                }
                output.try_reserve(1).map_err(|_| Error::BoundExceeded)?;
                output.push(ActualEntry {
                    components,
                    canonical_path: path,
                    kind: CandidateEntryKind::RegularFile,
                    identity,
                    byte_len,
                });
            }
            EntryKind::Unsupported => return Err(Error::CandidateVerificationFailed),
        }
    }
    Ok(())
}

fn verify_full_actual_candidate(
    root: &QualifiedDirectory,
    model: &AuthorizedReconstructionModel,
    actual: &ActualTree,
    expected_identities: Option<&BTreeMap<Vec<u8>, FileIdentity>>,
) -> Result<[u8; 32]> {
    if actual.entries.len() != model.plan().entries().len() {
        return Err(Error::CandidateVerificationFailed);
    }
    let actual_by_path = actual
        .entries
        .iter()
        .map(|entry| (entry.canonical_path.as_slice(), entry))
        .collect::<BTreeMap<_, _>>();
    if actual_by_path.len() != actual.entries.len() {
        return Err(Error::CandidateVerificationFailed);
    }
    for expected in model.plan().entries() {
        let found = actual_by_path
            .get(expected.canonical_path.as_slice())
            .ok_or(Error::CandidateVerificationFailed)?;
        if found.kind != expected.kind || found.components != expected.components {
            return Err(Error::CandidateVerificationFailed);
        }
        if expected_identities
            .and_then(|identities| identities.get(&expected.canonical_path))
            .is_some_and(|identity| *identity != found.identity)
        {
            return Err(Error::CandidateVerificationFailed);
        }
    }

    let schedule = model.authority.owner.key_schedule();
    let mut writer = CandidateCommitmentWriter::new(&schedule, model.inputs.profile, model.plan())?;
    let mut buffer = [0u8; STREAM_BUFFER_BYTES];
    for (index, entry) in model.plan().entries().iter().enumerate() {
        match entry.kind {
            CandidateEntryKind::Directory => writer.directory(model.plan(), index)?,
            CandidateEntryKind::RegularFile => {
                let expected = actual_by_path
                    .get(entry.canonical_path.as_slice())
                    .ok_or(Error::CandidateVerificationFailed)?;
                writer.begin_file(model.plan(), index, expected.byte_len)?;
                let mut file = open_plan_file(root, entry)?;
                let identity = file_identity(&file)?;
                let mut remaining = expected.byte_len;
                while remaining != 0 {
                    let request = usize::try_from(remaining.min(buffer.len() as u64))
                        .map_err(|_| Error::BoundExceeded)?;
                    let read = file
                        .read(&mut buffer[..request])
                        .map_err(|_| Error::CandidateVerificationFailed)?;
                    if read == 0 {
                        return Err(Error::CandidateVerificationFailed);
                    }
                    writer.file_chunk(&buffer[..read])?;
                    remaining -= u64::try_from(read).map_err(|_| Error::BoundExceeded)?;
                }
                if file
                    .read(&mut buffer[..1])
                    .map_err(|_| Error::CandidateVerificationFailed)?
                    != 0
                    || file_identity(&file)? != identity
                    || identity != expected.identity
                {
                    return Err(Error::CandidateVerificationFailed);
                }
                writer.end_file()?;
            }
        }
    }
    let commitment = writer.finish(model.plan())?;
    if constant_time_equal(&commitment, &model.expected_candidate_tree_commitment()) {
        Ok(commitment)
    } else {
        Err(Error::CandidateVerificationFailed)
    }
}

fn require_marker_precondition(root: &QualifiedDirectory, complete: bool) -> Result<()> {
    let observation = root.observe()?;
    let incomplete = observation
        .entries()
        .iter()
        .filter(|entry| entry.canonical_long_name() == CANDIDATE_INCOMPLETE_LEAF)
        .count();
    let completed = observation
        .entries()
        .iter()
        .filter(|entry| entry.canonical_long_name() == CANDIDATE_COMPLETE_LEAF)
        .count();
    if incomplete == 1 && completed == usize::from(complete) {
        Ok(())
    } else {
        Err(Error::CandidateVerificationFailed)
    }
}

fn open_plan_file(
    root: &QualifiedDirectory,
    entry: &super::candidate_model::CandidateNamespaceEntry,
) -> Result<File> {
    let (leaf, parents) = entry.components.split_last().ok_or(Error::InvalidState)?;
    let mut retained: Option<QualifiedDirectory> = None;
    for component in parents {
        retained = Some(match retained {
            Some(ref current) => current.open_exact_child_directory(OsStr::new(component))?,
            None => root.open_exact_child_directory(OsStr::new(component))?,
        });
    }
    retained
        .as_ref()
        .unwrap_or(root)
        .open_exact_regular(OsStr::new(leaf))
}

fn read_bounded(file: &mut File, limit: usize) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(limit.min(64 * 1024))
        .map_err(|_| Error::BoundExceeded)?;
    file.take(u64::try_from(limit + 1).map_err(|_| Error::BoundExceeded)?)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::FilesystemFailure)?;
    if bytes.len() > limit {
        return Err(Error::BoundExceeded);
    }
    Ok(bytes)
}
