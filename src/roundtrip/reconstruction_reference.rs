//! Independent reconstruction projected-retokenization and occurrence-graph reference.
//!
//! Unlike the production reconstruction walk, this verifier first compares
//! OID-keyed expected/actual graphs, then walks candidate spans to derive the
//! edited projection.  It never searches candidate bytes for raw values.

use std::collections::{BTreeMap, BTreeSet};

use super::candidate_model::{CandidateDisposition, CandidateEntryKind};
use super::crypto::{constant_time_equal, KeySchedule};
use super::edited::exact_file_match_commitment;
use super::reconstruct::{
    AuthorizedOccurrence, OccurrenceAction, ReconstructedBuffer, ReconstructionTraceNode,
};
use super::{Error, Result};

pub(crate) fn verify_reconstructed_component(
    schedule: &KeySchedule<'_>,
    original: &[u8],
    accepted_edited: &[u8],
    occurrences: &[AuthorizedOccurrence<'_>],
    reconstructed: &ReconstructedBuffer,
) -> Result<()> {
    let mut expected = BTreeMap::new();
    let mut placements = BTreeMap::new();
    for occurrence in occurrences {
        match occurrence.action {
            OccurrenceAction::RestoreOriginalOccurrence => {
                let placement = occurrence
                    .edited_placement
                    .ok_or(Error::OccurrenceGraphMismatch)?;
                if expected
                    .insert(occurrence.raw.occurrence_id, occurrence)
                    .is_some()
                    || placements
                        .insert(occurrence.raw.occurrence_id, placement)
                        .is_some()
                {
                    return Err(Error::OccurrenceGraphMismatch);
                }
            }
            OccurrenceAction::DeleteOccurrence => {
                if occurrence.edited_placement.is_some() {
                    return Err(Error::OccurrenceGraphMismatch);
                }
            }
        }
    }

    let mut actual = BTreeMap::new();
    for trace in reconstructed.trace() {
        if actual.insert(trace.occurrence_id, trace).is_some() {
            return Err(Error::OccurrenceGraphMismatch);
        }
    }
    if actual.len() != expected.len() {
        return Err(Error::OccurrenceGraphMismatch);
    }
    for (oid, occurrence) in &expected {
        let trace = actual.get(oid).ok_or(Error::OccurrenceGraphMismatch)?;
        compare_graph_node(occurrence, trace)?;
    }

    let mut ordered = reconstructed.trace().iter().collect::<Vec<_>>();
    ordered.sort_unstable_by_key(|trace| (trace.candidate_span.start, trace.candidate_span.end));
    let mut projected = Vec::new();
    projected
        .try_reserve_exact(accepted_edited.len())
        .map_err(|_| Error::BoundExceeded)?;
    let mut candidate_cursor = 0usize;
    let mut edited_cursor = 0usize;
    for trace in ordered {
        if trace.candidate_span.start < candidate_cursor {
            return Err(Error::OccurrenceGraphMismatch);
        }
        let placement = *placements
            .get(&trace.occurrence_id)
            .ok_or(Error::OccurrenceGraphMismatch)?;
        if placement.start < edited_cursor {
            return Err(Error::ProjectedRetokenizationMismatch);
        }
        projected.extend_from_slice(
            reconstructed
                .bytes()
                .get(candidate_cursor..trace.candidate_span.start)
                .ok_or(Error::OccurrenceGraphMismatch)?,
        );
        let raw_candidate = reconstructed
            .bytes()
            .get(trace.candidate_span.clone())
            .ok_or(Error::OccurrenceGraphMismatch)?;
        let raw_original = original
            .get(trace.original_span.clone())
            .ok_or(Error::OccurrenceGraphMismatch)?;
        if raw_candidate != raw_original {
            return Err(Error::OccurrenceGraphMismatch);
        }
        let token = accepted_edited
            .get(placement.start..placement.end)
            .ok_or(Error::ProjectedRetokenizationMismatch)?;
        verify_trace_token(schedule, token, trace)?;
        projected.extend_from_slice(token);
        candidate_cursor = trace.candidate_span.end;
        edited_cursor = placement.end;
    }
    projected.extend_from_slice(
        reconstructed
            .bytes()
            .get(candidate_cursor..)
            .ok_or(Error::OccurrenceGraphMismatch)?,
    );
    if projected != accepted_edited {
        return Err(Error::ProjectedRetokenizationMismatch);
    }
    Ok(())
}

fn compare_graph_node(
    occurrence: &&AuthorizedOccurrence<'_>,
    trace: &&ReconstructionTraceNode,
) -> Result<()> {
    if occurrence.raw.occurrence_id != trace.occurrence_id
        || occurrence.raw.category != trace.category
        || occurrence.raw.component_kind != trace.component_kind
        || occurrence.raw.component_index != trace.component_index
        || occurrence.raw.logical_file != trace.logical_file
        || occurrence.raw.source_span != trace.original_span
        || occurrence
            .edited_placement
            .map(|placement| placement.start..placement.end)
            != Some(trace.edited_span.clone())
        || occurrence.raw.occurrence_order != trace.occurrence_order
        || occurrence.raw.protected_anchor != trace.protected_anchor
        || trace.candidate_span.start >= trace.candidate_span.end
        || trace.candidate_span.len() != trace.original_span.len()
    {
        return Err(Error::OccurrenceGraphMismatch);
    }
    Ok(())
}

/// Independently derive an AI-visible component from a reconstructed candidate
/// component and its already graph-validated value-free trace.  This walk is
/// used for full path projection and never searches for raw values.
pub(crate) fn project_retokenized_component(
    schedule: &KeySchedule<'_>,
    original: &[u8],
    accepted_edited: &[u8],
    candidate: &[u8],
    trace: &[ReconstructionTraceNode],
) -> Result<Vec<u8>> {
    let mut ordered = trace.iter().collect::<Vec<_>>();
    ordered.sort_unstable_by_key(|node| (node.candidate_span.start, node.candidate_span.end));
    let mut projected = Vec::new();
    projected
        .try_reserve_exact(accepted_edited.len())
        .map_err(|_| Error::BoundExceeded)?;
    let mut candidate_cursor = 0usize;
    let mut edited_cursor = 0usize;
    for node in ordered {
        if node.candidate_span.start < candidate_cursor
            || node.edited_span.start < edited_cursor
            || node.candidate_span.start >= node.candidate_span.end
            || node.edited_span.start >= node.edited_span.end
        {
            return Err(Error::ProjectedRetokenizationMismatch);
        }
        projected.extend_from_slice(
            candidate
                .get(candidate_cursor..node.candidate_span.start)
                .ok_or(Error::ProjectedRetokenizationMismatch)?,
        );
        let candidate_raw = candidate
            .get(node.candidate_span.clone())
            .ok_or(Error::ProjectedRetokenizationMismatch)?;
        let original_raw = original
            .get(node.original_span.clone())
            .ok_or(Error::ProjectedRetokenizationMismatch)?;
        if candidate_raw != original_raw {
            return Err(Error::ProjectedRetokenizationMismatch);
        }
        let token = accepted_edited
            .get(node.edited_span.clone())
            .ok_or(Error::ProjectedRetokenizationMismatch)?;
        verify_trace_token(schedule, token, node)?;
        projected.extend_from_slice(token);
        candidate_cursor = node.candidate_span.end;
        edited_cursor = node.edited_span.end;
    }
    projected.extend_from_slice(
        candidate
            .get(candidate_cursor..)
            .ok_or(Error::ProjectedRetokenizationMismatch)?,
    );
    if projected != accepted_edited {
        return Err(Error::ProjectedRetokenizationMismatch);
    }
    Ok(projected)
}

fn verify_trace_token(
    schedule: &KeySchedule<'_>,
    token: &[u8],
    trace: &ReconstructionTraceNode,
) -> Result<()> {
    let token = std::str::from_utf8(token).map_err(|_| Error::ProjectedRetokenizationMismatch)?;
    let parsed =
        super::token::parse_token(token).map_err(|_| Error::ProjectedRetokenizationMismatch)?;
    if *parsed.occurrence_id() != trace.occurrence_id || parsed.category() != trace.category {
        return Err(Error::ProjectedRetokenizationMismatch);
    }
    super::token::authenticate_token(schedule, parsed)
        .map(|_| ())
        .map_err(|_| Error::ProjectedRetokenizationMismatch)
}

pub(crate) struct ExpectedEditedEntry<'a> {
    pub(crate) path: &'a [u8],
    pub(crate) kind: CandidateEntryKind,
    pub(crate) byte_len: u64,
    pub(crate) exact_file_match: Option<[u8; 32]>,
}

/// Incremental full AI projection equality verifier.  Original-only entries
/// are rejected at the boundary instead of silently being filtered.
pub(crate) struct ProjectionReference<'a, 'schedule, 'key> {
    schedule: &'schedule KeySchedule<'key>,
    expected: BTreeMap<&'a [u8], ExpectedEditedEntry<'a>>,
    seen: BTreeSet<Vec<u8>>,
}

impl<'a, 'schedule, 'key> ProjectionReference<'a, 'schedule, 'key> {
    pub(crate) fn new(
        schedule: &'schedule KeySchedule<'key>,
        entries: impl IntoIterator<Item = ExpectedEditedEntry<'a>>,
    ) -> Result<Self> {
        let mut expected = BTreeMap::new();
        for entry in entries {
            let path = entry.path;
            if expected.insert(path, entry).is_some() {
                return Err(Error::ProjectedRetokenizationMismatch);
            }
        }
        Ok(Self {
            schedule,
            expected,
            seen: BTreeSet::new(),
        })
    }

    pub(crate) fn observe(
        &mut self,
        disposition: CandidateDisposition,
        projected_path: &[u8],
        kind: CandidateEntryKind,
        projected_bytes: Option<&[u8]>,
    ) -> Result<()> {
        if disposition != CandidateDisposition::AiVisible
            || !self.seen.insert(projected_path.to_vec())
        {
            return Err(Error::ProjectedRetokenizationMismatch);
        }
        let expected = self
            .expected
            .get(projected_path)
            .ok_or(Error::ProjectedRetokenizationMismatch)?;
        if expected.kind != kind {
            return Err(Error::ProjectedRetokenizationMismatch);
        }
        match (kind, projected_bytes, expected.exact_file_match) {
            (CandidateEntryKind::Directory, None, None) if expected.byte_len == 0 => {}
            (CandidateEntryKind::RegularFile, Some(bytes), Some(expected_commitment))
                if u64::try_from(bytes.len()).ok() == Some(expected.byte_len) =>
            {
                let actual = exact_file_match_commitment(self.schedule, bytes)
                    .map_err(|_| Error::ProjectedRetokenizationMismatch)?;
                if !constant_time_equal(&actual, &expected_commitment) {
                    return Err(Error::ProjectedRetokenizationMismatch);
                }
            }
            _ => return Err(Error::ProjectedRetokenizationMismatch),
        }
        Ok(())
    }

    pub(crate) fn finish(self) -> Result<()> {
        if self.seen.len() != self.expected.len()
            || self.expected.keys().any(|path| !self.seen.contains(*path))
        {
            return Err(Error::ProjectedRetokenizationMismatch);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::roundtrip::anchor::ReconstructionPlacement;
    use crate::roundtrip::crypto::{SecretVec, SessionId, SessionMasterSecret};
    use crate::roundtrip::reconstruct::{RawOccurrenceNode, ReconstructionTraceNode};
    use crate::roundtrip::token::{
        generate_token, ComponentKind, EntryKind, OccurrenceDescriptor, ReviewProfile,
        TokenCategory,
    };

    fn fixture() -> (
        SessionMasterSecret,
        Vec<u8>,
        Vec<u8>,
        Vec<AuthorizedOccurrence<'static>>,
        ReconstructedBuffer,
    ) {
        let master = SessionMasterSecret::from_bytes([0xb1; 32]);
        let schedule = KeySchedule::new(&master, SessionId::from_bytes([0xb2; 16]));
        let original = b"raw@example.invalid".to_vec();
        let descriptor = OccurrenceDescriptor {
            session_id: schedule.session_id(),
            ruleset_id: crate::roundtrip::ruleset::ruleset_id(),
            review_profile: ReviewProfile::StandardV2,
            entry_kind: EntryKind::RegularFile,
            canonical_original_relative_path: b"file.txt",
            component_index: 0,
            component_kind: ComponentKind::Content,
            byte_span_start: 0,
            byte_span_end: original.len() as u64,
            category: TokenCategory::Email,
            occurrence_ordinal_within_component: 0,
            pre_token_anchor_commitment: [0xb3; 32],
        };
        let token = generate_token(&schedule, &descriptor)
            .expect("token")
            .into_bytes();
        let parsed =
            super::super::token::parse_token(std::str::from_utf8(&token).expect("token utf8"))
                .expect("parse");
        let oid = *parsed.occurrence_id();
        let mut edited = b"before ".to_vec();
        let start = edited.len();
        edited.extend_from_slice(&token);
        let end = edited.len();
        edited.extend_from_slice(b" after");
        let occurrences = vec![AuthorizedOccurrence {
            raw: RawOccurrenceNode {
                occurrence_id: oid,
                category: TokenCategory::Email,
                component_kind: ComponentKind::Content,
                original_canonical_path: b"file.txt",
                component_index: 0,
                logical_file: [0xb4; 32],
                source_span: 0..original.len(),
                occurrence_order: 0,
                protected_anchor: [0xb3; 32],
            },
            action: OccurrenceAction::RestoreOriginalOccurrence,
            edited_placement: Some(ReconstructionPlacement {
                occurrence_id: oid,
                start,
                end,
            }),
        }];
        let reconstructed_bytes = b"before raw@example.invalid after".to_vec();
        let reconstructed = ReconstructedBuffer {
            bytes: SecretVec::new(reconstructed_bytes),
            trace: vec![ReconstructionTraceNode {
                occurrence_id: oid,
                category: TokenCategory::Email,
                component_kind: ComponentKind::Content,
                component_index: 0,
                logical_file: [0xb4; 32],
                original_span: 0..original.len(),
                candidate_span: 7..26,
                edited_span: start..end,
                occurrence_order: 0,
                protected_anchor: [0xb3; 32],
            }],
        };
        (master, original, edited, occurrences, reconstructed)
    }

    #[test]
    fn independently_retokenizes_and_matches_the_expected_graph() {
        let (master, original, edited, occurrences, reconstructed) = fixture();
        let schedule = KeySchedule::new(&master, SessionId::from_bytes([0xb2; 16]));
        verify_reconstructed_component(&schedule, &original, &edited, &occurrences, &reconstructed)
            .expect("reference equality");
    }

    #[test]
    fn trace_mutations_fail_closed() {
        for mutation in 0..7 {
            let (master, original, edited, occurrences, mut reconstructed) = fixture();
            match mutation {
                0 => reconstructed.bytes.as_mut_slice()[7] = b'X',
                1 => reconstructed.trace.clear(),
                2 => {
                    let trace = reconstructed.trace[0].candidate_span.clone();
                    reconstructed.trace.push(ReconstructionTraceNode {
                        occurrence_id: reconstructed.trace[0].occurrence_id,
                        category: reconstructed.trace[0].category,
                        component_kind: reconstructed.trace[0].component_kind,
                        component_index: reconstructed.trace[0].component_index,
                        logical_file: reconstructed.trace[0].logical_file,
                        original_span: reconstructed.trace[0].original_span.clone(),
                        candidate_span: trace,
                        edited_span: reconstructed.trace[0].edited_span.clone(),
                        occurrence_order: reconstructed.trace[0].occurrence_order,
                        protected_anchor: reconstructed.trace[0].protected_anchor,
                    });
                }
                3 => reconstructed.trace[0].occurrence_id = [0xff; 16],
                4 => reconstructed.trace[0].category = TokenCategory::Secret,
                5 => reconstructed.trace[0].candidate_span = 8..27,
                6 => {
                    reconstructed.trace[0].edited_span.start = reconstructed.trace[0]
                        .edited_span
                        .start
                        .checked_add(1)
                        .expect("shifted boundary")
                }
                _ => unreachable!(),
            }
            let schedule = KeySchedule::new(&master, SessionId::from_bytes([0xb2; 16]));
            assert!(
                verify_reconstructed_component(
                    &schedule,
                    &original,
                    &edited,
                    &occurrences,
                    &reconstructed,
                )
                .is_err(),
                "mutation {mutation}"
            );
        }
    }

    #[test]
    fn projection_rejects_wrong_path_and_original_only_inclusion() {
        let master = SessionMasterSecret::from_bytes([0xc1; 32]);
        let schedule = KeySchedule::new(&master, SessionId::from_bytes([0xc2; 16]));
        let expected_commitment =
            exact_file_match_commitment(&schedule, b"edited").expect("expected commitment");
        let expected = [ExpectedEditedEntry {
            path: b"safe/file.txt",
            kind: CandidateEntryKind::RegularFile,
            byte_len: 6,
            exact_file_match: Some(expected_commitment),
        }];
        let mut wrong = ProjectionReference::new(&schedule, expected).expect("projection");
        assert_eq!(
            wrong.observe(
                CandidateDisposition::AiVisible,
                b"wrong/file.txt",
                CandidateEntryKind::RegularFile,
                Some(b"edited")
            ),
            Err(Error::ProjectedRetokenizationMismatch)
        );

        let expected = [ExpectedEditedEntry {
            path: b"safe/file.txt",
            kind: CandidateEntryKind::RegularFile,
            byte_len: 6,
            exact_file_match: Some(expected_commitment),
        }];
        let mut leaked = ProjectionReference::new(&schedule, expected).expect("projection");
        assert_eq!(
            leaked.observe(
                CandidateDisposition::OriginalOnly,
                b"safe/file.txt",
                CandidateEntryKind::RegularFile,
                Some(b"edited")
            ),
            Err(Error::ProjectedRetokenizationMismatch)
        );

        let expected = [ExpectedEditedEntry {
            path: b"safe/file.txt",
            kind: CandidateEntryKind::RegularFile,
            byte_len: 6,
            exact_file_match: Some(expected_commitment),
        }];
        let mut changed = ProjectionReference::new(&schedule, expected).expect("projection");
        assert_eq!(
            changed.observe(
                CandidateDisposition::AiVisible,
                b"safe/file.txt",
                CandidateEntryKind::RegularFile,
                Some(b"change")
            ),
            Err(Error::ProjectedRetokenizationMismatch)
        );
    }
}
