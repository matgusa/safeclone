//! Bounded StandardV2 anchors for token-bearing content runs.
//!
//! This module owns Original-side derivation and the edited-side exact relative
//! context matcher. File correspondence and events remain classifier policy;
//! approval, diff, and reconstruction have separate owners. Raw normalized context
//! is retained only in non-serializable, file-local transient values.

use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::mem::size_of;

use super::crypto::{HmacStream, KeyPurpose, KeySchedule};
use super::token::{ReviewProfile, TokenCategory, ENGINE_VERSION, POLICY_ID};
use super::{Error, Result};

pub(crate) const PROTECTED_ANCHOR_VERSION: u8 = 2;
pub(crate) const RELATIVE_CONTEXT_VERSION: u8 = 1;
pub(crate) const MAX_CONTEXT_LINES_PER_SIDE: usize = 16;
pub(crate) const MAX_CONTEXT_BYTES: usize = 5_242_880;
pub(crate) const MAX_ANCHOR_WINDOWS_PER_FILE: usize = 266_240;
pub(crate) const MAX_ANCHOR_SCAN_WORK_PER_FILE: usize = 8_388_608;
pub(crate) const MAX_ANCHOR_TEMP_BYTES_PER_FILE: usize = 33_554_432;
pub(crate) const MAX_FILE_BYTES: usize = 4_194_304;
pub(crate) const MAX_LOGICAL_LINES_PER_TOKEN_FILE: usize = 65_536;
pub(crate) const MAX_TOKENS_PER_FILE: usize = 16_640;

pub(crate) const RELATIVE_CONTEXT_PREFIX: &[u8] = b"SAFECLONE-RELATIVE-CONTEXT-V1\0";
pub(crate) const PRE_TOKEN_ANCHOR_DOMAIN: &[u8] = b"safeclone/rt3/pre-token-relative-anchor-v2";
pub(crate) const FINAL_ANCHOR_DOMAIN: &[u8] = b"safeclone/rt3/protected-relative-anchor-v2";

const RANKED_LINE_DOMAIN: &[u8] = b"safeclone/rt3/relative-anchor-line-rank-v1";
const RANKED_CORE_DOMAIN: &[u8] = b"safeclone/rt3/relative-anchor-core-rank-v1";
const REGULAR_CONTENT_ROLE: u8 = 1;
const SORT_STACK_ALLOWANCE: usize = 4_096;
const EDITED_MATCHER_CONTAINER_ALLOWANCE: usize = 65_536;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct TokenFact {
    pub(crate) category: TokenCategory,
    pub(crate) occurrence_id: [u8; 16],
}

#[derive(Clone, Copy)]
pub(crate) struct DetectedContentOccurrence {
    pub(crate) start: usize,
    pub(crate) end: usize,
    pub(crate) category: TokenCategory,
    pub(crate) ordinal: u32,
    pub(crate) category_bits: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct EvidenceRegion {
    pub(crate) start: u64,
    pub(crate) end: u64,
    pub(crate) category: TokenCategory,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ContentAnchorFact {
    pub(crate) anchor_version: u8,
    pub(crate) context_version: u8,
    pub(crate) selected_radius: u8,
    pub(crate) pre_token_anchor_commitment: [u8; 32],
    pub(crate) final_anchor_commitment: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ContentTokenSpan {
    pub(crate) start: usize,
    pub(crate) end: usize,
    pub(crate) fact: TokenFact,
}

/// Fresh, transient baseline content authority for classification. The safe tokenized
/// bytes and exact normalized context are deliberately non-serializable and
/// this type has no ordinary `Debug` implementation.
pub(crate) struct BaselineContentTemplate {
    source: Vec<u8>,
    facts: Vec<TokenFact>,
    model: NormalizedModel,
    runs: Vec<ProtectedRun>,
    anchors: Vec<ContentAnchorFact>,
}

/// Value-free authority needed by review to derive an opaque content anchor ID
/// and report its baseline line location. No context or line bytes escape.
pub(crate) struct ContentAnchorReportFact {
    pub(crate) occurrence_ids: Vec<[u8; 16]>,
    pub(crate) selected_radius: u8,
    pub(crate) final_anchor_commitment: [u8; 32],
    pub(crate) first_line: u32,
    pub(crate) end_line_exclusive: u32,
}

impl BaselineContentTemplate {
    pub(crate) fn token_order(&self) -> impl Iterator<Item = TokenFact> + '_ {
        self.facts.iter().copied()
    }

    pub(crate) fn pre_token_anchor(&self, oid: &[u8; 16]) -> Option<[u8; 32]> {
        self.runs
            .iter()
            .zip(&self.anchors)
            .find_map(|(run, anchor)| {
                let start = usize::try_from(run.first_occurrence).ok()?;
                let end = start.checked_add(usize::try_from(run.occurrence_count).ok()?)?;
                self.facts
                    .get(start..end)?
                    .iter()
                    .any(|fact| &fact.occurrence_id == oid)
                    .then_some(anchor.pre_token_anchor_commitment)
            })
    }

    pub(crate) fn reporting_anchor_facts(&self) -> Result<Vec<ContentAnchorReportFact>> {
        if self.runs.len() != self.anchors.len() {
            return Err(Error::AnchorEncodingInvalid);
        }
        let mut output = Vec::new();
        reserve_exact(&mut output, self.runs.len())?;
        for (run, anchor) in self.runs.iter().zip(&self.anchors) {
            let range = occurrence_range(run, self.facts.len())?;
            let mut occurrence_ids = Vec::new();
            reserve_exact(&mut occurrence_ids, range.len())?;
            occurrence_ids.extend(
                self.facts
                    .get(range)
                    .ok_or(Error::AnchorEncodingInvalid)?
                    .iter()
                    .map(|fact| fact.occurrence_id),
            );
            output.push(ContentAnchorReportFact {
                occurrence_ids,
                selected_radius: anchor.selected_radius,
                final_anchor_commitment: anchor.final_anchor_commitment,
                first_line: run
                    .first_line
                    .checked_add(1)
                    .ok_or(Error::AnchorEncodingInvalid)?,
                end_line_exclusive: run
                    .last_line
                    .checked_add(2)
                    .ok_or(Error::AnchorEncodingInvalid)?,
            });
        }
        Ok(output)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EditedAnchorOutcome {
    Preserved,
    Deleted,
    ProtectedContextChanged,
    ProtectedCoreChanged,
    AnchorAmbiguous,
}

pub(crate) struct EditedContentClassification {
    outcomes: Vec<([u8; 16], EditedAnchorOutcome)>,
    pub(crate) edited_oid_order: Vec<[u8; 16]>,
    deletion_eligible: Vec<[u8; 16]>,
    reconstruction_placements: Vec<ReconstructionPlacement>,
}

/// Exact edited-token placement released only after the existing StandardV2
/// anchor classifier has accepted the occurrence.  It contains no token text
/// or raw source value and deliberately has no ordinary `Debug` formatter.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct ReconstructionPlacement {
    pub(crate) occurrence_id: [u8; 16],
    pub(crate) start: usize,
    pub(crate) end: usize,
}

impl EditedContentClassification {
    pub(crate) fn outcome(&self, oid: &[u8; 16]) -> Option<EditedAnchorOutcome> {
        self.outcomes
            .binary_search_by_key(oid, |(candidate, _)| *candidate)
            .ok()
            .map(|index| self.outcomes[index].1)
    }

    pub(crate) fn deletion_is_eligible(&self, oid: &[u8; 16]) -> bool {
        self.deletion_eligible.binary_search(oid).is_ok()
    }

    pub(crate) fn reconstruction_placement(
        &self,
        oid: &[u8; 16],
    ) -> Option<ReconstructionPlacement> {
        self.reconstruction_placements
            .binary_search_by_key(oid, |placement| placement.occurrence_id)
            .ok()
            .and_then(|index| self.reconstruction_placements.get(index))
            .copied()
    }
}

/// Transient one-file preparation. Deliberately neither `Clone` nor `Debug`,
/// and no serialization API exists for its normalized context arena.
pub(crate) struct PreparedContentAnchors {
    occurrences: Vec<DetectedContentOccurrence>,
    model: NormalizedModel,
    runs: Vec<ProtectedRun>,
    selected: Vec<SelectedRun>,
    occurrence_commitments: Vec<[u8; 32]>,
}

impl PreparedContentAnchors {
    pub(crate) fn occurrences(&self) -> &[DetectedContentOccurrence] {
        &self.occurrences
    }

    pub(crate) fn pre_token_commitments(&self) -> &[[u8; 32]] {
        &self.occurrence_commitments
    }
}

#[derive(Clone, Copy)]
enum AtomRecord {
    Bytes { start: u32, end: u32 },
    Token { occurrence: u32 },
}

#[derive(Clone, Copy)]
struct LineRecord {
    atom_start: u32,
    atom_end: u32,
    canonical_start: u32,
    canonical_end: u32,
    token_count: u32,
    digest: [u8; 32],
}

struct NormalizedModel {
    atoms: Vec<AtomRecord>,
    lines: Vec<LineRecord>,
    canonical_lines: Vec<u8>,
    line_ranks: Vec<u32>,
    line_part_prefix: Vec<usize>,
}

#[derive(Clone, Copy)]
struct ProtectedRun {
    first_line: u32,
    last_line: u32,
    first_occurrence: u32,
    occurrence_count: u32,
    core_rank: u32,
    core_digest: [u8; 32],
}

#[derive(Clone, Copy)]
struct SelectedRun {
    radius: u8,
    pre_token_commitment: [u8; 32],
}

#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
struct BoundaryRank {
    state: u8,
    rank: u32,
}

#[derive(Clone, Copy)]
struct EditedLineIndexRecord {
    line_index: u32,
}

#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
struct WindowKey {
    inner_rank: u32,
    left: BoundaryRank,
    right: BoundaryRank,
}

#[derive(Clone, Copy)]
struct WindowCandidate {
    key: WindowKey,
    run_index: u32,
}

#[derive(Default)]
struct ResourceAccount {
    windows: usize,
    work: usize,
}

impl ResourceAccount {
    fn charge_windows(&mut self, count: usize) -> Result<()> {
        self.windows = resource_add(self.windows, count)?;
        if self.windows > MAX_ANCHOR_WINDOWS_PER_FILE {
            return Err(Error::AnchorResourceLimitExceeded);
        }
        Ok(())
    }

    fn charge_work(&mut self, count: usize) -> Result<()> {
        self.work = resource_add(self.work, count)?;
        if self.work > MAX_ANCHOR_SCAN_WORK_PER_FILE {
            return Err(Error::AnchorResourceLimitExceeded);
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
pub(crate) struct ContentFileRole<'a> {
    pub(crate) volume_serial: u64,
    pub(crate) file_id: [u8; 16],
    pub(crate) safe_canonical_path: &'a [u8],
}

pub(crate) fn prepare_content_anchors(
    schedule: &KeySchedule<'_>,
    profile: ReviewProfile,
    canonical_original_path: &[u8],
    bytes: &[u8],
    occurrences: Vec<DetectedContentOccurrence>,
) -> Result<PreparedContentAnchors> {
    require_current_profile(profile)?;
    if occurrences.is_empty() {
        return Ok(PreparedContentAnchors {
            occurrences: Vec::new(),
            model: NormalizedModel {
                atoms: Vec::new(),
                lines: Vec::new(),
                canonical_lines: Vec::new(),
                line_ranks: Vec::new(),
                line_part_prefix: Vec::new(),
            },
            runs: Vec::new(),
            selected: Vec::new(),
            occurrence_commitments: Vec::new(),
        });
    }
    validate_static_resource_model()?;
    validate_inputs(canonical_original_path, bytes, &occurrences)?;

    let mut account = ResourceAccount::default();
    let model = build_normalized_model(schedule, bytes, &occurrences, &mut account)?;
    let runs = discover_runs(schedule, &model, &occurrences, &mut account)?;
    let radii = select_unique_radii(&model, &runs, &mut account)?;
    let mut occurrence_commitments = allocate_filled(occurrences.len(), [0u8; 32])?;
    let mut selected = Vec::new();
    reserve_exact(&mut selected, runs.len())?;
    for (run, radius) in runs.iter().zip(radii) {
        let pre_token_commitment = pre_token_commitment(
            schedule,
            profile,
            canonical_original_path,
            bytes,
            &occurrences,
            &model,
            run,
            radius,
        )?;
        let start =
            usize::try_from(run.first_occurrence).map_err(|_| Error::AnchorEncodingInvalid)?;
        let end = start
            .checked_add(
                usize::try_from(run.occurrence_count).map_err(|_| Error::AnchorEncodingInvalid)?,
            )
            .ok_or(Error::AnchorEncodingInvalid)?;
        for commitment in occurrence_commitments
            .get_mut(start..end)
            .ok_or(Error::AnchorEncodingInvalid)?
        {
            *commitment = pre_token_commitment;
        }
        selected.push(SelectedRun {
            radius,
            pre_token_commitment,
        });
    }
    if occurrence_commitments.contains(&[0u8; 32]) {
        return Err(Error::AnchorEncodingInvalid);
    }

    Ok(PreparedContentAnchors {
        occurrences,
        model,
        runs,
        selected,
        occurrence_commitments,
    })
}

pub(crate) fn finalize_content_anchors(
    schedule: &KeySchedule<'_>,
    profile: ReviewProfile,
    role: ContentFileRole<'_>,
    source: &[u8],
    prepared: &PreparedContentAnchors,
    facts: &[TokenFact],
) -> Result<Vec<ContentAnchorFact>> {
    require_current_profile(profile)?;
    if source.len() > MAX_FILE_BYTES
        || facts.len() != prepared.occurrences.len()
        || prepared.runs.len() != prepared.selected.len()
        || role.safe_canonical_path.is_empty()
    {
        return Err(Error::AnchorEncodingInvalid);
    }
    for (fact, occurrence) in facts.iter().zip(&prepared.occurrences) {
        if fact.category != occurrence.category {
            return Err(Error::AnchorEncodingInvalid);
        }
    }
    let mut output = Vec::new();
    reserve_exact(&mut output, prepared.runs.len())?;
    for (run, selected) in prepared.runs.iter().zip(&prepared.selected) {
        let final_anchor_commitment = final_anchor_commitment(
            schedule,
            profile,
            &role,
            source,
            &prepared.occurrences,
            facts,
            &prepared.model,
            run,
            *selected,
        )?;
        output.push(ContentAnchorFact {
            anchor_version: PROTECTED_ANCHOR_VERSION,
            context_version: RELATIVE_CONTEXT_VERSION,
            selected_radius: selected.radius,
            pre_token_anchor_commitment: selected.pre_token_commitment,
            final_anchor_commitment,
        });
    }
    Ok(output)
}

pub(crate) fn build_baseline_content_template(
    schedule: &KeySchedule<'_>,
    source: Vec<u8>,
    spans: &[ContentTokenSpan],
    anchors: &[ContentAnchorFact],
) -> Result<BaselineContentTemplate> {
    let (occurrences, facts) = content_occurrences(spans, source.len())?;
    if occurrences.is_empty() || occurrences.len() > MAX_TOKENS_PER_FILE {
        return Err(Error::AnchorEncodingInvalid);
    }
    let mut account = ResourceAccount::default();
    let mut model = build_normalized_model(schedule, &source, &occurrences, &mut account)?;
    let runs = discover_runs(schedule, &model, &occurrences, &mut account)?;
    let selected = select_unique_radii(&model, &runs, &mut account)?;
    if runs.len() != anchors.len()
        || selected.iter().zip(anchors).any(|(radius, anchor)| {
            anchor.anchor_version != PROTECTED_ANCHOR_VERSION
                || anchor.context_version != RELATIVE_CONTEXT_VERSION
                || *radius != anchor.selected_radius
        })
    {
        return Err(Error::AnchorEncodingInvalid);
    }
    model.line_ranks = Vec::new();
    model.line_part_prefix = Vec::new();
    let mut retained_anchors = Vec::new();
    reserve_exact(&mut retained_anchors, anchors.len())?;
    retained_anchors.extend_from_slice(anchors);
    Ok(BaselineContentTemplate {
        source,
        facts,
        model,
        runs,
        anchors: retained_anchors,
    })
}

pub(crate) fn classify_edited_content(
    schedule: &KeySchedule<'_>,
    baseline: &BaselineContentTemplate,
    edited: &[u8],
    edited_spans: &[ContentTokenSpan],
    zero_attribution: &BTreeSet<[u8; 16]>,
) -> Result<EditedContentClassification> {
    require_edited_match_memory_bound(edited_match_memory_upper_bound(
        baseline,
        edited,
        edited_spans,
    )?)?;
    let (edited_occurrences, edited_facts) = content_occurrences(edited_spans, edited.len())?;
    let mut account = ResourceAccount::default();
    let mut edited_model =
        build_normalized_model(schedule, edited, &edited_occurrences, &mut account)?;
    edited_model.line_ranks = Vec::new();
    edited_model.line_part_prefix = Vec::new();
    let mut outcomes = Vec::new();
    reserve_exact(&mut outcomes, baseline.facts.len())?;
    let mut deletion_eligible = Vec::new();
    reserve_exact(&mut deletion_eligible, baseline.facts.len())?;
    let mut edited_oid_order = Vec::new();
    reserve_exact(&mut edited_oid_order, edited_facts.len())?;
    edited_oid_order.extend(edited_facts.iter().map(|fact| fact.occurrence_id));

    let edited_line_index = index_edited_lines(&edited_model, &mut account)?;
    let no_removed_tokens = BTreeSet::new();
    for (run_index, run) in baseline.runs.iter().enumerate() {
        let range = occurrence_range(run, baseline.facts.len())?;
        let run_facts = baseline
            .facts
            .get(range.clone())
            .ok_or(Error::AnchorEncodingInvalid)?;
        let run_has_deletion = run_facts
            .iter()
            .any(|fact| zero_attribution.contains(&fact.occurrence_id));
        let removed = if run_has_deletion {
            zero_attribution
        } else {
            &no_removed_tokens
        };
        let radius = usize::from(
            baseline
                .anchors
                .get(run_index)
                .ok_or(Error::AnchorEncodingInvalid)?
                .selected_radius,
        );
        let outcome = match_run(
            schedule,
            baseline,
            run,
            radius,
            removed,
            &edited_model,
            &edited_facts,
            &edited_line_index,
            &mut account,
        )?;
        for fact in run_facts {
            let is_missing = zero_attribution.contains(&fact.occurrence_id);
            let token_outcome = match (outcome, is_missing) {
                (EditedAnchorOutcome::Preserved, false) => EditedAnchorOutcome::Preserved,
                (EditedAnchorOutcome::Preserved, true) => {
                    deletion_eligible.push(fact.occurrence_id);
                    EditedAnchorOutcome::Deleted
                }
                (other, _) => other,
            };
            outcomes.push((fact.occurrence_id, token_outcome));
        }
    }
    if outcomes.len() != baseline.facts.len() {
        return Err(Error::AnchorEncodingInvalid);
    }
    outcomes.sort_unstable_by_key(|(oid, _)| *oid);
    if outcomes.windows(2).any(|pair| pair[0].0 == pair[1].0) {
        return Err(Error::AnchorEncodingInvalid);
    }
    deletion_eligible.sort_unstable();
    let mut spans_by_oid = Vec::new();
    reserve_exact(&mut spans_by_oid, edited_spans.len())?;
    spans_by_oid.extend_from_slice(edited_spans);
    spans_by_oid.sort_unstable_by_key(|span| span.fact.occurrence_id);
    let mut reconstruction_placements = Vec::new();
    reserve_exact(&mut reconstruction_placements, edited_spans.len())?;
    let mut span_index = 0usize;
    while span_index < spans_by_oid.len() {
        let oid = spans_by_oid[span_index].fact.occurrence_id;
        let mut next_index = span_index + 1;
        while next_index < spans_by_oid.len() && spans_by_oid[next_index].fact.occurrence_id == oid
        {
            next_index += 1;
        }
        let span = spans_by_oid[span_index];
        let outcome = outcomes
            .binary_search_by_key(&oid, |(candidate, _)| *candidate)
            .ok()
            .and_then(|index| outcomes.get(index))
            .map(|(_, outcome)| *outcome);
        // Duplicate authenticated token text remains an classification
        // TokenDuplicated outcome. It must not turn the classifier into an
        // encoding failure, and it cannot release a unique reconstruction
        // placement.
        if next_index == span_index + 1 && outcome == Some(EditedAnchorOutcome::Preserved) {
            reconstruction_placements.push(ReconstructionPlacement {
                occurrence_id: oid,
                start: span.start,
                end: span.end,
            });
        }
        span_index = next_index;
    }
    Ok(EditedContentClassification {
        outcomes,
        edited_oid_order,
        deletion_eligible,
        reconstruction_placements,
    })
}

fn content_occurrences(
    spans: &[ContentTokenSpan],
    source_len: usize,
) -> Result<(Vec<DetectedContentOccurrence>, Vec<TokenFact>)> {
    if source_len > MAX_FILE_BYTES || spans.len() > MAX_TOKENS_PER_FILE {
        return Err(Error::AnchorResourceLimitExceeded);
    }
    let mut occurrences = Vec::new();
    occurrences
        .try_reserve_exact(spans.len())
        .map_err(|_| Error::AnchorResourceLimitExceeded)?;
    let mut facts = Vec::new();
    facts
        .try_reserve_exact(spans.len())
        .map_err(|_| Error::AnchorResourceLimitExceeded)?;
    let mut prior_end = 0usize;
    for (ordinal, span) in spans.iter().enumerate() {
        if span.start >= span.end || span.end > source_len || span.start < prior_end {
            return Err(Error::AnchorEncodingInvalid);
        }
        occurrences.push(DetectedContentOccurrence {
            start: span.start,
            end: span.end,
            category: span.fact.category,
            ordinal: u32::try_from(ordinal).map_err(|_| Error::AnchorEncodingInvalid)?,
            category_bits: 1u16 << ((span.fact.category as u8) - 1),
        });
        facts.push(span.fact);
        prior_end = span.end;
    }
    Ok((occurrences, facts))
}

fn vec_capacity_bytes<T>(value: &Vec<T>) -> Result<usize> {
    resource_mul(value.capacity(), size_of::<T>())
}

fn baseline_template_capacity_bytes(baseline: &BaselineContentTemplate) -> Result<usize> {
    [
        baseline.source.capacity(),
        vec_capacity_bytes(&baseline.facts)?,
        vec_capacity_bytes(&baseline.model.atoms)?,
        vec_capacity_bytes(&baseline.model.lines)?,
        baseline.model.canonical_lines.capacity(),
        vec_capacity_bytes(&baseline.model.line_ranks)?,
        vec_capacity_bytes(&baseline.model.line_part_prefix)?,
        vec_capacity_bytes(&baseline.runs)?,
        vec_capacity_bytes(&baseline.anchors)?,
    ]
    .into_iter()
    .try_fold(0usize, resource_add)
}

fn edited_match_memory_upper_bound(
    baseline: &BaselineContentTemplate,
    edited: &[u8],
    edited_spans: &[ContentTokenSpan],
) -> Result<usize> {
    let edited_lines = logical_line_count(edited)?;
    require_resource_dimensions(edited.len(), edited_lines, edited_spans.len())?;
    let capacities = model_capacities(edited.len(), edited_lines, edited_spans.len())?;
    let common = [
        baseline_template_capacity_bytes(baseline)?,
        edited.len(),
        resource_mul(edited_spans.len(), size_of::<ContentTokenSpan>())?,
        resource_mul(edited_spans.len(), size_of::<DetectedContentOccurrence>())?,
        resource_mul(edited_spans.len(), size_of::<TokenFact>())?,
        resource_mul(capacities.atoms, size_of::<AtomRecord>())?,
        resource_mul(capacities.source_lines, size_of::<LineRecord>())?,
        capacities.canonical,
        EDITED_MATCHER_CONTAINER_ALLOWANCE,
    ]
    .into_iter()
    .try_fold(0usize, resource_add)?;

    let line_ranks = resource_mul(capacities.source_lines, size_of::<u32>())?;
    let sort_indices = resource_mul(capacities.source_lines, size_of::<usize>())?;
    let line_prefix = resource_mul(
        resource_add(capacities.source_lines, 1)?,
        size_of::<usize>(),
    )?;
    let build_scratch = resource_add(line_ranks, sort_indices.max(line_prefix))?;
    let build_peak = resource_add(common, build_scratch)?;

    let maximum_envelope_lines = baseline.model.lines.len().min(resource_add(
        baseline.facts.len(),
        resource_mul(MAX_CONTEXT_LINES_PER_SIDE, 2)?,
    )?);
    let projected_bytes = baseline
        .model
        .canonical_lines
        .len()
        .checked_add(resource_mul(baseline.facts.len(), 3)?)
        .ok_or(Error::AnchorResourceLimitExceeded)?
        .min(MAX_CONTEXT_BYTES);
    let match_scratch = [
        resource_mul(capacities.source_lines, size_of::<EditedLineIndexRecord>())?,
        resource_mul(
            baseline.facts.len(),
            size_of::<([u8; 16], EditedAnchorOutcome)>(),
        )?,
        resource_mul(baseline.facts.len(), size_of::<[u8; 16]>())?,
        resource_mul(edited_spans.len(), size_of::<[u8; 16]>())?,
        resource_mul(maximum_envelope_lines, size_of::<(usize, Vec<u8>)>())?,
        projected_bytes,
        resource_mul(
            resource_mul(baseline.facts.len(), 2)?,
            size_of::<[u8; 16]>(),
        )?,
    ]
    .into_iter()
    .try_fold(0usize, resource_add)?;
    Ok(build_peak.max(resource_add(common, match_scratch)?))
}

fn require_edited_match_memory_bound(upper_bound: usize) -> Result<()> {
    if upper_bound > MAX_ANCHOR_TEMP_BYTES_PER_FILE {
        Err(Error::AnchorResourceLimitExceeded)
    } else {
        Ok(())
    }
}

fn index_edited_lines(
    model: &NormalizedModel,
    account: &mut ResourceAccount,
) -> Result<Vec<EditedLineIndexRecord>> {
    account.charge_work(ordering_work(model.lines.len())?)?;
    let mut output = Vec::new();
    reserve_exact(&mut output, model.lines.len())?;
    for index in 0..model.lines.len() {
        output.push(EditedLineIndexRecord {
            line_index: to_u32(index)?,
        });
    }
    output.sort_unstable_by(|left, right| {
        compare_lines(model, left.line_index as usize, right.line_index as usize)
    });
    Ok(output)
}

#[allow(clippy::too_many_arguments)]
fn match_run(
    schedule: &KeySchedule<'_>,
    baseline: &BaselineContentTemplate,
    run: &ProtectedRun,
    radius: usize,
    removed: &BTreeSet<[u8; 16]>,
    edited_model: &NormalizedModel,
    edited_facts: &[TokenFact],
    edited_line_index: &[EditedLineIndexRecord],
    account: &mut ResourceAccount,
) -> Result<EditedAnchorOutcome> {
    let first = usize::try_from(run.first_line).map_err(|_| Error::AnchorEncodingInvalid)?;
    let last = usize::try_from(run.last_line).map_err(|_| Error::AnchorEncodingInvalid)?;
    let core_len = last
        .checked_sub(first)
        .and_then(|value| value.checked_add(1))
        .ok_or(Error::AnchorEncodingInvalid)?;
    let mut projected_lines = Vec::new();
    let needed_start = first.saturating_sub(radius);
    let needed_end = last
        .checked_add(radius)
        .and_then(|value| value.checked_add(1))
        .ok_or(Error::AnchorResourceLimitExceeded)?
        .min(baseline.model.lines.len());
    account.charge_work(resource_mul(needed_end - needed_start, 2)?)?;
    let projected_line_count = (needed_start..needed_end).try_fold(0usize, |count, line| {
        if line_contains_removed_token(&baseline.model, &baseline.facts, line, removed)? {
            resource_add(count, 1)
        } else {
            Ok(count)
        }
    })?;
    reserve_exact(&mut projected_lines, projected_line_count)?;
    let mut projected_bytes = 0usize;
    for line_index in needed_start..needed_end {
        if !line_contains_removed_token(&baseline.model, &baseline.facts, line_index, removed)? {
            continue;
        }
        let projected = projected_line(
            &baseline.source,
            &baseline.model,
            &baseline.facts,
            line_index,
            removed,
        )?;
        projected_bytes = resource_add(projected_bytes, projected.len())?;
        if projected_bytes > MAX_CONTEXT_BYTES {
            return Err(Error::AnchorResourceLimitExceeded);
        }
        projected_lines.push((line_index, projected));
    }
    let first_pattern = projected_line_bytes(&baseline.model, &projected_lines, first)?;
    let first_digest = transient_digest(schedule, RANKED_LINE_DOMAIN, first_pattern)?;
    account.charge_work(resource_mul(ceil_log2(edited_line_index.len()), 2)?)?;
    let candidate_start = edited_line_index.partition_point(|record| {
        compare_line_with_pattern(
            edited_model,
            record.line_index as usize,
            &first_digest,
            first_pattern,
        ) == Ordering::Less
    });
    let candidate_count = edited_line_index[candidate_start..].partition_point(|record| {
        compare_line_with_pattern(
            edited_model,
            record.line_index as usize,
            &first_digest,
            first_pattern,
        ) == Ordering::Equal
    });
    let candidates = &edited_line_index[candidate_start..candidate_start + candidate_count];
    let mut envelope_matches = 0usize;
    let mut exact_core_present = false;
    let mut exact_envelope_and_tokens = false;
    let occurrence_range = occurrence_range(run, baseline.facts.len())?;
    let mut expected_oids = Vec::new();
    reserve_exact(&mut expected_oids, occurrence_range.len())?;
    for index in occurrence_range {
        let fact = baseline.facts[index];
        if !removed.contains(&fact.occurrence_id) {
            expected_oids.push(fact.occurrence_id);
        }
    }

    for candidate in candidates {
        account.charge_windows(1)?;
        let candidate = candidate.line_index as usize;
        if candidate
            .checked_add(core_len)
            .is_none_or(|end| end > edited_model.lines.len())
        {
            continue;
        }
        if !core_lines_match(
            &baseline.model,
            &projected_lines,
            first,
            last,
            edited_model,
            candidate,
            account,
        )? {
            continue;
        }
        let candidate_oids =
            oids_in_line_range(edited_model, edited_facts, candidate, candidate + core_len)?;
        if candidate_oids == expected_oids {
            exact_core_present = true;
        }
        if envelope_matches_at(
            baseline,
            run,
            radius,
            &projected_lines,
            edited_model,
            candidate,
            account,
        )? {
            envelope_matches = envelope_matches
                .checked_add(1)
                .ok_or(Error::AnchorResourceLimitExceeded)?;
            if candidate_oids == expected_oids {
                exact_envelope_and_tokens = true;
            }
        }
    }

    if envelope_matches > 1 {
        Ok(EditedAnchorOutcome::AnchorAmbiguous)
    } else if envelope_matches == 1 && exact_envelope_and_tokens {
        Ok(EditedAnchorOutcome::Preserved)
    } else if exact_core_present {
        Ok(EditedAnchorOutcome::ProtectedContextChanged)
    } else {
        Ok(EditedAnchorOutcome::ProtectedCoreChanged)
    }
}

fn core_lines_match(
    baseline: &NormalizedModel,
    projected: &[(usize, Vec<u8>)],
    first: usize,
    last: usize,
    edited: &NormalizedModel,
    candidate: usize,
    account: &mut ResourceAccount,
) -> Result<bool> {
    for baseline_line in first..=last {
        account.charge_work(1)?;
        let offset = baseline_line - first;
        let edited_line = candidate
            .checked_add(offset)
            .ok_or(Error::AnchorResourceLimitExceeded)?;
        let expected = projected_line_bytes(baseline, projected, baseline_line)?;
        let observed = edited
            .lines
            .get(edited_line)
            .map(|_| line_bytes(edited, edited_line));
        if Some(expected) != observed {
            return Ok(false);
        }
    }
    Ok(true)
}

#[allow(clippy::too_many_arguments)]
fn envelope_matches_at(
    baseline: &BaselineContentTemplate,
    run: &ProtectedRun,
    radius: usize,
    projected: &[(usize, Vec<u8>)],
    edited: &NormalizedModel,
    candidate: usize,
    account: &mut ResourceAccount,
) -> Result<bool> {
    let first = usize::try_from(run.first_line).map_err(|_| Error::AnchorEncodingInvalid)?;
    let last = usize::try_from(run.last_line).map_err(|_| Error::AnchorEncodingInvalid)?;
    let core_len = last - first + 1;
    let baseline_layout = envelope_layout(baseline.model.lines.len(), run, radius)?;
    let candidate_last = candidate
        .checked_add(core_len - 1)
        .ok_or(Error::AnchorResourceLimitExceeded)?;
    let candidate_run = ProtectedRun {
        first_line: to_u32(candidate)?,
        last_line: to_u32(candidate_last)?,
        first_occurrence: 0,
        occurrence_count: 0,
        core_rank: 0,
        core_digest: [0; 32],
    };
    let edited_layout = envelope_layout(edited.lines.len(), &candidate_run, radius)?;
    if baseline_layout.bof != edited_layout.bof
        || baseline_layout.eof != edited_layout.eof
        || baseline_layout.left_end - baseline_layout.left_start
            != edited_layout.left_end - edited_layout.left_start
        || baseline_layout.right_end - baseline_layout.right_start
            != edited_layout.right_end - edited_layout.right_start
    {
        return Ok(false);
    }
    for (baseline_line, edited_line) in (baseline_layout.left_start..baseline_layout.left_end)
        .chain(baseline_layout.core_start..baseline_layout.core_end)
        .chain(baseline_layout.right_start..baseline_layout.right_end)
        .zip(
            (edited_layout.left_start..edited_layout.left_end)
                .chain(edited_layout.core_start..edited_layout.core_end)
                .chain(edited_layout.right_start..edited_layout.right_end),
        )
    {
        account.charge_work(1)?;
        let expected = projected_line_bytes(&baseline.model, projected, baseline_line)?;
        if expected != line_bytes(edited, edited_line) {
            return Ok(false);
        }
    }
    Ok(true)
}

fn projected_line_bytes<'a>(
    baseline: &'a NormalizedModel,
    projected: &'a [(usize, Vec<u8>)],
    line: usize,
) -> Result<&'a [u8]> {
    match projected.binary_search_by_key(&line, |(line, _)| *line) {
        Ok(index) => Ok(projected[index].1.as_slice()),
        Err(_) if line < baseline.lines.len() => Ok(line_bytes(baseline, line)),
        Err(_) => Err(Error::AnchorEncodingInvalid),
    }
}

fn line_contains_removed_token(
    model: &NormalizedModel,
    facts: &[TokenFact],
    line_index: usize,
    removed: &BTreeSet<[u8; 16]>,
) -> Result<bool> {
    if removed.is_empty() {
        return Ok(false);
    }
    let line = model
        .lines
        .get(line_index)
        .ok_or(Error::AnchorEncodingInvalid)?;
    for atom in line_atoms(model, line)? {
        if let AtomRecord::Token { occurrence } = *atom {
            let fact = facts
                .get(usize::try_from(occurrence).map_err(|_| Error::AnchorEncodingInvalid)?)
                .ok_or(Error::AnchorEncodingInvalid)?;
            if removed.contains(&fact.occurrence_id) {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

fn compare_line_with_pattern(
    model: &NormalizedModel,
    line_index: usize,
    digest: &[u8; 32],
    pattern: &[u8],
) -> Ordering {
    let line = &model.lines[line_index];
    line.digest
        .cmp(digest)
        .then_with(|| line_bytes(model, line_index).len().cmp(&pattern.len()))
        .then_with(|| line_bytes(model, line_index).cmp(pattern))
}

fn oids_in_line_range(
    model: &NormalizedModel,
    facts: &[TokenFact],
    start: usize,
    end: usize,
) -> Result<Vec<[u8; 16]>> {
    let lines = model
        .lines
        .get(start..end)
        .ok_or(Error::AnchorEncodingInvalid)?;
    let token_count = lines.iter().try_fold(0usize, |total, line| {
        resource_add(total, line.token_count as usize)
    })?;
    let mut output = Vec::new();
    reserve_exact(&mut output, token_count)?;
    for line in lines {
        for atom in line_atoms(model, line)? {
            if let AtomRecord::Token { occurrence } = *atom {
                output.push(
                    facts
                        .get(
                            usize::try_from(occurrence)
                                .map_err(|_| Error::AnchorEncodingInvalid)?,
                        )
                        .ok_or(Error::AnchorEncodingInvalid)?
                        .occurrence_id,
                );
            }
        }
    }
    Ok(output)
}

fn projected_line(
    source: &[u8],
    model: &NormalizedModel,
    facts: &[TokenFact],
    line_index: usize,
    removed: &BTreeSet<[u8; 16]>,
) -> Result<Vec<u8>> {
    let line = model
        .lines
        .get(line_index)
        .ok_or(Error::AnchorEncodingInvalid)?;
    let atoms = line_atoms(model, line)?;
    let mut atom_count = 0usize;
    let mut projected_len = size_of::<u32>();
    let mut byte_group_open = false;
    for atom in atoms {
        match *atom {
            AtomRecord::Bytes { start, end } => {
                if !byte_group_open {
                    atom_count = resource_add(atom_count, 1)?;
                    projected_len = resource_add(projected_len, 1 + size_of::<u32>())?;
                }
                projected_len =
                    resource_add(projected_len, source_span(source, start, end)?.len())?;
                byte_group_open = true;
            }
            AtomRecord::Token { occurrence } => {
                let fact = facts
                    .get(usize::try_from(occurrence).map_err(|_| Error::AnchorEncodingInvalid)?)
                    .ok_or(Error::AnchorEncodingInvalid)?;
                if !removed.contains(&fact.occurrence_id) {
                    atom_count = resource_add(atom_count, 1)?;
                    projected_len = resource_add(projected_len, 2)?;
                    byte_group_open = false;
                }
            }
        }
    }
    let empty_projection = atom_count == 0;
    if atom_count == 0 {
        atom_count = 1;
        projected_len = resource_add(projected_len, 1 + size_of::<u32>())?;
    }
    let mut output = Vec::new();
    reserve_exact(&mut output, projected_len)?;
    push_context_u32(&mut output, atom_count)?;
    let mut index = 0usize;
    while index < atoms.len() {
        match atoms[index] {
            AtomRecord::Token { occurrence } => {
                let fact = facts
                    .get(usize::try_from(occurrence).map_err(|_| Error::AnchorEncodingInvalid)?)
                    .ok_or(Error::AnchorEncodingInvalid)?;
                index += 1;
                if !removed.contains(&fact.occurrence_id) {
                    push_context_byte(&mut output, 1)?;
                    push_context_byte(&mut output, fact.category as u8)?;
                }
            }
            AtomRecord::Bytes { .. } => {
                let group_start = index;
                let mut byte_len = 0usize;
                while index < atoms.len() {
                    match atoms[index] {
                        AtomRecord::Bytes { start, end } => {
                            byte_len =
                                resource_add(byte_len, source_span(source, start, end)?.len())?;
                            index += 1;
                        }
                        AtomRecord::Token { occurrence } => {
                            let fact = facts
                                .get(
                                    usize::try_from(occurrence)
                                        .map_err(|_| Error::AnchorEncodingInvalid)?,
                                )
                                .ok_or(Error::AnchorEncodingInvalid)?;
                            if !removed.contains(&fact.occurrence_id) {
                                break;
                            }
                            index += 1;
                        }
                    }
                }
                push_context_byte(&mut output, 0)?;
                push_context_u32(&mut output, byte_len)?;
                for atom in &atoms[group_start..index] {
                    if let AtomRecord::Bytes { start, end } = *atom {
                        push_context_bytes(&mut output, source_span(source, start, end)?)?;
                    }
                }
            }
        }
    }
    if empty_projection {
        push_context_byte(&mut output, 0)?;
        push_context_u32(&mut output, 0)?;
    }
    if output.len() != projected_len {
        return Err(Error::AnchorEncodingInvalid);
    }
    require_context_byte_count(output.len())?;
    Ok(output)
}

fn require_current_profile(profile: ReviewProfile) -> Result<()> {
    if profile.is_current() {
        Ok(())
    } else {
        Err(Error::AnchorEncodingInvalid)
    }
}

fn validate_static_resource_model() -> Result<()> {
    if architecture_modeled_max_work()? > MAX_ANCHOR_SCAN_WORK_PER_FILE
        || conservative_max_work()? > MAX_ANCHOR_SCAN_WORK_PER_FILE
        || maximum_temporary_memory_bytes()? > MAX_ANCHOR_TEMP_BYTES_PER_FILE
    {
        Err(Error::AnchorResourceLimitExceeded)
    } else {
        Ok(())
    }
}

fn validate_inputs(
    canonical_original_path: &[u8],
    bytes: &[u8],
    occurrences: &[DetectedContentOccurrence],
) -> Result<()> {
    if canonical_original_path.is_empty() {
        return Err(Error::AnchorEncodingInvalid);
    }
    let logical_lines = logical_line_count(bytes)?;
    require_resource_dimensions(bytes.len(), logical_lines, occurrences.len())?;
    let mut previous_end = 0usize;
    for (index, occurrence) in occurrences.iter().enumerate() {
        if occurrence.start >= occurrence.end
            || occurrence.end > bytes.len()
            || occurrence.start < previous_end
            || usize::try_from(occurrence.ordinal).ok() != Some(index)
            || occurrence.category_bits == 0
        {
            return Err(Error::AnchorEncodingInvalid);
        }
        previous_end = occurrence.end;
    }
    Ok(())
}

fn require_resource_dimensions(
    file_bytes: usize,
    logical_lines: usize,
    tokens: usize,
) -> Result<()> {
    if file_bytes > MAX_FILE_BYTES
        || logical_lines > MAX_LOGICAL_LINES_PER_TOKEN_FILE
        || tokens > MAX_TOKENS_PER_FILE
    {
        return Err(Error::AnchorResourceLimitExceeded);
    }
    Ok(())
}

fn logical_line_count(bytes: &[u8]) -> Result<usize> {
    let lf = bytes.iter().try_fold(0usize, |count, byte| {
        if *byte == b'\n' {
            resource_add(count, 1)
        } else {
            Ok(count)
        }
    })?;
    if bytes.is_empty() || bytes.last() != Some(&b'\n') {
        resource_add(lf, 1)
    } else {
        Ok(lf)
    }
}

#[derive(Clone, Copy)]
struct ModelCapacities {
    source_lines: usize,
    atoms: usize,
    canonical: usize,
}

fn model_capacities(
    bytes_len: usize,
    source_lines: usize,
    occurrences: usize,
) -> Result<ModelCapacities> {
    let atoms = source_lines
        .checked_add(
            occurrences
                .checked_mul(2)
                .ok_or(Error::AnchorResourceLimitExceeded)?,
        )
        .and_then(|value| value.checked_add(1))
        .ok_or(Error::AnchorResourceLimitExceeded)?;
    let canonical = bytes_len
        .checked_add(
            source_lines
                .checked_mul(9)
                .ok_or(Error::AnchorResourceLimitExceeded)?,
        )
        .and_then(|value| value.checked_add(occurrences.checked_mul(7)?))
        .ok_or(Error::AnchorResourceLimitExceeded)?;
    if canonical > MAX_CONTEXT_BYTES {
        return Err(Error::AnchorResourceLimitExceeded);
    }
    Ok(ModelCapacities {
        source_lines,
        atoms,
        canonical,
    })
}

fn build_normalized_model(
    schedule: &KeySchedule<'_>,
    bytes: &[u8],
    occurrences: &[DetectedContentOccurrence],
    account: &mut ResourceAccount,
) -> Result<NormalizedModel> {
    let source_lines = logical_line_count(bytes)?;
    let capacities = model_capacities(bytes.len(), source_lines, occurrences.len())?;
    let mut builder = ModelBuilder::new(
        schedule,
        capacities.source_lines,
        capacities.atoms,
        capacities.canonical,
    )?;
    let mut cursor = 0usize;
    for (index, occurrence) in occurrences.iter().enumerate() {
        builder.push_source_bytes(bytes, occurrences, cursor, occurrence.start)?;
        builder.push_token(index)?;
        cursor = occurrence.end;
    }
    builder.push_source_bytes(bytes, occurrences, cursor, bytes.len())?;
    let mut model = builder.finish(bytes, occurrences)?;
    if model.lines.len() > MAX_LOGICAL_LINES_PER_TOKEN_FILE
        || model.canonical_lines.len() > MAX_CONTEXT_BYTES
    {
        return Err(Error::AnchorResourceLimitExceeded);
    }

    account.charge_work(model.lines.len())?;
    account.charge_work(occurrences.len())?;
    account.charge_work(ordering_work(model.lines.len())?)?;
    assign_line_ranks(&mut model)?;
    let mut prefix = Vec::new();
    reserve_exact(&mut prefix, resource_add(model.lines.len(), 1)?)?;
    prefix.push(0usize);
    for line in &model.lines {
        let length = usize::try_from(line.canonical_end - line.canonical_start)
            .map_err(|_| Error::AnchorEncodingInvalid)?;
        let part = resource_add(1, length)?;
        let next = resource_add(*prefix.last().ok_or(Error::AnchorEncodingInvalid)?, part)?;
        prefix.push(next);
    }
    model.line_part_prefix = prefix;
    Ok(model)
}

struct ModelBuilder<'schedule, 'master> {
    schedule: &'schedule KeySchedule<'master>,
    atoms: Vec<AtomRecord>,
    lines: Vec<LineRecord>,
    canonical_lines: Vec<u8>,
    current_atom_start: usize,
}

impl<'schedule, 'master> ModelBuilder<'schedule, 'master> {
    fn new(
        schedule: &'schedule KeySchedule<'master>,
        line_capacity: usize,
        atom_capacity: usize,
        canonical_capacity: usize,
    ) -> Result<Self> {
        let mut atoms = Vec::new();
        reserve_exact(&mut atoms, atom_capacity)?;
        let mut lines = Vec::new();
        reserve_exact(&mut lines, line_capacity)?;
        let mut canonical_lines = Vec::new();
        reserve_exact(&mut canonical_lines, canonical_capacity)?;
        Ok(Self {
            schedule,
            atoms,
            lines,
            canonical_lines,
            current_atom_start: 0,
        })
    }

    fn push_source_bytes(
        &mut self,
        bytes: &[u8],
        occurrences: &[DetectedContentOccurrence],
        start: usize,
        end: usize,
    ) -> Result<()> {
        if start > end || end > bytes.len() {
            return Err(Error::AnchorEncodingInvalid);
        }
        let mut segment = start;
        for index in start..end {
            if bytes[index] == b'\n' {
                let after_lf = resource_add(index, 1)?;
                self.push_byte_atom(segment, after_lf)?;
                self.finish_line(bytes, occurrences)?;
                segment = after_lf;
            }
        }
        if segment < end {
            self.push_byte_atom(segment, end)?;
        }
        Ok(())
    }

    fn push_byte_atom(&mut self, start: usize, end: usize) -> Result<()> {
        if start > end {
            return Err(Error::AnchorEncodingInvalid);
        }
        self.atoms.push(AtomRecord::Bytes {
            start: to_u32(start)?,
            end: to_u32(end)?,
        });
        Ok(())
    }

    fn push_token(&mut self, occurrence: usize) -> Result<()> {
        self.atoms.push(AtomRecord::Token {
            occurrence: to_u32(occurrence)?,
        });
        Ok(())
    }

    fn finish(
        mut self,
        bytes: &[u8],
        occurrences: &[DetectedContentOccurrence],
    ) -> Result<NormalizedModel> {
        if self.current_atom_start < self.atoms.len() {
            self.finish_line(bytes, occurrences)?;
        } else if self.lines.is_empty() {
            self.push_byte_atom(0, 0)?;
            self.finish_line(bytes, occurrences)?;
        }
        Ok(NormalizedModel {
            atoms: self.atoms,
            lines: self.lines,
            canonical_lines: self.canonical_lines,
            line_ranks: Vec::new(),
            line_part_prefix: Vec::new(),
        })
    }

    fn finish_line(
        &mut self,
        bytes: &[u8],
        occurrences: &[DetectedContentOccurrence],
    ) -> Result<()> {
        let atom_end = self.atoms.len();
        let atoms = self
            .atoms
            .get(self.current_atom_start..atom_end)
            .ok_or(Error::AnchorEncodingInvalid)?;
        if atoms.is_empty() {
            return Err(Error::AnchorEncodingInvalid);
        }
        let canonical_start = self.canonical_lines.len();
        push_context_u32(&mut self.canonical_lines, atoms.len())?;
        let mut token_count = 0usize;
        for atom in atoms {
            match *atom {
                AtomRecord::Bytes { start, end } => {
                    let start = usize::try_from(start).map_err(|_| Error::AnchorEncodingInvalid)?;
                    let end = usize::try_from(end).map_err(|_| Error::AnchorEncodingInvalid)?;
                    let value = bytes.get(start..end).ok_or(Error::AnchorEncodingInvalid)?;
                    push_context_byte(&mut self.canonical_lines, 0)?;
                    push_context_u32(&mut self.canonical_lines, value.len())?;
                    push_context_bytes(&mut self.canonical_lines, value)?;
                }
                AtomRecord::Token { occurrence } => {
                    let occurrence =
                        usize::try_from(occurrence).map_err(|_| Error::AnchorEncodingInvalid)?;
                    let category = occurrences
                        .get(occurrence)
                        .ok_or(Error::AnchorEncodingInvalid)?
                        .category;
                    push_context_byte(&mut self.canonical_lines, 1)?;
                    push_context_byte(&mut self.canonical_lines, category as u8)?;
                    token_count = resource_add(token_count, 1)?;
                }
            }
        }
        let canonical_end = self.canonical_lines.len();
        let digest = transient_digest(
            self.schedule,
            RANKED_LINE_DOMAIN,
            self.canonical_lines
                .get(canonical_start..canonical_end)
                .ok_or(Error::AnchorEncodingInvalid)?,
        )?;
        self.lines.push(LineRecord {
            atom_start: to_u32(self.current_atom_start)?,
            atom_end: to_u32(atom_end)?,
            canonical_start: to_u32(canonical_start)?,
            canonical_end: to_u32(canonical_end)?,
            token_count: to_u32(token_count)?,
            digest,
        });
        self.current_atom_start = atom_end;
        Ok(())
    }
}

fn assign_line_ranks(model: &mut NormalizedModel) -> Result<()> {
    let mut order = fallible_indices(model.lines.len())?;
    order.sort_unstable_by(|left, right| compare_lines(model, *left, *right));
    let mut ranks = allocate_filled(model.lines.len(), 0u32)?;
    let mut rank = 0u32;
    let mut prior = None;
    for index in order {
        if prior.is_some_and(|prior| !line_equal(model, prior, index)) {
            rank = rank
                .checked_add(1)
                .ok_or(Error::AnchorResourceLimitExceeded)?;
        }
        ranks[index] = rank;
        prior = Some(index);
    }
    model.line_ranks = ranks;
    Ok(())
}

fn compare_lines(model: &NormalizedModel, left: usize, right: usize) -> Ordering {
    let left_line = &model.lines[left];
    let right_line = &model.lines[right];
    left_line
        .digest
        .cmp(&right_line.digest)
        .then_with(|| {
            line_bytes(model, left)
                .len()
                .cmp(&line_bytes(model, right).len())
        })
        .then_with(|| line_bytes(model, left).cmp(line_bytes(model, right)))
}

fn line_equal(model: &NormalizedModel, left: usize, right: usize) -> bool {
    let left_line = &model.lines[left];
    let right_line = &model.lines[right];
    left_line.digest == right_line.digest && line_bytes(model, left) == line_bytes(model, right)
}

fn line_bytes(model: &NormalizedModel, index: usize) -> &[u8] {
    let line = &model.lines[index];
    &model.canonical_lines[line.canonical_start as usize..line.canonical_end as usize]
}

fn discover_runs(
    schedule: &KeySchedule<'_>,
    model: &NormalizedModel,
    occurrences: &[DetectedContentOccurrence],
    account: &mut ResourceAccount,
) -> Result<Vec<ProtectedRun>> {
    let mut runs = Vec::new();
    reserve_exact(&mut runs, occurrences.len())?;
    let mut line = 0usize;
    let mut next_occurrence = 0usize;
    while line < model.lines.len() {
        if model.lines[line].token_count == 0 {
            line += 1;
            continue;
        }
        let first_line = line;
        let first_occurrence = next_occurrence;
        while line < model.lines.len() && model.lines[line].token_count != 0 {
            next_occurrence = resource_add(
                next_occurrence,
                usize::try_from(model.lines[line].token_count)
                    .map_err(|_| Error::AnchorEncodingInvalid)?,
            )?;
            line += 1;
        }
        let last_line = line - 1;
        let occurrence_count = next_occurrence
            .checked_sub(first_occurrence)
            .ok_or(Error::AnchorEncodingInvalid)?;
        let core_digest = core_digest(schedule, &model.line_ranks[first_line..=last_line])?;
        runs.push(ProtectedRun {
            first_line: to_u32(first_line)?,
            last_line: to_u32(last_line)?,
            first_occurrence: to_u32(first_occurrence)?,
            occurrence_count: to_u32(occurrence_count)?,
            core_rank: 0,
            core_digest,
        });
    }
    if next_occurrence != occurrences.len() || runs.is_empty() {
        return Err(Error::AnchorEncodingInvalid);
    }
    account.charge_work(ordering_work(runs.len())?)?;
    assign_core_ranks(model, &mut runs)?;
    Ok(runs)
}

fn assign_core_ranks(model: &NormalizedModel, runs: &mut [ProtectedRun]) -> Result<()> {
    let mut order = fallible_indices(runs.len())?;
    order.sort_unstable_by(|left, right| compare_cores(model, &runs[*left], &runs[*right]));
    let mut rank = 0u32;
    let mut prior = None;
    for index in order {
        if prior.is_some_and(|prior| !core_equal(model, &runs[prior], &runs[index])) {
            rank = rank
                .checked_add(1)
                .ok_or(Error::AnchorResourceLimitExceeded)?;
        }
        runs[index].core_rank = rank;
        prior = Some(index);
    }
    Ok(())
}

fn compare_cores(model: &NormalizedModel, left: &ProtectedRun, right: &ProtectedRun) -> Ordering {
    left.core_digest
        .cmp(&right.core_digest)
        .then_with(|| {
            core_ranks(model, left)
                .len()
                .cmp(&core_ranks(model, right).len())
        })
        .then_with(|| core_ranks(model, left).cmp(core_ranks(model, right)))
}

fn core_equal(model: &NormalizedModel, left: &ProtectedRun, right: &ProtectedRun) -> bool {
    left.core_digest == right.core_digest && core_ranks(model, left) == core_ranks(model, right)
}

fn core_ranks<'a>(model: &'a NormalizedModel, run: &ProtectedRun) -> &'a [u32] {
    &model.line_ranks[run.first_line as usize..=run.last_line as usize]
}

fn core_digest(schedule: &KeySchedule<'_>, ranks: &[u32]) -> Result<[u8; 32]> {
    let mut stream = HmacStream::new(schedule, KeyPurpose::AnchorCommit)?;
    stream.update(RANKED_CORE_DOMAIN);
    stream.update(&to_u32(ranks.len())?.to_le_bytes());
    for rank in ranks {
        stream.update(&rank.to_le_bytes());
    }
    Ok(stream.finish())
}

fn select_unique_radii(
    model: &NormalizedModel,
    runs: &[ProtectedRun],
    account: &mut ResourceAccount,
) -> Result<Vec<u8>> {
    let mut selected = allocate_filled(runs.len(), 0u8)?;
    let mut prior_ranks = Vec::new();
    reserve_exact(&mut prior_ranks, runs.len())?;
    for run in runs {
        prior_ranks.push(run.core_rank);
    }
    let mut unresolved = runs.len();
    for radius in 1..=MAX_CONTEXT_LINES_PER_SIDE {
        account.charge_windows(runs.len())?;
        account.charge_work(runs.len())?;
        account.charge_work(ordering_work(runs.len())?)?;
        let mut candidates = Vec::new();
        reserve_exact(&mut candidates, runs.len())?;
        for (index, run) in runs.iter().enumerate() {
            require_context_size(model, run, radius)?;
            candidates.push(WindowCandidate {
                key: WindowKey {
                    inner_rank: prior_ranks[index],
                    left: left_boundary(model, run, radius)?,
                    right: right_boundary(model, run, radius)?,
                },
                run_index: to_u32(index)?,
            });
        }
        candidates.sort_unstable_by_key(|candidate| candidate.key);
        let mut next_ranks = allocate_filled(runs.len(), 0u32)?;
        let mut group_start = 0usize;
        let mut equality_rank = 0u32;
        while group_start < candidates.len() {
            let key = candidates[group_start].key;
            let mut group_end = resource_add(group_start, 1)?;
            while group_end < candidates.len() && candidates[group_end].key == key {
                group_end += 1;
            }
            for candidate in &candidates[group_start..group_end] {
                let run_index = usize::try_from(candidate.run_index)
                    .map_err(|_| Error::AnchorEncodingInvalid)?;
                next_ranks[run_index] = equality_rank;
                if group_end - group_start == 1 && selected[run_index] == 0 {
                    selected[run_index] =
                        u8::try_from(radius).map_err(|_| Error::AnchorEncodingInvalid)?;
                    unresolved = unresolved
                        .checked_sub(1)
                        .ok_or(Error::AnchorEncodingInvalid)?;
                }
            }
            equality_rank = equality_rank
                .checked_add(1)
                .ok_or(Error::AnchorResourceLimitExceeded)?;
            group_start = group_end;
        }
        prior_ranks = next_ranks;
        if unresolved == 0 {
            return Ok(selected);
        }
    }
    Err(Error::AnchorAmbiguous)
}

fn left_boundary(
    model: &NormalizedModel,
    run: &ProtectedRun,
    radius: usize,
) -> Result<BoundaryRank> {
    let first = usize::try_from(run.first_line).map_err(|_| Error::AnchorEncodingInvalid)?;
    if first < radius {
        Ok(BoundaryRank { state: 0, rank: 0 })
    } else {
        Ok(BoundaryRank {
            state: 1,
            rank: *model
                .line_ranks
                .get(first - radius)
                .ok_or(Error::AnchorEncodingInvalid)?,
        })
    }
}

fn right_boundary(
    model: &NormalizedModel,
    run: &ProtectedRun,
    radius: usize,
) -> Result<BoundaryRank> {
    let last = usize::try_from(run.last_line).map_err(|_| Error::AnchorEncodingInvalid)?;
    let index = last
        .checked_add(radius)
        .ok_or(Error::AnchorResourceLimitExceeded)?;
    if index >= model.lines.len() {
        Ok(BoundaryRank { state: 2, rank: 0 })
    } else {
        Ok(BoundaryRank {
            state: 1,
            rank: *model
                .line_ranks
                .get(index)
                .ok_or(Error::AnchorEncodingInvalid)?,
        })
    }
}

fn require_context_size(
    model: &NormalizedModel,
    run: &ProtectedRun,
    radius: usize,
) -> Result<usize> {
    let layout = envelope_layout(model.lines.len(), run, radius)?;
    let left_bytes = prefix_range(&model.line_part_prefix, layout.left_start, layout.left_end)?;
    let core_bytes = prefix_range(&model.line_part_prefix, layout.core_start, layout.core_end)?;
    let right_bytes = prefix_range(
        &model.line_part_prefix,
        layout.right_start,
        layout.right_end,
    )?;
    let mut total = resource_add(RELATIVE_CONTEXT_PREFIX.len(), size_of::<u32>())?;
    total = resource_add(total, left_bytes)?;
    total = resource_add(total, core_bytes)?;
    total = resource_add(total, right_bytes)?;
    total = resource_add(total, usize::from(layout.bof))?;
    total = resource_add(total, usize::from(layout.eof))?;
    require_context_byte_count(total)
}

fn require_context_byte_count(total: usize) -> Result<usize> {
    if total > MAX_CONTEXT_BYTES {
        Err(Error::AnchorResourceLimitExceeded)
    } else {
        Ok(total)
    }
}

struct EnvelopeLayout {
    bof: bool,
    eof: bool,
    left_start: usize,
    left_end: usize,
    core_start: usize,
    core_end: usize,
    right_start: usize,
    right_end: usize,
    part_count: usize,
}

fn envelope_layout(line_count: usize, run: &ProtectedRun, radius: usize) -> Result<EnvelopeLayout> {
    if !(1..=MAX_CONTEXT_LINES_PER_SIDE).contains(&radius) {
        return Err(Error::AnchorEncodingInvalid);
    }
    let first = usize::try_from(run.first_line).map_err(|_| Error::AnchorEncodingInvalid)?;
    let last = usize::try_from(run.last_line).map_err(|_| Error::AnchorEncodingInvalid)?;
    if first > last || last >= line_count {
        return Err(Error::AnchorEncodingInvalid);
    }
    let left_start = first.saturating_sub(radius);
    let right_start = last.checked_add(1).ok_or(Error::AnchorEncodingInvalid)?;
    let right_end = resource_add(right_start, radius)?.min(line_count);
    let bof = first < radius;
    let eof = line_count
        .checked_sub(right_start)
        .ok_or(Error::AnchorEncodingInvalid)?
        < radius;
    let core_end = last.checked_add(1).ok_or(Error::AnchorEncodingInvalid)?;
    let part_count = usize::from(bof)
        .checked_add(first - left_start)
        .and_then(|value| value.checked_add(core_end - first))
        .and_then(|value| value.checked_add(right_end - right_start))
        .and_then(|value| value.checked_add(usize::from(eof)))
        .ok_or(Error::AnchorResourceLimitExceeded)?;
    Ok(EnvelopeLayout {
        bof,
        eof,
        left_start,
        left_end: first,
        core_start: first,
        core_end,
        right_start,
        right_end,
        part_count,
    })
}

fn prefix_range(prefix: &[usize], start: usize, end: usize) -> Result<usize> {
    prefix
        .get(end)
        .and_then(|end_value| {
            prefix
                .get(start)
                .and_then(|start_value| end_value.checked_sub(*start_value))
        })
        .ok_or(Error::AnchorEncodingInvalid)
}

#[allow(clippy::too_many_arguments)]
fn pre_token_commitment(
    schedule: &KeySchedule<'_>,
    profile: ReviewProfile,
    canonical_original_path: &[u8],
    source: &[u8],
    occurrences: &[DetectedContentOccurrence],
    model: &NormalizedModel,
    run: &ProtectedRun,
    radius: u8,
) -> Result<[u8; 32]> {
    let mut writer = AnchorMac::new(schedule, PRE_TOKEN_ANCHOR_DOMAIN)?;
    writer.u8(PROTECTED_ANCHOR_VERSION);
    writer.u8(RELATIVE_CONTEXT_VERSION);
    writer.bytes(ENGINE_VERSION.as_bytes())?;
    writer.bytes(POLICY_ID.as_bytes())?;
    writer.u8(profile as u8);
    writer.u8(REGULAR_CONTENT_ROLE);
    writer.bytes(canonical_original_path)?;
    writer.u8(radius);
    write_exact_core_pre(&mut writer, source, occurrences, model, run)?;
    write_envelope(&mut writer, model, run, usize::from(radius))?;
    Ok(writer.finish())
}

#[allow(clippy::too_many_arguments)]
fn final_anchor_commitment(
    schedule: &KeySchedule<'_>,
    profile: ReviewProfile,
    role: &ContentFileRole<'_>,
    source: &[u8],
    occurrences: &[DetectedContentOccurrence],
    facts: &[TokenFact],
    model: &NormalizedModel,
    run: &ProtectedRun,
    selected: SelectedRun,
) -> Result<[u8; 32]> {
    let mut writer = AnchorMac::new(schedule, FINAL_ANCHOR_DOMAIN)?;
    writer.u8(PROTECTED_ANCHOR_VERSION);
    writer.u8(RELATIVE_CONTEXT_VERSION);
    writer.bytes(ENGINE_VERSION.as_bytes())?;
    writer.bytes(POLICY_ID.as_bytes())?;
    writer.u8(profile as u8);
    writer.u8(REGULAR_CONTENT_ROLE);
    writer.u64(role.volume_serial);
    writer.raw(&role.file_id);
    writer.bytes(role.safe_canonical_path)?;
    writer.u8(selected.radius);
    writer.raw(&selected.pre_token_commitment);
    write_exact_core_final(&mut writer, source, occurrences, facts, model, run)?;
    let range = occurrence_range(run, occurrences.len())?;
    writer.u32(range.len())?;
    for index in range {
        let occurrence = &occurrences[index];
        let fact = &facts[index];
        writer.raw(&fact.occurrence_id);
        writer.u8(fact.category as u8);
        writer
            .u32(usize::try_from(occurrence.ordinal).map_err(|_| Error::AnchorEncodingInvalid)?)?;
    }
    write_envelope(&mut writer, model, run, usize::from(selected.radius))?;
    Ok(writer.finish())
}

fn write_exact_core_pre(
    writer: &mut AnchorMac,
    source: &[u8],
    occurrences: &[DetectedContentOccurrence],
    model: &NormalizedModel,
    run: &ProtectedRun,
) -> Result<()> {
    write_exact_core(writer, source, occurrences, &[], model, run, false)
}

fn write_exact_core_final(
    writer: &mut AnchorMac,
    source: &[u8],
    occurrences: &[DetectedContentOccurrence],
    facts: &[TokenFact],
    model: &NormalizedModel,
    run: &ProtectedRun,
) -> Result<()> {
    write_exact_core(writer, source, occurrences, facts, model, run, true)
}

fn write_exact_core(
    writer: &mut AnchorMac,
    source: &[u8],
    occurrences: &[DetectedContentOccurrence],
    facts: &[TokenFact],
    model: &NormalizedModel,
    run: &ProtectedRun,
    final_form: bool,
) -> Result<()> {
    let first = usize::try_from(run.first_line).map_err(|_| Error::AnchorEncodingInvalid)?;
    let last = usize::try_from(run.last_line).map_err(|_| Error::AnchorEncodingInvalid)?;
    writer.u32(resource_add(
        last.checked_sub(first)
            .ok_or(Error::AnchorEncodingInvalid)?,
        1,
    )?)?;
    for line_index in first..=last {
        let line = model
            .lines
            .get(line_index)
            .ok_or(Error::AnchorEncodingInvalid)?;
        let atoms = line_atoms(model, line)?;
        let skeleton_len = atoms.iter().try_fold(0usize, |length, atom| match atom {
            AtomRecord::Bytes { start, end } => resource_add(
                length,
                usize::try_from(end - start).map_err(|_| Error::AnchorEncodingInvalid)?,
            ),
            AtomRecord::Token { .. } => Ok(length),
        })?;
        writer.u32(skeleton_len)?;
        for atom in atoms {
            if let AtomRecord::Bytes { start, end } = *atom {
                writer.raw(source_span(source, start, end)?);
            }
        }
        writer.u32(usize::try_from(line.token_count).map_err(|_| Error::AnchorEncodingInvalid)?)?;
        let mut skeleton_offset = 0usize;
        for atom in atoms {
            match *atom {
                AtomRecord::Bytes { start, end } => {
                    skeleton_offset = resource_add(
                        skeleton_offset,
                        usize::try_from(end - start).map_err(|_| Error::AnchorEncodingInvalid)?,
                    )?;
                }
                AtomRecord::Token { occurrence } => {
                    let occurrence_index =
                        usize::try_from(occurrence).map_err(|_| Error::AnchorEncodingInvalid)?;
                    let detected = occurrences
                        .get(occurrence_index)
                        .ok_or(Error::AnchorEncodingInvalid)?;
                    writer.u32(skeleton_offset)?;
                    if final_form {
                        let fact = facts
                            .get(occurrence_index)
                            .ok_or(Error::AnchorEncodingInvalid)?;
                        writer.raw(&fact.occurrence_id);
                        writer.u8(fact.category as u8);
                        writer.u32(
                            usize::try_from(detected.ordinal)
                                .map_err(|_| Error::AnchorEncodingInvalid)?,
                        )?;
                    } else {
                        writer.u8(detected.category as u8);
                    }
                }
            }
        }
    }
    Ok(())
}

fn line_atoms<'a>(model: &'a NormalizedModel, line: &LineRecord) -> Result<&'a [AtomRecord]> {
    model
        .atoms
        .get(line.atom_start as usize..line.atom_end as usize)
        .ok_or(Error::AnchorEncodingInvalid)
}

fn source_span(source: &[u8], start: u32, end: u32) -> Result<&[u8]> {
    source
        .get(start as usize..end as usize)
        .ok_or(Error::AnchorEncodingInvalid)
}

fn occurrence_range(run: &ProtectedRun, occurrence_len: usize) -> Result<std::ops::Range<usize>> {
    let start = usize::try_from(run.first_occurrence).map_err(|_| Error::AnchorEncodingInvalid)?;
    let end = start
        .checked_add(
            usize::try_from(run.occurrence_count).map_err(|_| Error::AnchorEncodingInvalid)?,
        )
        .ok_or(Error::AnchorEncodingInvalid)?;
    if end > occurrence_len {
        Err(Error::AnchorEncodingInvalid)
    } else {
        Ok(start..end)
    }
}

fn write_envelope(
    writer: &mut AnchorMac,
    model: &NormalizedModel,
    run: &ProtectedRun,
    radius: usize,
) -> Result<()> {
    require_context_size(model, run, radius)?;
    let layout = envelope_layout(model.lines.len(), run, radius)?;
    writer.raw(RELATIVE_CONTEXT_PREFIX);
    writer.context_u32(layout.part_count)?;
    if layout.bof {
        writer.u8(0);
    }
    for index in layout.left_start..layout.left_end {
        writer.u8(2);
        writer.raw(line_bytes(model, index));
    }
    for index in layout.core_start..layout.core_end {
        writer.u8(3);
        writer.raw(line_bytes(model, index));
    }
    for index in layout.right_start..layout.right_end {
        writer.u8(2);
        writer.raw(line_bytes(model, index));
    }
    if layout.eof {
        writer.u8(1);
    }
    Ok(())
}

struct AnchorMac(HmacStream);

impl AnchorMac {
    fn new(schedule: &KeySchedule<'_>, domain: &[u8]) -> Result<Self> {
        let mut stream = HmacStream::new(schedule, KeyPurpose::AnchorCommit)?;
        stream.update(domain);
        Ok(Self(stream))
    }

    fn u8(&mut self, value: u8) {
        self.0.update(&[value]);
    }

    fn u32(&mut self, value: usize) -> Result<()> {
        self.0.update(&to_u32(value)?.to_le_bytes());
        Ok(())
    }

    fn context_u32(&mut self, value: usize) -> Result<()> {
        self.u32(value)
    }

    fn u64(&mut self, value: u64) {
        self.0.update(&value.to_le_bytes());
    }

    fn bytes(&mut self, value: &[u8]) -> Result<()> {
        self.u32(value.len())?;
        self.raw(value);
        Ok(())
    }

    fn raw(&mut self, value: &[u8]) {
        self.0.update(value);
    }

    fn finish(self) -> [u8; 32] {
        self.0.finish()
    }
}

fn transient_digest(schedule: &KeySchedule<'_>, domain: &[u8], value: &[u8]) -> Result<[u8; 32]> {
    let mut stream = HmacStream::new(schedule, KeyPurpose::AnchorCommit)?;
    stream.update(domain);
    stream.update(&to_u32(value.len())?.to_le_bytes());
    stream.update(value);
    Ok(stream.finish())
}

fn push_context_byte(output: &mut Vec<u8>, value: u8) -> Result<()> {
    push_context_bytes(output, &[value])
}

fn push_context_u32(output: &mut Vec<u8>, value: usize) -> Result<()> {
    push_context_bytes(output, &to_u32(value)?.to_le_bytes())
}

fn push_context_bytes(output: &mut Vec<u8>, value: &[u8]) -> Result<()> {
    let next = resource_add(output.len(), value.len())?;
    if next > MAX_CONTEXT_BYTES {
        return Err(Error::AnchorResourceLimitExceeded);
    }
    output
        .try_reserve_exact(value.len())
        .map_err(|_| Error::AnchorResourceLimitExceeded)?;
    output.extend_from_slice(value);
    Ok(())
}

fn reserve_exact<T>(value: &mut Vec<T>, additional: usize) -> Result<()> {
    value
        .try_reserve_exact(additional)
        .map_err(|_| Error::AnchorResourceLimitExceeded)
}

fn allocate_filled<T: Clone>(length: usize, value: T) -> Result<Vec<T>> {
    let mut output = Vec::new();
    reserve_exact(&mut output, length)?;
    output.resize(length, value);
    Ok(output)
}

fn fallible_indices(length: usize) -> Result<Vec<usize>> {
    let mut output = Vec::new();
    reserve_exact(&mut output, length)?;
    for index in 0..length {
        output.push(index);
    }
    Ok(output)
}

fn resource_add(left: usize, right: usize) -> Result<usize> {
    left.checked_add(right)
        .ok_or(Error::AnchorResourceLimitExceeded)
}

fn resource_mul(left: usize, right: usize) -> Result<usize> {
    left.checked_mul(right)
        .ok_or(Error::AnchorResourceLimitExceeded)
}

fn to_u32(value: usize) -> Result<u32> {
    u32::try_from(value).map_err(|_| Error::AnchorResourceLimitExceeded)
}

const fn ceil_log2(value: usize) -> usize {
    if value <= 1 {
        0
    } else {
        usize::BITS as usize - (value - 1).leading_zeros() as usize
    }
}

fn ordering_work(records: usize) -> Result<usize> {
    resource_mul(records, ceil_log2(records))
}

pub(crate) fn architecture_modeled_max_work() -> Result<usize> {
    let window_sort = resource_mul(
        resource_mul(MAX_CONTEXT_LINES_PER_SIDE, MAX_TOKENS_PER_FILE)?,
        ceil_log2(MAX_TOKENS_PER_FILE),
    )?;
    let windows = resource_mul(MAX_CONTEXT_LINES_PER_SIDE, MAX_TOKENS_PER_FILE)?;
    resource_add(
        resource_add(window_sort, windows)?,
        resource_add(MAX_LOGICAL_LINES_PER_TOKEN_FILE, MAX_TOKENS_PER_FILE)?,
    )
}

pub(crate) fn conservative_max_work() -> Result<usize> {
    let value = architecture_modeled_max_work()?;
    let value = resource_add(value, ordering_work(MAX_LOGICAL_LINES_PER_TOKEN_FILE)?)?;
    resource_add(value, ordering_work(MAX_TOKENS_PER_FILE)?)
}

/// Conservative peak requested-capacity ledger for the production one-file
/// path. It counts caller-held source/transformed payloads and all anchor
/// record arenas that can coexist; `sort_unstable` uses no heap scratch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct AnchorMemoryLedger {
    pub(crate) source_payload: usize,
    pub(crate) transformed_payload: usize,
    pub(crate) normalized_occurrences: usize,
    pub(crate) content_evidence: usize,
    pub(crate) normalized_atoms: usize,
    pub(crate) logical_line_records: usize,
    pub(crate) canonical_normalized_lines: usize,
    pub(crate) line_ranks: usize,
    pub(crate) line_prefix: usize,
    pub(crate) sort_indices: usize,
    pub(crate) protected_runs: usize,
    pub(crate) selected_runs: usize,
    pub(crate) occurrence_commitments: usize,
    pub(crate) token_facts: usize,
    pub(crate) window_candidates: usize,
    pub(crate) window_ranks: usize,
    pub(crate) final_anchor_facts: usize,
    pub(crate) sort_stack: usize,
}

impl AnchorMemoryLedger {
    pub(crate) fn total(self) -> Result<usize> {
        [
            self.source_payload,
            self.transformed_payload,
            self.normalized_occurrences,
            self.content_evidence,
            self.normalized_atoms,
            self.logical_line_records,
            self.canonical_normalized_lines,
            self.line_ranks,
            self.line_prefix,
            self.sort_indices,
            self.protected_runs,
            self.selected_runs,
            self.occurrence_commitments,
            self.token_facts,
            self.window_candidates,
            self.window_ranks,
            self.final_anchor_facts,
            self.sort_stack,
        ]
        .into_iter()
        .try_fold(0usize, resource_add)
    }
}

pub(crate) fn maximum_temporary_memory_ledger() -> Result<AnchorMemoryLedger> {
    let max_atoms = resource_add(
        resource_add(
            MAX_LOGICAL_LINES_PER_TOKEN_FILE,
            resource_mul(MAX_TOKENS_PER_FILE, 2)?,
        )?,
        1,
    )?;
    Ok(AnchorMemoryLedger {
        source_payload: MAX_FILE_BYTES,
        transformed_payload: MAX_FILE_BYTES,
        normalized_occurrences: resource_mul(
            MAX_TOKENS_PER_FILE,
            size_of::<DetectedContentOccurrence>(),
        )?,
        content_evidence: resource_mul(MAX_TOKENS_PER_FILE, size_of::<EvidenceRegion>())?,
        normalized_atoms: resource_mul(max_atoms, size_of::<AtomRecord>())?,
        logical_line_records: resource_mul(
            MAX_LOGICAL_LINES_PER_TOKEN_FILE,
            size_of::<LineRecord>(),
        )?,
        canonical_normalized_lines: MAX_CONTEXT_BYTES,
        line_ranks: resource_mul(MAX_LOGICAL_LINES_PER_TOKEN_FILE, size_of::<u32>())?,
        line_prefix: resource_mul(
            resource_add(MAX_LOGICAL_LINES_PER_TOKEN_FILE, 1)?,
            size_of::<usize>(),
        )?,
        sort_indices: resource_mul(MAX_LOGICAL_LINES_PER_TOKEN_FILE, size_of::<usize>())?,
        protected_runs: resource_mul(MAX_TOKENS_PER_FILE, size_of::<ProtectedRun>())?,
        selected_runs: resource_mul(MAX_TOKENS_PER_FILE, size_of::<SelectedRun>())?,
        occurrence_commitments: resource_mul(MAX_TOKENS_PER_FILE, size_of::<[u8; 32]>())?,
        token_facts: resource_mul(MAX_TOKENS_PER_FILE, size_of::<TokenFact>())?,
        window_candidates: resource_mul(MAX_TOKENS_PER_FILE, size_of::<WindowCandidate>())?,
        window_ranks: resource_mul(MAX_TOKENS_PER_FILE, resource_mul(size_of::<u32>(), 2)?)?,
        final_anchor_facts: resource_mul(MAX_TOKENS_PER_FILE, size_of::<ContentAnchorFact>())?,
        sort_stack: SORT_STACK_ALLOWANCE,
    })
}

pub(crate) fn maximum_temporary_memory_bytes() -> Result<usize> {
    maximum_temporary_memory_ledger()?.total()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::roundtrip::crypto::{SessionId, SessionMasterSecret};
    use crate::roundtrip::ruleset::ruleset_id;
    use crate::roundtrip::token::{
        authenticate_token, generate_token, parse_token, ComponentKind, EntryKind,
        OccurrenceDescriptor,
    };

    fn schedule<'a>(master: &'a SessionMasterSecret) -> KeySchedule<'a> {
        KeySchedule::new(master, SessionId::from_bytes([0x11; 16]))
    }

    fn occurrence(
        text: &str,
        needle: &str,
        category: TokenCategory,
        ordinal: u32,
        after: usize,
    ) -> DetectedContentOccurrence {
        let relative = text[after..].find(needle).expect("synthetic occurrence");
        let start = after + relative;
        DetectedContentOccurrence {
            start,
            end: start + needle.len(),
            category,
            ordinal,
            category_bits: 1u16 << ((category as u8) - 1),
        }
    }

    fn two_block_fixture(
        distinguishing_radius: Option<usize>,
        categories: [TokenCategory; 2],
    ) -> (String, Vec<DetectedContentOccurrence>) {
        let mut lines = Vec::new();
        let mut needles = Vec::new();
        for block in 0..2 {
            for distance in (1..=MAX_CONTEXT_LINES_PER_SIDE).rev() {
                if distinguishing_radius == Some(distance) {
                    lines.push(format!("left-{distance}-block-{block}"));
                } else {
                    lines.push(format!("left-{distance}-shared"));
                }
            }
            let needle = format!("OPAQUE{block}");
            lines.push(format!("credential = {needle}"));
            needles.push(needle);
            for distance in 1..=MAX_CONTEXT_LINES_PER_SIDE {
                lines.push(format!("right-{distance}-shared"));
            }
        }
        let text = format!("{}\n", lines.join("\n"));
        let mut occurrences = Vec::new();
        let mut cursor = 0usize;
        for (index, needle) in needles.iter().enumerate() {
            let item = occurrence(
                &text,
                needle,
                categories[index],
                u32::try_from(index).expect("small ordinal"),
                cursor,
            );
            cursor = item.end;
            occurrences.push(item);
        }
        (text, occurrences)
    }

    fn prepare_fixture(
        text: &str,
        occurrences: &[DetectedContentOccurrence],
    ) -> Result<PreparedContentAnchors> {
        let master = SessionMasterSecret::from_bytes([0x42; 32]);
        prepare_content_anchors(
            &schedule(&master),
            ReviewProfile::StandardV2,
            b"synthetic/anchor.txt",
            text.as_bytes(),
            occurrences.to_vec(),
        )
    }

    #[test]
    fn exact_context_encoding_covers_bof_eof_crlf_and_unterminated_lines() {
        let master = SessionMasterSecret::from_bytes([0x42; 32]);
        let schedule = schedule(&master);
        let text = "OPAQUE\r\nlast";
        let occurrences = [occurrence(text, "OPAQUE", TokenCategory::Secret, 0, 0)];
        let prepared = prepare_content_anchors(
            &schedule,
            ReviewProfile::StandardV2,
            b"synthetic/vector.txt",
            text.as_bytes(),
            occurrences.to_vec(),
        )
        .expect("prepare vector");
        assert_eq!(prepared.selected[0].radius, 1);
        let mut bytes = Vec::new();
        let mut writer = RecordingWriter(&mut bytes);
        write_envelope_recording(&mut writer, &prepared.model, &prepared.runs[0], 1)
            .expect("canonical envelope");
        assert_eq!(
            bytes,
            [
                RELATIVE_CONTEXT_PREFIX,
                &3u32.to_le_bytes(),
                &[0],
                &[
                    3,
                    2,
                    0,
                    0,
                    0,
                    1,
                    TokenCategory::Secret as u8,
                    0,
                    2,
                    0,
                    0,
                    0,
                    b'\r',
                    b'\n',
                ],
                &[2, 1, 0, 0, 0, 0, 4, 0, 0, 0, b'l', b'a', b's', b't'],
            ]
            .concat()
        );

        let eof_text = "before\r\nvalue=OPAQUE";
        let eof_occurrences = vec![occurrence(eof_text, "OPAQUE", TokenCategory::Secret, 0, 0)];
        let eof = prepare_content_anchors(
            &schedule,
            ReviewProfile::StandardV2,
            b"synthetic/eof.txt",
            eof_text.as_bytes(),
            eof_occurrences,
        )
        .expect("prepare EOF vector");
        let layout =
            envelope_layout(eof.model.lines.len(), &eof.runs[0], 1).expect("EOF envelope layout");
        assert!(!layout.bof);
        assert!(layout.eof);
        assert_eq!(layout.part_count, 3);
    }

    #[test]
    fn consecutive_token_lines_form_one_run_and_separated_tokens_form_another() {
        let text = concat!(
            "before\n",
            "first=OPAQUE0\n",
            "second=OPAQUE1\n",
            "separator\n",
            "third=OPAQUE2\n",
            "after\n"
        );
        let first = occurrence(text, "OPAQUE0", TokenCategory::Secret, 0, 0);
        let second = occurrence(text, "OPAQUE1", TokenCategory::Email, 1, first.end);
        let third = occurrence(text, "OPAQUE2", TokenCategory::Ip, 2, second.end);
        let prepared = prepare_fixture(text, &[first, second, third]).expect("multiple runs");
        assert_eq!(prepared.runs.len(), 2);
        assert_eq!(
            (
                prepared.runs[0].first_line,
                prepared.runs[0].last_line,
                prepared.runs[0].occurrence_count,
            ),
            (1, 2, 2)
        );
        assert_eq!(
            (
                prepared.runs[1].first_line,
                prepared.runs[1].last_line,
                prepared.runs[1].occurrence_count,
            ),
            (4, 4, 1)
        );
        assert!(prepared
            .selected
            .iter()
            .all(|selected| selected.radius == 1));
    }

    #[test]
    fn first_unique_radius_is_exact_at_1_2_5_and_16() {
        for radius in [1, 2, 5, 16] {
            let (text, occurrences) =
                two_block_fixture(Some(radius), [TokenCategory::Secret, TokenCategory::Secret]);
            let prepared = prepare_fixture(&text, &occurrences).expect("unique baseline");
            assert_eq!(
                prepared
                    .selected
                    .iter()
                    .map(|selected| usize::from(selected.radius))
                    .collect::<Vec<_>>(),
                vec![radius, radius]
            );
        }
    }

    #[test]
    fn radius_17_and_same_category_oid_independent_repetition_are_ambiguous() {
        let (text, occurrences) =
            two_block_fixture(None, [TokenCategory::Secret, TokenCategory::Secret]);
        let master = SessionMasterSecret::from_bytes([0x42; 32]);
        let schedule = schedule(&master);
        let hypothetical_oids = occurrences
            .iter()
            .map(|item| {
                let descriptor = OccurrenceDescriptor {
                    session_id: schedule.session_id(),
                    ruleset_id: ruleset_id(),
                    review_profile: ReviewProfile::StandardV2,
                    entry_kind: EntryKind::RegularFile,
                    canonical_original_relative_path: b"synthetic/anchor.txt",
                    component_index: 0,
                    component_kind: ComponentKind::Content,
                    byte_span_start: u64::try_from(item.start).expect("bounded start"),
                    byte_span_end: u64::try_from(item.end).expect("bounded end"),
                    category: item.category,
                    occurrence_ordinal_within_component: item.ordinal,
                    // A fixed hypothetical pre-token commitment demonstrates
                    // that span/ordinal would produce different eventual OIDs.
                    // Neither value is available to, or consumed by, the
                    // actual uniqueness selection below.
                    pre_token_anchor_commitment: [0x55; 32],
                };
                let token = generate_token(&schedule, &descriptor).expect("hypothetical token");
                *authenticate_token(&schedule, parse_token(&token).expect("parse token"))
                    .expect("authenticate token")
                    .occurrence_id()
            })
            .collect::<Vec<_>>();
        assert_ne!(hypothetical_oids[0], hypothetical_oids[1]);
        assert!(matches!(
            prepare_fixture(&text, &occurrences),
            Err(Error::AnchorAmbiguous)
        ));

        let mut lines = Vec::new();
        for block in 0..2 {
            lines.push(format!("outside-16-block-{block}"));
            for distance in (1..=16).rev() {
                lines.push(format!("shared-left-{distance}"));
            }
            lines.push(format!("credential = OPAQUE{block}"));
            for distance in 1..=16 {
                lines.push(format!("shared-right-{distance}"));
            }
        }
        let text = format!("{}\n", lines.join("\n"));
        let first = occurrence(&text, "OPAQUE0", TokenCategory::Secret, 0, 0);
        let second = occurrence(&text, "OPAQUE1", TokenCategory::Secret, 1, first.end);
        assert!(matches!(
            prepare_fixture(&text, &[first, second]),
            Err(Error::AnchorAmbiguous)
        ));
    }

    #[test]
    fn category_is_context_but_profile_and_oid_are_not_uniqueness_inputs() {
        let (text, occurrences) =
            two_block_fixture(None, [TokenCategory::Secret, TokenCategory::Email]);
        let master = SessionMasterSecret::from_bytes([0x42; 32]);
        let schedule = schedule(&master);
        let standard = prepare_content_anchors(
            &schedule,
            ReviewProfile::StandardV2,
            b"synthetic/category.txt",
            text.as_bytes(),
            occurrences.clone(),
        )
        .expect("category distinguishes context");
        let strict = prepare_content_anchors(
            &schedule,
            ReviewProfile::StrictTokenFilesV2,
            b"synthetic/category.txt",
            text.as_bytes(),
            occurrences,
        )
        .expect("strict chooses same radii");
        assert!(standard.selected.iter().all(|item| item.radius == 1));
        assert_eq!(
            standard
                .selected
                .iter()
                .map(|item| item.radius)
                .collect::<Vec<_>>(),
            strict
                .selected
                .iter()
                .map(|item| item.radius)
                .collect::<Vec<_>>()
        );
        assert_ne!(
            standard.occurrence_commitments, strict.occurrence_commitments,
            "profile is committed only after uniqueness selection"
        );
    }

    #[test]
    fn anchor_payload_has_no_absolute_line_or_file_offset_authority() {
        let master = SessionMasterSecret::from_bytes([0x42; 32]);
        let schedule = schedule(&master);
        let baseline = "far-away\ncontext-before\nvalue=OPAQUE\ncontext-after\n";
        let shifted = "inserted\nfar-away\ncontext-before\nvalue=OPAQUE\ncontext-after\n";
        let baseline_occurrence = occurrence(baseline, "OPAQUE", TokenCategory::Secret, 0, 0);
        let shifted_occurrence = occurrence(shifted, "OPAQUE", TokenCategory::Secret, 0, 0);
        let first = prepare_content_anchors(
            &schedule,
            ReviewProfile::StandardV2,
            b"synthetic/shift.txt",
            baseline.as_bytes(),
            vec![baseline_occurrence],
        )
        .expect("baseline");
        let second = prepare_content_anchors(
            &schedule,
            ReviewProfile::StandardV2,
            b"synthetic/shift.txt",
            shifted.as_bytes(),
            vec![shifted_occurrence],
        )
        .expect("shifted");
        assert_eq!(first.occurrence_commitments, second.occurrence_commitments);
        let facts = [TokenFact {
            category: TokenCategory::Secret,
            occurrence_id: [0x77; 16],
        }];
        let role = ContentFileRole {
            volume_serial: 7,
            file_id: [8; 16],
            safe_canonical_path: b"synthetic/shift.txt",
        };
        assert_eq!(
            finalize_content_anchors(
                &schedule,
                ReviewProfile::StandardV2,
                role,
                baseline.as_bytes(),
                &first,
                &facts,
            )
            .expect("first final"),
            finalize_content_anchors(
                &schedule,
                ReviewProfile::StandardV2,
                role,
                shifted.as_bytes(),
                &second,
                &facts,
            )
            .expect("second final")
        );
    }

    #[test]
    fn resource_boundaries_and_concrete_memory_ledger_are_exact() {
        let mut account = ResourceAccount::default();
        account
            .charge_windows(MAX_ANCHOR_WINDOWS_PER_FILE)
            .expect("exact windows");
        assert_eq!(
            account.charge_windows(1),
            Err(Error::AnchorResourceLimitExceeded)
        );
        let mut account = ResourceAccount::default();
        account
            .charge_work(MAX_ANCHOR_SCAN_WORK_PER_FILE)
            .expect("exact work");
        assert_eq!(
            account.charge_work(1),
            Err(Error::AnchorResourceLimitExceeded)
        );
        assert_eq!(architecture_modeled_max_work().expect("modeled"), 4_342_016);
        assert_eq!(conservative_max_work().expect("conservative"), 5_640_192);
        assert!(conservative_max_work().expect("work") <= MAX_ANCHOR_SCAN_WORK_PER_FILE);
        let ledger = maximum_temporary_memory_ledger().expect("memory ledger");
        let total = ledger.total().expect("ledger total");
        assert_eq!(total, 24_215_828);
        assert_eq!(maximum_temporary_memory_bytes(), Ok(total));
        assert!(total <= MAX_ANCHOR_TEMP_BYTES_PER_FILE, "ledger={total}");
        assert!(total > MAX_CONTEXT_BYTES);
        assert_eq!(
            require_edited_match_memory_bound(MAX_ANCHOR_TEMP_BYTES_PER_FILE),
            Ok(())
        );
        assert_eq!(
            require_edited_match_memory_bound(MAX_ANCHOR_TEMP_BYTES_PER_FILE + 1),
            Err(Error::AnchorResourceLimitExceeded)
        );
        assert_eq!(
            require_context_byte_count(MAX_CONTEXT_BYTES),
            Ok(MAX_CONTEXT_BYTES)
        );
        assert_eq!(
            require_context_byte_count(MAX_CONTEXT_BYTES + 1),
            Err(Error::AnchorResourceLimitExceeded)
        );
        assert_eq!(
            require_resource_dimensions(
                MAX_FILE_BYTES,
                MAX_LOGICAL_LINES_PER_TOKEN_FILE,
                MAX_TOKENS_PER_FILE,
            ),
            Ok(())
        );
        for dimensions in [
            (MAX_FILE_BYTES + 1, 1, 1),
            (1, MAX_LOGICAL_LINES_PER_TOKEN_FILE + 1, 1),
            (1, 1, MAX_TOKENS_PER_FILE + 1),
        ] {
            assert_eq!(
                require_resource_dimensions(dimensions.0, dimensions.1, dimensions.2),
                Err(Error::AnchorResourceLimitExceeded)
            );
        }
    }

    #[test]
    fn relative_anchor_commitment_golden_vectors_are_exact() {
        let master = SessionMasterSecret::from_bytes([0x42; 32]);
        let schedule = schedule(&master);
        let text = "before\r\napi_key = OPAQUE\nafter";
        let occurrences = vec![occurrence(text, "OPAQUE", TokenCategory::Secret, 0, 0)];
        let prepared = prepare_content_anchors(
            &schedule,
            ReviewProfile::StandardV2,
            b"synthetic/golden.txt",
            text.as_bytes(),
            occurrences,
        )
        .expect("prepare golden");
        assert_eq!(prepared.selected[0].radius, 1);
        let span_start = text.find("OPAQUE").expect("golden span");
        let descriptor = OccurrenceDescriptor {
            session_id: schedule.session_id(),
            ruleset_id: ruleset_id(),
            review_profile: ReviewProfile::StandardV2,
            entry_kind: EntryKind::RegularFile,
            canonical_original_relative_path: b"synthetic/golden.txt",
            component_index: 0,
            component_kind: ComponentKind::Content,
            byte_span_start: u64::try_from(span_start).expect("bounded span"),
            byte_span_end: u64::try_from(span_start + "OPAQUE".len()).expect("bounded span"),
            category: TokenCategory::Secret,
            occurrence_ordinal_within_component: 0,
            pre_token_anchor_commitment: prepared.occurrence_commitments[0],
        };
        let token = generate_token(&schedule, &descriptor).expect("golden token");
        let authenticated =
            authenticate_token(&schedule, parse_token(&token).expect("parse golden token"))
                .expect("authenticate golden token");
        let facts = [TokenFact {
            category: TokenCategory::Secret,
            occurrence_id: *authenticated.occurrence_id(),
        }];
        let anchors = finalize_content_anchors(
            &schedule,
            ReviewProfile::StandardV2,
            ContentFileRole {
                volume_serial: 7,
                file_id: [8; 16],
                safe_canonical_path: b"synthetic/golden.txt",
            },
            text.as_bytes(),
            &prepared,
            &facts,
        )
        .expect("finalize golden");
        assert_eq!(anchors.len(), 1);
        assert_eq!(
            vector_hex(&anchors[0].pre_token_anchor_commitment),
            "393172dfc4916195d84ede7a1165e3d13405cd287361feeaa9b27afc1749557f"
        );
        assert_eq!(
            vector_hex(authenticated.occurrence_id()),
            "968f76db982ad8c1da54409ffe660e2e"
        );
        assert_eq!(
            token,
            "__SAFECLONE_RT1_SECRET_CEIRCEIRCEIRCEIRCEIRCEIRCE_S2HXNW4YFLMMDWSUICP74ZQOFY_HUSRPCGNYM3Z3FII4W4OX3NZYU__"
        );
        assert_eq!(
            vector_hex(&anchors[0].final_anchor_commitment),
            "73db032f66f94411f1c54a47ec8606ebd638f5cb734baae7dd802eef7079b48c"
        );
    }

    fn production_classifier_fixture() -> (
        SessionMasterSecret,
        BaselineContentTemplate,
        String,
        TokenFact,
    ) {
        let master = SessionMasterSecret::from_bytes([0x5a; 32]);
        let schedule = schedule(&master);
        let raw = concat!(
            "top-a\n",
            "top-b\n",
            "context-left\n",
            "credential=synthetic@example.invalid;\n",
            "context-right\n",
            "bottom-a\n",
            "bottom-b\n"
        );
        let detected = occurrence(raw, "synthetic@example.invalid", TokenCategory::Email, 0, 0);
        let prepared = prepare_content_anchors(
            &schedule,
            ReviewProfile::StandardV2,
            b"synthetic/production.txt",
            raw.as_bytes(),
            vec![detected],
        )
        .expect("prepare production baseline");
        let descriptor = OccurrenceDescriptor {
            session_id: schedule.session_id(),
            ruleset_id: ruleset_id(),
            review_profile: ReviewProfile::StandardV2,
            entry_kind: EntryKind::RegularFile,
            canonical_original_relative_path: b"synthetic/production.txt",
            component_index: 0,
            component_kind: ComponentKind::Content,
            byte_span_start: u64::try_from(detected.start).expect("small start"),
            byte_span_end: u64::try_from(detected.end).expect("small end"),
            category: TokenCategory::Email,
            occurrence_ordinal_within_component: 0,
            pre_token_anchor_commitment: prepared.occurrence_commitments[0],
        };
        let token = generate_token(&schedule, &descriptor).expect("generate production token");
        let parsed = authenticate_token(
            &schedule,
            parse_token(&token).expect("parse production token"),
        )
        .expect("authenticate production token");
        let fact = TokenFact {
            category: TokenCategory::Email,
            occurrence_id: *parsed.occurrence_id(),
        };
        let anchors = finalize_content_anchors(
            &schedule,
            ReviewProfile::StandardV2,
            ContentFileRole {
                volume_serial: 9,
                file_id: [0x44; 16],
                safe_canonical_path: b"synthetic/production.txt",
            },
            raw.as_bytes(),
            &prepared,
            &[fact],
        )
        .expect("finalize production baseline");
        let mut safe = raw.as_bytes()[..detected.start].to_vec();
        safe.extend_from_slice(token.as_bytes());
        safe.extend_from_slice(&raw.as_bytes()[detected.end..]);
        let span = ContentTokenSpan {
            start: detected.start,
            end: detected.start + token.len(),
            fact,
        };
        let template = build_baseline_content_template(&schedule, safe, &[span], &anchors)
            .expect("build production template");
        (master, template, token, fact)
    }

    fn edited_spans(text: &str, token: &str, fact: TokenFact) -> Vec<ContentTokenSpan> {
        text.match_indices(token)
            .map(|(start, value)| ContentTokenSpan {
                start,
                end: start + value.len(),
                fact,
            })
            .collect()
    }

    #[test]
    fn production_classifier_replays_absolute_shifts_and_workflows() {
        let (master, baseline, token, fact) = production_classifier_fixture();
        let schedule = schedule(&master);
        let baseline_text = format!(
            "top-a\ntop-b\ncontext-left\ncredential={token};\ncontext-right\nbottom-a\nbottom-b\n"
        );
        let baseline_spans = edited_spans(&baseline_text, &token, fact);
        assert!(
            edited_match_memory_upper_bound(&baseline, baseline_text.as_bytes(), &baseline_spans,)
                .expect("edited matcher memory ledger")
                <= MAX_ANCHOR_TEMP_BYTES_PER_FILE
        );
        let zero = BTreeSet::new();
        let mut old_absolute_shift_cases = 0usize;
        for count in 1..=60 {
            let prefix = (0..count)
                .map(|line| format!("ordinary-insert-{line}\n"))
                .collect::<String>();
            let edited = format!("{prefix}{baseline_text}");
            let outcome = classify_edited_content(
                &schedule,
                &baseline,
                edited.as_bytes(),
                &edited_spans(&edited, &token, fact),
                &zero,
            )
            .expect("classify absolute-shift replay");
            assert_eq!(
                outcome.outcome(&fact.occurrence_id),
                Some(EditedAnchorOutcome::Preserved)
            );
            old_absolute_shift_cases += 1;
        }
        let mut workflow_cases = 0usize;
        for bundle in 1..=7 {
            let edited = format!(
                "use synthetic_{bundle};\nfn helper_{bundle}() {{}}\n{baseline_text}\n// trailing edit {bundle}\n"
            );
            let outcome = classify_edited_content(
                &schedule,
                &baseline,
                edited.as_bytes(),
                &edited_spans(&edited, &token, fact),
                &zero,
            )
            .expect("classify workflow replay");
            assert_eq!(
                outcome.outcome(&fact.occurrence_id),
                Some(EditedAnchorOutcome::Preserved)
            );
            workflow_cases += 1;
        }
        assert_eq!(old_absolute_shift_cases, 60);
        assert_eq!(workflow_cases, 7);
    }

    #[test]
    fn production_classifier_distinguishes_relocation_context_core_ambiguity_and_deletion() {
        let (master, baseline, token, fact) = production_classifier_fixture();
        let schedule = schedule(&master);
        let zero = BTreeSet::new();
        let moved = format!(
            "top-a\ntop-b\nbottom-a\ncontext-left\ncredential={token};\ncontext-right\nbottom-b\n"
        );
        let moved_result = classify_edited_content(
            &schedule,
            &baseline,
            moved.as_bytes(),
            &edited_spans(&moved, &token, fact),
            &zero,
        )
        .expect("classify intact relocation");
        assert_eq!(
            moved_result.outcome(&fact.occurrence_id),
            Some(EditedAnchorOutcome::Preserved)
        );

        let changed_context = format!(
            "top-a\ntop-b\nchanged-left\ncredential={token};\ncontext-right\nbottom-a\nbottom-b\n"
        );
        let context_result = classify_edited_content(
            &schedule,
            &baseline,
            changed_context.as_bytes(),
            &edited_spans(&changed_context, &token, fact),
            &zero,
        )
        .expect("classify context change");
        assert_eq!(
            context_result.outcome(&fact.occurrence_id),
            Some(EditedAnchorOutcome::ProtectedContextChanged)
        );

        let changed_core = format!(
            "top-a\ntop-b\ncontext-left\ncredential= {token};\ncontext-right\nbottom-a\nbottom-b\n"
        );
        let core_result = classify_edited_content(
            &schedule,
            &baseline,
            changed_core.as_bytes(),
            &edited_spans(&changed_core, &token, fact),
            &zero,
        )
        .expect("classify core change");
        assert_eq!(
            core_result.outcome(&fact.occurrence_id),
            Some(EditedAnchorOutcome::ProtectedCoreChanged)
        );

        let duplicated = format!(
            "top-a\ncontext-left\ncredential={token};\ncontext-right\nmiddle\ncontext-left\ncredential={token};\ncontext-right\nbottom-b\n"
        );
        let ambiguous = classify_edited_content(
            &schedule,
            &baseline,
            duplicated.as_bytes(),
            &edited_spans(&duplicated, &token, fact),
            &zero,
        )
        .expect("classify repeated envelope");
        assert_eq!(
            ambiguous.outcome(&fact.occurrence_id),
            Some(EditedAnchorOutcome::AnchorAmbiguous)
        );

        let deleted =
            "top-a\ntop-b\ncontext-left\ncredential=;\ncontext-right\nbottom-a\nbottom-b\n";
        let missing = BTreeSet::from([fact.occurrence_id]);
        let deleted_result =
            classify_edited_content(&schedule, &baseline, deleted.as_bytes(), &[], &missing)
                .expect("classify exact deletion");
        assert_eq!(
            deleted_result.outcome(&fact.occurrence_id),
            Some(EditedAnchorOutcome::Deleted)
        );

        let deletion_plus_space =
            "top-a\ntop-b\ncontext-left\ncredential= ;\ncontext-right\nbottom-a\nbottom-b\n";
        let rejected_deletion = classify_edited_content(
            &schedule,
            &baseline,
            deletion_plus_space.as_bytes(),
            &[],
            &missing,
        )
        .expect("classify inexact deletion");
        assert_eq!(
            rejected_deletion.outcome(&fact.occurrence_id),
            Some(EditedAnchorOutcome::ProtectedCoreChanged)
        );
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

    struct RecordingWriter<'a>(&'a mut Vec<u8>);

    impl RecordingWriter<'_> {
        fn raw(&mut self, bytes: &[u8]) {
            self.0.extend_from_slice(bytes);
        }
        fn u8(&mut self, value: u8) {
            self.0.push(value);
        }
        fn u32(&mut self, value: usize) -> Result<()> {
            self.raw(&to_u32(value)?.to_le_bytes());
            Ok(())
        }
    }

    fn write_envelope_recording(
        writer: &mut RecordingWriter<'_>,
        model: &NormalizedModel,
        run: &ProtectedRun,
        radius: usize,
    ) -> Result<()> {
        require_context_size(model, run, radius)?;
        let layout = envelope_layout(model.lines.len(), run, radius)?;
        writer.raw(RELATIVE_CONTEXT_PREFIX);
        writer.u32(layout.part_count)?;
        if layout.bof {
            writer.u8(0);
        }
        for index in layout.left_start..layout.left_end {
            writer.u8(2);
            writer.raw(line_bytes(model, index));
        }
        for index in layout.core_start..layout.core_end {
            writer.u8(3);
            writer.raw(line_bytes(model, index));
        }
        for index in layout.right_start..layout.right_end {
            writer.u8(2);
            writer.raw(line_bytes(model, index));
        }
        if layout.eof {
            writer.u8(1);
        }
        Ok(())
    }
}
