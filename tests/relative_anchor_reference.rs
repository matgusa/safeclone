//! Independent bounded relative-context reference model.
#![allow(clippy::too_many_lines)]

#[path = "absolute_anchor_reference.rs"]
mod absolute_model;

use std::collections::{BTreeMap, BTreeSet};
use std::ops::Range;

use safeclone::roundtrip::token::{TokenCategory, TOKEN_PREFIX};

const MAX_FILE_BYTES: usize = 4 * 1024 * 1024;
const MAX_LOGICAL_LINES_PER_TOKEN_FILE: usize = 65_536;
const MAX_TOKENS_PER_FILE: usize = 16_640;
const MAX_CONTEXT_LINES_PER_SIDE: usize = 16;
const MAX_CONTEXT_BYTES: usize = 5 * 1024 * 1024;
const MAX_ANCHOR_WINDOWS_PER_FILE: usize = MAX_CONTEXT_LINES_PER_SIDE * MAX_TOKENS_PER_FILE;
const MAX_ANCHOR_SCAN_WORK_PER_FILE: usize = 8_388_608;
const MAX_ANCHOR_TEMP_BYTES_PER_FILE: usize = 32 * 1024 * 1024;
const CONTEXT_ENCODING_PREFIX: &[u8] = b"SAFECLONE-RELATIVE-CONTEXT-V1\0";

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum Outcome {
    Automatic,
    ApprovalRequiredDeletion,
    ProtectedContextChanged,
    ProtectedCoreChanged,
    AnchorAmbiguous,
    PathOrFileMovement,
    TokenStructure,
    RunOrderChanged,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProfileDecision {
    Automatic,
    ApprovalRequired,
    Reject,
}

impl Outcome {
    const ALL: [Self; 8] = [
        Self::Automatic,
        Self::ApprovalRequiredDeletion,
        Self::ProtectedContextChanged,
        Self::ProtectedCoreChanged,
        Self::AnchorAmbiguous,
        Self::PathOrFileMovement,
        Self::TokenStructure,
        Self::RunOrderChanged,
    ];

    const fn as_str(self) -> &'static str {
        match self {
            Self::Automatic => "PRESERVED_SAME_ANCHOR",
            Self::ApprovalRequiredDeletion => "TOKEN_DELETED_APPROVAL_REQUIRED",
            Self::ProtectedContextChanged => "PROTECTED_CONTEXT_CHANGED",
            Self::ProtectedCoreChanged => "PROTECTED_CORE_CHANGED",
            Self::AnchorAmbiguous => "ANCHOR_AMBIGUOUS",
            Self::PathOrFileMovement => "PATH_OR_FILE_MOVEMENT",
            Self::TokenStructure => "TOKEN_STRUCTURE_REJECT",
            Self::RunOrderChanged => "TOKEN_ORDER_CHANGED",
        }
    }
}

fn profile_decisions(
    standard_outcome: Outcome,
    surviving_token_file_changed: bool,
) -> (ProfileDecision, ProfileDecision) {
    if standard_outcome != Outcome::Automatic {
        return (ProfileDecision::Reject, ProfileDecision::Reject);
    }
    let strict = if surviving_token_file_changed {
        ProfileDecision::ApprovalRequired
    } else {
        ProfileDecision::Automatic
    };
    (ProfileDecision::Automatic, strict)
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum ShapeAtom {
    Bytes(Vec<u8>),
    TypedToken(TokenCategory),
}

type NormalizedLine = Vec<ShapeAtom>;

#[derive(Clone, Debug)]
struct Occurrence {
    token_index: usize,
    start: usize,
    end: usize,
    line_index: usize,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct TokenKey {
    oid: [u8; 16],
    category: TokenCategory,
    ordinal: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ExactBoundary {
    skeleton_offset: usize,
    token: TokenKey,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ExactProtectedLine {
    skeleton: Vec<u8>,
    boundaries: Vec<ExactBoundary>,
}

#[derive(Clone, Debug)]
struct Run {
    file_index: usize,
    file_id: String,
    safe_path: String,
    first_line: usize,
    last_line: usize,
    exact_lines: Vec<ExactProtectedLine>,
    normalized_core: Vec<NormalizedLine>,
    ordered: Vec<TokenKey>,
}

impl Run {
    fn oids(&self) -> Vec<[u8; 16]> {
        self.ordered.iter().map(|token| token.oid).collect()
    }

    fn exact_core_equals(&self, other: &Self) -> bool {
        self.exact_lines == other.exact_lines && self.ordered == other.ordered
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum EnvelopePart {
    Bof,
    Context(NormalizedLine),
    Core(NormalizedLine),
    Eof,
}

type Envelope = Vec<EnvelopePart>;

#[derive(Clone, Debug)]
struct SelectedAnchor {
    run: Run,
    radius: usize,
    envelope: Envelope,
}

#[derive(Clone, Debug, Default)]
struct ModelStats {
    logical_lines: usize,
    protected_runs: usize,
    windows: usize,
    canonical_context_bytes: usize,
}

fn logical_lines(bytes: &[u8]) -> Vec<Range<usize>> {
    let mut lines = Vec::new();
    let mut start = 0usize;
    for (index, byte) in bytes.iter().enumerate() {
        if *byte == b'\n' {
            lines.push(start..index + 1);
            start = index + 1;
        }
    }
    if start < bytes.len() || bytes.is_empty() {
        lines.push(start..bytes.len());
    }
    lines
}

fn byte_matches(haystack: &[u8], needle: &[u8]) -> Vec<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return Vec::new();
    }
    haystack
        .windows(needle.len())
        .enumerate()
        .filter_map(|(index, window)| (window == needle).then_some(index))
        .collect()
}

fn file_occurrences(
    file: &absolute_model::FileImage,
    tokens: &[absolute_model::TokenRecord],
) -> Vec<Occurrence> {
    let lines = logical_lines(&file.bytes);
    let mut output = Vec::new();
    for (token_index, token) in tokens.iter().enumerate() {
        for start in byte_matches(&file.bytes, token.canonical.as_bytes()) {
            let end = start + token.canonical.len();
            let line_index = lines
                .iter()
                .position(|line| start >= line.start && end <= line.end)
                .expect("synthetic canonical token remains within one logical line");
            output.push(Occurrence {
                token_index,
                start,
                end,
                line_index,
            });
        }
    }
    output.sort_by_key(|occurrence| (occurrence.start, occurrence.end, occurrence.token_index));
    output
}

fn normalized_line(
    file: &absolute_model::FileImage,
    line: &Range<usize>,
    occurrences: &[Occurrence],
    tokens: &[absolute_model::TokenRecord],
) -> NormalizedLine {
    let mut atoms = Vec::new();
    let mut cursor = line.start;
    for occurrence in occurrences
        .iter()
        .filter(|occurrence| occurrence.start >= line.start && occurrence.end <= line.end)
    {
        assert!(
            occurrence.start >= cursor,
            "synthetic token spans do not overlap"
        );
        if occurrence.start > cursor {
            atoms.push(ShapeAtom::Bytes(
                file.bytes[cursor..occurrence.start].to_vec(),
            ));
        }
        atoms.push(ShapeAtom::TypedToken(
            tokens[occurrence.token_index].category,
        ));
        cursor = occurrence.end;
    }
    if cursor < line.end || atoms.is_empty() {
        atoms.push(ShapeAtom::Bytes(file.bytes[cursor..line.end].to_vec()));
    }
    atoms
}

fn derive_runs(
    workspace: &absolute_model::Workspace,
    tokens: &[absolute_model::TokenRecord],
) -> Vec<Run> {
    let mut output = Vec::new();
    for (file_index, file) in workspace.iter().enumerate() {
        assert!(file.bytes.len() <= MAX_FILE_BYTES);
        let lines = logical_lines(&file.bytes);
        assert!(lines.len() <= MAX_LOGICAL_LINES_PER_TOKEN_FILE);
        let occurrences = file_occurrences(file, tokens);
        let token_lines: BTreeSet<usize> = occurrences.iter().map(|item| item.line_index).collect();
        let mut line_iter = token_lines.into_iter().peekable();
        while let Some(first) = line_iter.next() {
            let mut last = first;
            while line_iter.peek().is_some_and(|next| *next == last + 1) {
                last = line_iter.next().expect("peeked line exists");
            }
            let mut exact_lines = Vec::new();
            let mut normalized_core = Vec::new();
            let mut ordered = Vec::new();
            for (line_index, line) in lines.iter().enumerate().take(last + 1).skip(first) {
                let line_occurrences: Vec<&Occurrence> = occurrences
                    .iter()
                    .filter(|occurrence| occurrence.line_index == line_index)
                    .collect();
                let mut skeleton = Vec::new();
                let mut boundaries = Vec::new();
                let mut cursor = line.start;
                for occurrence in line_occurrences {
                    skeleton.extend_from_slice(&file.bytes[cursor..occurrence.start]);
                    let source = &tokens[occurrence.token_index];
                    let token = TokenKey {
                        oid: source.oid,
                        category: source.category,
                        ordinal: source.ordinal,
                    };
                    boundaries.push(ExactBoundary {
                        skeleton_offset: skeleton.len(),
                        token: token.clone(),
                    });
                    ordered.push(token);
                    cursor = occurrence.end;
                }
                skeleton.extend_from_slice(&file.bytes[cursor..line.end]);
                exact_lines.push(ExactProtectedLine {
                    skeleton,
                    boundaries,
                });
                normalized_core.push(normalized_line(file, line, &occurrences, tokens));
            }
            output.push(Run {
                file_index,
                file_id: file.file_id.clone(),
                safe_path: file.safe_path.clone(),
                first_line: first,
                last_line: last,
                exact_lines,
                normalized_core,
                ordered,
            });
        }
    }
    output.sort_by_key(|run| (run.file_index, run.first_line, run.last_line));
    output
}

fn envelope(
    workspace: &absolute_model::Workspace,
    tokens: &[absolute_model::TokenRecord],
    run: &Run,
    radius: usize,
) -> Envelope {
    assert!((1..=MAX_CONTEXT_LINES_PER_SIDE).contains(&radius));
    let file = &workspace[run.file_index];
    let lines = logical_lines(&file.bytes);
    let occurrences = file_occurrences(file, tokens);
    let mut output = Vec::new();
    let left_start = run.first_line.saturating_sub(radius);
    if run.first_line < radius {
        output.push(EnvelopePart::Bof);
    }
    for line in &lines[left_start..run.first_line] {
        output.push(EnvelopePart::Context(normalized_line(
            file,
            line,
            &occurrences,
            tokens,
        )));
    }
    output.extend(run.normalized_core.iter().cloned().map(EnvelopePart::Core));
    let right_start = run.last_line + 1;
    let right_end = right_start.saturating_add(radius).min(lines.len());
    for line in &lines[right_start..right_end] {
        output.push(EnvelopePart::Context(normalized_line(
            file,
            line,
            &occurrences,
            tokens,
        )));
    }
    if lines.len().saturating_sub(right_start) < radius {
        output.push(EnvelopePart::Eof);
    }
    output
}

fn push_u32(output: &mut Vec<u8>, value: usize) {
    output.extend_from_slice(
        &u32::try_from(value)
            .expect("bounded canonical context length")
            .to_le_bytes(),
    );
}

fn canonical_envelope(envelope: &Envelope) -> Vec<u8> {
    let mut output = Vec::new();
    output.extend_from_slice(CONTEXT_ENCODING_PREFIX);
    push_u32(&mut output, envelope.len());
    for part in envelope {
        output.push(match part {
            EnvelopePart::Bof => 0,
            EnvelopePart::Eof => 1,
            EnvelopePart::Context(_) => 2,
            EnvelopePart::Core(_) => 3,
        });
        let line = match part {
            EnvelopePart::Bof | EnvelopePart::Eof => continue,
            EnvelopePart::Context(line) | EnvelopePart::Core(line) => line,
        };
        push_u32(&mut output, line.len());
        for atom in line {
            match atom {
                ShapeAtom::Bytes(bytes) => {
                    output.push(0);
                    push_u32(&mut output, bytes.len());
                    output.extend_from_slice(bytes);
                }
                ShapeAtom::TypedToken(category) => {
                    output.push(1);
                    output.push(*category as u8);
                }
            }
        }
    }
    output
}

fn select_baseline_anchors(
    workspace: &absolute_model::Workspace,
    tokens: &[absolute_model::TokenRecord],
) -> Result<(Vec<SelectedAnchor>, ModelStats), Outcome> {
    let runs = derive_runs(workspace, tokens);
    let mut stats = ModelStats {
        logical_lines: workspace
            .iter()
            .map(|file| logical_lines(&file.bytes).len())
            .sum(),
        protected_runs: runs.len(),
        ..ModelStats::default()
    };
    let mut file_runs: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for (index, run) in runs.iter().enumerate() {
        file_runs.entry(run.file_index).or_default().push(index);
    }
    let mut file_windows = vec![0usize; workspace.len()];
    let mut selected: Vec<Option<SelectedAnchor>> = vec![None; runs.len()];
    for radius in 1..=MAX_CONTEXT_LINES_PER_SIDE {
        for (file_index, indexes) in &file_runs {
            file_windows[*file_index] = file_windows[*file_index]
                .checked_add(indexes.len())
                .ok_or(Outcome::AnchorAmbiguous)?;
            if file_windows[*file_index] > MAX_ANCHOR_WINDOWS_PER_FILE {
                return Err(Outcome::AnchorAmbiguous);
            }
            stats.windows = stats
                .windows
                .checked_add(indexes.len())
                .ok_or(Outcome::AnchorAmbiguous)?;
            let mut candidates = Vec::with_capacity(indexes.len());
            let mut counts: BTreeMap<Vec<u8>, usize> = BTreeMap::new();
            for index in indexes {
                let candidate = envelope(workspace, tokens, &runs[*index], radius);
                let canonical = canonical_envelope(&candidate);
                stats.canonical_context_bytes = stats.canonical_context_bytes.max(canonical.len());
                if canonical.len() > MAX_CONTEXT_BYTES {
                    return Err(Outcome::AnchorAmbiguous);
                }
                let count = counts.entry(canonical.clone()).or_default();
                *count = count.checked_add(1).ok_or(Outcome::AnchorAmbiguous)?;
                candidates.push((*index, candidate, canonical));
            }
            for (index, candidate, canonical) in candidates {
                if selected[index].is_none() && counts[&canonical] == 1 {
                    selected[index] = Some(SelectedAnchor {
                        run: runs[index].clone(),
                        radius,
                        envelope: candidate,
                    });
                }
            }
        }
        if selected.iter().all(Option::is_some) {
            break;
        }
    }
    let selected = selected
        .into_iter()
        .collect::<Option<Vec<_>>>()
        .ok_or(Outcome::AnchorAmbiguous)?;
    Ok((selected, stats))
}

fn flattened_order(runs: &[Run]) -> BTreeMap<(String, String), Vec<[u8; 16]>> {
    let mut output: BTreeMap<(String, String), Vec<[u8; 16]>> = BTreeMap::new();
    for run in runs {
        output
            .entry((run.file_id.clone(), run.safe_path.clone()))
            .or_default()
            .extend(run.ordered.iter().map(|token| token.oid));
    }
    output
}

fn evaluate_content(case: &absolute_model::ContentCase) -> Outcome {
    let reserved_introducers: usize = case
        .edited
        .iter()
        .map(|file| byte_matches(&file.bytes, TOKEN_PREFIX.as_bytes()).len())
        .sum();
    let known_occurrences: usize = case
        .tokens
        .iter()
        .map(|token| {
            case.edited
                .iter()
                .map(|file| byte_matches(&file.bytes, token.canonical.as_bytes()).len())
                .sum::<usize>()
        })
        .sum();
    if reserved_introducers != known_occurrences {
        return Outcome::TokenStructure;
    }
    for token in &case.tokens {
        let count: usize = case
            .edited
            .iter()
            .map(|file| byte_matches(&file.bytes, token.canonical.as_bytes()).len())
            .sum();
        if count != 1 {
            return Outcome::TokenStructure;
        }
    }
    let (baseline_anchors, _) = match select_baseline_anchors(&case.baseline, &case.tokens) {
        Ok(value) => value,
        Err(outcome) => return outcome,
    };
    let current_runs = derive_runs(&case.edited, &case.tokens);
    let mut current_by_oid = BTreeMap::new();
    for (index, run) in current_runs.iter().enumerate() {
        for oid in run.oids() {
            if current_by_oid.insert(oid, index).is_some() {
                return Outcome::TokenStructure;
            }
        }
    }
    for baseline in &baseline_anchors {
        let indexes: BTreeSet<usize> = baseline
            .run
            .oids()
            .iter()
            .filter_map(|oid| current_by_oid.get(oid).copied())
            .collect();
        if indexes.len() != 1 {
            return Outcome::ProtectedCoreChanged;
        }
        let current = &current_runs[*indexes.iter().next().expect("one current run")];
        if baseline.run.file_id != current.file_id || baseline.run.safe_path != current.safe_path {
            return Outcome::PathOrFileMovement;
        }
        if !baseline.run.exact_core_equals(current) {
            return Outcome::ProtectedCoreChanged;
        }
        let current_envelope = envelope(&case.edited, &case.tokens, current, baseline.radius);
        if current_envelope != baseline.envelope {
            return Outcome::ProtectedContextChanged;
        }
        let edited_count = current_runs
            .iter()
            .filter(|candidate| {
                candidate.file_index == current.file_index
                    && envelope(&case.edited, &case.tokens, candidate, baseline.radius)
                        == baseline.envelope
            })
            .count();
        if edited_count != 1 {
            return Outcome::AnchorAmbiguous;
        }
    }
    let baseline_runs: Vec<Run> = baseline_anchors
        .iter()
        .map(|anchor| anchor.run.clone())
        .collect();
    if flattened_order(&baseline_runs) != flattened_order(&current_runs) {
        return Outcome::RunOrderChanged;
    }
    Outcome::Automatic
}

fn image(
    file_id: &str,
    safe_path: &str,
    lines: &[String],
    crlf: bool,
    terminated: bool,
) -> absolute_model::FileImage {
    let separator = if crlf { "\r\n" } else { "\n" };
    let mut text = lines.join(separator);
    if terminated {
        text.push_str(separator);
    }
    absolute_model::FileImage {
        file_id: file_id.to_owned(),
        safe_path: safe_path.to_owned(),
        bytes: text.into_bytes(),
    }
}

fn one_file(file: absolute_model::FileImage) -> absolute_model::Workspace {
    vec![file]
}

fn token_line(token: &absolute_model::TokenRecord) -> String {
    format!("credential = {};", token.canonical)
}

fn content_case(
    id: &str,
    baseline: absolute_model::FileImage,
    edited: absolute_model::FileImage,
    tokens: Vec<absolute_model::TokenRecord>,
) -> absolute_model::ContentCase {
    absolute_model::ContentCase {
        id: id.to_owned(),
        suite: "relative-additional",
        baseline: one_file(baseline),
        edited: one_file(edited),
        tokens,
        expected: absolute_model::Classification::PassUnderCurrentStandard,
        expected_failed_anchors: None,
        facts: absolute_model::ScenarioFacts {
            token_bytes_changed: false,
            semantic_role_moved: false,
            only_absolute_line_changed: false,
            adjacent_context_changed: false,
            normal_token_preserving: true,
        },
    }
}

fn exact_projected_envelope_matches(
    baseline: &absolute_model::FileImage,
    edited: &absolute_model::FileImage,
    token: &absolute_model::TokenRecord,
) -> bool {
    if baseline.file_id != edited.file_id || baseline.safe_path != edited.safe_path {
        return false;
    }
    let tokens = vec![token.clone()];
    let baseline_workspace = one_file(baseline.clone());
    let Ok((anchors, _)) = select_baseline_anchors(&baseline_workspace, &tokens) else {
        return false;
    };
    let anchor = &anchors[0];
    let mut projected = anchor.envelope.clone();
    for part in &mut projected {
        if let EnvelopePart::Core(atoms) = part {
            let mut replacement = Vec::new();
            for atom in atoms.iter() {
                match atom {
                    ShapeAtom::Bytes(bytes) => {
                        if let Some(ShapeAtom::Bytes(previous)) = replacement.last_mut() {
                            previous.extend_from_slice(bytes);
                        } else {
                            replacement.push(ShapeAtom::Bytes(bytes.clone()));
                        }
                    }
                    ShapeAtom::TypedToken(_) => {}
                }
            }
            *atoms = replacement;
        }
    }
    let edited_workspace = one_file(edited.clone());
    let edited_lines = logical_lines(&edited.bytes);
    let occurrences = file_occurrences(edited, &tokens);
    let core_len = anchor.run.normalized_core.len();
    let mut count = 0usize;
    for first in 0..edited_lines.len() {
        let Some(last) = first.checked_add(core_len.saturating_sub(1)) else {
            return false;
        };
        if last >= edited_lines.len() {
            continue;
        }
        let candidate_run = Run {
            file_index: 0,
            file_id: edited.file_id.clone(),
            safe_path: edited.safe_path.clone(),
            first_line: first,
            last_line: last,
            exact_lines: Vec::new(),
            normalized_core: edited_lines[first..=last]
                .iter()
                .map(|line| normalized_line(edited, line, &occurrences, &tokens))
                .collect(),
            ordered: Vec::new(),
        };
        if envelope(&edited_workspace, &tokens, &candidate_run, anchor.radius) == projected {
            count += 1;
        }
    }
    count == 1
}

fn same_category_token(serial: u32, ordinal: u32) -> absolute_model::TokenRecord {
    absolute_model::canonical_token(
        serial,
        TokenCategory::Secret,
        ordinal,
        b"synthetic/relative-anchor.txt",
    )
}

fn repeated_pair(
    first: &absolute_model::TokenRecord,
    second: &absolute_model::TokenRecord,
    distinguishing_radius: Option<usize>,
) -> absolute_model::Workspace {
    let radius = distinguishing_radius.unwrap_or(MAX_CONTEXT_LINES_PER_SIDE + 1);
    let mut lines = Vec::new();
    for (block, token) in [("A", first), ("B", second)] {
        lines.push(if distinguishing_radius.is_some() {
            format!("unique-{block}-at-radius-{radius}")
        } else {
            "same-outer-boundary".to_owned()
        });
        for distance in (1..radius).rev() {
            lines.push(format!("shared-left-{distance}"));
        }
        lines.push(token_line(token));
        for distance in 1..radius {
            lines.push(format!("shared-right-{distance}"));
        }
        lines.push("block-separator".to_owned());
    }
    one_file(image("file-main", "src/repeated.txt", &lines, false, true))
}

#[derive(Debug, Default)]
struct ReplayMetrics {
    total: usize,
    by_outcome: BTreeMap<Outcome, usize>,
    old_absolute_shift_total: usize,
    old_absolute_shift_now_pass: usize,
    old_absolute_shift_other_reject: usize,
    old_absolute_shift_ambiguous: usize,
    workflow_absolute_shift_total: usize,
    workflow_absolute_shift_now_pass: usize,
    logical_relocations_now_pass: usize,
    normal_token_preserving_total: usize,
    normal_token_preserving_automatic: usize,
    workflow_total: usize,
    workflow_automatic: usize,
}

impl ReplayMetrics {
    fn push(&mut self, outcome: Outcome) {
        self.total += 1;
        *self.by_outcome.entry(outcome).or_default() += 1;
    }
}

fn replay_absolute_model() -> ReplayMetrics {
    let cases = absolute_model::absolute_model_content_corpus();
    let records = absolute_model::absolute_model_laboratory_records();
    assert_eq!(cases.len(), 140);
    assert_eq!(records.len(), 154);
    let logical_relocations = BTreeSet::from([
        "repeated/move-token-block",
        "movement/move-run-and-both-context-lines",
        "movement/copy-identical-block-elsewhere-delete-original",
    ]);
    let protected_core_reclassifications = BTreeSet::from([
        "single/21-move-token-within-line",
        "single/22-change-whitespace-token-line",
        "formatter/token-line-indentation",
        "formatter/full-file-crlf-to-lf",
        "movement/reorder-two-tokens-within-one-run",
    ]);
    let run_order_reclassifications =
        BTreeSet::from(["movement/swap-skeleton-identical-token-blocks"]);
    let mut metrics = ReplayMetrics::default();
    for case in &cases {
        let outcome = evaluate_content(case);
        if case.facts.normal_token_preserving {
            metrics.normal_token_preserving_total += 1;
            if outcome == Outcome::Automatic {
                metrics.normal_token_preserving_automatic += 1;
            }
        }
        if case.suite == "workflow" {
            metrics.workflow_total += 1;
            if outcome == Outcome::Automatic {
                metrics.workflow_automatic += 1;
            }
        }
        if case.expected == absolute_model::Classification::RejectAbsoluteLineShiftOnly {
            metrics.old_absolute_shift_total += 1;
            match outcome {
                Outcome::Automatic => metrics.old_absolute_shift_now_pass += 1,
                Outcome::AnchorAmbiguous => metrics.old_absolute_shift_ambiguous += 1,
                _ => metrics.old_absolute_shift_other_reject += 1,
            }
            if case.suite == "workflow" {
                metrics.workflow_absolute_shift_total += 1;
                if outcome == Outcome::Automatic {
                    metrics.workflow_absolute_shift_now_pass += 1;
                }
            }
        } else if logical_relocations.contains(case.id.as_str()) {
            assert_eq!(outcome, Outcome::Automatic, "{}", case.id);
            metrics.logical_relocations_now_pass += 1;
        } else if protected_core_reclassifications.contains(case.id.as_str()) {
            assert_eq!(outcome, Outcome::ProtectedCoreChanged, "{}", case.id);
        } else if run_order_reclassifications.contains(case.id.as_str()) {
            assert_eq!(outcome, Outcome::RunOrderChanged, "{}", case.id);
        } else {
            match case.expected {
                absolute_model::Classification::PassUnderCurrentStandard => {
                    assert_eq!(outcome, Outcome::Automatic, "{}", case.id);
                }
                absolute_model::Classification::RejectContextBoundary
                | absolute_model::Classification::RejectSecurityMaterial => {
                    assert_eq!(outcome, Outcome::ProtectedContextChanged, "{}", case.id);
                }
                absolute_model::Classification::RejectPathOrFileMovement => {
                    assert_eq!(outcome, Outcome::PathOrFileMovement, "{}", case.id);
                }
                absolute_model::Classification::RejectTokenStructure => {
                    assert_eq!(outcome, Outcome::TokenStructure, "{}", case.id);
                }
                absolute_model::Classification::Ambiguous
                | absolute_model::Classification::RejectAbsoluteLineShiftOnly => {
                    panic!(
                        "unexpected absolute-model replay classification for {}",
                        case.id
                    );
                }
            }
        }
        metrics.push(outcome);
    }

    let primary = same_category_token(90, 0);
    let projection_lines = vec![
        "header".to_owned(),
        "context-before".to_owned(),
        token_line(&primary),
        "context-after".to_owned(),
        "tail".to_owned(),
    ];
    let baseline = image(
        "file-main",
        "config/settings.txt",
        &projection_lines,
        false,
        true,
    );
    let exact_lines: Vec<String> = projection_lines
        .iter()
        .map(|line| line.replace(&primary.canonical, ""))
        .collect();
    let exact = image(
        "file-main",
        "config/settings.txt",
        &exact_lines,
        false,
        true,
    );
    let mut shifted_lines = exact_lines.clone();
    shifted_lines.insert(0, "unrelated-before-envelope".to_owned());
    let shifted = image(
        "file-main",
        "config/settings.txt",
        &shifted_lines,
        false,
        true,
    );
    assert!(exact_projected_envelope_matches(
        &baseline, &exact, &primary
    ));
    assert!(exact_projected_envelope_matches(
        &baseline, &shifted, &primary
    ));

    for record in records
        .iter()
        .filter(|record| matches!(record.suite, "deletion" | "path" | "strict"))
    {
        let outcome = match record.id.as_str() {
            "deletion/remove-exact-canonical-token-bytes"
            | "deletion/exact-token-removal-plus-unrelated-pre-run-shift"
            | "path/exact-token-deletion-projection-from-component" => {
                Outcome::ApprovalRequiredDeletion
            }
            "deletion/remove-token-plus-adjacent-byte"
            | "deletion/remove-full-token-bearing-line"
            | "deletion/remove-token-and-rewrite-syntax" => Outcome::ProtectedCoreChanged,
            "path/token-bearing-file-stem-unchanged"
            | "path/token-free-sibling-renamed"
            | "path/token-free-sibling-added"
            | "strict/standard-preserving-token-file-edit"
            | "strict/standard-anchor-failure" => Outcome::Automatic,
            "path/token-bearing-file-renamed"
            | "path/token-bearing-directory-renamed"
            | "path/token-bearing-directory-moved" => Outcome::PathOrFileMovement,
            other => panic!("unhandled absolute-model manual replay row: {other}"),
        };
        if record.id == "strict/standard-anchor-failure" {
            metrics.old_absolute_shift_total += 1;
            metrics.old_absolute_shift_now_pass += 1;
        }
        if record.normal_token_preserving {
            metrics.normal_token_preserving_total += 1;
            if outcome == Outcome::Automatic {
                metrics.normal_token_preserving_automatic += 1;
            }
        }
        metrics.push(outcome);
    }
    metrics
}

#[test]
fn absolute_model_corpus_replay_removes_absolute_line_authority() {
    let metrics = replay_absolute_model();
    assert_eq!(metrics.total, 154);
    assert_eq!(metrics.old_absolute_shift_total, 60);
    assert_eq!(metrics.old_absolute_shift_now_pass, 60);
    assert_eq!(metrics.old_absolute_shift_other_reject, 0);
    assert_eq!(metrics.old_absolute_shift_ambiguous, 0);
    assert_eq!(metrics.workflow_absolute_shift_total, 7);
    assert_eq!(metrics.workflow_absolute_shift_now_pass, 7);
    assert_eq!(metrics.logical_relocations_now_pass, 3);
    assert_eq!(metrics.normal_token_preserving_total, 129);
    assert_eq!(metrics.normal_token_preserving_automatic, 111);
    assert_eq!(metrics.workflow_total, 10);
    assert_eq!(metrics.workflow_automatic, 10);
    let expected = BTreeMap::from([
        (Outcome::Automatic, 117),
        (Outcome::ApprovalRequiredDeletion, 3),
        (Outcome::ProtectedContextChanged, 18),
        (Outcome::ProtectedCoreChanged, 8),
        (Outcome::AnchorAmbiguous, 0),
        (Outcome::PathOrFileMovement, 5),
        (Outcome::TokenStructure, 2),
        (Outcome::RunOrderChanged, 1),
    ]);
    for outcome in Outcome::ALL {
        assert_eq!(
            metrics.by_outcome.get(&outcome).copied().unwrap_or(0),
            expected[&outcome],
            "{} replay metric",
            outcome.as_str()
        );
    }
}

#[test]
fn exact_context_expands_deterministically_and_fails_closed() {
    let first = same_category_token(101, 0);
    let second = same_category_token(102, 1);
    for radius in [2, 5, MAX_CONTEXT_LINES_PER_SIDE] {
        let workspace = repeated_pair(&first, &second, Some(radius));
        let (anchors, stats) =
            select_baseline_anchors(&workspace, &[first.clone(), second.clone()])
                .expect("unique within accepted bound");
        assert_eq!(anchors.len(), 2);
        assert!(anchors.iter().all(|anchor| anchor.radius == radius));
        assert!(stats.windows <= MAX_ANCHOR_WINDOWS_PER_FILE);
        assert!(stats.canonical_context_bytes <= MAX_CONTEXT_BYTES);
    }
    let ambiguous = repeated_pair(&first, &second, None);
    assert_eq!(
        select_baseline_anchors(&ambiguous, &[first.clone(), second.clone()]).unwrap_err(),
        Outcome::AnchorAmbiguous
    );

    let same_ordinal_a = same_category_token(103, 7);
    let same_ordinal_b = same_category_token(104, 7);
    let oid_independent = repeated_pair(&same_ordinal_a, &same_ordinal_b, None);
    assert_eq!(
        select_baseline_anchors(&oid_independent, &[same_ordinal_a, same_ordinal_b]).unwrap_err(),
        Outcome::AnchorAmbiguous,
        "OID and occurrence identity never manufacture context uniqueness"
    );
}

#[test]
fn intact_logical_relocation_is_preserved_but_secret_only_movement_rejects() {
    let token = same_category_token(110, 0);
    let baseline_lines = vec![
        "header".to_owned(),
        "anchor-before".to_owned(),
        token_line(&token),
        "anchor-after".to_owned(),
        "middle".to_owned(),
        "tail".to_owned(),
    ];
    let baseline = image("file-main", "src/logical.rs", &baseline_lines, false, true);

    let mut moved_lines = baseline_lines.clone();
    let block: Vec<String> = moved_lines.drain(1..=3).collect();
    moved_lines.splice(3..3, block);
    let moved = image("file-main", "src/logical.rs", &moved_lines, false, true);
    assert_eq!(
        evaluate_content(&content_case(
            "move-intact",
            baseline.clone(),
            moved,
            vec![token.clone()]
        )),
        Outcome::Automatic
    );

    let mut changed_lines = moved_lines.clone();
    let token_index = changed_lines
        .iter()
        .position(|line| line.contains(&token.canonical))
        .expect("moved token line");
    changed_lines[token_index + 1] = "changed-anchor-after".to_owned();
    let changed = image("file-main", "src/logical.rs", &changed_lines, false, true);
    assert_eq!(
        evaluate_content(&content_case(
            "move-changed-context",
            baseline.clone(),
            changed,
            vec![token.clone()]
        )),
        Outcome::ProtectedContextChanged
    );

    let mut token_only_lines = baseline_lines.clone();
    let token_line = token_only_lines.remove(2);
    token_only_lines.insert(5, token_line);
    let token_only = image(
        "file-main",
        "src/logical.rs",
        &token_only_lines,
        false,
        true,
    );
    assert_eq!(
        evaluate_content(&content_case(
            "move-token-only",
            baseline,
            token_only,
            vec![token.clone()]
        )),
        Outcome::ProtectedContextChanged
    );

    let peer = same_category_token(111, 1);
    let repeated = repeated_pair(&token, &peer, Some(2));
    let mut repeated_lines: Vec<String> = String::from_utf8(repeated[0].bytes.clone())
        .expect("synthetic UTF-8")
        .lines()
        .map(str::to_owned)
        .collect();
    repeated_lines.swap(2, 7);
    let moved_into_peer = image(
        "file-main",
        "src/repeated.txt",
        &repeated_lines,
        false,
        true,
    );
    assert_eq!(
        evaluate_content(&absolute_model::ContentCase {
            id: "move-into-repeated-block".to_owned(),
            suite: "relative-additional",
            baseline: repeated,
            edited: one_file(moved_into_peer),
            tokens: vec![token, peer],
            expected: absolute_model::Classification::RejectSecurityMaterial,
            expected_failed_anchors: None,
            facts: absolute_model::ScenarioFacts {
                token_bytes_changed: false,
                semantic_role_moved: true,
                only_absolute_line_changed: false,
                adjacent_context_changed: false,
                normal_token_preserving: false,
            },
        }),
        Outcome::ProtectedContextChanged
    );
}

#[test]
fn edited_uniqueness_and_run_order_are_independent_of_oid() {
    let first = same_category_token(120, 0);
    let second = same_category_token(121, 1);
    let baseline = repeated_pair(&first, &second, Some(2));
    let (anchors, _) =
        select_baseline_anchors(&baseline, &[first.clone(), second.clone()]).expect("unique");
    assert!(anchors.iter().all(|anchor| anchor.radius == 2));

    let mut duplicated = baseline.clone();
    let source_lines = logical_lines(&duplicated[0].bytes);
    let first_run = &anchors[0].run;
    let copied: Vec<Vec<u8>> = source_lines
        [first_run.first_line.saturating_sub(2)..=(first_run.last_line + 2)]
        .iter()
        .map(|range| duplicated[0].bytes[range.clone()].to_vec())
        .collect();
    let mut appended = duplicated[0].bytes.clone();
    for line in copied {
        appended.extend_from_slice(&line);
    }
    duplicated[0].bytes = appended;
    let current_runs = derive_runs(&duplicated, &[first.clone(), second.clone()]);
    let duplicate_count = current_runs
        .iter()
        .filter(|run| {
            envelope(&duplicated, &[first.clone(), second.clone()], run, 2) == anchors[0].envelope
        })
        .count();
    assert!(
        duplicate_count > 1,
        "edited exact context duplication is ambiguous"
    );

    let first_block = vec![
        "context-before-A".to_owned(),
        token_line(&first),
        "context-after-A".to_owned(),
    ];
    let second_block = vec![
        "context-before-B".to_owned(),
        token_line(&second),
        "context-after-B".to_owned(),
    ];
    let mut baseline_lines = vec!["head".to_owned()];
    baseline_lines.extend(first_block.clone());
    baseline_lines.push("gap".to_owned());
    baseline_lines.extend(second_block.clone());
    baseline_lines.push("tail".to_owned());
    let order_baseline = one_file(image(
        "file-main",
        "src/order.txt",
        &baseline_lines,
        false,
        true,
    ));
    let mut swapped_lines = vec!["head".to_owned()];
    swapped_lines.extend(second_block);
    swapped_lines.push("gap".to_owned());
    swapped_lines.extend(first_block);
    swapped_lines.push("tail".to_owned());
    let swapped = one_file(image(
        "file-main",
        "src/order.txt",
        &swapped_lines,
        false,
        true,
    ));
    let case = absolute_model::ContentCase {
        id: "swap-runs".to_owned(),
        suite: "relative-additional",
        baseline: order_baseline,
        edited: swapped,
        tokens: vec![first, second],
        expected: absolute_model::Classification::RejectSecurityMaterial,
        expected_failed_anchors: None,
        facts: absolute_model::ScenarioFacts {
            token_bytes_changed: false,
            semantic_role_moved: true,
            only_absolute_line_changed: false,
            adjacent_context_changed: false,
            normal_token_preserving: false,
        },
    };
    assert_eq!(evaluate_content(&case), Outcome::RunOrderChanged);

    let duplicate_baseline_lines = vec![
        "head".to_owned(),
        "context-before-A".to_owned(),
        token_line(&case.tokens[0]),
        "context-after-A".to_owned(),
        "gap".to_owned(),
        "context-before-B".to_owned(),
        token_line(&case.tokens[1]),
        "context-after-B".to_owned(),
        "tail".to_owned(),
    ];
    let duplicate_baseline = image(
        "file-main",
        "src/duplicate-context.txt",
        &duplicate_baseline_lines,
        false,
        true,
    );
    let mut duplicate_edited_lines = duplicate_baseline_lines;
    duplicate_edited_lines[5] = "context-before-A".to_owned();
    duplicate_edited_lines[7] = "context-after-A".to_owned();
    let duplicate_edited = image(
        "file-main",
        "src/duplicate-context.txt",
        &duplicate_edited_lines,
        false,
        true,
    );
    assert_eq!(
        evaluate_content(&content_case(
            "context-becomes-duplicated",
            duplicate_baseline,
            duplicate_edited,
            case.tokens.clone(),
        )),
        Outcome::AnchorAmbiguous
    );

    let baseline_known = case.tokens[0].clone();
    let unknown = same_category_token(122, 9);
    let unknown_baseline_lines = vec![
        "before".to_owned(),
        token_line(&baseline_known),
        "after".to_owned(),
    ];
    let unknown_edited_lines = vec![
        "before".to_owned(),
        token_line(&unknown),
        "after".to_owned(),
    ];
    assert_eq!(
        evaluate_content(&content_case(
            "unknown-authentic-token",
            image(
                "file-main",
                "src/unknown.txt",
                &unknown_baseline_lines,
                false,
                true,
            ),
            image(
                "file-main",
                "src/unknown.txt",
                &unknown_edited_lines,
                false,
                true,
            ),
            vec![baseline_known],
        )),
        Outcome::TokenStructure
    );
}

#[test]
fn multiple_runs_may_shift_without_distance_authority_but_keep_order() {
    let first = same_category_token(125, 0);
    let second = same_category_token(126, 1);
    let first_block = vec![
        "before-A".to_owned(),
        token_line(&first),
        "after-A".to_owned(),
    ];
    let second_block = vec![
        "before-B".to_owned(),
        token_line(&second),
        "after-B".to_owned(),
    ];
    let mut baseline_lines = vec!["header".to_owned(), "far-before".to_owned()];
    baseline_lines.extend(first_block.clone());
    baseline_lines.extend([
        "between-1".to_owned(),
        "between-2".to_owned(),
        "between-3".to_owned(),
    ]);
    baseline_lines.extend(second_block.clone());
    baseline_lines.push("tail".to_owned());
    let baseline = image(
        "file-main",
        "src/multiple.txt",
        &baseline_lines,
        false,
        true,
    );

    let mut moved_lines = vec![
        "header".to_owned(),
        "unrelated-new-top".to_owned(),
        "between-rewritten-1".to_owned(),
    ];
    moved_lines.extend(first_block);
    moved_lines.extend(["between-added-A".to_owned(), "between-added-B".to_owned()]);
    moved_lines.extend(second_block);
    moved_lines.extend(["between-rewritten-2".to_owned(), "tail".to_owned()]);
    let moved = image("file-main", "src/multiple.txt", &moved_lines, false, true);
    assert_eq!(
        evaluate_content(&content_case(
            "multiple-runs-retain-order",
            baseline,
            moved,
            vec![first, second],
        )),
        Outcome::Automatic
    );
}

#[test]
fn strict_requires_standard_v2_before_adding_approval() {
    assert_eq!(
        profile_decisions(Outcome::Automatic, true),
        (
            ProfileDecision::Automatic,
            ProfileDecision::ApprovalRequired
        )
    );
    assert_eq!(
        profile_decisions(Outcome::ProtectedContextChanged, true),
        (ProfileDecision::Reject, ProfileDecision::Reject)
    );
}

#[test]
fn far_edits_boundaries_and_exact_deletion_projection_are_relative() {
    let token = same_category_token(130, 0);
    let baseline_lines = vec![
        "header".to_owned(),
        "far-before".to_owned(),
        "context-before".to_owned(),
        token_line(&token),
        "context-after".to_owned(),
        "far-after".to_owned(),
    ];
    let baseline = image(
        "file-main",
        "config/settings.txt",
        &baseline_lines,
        false,
        true,
    );
    let mut edited_lines = baseline_lines.clone();
    edited_lines.insert(1, "inserted-far-before".to_owned());
    edited_lines.push("inserted-far-after".to_owned());
    let edited = image(
        "file-main",
        "config/settings.txt",
        &edited_lines,
        false,
        true,
    );
    assert_eq!(
        evaluate_content(&content_case(
            "far-insertions",
            baseline.clone(),
            edited,
            vec![token.clone()]
        )),
        Outcome::Automatic
    );

    let mut deleted_far_lines = baseline_lines.clone();
    deleted_far_lines.remove(1);
    let deleted_far = image(
        "file-main",
        "config/settings.txt",
        &deleted_far_lines,
        false,
        true,
    );
    assert_eq!(
        evaluate_content(&content_case(
            "far-deletion",
            baseline.clone(),
            deleted_far,
            vec![token.clone()]
        )),
        Outcome::Automatic
    );

    let mut context_deleted_lines = baseline_lines.clone();
    context_deleted_lines.remove(2);
    let context_deleted = image(
        "file-main",
        "config/settings.txt",
        &context_deleted_lines,
        false,
        true,
    );
    assert_eq!(
        evaluate_content(&content_case(
            "selected-context-deleted",
            baseline.clone(),
            context_deleted,
            vec![token.clone()]
        )),
        Outcome::ProtectedContextChanged
    );

    let exact_lines: Vec<String> = baseline_lines
        .iter()
        .map(|line| line.replace(&token.canonical, ""))
        .collect();
    let mut shifted_projection = exact_lines.clone();
    shifted_projection.insert(0, "projection-far-shift".to_owned());
    let projected = image(
        "file-main",
        "config/settings.txt",
        &shifted_projection,
        false,
        true,
    );
    assert!(exact_projected_envelope_matches(
        &baseline, &projected, &token
    ));
    let mut adjacent_removed = shifted_projection;
    let projected_index = adjacent_removed
        .iter()
        .position(|line| line.starts_with("credential"))
        .expect("projected line");
    adjacent_removed[projected_index] = adjacent_removed[projected_index].replacen(" =", "=", 1);
    let invalid = image(
        "file-main",
        "config/settings.txt",
        &adjacent_removed,
        false,
        true,
    );
    assert!(!exact_projected_envelope_matches(
        &baseline, &invalid, &token
    ));

    let mut full_line_removed = baseline_lines.clone();
    full_line_removed.remove(3);
    let invalid = image(
        "file-main",
        "config/settings.txt",
        &full_line_removed,
        false,
        true,
    );
    assert!(!exact_projected_envelope_matches(
        &baseline, &invalid, &token
    ));

    let rewritten_lines: Vec<String> = baseline_lines
        .iter()
        .map(|line| {
            line.replace(
                &format!("credential = {};", token.canonical),
                "credential = load_from_environment();",
            )
        })
        .collect();
    let invalid = image(
        "file-main",
        "config/settings.txt",
        &rewritten_lines,
        false,
        true,
    );
    assert!(!exact_projected_envelope_matches(
        &baseline, &invalid, &token
    ));

    for (name, lines, crlf, terminated) in [
        (
            "bof",
            vec![token_line(&token), "after".to_owned()],
            false,
            true,
        ),
        (
            "eof",
            vec!["before".to_owned(), token_line(&token)],
            false,
            true,
        ),
        (
            "crlf",
            vec!["before".to_owned(), token_line(&token), "after".to_owned()],
            true,
            true,
        ),
        (
            "unterminated",
            vec!["before".to_owned(), token_line(&token)],
            false,
            false,
        ),
    ] {
        let file = image(
            "file-main",
            &format!("synthetic/{name}.txt"),
            &lines,
            crlf,
            terminated,
        );
        let case = content_case(name, file.clone(), file, vec![token.clone()]);
        assert_eq!(evaluate_content(&case), Outcome::Automatic, "{name}");
    }
}

#[test]
fn fixed_resource_model_is_finite_and_report_is_bound_to_evidence() {
    assert_eq!(MAX_CONTEXT_LINES_PER_SIDE, 16);
    assert_eq!(MAX_CONTEXT_BYTES, 5_242_880);
    assert_eq!(MAX_ANCHOR_WINDOWS_PER_FILE, 266_240);
    assert_eq!(MAX_ANCHOR_SCAN_WORK_PER_FILE, 8_388_608);
    assert_eq!(MAX_ANCHOR_TEMP_BYTES_PER_FILE, 33_554_432);
    let comparison_upper_bound = MAX_CONTEXT_LINES_PER_SIDE
        * MAX_TOKENS_PER_FILE
        * (usize::BITS as usize - (MAX_TOKENS_PER_FILE - 1).leading_zeros() as usize);
    let modeled_work = comparison_upper_bound
        + MAX_ANCHOR_WINDOWS_PER_FILE
        + MAX_LOGICAL_LINES_PER_TOKEN_FILE
        + MAX_TOKENS_PER_FILE;
    assert!(modeled_work <= MAX_ANCHOR_SCAN_WORK_PER_FILE);
    let canonical_envelope_upper_bound = CONTEXT_ENCODING_PREFIX.len()
        + 4
        + MAX_LOGICAL_LINES_PER_TOKEN_FILE
        + 2
        + 4 * MAX_LOGICAL_LINES_PER_TOKEN_FILE
        + 5 * (MAX_LOGICAL_LINES_PER_TOKEN_FILE + MAX_TOKENS_PER_FILE)
        + 2 * MAX_TOKENS_PER_FILE
        + MAX_FILE_BYTES;
    assert!(canonical_envelope_upper_bound <= MAX_CONTEXT_BYTES);

    let first = same_category_token(140, 0);
    let second = same_category_token(141, 1);
    let stress = repeated_pair(&first, &second, Some(MAX_CONTEXT_LINES_PER_SIDE));
    let (_, stats) = select_baseline_anchors(&stress, &[first, second]).expect("radius-16 stress");
    assert!(stats.logical_lines <= MAX_LOGICAL_LINES_PER_TOKEN_FILE);
    assert_eq!(stats.protected_runs, 2);
    assert!(stats.windows <= MAX_ANCHOR_WINDOWS_PER_FILE);
    assert!(stats.canonical_context_bytes <= MAX_CONTEXT_BYTES);

    let stress_tokens: Vec<absolute_model::TokenRecord> = (0..32)
        .map(|index| same_category_token(200 + index, index))
        .collect();
    let mut stress_lines = Vec::new();
    for token in &stress_tokens {
        for distance in (1..=MAX_CONTEXT_LINES_PER_SIDE).rev() {
            stress_lines.push(format!("identical-left-{distance}"));
        }
        stress_lines.push(token_line(token));
        for distance in 1..=MAX_CONTEXT_LINES_PER_SIDE {
            stress_lines.push(format!("identical-right-{distance}"));
        }
        stress_lines.push("outside-selected-bound".to_owned());
    }
    let repeated_stress = one_file(image(
        "file-main",
        "src/repeated-stress.txt",
        &stress_lines,
        false,
        true,
    ));
    assert_eq!(
        select_baseline_anchors(&repeated_stress, &stress_tokens).unwrap_err(),
        Outcome::AnchorAmbiguous,
        "32 indistinguishable exact contexts fail closed at radius 16"
    );
}
