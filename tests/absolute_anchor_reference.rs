//! Independent absolute-position contrast model; not the runtime StandardV2 algorithm.
use std::collections::{BTreeMap, BTreeSet};
use std::ops::Range;

use safeclone::roundtrip::crypto::{KeySchedule, SessionId, SessionMasterSecret};
use safeclone::roundtrip::ruleset::ruleset_id;
use safeclone::roundtrip::token::{
    authenticate_token, generate_token, parse_token, ComponentKind, EntryKind,
    OccurrenceDescriptor, ReviewProfile, TokenCategory, ENGINE_VERSION, POLICY_ID, TOKEN_PREFIX,
    TOKEN_SUITE_ID,
};

const LAB_MAX_SYNTHETIC_FILES: usize = 128;
const LAB_MAX_LINES_PER_FILE: usize = 2_000;
const LAB_MAX_TOKENS_PER_FILE: usize = 64;
const LAB_MAX_SCENARIOS: usize = 2_000;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum Classification {
    PassUnderCurrentStandard,
    RejectSecurityMaterial,
    RejectContextBoundary,
    RejectAbsoluteLineShiftOnly,
    RejectPathOrFileMovement,
    RejectTokenStructure,
    Ambiguous,
}

impl Classification {
    const ALL: [Self; 7] = [
        Self::PassUnderCurrentStandard,
        Self::RejectSecurityMaterial,
        Self::RejectContextBoundary,
        Self::RejectAbsoluteLineShiftOnly,
        Self::RejectPathOrFileMovement,
        Self::RejectTokenStructure,
        Self::Ambiguous,
    ];

    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::PassUnderCurrentStandard => "PASS_UNDER_CURRENT_STANDARD",
            Self::RejectSecurityMaterial => "REJECT_SECURITY_MATERIAL",
            Self::RejectContextBoundary => "REJECT_CONTEXT_BOUNDARY",
            Self::RejectAbsoluteLineShiftOnly => "REJECT_ABSOLUTE_LINE_SHIFT_ONLY",
            Self::RejectPathOrFileMovement => "REJECT_PATH_OR_FILE_MOVEMENT",
            Self::RejectTokenStructure => "REJECT_TOKEN_STRUCTURE",
            Self::Ambiguous => "AMBIGUOUS",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct TokenRecord {
    pub(crate) canonical: String,
    pub(crate) oid: [u8; 16],
    pub(crate) category: TokenCategory,
    pub(crate) ordinal: u32,
}

pub(crate) fn canonical_token(
    serial: u32,
    category: TokenCategory,
    ordinal: u32,
    component_path: &[u8],
) -> TokenRecord {
    let master = SessionMasterSecret::from_bytes([0x42; 32]);
    let session_id = SessionId::from_bytes([0x24; 16]);
    let schedule = KeySchedule::new(&master, session_id);
    let descriptor = OccurrenceDescriptor {
        session_id,
        ruleset_id: ruleset_id(),
        review_profile: ReviewProfile::StandardV2,
        entry_kind: EntryKind::RegularFile,
        canonical_original_relative_path: component_path,
        component_index: 0,
        component_kind: ComponentKind::Content,
        byte_span_start: u64::from(serial) * 16,
        byte_span_end: u64::from(serial) * 16 + 8,
        category,
        occurrence_ordinal_within_component: ordinal,
        pre_token_anchor_commitment: [serial as u8; 32],
    };
    let canonical = generate_token(&schedule, &descriptor).expect("generate canonical token");
    let authenticated = authenticate_token(
        &schedule,
        parse_token(&canonical).expect("parse generated canonical token"),
    )
    .expect("authenticate generated canonical token");
    assert_eq!(authenticated.category(), category);
    assert_eq!(authenticated.session_id(), session_id);
    TokenRecord {
        canonical,
        oid: *authenticated.occurrence_id(),
        category,
        ordinal,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Newline {
    Lf,
    Crlf,
}

impl Newline {
    const fn bytes(self) -> &'static [u8] {
        match self {
            Self::Lf => b"\n",
            Self::Crlf => b"\r\n",
        }
    }
}

#[derive(Clone, Debug)]
struct Document {
    lines: Vec<String>,
    newline: Newline,
    terminated: bool,
}

impl Document {
    fn bytes(&self) -> Vec<u8> {
        let separator = self.newline.bytes();
        let separator_count = self
            .lines
            .len()
            .saturating_sub(1)
            .saturating_add(usize::from(self.terminated));
        let mut output = Vec::with_capacity(
            self.lines.iter().map(String::len).sum::<usize>() + separator_count * separator.len(),
        );
        for (index, line) in self.lines.iter().enumerate() {
            output.extend_from_slice(line.as_bytes());
            if index + 1 < self.lines.len() || self.terminated {
                output.extend_from_slice(separator);
            }
        }
        if self.lines.is_empty() && self.terminated {
            output.extend_from_slice(separator);
        }
        output
    }
}

#[derive(Clone, Debug)]
pub(crate) struct FileImage {
    pub(crate) file_id: String,
    pub(crate) safe_path: String,
    pub(crate) bytes: Vec<u8>,
}

pub(crate) type Workspace = Vec<FileImage>;

fn one_file(file_id: &str, safe_path: &str, document: &Document) -> Workspace {
    vec![FileImage {
        file_id: file_id.to_owned(),
        safe_path: safe_path.to_owned(),
        bytes: document.bytes(),
    }]
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

#[derive(Clone, Debug)]
struct Occurrence {
    file_index: usize,
    token_index: usize,
    start: usize,
    end: usize,
    line_index: usize,
}

fn occurrences(workspace: &Workspace, tokens: &[TokenRecord]) -> Vec<Occurrence> {
    let mut output = Vec::new();
    for (file_index, file) in workspace.iter().enumerate() {
        let lines = logical_lines(&file.bytes);
        for (token_index, token) in tokens.iter().enumerate() {
            for start in byte_matches(&file.bytes, token.canonical.as_bytes()) {
                let end = start + token.canonical.len();
                let line_index = lines
                    .iter()
                    .position(|line| start >= line.start && end <= line.end)
                    .expect("canonical token stays within one logical line");
                output.push(Occurrence {
                    file_index,
                    token_index,
                    start,
                    end,
                    line_index,
                });
            }
        }
    }
    output.sort_by_key(|item| (item.file_index, item.start, item.end, item.token_index));
    output
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Boundary {
    skeleton_offset: usize,
    oid: [u8; 16],
    category: TokenCategory,
    ordinal: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct OrderedToken {
    oid: [u8; 16],
    category: TokenCategory,
    ordinal: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ProtectedLine {
    skeleton: Vec<u8>,
    boundaries: Vec<Boundary>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum AdjacentContext {
    Bof,
    Eof,
    Line(Vec<u8>),
}

#[derive(Clone, Debug)]
struct RunAnchor {
    file_id: String,
    safe_path: String,
    first_line: usize,
    last_line: usize,
    protected_lines: Vec<ProtectedLine>,
    preceding: AdjacentContext,
    following: AdjacentContext,
    ordered: Vec<OrderedToken>,
}

impl RunAnchor {
    fn oids(&self) -> Vec<[u8; 16]> {
        self.ordered.iter().map(|item| item.oid).collect()
    }

    fn label(&self) -> String {
        format!("{}:L{}-L{}", self.file_id, self.first_line, self.last_line)
    }
}

fn derive_run_anchors(workspace: &Workspace, tokens: &[TokenRecord]) -> Vec<RunAnchor> {
    let all_occurrences = occurrences(workspace, tokens);
    let mut output = Vec::new();
    for (file_index, file) in workspace.iter().enumerate() {
        let lines = logical_lines(&file.bytes);
        let file_occurrences: Vec<&Occurrence> = all_occurrences
            .iter()
            .filter(|item| item.file_index == file_index)
            .collect();
        let token_lines: BTreeSet<usize> = file_occurrences
            .iter()
            .map(|item| item.line_index)
            .collect();
        let mut iter = token_lines.into_iter().peekable();
        while let Some(first) = iter.next() {
            let mut last = first;
            while iter.peek().is_some_and(|next| *next == last + 1) {
                last = iter.next().expect("peeked line exists");
            }
            let mut protected_lines = Vec::new();
            let mut ordered = Vec::new();
            for (line_index, line) in lines.iter().enumerate().take(last + 1).skip(first) {
                let mut line_occurrences: Vec<&Occurrence> = file_occurrences
                    .iter()
                    .copied()
                    .filter(|item| item.line_index == line_index)
                    .collect();
                line_occurrences.sort_by_key(|item| item.start);
                let mut skeleton = Vec::new();
                let mut boundaries = Vec::new();
                let mut cursor = line.start;
                for occurrence in line_occurrences {
                    assert!(occurrence.start >= cursor, "token spans do not overlap");
                    skeleton.extend_from_slice(&file.bytes[cursor..occurrence.start]);
                    let token = &tokens[occurrence.token_index];
                    let boundary = Boundary {
                        skeleton_offset: skeleton.len(),
                        oid: token.oid,
                        category: token.category,
                        ordinal: token.ordinal,
                    };
                    boundaries.push(boundary.clone());
                    ordered.push(OrderedToken {
                        oid: boundary.oid,
                        category: boundary.category,
                        ordinal: boundary.ordinal,
                    });
                    cursor = occurrence.end;
                }
                skeleton.extend_from_slice(&file.bytes[cursor..line.end]);
                protected_lines.push(ProtectedLine {
                    skeleton,
                    boundaries,
                });
            }
            let preceding = if first == 0 {
                AdjacentContext::Bof
            } else {
                AdjacentContext::Line(file.bytes[lines[first - 1].clone()].to_vec())
            };
            let following = if last + 1 == lines.len() {
                AdjacentContext::Eof
            } else {
                AdjacentContext::Line(file.bytes[lines[last + 1].clone()].to_vec())
            };
            output.push(RunAnchor {
                file_id: file.file_id.clone(),
                safe_path: file.safe_path.clone(),
                first_line: first + 1,
                last_line: last + 1,
                protected_lines,
                preceding,
                following,
                ordered,
            });
        }
    }
    output
}

#[derive(Clone, Debug, Default)]
struct Mismatch {
    global_count: bool,
    file_or_safe_path: bool,
    absolute_range: bool,
    protected_skeleton: bool,
    token_boundaries: bool,
    adjacent_context: bool,
    token_order_category_ordinal: bool,
}

impl Mismatch {
    fn any(&self) -> bool {
        self.global_count
            || self.file_or_safe_path
            || self.absolute_range
            || self.protected_skeleton
            || self.token_boundaries
            || self.adjacent_context
            || self.token_order_category_ordinal
    }

    fn reason(&self) -> String {
        let mut reasons = Vec::new();
        if self.global_count {
            reasons.push("global_token_count");
        }
        if self.file_or_safe_path {
            reasons.push("file_or_safe_path");
        }
        if self.absolute_range {
            reasons.push("absolute_line_range");
        }
        if self.protected_skeleton {
            reasons.push("protected_line_skeleton");
        }
        if self.token_boundaries {
            reasons.push("token_boundary");
        }
        if self.adjacent_context {
            reasons.push("adjacent_context");
        }
        if self.token_order_category_ordinal {
            reasons.push("token_order_category_ordinal");
        }
        if reasons.is_empty() {
            "none".to_owned()
        } else {
            reasons.join("+")
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct ScenarioFacts {
    pub(crate) token_bytes_changed: bool,
    pub(crate) semantic_role_moved: bool,
    pub(crate) only_absolute_line_changed: bool,
    pub(crate) adjacent_context_changed: bool,
    pub(crate) normal_token_preserving: bool,
}

#[derive(Clone, Debug)]
pub(crate) struct ContentCase {
    pub(crate) id: String,
    pub(crate) suite: &'static str,
    pub(crate) baseline: Workspace,
    pub(crate) edited: Workspace,
    pub(crate) tokens: Vec<TokenRecord>,
    pub(crate) expected: Classification,
    pub(crate) expected_failed_anchors: Option<Vec<String>>,
    pub(crate) facts: ScenarioFacts,
}

#[derive(Clone, Debug)]
struct Evaluation {
    classification: Classification,
    mismatch: Mismatch,
    failed_anchors: Vec<String>,
}

fn evaluate_content(case: &ContentCase) -> Evaluation {
    let baseline_anchors = derive_run_anchors(&case.baseline, &case.tokens);
    let edited_anchors = derive_run_anchors(&case.edited, &case.tokens);
    let edited_occurrences = occurrences(&case.edited, &case.tokens);
    let mut mismatch = Mismatch::default();
    let mut failed = BTreeSet::new();

    for (token_index, _) in case.tokens.iter().enumerate() {
        if edited_occurrences
            .iter()
            .filter(|item| item.token_index == token_index)
            .count()
            != 1
        {
            mismatch.global_count = true;
            for anchor in &baseline_anchors {
                if anchor.oids().contains(&case.tokens[token_index].oid) {
                    failed.insert(anchor.label());
                }
            }
        }
    }

    if !mismatch.global_count {
        let mut current_by_oid = BTreeMap::new();
        for (anchor_index, anchor) in edited_anchors.iter().enumerate() {
            for oid in anchor.oids() {
                if current_by_oid.insert(oid, anchor_index).is_some() {
                    mismatch.global_count = true;
                }
            }
        }
        for baseline in &baseline_anchors {
            let current_indexes: BTreeSet<usize> = baseline
                .oids()
                .iter()
                .filter_map(|oid| current_by_oid.get(oid).copied())
                .collect();
            if current_indexes.len() != 1 {
                mismatch.token_order_category_ordinal = true;
                failed.insert(baseline.label());
                continue;
            }
            let current = &edited_anchors[*current_indexes.iter().next().expect("one anchor")];
            let local = Mismatch {
                file_or_safe_path: baseline.file_id != current.file_id
                    || baseline.safe_path != current.safe_path,
                absolute_range: baseline.first_line != current.first_line
                    || baseline.last_line != current.last_line,
                protected_skeleton: baseline
                    .protected_lines
                    .iter()
                    .map(|line| &line.skeleton)
                    .ne(current.protected_lines.iter().map(|line| &line.skeleton)),
                token_boundaries: baseline
                    .protected_lines
                    .iter()
                    .map(|line| &line.boundaries)
                    .ne(current.protected_lines.iter().map(|line| &line.boundaries)),
                adjacent_context: baseline.preceding != current.preceding
                    || baseline.following != current.following,
                token_order_category_ordinal: baseline.ordered != current.ordered,
                ..Mismatch::default()
            };
            if local.any() {
                failed.insert(baseline.label());
            }
            mismatch.file_or_safe_path |= local.file_or_safe_path;
            mismatch.absolute_range |= local.absolute_range;
            mismatch.protected_skeleton |= local.protected_skeleton;
            mismatch.token_boundaries |= local.token_boundaries;
            mismatch.adjacent_context |= local.adjacent_context;
            mismatch.token_order_category_ordinal |= local.token_order_category_ordinal;
        }
    }

    let classification = if !mismatch.any() {
        Classification::PassUnderCurrentStandard
    } else if mismatch.file_or_safe_path {
        Classification::RejectPathOrFileMovement
    } else if mismatch.global_count
        || mismatch.protected_skeleton
        || mismatch.token_boundaries
        || mismatch.token_order_category_ordinal
    {
        Classification::RejectTokenStructure
    } else if case.facts.semantic_role_moved {
        Classification::RejectSecurityMaterial
    } else if mismatch.adjacent_context {
        Classification::RejectContextBoundary
    } else if mismatch.absolute_range
        && !case.facts.token_bytes_changed
        && !case.facts.semantic_role_moved
    {
        Classification::RejectAbsoluteLineShiftOnly
    } else {
        Classification::Ambiguous
    };

    Evaluation {
        classification,
        mismatch,
        failed_anchors: failed.into_iter().collect(),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FixtureKind {
    Rust,
    TypeScript,
    Config,
    Markdown,
}

impl FixtureKind {
    const ALL: [Self; 4] = [Self::Rust, Self::TypeScript, Self::Config, Self::Markdown];

    const fn path(self) -> &'static str {
        match self {
            Self::Rust => "src/anchor_fixture.rs",
            Self::TypeScript => "src/anchor-fixture.ts",
            Self::Config => "config/anchor-fixture.yaml",
            Self::Markdown => "docs/anchor-fixture.md",
        }
    }

    fn filler(self, index: usize) -> String {
        match self {
            Self::Rust => format!("// rust synthetic line {index:02}"),
            Self::TypeScript => format!("// typescript synthetic line {index:02}"),
            Self::Config => format!("setting_{index:02}: synthetic"),
            Self::Markdown => format!("Paragraph line {index:02} with synthetic text."),
        }
    }

    fn token_line(self, token: &str) -> String {
        match self {
            Self::Rust => format!("    let credential = \"{token}\";"),
            Self::TypeScript => format!("const credential = \"{token}\";"),
            Self::Config => format!("credential: \"{token}\""),
            Self::Markdown => format!("Credential reference: {token}"),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Position {
    NearBof,
    UpperThird,
    Middle,
    LowerThird,
    NearEof,
}

impl Position {
    const ALL: [Self; 5] = [
        Self::NearBof,
        Self::UpperThird,
        Self::Middle,
        Self::LowerThird,
        Self::NearEof,
    ];

    const fn index(self) -> usize {
        match self {
            Self::NearBof => 4,
            Self::UpperThird => 16,
            Self::Middle => 30,
            Self::LowerThird => 44,
            Self::NearEof => 56,
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::NearBof => "A",
            Self::UpperThird => "B",
            Self::Middle => "C",
            Self::LowerThird => "D",
            Self::NearEof => "E",
        }
    }
}

fn fixture_document(kind: FixtureKind, position: Position, token: &TokenRecord) -> Document {
    let mut lines: Vec<String> = (0..60).map(|index| kind.filler(index)).collect();
    lines[0] = match kind {
        FixtureKind::Rust => "use std::collections::BTreeMap;".to_owned(),
        FixtureKind::TypeScript => "import { parse } from \"./parse\";".to_owned(),
        FixtureKind::Config => "version: 1".to_owned(),
        FixtureKind::Markdown => "# Synthetic anchor document".to_owned(),
    };
    lines[1] = match kind {
        FixtureKind::Rust => "use unused::Synthetic;".to_owned(),
        FixtureKind::TypeScript => "import { unused } from \"./unused\";".to_owned(),
        FixtureKind::Config => "unused_setting: true".to_owned(),
        FixtureKind::Markdown => "Unused introductory sentence.".to_owned(),
    };
    lines[4.min(position.index().saturating_sub(2))] = String::new();
    let token_index = position.index();
    lines[token_index - 1] = "ANCHOR_CONTEXT_BEFORE".to_owned();
    lines[token_index] = kind.token_line(&token.canonical);
    lines[token_index + 1] = "ANCHOR_CONTEXT_AFTER".to_owned();
    Document {
        lines,
        newline: Newline::Lf,
        terminated: true,
    }
}

fn facts(
    normal_token_preserving: bool,
    semantic_role_moved: bool,
    token_bytes_changed: bool,
    adjacent_context_changed: bool,
    only_absolute_line_changed: bool,
) -> ScenarioFacts {
    ScenarioFacts {
        token_bytes_changed,
        semantic_role_moved,
        only_absolute_line_changed,
        adjacent_context_changed,
        normal_token_preserving,
    }
}

#[allow(clippy::too_many_arguments)]
fn content_case(
    id: impl Into<String>,
    suite: &'static str,
    kind: FixtureKind,
    baseline: Document,
    edited: Document,
    tokens: Vec<TokenRecord>,
    expected: Classification,
    scenario_facts: ScenarioFacts,
) -> ContentCase {
    ContentCase {
        id: id.into(),
        suite,
        baseline: one_file("file-main", kind.path(), &baseline),
        edited: one_file("file-main", kind.path(), &edited),
        tokens,
        expected,
        expected_failed_anchors: None,
        facts: scenario_facts,
    }
}

fn atomic_cases(token: &TokenRecord) -> Vec<ContentCase> {
    let base = fixture_document(FixtureKind::Rust, Position::Middle, token);
    let token_index = Position::Middle.index();
    let mut cases = Vec::new();
    let mut deferred = Vec::new();
    {
        let mut add = |id: &str,
                       edited: Document,
                       expected: Classification,
                       scenario_facts: ScenarioFacts| {
            cases.push(content_case(
                format!("single/{id}"),
                "single",
                FixtureKind::Rust,
                base.clone(),
                edited,
                vec![token.clone()],
                expected,
                scenario_facts,
            ));
        };

        let mut edited = base.clone();
        edited.lines.insert(2, "use synthetic::Added;".to_owned());
        add(
            "01-insert-one-import-before",
            edited,
            Classification::RejectAbsoluteLineShiftOnly,
            facts(true, false, false, false, true),
        );

        let mut edited = base.clone();
        edited.lines.splice(
            2..2,
            [
                "use synthetic::First;".to_owned(),
                "use synthetic::Second;".to_owned(),
                "use synthetic::Third;".to_owned(),
            ],
        );
        add(
            "02-insert-several-imports-before",
            edited,
            Classification::RejectAbsoluteLineShiftOnly,
            facts(true, false, false, false, true),
        );

        let mut edited = base.clone();
        edited.lines.remove(1);
        add(
            "03-remove-unused-import-before",
            edited,
            Classification::RejectAbsoluteLineShiftOnly,
            facts(true, false, false, false, true),
        );

        let mut edited = base.clone();
        edited.lines.splice(
            8..8,
            [
                "fn added_helper() {".to_owned(),
                "    synthetic_work();".to_owned(),
                "}".to_owned(),
            ],
        );
        add(
            "04-insert-helper-before",
            edited,
            Classification::RejectAbsoluteLineShiftOnly,
            facts(true, false, false, false, true),
        );

        let mut helper_base = base.clone();
        helper_base.lines.splice(
            8..8,
            [
                "fn removable_helper() {".to_owned(),
                "    synthetic_work();".to_owned(),
                "}".to_owned(),
            ],
        );
        let mut edited = helper_base.clone();
        edited.lines.drain(8..11);
        deferred.push(content_case(
            "single/05-delete-helper-before",
            "single",
            FixtureKind::Rust,
            helper_base,
            edited,
            vec![token.clone()],
            Classification::RejectAbsoluteLineShiftOnly,
            facts(true, false, false, false, true),
        ));

        let mut edited = base.clone();
        edited
            .lines
            .insert(12, "// inserted explanation".to_owned());
        add(
            "06-insert-comment-before",
            edited,
            Classification::RejectAbsoluteLineShiftOnly,
            facts(true, false, false, false, true),
        );

        let mut comment_base = base.clone();
        comment_base
            .lines
            .insert(12, "// removable explanation".to_owned());
        let mut edited = comment_base.clone();
        edited.lines.remove(12);
        deferred.push(content_case(
            "single/07-remove-comment-before",
            "single",
            FixtureKind::Rust,
            comment_base,
            edited,
            vec![token.clone()],
            Classification::RejectAbsoluteLineShiftOnly,
            facts(true, false, false, false, true),
        ));

        let mut edited = base.clone();
        edited.lines.splice(
            14..15,
            [
                "let expanded = call(".to_owned(),
                "    first,".to_owned(),
                "    second,".to_owned(),
                ");".to_owned(),
            ],
        );
        add(
            "08-expand-one-line-before",
            edited,
            Classification::RejectAbsoluteLineShiftOnly,
            facts(true, false, false, false, true),
        );

        let mut collapse_base = base.clone();
        collapse_base.lines.splice(
            14..15,
            [
                "let collapsed = call(".to_owned(),
                "    first,".to_owned(),
                "    second,".to_owned(),
                ");".to_owned(),
            ],
        );
        let mut edited = collapse_base.clone();
        edited
            .lines
            .splice(14..18, ["let collapsed = call(first, second);".to_owned()]);
        deferred.push(content_case(
            "single/09-collapse-pre-token-lines",
            "single",
            FixtureKind::Rust,
            collapse_base,
            edited,
            vec![token.clone()],
            Classification::RejectAbsoluteLineShiftOnly,
            facts(true, false, false, false, true),
        ));

        let mut edited = base.clone();
        edited.lines[10] = "let same_height = revised_algorithm();".to_owned();
        add(
            "10-modify-bytes-before-same-line-count",
            edited,
            Classification::PassUnderCurrentStandard,
            facts(true, false, false, false, false),
        );

        let mut edited = base.clone();
        edited.lines.extend([
            "fn appended() {".to_owned(),
            "    synthetic_work();".to_owned(),
            "}".to_owned(),
        ]);
        add(
            "11-append-function-after",
            edited,
            Classification::PassUnderCurrentStandard,
            facts(true, false, false, false, false),
        );

        let mut edited = base.clone();
        edited.lines.truncate(55);
        add(
            "12-delete-lines-after",
            edited,
            Classification::PassUnderCurrentStandard,
            facts(true, false, false, false, false),
        );

        let mut edited = base.clone();
        edited.lines.push("// appended comment".to_owned());
        add(
            "13-append-comment-after",
            edited,
            Classification::PassUnderCurrentStandard,
            facts(true, false, false, false, false),
        );

        let mut edited = base.clone();
        edited.lines[45] = "// unrelated later edit".to_owned();
        add(
            "14-edit-unrelated-line-after",
            edited,
            Classification::PassUnderCurrentStandard,
            facts(true, false, false, false, false),
        );

        let mut edited = base.clone();
        edited.lines[token_index - 1] = "CHANGED_CONTEXT_BEFORE".to_owned();
        add(
            "15-edit-immediate-preceding-context",
            edited,
            Classification::RejectContextBoundary,
            facts(true, false, false, true, false),
        );

        let mut edited = base.clone();
        edited.lines[token_index + 1] = "CHANGED_CONTEXT_AFTER".to_owned();
        add(
            "16-edit-immediate-following-context",
            edited,
            Classification::RejectContextBoundary,
            facts(true, false, false, true, false),
        );

        let mut edited = base.clone();
        edited
            .lines
            .insert(token_index, "inserted between context and token".to_owned());
        add(
            "17-insert-between-preceding-and-token",
            edited,
            Classification::RejectContextBoundary,
            facts(true, false, false, true, false),
        );

        let mut edited = base.clone();
        edited.lines.insert(
            token_index + 1,
            "inserted between token and context".to_owned(),
        );
        add(
            "18-insert-between-token-and-following",
            edited,
            Classification::RejectContextBoundary,
            facts(true, false, false, true, false),
        );

        let mut edited = base.clone();
        let token_line = edited.lines.remove(token_index);
        edited.lines.insert(20, token_line);
        add(
            "19-move-token-line-upward",
            edited,
            Classification::RejectSecurityMaterial,
            facts(false, true, false, true, false),
        );

        let mut edited = base.clone();
        let token_line = edited.lines.remove(token_index);
        edited.lines.insert(40, token_line);
        add(
            "20-move-token-line-downward",
            edited,
            Classification::RejectSecurityMaterial,
            facts(false, true, false, true, false),
        );

        let mut edited = base.clone();
        let without = edited.lines[token_index].replace(&token.canonical, "");
        edited.lines[token_index] = format!("{} {without}", token.canonical);
        add(
            "21-move-token-within-line",
            edited,
            Classification::RejectTokenStructure,
            facts(false, true, false, false, false),
        );

        let mut edited = base.clone();
        edited.lines[token_index] = format!("  {}", edited.lines[token_index]);
        add(
            "22-change-whitespace-token-line",
            edited,
            Classification::RejectTokenStructure,
            facts(true, false, false, false, false),
        );

        let mut edited = base.clone();
        edited.lines[18] = format!("    {}", edited.lines[18]);
        add(
            "23-change-whitespace-away",
            edited,
            Classification::PassUnderCurrentStandard,
            facts(true, false, false, false, false),
        );

        let mut edited = base.clone();
        edited.lines.insert(token_index, String::new());
        add(
            "24-add-blank-line-before-token",
            edited,
            Classification::RejectContextBoundary,
            facts(true, false, false, true, false),
        );

        let mut edited = base.clone();
        edited.lines.insert(token_index + 1, String::new());
        add(
            "25-add-blank-line-after-token",
            edited,
            Classification::RejectContextBoundary,
            facts(true, false, false, true, false),
        );
    }
    cases.append(&mut deferred);
    cases
}

fn position_cases(token: &TokenRecord) -> Vec<ContentCase> {
    let families: [(&str, Classification); 10] = [
        (
            "insert-one-before",
            Classification::RejectAbsoluteLineShiftOnly,
        ),
        (
            "insert-helper-before",
            Classification::RejectAbsoluteLineShiftOnly,
        ),
        (
            "delete-line-before",
            Classification::RejectAbsoluteLineShiftOnly,
        ),
        (
            "expand-line-before",
            Classification::RejectAbsoluteLineShiftOnly,
        ),
        (
            "collapse-lines-before",
            Classification::RejectAbsoluteLineShiftOnly,
        ),
        (
            "same-count-edit-before",
            Classification::PassUnderCurrentStandard,
        ),
        (
            "indent-away-before",
            Classification::PassUnderCurrentStandard,
        ),
        ("edit-away-after", Classification::PassUnderCurrentStandard),
        ("append-after", Classification::PassUnderCurrentStandard),
        (
            "edit-immediate-context",
            Classification::RejectContextBoundary,
        ),
    ];
    let mut cases = Vec::new();
    for (family_index, (family, expected)) in families.into_iter().enumerate() {
        for (position_index, position) in Position::ALL.into_iter().enumerate() {
            let kind = FixtureKind::ALL[(family_index + position_index) % FixtureKind::ALL.len()];
            let mut baseline = fixture_document(kind, position, token);
            let mut edited = baseline.clone();
            match family {
                "insert-one-before" => edited.lines.insert(2, "inserted line".to_owned()),
                "insert-helper-before" => {
                    edited
                        .lines
                        .splice(2..2, ["helper start".to_owned(), "helper end".to_owned()]);
                }
                "delete-line-before" => {
                    edited.lines.remove(1);
                }
                "expand-line-before" => {
                    edited.lines.splice(
                        2..3,
                        ["expanded start".to_owned(), "expanded end".to_owned()],
                    );
                }
                "collapse-lines-before" => {
                    baseline.lines.splice(
                        1..2,
                        ["collapse start".to_owned(), "collapse end".to_owned()],
                    );
                    edited = baseline.clone();
                    edited.lines.splice(1..3, ["collapsed".to_owned()]);
                }
                "same-count-edit-before" => edited.lines[2] = "same count rewrite".to_owned(),
                "indent-away-before" => edited.lines[2] = format!("  {}", edited.lines[2]),
                "edit-away-after" => {
                    let target = position.index() + 2;
                    edited.lines[target] = "later same-count rewrite".to_owned();
                }
                "append-after" => edited.lines.push("appended after all runs".to_owned()),
                "edit-immediate-context" => {
                    edited.lines[position.index() - 1] = "changed immediate context".to_owned();
                }
                _ => unreachable!("closed position family"),
            }
            let is_absolute = expected == Classification::RejectAbsoluteLineShiftOnly;
            let is_context = expected == Classification::RejectContextBoundary;
            cases.push(content_case(
                format!("position/{family}/{}", position.label()),
                "position",
                kind,
                baseline,
                edited,
                vec![token.clone()],
                expected,
                facts(true, false, false, is_context, is_absolute),
            ));
        }
    }
    cases
}

fn formatter_cases(token: &TokenRecord) -> Vec<ContentCase> {
    let mut cases = Vec::new();
    let mut push = |id: &str,
                    kind: FixtureKind,
                    baseline: Document,
                    edited: Document,
                    expected: Classification,
                    context_changed: bool,
                    absolute_only: bool| {
        cases.push(content_case(
            format!("formatter/{id}"),
            "formatter",
            kind,
            baseline,
            edited,
            vec![token.clone()],
            expected,
            facts(true, false, false, context_changed, absolute_only),
        ));
    };
    let baseline = fixture_document(FixtureKind::TypeScript, Position::Middle, token);

    let mut edited = baseline.clone();
    edited.lines.swap(0, 1);
    push(
        "import-reordering-before-same-count",
        FixtureKind::TypeScript,
        baseline.clone(),
        edited,
        Classification::PassUnderCurrentStandard,
        false,
        false,
    );

    let mut edited = baseline.clone();
    edited.lines.insert(2, String::new());
    push(
        "import-regrouping-adds-blank-before",
        FixtureKind::TypeScript,
        baseline.clone(),
        edited,
        Classification::RejectAbsoluteLineShiftOnly,
        false,
        true,
    );

    let mut blank_base = baseline.clone();
    blank_base.lines.insert(3, String::new());
    let mut edited = blank_base.clone();
    edited.lines.remove(3);
    push(
        "blank-line-removal-before",
        FixtureKind::TypeScript,
        blank_base,
        edited,
        Classification::RejectAbsoluteLineShiftOnly,
        false,
        true,
    );

    let mut edited = baseline.clone();
    edited.lines.splice(
        8..9,
        [
            "call(".to_owned(),
            "  first,".to_owned(),
            "  second,".to_owned(),
            ");".to_owned(),
        ],
    );
    push(
        "multiline-call-expansion-before",
        FixtureKind::TypeScript,
        baseline.clone(),
        edited,
        Classification::RejectAbsoluteLineShiftOnly,
        false,
        true,
    );

    let mut edited = baseline.clone();
    edited.lines.splice(
        10..11,
        [
            "const options = {".to_owned(),
            "  enabled: true,".to_owned(),
            "};".to_owned(),
        ],
    );
    push(
        "object-formatting-before",
        FixtureKind::TypeScript,
        baseline.clone(),
        edited,
        Classification::RejectAbsoluteLineShiftOnly,
        false,
        true,
    );

    let mut markdown = fixture_document(FixtureKind::Markdown, Position::Middle, token);
    let markdown_base = markdown.clone();
    markdown.lines.splice(
        12..13,
        [
            "Wrapped comment first line.".to_owned(),
            "Wrapped comment second line.".to_owned(),
        ],
    );
    push(
        "comment-wrapping-before",
        FixtureKind::Markdown,
        markdown_base,
        markdown,
        Classification::RejectAbsoluteLineShiftOnly,
        false,
        true,
    );

    let mut edited = baseline.clone();
    edited.lines[14] = format!("  {}", edited.lines[14]);
    push(
        "indentation-only-before-away",
        FixtureKind::TypeScript,
        baseline.clone(),
        edited,
        Classification::PassUnderCurrentStandard,
        false,
        false,
    );

    let mut edited = baseline.clone();
    edited.lines.splice(
        40..41,
        [
            "laterCall(".to_owned(),
            "  first,".to_owned(),
            "  second,".to_owned(),
            ");".to_owned(),
        ],
    );
    push(
        "multiline-call-expansion-after",
        FixtureKind::TypeScript,
        baseline.clone(),
        edited,
        Classification::PassUnderCurrentStandard,
        false,
        false,
    );

    let mut edited = baseline.clone();
    edited.lines.insert(45, String::new());
    push(
        "blank-line-insertion-after-away",
        FixtureKind::TypeScript,
        baseline.clone(),
        edited,
        Classification::PassUnderCurrentStandard,
        false,
        false,
    );

    let mut after_blank = baseline.clone();
    after_blank.lines.insert(45, String::new());
    let mut edited = after_blank.clone();
    edited.lines.remove(45);
    push(
        "blank-line-removal-after-away",
        FixtureKind::TypeScript,
        after_blank,
        edited,
        Classification::PassUnderCurrentStandard,
        false,
        false,
    );

    let mut edited = baseline.clone();
    edited.lines[44] = format!("    {}", edited.lines[44]);
    push(
        "indentation-only-after-away",
        FixtureKind::TypeScript,
        baseline.clone(),
        edited,
        Classification::PassUnderCurrentStandard,
        false,
        false,
    );

    let mut edited = baseline.clone();
    edited.lines[Position::Middle.index() - 1] = "formatted immediate before".to_owned();
    push(
        "immediate-preceding-format",
        FixtureKind::TypeScript,
        baseline.clone(),
        edited,
        Classification::RejectContextBoundary,
        true,
        false,
    );

    let mut edited = baseline.clone();
    edited.lines[Position::Middle.index() + 1] = "formatted immediate after".to_owned();
    push(
        "immediate-following-format",
        FixtureKind::TypeScript,
        baseline.clone(),
        edited,
        Classification::RejectContextBoundary,
        true,
        false,
    );

    let mut edited = baseline.clone();
    edited.lines[Position::Middle.index()] =
        format!("  {}", edited.lines[Position::Middle.index()]);
    push(
        "token-line-indentation",
        FixtureKind::TypeScript,
        baseline.clone(),
        edited,
        Classification::RejectTokenStructure,
        false,
        false,
    );

    let mut unterminated = baseline.clone();
    unterminated.terminated = false;
    let mut edited = unterminated.clone();
    edited.terminated = true;
    push(
        "trailing-newline-after-away",
        FixtureKind::TypeScript,
        unterminated,
        edited,
        Classification::PassUnderCurrentStandard,
        false,
        false,
    );

    let mut near_eof = fixture_document(FixtureKind::Markdown, Position::NearEof, token);
    near_eof.lines.truncate(Position::NearEof.index() + 2);
    near_eof.terminated = false;
    let mut edited = near_eof.clone();
    edited.terminated = true;
    push(
        "trailing-newline-changes-following-context",
        FixtureKind::Markdown,
        near_eof,
        edited,
        Classification::RejectContextBoundary,
        true,
        false,
    );

    let mut crlf = fixture_document(FixtureKind::Config, Position::Middle, token);
    crlf.newline = Newline::Crlf;
    let mut edited = crlf.clone();
    edited.newline = Newline::Lf;
    push(
        "full-file-crlf-to-lf",
        FixtureKind::Config,
        crlf,
        edited,
        Classification::RejectTokenStructure,
        true,
        false,
    );

    cases
}

fn refactor_cases(token: &TokenRecord) -> Vec<ContentCase> {
    let baseline = fixture_document(FixtureKind::Rust, Position::Middle, token);
    let mut cases = Vec::new();
    let mut push = |id: &str,
                    base: Document,
                    edited: Document,
                    expected: Classification,
                    absolute_only: bool| {
        cases.push(content_case(
            format!("refactor/{id}"),
            "refactor",
            FixtureKind::Rust,
            base,
            edited,
            vec![token.clone()],
            expected,
            facts(true, false, false, false, absolute_only),
        ));
    };

    let mut edited = baseline.clone();
    edited.lines[8] = "let renamed_local = prior_local;".to_owned();
    push(
        "rename-local-away",
        baseline.clone(),
        edited,
        Classification::PassUnderCurrentStandard,
        false,
    );

    let mut edited = baseline.clone();
    edited.lines[10] = "fn rewritten() { revised(); }".to_owned();
    push(
        "rewrite-function-away-same-count",
        baseline.clone(),
        edited,
        Classification::PassUnderCurrentStandard,
        false,
    );

    let mut edited = baseline.clone();
    edited.lines.swap(12, 14);
    push(
        "reorder-token-free-helpers",
        baseline.clone(),
        edited,
        Classification::PassUnderCurrentStandard,
        false,
    );

    let mut edited = baseline.clone();
    edited.lines.splice(
        16..16,
        [
            "fn extracted_before() {".to_owned(),
            "    work();".to_owned(),
            "}".to_owned(),
        ],
    );
    push(
        "extract-helper-before",
        baseline.clone(),
        edited,
        Classification::RejectAbsoluteLineShiftOnly,
        true,
    );

    let mut edited = baseline.clone();
    edited.lines.splice(
        42..42,
        [
            "fn extracted_after() {".to_owned(),
            "    work();".to_owned(),
            "}".to_owned(),
        ],
    );
    push(
        "extract-helper-after",
        baseline.clone(),
        edited,
        Classification::PassUnderCurrentStandard,
        false,
    );

    let mut inline_before = baseline.clone();
    inline_before.lines.splice(
        16..16,
        [
            "fn inline_before() {".to_owned(),
            "    work();".to_owned(),
            "}".to_owned(),
        ],
    );
    let mut edited = inline_before.clone();
    edited.lines.drain(16..19);
    push(
        "inline-helper-before",
        inline_before,
        edited,
        Classification::RejectAbsoluteLineShiftOnly,
        true,
    );

    let mut inline_after = baseline.clone();
    inline_after.lines.splice(
        42..42,
        [
            "fn inline_after() {".to_owned(),
            "    work();".to_owned(),
            "}".to_owned(),
        ],
    );
    let mut edited = inline_after.clone();
    edited.lines.drain(42..45);
    push(
        "inline-helper-after",
        inline_after,
        edited,
        Classification::PassUnderCurrentStandard,
        false,
    );

    let mut edited = baseline.clone();
    edited.lines[18] = "let result = replacement_same_height();".to_owned();
    push(
        "replace-algorithm-same-line-count-before",
        baseline.clone(),
        edited,
        Classification::PassUnderCurrentStandard,
        false,
    );

    let mut edited = baseline.clone();
    edited.lines.splice(
        18..19,
        [
            "let result = replacement(".to_owned(),
            "    input,".to_owned(),
            ");".to_owned(),
        ],
    );
    push(
        "replace-algorithm-different-line-count-before",
        baseline.clone(),
        edited,
        Classification::RejectAbsoluteLineShiftOnly,
        true,
    );

    let mut edited = baseline.clone();
    edited.lines.splice(
        44..45,
        [
            "let later = replacement(".to_owned(),
            "    input,".to_owned(),
            ");".to_owned(),
        ],
    );
    push(
        "replace-algorithm-after",
        baseline,
        edited,
        Classification::PassUnderCurrentStandard,
        false,
    );

    cases
}

fn multi_document(layout: &[usize], tokens: &[TokenRecord]) -> Document {
    assert_eq!(layout.len(), tokens.len());
    let mut lines: Vec<String> = (0..40)
        .map(|index| format!("// multi-run synthetic line {index:02}"))
        .collect();
    let mut grouped: BTreeMap<usize, Vec<&TokenRecord>> = BTreeMap::new();
    for (line, token) in layout.iter().zip(tokens) {
        grouped.entry(*line).or_default().push(token);
    }
    let token_lines: BTreeSet<usize> = grouped.keys().copied().collect();
    for (line, line_tokens) in grouped {
        lines[line] = line_tokens
            .iter()
            .enumerate()
            .map(|(index, token)| format!("slot_{index}=\"{}\";", token.canonical))
            .collect::<Vec<_>>()
            .join(" ");
        if line > 0 && !token_lines.contains(&(line - 1)) {
            lines[line - 1] = format!("MULTI_CONTEXT_LINE_{}", line - 1);
        }
        if line + 1 < lines.len() && !token_lines.contains(&(line + 1)) {
            lines[line + 1] = format!("MULTI_CONTEXT_LINE_{}", line + 1);
        }
    }
    Document {
        lines,
        newline: Newline::Lf,
        terminated: true,
    }
}

fn with_failed_anchors(mut case: ContentCase, anchors: &[&str]) -> ContentCase {
    case.expected_failed_anchors = Some(anchors.iter().map(|value| (*value).to_owned()).collect());
    case
}

fn multiple_run_cases(tokens: &[TokenRecord]) -> Vec<ContentCase> {
    let topologies: [(&str, &[usize], &[&str]); 5] = [
        ("A-same-line", &[10, 10], &["file-main:L11-L11"]),
        ("B-consecutive", &[10, 11], &["file-main:L11-L12"]),
        (
            "C-one-separator",
            &[10, 12],
            &["file-main:L11-L11", "file-main:L13-L13"],
        ),
        (
            "D-many-separators",
            &[8, 20],
            &["file-main:L9-L9", "file-main:L21-L21"],
        ),
        (
            "E-three-runs",
            &[6, 18, 30],
            &["file-main:L7-L7", "file-main:L19-L19", "file-main:L31-L31"],
        ),
    ];
    let mut cases = Vec::new();
    for (name, layout, anchors) in topologies {
        let selected = tokens[..layout.len()].to_vec();
        let baseline = multi_document(layout, &selected);
        let mut edited = baseline.clone();
        edited
            .lines
            .insert(1, "inserted before all runs".to_owned());
        cases.push(with_failed_anchors(
            content_case(
                format!("multiple/{name}/before-all"),
                "multiple",
                FixtureKind::Rust,
                baseline.clone(),
                edited,
                selected.clone(),
                Classification::RejectAbsoluteLineShiftOnly,
                facts(true, false, false, false, true),
            ),
            anchors,
        ));

        let mut edited = baseline.clone();
        edited.lines.push("inserted after all runs".to_owned());
        cases.push(content_case(
            format!("multiple/{name}/after-all"),
            "multiple",
            FixtureKind::Rust,
            baseline.clone(),
            edited,
            selected.clone(),
            Classification::PassUnderCurrentStandard,
            facts(true, false, false, false, false),
        ));

        match name {
            "C-one-separator" => {
                let mut edited = baseline.clone();
                edited
                    .lines
                    .insert(12, "inserted adjacent to run two".to_owned());
                cases.push(with_failed_anchors(
                    content_case(
                        "multiple/C-one-separator/between-runs",
                        "multiple",
                        FixtureKind::Rust,
                        baseline,
                        edited,
                        selected,
                        Classification::RejectContextBoundary,
                        facts(true, false, false, true, false),
                    ),
                    &[anchors[1]],
                ));
            }
            "D-many-separators" => {
                let mut edited = baseline.clone();
                edited
                    .lines
                    .insert(14, "inserted between distant runs".to_owned());
                cases.push(with_failed_anchors(
                    content_case(
                        "multiple/D-many-separators/between-runs",
                        "multiple",
                        FixtureKind::Rust,
                        baseline,
                        edited,
                        selected,
                        Classification::RejectAbsoluteLineShiftOnly,
                        facts(true, false, false, false, true),
                    ),
                    &[anchors[1]],
                ));
            }
            "E-three-runs" => {
                let mut between_one_two = baseline.clone();
                between_one_two
                    .lines
                    .insert(12, "inserted between run one and two".to_owned());
                cases.push(with_failed_anchors(
                    content_case(
                        "multiple/E-three-runs/between-run-1-2",
                        "multiple",
                        FixtureKind::Rust,
                        baseline.clone(),
                        between_one_two,
                        selected.clone(),
                        Classification::RejectAbsoluteLineShiftOnly,
                        facts(true, false, false, false, true),
                    ),
                    &[anchors[1], anchors[2]],
                ));
                let mut between_two_three = baseline.clone();
                between_two_three
                    .lines
                    .insert(24, "inserted between run two and three".to_owned());
                cases.push(with_failed_anchors(
                    content_case(
                        "multiple/E-three-runs/between-run-2-3",
                        "multiple",
                        FixtureKind::Rust,
                        baseline,
                        between_two_three,
                        selected,
                        Classification::RejectAbsoluteLineShiftOnly,
                        facts(true, false, false, false, true),
                    ),
                    &[anchors[2]],
                ));
            }
            _ => {}
        }
    }
    cases
}

fn service_block(name: &str) -> Vec<String> {
    vec![
        format!("service {name} {{"),
        "  endpoint = synthetic".to_owned(),
        "  enabled = true".to_owned(),
        "}".to_owned(),
    ]
}

fn repeated_block_cases(token: &TokenRecord) -> Vec<ContentCase> {
    let mut lines = vec!["# repeated synthetic services".to_owned()];
    lines.extend(service_block("A"));
    lines.extend(service_block("B"));
    lines.push("REPEATED_CONTEXT_BEFORE".to_owned());
    lines.push(format!(
        "service TOKEN {{ credential = {} }}",
        token.canonical
    ));
    lines.push("REPEATED_CONTEXT_AFTER".to_owned());
    lines.extend(service_block("C"));
    lines.push("# end".to_owned());
    let baseline = Document {
        lines,
        newline: Newline::Lf,
        terminated: true,
    };
    let token_line = 10;
    let mut cases = Vec::new();

    let mut edited = baseline.clone();
    let first = edited.lines[1..5].to_vec();
    let second = edited.lines[5..9].to_vec();
    edited.lines.splice(1..9, second.into_iter().chain(first));
    cases.push(content_case(
        "repeated/reorder-token-free-similar-blocks",
        "repeated",
        FixtureKind::Config,
        baseline.clone(),
        edited,
        vec![token.clone()],
        Classification::PassUnderCurrentStandard,
        facts(true, false, false, false, false),
    ));

    let mut edited = baseline.clone();
    edited.lines.splice(9..9, service_block("NEW"));
    cases.push(content_case(
        "repeated/insert-similar-block-before-token",
        "repeated",
        FixtureKind::Config,
        baseline.clone(),
        edited,
        vec![token.clone()],
        Classification::RejectAbsoluteLineShiftOnly,
        facts(true, false, false, false, true),
    ));

    let mut edited = baseline.clone();
    edited.lines.splice(9..9, service_block("A-COPY"));
    cases.push(content_case(
        "repeated/duplicate-token-free-block-before-token",
        "repeated",
        FixtureKind::Config,
        baseline.clone(),
        edited,
        vec![token.clone()],
        Classification::RejectAbsoluteLineShiftOnly,
        facts(true, false, false, false, true),
    ));

    let mut edited = baseline.clone();
    let moved: Vec<String> = edited
        .lines
        .drain(token_line - 1..=token_line + 1)
        .collect();
    let insertion = edited.lines.len() - 1;
    edited.lines.splice(insertion..insertion, moved);
    cases.push(content_case(
        "repeated/move-token-block",
        "repeated",
        FixtureKind::Config,
        baseline.clone(),
        edited,
        vec![token.clone()],
        Classification::RejectSecurityMaterial,
        facts(false, true, false, false, false),
    ));

    let mut edited = baseline.clone();
    edited.lines[7] = "  enabled = revised".to_owned();
    cases.push(content_case(
        "repeated/modify-nearby-similar-block",
        "repeated",
        FixtureKind::Config,
        baseline,
        edited,
        vec![token.clone()],
        Classification::PassUnderCurrentStandard,
        facts(true, false, false, false, false),
    ));
    cases
}

fn movement_cases(tokens: &[TokenRecord]) -> Vec<ContentCase> {
    let token = &tokens[0];
    let baseline = fixture_document(FixtureKind::Rust, Position::Middle, token);
    let token_index = Position::Middle.index();
    let mut cases = Vec::new();

    let mut edited = baseline.clone();
    let line = edited.lines.remove(token_index);
    edited.lines.insert(token_index + 6, line);
    cases.push(content_case(
        "movement/move-protected-run-identical-bytes",
        "movement",
        FixtureKind::Rust,
        baseline.clone(),
        edited,
        vec![token.clone()],
        Classification::RejectSecurityMaterial,
        facts(false, true, false, true, false),
    ));

    let mut edited = baseline.clone();
    let block: Vec<String> = edited
        .lines
        .drain(token_index - 1..=token_index + 1)
        .collect();
    edited.lines.splice(token_index + 5..token_index + 5, block);
    cases.push(content_case(
        "movement/move-run-and-both-context-lines",
        "movement",
        FixtureKind::Rust,
        baseline.clone(),
        edited,
        vec![token.clone()],
        Classification::RejectSecurityMaterial,
        facts(false, true, false, false, false),
    ));

    let mut edited = baseline.clone();
    let copied = edited.lines[token_index - 1..=token_index + 1].to_vec();
    edited
        .lines
        .splice(token_index + 8..token_index + 8, copied);
    edited.lines.drain(token_index - 1..=token_index + 1);
    cases.push(content_case(
        "movement/copy-identical-block-elsewhere-delete-original",
        "movement",
        FixtureKind::Rust,
        baseline.clone(),
        edited,
        vec![token.clone()],
        Classification::RejectSecurityMaterial,
        facts(false, true, false, false, false),
    ));

    let mut edited = baseline.clone();
    let copied = edited.lines[token_index - 1..=token_index + 1].to_vec();
    edited
        .lines
        .splice(token_index + 8..token_index + 8, copied);
    cases.push(content_case(
        "movement/duplicate-protected-context-block",
        "movement",
        FixtureKind::Rust,
        baseline.clone(),
        edited,
        vec![token.clone()],
        Classification::RejectTokenStructure,
        facts(false, true, false, false, false),
    ));

    let pair = tokens[..2].to_vec();
    let mut two_block = multi_document(&[10, 20], &pair);
    two_block.lines[9] = "IDENTICAL_CONTEXT_BEFORE".to_owned();
    two_block.lines[11] = "IDENTICAL_CONTEXT_AFTER".to_owned();
    two_block.lines[19] = "IDENTICAL_CONTEXT_BEFORE".to_owned();
    two_block.lines[21] = "IDENTICAL_CONTEXT_AFTER".to_owned();
    let mut edited = two_block.clone();
    edited.lines.swap(10, 20);
    cases.push(content_case(
        "movement/swap-skeleton-identical-token-blocks",
        "movement",
        FixtureKind::Rust,
        two_block,
        edited,
        pair,
        Classification::RejectSecurityMaterial,
        facts(false, true, false, false, false),
    ));

    let same_line_pair = tokens[..2].to_vec();
    let same_line = multi_document(&[10, 10], &same_line_pair);
    let mut edited = same_line.clone();
    edited.lines[10] = edited.lines[10]
        .replace(&same_line_pair[0].canonical, "SYNTHETIC_FIRST_TOKEN_SLOT")
        .replace(&same_line_pair[1].canonical, &same_line_pair[0].canonical)
        .replace("SYNTHETIC_FIRST_TOKEN_SLOT", &same_line_pair[1].canonical);
    cases.push(content_case(
        "movement/reorder-two-tokens-within-one-run",
        "movement",
        FixtureKind::Rust,
        same_line,
        edited,
        same_line_pair,
        Classification::RejectTokenStructure,
        facts(false, true, false, false, false),
    ));

    let mut source = baseline.clone();
    let moved_line = source.lines.remove(token_index);
    let target = Document {
        lines: vec![
            "target context before".to_owned(),
            moved_line,
            "target context after".to_owned(),
        ],
        newline: Newline::Lf,
        terminated: true,
    };
    let baseline_workspace = one_file("file-main", FixtureKind::Rust.path(), &baseline);
    let mut edited_workspace = one_file("file-main", FixtureKind::Rust.path(), &source);
    edited_workspace.push(FileImage {
        file_id: "file-other".to_owned(),
        safe_path: "src/other.rs".to_owned(),
        bytes: target.bytes(),
    });
    cases.push(ContentCase {
        id: "movement/move-token-to-another-file".to_owned(),
        suite: "movement",
        baseline: baseline_workspace,
        edited: edited_workspace,
        tokens: vec![token.clone()],
        expected: Classification::RejectPathOrFileMovement,
        expected_failed_anchors: None,
        facts: facts(false, true, false, true, false),
    });

    let mut moved_path = one_file("file-main", "src/renamed.rs", &baseline);
    moved_path[0].file_id = "file-main".to_owned();
    cases.push(ContentCase {
        id: "movement/move-file-path-containing-token".to_owned(),
        suite: "movement",
        baseline: one_file("file-main", FixtureKind::Rust.path(), &baseline),
        edited: moved_path,
        tokens: vec![token.clone()],
        expected: Classification::RejectPathOrFileMovement,
        expected_failed_anchors: None,
        facts: facts(false, true, false, false, false),
    });

    let mut edited = baseline.clone();
    edited.lines[token_index] = edited.lines[token_index].replacen("SECRET", "EMAIL", 1);
    cases.push(content_case(
        "movement/modify-canonical-token-category",
        "movement",
        FixtureKind::Rust,
        baseline,
        edited,
        vec![token.clone()],
        Classification::RejectTokenStructure,
        facts(false, false, true, false, false),
    ));
    cases
}

fn workflow_cases(tokens: &[TokenRecord]) -> Vec<ContentCase> {
    let token = &tokens[0];
    let baseline = fixture_document(FixtureKind::Rust, Position::Middle, token);
    let mut cases = Vec::new();
    let mut deferred = Vec::new();
    {
        let mut push = |number: usize,
                        kind: FixtureKind,
                        base: Document,
                        edited: Document,
                        expected: Classification,
                        absolute_only: bool| {
            cases.push(content_case(
                format!("workflow/bundle-{number:02}"),
                "workflow",
                kind,
                base,
                edited,
                vec![token.clone()],
                expected,
                facts(true, false, false, false, absolute_only),
            ));
        };

        let mut edited = baseline.clone();
        edited.lines.insert(2, "use new::Import;".to_owned());
        edited.lines.splice(
            8..8,
            [
                "fn helper() {".to_owned(),
                "    work();".to_owned(),
                "}".to_owned(),
            ],
        );
        *edited.lines.last_mut().expect("fixture has last line") = "later logic revised".to_owned();
        push(
            1,
            FixtureKind::Rust,
            baseline.clone(),
            edited,
            Classification::RejectAbsoluteLineShiftOnly,
            true,
        );

        let mut edited = baseline.clone();
        edited.lines.insert(4, String::new());
        edited.lines[45] = "ordinary logic below revised".to_owned();
        push(
            2,
            FixtureKind::Rust,
            baseline.clone(),
            edited,
            Classification::RejectAbsoluteLineShiftOnly,
            true,
        );

        let mut edited = baseline.clone();
        edited.lines.splice(
            6..6,
            [
                "fn validate() {".to_owned(),
                "    check();".to_owned(),
                "    confirm();".to_owned(),
                "}".to_owned(),
            ],
        );
        push(
            3,
            FixtureKind::Rust,
            baseline.clone(),
            edited,
            Classification::RejectAbsoluteLineShiftOnly,
            true,
        );

        let markdown = fixture_document(FixtureKind::Markdown, Position::Middle, token);
        let mut edited = markdown.clone();
        edited.lines.splice(
            10..11,
            [
                "Expanded documentation first line.".to_owned(),
                "Expanded documentation second line.".to_owned(),
                "Expanded documentation third line.".to_owned(),
            ],
        );
        push(
            4,
            FixtureKind::Markdown,
            markdown,
            edited,
            Classification::RejectAbsoluteLineShiftOnly,
            true,
        );

        let mut edited = baseline.clone();
        edited.lines[42] = "refactor below part one".to_owned();
        edited.lines[43] = "refactor below part two".to_owned();
        edited.lines[44] = "refactor below part three".to_owned();
        push(
            5,
            FixtureKind::Rust,
            baseline.clone(),
            edited,
            Classification::PassUnderCurrentStandard,
            false,
        );

        let pair = tokens[..2].to_vec();
        let multi = multi_document(&[8, 24], &pair);
        let mut edited = multi.clone();
        edited.lines.splice(
            16..16,
            [
                "fn between() {".to_owned(),
                "    work();".to_owned(),
                "}".to_owned(),
            ],
        );
        let case = content_case(
            "workflow/bundle-06",
            "workflow",
            FixtureKind::Rust,
            multi,
            edited,
            pair,
            Classification::RejectAbsoluteLineShiftOnly,
            facts(true, false, false, false, true),
        );
        deferred.push(case);

        let mut edited = baseline.clone();
        edited.lines.extend([
            "#[test]".to_owned(),
            "fn new_test() {".to_owned(),
            "    assert!(true);".to_owned(),
            "}".to_owned(),
        ]);
        push(
            7,
            FixtureKind::Rust,
            baseline.clone(),
            edited,
            Classification::PassUnderCurrentStandard,
            false,
        );

        let mut edited = baseline.clone();
        edited.lines.remove(1);
        edited.lines.splice(
            8..8,
            [
                "fn extracted() {".to_owned(),
                "    work();".to_owned(),
                "}".to_owned(),
            ],
        );
        push(
            8,
            FixtureKind::Rust,
            baseline.clone(),
            edited,
            Classification::RejectAbsoluteLineShiftOnly,
            true,
        );

        let config = fixture_document(FixtureKind::Config, Position::Middle, token);
        let mut edited = config.clone();
        edited
            .lines
            .insert(8, "unrelated_setting: added".to_owned());
        push(
            9,
            FixtureKind::Config,
            config.clone(),
            edited,
            Classification::RejectAbsoluteLineShiftOnly,
            true,
        );

        let mut edited = config.clone();
        edited
            .lines
            .insert(45, "later_unrelated_setting: added".to_owned());
        push(
            10,
            FixtureKind::Config,
            config,
            edited,
            Classification::PassUnderCurrentStandard,
            false,
        );
    }
    cases.append(&mut deferred);
    cases
}

#[derive(Clone, Debug)]
struct ProjectionCheck {
    matches: bool,
    reason: &'static str,
}

fn content_deletion_projection(
    baseline: &FileImage,
    edited: &FileImage,
    token: &TokenRecord,
) -> ProjectionCheck {
    if !byte_matches(&edited.bytes, token.canonical.as_bytes()).is_empty() {
        return ProjectionCheck {
            matches: false,
            reason: "canonical_token_still_present",
        };
    }
    let anchors = derive_run_anchors(&vec![baseline.clone()], std::slice::from_ref(token));
    let anchor = anchors.first().expect("one baseline deletion anchor");
    let baseline_lines = logical_lines(&baseline.bytes);
    let edited_lines = logical_lines(&edited.bytes);
    let first = anchor.first_line - 1;
    let last = anchor.last_line - 1;
    if last >= edited_lines.len() {
        return ProjectionCheck {
            matches: false,
            reason: "projected_absolute_range_missing",
        };
    }
    let mut expected_lines = Vec::new();
    for line in &baseline_lines[first..=last] {
        let bytes = &baseline.bytes[line.clone()];
        let start = byte_matches(bytes, token.canonical.as_bytes())
            .first()
            .copied()
            .expect("token occurs in projected line");
        let mut expected = bytes.to_vec();
        expected.drain(start..start + token.canonical.len());
        expected_lines.push(expected);
    }
    let actual_lines: Vec<Vec<u8>> = edited_lines[first..=last]
        .iter()
        .map(|line| edited.bytes[line.clone()].to_vec())
        .collect();
    if actual_lines != expected_lines {
        return ProjectionCheck {
            matches: false,
            reason: "projected_protected_line_mismatch",
        };
    }
    let preceding_matches = if first == 0 {
        true
    } else {
        edited_lines.get(first - 1).is_some_and(|line| {
            edited.bytes[line.clone()] == baseline.bytes[baseline_lines[first - 1].clone()]
        })
    };
    let following_matches = if last + 1 == baseline_lines.len() {
        last + 1 == edited_lines.len()
    } else {
        edited_lines.get(last + 1).is_some_and(|line| {
            edited.bytes[line.clone()] == baseline.bytes[baseline_lines[last + 1].clone()]
        })
    };
    if !preceding_matches || !following_matches {
        return ProjectionCheck {
            matches: false,
            reason: "projected_adjacent_context_mismatch",
        };
    }
    ProjectionCheck {
        matches: true,
        reason: "exact_token_bytes_only",
    }
}

#[derive(Clone, Debug)]
struct PathEntry {
    file_id: String,
    parent_id: String,
    components: Vec<String>,
    token_component_index: usize,
    protected_suffix: String,
}

#[derive(Clone, Debug)]
struct PathWorkspace {
    token_entry: PathEntry,
    siblings: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PathAnchor {
    file_id: String,
    parent_id: String,
    components: Vec<String>,
    component_index: usize,
    skeleton: String,
    boundary: Boundary,
    protected_suffix: String,
}

fn derive_path_anchor(entry: &PathEntry, token: &TokenRecord) -> Option<PathAnchor> {
    let component = entry.components.get(entry.token_component_index)?;
    let start = component.find(&token.canonical)?;
    let mut skeleton = component.clone();
    skeleton.replace_range(start..start + token.canonical.len(), "");
    Some(PathAnchor {
        file_id: entry.file_id.clone(),
        parent_id: entry.parent_id.clone(),
        components: entry.components.clone(),
        component_index: entry.token_component_index,
        skeleton,
        boundary: Boundary {
            skeleton_offset: start,
            oid: token.oid,
            category: token.category,
            ordinal: token.ordinal,
        },
        protected_suffix: entry.protected_suffix.clone(),
    })
}

fn path_projection_matches(before: &PathEntry, after: &PathEntry, token: &TokenRecord) -> bool {
    let Some(anchor) = derive_path_anchor(before, token) else {
        return false;
    };
    if before.file_id != after.file_id
        || before.parent_id != after.parent_id
        || before.token_component_index != after.token_component_index
        || before.protected_suffix != after.protected_suffix
        || before.components.len() != after.components.len()
    {
        return false;
    }
    let mut expected = before.components.clone();
    expected[before.token_component_index] = anchor.skeleton;
    expected == after.components
}

#[derive(Clone, Debug)]
pub(crate) struct EvidenceRecord {
    pub(crate) id: String,
    pub(crate) suite: &'static str,
    pub(crate) classification: Classification,
    pub(crate) reason: String,
    pub(crate) token_bytes_changed: bool,
    pub(crate) semantic_role_moved: bool,
    pub(crate) only_absolute_line_changed: bool,
    pub(crate) adjacent_context_changed: bool,
    pub(crate) normal_token_preserving: bool,
    pub(crate) eligible: bool,
    pub(crate) failed_anchors: Vec<String>,
    pub(crate) projection_matches: Option<bool>,
    pub(crate) strict_result: Option<&'static str>,
}

#[derive(Default)]
struct Bounds {
    scenario_count: usize,
    synthetic_paths: BTreeSet<String>,
    max_files_per_scenario: usize,
    max_lines_per_file: usize,
    max_tokens_per_file: usize,
}

impl Bounds {
    fn observe_content(&mut self, case: &ContentCase) {
        self.scenario_count += 1;
        self.max_files_per_scenario = self
            .max_files_per_scenario
            .max(case.baseline.len())
            .max(case.edited.len());
        for file in case.baseline.iter().chain(&case.edited) {
            self.synthetic_paths.insert(file.safe_path.clone());
            self.max_lines_per_file = self
                .max_lines_per_file
                .max(logical_lines(&file.bytes).len());
            let count = case
                .tokens
                .iter()
                .map(|token| byte_matches(&file.bytes, token.canonical.as_bytes()).len())
                .sum();
            self.max_tokens_per_file = self.max_tokens_per_file.max(count);
        }
    }

    fn observe_manual(&mut self, path: &str, lines: usize, tokens: usize) {
        self.scenario_count += 1;
        self.synthetic_paths.insert(path.to_owned());
        self.max_files_per_scenario = self.max_files_per_scenario.max(1);
        self.max_lines_per_file = self.max_lines_per_file.max(lines);
        self.max_tokens_per_file = self.max_tokens_per_file.max(tokens);
    }
}

#[derive(Default)]
struct Laboratory {
    records: Vec<EvidenceRecord>,
    bounds: Bounds,
}

impl Laboratory {
    fn run_content(&mut self, case: ContentCase) {
        self.bounds.observe_content(&case);
        let evaluation = evaluate_content(&case);
        assert_eq!(
            evaluation.classification,
            case.expected,
            "{}: expected {}, actual {}, reason {}",
            case.id,
            case.expected.as_str(),
            evaluation.classification.as_str(),
            evaluation.mismatch.reason()
        );
        assert_eq!(
            evaluation.mismatch.adjacent_context, case.facts.adjacent_context_changed,
            "{}: adjacent-context fact",
            case.id
        );
        assert_eq!(
            evaluation.classification == Classification::RejectAbsoluteLineShiftOnly,
            case.facts.only_absolute_line_changed,
            "{}: absolute-only fact",
            case.id
        );
        if let Some(expected) = &case.expected_failed_anchors {
            let actual_set: BTreeSet<&String> = evaluation.failed_anchors.iter().collect();
            let expected_set: BTreeSet<&String> = expected.iter().collect();
            assert_eq!(actual_set, expected_set, "{}: failed anchors", case.id);
        }
        if !case.facts.token_bytes_changed {
            let edited_occurrences = occurrences(&case.edited, &case.tokens);
            for token_index in 0..case.tokens.len() {
                assert!(
                    edited_occurrences
                        .iter()
                        .any(|item| item.token_index == token_index),
                    "{}: unchanged canonical token remains present",
                    case.id
                );
            }
        }
        self.records.push(EvidenceRecord {
            id: case.id,
            suite: case.suite,
            classification: evaluation.classification,
            reason: evaluation.mismatch.reason(),
            token_bytes_changed: case.facts.token_bytes_changed,
            semantic_role_moved: case.facts.semantic_role_moved,
            only_absolute_line_changed: case.facts.only_absolute_line_changed,
            adjacent_context_changed: case.facts.adjacent_context_changed,
            normal_token_preserving: case.facts.normal_token_preserving,
            eligible: evaluation.classification == Classification::PassUnderCurrentStandard,
            failed_anchors: evaluation.failed_anchors,
            projection_matches: None,
            strict_result: None,
        });
    }

    fn push_manual(&mut self, record: EvidenceRecord, path: &str, lines: usize, tokens: usize) {
        assert_ne!(
            record.classification,
            Classification::Ambiguous,
            "{}",
            record.id
        );
        self.bounds.observe_manual(path, lines, tokens);
        self.records.push(record);
    }
}

fn manual_record(
    id: impl Into<String>,
    suite: &'static str,
    classification: Classification,
    reason: impl Into<String>,
) -> EvidenceRecord {
    EvidenceRecord {
        id: id.into(),
        suite,
        classification,
        reason: reason.into(),
        token_bytes_changed: false,
        semantic_role_moved: false,
        only_absolute_line_changed: false,
        adjacent_context_changed: false,
        normal_token_preserving: false,
        eligible: classification == Classification::PassUnderCurrentStandard,
        failed_anchors: Vec::new(),
        projection_matches: None,
        strict_result: None,
    }
}

fn add_deletion_projection_controls(lab: &mut Laboratory, token: &TokenRecord) {
    let mut baseline_doc = fixture_document(FixtureKind::Config, Position::Middle, token);
    baseline_doc.lines[Position::Middle.index()] = format!("credential: {} ;", token.canonical);
    let baseline_file = &one_file("file-main", FixtureKind::Config.path(), &baseline_doc)[0];
    let index = Position::Middle.index();

    let mut exact = baseline_doc.clone();
    exact.lines[index] = exact.lines[index].replace(&token.canonical, "");
    let exact_file = &one_file("file-main", FixtureKind::Config.path(), &exact)[0];
    let check = content_deletion_projection(baseline_file, exact_file, token);
    assert!(check.matches);
    let mut record = manual_record(
        "deletion/remove-exact-canonical-token-bytes",
        "deletion",
        Classification::RejectSecurityMaterial,
        check.reason,
    );
    record.token_bytes_changed = true;
    record.projection_matches = Some(true);
    lab.push_manual(record, FixtureKind::Config.path(), 60, 1);

    let mut extra_space = baseline_doc.clone();
    extra_space.lines[index] =
        extra_space.lines[index].replace(&format!("{} ", token.canonical), "");
    let extra_file = &one_file("file-main", FixtureKind::Config.path(), &extra_space)[0];
    let check = content_deletion_projection(baseline_file, extra_file, token);
    assert!(!check.matches);
    let mut record = manual_record(
        "deletion/remove-token-plus-adjacent-byte",
        "deletion",
        Classification::RejectTokenStructure,
        check.reason,
    );
    record.token_bytes_changed = true;
    record.projection_matches = Some(false);
    lab.push_manual(record, FixtureKind::Config.path(), 60, 1);

    let mut full_line = baseline_doc.clone();
    full_line.lines.remove(index);
    let full_file = &one_file("file-main", FixtureKind::Config.path(), &full_line)[0];
    let check = content_deletion_projection(baseline_file, full_file, token);
    assert!(!check.matches);
    let mut record = manual_record(
        "deletion/remove-full-token-bearing-line",
        "deletion",
        Classification::RejectTokenStructure,
        check.reason,
    );
    record.token_bytes_changed = true;
    record.adjacent_context_changed = true;
    record.projection_matches = Some(false);
    lab.push_manual(record, FixtureKind::Config.path(), 60, 1);

    let mut rewrite = baseline_doc.clone();
    rewrite.lines[index] = "credential: intentionally removed and syntax rewritten".to_owned();
    let rewrite_file = &one_file("file-main", FixtureKind::Config.path(), &rewrite)[0];
    let check = content_deletion_projection(baseline_file, rewrite_file, token);
    assert!(!check.matches);
    let mut record = manual_record(
        "deletion/remove-token-and-rewrite-syntax",
        "deletion",
        Classification::RejectTokenStructure,
        check.reason,
    );
    record.token_bytes_changed = true;
    record.projection_matches = Some(false);
    lab.push_manual(record, FixtureKind::Config.path(), 60, 1);

    let mut shifted = exact;
    shifted
        .lines
        .insert(5, "unrelated setting before token".to_owned());
    let shifted_file = &one_file("file-main", FixtureKind::Config.path(), &shifted)[0];
    let check = content_deletion_projection(baseline_file, shifted_file, token);
    assert!(!check.matches);
    let mut record = manual_record(
        "deletion/exact-token-removal-plus-unrelated-pre-run-shift",
        "deletion",
        Classification::RejectContextBoundary,
        check.reason,
    );
    record.token_bytes_changed = true;
    record.adjacent_context_changed = true;
    record.projection_matches = Some(false);
    lab.push_manual(record, FixtureKind::Config.path(), 61, 1);
}

fn add_path_controls(lab: &mut Laboratory, token: &TokenRecord) {
    let component = format!("service-{}.json", token.canonical);
    let baseline = PathWorkspace {
        token_entry: PathEntry {
            file_id: "path-file".to_owned(),
            parent_id: "path-parent".to_owned(),
            components: vec!["config".to_owned(), component],
            token_component_index: 1,
            protected_suffix: ".json".to_owned(),
        },
        siblings: vec!["ordinary.yaml".to_owned()],
    };
    let baseline_anchor = derive_path_anchor(&baseline.token_entry, token).expect("path anchor");

    let unchanged = baseline.clone();
    assert_eq!(
        derive_path_anchor(&unchanged.token_entry, token),
        Some(baseline_anchor.clone())
    );
    lab.push_manual(
        manual_record(
            "path/token-bearing-file-stem-unchanged",
            "path",
            Classification::PassUnderCurrentStandard,
            "exact_path_anchor",
        ),
        "config/<token>.json",
        1,
        1,
    );

    let mut renamed = baseline.clone();
    renamed.token_entry.components[1].insert_str(0, "renamed-");
    assert_ne!(
        derive_path_anchor(&renamed.token_entry, token),
        Some(baseline_anchor.clone())
    );
    lab.push_manual(
        manual_record(
            "path/token-bearing-file-renamed",
            "path",
            Classification::RejectPathOrFileMovement,
            "component_skeleton_and_safe_path",
        ),
        "config/<token>.json",
        1,
        1,
    );

    let mut directory_renamed = baseline.clone();
    directory_renamed.token_entry.components[0] = "renamed-config".to_owned();
    lab.push_manual(
        manual_record(
            "path/token-bearing-directory-renamed",
            "path",
            Classification::RejectPathOrFileMovement,
            "safe_path_lineage",
        ),
        "config/<token>.json",
        1,
        1,
    );

    let mut directory_moved = baseline.clone();
    directory_moved.token_entry.parent_id = "other-parent".to_owned();
    directory_moved
        .token_entry
        .components
        .insert(0, "moved".to_owned());
    directory_moved.token_entry.token_component_index += 1;
    lab.push_manual(
        manual_record(
            "path/token-bearing-directory-moved",
            "path",
            Classification::RejectPathOrFileMovement,
            "parent_identity_and_component_index",
        ),
        "config/<token>.json",
        1,
        1,
    );

    let mut sibling_renamed = baseline.clone();
    sibling_renamed.siblings[0] = "renamed-ordinary.yaml".to_owned();
    assert_eq!(
        derive_path_anchor(&sibling_renamed.token_entry, token),
        Some(baseline_anchor.clone())
    );
    lab.push_manual(
        manual_record(
            "path/token-free-sibling-renamed",
            "path",
            Classification::PassUnderCurrentStandard,
            "token_path_anchor_unchanged",
        ),
        "config/<token>.json",
        1,
        1,
    );

    let mut sibling_added = baseline.clone();
    sibling_added.siblings.push("new-sibling.yaml".to_owned());
    assert_eq!(
        derive_path_anchor(&sibling_added.token_entry, token),
        Some(baseline_anchor)
    );
    lab.push_manual(
        manual_record(
            "path/token-free-sibling-added",
            "path",
            Classification::PassUnderCurrentStandard,
            "token_path_anchor_unchanged",
        ),
        "config/<token>.json",
        1,
        1,
    );

    let mut projected = baseline.clone();
    projected.token_entry.components[1] =
        projected.token_entry.components[1].replace(&token.canonical, "");
    assert!(path_projection_matches(
        &baseline.token_entry,
        &projected.token_entry,
        token
    ));
    let mut record = manual_record(
        "path/exact-token-deletion-projection-from-component",
        "path",
        Classification::RejectSecurityMaterial,
        "exact_path_token_bytes_only",
    );
    record.token_bytes_changed = true;
    record.projection_matches = Some(true);
    lab.push_manual(record, "config/<token>.json", 1, 1);
}

fn add_strict_controls(lab: &mut Laboratory, token: &TokenRecord) {
    let baseline = fixture_document(FixtureKind::Rust, Position::Middle, token);
    let mut edited = baseline.clone();
    edited.lines[45] = "later standard-preserving edit".to_owned();
    let case = content_case(
        "strict/standard-preserving-token-file-edit",
        "strict",
        FixtureKind::Rust,
        baseline.clone(),
        edited,
        vec![token.clone()],
        Classification::PassUnderCurrentStandard,
        facts(true, false, false, false, false),
    );
    lab.run_content(case);
    lab.records.last_mut().expect("strict record").strict_result =
        Some("STANDARD_AUTOMATIC;STRICT_APPROVAL_REQUIRED");

    let mut edited = baseline.clone();
    edited
        .lines
        .insert(5, "line shift before protected run".to_owned());
    let case = content_case(
        "strict/standard-anchor-failure",
        "strict",
        FixtureKind::Rust,
        baseline,
        edited,
        vec![token.clone()],
        Classification::RejectAbsoluteLineShiftOnly,
        facts(true, false, false, false, true),
    );
    lab.run_content(case);
    lab.records.last_mut().expect("strict record").strict_result =
        Some("STANDARD_REJECT;STRICT_REJECT");
}

pub(crate) fn absolute_model_content_corpus() -> Vec<ContentCase> {
    let primary = canonical_token(1, TokenCategory::Secret, 0, b"synthetic/anchor-fixture.rs");
    let second = canonical_token(2, TokenCategory::Email, 1, b"synthetic/anchor-fixture.rs");
    let third = canonical_token(3, TokenCategory::Ip, 2, b"synthetic/anchor-fixture.rs");
    let tokens = vec![primary.clone(), second, third];

    atomic_cases(&primary)
        .into_iter()
        .chain(position_cases(&primary))
        .chain(formatter_cases(&primary))
        .chain(refactor_cases(&primary))
        .chain(multiple_run_cases(&tokens))
        .chain(repeated_block_cases(&primary))
        .chain(movement_cases(&tokens))
        .chain(workflow_cases(&tokens))
        .collect()
}

pub(crate) fn absolute_model_laboratory_records() -> Vec<EvidenceRecord> {
    run_laboratory().records
}

fn run_laboratory() -> Laboratory {
    let primary = canonical_token(1, TokenCategory::Secret, 0, b"synthetic/anchor-fixture.rs");
    let mut lab = Laboratory::default();

    for case in absolute_model_content_corpus() {
        lab.run_content(case);
    }
    add_deletion_projection_controls(&mut lab, &primary);
    add_path_controls(&mut lab, &primary);
    add_strict_controls(&mut lab, &primary);
    lab
}

#[derive(Debug)]
struct Metrics {
    by_classification: BTreeMap<Classification, usize>,
    normal_total: usize,
    normal_passes: usize,
    normal_absolute_shift_rejects: usize,
    workflow_total: usize,
    workflow_eligible: usize,
    workflow_absolute_shift_rejects: usize,
}

fn metrics(records: &[EvidenceRecord]) -> Metrics {
    let mut by_classification = BTreeMap::new();
    for classification in Classification::ALL {
        by_classification.insert(classification, 0);
    }
    for record in records {
        *by_classification
            .get_mut(&record.classification)
            .expect("classification initialized") += 1;
    }
    Metrics {
        by_classification,
        normal_total: records
            .iter()
            .filter(|record| record.normal_token_preserving)
            .count(),
        normal_passes: records
            .iter()
            .filter(|record| {
                record.normal_token_preserving
                    && record.classification == Classification::PassUnderCurrentStandard
            })
            .count(),
        normal_absolute_shift_rejects: records
            .iter()
            .filter(|record| {
                record.normal_token_preserving
                    && record.classification == Classification::RejectAbsoluteLineShiftOnly
            })
            .count(),
        workflow_total: records
            .iter()
            .filter(|record| record.suite == "workflow")
            .count(),
        workflow_eligible: records
            .iter()
            .filter(|record| record.suite == "workflow" && record.eligible)
            .count(),
        workflow_absolute_shift_rejects: records
            .iter()
            .filter(|record| {
                record.suite == "workflow"
                    && record.classification == Classification::RejectAbsoluteLineShiftOnly
            })
            .count(),
    }
}

#[test]
fn logical_line_model_retains_exact_newline_bytes() {
    let bytes = b"alpha\nbeta\r\ngamma";
    let lines = logical_lines(bytes);
    let values: Vec<&[u8]> = lines.iter().map(|line| &bytes[line.clone()]).collect();
    assert_eq!(
        values,
        vec![&b"alpha\n"[..], &b"beta\r\n"[..], &b"gamma"[..]]
    );
    assert_eq!(logical_lines(b"").len(), 1);
    assert_eq!(logical_lines(b"one\n").len(), 1);
    assert_eq!(logical_lines(b"one\ntwo").len(), 2);
}

#[test]
fn laboratory_uses_current_canonical_token_grammar() {
    let token = canonical_token(99, TokenCategory::Multiple, 7, b"synthetic/token.txt");
    assert!(token.canonical.starts_with(TOKEN_PREFIX));
    assert!(token.canonical.contains("_MULTIPLE_"));
    assert_eq!(ENGINE_VERSION, "safeclone-roundtrip-engine-v3");
    assert_eq!(POLICY_ID, "roundtrip-v3");
    assert_eq!(TOKEN_SUITE_ID, 1);
}

#[test]
fn standard_anchor_operability_scenarios_are_deterministic_and_bounded() {
    let lab = run_laboratory();
    assert_eq!(absolute_model_laboratory_records().len(), lab.records.len());
    let metrics = metrics(&lab.records);
    assert_eq!(lab.records.len(), lab.bounds.scenario_count);
    assert_eq!(lab.records.len(), 154, "report metric drift");
    assert!(lab.records.len() <= LAB_MAX_SCENARIOS);
    assert!(lab.bounds.synthetic_paths.len() <= LAB_MAX_SYNTHETIC_FILES);
    assert!(lab.bounds.max_lines_per_file <= LAB_MAX_LINES_PER_FILE);
    assert!(lab.bounds.max_tokens_per_file <= LAB_MAX_TOKENS_PER_FILE);
    assert!(lab.bounds.max_files_per_scenario <= LAB_MAX_SYNTHETIC_FILES);
    assert_eq!(
        metrics.by_classification[&Classification::Ambiguous],
        0,
        "no ambiguous outcome is acceptable"
    );
    assert_eq!(metrics.workflow_total, 10);
    assert_eq!(metrics.workflow_eligible, 3);
    assert_eq!(metrics.workflow_absolute_shift_rejects, 7);
    assert_eq!(
        metrics.by_classification[&Classification::PassUnderCurrentStandard],
        54
    );
    assert_eq!(
        metrics.by_classification[&Classification::RejectSecurityMaterial],
        9
    );
    assert_eq!(
        metrics.by_classification[&Classification::RejectContextBoundary],
        16
    );
    assert_eq!(
        metrics.by_classification[&Classification::RejectAbsoluteLineShiftOnly],
        60
    );
    assert_eq!(
        metrics.by_classification[&Classification::RejectPathOrFileMovement],
        5
    );
    assert_eq!(
        metrics.by_classification[&Classification::RejectTokenStructure],
        10
    );
    assert_eq!(metrics.normal_total, 129);
    assert_eq!(metrics.normal_passes, 51);
    assert_eq!(metrics.normal_absolute_shift_rejects, 60);
    assert_eq!(lab.bounds.synthetic_paths.len(), 7);
    assert_eq!(lab.bounds.max_files_per_scenario, 2);
    assert_eq!(lab.bounds.max_lines_per_file, 64);
    assert_eq!(lab.bounds.max_tokens_per_file, 3);
    let suite_matrix = [
        ("single", [6, 2, 6, 9, 0, 2]),
        ("position", [20, 0, 5, 25, 0, 0]),
        ("formatter", [7, 0, 3, 5, 0, 2]),
        ("refactor", [7, 0, 0, 3, 0, 0]),
        ("multiple", [5, 0, 1, 8, 0, 0]),
        ("repeated", [2, 1, 0, 2, 0, 0]),
        ("movement", [0, 4, 0, 0, 2, 3]),
        ("workflow", [3, 0, 0, 7, 0, 0]),
        ("deletion", [0, 1, 1, 0, 0, 3]),
        ("path", [3, 1, 0, 0, 3, 0]),
        ("strict", [1, 0, 0, 1, 0, 0]),
    ];
    let matrix_classes = [
        Classification::PassUnderCurrentStandard,
        Classification::RejectSecurityMaterial,
        Classification::RejectContextBoundary,
        Classification::RejectAbsoluteLineShiftOnly,
        Classification::RejectPathOrFileMovement,
        Classification::RejectTokenStructure,
    ];
    for (suite, expected) in suite_matrix {
        let actual = matrix_classes.map(|classification| {
            lab.records
                .iter()
                .filter(|record| record.suite == suite && record.classification == classification)
                .count()
        });
        assert_eq!(actual, expected, "{suite} report matrix drift");
    }
    assert!(lab.records.iter().all(|record| !record.reason.is_empty()));
    assert!(lab.records.iter().any(|record| record.token_bytes_changed));
    assert!(lab.records.iter().any(|record| record.semantic_role_moved));
    assert!(lab
        .records
        .iter()
        .any(|record| record.only_absolute_line_changed));
    assert!(lab
        .records
        .iter()
        .any(|record| record.adjacent_context_changed));
    assert!(lab
        .records
        .iter()
        .any(|record| !record.failed_anchors.is_empty()));
    assert_eq!(
        lab.records
            .iter()
            .filter(|record| record.projection_matches == Some(true))
            .count(),
        2
    );
    assert_eq!(
        lab.records
            .iter()
            .filter(|record| record.strict_result.is_some())
            .count(),
        2
    );
    println!("ABSOLUTE_MODEL_TOTAL_SCENARIOS={}", lab.records.len());
    for classification in Classification::ALL {
        println!(
            "ABSOLUTE_MODEL_{}={}",
            classification.as_str(),
            metrics.by_classification[&classification]
        );
    }
    println!(
        "ABSOLUTE_MODEL_NORMAL_TOKEN_PRESERVING={}",
        metrics.normal_total
    );
    println!("ABSOLUTE_MODEL_NORMAL_PASSES={}", metrics.normal_passes);
    println!(
        "ABSOLUTE_MODEL_NORMAL_ABSOLUTE_SHIFT_REJECTS={}",
        metrics.normal_absolute_shift_rejects
    );
    println!("ABSOLUTE_MODEL_WORKFLOW_TOTAL={}", metrics.workflow_total);
    println!(
        "ABSOLUTE_MODEL_WORKFLOW_ELIGIBLE={}",
        metrics.workflow_eligible
    );
    println!(
        "ABSOLUTE_MODEL_WORKFLOW_ABSOLUTE_SHIFT_REJECTS={}",
        metrics.workflow_absolute_shift_rejects
    );
    println!(
        "ABSOLUTE_MODEL_BOUNDS=paths:{},files_per_scenario:{},lines:{},tokens:{}",
        lab.bounds.synthetic_paths.len(),
        lab.bounds.max_files_per_scenario,
        lab.bounds.max_lines_per_file,
        lab.bounds.max_tokens_per_file
    );
}
