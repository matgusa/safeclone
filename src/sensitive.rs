//! Deterministic, bounded sensitive-identifier evidence for transient readable text.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::IpAddr;

use regex::{Captures, Regex};

use crate::rule_metadata::{DetectorRuleSpec, Parameter, SCOPE_CONTENT, SCOPE_PATH};

pub const DEFAULT_MAX_FINDINGS_PER_FILE: usize = 16_384;
pub const DEFAULT_MAX_FINDINGS_PER_RUN: usize = 131_072;
pub const DEFAULT_MAX_CANDIDATES_PER_RULE_PER_FILE: usize = 32_768;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum SensitiveRuleId {
    AsciiEmailV1,
    InternationalPhoneV1,
    JapaneseMobilePhoneV1,
    JapaneseIpPhoneV1,
    JapaneseFixedPhoneHyphenatedV1,
    JapaneseServicePhoneV1,
    Ipv4AddressV1,
    Ipv6AddressV1,
    JapanesePostalCodeV1,
    JapaneseMyNumberCandidateV1,
    JapaneseCorporateNumberCandidateV1,
}

impl SensitiveRuleId {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AsciiEmailV1 => "ascii-email-v1",
            Self::InternationalPhoneV1 => "international-phone-v1",
            Self::JapaneseMobilePhoneV1 => "japanese-mobile-phone-v1",
            Self::JapaneseIpPhoneV1 => "japanese-ip-phone-v1",
            Self::JapaneseFixedPhoneHyphenatedV1 => "japanese-fixed-phone-hyphenated-v1",
            Self::JapaneseServicePhoneV1 => "japanese-service-phone-v1",
            Self::Ipv4AddressV1 => "ipv4-address-v1",
            Self::Ipv6AddressV1 => "ipv6-address-v1",
            Self::JapanesePostalCodeV1 => "japanese-postal-code-v1",
            Self::JapaneseMyNumberCandidateV1 => "japanese-my-number-candidate-v1",
            Self::JapaneseCorporateNumberCandidateV1 => "japanese-corporate-number-candidate-v1",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum SensitiveCategory {
    EmailAddress,
    InternationalPhone,
    JapaneseDomesticPhoneCandidate,
    IpAddress,
    JapanesePostalCodeCandidate,
    MyNumberCandidate,
    JapaneseCorporateNumberCandidate,
}

impl SensitiveCategory {
    const fn as_str(self) -> &'static str {
        match self {
            Self::EmailAddress => "email_address",
            Self::InternationalPhone => "international_phone",
            Self::JapaneseDomesticPhoneCandidate => "japanese_domestic_phone_candidate",
            Self::IpAddress => "ip_address",
            Self::JapanesePostalCodeCandidate => "japanese_postal_code_candidate",
            Self::MyNumberCandidate => "my_number_candidate",
            Self::JapaneseCorporateNumberCandidate => "japanese_corporate_number_candidate",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct SensitiveSpan {
    pub start: usize,
    pub end: usize,
}

/// File-local syntactic evidence. It intentionally contains no matched value.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct SensitiveFinding {
    pub span: SensitiveSpan,
    pub rule_id: SensitiveRuleId,
    pub category: SensitiveCategory,
}

impl fmt::Display for SensitiveFinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}:{}@{}..{}",
            self.rule_id.as_str(),
            self.category.as_str(),
            self.span.start,
            self.span.end
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    pub max_findings_per_file: usize,
    pub max_findings_per_run: usize,
    pub max_candidates_per_rule_per_file: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_findings_per_file: DEFAULT_MAX_FINDINGS_PER_FILE,
            max_findings_per_run: DEFAULT_MAX_FINDINGS_PER_RUN,
            max_candidates_per_rule_per_file: DEFAULT_MAX_CANDIDATES_PER_RULE_PER_FILE,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Report {
    pub scan_candidates: usize,
    pub findings: usize,
    pub files_with_findings: usize,
    pub email_findings: usize,
    pub phone_findings: usize,
    pub jp_phone_findings: usize,
    pub ip_findings: usize,
    pub jp_postal_findings: usize,
    pub my_number_candidate_findings: usize,
    pub corporate_number_candidate_findings: usize,
}

impl Report {
    fn category_total(self) -> Result<usize, SensitiveError> {
        [
            self.email_findings,
            self.phone_findings,
            self.jp_phone_findings,
            self.ip_findings,
            self.jp_postal_findings,
            self.my_number_candidate_findings,
            self.corporate_number_candidate_findings,
        ]
        .into_iter()
        .try_fold(0_usize, |total, count| {
            total
                .checked_add(count)
                .ok_or(SensitiveError::CountOverflow)
        })
    }

    pub(crate) fn validate(self) -> Result<(), SensitiveError> {
        if self.category_total()? != self.findings
            || self.files_with_findings > self.scan_candidates
            || self.files_with_findings > self.findings
            || (self.findings == 0) != (self.files_with_findings == 0)
        {
            return Err(SensitiveError::InconsistentCounts);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SensitiveError {
    RuleCompilationFailed,
    InvalidFindingSpan,
    CandidateLimitExceeded,
    FileFindingLimitExceeded,
    RunFindingLimitExceeded,
    CountOverflow,
    InconsistentCounts,
}

impl fmt::Display for SensitiveError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::RuleCompilationFailed => "sensitive identifier rules could not be initialized",
            Self::InvalidFindingSpan => "sensitive identifier detector produced invalid evidence",
            Self::CandidateLimitExceeded => {
                "sensitive identifier detector candidate limit exceeded"
            }
            Self::FileFindingLimitExceeded => {
                "sensitive identifier finding per-file limit exceeded"
            }
            Self::RunFindingLimitExceeded => "sensitive identifier finding run limit exceeded",
            Self::CountOverflow => "sensitive identifier evidence count overflowed",
            Self::InconsistentCounts => "sensitive identifier evidence counts are inconsistent",
        })
    }
}

#[derive(Clone, Copy)]
enum RuleKind {
    Email,
    Phone,
    JapaneseMobilePhone,
    JapaneseIpPhone,
    JapaneseFixedPhone,
    JapaneseServicePhone,
    Ipv4,
    Ipv6,
    JapanesePostalCode,
    JapaneseMyNumber,
    JapaneseCorporateNumber,
}

struct CompiledRule {
    id: SensitiveRuleId,
    category: SensitiveCategory,
    kind: RuleKind,
    regex: Regex,
}

struct SourceRuleSpec {
    id: SensitiveRuleId,
    category: SensitiveCategory,
    kind: RuleKind,
    pattern: &'static str,
    validator_id: &'static str,
}

/// Compiled fixed rules reused by content and path-component scans.
pub(crate) struct RuleSet {
    rules: Vec<CompiledRule>,
}

impl RuleSet {
    pub(crate) fn compile() -> Result<Self, SensitiveError> {
        let rules = source_rule_specs()
            .into_iter()
            .map(|source| {
                Ok(CompiledRule {
                    id: source.id,
                    category: source.category,
                    kind: source.kind,
                    regex: compile_regex(source.pattern)?,
                })
            })
            .collect::<Result<Vec<_>, SensitiveError>>()?;
        Ok(Self { rules })
    }

    pub(crate) fn find(
        &self,
        text: &str,
        limits: Limits,
    ) -> Result<Vec<SensitiveFinding>, SensitiveError> {
        let mut findings = BTreeSet::new();
        let mut candidates_per_rule = BTreeMap::new();
        for rule in &self.rules {
            scan_rule(rule, text, limits, &mut candidates_per_rule, &mut findings)?;
        }
        Ok(findings.into_iter().collect())
    }
}

fn source_rule_specs() -> Vec<SourceRuleSpec> {
    vec![
        SourceRuleSpec {
            id: SensitiveRuleId::AsciiEmailV1,
            category: SensitiveCategory::EmailAddress,
            kind: RuleKind::Email,
            pattern: r#"(?:^|[^A-Za-z0-9!#$%&'*+/=?^_`{|}~.@-])([A-Za-z0-9!#$%&'*+/=?^_`{|}~.-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*)"#,
            validator_id: "ascii-email-boundary-domain-v1",
        },
        SourceRuleSpec {
            id: SensitiveRuleId::InternationalPhoneV1,
            category: SensitiveCategory::InternationalPhone,
            kind: RuleKind::Phone,
            pattern: r"(?:^|[^A-Za-z0-9+])(\+[0-9](?:[0-9 ()-]*[0-9])?)",
            validator_id: "international-phone-digit-boundary-v1",
        },
        SourceRuleSpec {
            id: SensitiveRuleId::JapaneseMobilePhoneV1,
            category: SensitiveCategory::JapaneseDomesticPhoneCandidate,
            kind: RuleKind::JapaneseMobilePhone,
            pattern: r"(?:^|[^A-Za-z0-9-])(0(?:60|70|80|90)(?:-[0-9]{4}-[0-9]{4}|[0-9]{8}))",
            validator_id: "japanese-mobile-phone-v1",
        },
        SourceRuleSpec {
            id: SensitiveRuleId::JapaneseIpPhoneV1,
            category: SensitiveCategory::JapaneseDomesticPhoneCandidate,
            kind: RuleKind::JapaneseIpPhone,
            pattern: r"(?:^|[^A-Za-z0-9-])(050(?:-[0-9]{4}-[0-9]{4}|[0-9]{8}))",
            validator_id: "japanese-ip-phone-v1",
        },
        SourceRuleSpec {
            id: SensitiveRuleId::JapaneseFixedPhoneHyphenatedV1,
            category: SensitiveCategory::JapaneseDomesticPhoneCandidate,
            kind: RuleKind::JapaneseFixedPhone,
            pattern: r"(?:^|[^A-Za-z0-9-])(0[0-9]-[0-9]{4}-[0-9]{4}|0[0-9]{2}-[0-9]{3}-[0-9]{4}|0[0-9]{3}-[0-9]{2}-[0-9]{4}|0[0-9]{4}-[0-9]-[0-9]{4})",
            validator_id: "japanese-fixed-phone-hyphenated-v1",
        },
        SourceRuleSpec {
            id: SensitiveRuleId::JapaneseServicePhoneV1,
            category: SensitiveCategory::JapaneseDomesticPhoneCandidate,
            kind: RuleKind::JapaneseServicePhone,
            pattern: r"(?:^|[^A-Za-z0-9-])(0120-[0-9]{3}-[0-9]{3}|0800-[0-9]{3}-[0-9]{4}|0570-[0-9]{3}-[0-9]{3})",
            validator_id: "japanese-service-phone-v1",
        },
        SourceRuleSpec {
            id: SensitiveRuleId::Ipv4AddressV1,
            category: SensitiveCategory::IpAddress,
            kind: RuleKind::Ipv4,
            pattern: r"(?:^|[^A-Za-z0-9_:.%])([0-9]{1,3}(?:\.[0-9]{1,3}){3})",
            validator_id: "ipv4-parse-boundary-v1",
        },
        SourceRuleSpec {
            id: SensitiveRuleId::Ipv6AddressV1,
            category: SensitiveCategory::IpAddress,
            kind: RuleKind::Ipv6,
            pattern: r"(?:^|[^A-Za-z0-9_:.%])([0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){1,6}:[0-9]{1,3}(?:\.[0-9]{1,3}){3}|[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,8})",
            validator_id: "ipv6-parse-boundary-v1",
        },
        SourceRuleSpec {
            id: SensitiveRuleId::JapanesePostalCodeV1,
            category: SensitiveCategory::JapanesePostalCodeCandidate,
            kind: RuleKind::JapanesePostalCode,
            pattern: r"(?:^|[^A-Za-z0-9])([0-9]{3}-[0-9]{4})",
            validator_id: "japanese-postal-boundary-v1",
        },
        SourceRuleSpec {
            id: SensitiveRuleId::JapaneseMyNumberCandidateV1,
            category: SensitiveCategory::MyNumberCandidate,
            kind: RuleKind::JapaneseMyNumber,
            pattern: r"(?:^|[^A-Za-z0-9])([0-9]{12})",
            validator_id: "japanese-my-number-check-digit-v1",
        },
        SourceRuleSpec {
            id: SensitiveRuleId::JapaneseCorporateNumberCandidateV1,
            category: SensitiveCategory::JapaneseCorporateNumberCandidate,
            kind: RuleKind::JapaneseCorporateNumber,
            pattern: r"(?:^|[^A-Za-z0-9])([0-9]{13})",
            validator_id: "japanese-corporate-number-check-digit-v1",
        },
    ]
}

pub(crate) fn descriptor_rule_specs() -> Vec<DetectorRuleSpec> {
    source_rule_specs()
        .into_iter()
        .map(|source| DetectorRuleSpec {
            rule_id: source.id.as_str(),
            scope_flags: SCOPE_CONTENT | SCOPE_PATH,
            patterns: vec![source.pattern.as_bytes().to_vec()],
            validator_id: source.validator_id,
            category: source.category.as_str(),
            token_category: match source.category {
                SensitiveCategory::EmailAddress => "EMAIL",
                SensitiveCategory::InternationalPhone => "PHONE",
                SensitiveCategory::JapaneseDomesticPhoneCandidate => "JPPHONE",
                SensitiveCategory::IpAddress => "IP",
                SensitiveCategory::JapanesePostalCodeCandidate => "JPPOSTAL",
                SensitiveCategory::MyNumberCandidate => "MYNUMBER",
                SensitiveCategory::JapaneseCorporateNumberCandidate => "CORPNUM",
            },
            parameters: vec![
                Parameter {
                    id: "max-findings-per-file",
                    value: DEFAULT_MAX_FINDINGS_PER_FILE as u64,
                },
                Parameter {
                    id: "max-findings-per-run",
                    value: DEFAULT_MAX_FINDINGS_PER_RUN as u64,
                },
                Parameter {
                    id: "max-candidates-per-rule-per-file",
                    value: DEFAULT_MAX_CANDIDATES_PER_RULE_PER_FILE as u64,
                },
            ],
        })
        .collect()
}

fn compile_regex(pattern: &str) -> Result<Regex, SensitiveError> {
    Regex::new(pattern).map_err(|_| SensitiveError::RuleCompilationFailed)
}

fn scan_rule(
    rule: &CompiledRule,
    text: &str,
    limits: Limits,
    candidates_per_rule: &mut BTreeMap<SensitiveRuleId, usize>,
    findings: &mut BTreeSet<SensitiveFinding>,
) -> Result<(), SensitiveError> {
    let mut search_at = 0_usize;
    while search_at <= text.len() {
        let Some(captures) = rule.regex.captures_at(text, search_at) else {
            break;
        };
        record_rule_candidate(
            candidates_per_rule,
            rule.id,
            limits.max_candidates_per_rule_per_file,
        )?;
        let whole = captures.get(0).ok_or(SensitiveError::InvalidFindingSpan)?;
        let next_search = whole.end();
        if next_search <= search_at {
            return Err(SensitiveError::InvalidFindingSpan);
        }

        if let Some(span) = validate_match(rule.kind, text, &captures) {
            insert_finding(
                findings,
                SensitiveFinding {
                    span,
                    rule_id: rule.id,
                    category: rule.category,
                },
                text.len(),
                limits.max_findings_per_file,
            )?;
        }
        search_at = next_search;
    }
    Ok(())
}

fn record_rule_candidate(
    candidates_per_rule: &mut BTreeMap<SensitiveRuleId, usize>,
    rule_id: SensitiveRuleId,
    limit: usize,
) -> Result<(), SensitiveError> {
    let count = candidates_per_rule.entry(rule_id).or_default();
    let next = count.checked_add(1).ok_or(SensitiveError::CountOverflow)?;
    if next > limit {
        return Err(SensitiveError::CandidateLimitExceeded);
    }
    *count = next;
    Ok(())
}

fn insert_finding(
    findings: &mut BTreeSet<SensitiveFinding>,
    finding: SensitiveFinding,
    text_len: usize,
    limit: usize,
) -> Result<(), SensitiveError> {
    if finding.span.start >= finding.span.end || finding.span.end > text_len {
        return Err(SensitiveError::InvalidFindingSpan);
    }
    if findings.insert(finding) && findings.len() > limit {
        return Err(SensitiveError::FileFindingLimitExceeded);
    }
    Ok(())
}

fn validate_match(kind: RuleKind, text: &str, captures: &Captures<'_>) -> Option<SensitiveSpan> {
    match kind {
        RuleKind::Email => validate_email(text, captures),
        RuleKind::Phone => validate_phone(text, captures),
        RuleKind::JapaneseMobilePhone => validate_japanese_mobile_phone(text, captures),
        RuleKind::JapaneseIpPhone => validate_japanese_ip_phone(text, captures),
        RuleKind::JapaneseFixedPhone => validate_japanese_fixed_phone(text, captures),
        RuleKind::JapaneseServicePhone => validate_japanese_service_phone(text, captures),
        RuleKind::Ipv4 => validate_ip(text, captures, false),
        RuleKind::Ipv6 => validate_ip(text, captures, true),
        RuleKind::JapanesePostalCode => validate_japanese_postal_code(text, captures),
        RuleKind::JapaneseMyNumber => validate_japanese_my_number(text, captures),
        RuleKind::JapaneseCorporateNumber => validate_japanese_corporate_number(text, captures),
    }
}

fn validate_email(text: &str, captures: &Captures<'_>) -> Option<SensitiveSpan> {
    let span = capture_span(captures, 1)?;
    if !email_left_boundary(text, span.start) || !email_right_boundary(text, span.end) {
        return None;
    }
    let candidate = &text[span.start..span.end];
    let (local, domain) = candidate.split_once('@')?;
    if local.is_empty()
        || local.len() > 64
        || domain.is_empty()
        || domain.len() > 253
        || local.starts_with('.')
        || local.ends_with('.')
        || local.contains("..")
        || !local.bytes().all(is_email_local_byte)
    {
        return None;
    }
    if !domain.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            && label
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphanumeric)
            && label
                .as_bytes()
                .last()
                .is_some_and(u8::is_ascii_alphanumeric)
    }) {
        return None;
    }
    Some(span)
}

fn is_email_local_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'/'
                | b'='
                | b'?'
                | b'^'
                | b'_'
                | b'`'
                | b'{'
                | b'|'
                | b'}'
                | b'~'
                | b'.'
        )
}

fn is_email_token(character: char) -> bool {
    character.is_ascii() && (is_email_local_byte(character as u8) || matches!(character, '@'))
}

fn email_left_boundary(text: &str, start: usize) -> bool {
    text[..start]
        .chars()
        .next_back()
        .is_none_or(|character| is_identifier_boundary(character, is_email_token))
}

fn email_right_boundary(text: &str, end: usize) -> bool {
    let mut suffix = text[end..].chars();
    match suffix.next() {
        None => true,
        Some('.') => suffix
            .next()
            .is_none_or(|character| is_identifier_boundary(character, is_email_token)),
        Some(character) => is_identifier_boundary(character, is_email_token),
    }
}

fn validate_phone(text: &str, captures: &Captures<'_>) -> Option<SensitiveSpan> {
    let span = capture_span(captures, 1)?;
    if !ascii_left_boundary(text, span.start, is_phone_token)
        || !ascii_right_boundary(text, span.end, is_phone_token)
    {
        return None;
    }
    let candidate = &text[span.start..span.end];
    let bytes = candidate.as_bytes();
    if bytes.first() != Some(&b'+') || !matches!(bytes.get(1), Some(b'1'..=b'9')) {
        return None;
    }

    let mut digit_count = 0_usize;
    let mut in_parentheses = false;
    let mut parenthesized_digits = 0_usize;
    for byte in bytes.iter().copied().skip(1) {
        match byte {
            b'0'..=b'9' => {
                digit_count = digit_count.checked_add(1)?;
                if in_parentheses {
                    parenthesized_digits = parenthesized_digits.checked_add(1)?;
                }
            }
            b'(' if !in_parentheses => {
                in_parentheses = true;
                parenthesized_digits = 0;
            }
            b')' if in_parentheses && parenthesized_digits != 0 => {
                in_parentheses = false;
            }
            b' ' | b'-' => {}
            _ => return None,
        }
    }
    if in_parentheses || !(8..=15).contains(&digit_count) {
        return None;
    }
    Some(span)
}

fn is_phone_token(character: char) -> bool {
    character.is_ascii_alphanumeric() || matches!(character, '+' | '-' | '(' | ')')
}

fn validate_japanese_mobile_phone(text: &str, captures: &Captures<'_>) -> Option<SensitiveSpan> {
    let span = domestic_phone_span(text, captures)?;
    let bytes = &text.as_bytes()[span.start..span.end];
    let (prefix, first_subscriber_digit) = match bytes {
        [prefix @ .., b'-', first, _, _, _, b'-', _, _, _, _] if prefix.len() == 3 => {
            (prefix, *first)
        }
        [prefix @ .., first, _, _, _, _, _, _, _] if prefix.len() == 3 => (prefix, *first),
        _ => return None,
    };
    if !bytes
        .iter()
        .all(|byte| byte.is_ascii_digit() || *byte == b'-')
    {
        return None;
    }
    match prefix {
        b"070" | b"090" => Some(span),
        b"080" if matches!(first_subscriber_digit, b'1'..=b'9') => Some(span),
        b"060" if matches!(first_subscriber_digit, b'1'..=b'9') => Some(span),
        _ => None,
    }
}

fn validate_japanese_ip_phone(text: &str, captures: &Captures<'_>) -> Option<SensitiveSpan> {
    let span = domestic_phone_span(text, captures)?;
    let bytes = &text.as_bytes()[span.start..span.end];
    let valid = match bytes {
        [b'0', b'5', b'0', b'-', a, b, c, d, b'-', e, f, g, h] => [a, b, c, d, e, f, g, h]
            .into_iter()
            .all(|byte| byte.is_ascii_digit()),
        [b'0', b'5', b'0', rest @ ..] if rest.len() == 8 => rest.iter().all(u8::is_ascii_digit),
        _ => false,
    };
    valid.then_some(span)
}

fn validate_japanese_fixed_phone(text: &str, captures: &Captures<'_>) -> Option<SensitiveSpan> {
    let span = domestic_phone_span(text, captures)?;
    let candidate = &text[span.start..span.end];
    if [
        "0120-", "0170-", "0180-", "020", "050", "0570-", "060", "070", "080", "090", "091",
        "0990-",
    ]
    .into_iter()
    .any(|prefix| candidate.starts_with(prefix))
    {
        return None;
    }

    let mut groups = candidate.split('-');
    let area = groups.next()?;
    let exchange = groups.next()?;
    let subscriber = groups.next()?;
    if groups.next().is_some()
        || !matches!(
            (area.len(), exchange.len(), subscriber.len()),
            (2, 4, 4) | (3, 3, 4) | (4, 2, 4) | (5, 1, 4)
        )
        || !area.starts_with('0')
        || !matches!(area.as_bytes().get(1), Some(b'1'..=b'9'))
        || (area.len() == 2 && !matches!(area, "03" | "06"))
        || ![area, exchange, subscriber]
            .into_iter()
            .all(|group| group.bytes().all(|byte| byte.is_ascii_digit()))
    {
        return None;
    }
    Some(span)
}

fn validate_japanese_service_phone(text: &str, captures: &Captures<'_>) -> Option<SensitiveSpan> {
    let span = domestic_phone_span(text, captures)?;
    matches!(
        &text[span.start..span.end],
        value if (value.starts_with("0120-") || value.starts_with("0570-"))
            && value.len() == 12
            || value.starts_with("0800-") && value.len() == 13
    )
    .then_some(span)
}

fn domestic_phone_span(text: &str, captures: &Captures<'_>) -> Option<SensitiveSpan> {
    let span = capture_span(captures, 1)?;
    (ascii_left_boundary(text, span.start, is_japanese_phone_token)
        && ascii_right_boundary(text, span.end, is_japanese_phone_token))
    .then_some(span)
}

fn is_japanese_phone_token(character: char) -> bool {
    character.is_ascii_alphanumeric() || character == '-'
}

fn validate_ip(text: &str, captures: &Captures<'_>, expect_ipv6: bool) -> Option<SensitiveSpan> {
    let span = capture_span(captures, 1)?;
    if expect_ipv6 {
        if !valid_ipv6_boundary(text, span) {
            return None;
        }
    } else if !valid_ipv4_boundary(text, span) {
        return None;
    }

    let parsed = text[span.start..span.end].parse::<IpAddr>().ok()?;
    if matches!(
        (expect_ipv6, parsed),
        (true, IpAddr::V6(_)) | (false, IpAddr::V4(_))
    ) {
        Some(span)
    } else {
        None
    }
}

fn valid_ipv4_boundary(text: &str, span: SensitiveSpan) -> bool {
    if span
        .start
        .checked_sub(1)
        .and_then(|index| text.as_bytes().get(index))
        == Some(&b'[')
        || text.as_bytes().get(span.end) == Some(&b']')
    {
        return false;
    }
    ascii_left_boundary(text, span.start, is_ip_token)
        && ascii_right_boundary(text, span.end, is_ipv4_right_token)
}

fn valid_ipv6_boundary(text: &str, span: SensitiveSpan) -> bool {
    let left_bracket = span
        .start
        .checked_sub(1)
        .and_then(|index| text.as_bytes().get(index))
        == Some(&b'[');
    let right_bracket = text.as_bytes().get(span.end) == Some(&b']');
    if left_bracket || right_bracket {
        return left_bracket && right_bracket;
    }
    ascii_left_boundary(text, span.start, is_ip_token)
        && ascii_right_boundary(text, span.end, is_ip_token)
}

fn is_ip_token(character: char) -> bool {
    character.is_ascii_alphanumeric() || matches!(character, '_' | '.' | ':' | '%')
}

fn is_ipv4_right_token(character: char) -> bool {
    character.is_ascii_alphanumeric() || matches!(character, '_' | '.' | '%')
}

fn validate_japanese_postal_code(text: &str, captures: &Captures<'_>) -> Option<SensitiveSpan> {
    let span = capture_span(captures, 1)?;
    if !japanese_postal_code_boundaries(text, span) {
        return None;
    }
    let bytes = &text.as_bytes()[span.start..span.end];
    if bytes.len() == 8
        && bytes.get(3) == Some(&b'-')
        && bytes[..3].iter().all(u8::is_ascii_digit)
        && bytes[4..].iter().all(u8::is_ascii_digit)
    {
        Some(span)
    } else {
        None
    }
}

fn validate_japanese_my_number(text: &str, captures: &Captures<'_>) -> Option<SensitiveSpan> {
    let span = capture_span(captures, 1)?;
    if !numeric_identifier_boundaries(text, span) {
        return None;
    }
    let bytes = &text.as_bytes()[span.start..span.end];
    let (base, check) = bytes.split_at_checked(11)?;
    let actual = ascii_digit(*check.first()?)?;
    if check.len() == 1 && actual == my_number_check_digit(base)? {
        Some(span)
    } else {
        None
    }
}

fn my_number_check_digit(base: &[u8]) -> Option<u32> {
    if base.len() != 11 {
        return None;
    }
    let sum = base
        .iter()
        .rev()
        .enumerate()
        .try_fold(0_u32, |sum, (zero_based_index, byte)| {
            let n = zero_based_index.checked_add(1)?;
            let weight = if n <= 6 {
                n.checked_add(1)?
            } else {
                n.checked_sub(5)?
            };
            let weighted = ascii_digit(*byte)?.checked_mul(u32::try_from(weight).ok()?)?;
            sum.checked_add(weighted)
        })?;
    let remainder = sum % 11;
    Some(if remainder <= 1 { 0 } else { 11 - remainder })
}

fn validate_japanese_corporate_number(
    text: &str,
    captures: &Captures<'_>,
) -> Option<SensitiveSpan> {
    let span = capture_span(captures, 1)?;
    if !numeric_identifier_boundaries(text, span) {
        return None;
    }
    let bytes = &text.as_bytes()[span.start..span.end];
    let (check, base) = bytes.split_at_checked(1)?;
    let actual = ascii_digit(*check.first()?)?;
    if base.len() == 12 && actual == corporate_number_check_digit(base)? {
        Some(span)
    } else {
        None
    }
}

fn corporate_number_check_digit(base: &[u8]) -> Option<u32> {
    if base.len() != 12 {
        return None;
    }
    let sum = base
        .iter()
        .rev()
        .enumerate()
        .try_fold(0_u32, |sum, (zero_based_index, byte)| {
            let weight = if zero_based_index % 2 == 0 {
                1_u32
            } else {
                2_u32
            };
            let weighted = ascii_digit(*byte)?.checked_mul(weight)?;
            sum.checked_add(weighted)
        })?;
    Some(9 - (sum % 9))
}

fn ascii_digit(byte: u8) -> Option<u32> {
    byte.is_ascii_digit().then(|| u32::from(byte - b'0'))
}

fn numeric_identifier_boundaries(text: &str, span: SensitiveSpan) -> bool {
    ascii_left_boundary(text, span.start, is_numeric_identifier_token)
        && ascii_right_boundary(text, span.end, is_numeric_identifier_token)
}

fn japanese_postal_code_boundaries(text: &str, span: SensitiveSpan) -> bool {
    ascii_left_boundary(text, span.start, is_japanese_postal_code_token)
        && ascii_right_boundary(text, span.end, is_japanese_postal_code_token)
}

fn is_numeric_identifier_token(character: char) -> bool {
    character.is_ascii_alphanumeric()
}

fn is_japanese_postal_code_token(character: char) -> bool {
    character.is_ascii_alphanumeric() || character == '-'
}

fn ascii_left_boundary(text: &str, start: usize, token: fn(char) -> bool) -> bool {
    text[..start]
        .chars()
        .next_back()
        .is_none_or(|character| is_identifier_boundary(character, token))
}

fn ascii_right_boundary(text: &str, end: usize, token: fn(char) -> bool) -> bool {
    text[end..]
        .chars()
        .next()
        .is_none_or(|character| is_identifier_boundary(character, token))
}

fn is_identifier_boundary(character: char, ascii_token: fn(char) -> bool) -> bool {
    if character.is_ascii() {
        !ascii_token(character)
    } else {
        !character.is_alphanumeric()
    }
}

fn capture_span(captures: &Captures<'_>, index: usize) -> Option<SensitiveSpan> {
    let matched = captures.get(index)?;
    Some(SensitiveSpan {
        start: matched.start(),
        end: matched.end(),
    })
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct CategoryCounts {
    email: usize,
    phone: usize,
    jp_phone: usize,
    ip: usize,
    jp_postal: usize,
    my_number_candidate: usize,
    corporate_number_candidate: usize,
}

impl CategoryCounts {
    fn from_findings(findings: &[SensitiveFinding]) -> Result<Self, SensitiveError> {
        let mut counts = Self::default();
        for finding in findings {
            let count = match finding.category {
                SensitiveCategory::EmailAddress => &mut counts.email,
                SensitiveCategory::InternationalPhone => &mut counts.phone,
                SensitiveCategory::JapaneseDomesticPhoneCandidate => &mut counts.jp_phone,
                SensitiveCategory::IpAddress => &mut counts.ip,
                SensitiveCategory::JapanesePostalCodeCandidate => &mut counts.jp_postal,
                SensitiveCategory::MyNumberCandidate => &mut counts.my_number_candidate,
                SensitiveCategory::JapaneseCorporateNumberCandidate => {
                    &mut counts.corporate_number_candidate
                }
            };
            *count = count.checked_add(1).ok_or(SensitiveError::CountOverflow)?;
        }
        Ok(counts)
    }
}

pub(crate) struct Session {
    limits: Limits,
    rules: RuleSet,
    report: Report,
}

impl Session {
    pub(crate) fn new(limits: Limits) -> Result<Self, SensitiveError> {
        Ok(Self {
            limits,
            rules: RuleSet::compile()?,
            report: Report::default(),
        })
    }

    pub(crate) fn scan_file(
        &mut self,
        text: &str,
        mut consume_findings: impl FnMut(&[SensitiveFinding]),
    ) -> Result<usize, SensitiveError> {
        let findings = self.rules.find(text, self.limits)?;
        let file_counts = CategoryCounts::from_findings(&findings)?;
        let finding_count = findings.len();
        let next_findings = self
            .report
            .findings
            .checked_add(finding_count)
            .ok_or(SensitiveError::CountOverflow)?;
        if next_findings > self.limits.max_findings_per_run {
            return Err(SensitiveError::RunFindingLimitExceeded);
        }
        let next_report = Report {
            scan_candidates: self
                .report
                .scan_candidates
                .checked_add(1)
                .ok_or(SensitiveError::CountOverflow)?,
            findings: next_findings,
            files_with_findings: if findings.is_empty() {
                self.report.files_with_findings
            } else {
                self.report
                    .files_with_findings
                    .checked_add(1)
                    .ok_or(SensitiveError::CountOverflow)?
            },
            email_findings: self
                .report
                .email_findings
                .checked_add(file_counts.email)
                .ok_or(SensitiveError::CountOverflow)?,
            phone_findings: self
                .report
                .phone_findings
                .checked_add(file_counts.phone)
                .ok_or(SensitiveError::CountOverflow)?,
            jp_phone_findings: self
                .report
                .jp_phone_findings
                .checked_add(file_counts.jp_phone)
                .ok_or(SensitiveError::CountOverflow)?,
            ip_findings: self
                .report
                .ip_findings
                .checked_add(file_counts.ip)
                .ok_or(SensitiveError::CountOverflow)?,
            jp_postal_findings: self
                .report
                .jp_postal_findings
                .checked_add(file_counts.jp_postal)
                .ok_or(SensitiveError::CountOverflow)?,
            my_number_candidate_findings: self
                .report
                .my_number_candidate_findings
                .checked_add(file_counts.my_number_candidate)
                .ok_or(SensitiveError::CountOverflow)?,
            corporate_number_candidate_findings: self
                .report
                .corporate_number_candidate_findings
                .checked_add(file_counts.corporate_number_candidate)
                .ok_or(SensitiveError::CountOverflow)?,
        };
        next_report.validate()?;
        self.report = next_report;
        consume_findings(&findings);
        Ok(finding_count)
    }

    pub(crate) fn finish(self) -> Result<Report, SensitiveError> {
        self.report.validate()?;
        Ok(self.report)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EMAIL: &str = "fixture.user+test@example.invalid";
    const PHONE: &str = "+1 (202) 555-0100";
    const COMPACT_PHONE: &str = "+12345678";
    const IPV4: &str = "192.0.2.10";
    const IPV6: &str = "2001:db8::10";
    const POSTAL: &str = "123-4567";
    const JP_MOBILE: &str = "090-0000-0000";

    fn synthetic_my_number(base: &str) -> String {
        assert_eq!(base.len(), 11);
        assert!(base.bytes().all(|byte| byte.is_ascii_digit()));
        let sum = base
            .bytes()
            .rev()
            .enumerate()
            .map(|(index, byte)| {
                let n = index as u32 + 1;
                let weight = if n <= 6 { n + 1 } else { n - 5 };
                u32::from(byte - b'0') * weight
            })
            .sum::<u32>();
        let remainder = sum % 11;
        let check = if remainder <= 1 { 0 } else { 11 - remainder };
        format!("{base}{check}")
    }

    fn synthetic_corporate_number(base: &str) -> String {
        assert_eq!(base.len(), 12);
        assert!(base.bytes().all(|byte| byte.is_ascii_digit()));
        let sum = base
            .bytes()
            .rev()
            .enumerate()
            .map(|(index, byte)| {
                let weight = if index % 2 == 0 { 1 } else { 2 };
                u32::from(byte - b'0') * weight
            })
            .sum::<u32>();
        let check = 9 - (sum % 9);
        format!("{check}{base}")
    }

    fn scan(text: &str) -> Vec<SensitiveFinding> {
        let mut session = Session::new(Limits::default()).expect("compile trusted rules");
        let mut findings = Vec::new();
        session
            .scan_file(text, |file_findings| {
                findings.extend_from_slice(file_findings)
            })
            .expect("scan succeeds");
        session.finish().expect("report is consistent");
        findings
    }

    fn assert_rule(text: &str, rule_id: SensitiveRuleId) {
        assert!(
            scan(text).iter().any(|finding| finding.rule_id == rule_id),
            "expected synthetic fixture to match {}",
            rule_id.as_str()
        );
    }

    fn assert_no_rule(text: &str, rule_id: SensitiveRuleId) {
        assert!(
            scan(text).iter().all(|finding| finding.rule_id != rule_id),
            "unexpected match for {}",
            rule_id.as_str()
        );
    }

    fn assert_rule_span(text: &str, rule_id: SensitiveRuleId, expected: &str) {
        let findings = scan(text);
        let finding = findings
            .iter()
            .find(|finding| finding.rule_id == rule_id)
            .expect("expected synthetic fixture to match rule");
        assert_eq!(
            &text[finding.span.start..finding.span.end],
            expected,
            "finding span should contain only the ASCII identifier"
        );
    }

    #[test]
    fn default_limits_are_explicit() {
        assert_eq!(
            Limits::default(),
            Limits {
                max_findings_per_file: 16_384,
                max_findings_per_run: 131_072,
                max_candidates_per_rule_per_file: 32_768,
            }
        );
    }

    #[test]
    fn email_rule_accepts_conservative_ascii_forms() {
        assert_rule(EMAIL, SensitiveRuleId::AsciiEmailV1);
        assert_rule("fixture+tag@example.invalid", SensitiveRuleId::AsciiEmailV1);
        assert_rule("fixture@corp", SensitiveRuleId::AsciiEmailV1);
        assert_rule(
            "contact: fixture@example.invalid.",
            SensitiveRuleId::AsciiEmailV1,
        );
    }

    #[test]
    fn email_rule_rejects_malformed_parts_and_boundaries() {
        for near_miss in [
            "@example.invalid",
            "fixture@",
            "fixture..user@example.invalid",
            ".fixture@example.invalid",
            "fixture@example.invalid_extra",
            "fixture@-example.invalid",
            "fixture@example-.invalid",
            "éfixture@example.invalid",
        ] {
            assert_no_rule(near_miss, SensitiveRuleId::AsciiEmailV1);
        }
    }

    #[test]
    fn email_rule_enforces_component_lengths() {
        let long_local = "a".repeat(65);
        let long_label = "b".repeat(64);
        assert!(scan(&format!("{long_local}@example.invalid")).is_empty());
        assert!(scan(&format!("fixture@{long_label}.invalid")).is_empty());

        let label = "c".repeat(63);
        let oversized_domain = format!("{label}.{label}.{label}.{label}");
        assert!(oversized_domain.len() > 253);
        assert!(scan(&format!("fixture@{oversized_domain}")).is_empty());
    }

    #[test]
    fn phone_rule_accepts_international_bounds_and_separators() {
        for value in [PHONE, "+81 90-1234-5678", "+12345678", "+123456789012345"] {
            assert_rule(value, SensitiveRuleId::InternationalPhoneV1);
        }
    }

    #[test]
    fn phone_rule_rejects_domestic_length_and_contamination() {
        for near_miss in [
            "+1234567",
            "+1234567890123456",
            "090-1234-5678",
            "2026-08-13",
            "123456789012345",
            "+00012345678",
            "+12abc345",
            "x+12345678",
            "+12345678x",
            "+1 ((202)) 555-0100",
            "+1 () 2025550100",
            "+1 (202 555-0100",
        ] {
            assert_no_rule(near_miss, SensitiveRuleId::InternationalPhoneV1);
        }
    }

    #[test]
    fn japanese_mobile_rule_accepts_current_number_plan_shapes() {
        for value in [
            "070-0000-0000",
            "080-1000-0000",
            JP_MOBILE,
            "060-1000-0000",
            "07000000000",
            "08010000000",
            "09000000000",
            "06010000000",
        ] {
            assert_rule(value, SensitiveRuleId::JapaneseMobilePhoneV1);
        }

        for near_miss in [
            "060-0000-0000",
            "06000000000",
            "080-0000-0000",
            "08000000000",
            "0800-123-4567",
            "08001234567",
            "090-000-0000",
            "090-00000-0000",
            "0900000000",
            "090000000000",
            "A09000000000B",
            "1090000000009",
        ] {
            assert_no_rule(near_miss, SensitiveRuleId::JapaneseMobilePhoneV1);
        }

        let international = "+81 90-0000-0000";
        assert_rule(international, SensitiveRuleId::InternationalPhoneV1);
        for domestic_rule in [
            SensitiveRuleId::JapaneseMobilePhoneV1,
            SensitiveRuleId::JapaneseIpPhoneV1,
            SensitiveRuleId::JapaneseFixedPhoneHyphenatedV1,
            SensitiveRuleId::JapaneseServicePhoneV1,
        ] {
            assert_no_rule(international, domestic_rule);
        }
    }

    #[test]
    fn japanese_ip_phone_rule_accepts_only_eleven_digit_050_shapes() {
        for value in ["050-0000-0000", "05000000000"] {
            assert_rule(value, SensitiveRuleId::JapaneseIpPhoneV1);
        }
        for near_miss in [
            "050-000-0000",
            "050-00000-0000",
            "0500000000",
            "050000000000",
            "A05000000000B",
        ] {
            assert_no_rule(near_miss, SensitiveRuleId::JapaneseIpPhoneV1);
        }
    }

    #[test]
    fn japanese_fixed_phone_rule_requires_explicit_hyphenated_grouping() {
        for value in [
            "03-0000-0000",
            "06-0000-0000",
            "045-000-0000",
            "099-000-0000",
            "0774-00-0000",
            "04992-0-0000",
        ] {
            assert_rule(value, SensitiveRuleId::JapaneseFixedPhoneHyphenatedV1);
        }

        for near_miss in [
            "0300000000",
            "01-0000-0000",
            "03-000-0000",
            "045-0000-0000",
            "0120-00-0000",
            "0204-00-0000",
            "050-0000-0000",
            "0600-00-0000",
            "090-0000-0000",
            "0120-000-000",
            "0800-000-0000",
            "0570-000-000",
            "A03-0000-0000B",
        ] {
            assert_no_rule(near_miss, SensitiveRuleId::JapaneseFixedPhoneHyphenatedV1);
        }
    }

    #[test]
    fn japanese_service_phone_rule_accepts_only_official_shapes() {
        for value in [
            "0120-000-000",
            "0800-000-0000",
            "0800-123-4567",
            "0570-000-000",
        ] {
            assert_rule(value, SensitiveRuleId::JapaneseServicePhoneV1);
        }
        for near_miss in [
            "0120-0000-000",
            "0120-000-0000",
            "0800-0000-0000",
            "0800-000-000",
            "0570-0000-000",
            "0570-000-0000",
            "0120000000",
            "08001234567",
        ] {
            assert_no_rule(near_miss, SensitiveRuleId::JapaneseServicePhoneV1);
        }
    }

    #[test]
    fn japanese_domestic_phone_uses_unicode_aware_boundaries() {
        assert_rule_span(
            "電話：090-0000-0000。",
            SensitiveRuleId::JapaneseMobilePhoneV1,
            JP_MOBILE,
        );
        assert_rule_span(
            "TEL：03-0000-0000。",
            SensitiveRuleId::JapaneseFixedPhoneHyphenatedV1,
            "03-0000-0000",
        );

        for near_miss in [
            "日本語090-0000-0000",
            "090-0000-0000日本語",
            "Ａ09000000000",
            "０９０-0000-0000",
            "090－0000－0000",
        ] {
            for rule_id in [
                SensitiveRuleId::JapaneseMobilePhoneV1,
                SensitiveRuleId::JapaneseFixedPhoneHyphenatedV1,
            ] {
                assert_no_rule(near_miss, rule_id);
            }
        }
    }

    #[test]
    fn ip_rules_use_std_parsing_for_valid_addresses() {
        assert_rule(IPV4, SensitiveRuleId::Ipv4AddressV1);
        assert_rule(IPV6, SensitiveRuleId::Ipv6AddressV1);
        assert_rule("::", SensitiveRuleId::Ipv6AddressV1);
        assert_rule("::ffff:192.0.2.128", SensitiveRuleId::Ipv6AddressV1);
        let bracketed = scan("[2001:db8::20]");
        assert_eq!(bracketed.len(), 1);
        assert_eq!(bracketed[0].rule_id, SensitiveRuleId::Ipv6AddressV1);
        assert_eq!(
            &"[2001:db8::20]"[bracketed[0].span.start..bracketed[0].span.end],
            "2001:db8::20"
        );
    }

    #[test]
    fn ip_rules_reject_invalid_addresses_and_token_boundaries() {
        for near_miss in [
            "192.0.2.999",
            "1.2.3.4.5",
            "v1.2.3.4",
            "2001:db8:::1",
            "x2001:db8::1",
            "2001:db8::1x",
            "[2001:db8::1",
            "2001:db8::1]",
            "fe80::1%eth0",
        ] {
            assert_no_rule(near_miss, SensitiveRuleId::Ipv4AddressV1);
            assert_no_rule(near_miss, SensitiveRuleId::Ipv6AddressV1);
        }
    }

    #[test]
    fn japanese_postal_rule_accepts_only_explicit_ascii_shape() {
        assert_rule(POSTAL, SensitiveRuleId::JapanesePostalCodeV1);
        assert_rule_span(
            "郵便番号：〒123-4567。",
            SensitiveRuleId::JapanesePostalCodeV1,
            POSTAL,
        );

        for near_miss in [
            "1234567",
            "12-34567",
            "1234-567",
            "１２３-４５６７",
            "123‐4567",
            "090-1234-5678",
            "A123-4567B",
            "9123-45678",
            "日123-4567",
            "123-4567日",
        ] {
            assert_no_rule(near_miss, SensitiveRuleId::JapanesePostalCodeV1);
        }
    }

    #[test]
    fn japanese_my_number_rule_uses_the_official_digit_order() {
        let generated = synthetic_my_number("10000000000");
        assert_eq!(generated.as_bytes().last(), Some(&b'5'));
        assert_rule_span(
            &format!("個人番号候補：{generated}。"),
            SensitiveRuleId::JapaneseMyNumberCandidateV1,
            &generated,
        );

        let mut altered = generated.clone().into_bytes();
        altered[11] = if altered[11] == b'9' {
            b'0'
        } else {
            altered[11] + 1
        };
        let altered = String::from_utf8(altered).expect("ASCII fixture");
        for near_miss in [
            altered,
            "12345678901".to_owned(),
            format!("{generated}0"),
            format!("9{generated}8"),
            format!("A{generated}B"),
            format!("日{generated}"),
            format!("{generated}日"),
        ] {
            assert_no_rule(&near_miss, SensitiveRuleId::JapaneseMyNumberCandidateV1);
        }

        assert_eq!(my_number_check_digit(b"00000000000"), Some(0));
        assert_eq!(my_number_check_digit(b"00000000006"), Some(0));
    }

    #[test]
    fn japanese_corporate_rule_uses_leading_check_digit_and_official_parity() {
        let base = "102030405060";
        let generated = synthetic_corporate_number(base);
        assert_eq!(generated.as_bytes().first(), Some(&b'3'));
        assert_rule_span(
            &format!("法人番号候補：{generated}。"),
            SensitiveRuleId::JapaneseCorporateNumberCandidateV1,
            &generated,
        );
        assert_rule_span(
            &format!("REPORT-{generated}"),
            SensitiveRuleId::JapaneseCorporateNumberCandidateV1,
            &generated,
        );

        for near_miss in [
            base.to_owned(),
            format!("{generated}0"),
            format!("X{generated}Y"),
            format!("T{generated}"),
            format!("{base}3"),
            format!("6{base}"),
            format!("日{generated}"),
            format!("{generated}日"),
        ] {
            assert_no_rule(
                &near_miss,
                SensitiveRuleId::JapaneseCorporateNumberCandidateV1,
            );
        }
    }

    #[test]
    fn unicode_punctuation_is_an_identifier_boundary() {
        assert_rule_span(
            "メール：fixture.user@example.invalid。",
            SensitiveRuleId::AsciiEmailV1,
            "fixture.user@example.invalid",
        );
        assert_rule_span(
            "電話（代表）：+81 90-1234-5678。",
            SensitiveRuleId::InternationalPhoneV1,
            "+81 90-1234-5678",
        );
        assert_rule_span(
            "接続先：192.0.2.10。",
            SensitiveRuleId::Ipv4AddressV1,
            "192.0.2.10",
        );
        assert_rule_span(
            "接続先：[2001:db8::10]。",
            SensitiveRuleId::Ipv6AddressV1,
            "2001:db8::10",
        );
    }

    #[test]
    fn unicode_alphanumeric_adjacency_is_not_a_boundary() {
        for near_miss in [
            "日本語fixture.user@example.invalid",
            "fixture.user@example.invalid日本語",
            "éfixture.user@example.invalid",
            "fixture.user@example.invalidé",
            "接続先192.0.2.10",
            "192.0.2.10接続先",
        ] {
            assert!(scan(near_miss).is_empty(), "unexpected match: {near_miss}");
        }
    }

    #[test]
    fn identifier_boundary_distinguishes_unicode_delimiters_from_alphanumeric() {
        assert!(is_identifier_boundary(':', is_email_token));
        assert!(!is_identifier_boundary('@', is_email_token));
        for delimiter in ['：', '。', '★', '\u{3000}'] {
            assert!(is_identifier_boundary(delimiter, is_email_token));
        }
        for token_continuation in ['日', 'é', '９'] {
            assert!(!is_identifier_boundary(token_continuation, is_email_token));
        }
    }

    #[test]
    fn multiple_findings_are_deduplicated_and_deterministically_ordered() {
        let my_number = synthetic_my_number("10000000000");
        let corporate_number = synthetic_corporate_number("102030405060");
        let text = format!(
            "{EMAIL}\n{COMPACT_PHONE}\n{JP_MOBILE}\n{IPV4}\n{IPV6}\n{POSTAL}\n{my_number}\n{corporate_number}"
        );
        let mut session = Session::new(Limits::default()).expect("compile trusted rules");
        let mut first = Vec::new();
        session
            .scan_file(&text, |findings| first.extend_from_slice(findings))
            .expect("scan succeeds");
        let report = session.finish().expect("report is consistent");
        let second = scan(&text);

        assert_eq!(first, second);
        assert_eq!(first.len(), 8);
        assert!(first.windows(2).all(|pair| pair[0] < pair[1]));
        assert_eq!(report.scan_candidates, 1);
        assert_eq!(report.findings, 8);
        assert_eq!(report.files_with_findings, 1);
        assert_eq!(report.email_findings, 1);
        assert_eq!(report.phone_findings, 1);
        assert_eq!(report.jp_phone_findings, 1);
        assert_eq!(report.ip_findings, 2);
        assert_eq!(report.jp_postal_findings, 1);
        assert_eq!(report.my_number_candidate_findings, 1);
        assert_eq!(report.corporate_number_candidate_findings, 1);

        let duplicate = first[0];
        let mut set = BTreeSet::new();
        insert_finding(&mut set, duplicate, text.len(), 1).expect("first insert");
        insert_finding(&mut set, duplicate, text.len(), 1).expect("duplicate is deduplicated");
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn candidate_and_finding_limits_fail_closed() {
        let mut logical_counts = BTreeMap::new();
        assert_eq!(
            record_rule_candidate(&mut logical_counts, SensitiveRuleId::AsciiEmailV1, 1),
            Ok(())
        );
        assert_eq!(
            record_rule_candidate(&mut logical_counts, SensitiveRuleId::AsciiEmailV1, 1),
            Err(SensitiveError::CandidateLimitExceeded)
        );
        assert_eq!(
            record_rule_candidate(
                &mut logical_counts,
                SensitiveRuleId::InternationalPhoneV1,
                1
            ),
            Ok(())
        );

        let two_emails = format!("{EMAIL}\nfixture.two@example.invalid");
        let mut candidate_limited = Session::new(Limits {
            max_candidates_per_rule_per_file: 1,
            ..Limits::default()
        })
        .expect("compile rules");
        assert_eq!(
            candidate_limited.scan_file(&two_emails, |_| {}),
            Err(SensitiveError::CandidateLimitExceeded)
        );

        let mut invalid_candidate_limited = Session::new(Limits {
            max_candidates_per_rule_per_file: 0,
            ..Limits::default()
        })
        .expect("compile rules");
        assert_eq!(
            invalid_candidate_limited.scan_file("192.0.2.999", |_| {}),
            Err(SensitiveError::CandidateLimitExceeded)
        );

        let mut checksum_candidate_limited = Session::new(Limits {
            max_candidates_per_rule_per_file: 0,
            ..Limits::default()
        })
        .expect("compile rules");
        assert_eq!(
            checksum_candidate_limited.scan_file("123456789012", |_| {}),
            Err(SensitiveError::CandidateLimitExceeded)
        );

        let mut domestic_candidate_limited = Session::new(Limits {
            max_candidates_per_rule_per_file: 1,
            ..Limits::default()
        })
        .expect("compile rules");
        assert_eq!(
            domestic_candidate_limited.scan_file("060-0000-0000\n060-0000-0000", |_| {}),
            Err(SensitiveError::CandidateLimitExceeded),
            "candidates are counted before the 060 subrange validator rejects them"
        );

        let mut domestic_rules_are_independent = Session::new(Limits {
            max_candidates_per_rule_per_file: 1,
            ..Limits::default()
        })
        .expect("compile rules");
        assert_eq!(
            domestic_rules_are_independent
                .scan_file("09000000000\n05000000000\n0120-000-000", |_| {}),
            Ok(3)
        );

        let my_number = synthetic_my_number("10000000000");
        let corporate_number = synthetic_corporate_number("102030405060");
        let mut new_rules_are_independent = Session::new(Limits {
            max_candidates_per_rule_per_file: 1,
            ..Limits::default()
        })
        .expect("compile rules");
        assert_eq!(
            new_rules_are_independent.scan_file(&format!("{POSTAL}\n{my_number}"), |_| {}),
            Ok(2)
        );

        let mut overlapping_rules_are_independently_bounded = Session::new(Limits {
            max_candidates_per_rule_per_file: 1,
            ..Limits::default()
        })
        .expect("compile rules");
        assert_eq!(
            overlapping_rules_are_independently_bounded.scan_file(&corporate_number, |_| {}),
            Ok(1)
        );

        let mut new_logical_rule_limited = Session::new(Limits {
            max_candidates_per_rule_per_file: 1,
            ..Limits::default()
        })
        .expect("compile rules");
        assert_eq!(
            new_logical_rule_limited.scan_file(&format!("{my_number}\n{my_number}"), |_| {}),
            Err(SensitiveError::CandidateLimitExceeded)
        );

        let mut independent_rules = Session::new(Limits {
            max_candidates_per_rule_per_file: 1,
            ..Limits::default()
        })
        .expect("compile rules");
        assert_eq!(
            independent_rules.scan_file(&format!("{EMAIL}\n{COMPACT_PHONE}"), |_| {}),
            Ok(2)
        );
        assert_eq!(independent_rules.scan_file(EMAIL, |_| {}), Ok(1));

        let mut file_limited = Session::new(Limits {
            max_findings_per_file: 1,
            ..Limits::default()
        })
        .expect("compile rules");
        assert_eq!(
            file_limited.scan_file(&format!("{EMAIL}\n{PHONE}"), |_| {}),
            Err(SensitiveError::FileFindingLimitExceeded)
        );

        let mut run_limited = Session::new(Limits {
            max_findings_per_run: 1,
            ..Limits::default()
        })
        .expect("compile rules");
        assert_eq!(run_limited.scan_file(EMAIL, |_| {}), Ok(1));
        assert_eq!(
            run_limited.scan_file(EMAIL, |_| {}),
            Err(SensitiveError::RunFindingLimitExceeded)
        );
    }

    #[test]
    fn checked_overflow_and_inconsistent_reports_fail_closed() {
        let mut candidate_counts = BTreeMap::from([(SensitiveRuleId::AsciiEmailV1, usize::MAX)]);
        assert_eq!(
            record_rule_candidate(
                &mut candidate_counts,
                SensitiveRuleId::AsciiEmailV1,
                usize::MAX
            ),
            Err(SensitiveError::CountOverflow)
        );

        let mut session = Session::new(Limits::default()).expect("compile rules");
        session.report.scan_candidates = usize::MAX;
        assert_eq!(
            session.scan_file("ordinary readable text", |_| {}),
            Err(SensitiveError::CountOverflow)
        );

        assert_eq!(
            Report {
                findings: usize::MAX,
                email_findings: usize::MAX,
                phone_findings: 1,
                ..Report::default()
            }
            .validate(),
            Err(SensitiveError::CountOverflow)
        );
        assert_eq!(
            Report {
                scan_candidates: 1,
                findings: 1,
                files_with_findings: 1,
                ..Report::default()
            }
            .validate(),
            Err(SensitiveError::InconsistentCounts)
        );
        assert_eq!(
            Report {
                findings: 1,
                files_with_findings: 1,
                email_findings: 1,
                ..Report::default()
            }
            .validate(),
            Err(SensitiveError::InconsistentCounts)
        );
    }

    #[test]
    fn findings_and_errors_never_format_raw_values() {
        let raw = JP_MOBILE.to_owned();
        let finding = scan(&raw)[0];
        assert!(!format!("{finding:?}").contains(&raw));
        assert!(!finding.to_string().contains(&raw));
        for error in [
            SensitiveError::RuleCompilationFailed,
            SensitiveError::InvalidFindingSpan,
            SensitiveError::CandidateLimitExceeded,
            SensitiveError::FileFindingLimitExceeded,
            SensitiveError::RunFindingLimitExceeded,
            SensitiveError::CountOverflow,
            SensitiveError::InconsistentCounts,
        ] {
            assert!(!format!("{error:?}").contains(&raw));
            assert!(!error.to_string().contains(&raw));
        }
    }
}
