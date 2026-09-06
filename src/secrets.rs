//! Deterministic, bounded secret evidence for transient readable text.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use regex::{Captures, Regex};

use crate::rule_metadata::{DetectorRuleSpec, Parameter, SCOPE_CONTENT, SCOPE_PATH};

pub const DEFAULT_MAX_FINDINGS_PER_FILE: usize = 256;
pub const DEFAULT_MAX_FINDINGS_PER_RUN: usize = 4_096;
pub const DEFAULT_MAX_MATCHES_PER_RULE_PER_FILE: usize = 512;

const MIN_PRIVATE_KEY_BODY_BYTES: usize = 64;
const MAX_PRIVATE_KEY_BODY_BYTES: usize = 1024 * 1024;
const MIN_ASSIGNMENT_VALUE_BYTES: usize = 16;
const MAX_ASSIGNMENT_VALUE_BYTES: usize = 256;
const MIN_GITHUB_TOKEN_ENTROPY: f64 = 3.0;
const MIN_ASSIGNMENT_ENTROPY: f64 = 3.5;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum RuleId {
    PrivateKeyMaterialV1,
    JwtCompactJwsV1,
    CredentialUriUserinfoV1,
    GithubClassicPatV1,
    GithubFineGrainedPatV1,
    GithubOauthTokenV1,
    GithubAppTokenV1,
    GithubRefreshTokenV1,
    ExplicitSecretAssignmentV1,
}

impl RuleId {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PrivateKeyMaterialV1 => "private-key-material-v1",
            Self::JwtCompactJwsV1 => "jwt-compact-jws-v1",
            Self::CredentialUriUserinfoV1 => "credential-uri-userinfo-v1",
            Self::GithubClassicPatV1 => "github-classic-pat-v1",
            Self::GithubFineGrainedPatV1 => "github-fine-grained-pat-v1",
            Self::GithubOauthTokenV1 => "github-oauth-token-v1",
            Self::GithubAppTokenV1 => "github-app-token-v1",
            Self::GithubRefreshTokenV1 => "github-refresh-token-v1",
            Self::ExplicitSecretAssignmentV1 => "explicit-secret-assignment-v1",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum SecretCategory {
    PrivateKeyMaterial,
    JwtCredential,
    CredentialUri,
    ProviderToken,
    ExplicitAssignment,
}

impl SecretCategory {
    const fn as_str(self) -> &'static str {
        match self {
            Self::PrivateKeyMaterial => "private_key_material",
            Self::JwtCredential => "jwt_credential",
            Self::CredentialUri => "credential_uri",
            Self::ProviderToken => "provider_token",
            Self::ExplicitAssignment => "explicit_assignment",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct SecretSpan {
    pub start: usize,
    pub end: usize,
}

/// File-local evidence. It intentionally contains no matched text.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct SecretFinding {
    pub span: SecretSpan,
    pub rule_id: RuleId,
    pub category: SecretCategory,
}

impl fmt::Display for SecretFinding {
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
    pub max_matches_per_rule_per_file: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_findings_per_file: DEFAULT_MAX_FINDINGS_PER_FILE,
            max_findings_per_run: DEFAULT_MAX_FINDINGS_PER_RUN,
            max_matches_per_rule_per_file: DEFAULT_MAX_MATCHES_PER_RULE_PER_FILE,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Report {
    pub scan_candidates: usize,
    pub findings: usize,
    pub files_with_findings: usize,
}

impl Report {
    pub(crate) fn validate(self) -> Result<(), SecretError> {
        if self.files_with_findings > self.scan_candidates
            || self.files_with_findings > self.findings
            || (self.findings == 0) != (self.files_with_findings == 0)
        {
            return Err(SecretError::InconsistentCounts);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecretError {
    RuleCompilationFailed,
    InvalidFindingSpan,
    MatchLimitExceeded,
    FileFindingLimitExceeded,
    RunFindingLimitExceeded,
    CountOverflow,
    InconsistentCounts,
}

impl fmt::Display for SecretError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::RuleCompilationFailed => "secret rules could not be initialized",
            Self::InvalidFindingSpan => "secret detector produced invalid evidence",
            Self::MatchLimitExceeded => "secret detector match limit exceeded",
            Self::FileFindingLimitExceeded => "secret finding per-file limit exceeded",
            Self::RunFindingLimitExceeded => "secret finding run limit exceeded",
            Self::CountOverflow => "secret evidence count overflowed",
            Self::InconsistentCounts => "secret evidence counts are inconsistent",
        })
    }
}

#[derive(Clone, Copy)]
enum RuleKind {
    PrivateKey,
    Jwt,
    CredentialUri,
    GithubToken,
    Assignment,
}

struct CompiledRule {
    id: RuleId,
    category: SecretCategory,
    kind: RuleKind,
    regex: Regex,
}

struct SourceRuleSpec {
    id: RuleId,
    category: SecretCategory,
    kind: RuleKind,
    patterns: Vec<String>,
    validator_id: &'static str,
    parameters: Vec<Parameter>,
}

/// Compiled fixed rules reused by content and path-component scans.
//
// The additional GitHub token-family rules below adapt the selected
// `cmd/generate/config/rules/github.go` metadata from
// gitleaks/gitleaks@b58d3f102cf3a2c84cb7f923d05c25c9b1aed84b under MIT.
// The classic PAT remains the earlier 83d9cd684c87d95d656c1458ef04895a7f1cbd8e
// adaptation; scanner, allowlist, and Git behavior are intentionally omitted.
pub(crate) struct RuleSet {
    rules: Vec<CompiledRule>,
}

impl RuleSet {
    pub(crate) fn compile() -> Result<Self, SecretError> {
        let mut rules = Vec::new();
        for source in source_rule_specs() {
            for pattern in source.patterns {
                rules.push(CompiledRule {
                    id: source.id,
                    category: source.category,
                    kind: source.kind,
                    regex: compile_regex(&pattern)?,
                });
            }
        }
        Ok(Self { rules })
    }

    pub(crate) fn find(
        &self,
        text: &str,
        limits: Limits,
    ) -> Result<Vec<SecretFinding>, SecretError> {
        let mut findings = BTreeSet::new();
        let mut matches_per_rule = BTreeMap::new();
        for rule in &self.rules {
            scan_rule(rule, text, limits, &mut matches_per_rule, &mut findings)?;
        }
        Ok(findings.into_iter().collect())
    }
}

fn common_parameters() -> Vec<Parameter> {
    vec![
        Parameter {
            id: "max-findings-per-file",
            value: DEFAULT_MAX_FINDINGS_PER_FILE as u64,
        },
        Parameter {
            id: "max-findings-per-run",
            value: DEFAULT_MAX_FINDINGS_PER_RUN as u64,
        },
        Parameter {
            id: "max-matches-per-rule-per-file",
            value: DEFAULT_MAX_MATCHES_PER_RULE_PER_FILE as u64,
        },
    ]
}

fn source_rule_specs() -> Vec<SourceRuleSpec> {
    let private_patterns = [
        "PRIVATE KEY",
        "ENCRYPTED PRIVATE KEY",
        "RSA PRIVATE KEY",
        "EC PRIVATE KEY",
        "DSA PRIVATE KEY",
        "OPENSSH PRIVATE KEY",
    ]
    .into_iter()
    .map(|label| format!("-----BEGIN {label}-----([A-Za-z0-9+/=\\r\\n\\t ]+)-----END {label}-----"))
    .collect();
    let mut private_parameters = common_parameters();
    private_parameters.extend([
        Parameter {
            id: "minimum-private-key-body-bytes",
            value: MIN_PRIVATE_KEY_BODY_BYTES as u64,
        },
        Parameter {
            id: "maximum-private-key-body-bytes",
            value: MAX_PRIVATE_KEY_BODY_BYTES as u64,
        },
    ]);
    let mut github_parameters = common_parameters();
    github_parameters.push(Parameter {
        id: "minimum-shannon-entropy-milli-bits",
        value: (MIN_GITHUB_TOKEN_ENTROPY * 1000.0) as u64,
    });
    let github = |id, pattern: &str| SourceRuleSpec {
        id,
        category: SecretCategory::ProviderToken,
        kind: RuleKind::GithubToken,
        patterns: vec![pattern.to_owned()],
        validator_id: "github-token-boundary-entropy-v1",
        parameters: github_parameters.clone(),
    };
    let mut assignment_parameters = common_parameters();
    assignment_parameters.extend([
        Parameter {
            id: "minimum-assignment-value-bytes",
            value: MIN_ASSIGNMENT_VALUE_BYTES as u64,
        },
        Parameter {
            id: "maximum-assignment-value-bytes",
            value: MAX_ASSIGNMENT_VALUE_BYTES as u64,
        },
        Parameter {
            id: "minimum-shannon-entropy-milli-bits",
            value: (MIN_ASSIGNMENT_ENTROPY * 1000.0) as u64,
        },
    ]);
    vec![
        SourceRuleSpec {
            id: RuleId::PrivateKeyMaterialV1,
            category: SecretCategory::PrivateKeyMaterial,
            kind: RuleKind::PrivateKey,
            patterns: private_patterns,
            validator_id: "pem-private-key-body-v1",
            parameters: private_parameters,
        },
        SourceRuleSpec {
            id: RuleId::JwtCompactJwsV1,
            category: SecretCategory::JwtCredential,
            kind: RuleKind::Jwt,
            patterns: vec![r"(?:^|[^A-Za-z0-9_.-])(eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)".to_owned()],
            validator_id: "jwt-three-base64url-segments-v1",
            parameters: common_parameters(),
        },
        SourceRuleSpec {
            id: RuleId::CredentialUriUserinfoV1,
            category: SecretCategory::CredentialUri,
            kind: RuleKind::CredentialUri,
            patterns: vec![r"(?:^|[^A-Za-z0-9+.-])(?i:(?:https?|ftps?|ssh|git|postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|rediss?|amqps?))://[A-Za-z0-9._~!$&'()*+,;=%-]+:([A-Za-z0-9._~!$&'()*+,;=:%-]+)@[A-Za-z0-9.\[\]:_-]+".to_owned()],
            validator_id: "credential-uri-userinfo-boundary-v1",
            parameters: common_parameters(),
        },
        github(RuleId::GithubClassicPatV1, r"(?:^|[^A-Za-z0-9_])(ghp_[A-Za-z0-9]{36})"),
        github(RuleId::GithubFineGrainedPatV1, r"(?:^|[^A-Za-z0-9_])(github_pat_[A-Za-z0-9_]{82})"),
        github(RuleId::GithubOauthTokenV1, r"(?:^|[^A-Za-z0-9_])(gho_[A-Za-z0-9]{36})"),
        github(RuleId::GithubAppTokenV1, r"(?:^|[^A-Za-z0-9_])((?:ghu|ghs)_[A-Za-z0-9]{36})"),
        github(RuleId::GithubRefreshTokenV1, r"(?:^|[^A-Za-z0-9_])(ghr_[A-Za-z0-9]{36})"),
        SourceRuleSpec {
            id: RuleId::ExplicitSecretAssignmentV1,
            category: SecretCategory::ExplicitAssignment,
            kind: RuleKind::Assignment,
            patterns: vec![r#"(?im)^[\t ]*(?:export[\t ]+)?(?:secret|password|passwd|token|api[_-]?key)[\t ]*(?::=|=|:)[\t ]*(?:"([A-Za-z0-9+/_.=-]+)"|'([A-Za-z0-9+/_.=-]+)'|([A-Za-z0-9+/_.=-]+))[\t ]*[,;]?[\t ]*\r?$"#.to_owned()],
            validator_id: "explicit-assignment-boundary-entropy-v1",
            parameters: assignment_parameters,
        },
    ]
}

pub(crate) fn descriptor_rule_specs() -> Vec<DetectorRuleSpec> {
    source_rule_specs()
        .into_iter()
        .map(|source| DetectorRuleSpec {
            rule_id: source.id.as_str(),
            scope_flags: SCOPE_CONTENT | SCOPE_PATH,
            patterns: source
                .patterns
                .into_iter()
                .map(String::into_bytes)
                .collect(),
            validator_id: source.validator_id,
            category: source.category.as_str(),
            token_category: "SECRET",
            parameters: source.parameters,
        })
        .collect()
}

fn compile_regex(pattern: &str) -> Result<Regex, SecretError> {
    Regex::new(pattern).map_err(|_| SecretError::RuleCompilationFailed)
}

fn scan_rule(
    rule: &CompiledRule,
    text: &str,
    limits: Limits,
    matches_per_rule: &mut BTreeMap<RuleId, usize>,
    findings: &mut BTreeSet<SecretFinding>,
) -> Result<(), SecretError> {
    let mut search_at = 0_usize;
    while search_at <= text.len() {
        let Some(captures) = rule.regex.captures_at(text, search_at) else {
            break;
        };
        record_rule_match(
            matches_per_rule,
            rule.id,
            limits.max_matches_per_rule_per_file,
        )?;
        let whole = captures.get(0).ok_or(SecretError::InvalidFindingSpan)?;
        let next_search = whole.end();
        if next_search <= search_at {
            return Err(SecretError::InvalidFindingSpan);
        }

        if let Some(span) = validate_match(rule.kind, text, &captures) {
            let finding = SecretFinding {
                span,
                rule_id: rule.id,
                category: rule.category,
            };
            insert_finding(findings, finding, text.len(), limits.max_findings_per_file)?;
        }
        search_at = next_search;
    }
    Ok(())
}

fn record_rule_match(
    matches_per_rule: &mut BTreeMap<RuleId, usize>,
    rule_id: RuleId,
    limit: usize,
) -> Result<(), SecretError> {
    let count = matches_per_rule.entry(rule_id).or_default();
    let next = count.checked_add(1).ok_or(SecretError::CountOverflow)?;
    if next > limit {
        return Err(SecretError::MatchLimitExceeded);
    }
    *count = next;
    Ok(())
}

fn insert_finding(
    findings: &mut BTreeSet<SecretFinding>,
    finding: SecretFinding,
    text_len: usize,
    limit: usize,
) -> Result<(), SecretError> {
    if finding.span.start >= finding.span.end || finding.span.end > text_len {
        return Err(SecretError::InvalidFindingSpan);
    }
    if findings.insert(finding) && findings.len() > limit {
        return Err(SecretError::FileFindingLimitExceeded);
    }
    Ok(())
}

fn validate_match(kind: RuleKind, text: &str, captures: &Captures<'_>) -> Option<SecretSpan> {
    match kind {
        RuleKind::PrivateKey => validate_private_key(captures),
        RuleKind::Jwt => validate_jwt(text, captures),
        RuleKind::CredentialUri => capture_span(captures, 1).filter(|span| {
            let length = span.end - span.start;
            (1..=MAX_ASSIGNMENT_VALUE_BYTES).contains(&length)
        }),
        RuleKind::GithubToken => capture_span(captures, 1).filter(|span| {
            has_github_token_boundary_after(text, *span)
                && shannon_entropy(&text[span.start..span.end]) >= MIN_GITHUB_TOKEN_ENTROPY
        }),
        RuleKind::Assignment => validate_assignment(text, captures),
    }
}

fn validate_private_key(captures: &Captures<'_>) -> Option<SecretSpan> {
    let body = captures.get(1)?.as_str();
    let mut body_bytes = 0_usize;
    let mut padding = 0_usize;
    for byte in body.bytes() {
        if byte.is_ascii_whitespace() {
            continue;
        }
        body_bytes = body_bytes.checked_add(1)?;
        if byte == b'=' {
            padding = padding.checked_add(1)?;
            if padding > 2 {
                return None;
            }
        } else if padding != 0 {
            return None;
        }
    }
    if !(MIN_PRIVATE_KEY_BODY_BYTES..=MAX_PRIVATE_KEY_BODY_BYTES).contains(&body_bytes)
        || !body_bytes.is_multiple_of(4)
    {
        return None;
    }
    capture_span(captures, 0)
}

fn validate_jwt(text: &str, captures: &Captures<'_>) -> Option<SecretSpan> {
    let span = capture_span(captures, 1)?;
    if !has_token_boundary_after(text, span) {
        return None;
    }
    let mut segments = text[span.start..span.end].split('.');
    let header = segments.next()?;
    let payload = segments.next()?;
    let signature = segments.next()?;
    if segments.next().is_some()
        || !valid_base64url_segment(header, 8, 2_048)
        || !valid_base64url_segment(payload, 2, 8_192)
        || !valid_base64url_segment(signature, 16, 4_096)
    {
        return None;
    }
    Some(span)
}

fn valid_base64url_segment(value: &str, min: usize, max: usize) -> bool {
    (min..=max).contains(&value.len()) && value.len() % 4 != 1
}

fn has_token_boundary_after(text: &str, span: SecretSpan) -> bool {
    text.as_bytes()
        .get(span.end)
        .is_none_or(|byte| !byte.is_ascii_alphanumeric() && !matches!(byte, b'_' | b'-' | b'.'))
}

fn has_github_token_boundary_after(text: &str, span: SecretSpan) -> bool {
    text.as_bytes()
        .get(span.end)
        .is_none_or(|byte| !byte.is_ascii_alphanumeric() && *byte != b'_')
}

fn validate_assignment(text: &str, captures: &Captures<'_>) -> Option<SecretSpan> {
    let span = [1, 2, 3]
        .into_iter()
        .find_map(|capture| capture_span(captures, capture))?;
    let value = &text[span.start..span.end];
    if !(MIN_ASSIGNMENT_VALUE_BYTES..=MAX_ASSIGNMENT_VALUE_BYTES).contains(&value.len())
        || !value.bytes().any(|byte| byte.is_ascii_alphabetic())
        || !value.bytes().any(|byte| byte.is_ascii_digit())
        || shannon_entropy(value) < MIN_ASSIGNMENT_ENTROPY
    {
        return None;
    }
    Some(span)
}

fn capture_span(captures: &Captures<'_>, index: usize) -> Option<SecretSpan> {
    let matched = captures.get(index)?;
    Some(SecretSpan {
        start: matched.start(),
        end: matched.end(),
    })
}

fn shannon_entropy(value: &str) -> f64 {
    let mut frequencies = [0_usize; 256];
    for byte in value.bytes() {
        frequencies[usize::from(byte)] += 1;
    }
    let length = value.len() as f64;
    frequencies
        .into_iter()
        .filter(|count| *count != 0)
        .map(|count| {
            let probability = count as f64 / length;
            -probability * probability.log2()
        })
        .sum()
}

pub(crate) struct Session {
    limits: Limits,
    rules: RuleSet,
    report: Report,
}

impl Session {
    pub(crate) fn new(limits: Limits) -> Result<Self, SecretError> {
        Ok(Self {
            limits,
            rules: RuleSet::compile()?,
            report: Report::default(),
        })
    }

    pub(crate) fn scan_file(
        &mut self,
        text: &str,
        mut consume_findings: impl FnMut(&[SecretFinding]),
    ) -> Result<usize, SecretError> {
        let findings = self.rules.find(text, self.limits)?;
        let finding_count = findings.len();
        let next_scan_candidates = self
            .report
            .scan_candidates
            .checked_add(1)
            .ok_or(SecretError::CountOverflow)?;
        let next_findings = self
            .report
            .findings
            .checked_add(finding_count)
            .ok_or(SecretError::CountOverflow)?;
        if next_findings > self.limits.max_findings_per_run {
            return Err(SecretError::RunFindingLimitExceeded);
        }
        let next_files_with_findings = if findings.is_empty() {
            self.report.files_with_findings
        } else {
            self.report
                .files_with_findings
                .checked_add(1)
                .ok_or(SecretError::CountOverflow)?
        };

        self.report = Report {
            scan_candidates: next_scan_candidates,
            findings: next_findings,
            files_with_findings: next_files_with_findings,
        };
        consume_findings(&findings);
        Ok(finding_count)
    }

    pub(crate) fn finish(self) -> Result<Report, SecretError> {
        self.report.validate()?;
        Ok(self.report)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SYNTHETIC_JWT: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJmaXh0dXJlLW9ubHkiLCJleHAiOjB9.c3ludGhldGljLW5vbi1saXZlLXNpZ25hdHVyZQ";
    const SYNTHETIC_GITHUB_PAT: &str = "ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8";
    const SYNTHETIC_ASSIGNMENT: &str = "N0nLive_Fixture_4A7c9E2b";

    fn synthetic_github_token(prefix: &str, body_len: usize) -> String {
        const ALPHABET: &[u8] = b"A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0UvWxYz_";
        let body = (0..body_len)
            .map(|index| ALPHABET[index % ALPHABET.len()])
            .collect::<Vec<_>>();
        format!(
            "{prefix}{}",
            String::from_utf8(body).expect("ASCII fixture")
        )
    }

    fn low_entropy_github_token(prefix: &str, body_len: usize) -> String {
        format!("{prefix}{}", "x".repeat(body_len))
    }

    fn scan(text: &str) -> Vec<SecretFinding> {
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

    fn assert_rule(text: &str, rule_id: RuleId) {
        assert!(
            scan(text).iter().any(|finding| finding.rule_id == rule_id),
            "expected synthetic fixture to match {}",
            rule_id.as_str()
        );
    }

    fn synthetic_private_key(label: &str) -> String {
        let body = "Q".repeat(64);
        format!("-----BEGIN {label}-----\n{body}\n-----END {label}-----")
    }

    #[test]
    fn default_limits_are_explicit() {
        assert_eq!(
            Limits::default(),
            Limits {
                max_findings_per_file: 256,
                max_findings_per_run: 4_096,
                max_matches_per_rule_per_file: 512,
            }
        );
    }

    #[test]
    fn private_key_rule_requires_matching_private_markers_and_body() {
        let body = "Q".repeat(64);
        assert_rule(
            &synthetic_private_key("PRIVATE KEY"),
            RuleId::PrivateKeyMaterialV1,
        );
        for near_miss in [
            format!("-----BEGIN PUBLIC KEY-----\n{body}\n-----END PUBLIC KEY-----"),
            format!("-----BEGIN PRIVATE KEY-----\n{body}"),
            "-----BEGIN PRIVATE KEY-----\nQUJD\n-----END PRIVATE KEY-----".to_owned(),
        ] {
            assert!(scan(&near_miss).is_empty());
        }
    }

    #[test]
    fn jwt_rule_requires_three_bounded_compact_segments() {
        assert_rule(SYNTHETIC_JWT, RuleId::JwtCompactJwsV1);
        assert!(scan("eyJhbGciOiJIUzI1NiJ9.payload").is_empty());
        assert!(scan("eyJhbGciOiJIUzI1NiJ9.payload.short").is_empty());
        assert!(scan(&format!("{SYNTHETIC_JWT}.fourth")).is_empty());
    }

    #[test]
    fn credential_uri_rule_requires_nonempty_password_userinfo() {
        assert_rule(
            "https://fixture-user:N0nLiveFixtureP4ss@example.invalid/repo",
            RuleId::CredentialUriUserinfoV1,
        );
        assert!(scan("https://fixture-user@example.invalid/repo").is_empty());
        assert!(scan("https://fixture-user:@example.invalid/repo").is_empty());
        assert!(scan("nothttps://fixture-user:N0nLiveFixtureP4ss@example.invalid").is_empty());
    }

    #[test]
    fn github_rule_uses_documented_classic_pat_shape_and_entropy() {
        assert_rule(SYNTHETIC_GITHUB_PAT, RuleId::GithubClassicPatV1);
        assert_rule(
            &format!("{SYNTHETIC_GITHUB_PAT}."),
            RuleId::GithubClassicPatV1,
        );
        assert!(scan("ghp_too_short").is_empty());
        assert!(scan("github_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8").is_empty());
        assert!(scan("ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx").is_empty());
        assert!(scan(&format!("{SYNTHETIC_GITHUB_PAT}x")).is_empty());
        assert!(scan("AKIAIOSFODNN7EXAMPLE").is_empty());
    }

    #[test]
    fn github_token_family_rules_use_ascii_shapes_and_entropy() {
        let fine_grained = synthetic_github_token("github_pat_", 82);
        let oauth = synthetic_github_token("gho_", 36);
        let app_user = synthetic_github_token("ghu_", 36);
        let app_server = synthetic_github_token("ghs_", 36);
        let refresh = synthetic_github_token("ghr_", 36);

        assert_rule(&fine_grained, RuleId::GithubFineGrainedPatV1);
        assert_rule(&oauth, RuleId::GithubOauthTokenV1);
        assert_rule(&app_user, RuleId::GithubAppTokenV1);
        assert_rule(&app_server, RuleId::GithubAppTokenV1);
        assert_rule(&refresh, RuleId::GithubRefreshTokenV1);

        assert!(scan(&synthetic_github_token("ghx_", 36)).is_empty());
        assert!(scan(&low_entropy_github_token("ghs_", 36)).is_empty());

        let findings = scan(&format!(
            "{fine_grained}\n{oauth}\n{app_user}\n{app_server}\n{refresh}"
        ));
        assert_eq!(
            findings
                .iter()
                .filter(|finding| finding.category == SecretCategory::ProviderToken)
                .count(),
            5
        );

        for (token, rule_id) in [
            (&fine_grained, RuleId::GithubFineGrainedPatV1),
            (&oauth, RuleId::GithubOauthTokenV1),
            (&app_user, RuleId::GithubAppTokenV1),
            (&refresh, RuleId::GithubRefreshTokenV1),
        ] {
            assert!(scan(&token[..token.len() - 1]).is_empty());
            assert!(scan(&format!("{token}A")).is_empty());
            assert!(scan(&format!("x{token}")).is_empty());
            assert!(
                scan(&low_entropy_github_token(
                    match rule_id {
                        RuleId::GithubFineGrainedPatV1 => "github_pat_",
                        RuleId::GithubOauthTokenV1 => "gho_",
                        RuleId::GithubAppTokenV1 => "ghu_",
                        RuleId::GithubRefreshTokenV1 => "ghr_",
                        _ => unreachable!(),
                    },
                    match rule_id {
                        RuleId::GithubFineGrainedPatV1 => 82,
                        RuleId::GithubOauthTokenV1
                        | RuleId::GithubAppTokenV1
                        | RuleId::GithubRefreshTokenV1 => 36,
                        _ => unreachable!(),
                    },
                ))
                .is_empty(),
                "low-entropy {rule_id:?} fixture must be rejected"
            );
        }

        let unicode_widening = format!("github_pat_{}", "é".repeat(82));
        assert!(scan(&unicode_widening).is_empty());
    }

    #[test]
    fn github_app_variants_share_one_logical_candidate_limit() {
        let app_user = synthetic_github_token("ghu_", 36);
        let app_server = synthetic_github_token("ghs_", 36);
        let mut limited = Session::new(Limits {
            max_matches_per_rule_per_file: 1,
            ..Limits::default()
        })
        .expect("compile rules");

        assert_eq!(
            limited.scan_file(&format!("{app_user} {app_server}"), |_| {}),
            Err(SecretError::MatchLimitExceeded)
        );
    }

    #[test]
    fn github_token_rules_have_independent_candidate_limits() {
        let fine_grained = synthetic_github_token("github_pat_", 82);
        let oauth = synthetic_github_token("gho_", 36);
        let app = synthetic_github_token("ghu_", 36);
        let refresh = synthetic_github_token("ghr_", 36);
        let text = format!("{fine_grained}\n{oauth}\n{app}\n{refresh}");
        let mut limited = Session::new(Limits {
            max_matches_per_rule_per_file: 1,
            ..Limits::default()
        })
        .expect("compile rules");

        assert_eq!(limited.scan_file(&text, |_| {}), Ok(4));
    }

    #[test]
    fn assignment_rule_is_exact_constrained_and_high_entropy() {
        assert_rule(
            &format!("password = \"{SYNTHETIC_ASSIGNMENT}\""),
            RuleId::ExplicitSecretAssignmentV1,
        );
        for near_miss in [
            "password_length = 32",
            "password = \"placeholder\"",
            "token = \"abcdefghijklmnop\"",
            "secret = \"${SECRET_FROM_ENV}\"",
        ] {
            assert!(scan(near_miss).is_empty());
        }
    }

    #[test]
    fn multiple_findings_are_deduplicated_and_deterministically_ordered() {
        let text = format!(
            "token = \"{SYNTHETIC_GITHUB_PAT}\"\npassword = \"{SYNTHETIC_ASSIGNMENT}\"\n{SYNTHETIC_JWT}"
        );
        let mut session = Session::new(Limits::default()).expect("compile trusted rules");
        let mut first = Vec::new();
        session
            .scan_file(&text, |findings| first.extend_from_slice(findings))
            .expect("scan succeeds");
        let report = session.finish().expect("report is consistent");
        let second = scan(&text);

        assert_eq!(first, second);
        assert_eq!(first.len(), 4);
        assert!(first.windows(2).all(|pair| pair[0] < pair[1]));
        assert_eq!(report.scan_candidates, 1);
        assert_eq!(report.findings, 4);
        assert_eq!(report.files_with_findings, 1);

        let duplicate = first[0];
        let mut set = BTreeSet::new();
        insert_finding(&mut set, duplicate, text.len(), 1).expect("first insert");
        insert_finding(&mut set, duplicate, text.len(), 1).expect("duplicate is deduplicated");
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn finding_and_errors_never_format_matched_text() {
        let raw_secret = SYNTHETIC_ASSIGNMENT;
        let finding = scan(&format!("password = \"{raw_secret}\""))[0];
        assert!(!format!("{finding:?}").contains(raw_secret));
        assert!(!finding.to_string().contains(raw_secret));
        for error in [
            SecretError::RuleCompilationFailed,
            SecretError::InvalidFindingSpan,
            SecretError::MatchLimitExceeded,
            SecretError::FileFindingLimitExceeded,
            SecretError::RunFindingLimitExceeded,
            SecretError::CountOverflow,
            SecretError::InconsistentCounts,
        ] {
            assert!(!format!("{error:?}").contains(raw_secret));
            assert!(!error.to_string().contains(raw_secret));
        }
    }

    #[test]
    fn file_and_run_finding_limits_fail_closed() {
        let two_findings =
            format!("password = \"{SYNTHETIC_ASSIGNMENT}\"\ntoken = \"A7c9E2bN0nLive_Fixture_4\"");
        let mut file_limited = Session::new(Limits {
            max_findings_per_file: 1,
            ..Limits::default()
        })
        .expect("compile rules");
        assert_eq!(
            file_limited.scan_file(&two_findings, |_| {}),
            Err(SecretError::FileFindingLimitExceeded)
        );

        let mut run_limited = Session::new(Limits {
            max_findings_per_run: 1,
            ..Limits::default()
        })
        .expect("compile rules");
        let one_finding = format!("password = \"{SYNTHETIC_ASSIGNMENT}\"");
        assert_eq!(run_limited.scan_file(&one_finding, |_| {}), Ok(1));
        assert_eq!(
            run_limited.scan_file(&one_finding, |_| {}),
            Err(SecretError::RunFindingLimitExceeded)
        );
    }

    #[test]
    fn private_key_patterns_share_one_logical_rule_match_limit() {
        let private_key_variants = format!(
            "{}\n{}",
            synthetic_private_key("PRIVATE KEY"),
            synthetic_private_key("RSA PRIVATE KEY")
        );
        let mut logical_rule_limited = Session::new(Limits {
            max_matches_per_rule_per_file: 1,
            ..Limits::default()
        })
        .expect("compile rules");
        assert_eq!(
            logical_rule_limited.scan_file(&private_key_variants, |_| {}),
            Err(SecretError::MatchLimitExceeded)
        );
    }

    #[test]
    fn different_logical_rules_have_independent_match_limits_per_file() {
        let distinct_rules = format!("{SYNTHETIC_JWT}\npassword = \"{SYNTHETIC_ASSIGNMENT}\"");
        let mut independently_limited = Session::new(Limits {
            max_matches_per_rule_per_file: 1,
            ..Limits::default()
        })
        .expect("compile rules");
        assert_eq!(
            independently_limited.scan_file(&distinct_rules, |_| {}),
            Ok(2)
        );

        assert_eq!(
            independently_limited.scan_file(&distinct_rules, |_| {}),
            Ok(2)
        );
    }

    #[test]
    fn match_limit_and_count_overflow_fail_closed() {
        let mut match_limited = Session::new(Limits {
            max_matches_per_rule_per_file: 0,
            ..Limits::default()
        })
        .expect("compile rules");
        assert_eq!(
            match_limited.scan_file(SYNTHETIC_JWT, |_| {}),
            Err(SecretError::MatchLimitExceeded)
        );

        let mut rule_match_overflow = BTreeMap::from([(RuleId::JwtCompactJwsV1, usize::MAX)]);
        assert_eq!(
            record_rule_match(
                &mut rule_match_overflow,
                RuleId::JwtCompactJwsV1,
                usize::MAX
            ),
            Err(SecretError::CountOverflow)
        );

        let mut count_overflow = Session::new(Limits::default()).expect("compile rules");
        count_overflow.report.scan_candidates = usize::MAX;
        assert_eq!(
            count_overflow.scan_file("ordinary readable text", |_| {}),
            Err(SecretError::CountOverflow)
        );

        let one_finding = format!("password = \"{SYNTHETIC_ASSIGNMENT}\"");
        let mut finding_overflow = Session::new(Limits {
            max_findings_per_run: usize::MAX,
            ..Limits::default()
        })
        .expect("compile rules");
        finding_overflow.report.findings = usize::MAX;
        assert_eq!(
            finding_overflow.scan_file(&one_finding, |_| {}),
            Err(SecretError::CountOverflow)
        );

        let mut file_count_overflow = Session::new(Limits::default()).expect("compile rules");
        file_count_overflow.report.files_with_findings = usize::MAX;
        assert_eq!(
            file_count_overflow.scan_file(&one_finding, |_| {}),
            Err(SecretError::CountOverflow)
        );
    }

    #[test]
    fn invalid_and_inconsistent_evidence_fails_closed() {
        let finding = SecretFinding {
            span: SecretSpan { start: 2, end: 1 },
            rule_id: RuleId::JwtCompactJwsV1,
            category: SecretCategory::JwtCredential,
        };
        assert_eq!(
            insert_finding(&mut BTreeSet::new(), finding, 3, 1),
            Err(SecretError::InvalidFindingSpan)
        );
        assert_eq!(
            Report {
                scan_candidates: 0,
                findings: 1,
                files_with_findings: 1,
            }
            .validate(),
            Err(SecretError::InconsistentCounts)
        );
    }
}
