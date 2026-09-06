//! File-local span normalization and irreversible text transformation.
//!
//! This module is deliberately pure: it receives borrowed text and detector
//! evidence, performs no filesystem access, and retains no source-to-output
//! mapping. The clone pipeline may call this kernel only after its own
//! capability and policy checks.

use std::fmt;

use crate::secrets::SecretFinding;
use crate::sensitive::{SensitiveCategory, SensitiveFinding};

pub const DEFAULT_MAX_INPUT_FINDINGS_PER_FILE: usize = 16_640;
pub const DEFAULT_MAX_REGIONS_PER_FILE: usize = 16_640;
pub const DEFAULT_MAX_OUTPUT_BYTES_PER_FILE: usize = 8 * 1024 * 1024;
pub(crate) const MAX_REPLACEMENT_MARKER_BYTES: usize = 27;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    pub max_input_findings_per_file: usize,
    pub max_regions_per_file: usize,
    pub max_output_bytes_per_file: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_input_findings_per_file: DEFAULT_MAX_INPUT_FINDINGS_PER_FILE,
            max_regions_per_file: DEFAULT_MAX_REGIONS_PER_FILE,
            max_output_bytes_per_file: DEFAULT_MAX_OUTPUT_BYTES_PER_FILE,
        }
    }
}

/// Descriptive alias for callers that want to distinguish transform limits
/// from the detector limits with the same field names.
pub type TransformLimits = Limits;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum ReplacementClass {
    Secret,
    Email,
    Phone,
    IpAddress,
    JapanesePostal,
    MyNumber,
    CorporateNumber,
    Multiple,
}

impl ReplacementClass {
    const fn marker(self) -> &'static str {
        match self {
            Self::Secret => "[REDACTED:SECRET]",
            Self::Email => "[REDACTED:EMAIL]",
            Self::Phone => "[REDACTED:PHONE]",
            Self::IpAddress => "[REDACTED:IP]",
            Self::JapanesePostal => "[REDACTED:POSTAL_CODE]",
            Self::MyNumber => "[REDACTED:MY_NUMBER]",
            Self::CorporateNumber => "[REDACTED:CORPORATE_NUMBER]",
            Self::Multiple => "[REDACTED:MULTIPLE]",
        }
    }

    const fn bit(self) -> u8 {
        match self {
            Self::Secret => 1 << 0,
            Self::Email => 1 << 1,
            Self::Phone => 1 << 2,
            Self::IpAddress => 1 << 3,
            Self::JapanesePostal => 1 << 4,
            Self::MyNumber => 1 << 5,
            Self::CorporateNumber => 1 << 6,
            Self::Multiple => 0,
        }
    }

    const fn from_bits(bits: u8) -> Self {
        match bits {
            1 => Self::Secret,
            2 => Self::Email,
            4 => Self::Phone,
            8 => Self::IpAddress,
            16 => Self::JapanesePostal,
            32 => Self::MyNumber,
            64 => Self::CorporateNumber,
            _ => Self::Multiple,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct NormalizedRegion {
    start: usize,
    end: usize,
    replacement: ReplacementClass,
}

impl NormalizedRegion {
    const fn len(self) -> usize {
        self.end.saturating_sub(self.start)
    }

    const fn marker(self) -> &'static str {
        self.replacement.marker()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct TransformPlan {
    source_bytes: usize,
    output_bytes: usize,
    source_bytes_redacted: usize,
    regions: Vec<NormalizedRegion>,
}

#[derive(Clone, Eq, PartialEq)]
pub struct TransformedText {
    pub text: String,
    pub regions: usize,
    pub source_bytes_redacted: usize,
}

impl fmt::Debug for TransformedText {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TransformedText")
            .field("regions", &self.regions)
            .field("source_bytes_redacted", &self.source_bytes_redacted)
            .field("output_bytes", &self.text.len())
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransformError {
    InputFindingLimitExceeded,
    InvalidSpan,
    RegionLimitExceeded,
    OutputLimitExceeded,
    CountOverflow,
    SourceLengthMismatch,
    InvalidPlan,
}

impl fmt::Display for TransformError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InputFindingLimitExceeded => "transform input finding limit exceeded",
            Self::InvalidSpan => "transform received an invalid byte span",
            Self::RegionLimitExceeded => "transform region limit exceeded",
            Self::OutputLimitExceeded => "transform output byte limit exceeded",
            Self::CountOverflow => "transform arithmetic overflowed",
            Self::SourceLengthMismatch => "transform source length does not match its plan",
            Self::InvalidPlan => "transform plan is invalid",
        })
    }
}

#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
struct Candidate {
    start: usize,
    end: usize,
    replacement: ReplacementClass,
}

/// Build a normalized plan using the default finite transform limits.
fn plan(
    source: &str,
    secret_findings: &[SecretFinding],
    sensitive_findings: &[SensitiveFinding],
) -> Result<TransformPlan, TransformError> {
    plan_with_limits(
        source,
        secret_findings,
        sensitive_findings,
        Limits::default(),
    )
}

/// Build a normalized plan without retaining the source text or a mapping.
fn plan_with_limits(
    source: &str,
    secret_findings: &[SecretFinding],
    sensitive_findings: &[SensitiveFinding],
    limits: Limits,
) -> Result<TransformPlan, TransformError> {
    let input_findings = secret_findings
        .len()
        .checked_add(sensitive_findings.len())
        .ok_or(TransformError::CountOverflow)?;
    if input_findings > limits.max_input_findings_per_file {
        return Err(TransformError::InputFindingLimitExceeded);
    }

    let mut candidates = Vec::with_capacity(input_findings);
    for finding in secret_findings {
        push_candidate(
            source,
            &mut candidates,
            finding.span.start,
            finding.span.end,
            ReplacementClass::Secret,
        )?;
    }
    for finding in sensitive_findings {
        push_candidate(
            source,
            &mut candidates,
            finding.span.start,
            finding.span.end,
            sensitive_replacement(finding.category),
        )?;
    }

    candidates.sort_unstable();
    candidates.dedup();

    let mut regions = Vec::with_capacity(candidates.len());
    for candidate in candidates {
        let Some(current) = regions.last_mut() else {
            regions.push(NormalizedRegion {
                start: candidate.start,
                end: candidate.end,
                replacement: candidate.replacement,
            });
            continue;
        };

        if candidate.start < current.end {
            current.end = current.end.max(candidate.end);
            current.replacement = merge_replacements(current.replacement, candidate.replacement);
        } else {
            regions.push(NormalizedRegion {
                start: candidate.start,
                end: candidate.end,
                replacement: candidate.replacement,
            });
        }
        if regions.len() > limits.max_regions_per_file {
            return Err(TransformError::RegionLimitExceeded);
        }
    }
    if regions.len() > limits.max_regions_per_file {
        return Err(TransformError::RegionLimitExceeded);
    }

    let source_bytes_redacted = regions.iter().try_fold(0_usize, |total, region| {
        total
            .checked_add(region.len())
            .ok_or(TransformError::CountOverflow)
    })?;
    let remaining_bytes = source
        .len()
        .checked_sub(source_bytes_redacted)
        .ok_or(TransformError::InvalidPlan)?;
    let output_bytes = regions.iter().try_fold(remaining_bytes, |total, region| {
        total
            .checked_add(region.marker().len())
            .ok_or(TransformError::CountOverflow)
    })?;
    if output_bytes > limits.max_output_bytes_per_file {
        return Err(TransformError::OutputLimitExceeded);
    }

    Ok(TransformPlan {
        source_bytes: source.len(),
        output_bytes,
        source_bytes_redacted,
        regions,
    })
}

/// Apply a previously validated plan in forward byte order.
fn apply(source: &str, plan: &TransformPlan) -> Result<TransformedText, TransformError> {
    if source.len() != plan.source_bytes {
        return Err(TransformError::SourceLengthMismatch);
    }
    validate_plan(source, plan)?;

    let mut output = String::with_capacity(plan.output_bytes);
    let mut cursor = 0_usize;
    for region in &plan.regions {
        output.push_str(&source[cursor..region.start]);
        output.push_str(region.marker());
        cursor = region.end;
    }
    output.push_str(&source[cursor..]);
    if output.len() != plan.output_bytes {
        return Err(TransformError::InvalidPlan);
    }

    Ok(TransformedText {
        text: output,
        regions: plan.regions.len(),
        source_bytes_redacted: plan.source_bytes_redacted,
    })
}

/// Convenience wrapper for callers that do not need to retain the plan.
pub fn transform(
    source: &str,
    secret_findings: &[SecretFinding],
    sensitive_findings: &[SensitiveFinding],
) -> Result<TransformedText, TransformError> {
    let plan = plan(source, secret_findings, sensitive_findings)?;
    apply(source, &plan)
}

pub fn transform_with_limits(
    source: &str,
    secret_findings: &[SecretFinding],
    sensitive_findings: &[SensitiveFinding],
    limits: Limits,
) -> Result<TransformedText, TransformError> {
    let plan = plan_with_limits(source, secret_findings, sensitive_findings, limits)?;
    apply(source, &plan)
}

fn push_candidate(
    source: &str,
    candidates: &mut Vec<Candidate>,
    start: usize,
    end: usize,
    replacement: ReplacementClass,
) -> Result<(), TransformError> {
    if start >= end
        || end > source.len()
        || !source.is_char_boundary(start)
        || !source.is_char_boundary(end)
    {
        return Err(TransformError::InvalidSpan);
    }
    candidates.push(Candidate {
        start,
        end,
        replacement,
    });
    Ok(())
}

fn sensitive_replacement(category: SensitiveCategory) -> ReplacementClass {
    match category {
        SensitiveCategory::EmailAddress => ReplacementClass::Email,
        SensitiveCategory::InternationalPhone
        | SensitiveCategory::JapaneseDomesticPhoneCandidate => ReplacementClass::Phone,
        SensitiveCategory::IpAddress => ReplacementClass::IpAddress,
        SensitiveCategory::JapanesePostalCodeCandidate => ReplacementClass::JapanesePostal,
        SensitiveCategory::MyNumberCandidate => ReplacementClass::MyNumber,
        SensitiveCategory::JapaneseCorporateNumberCandidate => ReplacementClass::CorporateNumber,
    }
}

fn merge_replacements(left: ReplacementClass, right: ReplacementClass) -> ReplacementClass {
    if left == ReplacementClass::Multiple || right == ReplacementClass::Multiple {
        return ReplacementClass::Multiple;
    }
    ReplacementClass::from_bits(left.bit() | right.bit())
}

fn validate_plan(source: &str, plan: &TransformPlan) -> Result<(), TransformError> {
    let mut previous_end = 0_usize;
    let mut redacted_bytes = 0_usize;
    let mut output_bytes = source.len();
    for (index, region) in plan.regions.iter().enumerate() {
        if region.start >= region.end
            || region.end > source.len()
            || !source.is_char_boundary(region.start)
            || !source.is_char_boundary(region.end)
            || (index != 0 && region.start < previous_end)
        {
            return Err(TransformError::InvalidPlan);
        }
        redacted_bytes = redacted_bytes
            .checked_add(region.len())
            .ok_or(TransformError::CountOverflow)?;
        output_bytes = output_bytes
            .checked_sub(region.len())
            .ok_or(TransformError::InvalidPlan)?
            .checked_add(region.marker().len())
            .ok_or(TransformError::CountOverflow)?;
        previous_end = region.end;
    }
    if redacted_bytes != plan.source_bytes_redacted || output_bytes != plan.output_bytes {
        return Err(TransformError::InvalidPlan);
    }
    Ok(())
}

/// The full filesystem transformation workflow remains intentionally absent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransformationUnavailable;

impl fmt::Display for TransformationUnavailable {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("transformation is not implemented")
    }
}

pub fn execute() -> Result<(), TransformationUnavailable> {
    Err(TransformationUnavailable)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secrets::{self, RuleId, SecretCategory, SecretSpan, Session as SecretSession};
    use crate::sensitive::{self, SensitiveRuleId, SensitiveSpan, Session as SensitiveSession};

    fn secret(start: usize, end: usize, rule_id: RuleId) -> SecretFinding {
        SecretFinding {
            span: SecretSpan { start, end },
            rule_id,
            category: SecretCategory::ProviderToken,
        }
    }

    fn sensitive(
        start: usize,
        end: usize,
        rule_id: SensitiveRuleId,
        category: SensitiveCategory,
    ) -> SensitiveFinding {
        SensitiveFinding {
            span: SensitiveSpan { start, end },
            rule_id,
            category,
        }
    }

    fn plan_for(
        source: &str,
        secret_findings: &[SecretFinding],
        sensitive_findings: &[SensitiveFinding],
    ) -> TransformPlan {
        plan(source, secret_findings, sensitive_findings).expect("plan succeeds")
    }

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

    fn synthetic_my_number(base: &str) -> String {
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
        let sum = base
            .bytes()
            .rev()
            .enumerate()
            .map(|(index, byte)| {
                let weight = if index % 2 == 0 { 1 } else { 2 };
                u32::from(byte - b'0') * weight
            })
            .sum::<u32>();
        format!("{}{}", 9 - (sum % 9), base)
    }

    fn detect(source: &str) -> (Vec<SecretFinding>, Vec<SensitiveFinding>) {
        let mut secrets = SecretSession::new(secrets::Limits::default()).expect("secret rules");
        let mut secret_findings = Vec::new();
        secrets
            .scan_file(source, |findings| {
                secret_findings.extend_from_slice(findings)
            })
            .expect("secret scan");
        secrets.finish().expect("secret report");

        let mut sensitive =
            SensitiveSession::new(sensitive::Limits::default()).expect("sensitive rules");
        let mut sensitive_findings = Vec::new();
        sensitive
            .scan_file(source, |findings| {
                sensitive_findings.extend_from_slice(findings)
            })
            .expect("sensitive scan");
        sensitive.finish().expect("sensitive report");
        (secret_findings, sensitive_findings)
    }

    #[test]
    fn exact_duplicates_and_same_class_overlaps_normalize_to_one_region() {
        let source = "abcdef";
        let first = secret(0, 3, RuleId::GithubClassicPatV1);
        let overlapping = secret(2, 5, RuleId::ExplicitSecretAssignmentV1);
        let plan = plan_for(source, &[first, first, overlapping], &[]);

        assert_eq!(plan.regions.len(), 1);
        assert_eq!(plan.regions[0].start, 0);
        assert_eq!(plan.regions[0].end, 5);
        assert_eq!(plan.regions[0].replacement, ReplacementClass::Secret);
        assert_eq!(
            apply(source, &plan).expect("apply").text,
            "[REDACTED:SECRET]f"
        );
    }

    #[test]
    fn overlapping_classes_and_chains_merge_to_multiple() {
        let source = "abcdefgh";
        let secret_finding = secret(0, 3, RuleId::GithubClassicPatV1);
        let email = sensitive(
            2,
            5,
            SensitiveRuleId::AsciiEmailV1,
            SensitiveCategory::EmailAddress,
        );
        let phone = sensitive(
            4,
            7,
            SensitiveRuleId::InternationalPhoneV1,
            SensitiveCategory::InternationalPhone,
        );
        let plan = plan_for(source, &[secret_finding], &[email, phone]);

        assert_eq!(plan.regions.len(), 1);
        assert_eq!(plan.regions[0].end, 7);
        assert_eq!(plan.regions[0].replacement, ReplacementClass::Multiple);
        assert_eq!(
            apply(source, &plan).expect("apply").text,
            "[REDACTED:MULTIPLE]h"
        );
    }

    #[test]
    fn adjacent_regions_remain_separate_and_order_is_deterministic() {
        let source = "abcdef";
        let secret_finding = secret(0, 3, RuleId::GithubClassicPatV1);
        let email = sensitive(
            3,
            6,
            SensitiveRuleId::AsciiEmailV1,
            SensitiveCategory::EmailAddress,
        );
        let first = plan_for(source, &[secret_finding], &[email]);
        let second = plan_for(source, &[secret_finding], &[email]);
        assert_eq!(first, second);
        assert_eq!(first.regions.len(), 2);
        assert_eq!(
            apply(source, &first).expect("apply").text,
            "[REDACTED:SECRET][REDACTED:EMAIL]"
        );
    }

    #[test]
    fn unordered_findings_produce_the_same_plan() {
        let source = "abcdefgh";
        let early = secret(0, 2, RuleId::GithubClassicPatV1);
        let late = secret(5, 8, RuleId::ExplicitSecretAssignmentV1);
        let ordered = plan_for(source, &[early, late], &[]);
        let reversed = plan_for(source, &[late, early], &[]);
        assert_eq!(ordered, reversed);
    }

    #[test]
    fn japanese_surrounding_text_is_preserved_byte_exactly() {
        let source = "前置き日本語 fixture.user@example.invalid 後置き";
        let value = "fixture.user@example.invalid";
        let start = source.find(value).expect("fixture span");
        let end = start + value.len();
        let finding = sensitive(
            start,
            end,
            SensitiveRuleId::AsciiEmailV1,
            SensitiveCategory::EmailAddress,
        );
        let output = transform(source, &[], &[finding]).expect("transform");
        assert_eq!(output.text, "前置き日本語 [REDACTED:EMAIL] 後置き");
    }

    #[test]
    fn invalid_spans_fail_closed_without_raw_error_content() {
        let source = "あいう";
        let non_boundary = secret(1, 2, RuleId::GithubClassicPatV1);
        let out_of_bounds = secret(0, source.len() + 1, RuleId::GithubClassicPatV1);
        let reversed = secret(2, 1, RuleId::GithubClassicPatV1);

        for finding in [non_boundary, out_of_bounds, reversed] {
            let error = plan(source, &[finding], &[]).expect_err("invalid span must fail");
            assert_eq!(error, TransformError::InvalidSpan);
            assert!(!error.to_string().contains(source));
            assert!(!format!("{error:?}").contains(source));
        }
    }

    #[test]
    fn limits_fail_closed_before_unbounded_output() {
        let source = "abcdef";
        let first = secret(0, 1, RuleId::GithubClassicPatV1);
        let second = secret(2, 3, RuleId::ExplicitSecretAssignmentV1);
        assert_eq!(
            plan_with_limits(
                source,
                &[first, second],
                &[],
                Limits {
                    max_input_findings_per_file: 1,
                    ..Limits::default()
                }
            ),
            Err(TransformError::InputFindingLimitExceeded)
        );
        assert_eq!(
            plan_with_limits(
                source,
                &[first, second],
                &[],
                Limits {
                    max_regions_per_file: 1,
                    ..Limits::default()
                }
            ),
            Err(TransformError::RegionLimitExceeded)
        );
        assert_eq!(
            plan_with_limits(
                source,
                &[first],
                &[],
                Limits {
                    max_output_bytes_per_file: 1,
                    ..Limits::default()
                }
            ),
            Err(TransformError::OutputLimitExceeded)
        );
    }

    #[test]
    fn transformed_debug_is_aggregate_only_and_source_length_is_bound() {
        let source = "fixture-secret";
        let finding = secret(0, source.len(), RuleId::GithubClassicPatV1);
        let plan = plan_for(source, &[finding], &[]);
        let transformed = apply(source, &plan).expect("apply");
        let debug = format!("{transformed:?}");
        assert!(!debug.contains(source));
        assert_eq!(
            apply("different-length", &plan),
            Err(TransformError::SourceLengthMismatch)
        );
    }

    #[test]
    fn real_detector_findings_are_transformed_and_do_not_retrigger() {
        let github = synthetic_github_token("gho_", 36);
        let email = "fixture.user+test@example.invalid";
        let phone = "090-0000-0000";
        let ip = "192.0.2.10";
        let postal = "123-4567";
        let my_number = synthetic_my_number("10000000000");
        let corporate_number = synthetic_corporate_number("102030405060");
        let source = format!(
            "github {github}\nemail {email}\nphone {phone}\nip {ip}\npostal {postal}\nmy {my_number}\ncorporate {corporate_number}"
        );
        let (secret_findings, sensitive_findings) = detect(&source);
        assert!(!secret_findings.is_empty());
        assert!(!sensitive_findings.is_empty());

        let transformed = transform(&source, &secret_findings, &sensitive_findings)
            .expect("detector findings transform");
        for finding in &secret_findings {
            assert!(!transformed
                .text
                .contains(&source[finding.span.start..finding.span.end]));
        }
        for finding in &sensitive_findings {
            assert!(!transformed
                .text
                .contains(&source[finding.span.start..finding.span.end]));
        }
        assert!(transformed.text.contains("[REDACTED:SECRET]"));
        assert!(transformed.text.contains("[REDACTED:EMAIL]"));
        assert!(transformed.text.contains("[REDACTED:PHONE]"));
        assert!(transformed.text.contains("[REDACTED:IP]"));
        assert!(transformed.text.contains("[REDACTED:POSTAL_CODE]"));
        assert!(transformed.text.contains("[REDACTED:MY_NUMBER]"));
        assert!(transformed.text.contains("[REDACTED:CORPORATE_NUMBER]"));

        let (remaining_secrets, remaining_sensitive) = detect(&transformed.text);
        assert!(remaining_secrets.is_empty());
        assert!(remaining_sensitive.is_empty());
        assert!(std::str::from_utf8(transformed.text.as_bytes()).is_ok());
    }

    #[test]
    fn replacement_marker_bound_matches_all_fixed_markers() {
        let markers = [
            ReplacementClass::Secret.marker(),
            ReplacementClass::Email.marker(),
            ReplacementClass::Phone.marker(),
            ReplacementClass::IpAddress.marker(),
            ReplacementClass::JapanesePostal.marker(),
            ReplacementClass::MyNumber.marker(),
            ReplacementClass::CorporateNumber.marker(),
            ReplacementClass::Multiple.marker(),
        ];
        assert!(markers
            .into_iter()
            .all(|marker| marker.len() <= MAX_REPLACEMENT_MARKER_BYTES));
        assert_eq!(
            markers.into_iter().map(str::len).max(),
            Some(MAX_REPLACEMENT_MARKER_BYTES)
        );
    }
}
