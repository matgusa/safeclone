//! Pure, filesystem-safe transformation of one source path component.
//!
//! This module accepts borrowed UTF-8 component text and the existing raw-free
//! detector findings. It performs no filesystem access, keeps no component
//! manifest or source mapping, and exposes only one-shot production APIs.

use std::fmt;
use std::path::Path;

use crate::detection::{classify_path, DetectedKind};
use crate::secrets::SecretFinding;
use crate::sensitive::{SensitiveCategory, SensitiveFinding};

pub const DEFAULT_MAX_INPUT_FINDINGS_PER_COMPONENT: usize = 16_640;
pub const DEFAULT_MAX_REGIONS_PER_COMPONENT: usize = 16_640;
pub const DEFAULT_MAX_OUTPUT_BYTES_PER_COMPONENT: usize = 8 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    pub max_input_findings_per_component: usize,
    pub max_regions_per_component: usize,
    pub max_output_bytes_per_component: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_input_findings_per_component: DEFAULT_MAX_INPUT_FINDINGS_PER_COMPONENT,
            max_regions_per_component: DEFAULT_MAX_REGIONS_PER_COMPONENT,
            max_output_bytes_per_component: DEFAULT_MAX_OUTPUT_BYTES_PER_COMPONENT,
        }
    }
}

/// Alias documenting that these bounds apply to path components.
pub type PathTransformLimits = Limits;

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
            Self::Secret => "__REDACTED_SECRET__",
            Self::Email => "__REDACTED_EMAIL__",
            Self::Phone => "__REDACTED_PHONE__",
            Self::IpAddress => "__REDACTED_IP__",
            Self::JapanesePostal => "__REDACTED_POSTAL_CODE__",
            Self::MyNumber => "__REDACTED_MY_NUMBER__",
            Self::CorporateNumber => "__REDACTED_CORPORATE_NUMBER__",
            Self::Multiple => "__REDACTED_MULTIPLE__",
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
        self.end - self.start
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

/// In-memory result of one component transformation.
///
/// Debug intentionally reports only aggregate sizes and never the sanitized
/// text, so accidental diagnostics do not retain component contents.
#[derive(Clone, Eq, PartialEq)]
pub struct TransformedComponent {
    pub text: String,
    pub regions: usize,
    pub source_bytes_redacted: usize,
}

impl fmt::Debug for TransformedComponent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TransformedComponent")
            .field("regions", &self.regions)
            .field("source_bytes_redacted", &self.source_bytes_redacted)
            .field("output_bytes", &self.text.len())
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PathTransformError {
    InputFindingLimitExceeded,
    InvalidSpan,
    RegionLimitExceeded,
    OutputLimitExceeded,
    CountOverflow,
    InvalidComponent,
    NotTransformableFileComponent,
    MissingFileExtension,
    InvalidPlan,
}

impl fmt::Display for PathTransformError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InputFindingLimitExceeded => "path transform input finding limit exceeded",
            Self::InvalidSpan => "path transform received an invalid byte span",
            Self::RegionLimitExceeded => "path transform region limit exceeded",
            Self::OutputLimitExceeded => "path transform output byte limit exceeded",
            Self::CountOverflow => "path transform arithmetic overflowed",
            Self::InvalidComponent => "path transform received an invalid component",
            Self::NotTransformableFileComponent => {
                "path transform file component is not a text/code candidate"
            }
            Self::MissingFileExtension => "path transform file component has no safe extension",
            Self::InvalidPlan => "path transform plan is invalid",
        })
    }
}

#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
struct Candidate {
    start: usize,
    end: usize,
    replacement: ReplacementClass,
}

/// Transform one borrowed UTF-8 component with the default finite bounds.
///
/// Planning and application are intentionally one operation, binding the
/// normalized spans to this exact borrowed source without a public plan type.
pub fn transform_component(
    source: &str,
    secret_findings: &[SecretFinding],
    sensitive_findings: &[SensitiveFinding],
) -> Result<TransformedComponent, PathTransformError> {
    transform_component_with_limits(
        source,
        secret_findings,
        sensitive_findings,
        Limits::default(),
    )
}

/// Transform one borrowed UTF-8 component with explicit finite bounds.
pub fn transform_component_with_limits(
    source: &str,
    secret_findings: &[SecretFinding],
    sensitive_findings: &[SensitiveFinding],
    limits: Limits,
) -> Result<TransformedComponent, PathTransformError> {
    validate_component(source)?;
    let plan = plan_with_limits(source, secret_findings, sensitive_findings, limits)?;
    apply(source, &plan)
}

/// Split a known transformable text/code filename into borrowed stem and the
/// byte-exact extension suffix. Extension ownership remains in
/// detection::classify_path; this helper does not duplicate its list.
pub fn split_transformable_file_component(name: &str) -> Result<(&str, &str), PathTransformError> {
    validate_component(name)?;
    if classify_path(Path::new(name), false) != DetectedKind::TextOrCodeCandidate {
        return Err(PathTransformError::NotTransformableFileComponent);
    }

    let extension = Path::new(name)
        .extension()
        .and_then(|extension| extension.to_str())
        .ok_or(PathTransformError::MissingFileExtension)?;
    let suffix_len = extension
        .len()
        .checked_add(1)
        .ok_or(PathTransformError::CountOverflow)?;
    let suffix_start = name
        .len()
        .checked_sub(suffix_len)
        .ok_or(PathTransformError::InvalidComponent)?;
    if suffix_start == 0 || name.as_bytes().get(suffix_start) != Some(&b'.') {
        return Err(PathTransformError::InvalidComponent);
    }
    let (stem, suffix) = name.split_at(suffix_start);
    if stem.is_empty() || stem == "." || stem == ".." || suffix.len() <= 1 {
        return Err(PathTransformError::InvalidComponent);
    }
    Ok((stem, suffix))
}

fn validate_component(source: &str) -> Result<(), PathTransformError> {
    if source.is_empty()
        || source == "."
        || source == ".."
        || source.chars().any(|character| {
            matches!(
                character,
                '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|' | '\0'
            )
        })
    {
        return Err(PathTransformError::InvalidComponent);
    }
    Ok(())
}

fn plan_with_limits(
    source: &str,
    secret_findings: &[SecretFinding],
    sensitive_findings: &[SensitiveFinding],
    limits: Limits,
) -> Result<TransformPlan, PathTransformError> {
    let input_findings = secret_findings
        .len()
        .checked_add(sensitive_findings.len())
        .ok_or(PathTransformError::CountOverflow)?;
    if input_findings > limits.max_input_findings_per_component {
        return Err(PathTransformError::InputFindingLimitExceeded);
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

    let mut regions: Vec<NormalizedRegion> = Vec::with_capacity(candidates.len());
    for candidate in candidates {
        if let Some(current) = regions.last_mut() {
            if candidate.start < current.end {
                current.end = current.end.max(candidate.end);
                current.replacement =
                    merge_replacements(current.replacement, candidate.replacement);
            } else {
                regions.push(NormalizedRegion {
                    start: candidate.start,
                    end: candidate.end,
                    replacement: candidate.replacement,
                });
            }
        } else {
            regions.push(NormalizedRegion {
                start: candidate.start,
                end: candidate.end,
                replacement: candidate.replacement,
            });
        }
        if regions.len() > limits.max_regions_per_component {
            return Err(PathTransformError::RegionLimitExceeded);
        }
    }

    let source_bytes_redacted = regions.iter().try_fold(0_usize, |total, region| {
        total
            .checked_add(region.len())
            .ok_or(PathTransformError::CountOverflow)
    })?;
    let remaining_bytes = source
        .len()
        .checked_sub(source_bytes_redacted)
        .ok_or(PathTransformError::InvalidPlan)?;
    let output_bytes = regions.iter().try_fold(remaining_bytes, |total, region| {
        total
            .checked_add(region.marker().len())
            .ok_or(PathTransformError::CountOverflow)
    })?;
    if output_bytes > limits.max_output_bytes_per_component {
        return Err(PathTransformError::OutputLimitExceeded);
    }

    Ok(TransformPlan {
        source_bytes: source.len(),
        output_bytes,
        source_bytes_redacted,
        regions,
    })
}

fn apply(source: &str, plan: &TransformPlan) -> Result<TransformedComponent, PathTransformError> {
    if source.len() != plan.source_bytes {
        return Err(PathTransformError::InvalidPlan);
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
        return Err(PathTransformError::InvalidPlan);
    }

    Ok(TransformedComponent {
        text: output,
        regions: plan.regions.len(),
        source_bytes_redacted: plan.source_bytes_redacted,
    })
}

fn push_candidate(
    source: &str,
    candidates: &mut Vec<Candidate>,
    start: usize,
    end: usize,
    replacement: ReplacementClass,
) -> Result<(), PathTransformError> {
    if start >= end
        || end > source.len()
        || !source.is_char_boundary(start)
        || !source.is_char_boundary(end)
    {
        return Err(PathTransformError::InvalidSpan);
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

fn validate_plan(source: &str, plan: &TransformPlan) -> Result<(), PathTransformError> {
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
            return Err(PathTransformError::InvalidPlan);
        }
        redacted_bytes = redacted_bytes
            .checked_add(region.len())
            .ok_or(PathTransformError::CountOverflow)?;
        output_bytes = output_bytes
            .checked_sub(region.len())
            .ok_or(PathTransformError::InvalidPlan)?
            .checked_add(region.marker().len())
            .ok_or(PathTransformError::CountOverflow)?;
        previous_end = region.end;
    }
    if redacted_bytes != plan.source_bytes_redacted || output_bytes != plan.output_bytes {
        return Err(PathTransformError::InvalidPlan);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secrets::{self, RuleId, SecretCategory, SecretSpan};
    use crate::sensitive::{self, SensitiveRuleId, SensitiveSpan};

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

    fn detect(source: &str) -> (Vec<SecretFinding>, Vec<SensitiveFinding>) {
        let secrets = secrets::RuleSet::compile().expect("secret rules");
        let sensitive = sensitive::RuleSet::compile().expect("sensitive rules");
        (
            secrets
                .find(source, secrets::Limits::default())
                .expect("secret scan"),
            sensitive
                .find(source, sensitive::Limits::default())
                .expect("sensitive scan"),
        )
    }

    fn synthetic_github_token() -> String {
        const ALPHABET: &[u8] = b"A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0UvWxYz_";
        let body = (0..36)
            .map(|index| ALPHABET[index % ALPHABET.len()])
            .collect::<Vec<_>>();
        format!("gho_{}", String::from_utf8(body).expect("ASCII fixture"))
    }

    #[test]
    fn detector_integration_transforms_components_and_preserves_extensions() {
        let directory = "fixture.user@example.invalid";
        let (secrets, sensitive) = detect(directory);
        let transformed = transform_component(directory, &secrets, &sensitive).expect("email");
        assert_eq!(transformed.text, "__REDACTED_EMAIL__");

        let (stem, suffix) = split_transformable_file_component("fixture.user@example.invalid.txt")
            .expect("text extension");
        assert_eq!(stem, directory);
        assert_eq!(suffix, ".txt");
        let (secrets, sensitive) = detect(stem);
        let transformed = transform_component(stem, &secrets, &sensitive).expect("email stem");
        assert_eq!(
            format!("{}{}", transformed.text, suffix),
            "__REDACTED_EMAIL__.txt"
        );

        let (stem, suffix) =
            split_transformable_file_component("192.0.2.10.rs").expect("code extension");
        let (secrets, sensitive) = detect(stem);
        let transformed = transform_component(stem, &secrets, &sensitive).expect("ip stem");
        assert_eq!(
            format!("{}{}", transformed.text, suffix),
            "__REDACTED_IP__.rs"
        );

        let token = synthetic_github_token();
        let (secrets, sensitive) = detect(&token);
        let transformed = transform_component(&token, &secrets, &sensitive).expect("token");
        assert_eq!(transformed.text, "__REDACTED_SECRET__");
        let filename = format!("{token}.txt");
        let (stem, suffix) = split_transformable_file_component(&filename).expect("token file");
        let (secrets, sensitive) = detect(stem);
        let transformed = transform_component(stem, &secrets, &sensitive).expect("token stem");
        assert_eq!(
            format!("{}{}", transformed.text, suffix),
            "__REDACTED_SECRET__.txt"
        );
    }

    #[test]
    fn phone_stem_preserves_prefix_and_suffix() {
        let source = "report_090-1234-5678";
        let (secrets, sensitive) = detect(source);
        let transformed = transform_component(source, &secrets, &sensitive).expect("phone");
        assert_eq!(transformed.text, "report___REDACTED_PHONE__");

        let (stem, suffix) =
            split_transformable_file_component("report_090-1234-5678.md").expect("markdown");
        let (secrets, sensitive) = detect(stem);
        let transformed = transform_component(stem, &secrets, &sensitive).expect("phone stem");
        assert_eq!(
            format!("{}{}", transformed.text, suffix),
            "report___REDACTED_PHONE__.md"
        );
    }

    #[test]
    fn overlap_chain_is_multiple_and_adjacency_stays_separate() {
        let source = "abcdefghij";
        let secret_finding = secret(0, 4, RuleId::GithubClassicPatV1);
        let email = sensitive(
            2,
            6,
            SensitiveRuleId::AsciiEmailV1,
            SensitiveCategory::EmailAddress,
        );
        let phone = sensitive(
            5,
            8,
            SensitiveRuleId::InternationalPhoneV1,
            SensitiveCategory::InternationalPhone,
        );
        let transformed =
            transform_component(source, &[secret_finding], &[email, phone]).expect("overlap");
        assert_eq!(transformed.text, "__REDACTED_MULTIPLE__ij");

        let adjacent = transform_component(
            source,
            &[secret(0, 2, RuleId::GithubClassicPatV1)],
            &[sensitive(
                2,
                4,
                SensitiveRuleId::AsciiEmailV1,
                SensitiveCategory::EmailAddress,
            )],
        )
        .expect("adjacent");
        assert_eq!(adjacent.text, "__REDACTED_SECRET____REDACTED_EMAIL__efghij");

        let unordered = transform_component(
            source,
            &[
                secret(5, 8, RuleId::ExplicitSecretAssignmentV1),
                secret_finding,
            ],
            &[],
        )
        .expect("unordered");
        let ordered = transform_component(
            source,
            &[
                secret_finding,
                secret(5, 8, RuleId::ExplicitSecretAssignmentV1),
            ],
            &[],
        )
        .expect("ordered");
        assert_eq!(unordered, ordered);
    }

    #[test]
    fn duplicate_and_same_class_overlap_normalize_once() {
        let source = "abcdef";
        let first = secret(0, 3, RuleId::GithubClassicPatV1);
        let second = secret(2, 5, RuleId::ExplicitSecretAssignmentV1);
        let transformed =
            transform_component(source, &[first, first, second], &[]).expect("same class");
        assert_eq!(transformed.text, "__REDACTED_SECRET__f");
        assert_eq!(transformed.regions, 1);
        assert_eq!(transformed.source_bytes_redacted, 5);
    }

    #[test]
    fn japanese_surrounding_text_is_preserved() {
        let source = "\u{65E5}\u{672C} fixture.user@example.invalid \u{5F8C}\u{7F6E}";
        let value = "fixture.user@example.invalid";
        let start = source.find(value).expect("fixture");
        let end = start + value.len();
        let transformed = transform_component(
            source,
            &[],
            &[sensitive(
                start,
                end,
                SensitiveRuleId::AsciiEmailV1,
                SensitiveCategory::EmailAddress,
            )],
        )
        .expect("boundaries");
        assert_eq!(
            transformed.text,
            "\u{65E5}\u{672C} __REDACTED_EMAIL__ \u{5F8C}\u{7F6E}"
        );
    }

    #[test]
    fn invalid_spans_and_limits_fail_closed_without_raw_errors() {
        let source = "\u{65E5}\u{672C}";
        for finding in [
            secret(1, 2, RuleId::GithubClassicPatV1),
            secret(0, source.len() + 1, RuleId::GithubClassicPatV1),
            secret(2, 1, RuleId::GithubClassicPatV1),
        ] {
            let error = transform_component(source, &[finding], &[]).expect_err("invalid");
            assert_eq!(error, PathTransformError::InvalidSpan);
            assert!(!error.to_string().contains(source));
            assert!(!format!("{error:?}").contains(source));
        }

        let finding = secret(0, 1, RuleId::GithubClassicPatV1);
        assert_eq!(
            transform_component_with_limits(
                "abcdef",
                &[finding, secret(2, 3, RuleId::ExplicitSecretAssignmentV1)],
                &[],
                Limits {
                    max_input_findings_per_component: 1,
                    ..Limits::default()
                },
            ),
            Err(PathTransformError::InputFindingLimitExceeded)
        );
        assert_eq!(
            transform_component_with_limits(
                "abcdef",
                &[finding],
                &[],
                Limits {
                    max_output_bytes_per_component: 1,
                    ..Limits::default()
                },
            ),
            Err(PathTransformError::OutputLimitExceeded)
        );
    }

    #[test]
    fn markers_are_ascii_safe_and_do_not_retrigger_detectors() {
        let markers = [
            "__REDACTED_SECRET__",
            "__REDACTED_EMAIL__",
            "__REDACTED_PHONE__",
            "__REDACTED_IP__",
            "__REDACTED_POSTAL_CODE__",
            "__REDACTED_MY_NUMBER__",
            "__REDACTED_CORPORATE_NUMBER__",
            "__REDACTED_MULTIPLE__",
        ];
        let secrets = secrets::RuleSet::compile().expect("secret rules");
        let sensitive = sensitive::RuleSet::compile().expect("sensitive rules");
        for marker in markers {
            assert!(marker.is_ascii());
            assert!(!marker.chars().any(|character| {
                matches!(
                    character,
                    '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|' | '\0'
                )
            }));
            assert_ne!(marker, ".");
            assert_ne!(marker, "..");
            assert!(secrets
                .find(marker, secrets::Limits::default())
                .expect("secret marker scan")
                .is_empty());
            assert!(sensitive
                .find(marker, sensitive::Limits::default())
                .expect("sensitive marker scan")
                .is_empty());
        }
    }

    #[test]
    fn component_and_extension_validation_is_conservative() {
        for invalid in ["", ".", "..", "a/b", "a\\\\b", "a:b", "a\\0b"] {
            assert_eq!(
                transform_component(invalid, &[], &[]),
                Err(PathTransformError::InvalidComponent)
            );
        }
        assert_eq!(
            split_transformable_file_component("migration.sql"),
            Err(PathTransformError::NotTransformableFileComponent)
        );
        assert_eq!(
            split_transformable_file_component("directory"),
            Err(PathTransformError::NotTransformableFileComponent)
        );
        assert_eq!(
            split_transformable_file_component(".env"),
            Err(PathTransformError::NotTransformableFileComponent)
        );
        assert_eq!(
            split_transformable_file_component("main.rs"),
            Ok(("main", ".rs"))
        );
    }

    #[test]
    fn transformed_debug_omits_raw_component_text() {
        let source = "fixture.user@example.invalid";
        let (secrets, sensitive) = detect(source);
        let transformed = transform_component(source, &secrets, &sensitive).expect("transform");
        let debug = format!("{transformed:?}");
        assert!(!debug.contains(source));
        assert!(debug.contains("regions"));
        assert!(debug.contains("source_bytes_redacted"));
    }
}
