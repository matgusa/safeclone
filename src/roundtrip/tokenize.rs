//! Deterministic roundtrip-v3 detector normalization and typed-token output.
//!
//! Raw matched values are borrowed only while one component or file is being
//! transformed. Neither an occurrence nor the returned inventory contains a
//! value, value hash, or token-to-source mapping.

use std::collections::BTreeMap;

use crate::secrets::{self, SecretFinding};
use crate::sensitive::{self, SensitiveCategory, SensitiveFinding};

use super::anchor::{prepare_content_anchors, DetectedContentOccurrence, PreparedContentAnchors};
pub(super) use super::anchor::{EvidenceRegion, TokenFact};
use super::crypto::{HmacStream, KeyPurpose, KeySchedule};
use super::observe::FileIdentity;
use super::ruleset::ruleset_id;
use super::token::{
    authenticate_token, generate_token, parse_token, ComponentKind, EntryKind,
    OccurrenceDescriptor, ReviewProfile, TokenCategory, TokenUniqueness,
};
use super::{Error, Result};

pub(super) const MAX_OCCURRENCES_PER_COMPONENT: usize = 16_640;
pub(super) const MAX_SESSION_OCCURRENCES: usize = 100_000;
pub(super) const MAX_TRANSFORMED_FILE_BYTES: usize = 4 * 1024 * 1024;
const TOKEN_INTRODUCER: &[u8] = b"__SAFECLONE_RT1_";

pub(super) struct DetectorSet {
    secrets: secrets::RuleSet,
    sensitive: sensitive::RuleSet,
}

impl DetectorSet {
    pub(super) fn compile() -> Result<Self> {
        Ok(Self {
            secrets: secrets::RuleSet::compile().map_err(|_| Error::InvalidState)?,
            sensitive: sensitive::RuleSet::compile().map_err(|_| Error::InvalidState)?,
        })
    }

    fn findings(&self, text: &str) -> Result<(Vec<SecretFinding>, Vec<SensitiveFinding>)> {
        let secrets = self
            .secrets
            .find(text, secrets::Limits::default())
            .map_err(|_| Error::BoundExceeded)?;
        let sensitive = self
            .sensitive
            .find(text, sensitive::Limits::default())
            .map_err(|_| Error::BoundExceeded)?;
        Ok((secrets, sensitive))
    }

    pub(super) fn has_finding(&self, text: &str) -> Result<bool> {
        let (secret, sensitive) = self.findings(text)?;
        Ok(!secret.is_empty() || !sensitive.is_empty())
    }
}

pub(super) struct TokenInventory {
    uniqueness: TokenUniqueness,
    by_oid: BTreeMap<[u8; 16], TokenCategory>,
}

impl TokenInventory {
    pub(super) fn new() -> Self {
        Self {
            uniqueness: TokenUniqueness::default(),
            by_oid: BTreeMap::new(),
        }
    }

    fn insert(&mut self, token: &str, fact: &TokenFact) -> Result<()> {
        if self.by_oid.len() >= MAX_SESSION_OCCURRENCES {
            return Err(Error::BoundExceeded);
        }
        self.uniqueness.insert(token)?;
        if self
            .by_oid
            .insert(fact.occurrence_id, fact.category)
            .is_some()
        {
            return Err(Error::InvalidToken);
        }
        Ok(())
    }

    pub(super) fn len(&self) -> usize {
        self.by_oid.len()
    }

    pub(super) fn category_for(&self, oid: &[u8; 16]) -> Option<TokenCategory> {
        self.by_oid.get(oid).copied()
    }

    pub(super) fn iter(&self) -> impl Iterator<Item = (&[u8; 16], &TokenCategory)> {
        self.by_oid.iter()
    }

    #[cfg(test)]
    pub(super) fn insert_test_token(&mut self, token: &str, fact: &TokenFact) -> Result<()> {
        self.insert(token, fact)
    }
}

pub(super) struct Tokenizer<'a> {
    schedule: &'a KeySchedule<'a>,
    profile: ReviewProfile,
    detectors: DetectorSet,
    inventory: TokenInventory,
}

pub(super) struct TransformOutput {
    pub(super) bytes: Vec<u8>,
    pub(super) facts: Vec<TokenFact>,
    pub(super) prepared_content_anchors: PreparedContentAnchors,
}

pub(super) struct PathTransformOutput {
    pub(super) name: String,
    pub(super) facts: Vec<TokenFact>,
    pub(super) evidence: Vec<EvidenceRegion>,
    pub(super) pre_token_anchors: Vec<[u8; 32]>,
}

pub(super) struct PathTokenContext<'a> {
    pub(super) canonical_original_path: &'a [u8],
    pub(super) parent_identity: FileIdentity,
    pub(super) component_index: u32,
    pub(super) entry_kind: EntryKind,
    pub(super) component_kind: ComponentKind,
    pub(super) protected_suffix: &'a str,
}

struct ApplyContext<'a> {
    canonical_original_path: &'a [u8],
    entry_kind: EntryKind,
    component_index: u32,
    component_kind: ComponentKind,
    max_output: usize,
}

impl<'a> Tokenizer<'a> {
    pub(super) fn new(schedule: &'a KeySchedule<'a>, profile: ReviewProfile) -> Result<Self> {
        if !profile.is_current() {
            return Err(Error::InvalidState);
        }
        Ok(Self {
            schedule,
            profile,
            detectors: DetectorSet::compile()?,
            inventory: TokenInventory::new(),
        })
    }

    pub(super) fn inventory(&self) -> &TokenInventory {
        &self.inventory
    }

    pub(super) fn into_inventory(self) -> TokenInventory {
        self.inventory
    }

    pub(super) fn transform_content(
        &mut self,
        text: &str,
        canonical_original_path: &[u8],
    ) -> Result<TransformOutput> {
        let regions = self.regions(text)?;
        let prepared_content_anchors = prepare_content_anchors(
            self.schedule,
            self.profile,
            canonical_original_path,
            text.as_bytes(),
            regions,
        )?;
        let applied = self.apply(
            text,
            prepared_content_anchors.occurrences(),
            prepared_content_anchors.pre_token_commitments(),
            ApplyContext {
                canonical_original_path,
                entry_kind: EntryKind::RegularFile,
                component_index: 0,
                component_kind: ComponentKind::Content,
                max_output: MAX_TRANSFORMED_FILE_BYTES,
            },
        )?;
        Ok(TransformOutput {
            bytes: applied.bytes,
            facts: applied.facts,
            prepared_content_anchors,
        })
    }

    pub(super) fn observe_evidence(&self, text: &str) -> Result<Vec<EvidenceRegion>> {
        self.regions(text)?
            .iter()
            .map(EvidenceRegion::try_from)
            .collect()
    }

    pub(super) fn transform_path(
        &mut self,
        source: &str,
        tokenizable_bytes: usize,
        context: PathTokenContext<'_>,
    ) -> Result<PathTransformOutput> {
        let tokenizable = source
            .get(..tokenizable_bytes)
            .ok_or(Error::InvalidCanonicalInput)?;
        if source.get(tokenizable_bytes..) != Some(context.protected_suffix) {
            return Err(Error::InvalidState);
        }
        // A finding whose accepted full-component span enters the protected
        // suffix is not eligible for partial replacement.
        if self
            .regions(source)?
            .iter()
            .any(|region| region.end > tokenizable_bytes)
        {
            return Err(Error::InvalidState);
        }
        // Run boundary-sensitive detectors against the tokenizable stem. A
        // protected suffix such as `.txt` must not hide an IP address at the
        // end of that stem merely because `.` is meaningful to the detector.
        let regions = self.regions(tokenizable)?;
        let anchors = path_anchor_commitments(self.schedule, source, &regions, &context)?;
        let transformed = self.apply(
            tokenizable,
            &regions,
            &anchors,
            ApplyContext {
                canonical_original_path: context.canonical_original_path,
                entry_kind: context.entry_kind,
                component_index: context.component_index,
                component_kind: context.component_kind,
                max_output: 8 * 1024,
            },
        )?;
        let AppliedOutput {
            bytes,
            facts,
            evidence,
        } = transformed;
        let transformed = String::from_utf8(bytes).map_err(|_| Error::InvalidCanonicalInput)?;
        let mut name = transformed;
        name.try_reserve_exact(context.protected_suffix.len())
            .map_err(|_| Error::BoundExceeded)?;
        name.push_str(context.protected_suffix);
        Ok(PathTransformOutput {
            name,
            facts,
            evidence,
            pre_token_anchors: anchors,
        })
    }

    fn regions(&self, text: &str) -> Result<Vec<DetectedContentOccurrence>> {
        let (secret, sensitive) = self.detectors.findings(text)?;
        normalize_regions(text, &secret, &sensitive)
    }

    fn apply(
        &mut self,
        source: &str,
        regions: &[DetectedContentOccurrence],
        anchors: &[[u8; 32]],
        context: ApplyContext<'_>,
    ) -> Result<AppliedOutput> {
        if regions.len() != anchors.len() {
            return Err(Error::InvalidState);
        }
        let mut output = Vec::new();
        output
            .try_reserve_exact(source.len())
            .map_err(|_| Error::BoundExceeded)?;
        let mut facts = Vec::new();
        facts
            .try_reserve_exact(regions.len())
            .map_err(|_| Error::BoundExceeded)?;
        let mut cursor = 0usize;
        for (ordinal, (region, anchor)) in regions.iter().zip(anchors).enumerate() {
            let descriptor = OccurrenceDescriptor {
                session_id: self.schedule.session_id(),
                ruleset_id: ruleset_id(),
                review_profile: self.profile,
                entry_kind: context.entry_kind,
                canonical_original_relative_path: context.canonical_original_path,
                component_index: context.component_index,
                component_kind: context.component_kind,
                byte_span_start: u64::try_from(region.start).map_err(|_| Error::BoundExceeded)?,
                byte_span_end: u64::try_from(region.end).map_err(|_| Error::BoundExceeded)?,
                category: region.category,
                occurrence_ordinal_within_component: u32::try_from(ordinal)
                    .map_err(|_| Error::BoundExceeded)?,
                pre_token_anchor_commitment: *anchor,
            };
            let token = generate_token(self.schedule, &descriptor)?;
            if self.detectors.has_finding(&token)? {
                return Err(Error::InvalidToken);
            }
            let authenticated = authenticate_token(self.schedule, parse_token(&token)?)?;
            let fact = TokenFact {
                category: authenticated.category(),
                occurrence_id: *authenticated.occurrence_id(),
            };
            self.inventory.insert(&token, &fact)?;
            output.extend_from_slice(
                source
                    .as_bytes()
                    .get(cursor..region.start)
                    .ok_or(Error::InvalidCanonicalInput)?,
            );
            output.extend_from_slice(token.as_bytes());
            if output.len() > context.max_output {
                return Err(Error::BoundExceeded);
            }
            facts.push(fact);
            cursor = region.end;
        }
        output.extend_from_slice(
            source
                .as_bytes()
                .get(cursor..)
                .ok_or(Error::InvalidCanonicalInput)?,
        );
        if output.len() > context.max_output {
            return Err(Error::BoundExceeded);
        }
        let evidence = regions
            .iter()
            .map(EvidenceRegion::try_from)
            .collect::<Result<Vec<_>>>()?;
        Ok(AppliedOutput {
            bytes: output,
            facts,
            evidence,
        })
    }
}

struct AppliedOutput {
    bytes: Vec<u8>,
    facts: Vec<TokenFact>,
    evidence: Vec<EvidenceRegion>,
}

impl TryFrom<&DetectedContentOccurrence> for EvidenceRegion {
    type Error = Error;

    fn try_from(region: &DetectedContentOccurrence) -> Result<Self> {
        Ok(Self {
            start: u64::try_from(region.start).map_err(|_| Error::BoundExceeded)?,
            end: u64::try_from(region.end).map_err(|_| Error::BoundExceeded)?,
            category: region.category,
        })
    }
}

#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
struct Candidate {
    start: usize,
    end: usize,
    category_bits: u16,
}

fn normalize_regions(
    text: &str,
    secrets: &[SecretFinding],
    sensitive: &[SensitiveFinding],
) -> Result<Vec<DetectedContentOccurrence>> {
    let count = secrets
        .len()
        .checked_add(sensitive.len())
        .ok_or(Error::BoundExceeded)?;
    if count > MAX_OCCURRENCES_PER_COMPONENT {
        return Err(Error::BoundExceeded);
    }
    let mut candidates = Vec::new();
    candidates
        .try_reserve_exact(count)
        .map_err(|_| Error::BoundExceeded)?;
    for finding in secrets {
        push_candidate(
            text,
            &mut candidates,
            finding.span.start,
            finding.span.end,
            category_bit(TokenCategory::Secret),
        )?;
    }
    for finding in sensitive {
        let category = map_sensitive(finding.category);
        push_candidate(
            text,
            &mut candidates,
            finding.span.start,
            finding.span.end,
            category_bit(category),
        )?;
    }
    candidates.sort_unstable();
    candidates.dedup();
    let mut regions: Vec<DetectedContentOccurrence> = Vec::new();
    regions
        .try_reserve_exact(candidates.len())
        .map_err(|_| Error::BoundExceeded)?;
    for candidate in candidates {
        if let Some(current) = regions.last_mut() {
            if candidate.start < current.end {
                current.end = current.end.max(candidate.end);
                current.category_bits |= candidate.category_bits;
                current.category = category_from_bits(current.category_bits);
                continue;
            }
        }
        regions.push(DetectedContentOccurrence {
            start: candidate.start,
            end: candidate.end,
            category: category_from_bits(candidate.category_bits),
            ordinal: u32::try_from(regions.len()).map_err(|_| Error::BoundExceeded)?,
            category_bits: candidate.category_bits,
        });
    }
    if regions.len() > MAX_OCCURRENCES_PER_COMPONENT {
        return Err(Error::BoundExceeded);
    }
    Ok(regions)
}

fn push_candidate(
    text: &str,
    output: &mut Vec<Candidate>,
    start: usize,
    end: usize,
    category_bits: u16,
) -> Result<()> {
    if start >= end
        || end > text.len()
        || !text.is_char_boundary(start)
        || !text.is_char_boundary(end)
    {
        return Err(Error::InvalidState);
    }
    output.push(Candidate {
        start,
        end,
        category_bits,
    });
    Ok(())
}

fn map_sensitive(category: SensitiveCategory) -> TokenCategory {
    match category {
        SensitiveCategory::EmailAddress => TokenCategory::Email,
        SensitiveCategory::InternationalPhone => TokenCategory::Phone,
        SensitiveCategory::JapaneseDomesticPhoneCandidate => TokenCategory::JapanesePhone,
        SensitiveCategory::IpAddress => TokenCategory::Ip,
        SensitiveCategory::JapanesePostalCodeCandidate => TokenCategory::JapanesePostal,
        SensitiveCategory::MyNumberCandidate => TokenCategory::MyNumber,
        SensitiveCategory::JapaneseCorporateNumberCandidate => TokenCategory::CorporateNumber,
    }
}

const fn category_bit(category: TokenCategory) -> u16 {
    1u16 << ((category as u8) - 1)
}

fn category_from_bits(bits: u16) -> TokenCategory {
    if bits.count_ones() != 1 {
        return TokenCategory::Multiple;
    }
    TokenCategory::ALL
        .into_iter()
        .find(|category| category_bit(*category) == bits)
        .unwrap_or(TokenCategory::Multiple)
}

fn path_anchor_commitments(
    schedule: &KeySchedule<'_>,
    source: &str,
    regions: &[DetectedContentOccurrence],
    context: &PathTokenContext<'_>,
) -> Result<Vec<[u8; 32]>> {
    if regions.is_empty() {
        return Ok(Vec::new());
    }
    let mut encoder = MacEncoder::new(
        schedule,
        KeyPurpose::AnchorCommit,
        b"safeclone/rt1/pre-token-anchor",
    )?;
    encoder.u8(2);
    encoder.u64(context.parent_identity.volume_serial);
    encoder.bytes(&context.parent_identity.file_id)?;
    encoder.u32(context.component_index);
    encoder.u8(context.entry_kind as u8);
    encoder.u8(context.component_kind as u8);
    encoder.bytes(context.protected_suffix.as_bytes())?;
    encoder.u32(u32::try_from(regions.len()).map_err(|_| Error::BoundExceeded)?);
    let mut cursor = 0usize;
    for (ordinal, region) in regions.iter().enumerate() {
        encoder.bytes(&source.as_bytes()[cursor..region.start])?;
        encoder.u8(region.category as u8);
        encoder.u32(u32::try_from(ordinal).map_err(|_| Error::BoundExceeded)?);
        encoder.u64(u64::try_from(region.start).map_err(|_| Error::BoundExceeded)?);
        encoder.u64(u64::try_from(region.end).map_err(|_| Error::BoundExceeded)?);
        cursor = region.end;
    }
    encoder.bytes(&source.as_bytes()[cursor..])?;
    let tag = encoder.finish();
    Ok(vec![tag; regions.len()])
}

struct MacEncoder(HmacStream);

impl MacEncoder {
    fn new(schedule: &KeySchedule<'_>, purpose: KeyPurpose, domain: &[u8]) -> Result<Self> {
        let mut stream = HmacStream::new(schedule, purpose)?;
        stream.update(&(domain.len() as u32).to_be_bytes());
        stream.update(domain);
        Ok(Self(stream))
    }

    fn u8(&mut self, value: u8) {
        self.0.update(&[value]);
    }

    fn u32(&mut self, value: u32) {
        self.0.update(&value.to_be_bytes());
    }

    fn u64(&mut self, value: u64) {
        self.0.update(&value.to_be_bytes());
    }

    fn bytes(&mut self, value: &[u8]) -> Result<()> {
        self.u32(u32::try_from(value.len()).map_err(|_| Error::BoundExceeded)?);
        self.0.update(value);
        Ok(())
    }

    fn finish(self) -> [u8; 32] {
        self.0.finish()
    }
}

pub(super) fn contains_reserved_introducer(bytes: &[u8]) -> bool {
    bytes
        .windows(TOKEN_INTRODUCER.len())
        .any(|window| window.eq_ignore_ascii_case(TOKEN_INTRODUCER))
}

pub(super) fn verify_authentic_token(
    schedule: &KeySchedule<'_>,
    token: &str,
    inventory: &TokenInventory,
) -> Result<TokenFact> {
    let authenticated = authenticate_token(schedule, parse_token(token)?)?;
    if authenticated.session_id() != schedule.session_id() {
        return Err(Error::AuthenticationFailed);
    }
    let category = inventory
        .category_for(authenticated.occurrence_id())
        .ok_or(Error::InvalidToken)?;
    if category != authenticated.category() {
        return Err(Error::InvalidToken);
    }
    Ok(TokenFact {
        category,
        occurrence_id: *authenticated.occurrence_id(),
    })
}

pub(super) fn scan_authentic_tokens(
    schedule: &KeySchedule<'_>,
    text: &str,
    inventory: &TokenInventory,
    detectors: &DetectorSet,
) -> Result<(Vec<TokenFact>, String)> {
    let bytes = text.as_bytes();
    let mut facts = Vec::new();
    let mut masked = String::new();
    masked
        .try_reserve_exact(text.len())
        .map_err(|_| Error::BoundExceeded)?;
    let mut cursor = 0usize;
    while cursor < bytes.len() {
        let Some(relative) = bytes[cursor..]
            .windows(TOKEN_INTRODUCER.len())
            .position(|window| window.eq_ignore_ascii_case(TOKEN_INTRODUCER))
        else {
            masked.push_str(text.get(cursor..).ok_or(Error::InvalidCanonicalInput)?);
            break;
        };
        let start = cursor.checked_add(relative).ok_or(Error::BoundExceeded)?;
        if bytes.get(start..start + TOKEN_INTRODUCER.len()) != Some(TOKEN_INTRODUCER) {
            return Err(Error::InvalidToken);
        }
        masked.push_str(
            text.get(cursor..start)
                .ok_or(Error::InvalidCanonicalInput)?,
        );
        let body = start
            .checked_add(TOKEN_INTRODUCER.len())
            .ok_or(Error::BoundExceeded)?;
        let suffix = bytes[body..]
            .windows(2)
            .position(|window| window == b"__")
            .ok_or(Error::InvalidToken)?;
        let end = body
            .checked_add(suffix)
            .and_then(|value| value.checked_add(2))
            .ok_or(Error::BoundExceeded)?;
        let token = text.get(start..end).ok_or(Error::InvalidToken)?;
        let fact = verify_authentic_token(schedule, token, inventory)?;
        facts.push(fact);
        if facts.len() > MAX_SESSION_OCCURRENCES {
            return Err(Error::BoundExceeded);
        }
        masked.push_str("SAFECLONE_TOKEN");
        cursor = end;
    }
    if cursor == bytes.len() {
        // Nothing remains to append.
    }
    if detectors.has_finding(&masked)? {
        return Err(Error::InvalidState);
    }
    Ok((facts, masked))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::roundtrip::crypto::{SessionId, SessionMasterSecret};

    fn schedule<'a>(master: &'a SessionMasterSecret) -> KeySchedule<'a> {
        KeySchedule::new(master, SessionId::from_bytes([8; 16]))
    }

    fn synthetic_my_number(base: &str) -> String {
        let sum = base
            .bytes()
            .rev()
            .enumerate()
            .map(|(index, byte)| {
                let position = index as u32 + 1;
                let weight = if position <= 6 {
                    position + 1
                } else {
                    position - 5
                };
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
            .map(|(index, byte)| u32::from(byte - b'0') * if index % 2 == 0 { 1 } else { 2 })
            .sum::<u32>();
        format!("{}{base}", 9 - (sum % 9))
    }

    #[test]
    fn reserved_introducer_is_ascii_case_insensitive() {
        assert!(contains_reserved_introducer(b"x__safeclone_rt1_y"));
        assert!(!contains_reserved_introducer(b"__SAFECLONE_RT2_"));
    }

    #[test]
    fn transformed_file_bound_is_exact_and_enforced_before_output_is_returned() {
        assert_eq!(MAX_TRANSFORMED_FILE_BYTES, 4 * 1024 * 1024);
        let master = SessionMasterSecret::from_bytes([0x21; 32]);
        let schedule = schedule(&master);
        let mut tokenizer =
            Tokenizer::new(&schedule, ReviewProfile::StandardV2).expect("compile rules");
        let source = "192.0.2.10";
        let regions = tokenizer.regions(source).expect("find one IP");
        let prepared = prepare_content_anchors(
            &schedule,
            ReviewProfile::StandardV2,
            b"synthetic/bound.txt",
            source.as_bytes(),
            regions,
        )
        .expect("derive anchor");
        assert!(matches!(
            tokenizer.apply(
                source,
                prepared.occurrences(),
                prepared.pre_token_commitments(),
                ApplyContext {
                    canonical_original_path: b"synthetic/bound.txt",
                    entry_kind: EntryKind::RegularFile,
                    component_index: 0,
                    component_kind: ComponentKind::Content,
                    max_output: 1,
                },
            ),
            Err(Error::BoundExceeded)
        ));
    }

    #[test]
    fn same_category_overlap_remains_category_and_distinct_overlap_is_multiple() {
        let text = "fixture.user+test@example.invalid";
        let same = normalize_regions(
            text,
            &[],
            &[
                SensitiveFinding {
                    span: sensitive::SensitiveSpan { start: 0, end: 12 },
                    rule_id: sensitive::SensitiveRuleId::AsciiEmailV1,
                    category: SensitiveCategory::EmailAddress,
                },
                SensitiveFinding {
                    span: sensitive::SensitiveSpan { start: 4, end: 20 },
                    rule_id: sensitive::SensitiveRuleId::AsciiEmailV1,
                    category: SensitiveCategory::EmailAddress,
                },
            ],
        )
        .expect("normalize");
        assert_eq!(same[0].category, TokenCategory::Email);

        let multiple = normalize_regions(
            text,
            &[],
            &[
                SensitiveFinding {
                    span: sensitive::SensitiveSpan { start: 0, end: 12 },
                    rule_id: sensitive::SensitiveRuleId::AsciiEmailV1,
                    category: SensitiveCategory::EmailAddress,
                },
                SensitiveFinding {
                    span: sensitive::SensitiveSpan { start: 4, end: 20 },
                    rule_id: sensitive::SensitiveRuleId::InternationalPhoneV1,
                    category: SensitiveCategory::InternationalPhone,
                },
            ],
        )
        .expect("normalize");
        assert_eq!(multiple[0].category, TokenCategory::Multiple);
    }

    #[test]
    fn separate_equal_values_get_distinct_occurrence_ids() {
        let master = SessionMasterSecret::from_bytes([7; 32]);
        let schedule = schedule(&master);
        let mut tokenizer =
            Tokenizer::new(&schedule, ReviewProfile::StandardV2).expect("compile rules");
        let output = tokenizer
            .transform_content("192.0.2.10 then 192.0.2.10", b"synthetic/example.txt")
            .expect("transform");
        assert_eq!(output.facts.len(), 2);
        assert_ne!(output.facts[0].occurrence_id, output.facts[1].occurrence_id);
    }

    #[test]
    fn all_detector_categories_are_preserved_as_typed_facts() {
        let master = SessionMasterSecret::from_bytes([9; 32]);
        let schedule = schedule(&master);
        let mut tokenizer =
            Tokenizer::new(&schedule, ReviewProfile::StandardV2).expect("compile rules");
        let my_number = synthetic_my_number("10000000000");
        let corporate = synthetic_corporate_number("102030405060");
        let cases = [
            (
                "password = \"N0nLive_Fixture_4A7c9E2b\"".to_owned(),
                TokenCategory::Secret,
            ),
            (
                "fixture.user+test@example.invalid".to_owned(),
                TokenCategory::Email,
            ),
            ("+12345678".to_owned(), TokenCategory::Phone),
            ("090-0000-0000".to_owned(), TokenCategory::JapanesePhone),
            ("192.0.2.10".to_owned(), TokenCategory::Ip),
            ("123-4567".to_owned(), TokenCategory::JapanesePostal),
            (my_number, TokenCategory::MyNumber),
            (corporate, TokenCategory::CorporateNumber),
            ("+1 123-4567".to_owned(), TokenCategory::Multiple),
        ];
        for (index, (text, expected)) in cases.into_iter().enumerate() {
            let path = format!("synthetic/category-{index}.txt");
            let transformed = tokenizer
                .transform_content(&text, path.as_bytes())
                .expect("synthetic category transforms");
            assert!(
                transformed
                    .facts
                    .iter()
                    .any(|fact| fact.category == expected),
                "missing typed category {}",
                expected.as_str()
            );
            assert!(!String::from_utf8(transformed.bytes)
                .expect("token output is ASCII/UTF-8")
                .contains(&text));
        }
        assert_eq!(
            category_from_bits(
                category_bit(TokenCategory::Secret) | category_bit(TokenCategory::Email)
            ),
            TokenCategory::Multiple
        );
    }

    #[test]
    fn path_transform_preserves_suffix_and_binds_parent_context() {
        let master = SessionMasterSecret::from_bytes([10; 32]);
        let schedule = schedule(&master);
        let source = "address-192.0.2.10.txt";
        let stem = source.strip_suffix(".txt").expect("fixture suffix");
        let context = |file_id| PathTokenContext {
            canonical_original_path: b"synthetic/address-192.0.2.10.txt",
            parent_identity: FileIdentity {
                volume_serial: 7,
                file_id: [file_id; 16],
            },
            component_index: 0,
            entry_kind: EntryKind::RegularFile,
            component_kind: ComponentKind::Filename,
            protected_suffix: ".txt",
        };
        let mut first =
            Tokenizer::new(&schedule, ReviewProfile::StandardV2).expect("compile first");
        let output = first
            .transform_path(source, stem.len(), context(1))
            .expect("filename transform");
        assert!(output.name.ends_with(".txt"));
        assert!(output.name.contains("__SAFECLONE_RT1_"));
        assert!(output
            .facts
            .iter()
            .any(|fact| fact.category == TokenCategory::Ip));
        assert!(!output.name.contains("192.0.2.10"));

        let mut second =
            Tokenizer::new(&schedule, ReviewProfile::StandardV2).expect("compile second");
        let other_parent = second
            .transform_path(source, stem.len(), context(2))
            .expect("other-parent transform");
        assert_ne!(
            output.facts[0].occurrence_id,
            other_parent.facts[0].occurrence_id
        );

        let crossing = "fixture.user@example.txt";
        let crossing_stem = crossing.strip_suffix(".txt").expect("crossing suffix");
        let mut crossing_tokenizer =
            Tokenizer::new(&schedule, ReviewProfile::StandardV2).expect("compile crossing");
        assert_eq!(
            crossing_tokenizer
                .transform_path(crossing, crossing_stem.len(), context(1))
                .err(),
            Some(Error::InvalidState)
        );

        let expanding = (0..12)
            .map(|index| format!("192.0.2.{index}"))
            .collect::<Vec<_>>()
            .join("-");
        let mut expansion_tokenizer =
            Tokenizer::new(&schedule, ReviewProfile::StandardV2).expect("compile expansion");
        let expansion_context = PathTokenContext {
            canonical_original_path: b"synthetic/expansion",
            parent_identity: FileIdentity {
                volume_serial: 7,
                file_id: [3; 16],
            },
            component_index: 0,
            entry_kind: EntryKind::DirectoryComponent,
            component_kind: ComponentKind::Path,
            protected_suffix: "",
        };
        let expanded = expansion_tokenizer
            .transform_path(&expanding, expanding.len(), expansion_context)
            .expect("derive expanded safe component");
        assert!(expanded.name.encode_utf16().count() > 255);
        assert_eq!(
            crate::roundtrip::observe::validate_workspace_component(&expanded.name).err(),
            Some(Error::BoundExceeded)
        );
    }

    #[test]
    fn pre_token_anchor_excludes_raw_region_but_commits_surrounding_skeleton() {
        let master = SessionMasterSecret::from_bytes([11; 32]);
        let schedule = schedule(&master);
        let derive = |source: &str, end: usize| {
            prepare_content_anchors(
                &schedule,
                ReviewProfile::StandardV2,
                b"synthetic/pre-token.txt",
                source.as_bytes(),
                vec![DetectedContentOccurrence {
                    start: 7,
                    end,
                    category: TokenCategory::Secret,
                    ordinal: 0,
                    category_bits: category_bit(TokenCategory::Secret),
                }],
            )
            .expect("derive anchor")
            .pre_token_commitments()[0]
        };
        let first = derive("prefix AAA suffix\n", 10);
        let same_skeleton = derive("prefix BBB suffix\n", 10);
        let changed_skeleton = derive("prefix CCC changed\n", 10);
        let boundary = |source: &str, start: usize, end: usize| {
            prepare_content_anchors(
                &schedule,
                ReviewProfile::StandardV2,
                b"synthetic/pre-token.txt",
                source.as_bytes(),
                vec![DetectedContentOccurrence {
                    start,
                    end,
                    category: TokenCategory::Secret,
                    ordinal: 0,
                    category_bits: category_bit(TokenCategory::Secret),
                }],
            )
            .expect("derive boundary anchor")
            .pre_token_commitments()[0]
        };
        let boundary_at_one = boundary("aAAA b\n", 1, 4);
        let boundary_at_two = boundary("a AAAb\n", 2, 5);
        assert_eq!(first, same_skeleton);
        assert_ne!(first, changed_skeleton);
        assert_ne!(boundary_at_one, boundary_at_two);
    }

    #[test]
    fn verifier_rejects_malformed_wrong_auth_unknown_and_raw_residue() {
        let master = SessionMasterSecret::from_bytes([12; 32]);
        let schedule = schedule(&master);
        let mut tokenizer =
            Tokenizer::new(&schedule, ReviewProfile::StandardV2).expect("compile rules");
        let transformed = tokenizer
            .transform_content("192.0.2.10", b"synthetic/token.txt")
            .expect("create authentic token");
        let authentic = String::from_utf8(transformed.bytes).expect("token UTF-8");
        let inventory = tokenizer.into_inventory();
        let detectors = DetectorSet::compile().expect("compile verifier rules");
        assert_eq!(
            scan_authentic_tokens(&schedule, &authentic, &inventory, &detectors)
                .expect("authentic token")
                .0,
            transformed.facts
        );

        let wrong_case = authentic.replacen("__SAFECLONE_RT1_", "__safeclone_rt1_", 1);
        assert!(scan_authentic_tokens(&schedule, &wrong_case, &inventory, &detectors).is_err());
        let wrong_category = authentic.replacen("_IP_", "_EMAIL_", 1);
        assert!(scan_authentic_tokens(&schedule, &wrong_category, &inventory, &detectors).is_err());
        let malformed = "__SAFECLONE_RT1_IP_NOT-CANONICAL__";
        assert!(scan_authentic_tokens(&schedule, malformed, &inventory, &detectors).is_err());
        let raw_residue = format!("{authentic} fixture.user+test@example.invalid");
        assert!(scan_authentic_tokens(&schedule, &raw_residue, &inventory, &detectors).is_err());

        let other_schedule = KeySchedule::new(&master, SessionId::from_bytes([9; 16]));
        let mut other_session =
            Tokenizer::new(&other_schedule, ReviewProfile::StandardV2).expect("compile other SID");
        let wrong_sid = other_session
            .transform_content("192.0.2.12", b"synthetic/wrong-sid.txt")
            .expect("other-session authentic token");
        let wrong_sid = String::from_utf8(wrong_sid.bytes).expect("wrong SID UTF-8");
        assert!(scan_authentic_tokens(&schedule, &wrong_sid, &inventory, &detectors).is_err());

        let mut unrelated =
            Tokenizer::new(&schedule, ReviewProfile::StandardV2).expect("compile unrelated");
        let unknown = unrelated
            .transform_content("192.0.2.11", b"synthetic/unknown.txt")
            .expect("unrelated authentic token");
        let unknown = String::from_utf8(unknown.bytes).expect("unknown UTF-8");
        assert!(scan_authentic_tokens(&schedule, &unknown, &inventory, &detectors).is_err());
    }
}
