//! Canonical typed tokens and occurrence-derived authentication.

use std::collections::BTreeSet;

use data_encoding::BASE32_NOPAD;

use super::canonical::CanonicalWriter;
use super::crypto::{
    constant_time_equal, hmac_tag, hmac_verify_left, leftmost_16, KeyPurpose, KeySchedule,
    SessionId,
};
use super::{Error, Result};

pub const TOKEN_SUITE_ID: u16 = 1;
pub const ENGINE_VERSION: &str = "safeclone-roundtrip-engine-v3";
pub const POLICY_ID: &str = "roundtrip-v3";
pub const TOKEN_PREFIX: &str = "__SAFECLONE_RT1_";
pub const TOKEN_SUFFIX: &str = "__";
pub const BASE32_128_LENGTH: usize = 26;
pub const MAX_CANONICAL_RELATIVE_PATH_BYTES: usize = 128 * 1024;
const MAX_OCCURRENCE_DESCRIPTOR_BYTES: usize = 256 * 1024;
const TOKEN_AUTH_INPUT_LIMIT: usize = 256;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum TokenCategory {
    Secret = 1,
    Email = 2,
    Phone = 3,
    JapanesePhone = 4,
    Ip = 5,
    JapanesePostal = 6,
    MyNumber = 7,
    CorporateNumber = 8,
    Multiple = 9,
}

impl TokenCategory {
    pub const ALL: [Self; 9] = [
        Self::Secret,
        Self::Email,
        Self::Phone,
        Self::JapanesePhone,
        Self::Ip,
        Self::JapanesePostal,
        Self::MyNumber,
        Self::CorporateNumber,
        Self::Multiple,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Secret => "SECRET",
            Self::Email => "EMAIL",
            Self::Phone => "PHONE",
            Self::JapanesePhone => "JPPHONE",
            Self::Ip => "IP",
            Self::JapanesePostal => "JPPOSTAL",
            Self::MyNumber => "MYNUMBER",
            Self::CorporateNumber => "CORPNUM",
            Self::Multiple => "MULTIPLE",
        }
    }

    pub(crate) const fn from_code(value: u64) -> Option<Self> {
        match value {
            1 => Some(Self::Secret),
            2 => Some(Self::Email),
            3 => Some(Self::Phone),
            4 => Some(Self::JapanesePhone),
            5 => Some(Self::Ip),
            6 => Some(Self::JapanesePostal),
            7 => Some(Self::MyNumber),
            8 => Some(Self::CorporateNumber),
            9 => Some(Self::Multiple),
            _ => None,
        }
    }

    fn parse(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|category| category.as_str() == value)
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(u8)]
pub enum ReviewProfile {
    StandardV1 = 1,
    StrictTokenFileV1 = 2,
    #[default]
    StandardV2 = 3,
    StrictTokenFilesV2 = 4,
}

impl ReviewProfile {
    pub(crate) fn parse(value: u64) -> Option<Self> {
        match value {
            1 => Some(Self::StandardV1),
            2 => Some(Self::StrictTokenFileV1),
            3 => Some(Self::StandardV2),
            4 => Some(Self::StrictTokenFilesV2),
            _ => None,
        }
    }

    pub const fn is_current(self) -> bool {
        matches!(self, Self::StandardV2 | Self::StrictTokenFilesV2)
    }

    pub const fn external_label(self) -> &'static str {
        match self {
            Self::StandardV1 => "standard-v1",
            Self::StrictTokenFileV1 => "strict-token-file-v1",
            Self::StandardV2 => "standard-v2",
            Self::StrictTokenFilesV2 => "strict-token-files-v2",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum EntryKind {
    RegularFile = 1,
    DirectoryComponent = 2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ComponentKind {
    Content = 1,
    Path = 2,
    Filename = 3,
}

/// Pure, transient occurrence input. It contains no matched raw value.
pub struct OccurrenceDescriptor<'a> {
    pub session_id: SessionId,
    pub ruleset_id: &'a str,
    pub review_profile: ReviewProfile,
    pub entry_kind: EntryKind,
    pub canonical_original_relative_path: &'a [u8],
    pub component_index: u32,
    pub component_kind: ComponentKind,
    pub byte_span_start: u64,
    pub byte_span_end: u64,
    pub category: TokenCategory,
    pub occurrence_ordinal_within_component: u32,
    pub pre_token_anchor_commitment: [u8; 32],
}

impl OccurrenceDescriptor<'_> {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        if !self.review_profile.is_current()
            || !valid_ruleset_id(self.ruleset_id)
            || self.canonical_original_relative_path.is_empty()
            || self.canonical_original_relative_path.len() > MAX_CANONICAL_RELATIVE_PATH_BYTES
            || self.byte_span_start >= self.byte_span_end
        {
            return Err(Error::InvalidCanonicalInput);
        }
        let mut writer = CanonicalWriter::new(
            "safeclone/rt1/occurrence-descriptor",
            MAX_OCCURRENCE_DESCRIPTOR_BYTES,
        )?;
        writer.u16(TOKEN_SUITE_ID)?;
        writer.bytes(self.session_id.as_bytes())?;
        writer.ascii(ENGINE_VERSION)?;
        writer.ascii(POLICY_ID)?;
        writer.ascii(self.ruleset_id)?;
        writer.u8(self.review_profile as u8)?;
        writer.u8(self.entry_kind as u8)?;
        writer.bytes(self.canonical_original_relative_path)?;
        writer.u32(self.component_index)?;
        writer.u8(self.component_kind as u8)?;
        writer.u64(self.byte_span_start)?;
        writer.u64(self.byte_span_end)?;
        writer.u8(self.category as u8)?;
        writer.u32(self.occurrence_ordinal_within_component)?;
        writer.bytes(&self.pre_token_anchor_commitment)?;
        Ok(writer.finish())
    }
}

pub struct ParsedToken {
    category: TokenCategory,
    session_id: SessionId,
    occurrence_id: [u8; 16],
    authentication: [u8; 16],
}

impl ParsedToken {
    pub const fn category(&self) -> TokenCategory {
        self.category
    }

    pub const fn session_id(&self) -> SessionId {
        self.session_id
    }

    pub const fn occurrence_id(&self) -> &[u8; 16] {
        &self.occurrence_id
    }
}

pub struct AuthenticatedToken(ParsedToken);

impl AuthenticatedToken {
    pub const fn category(&self) -> TokenCategory {
        self.0.category
    }

    pub const fn session_id(&self) -> SessionId {
        self.0.session_id
    }

    pub const fn occurrence_id(&self) -> &[u8; 16] {
        &self.0.occurrence_id
    }
}

pub fn encode_base32_128(bytes: &[u8; 16]) -> String {
    BASE32_NOPAD.encode(bytes)
}

pub fn encode_base32_256(bytes: &[u8; 32]) -> String {
    BASE32_NOPAD.encode(bytes)
}

pub fn decode_base32_128(value: &str) -> Result<[u8; 16]> {
    if value.len() != BASE32_128_LENGTH
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || matches!(byte, b'2'..=b'7'))
    {
        return Err(Error::InvalidToken);
    }
    let decoded = BASE32_NOPAD
        .decode(value.as_bytes())
        .map_err(|_| Error::InvalidToken)?;
    let bytes: [u8; 16] = decoded.try_into().map_err(|_| Error::InvalidToken)?;
    if BASE32_NOPAD.encode(&bytes) != value {
        return Err(Error::InvalidToken);
    }
    Ok(bytes)
}

pub fn parse_token(value: &str) -> Result<ParsedToken> {
    if !value.is_ascii() {
        return Err(Error::InvalidToken);
    }
    let body = value
        .strip_prefix(TOKEN_PREFIX)
        .and_then(|value| value.strip_suffix(TOKEN_SUFFIX))
        .ok_or(Error::InvalidToken)?;
    let mut fields = body.split('_');
    let category = TokenCategory::parse(fields.next().ok_or(Error::InvalidToken)?)
        .ok_or(Error::InvalidToken)?;
    let session_id = SessionId::from_bytes(decode_base32_128(
        fields.next().ok_or(Error::InvalidToken)?,
    )?);
    let occurrence_id = decode_base32_128(fields.next().ok_or(Error::InvalidToken)?)?;
    let authentication = decode_base32_128(fields.next().ok_or(Error::InvalidToken)?)?;
    if fields.next().is_some() {
        return Err(Error::InvalidToken);
    }
    Ok(ParsedToken {
        category,
        session_id,
        occurrence_id,
        authentication,
    })
}

pub fn generate_token(
    schedule: &KeySchedule<'_>,
    descriptor: &OccurrenceDescriptor<'_>,
) -> Result<String> {
    if descriptor.session_id != schedule.session_id() {
        return Err(Error::InvalidCanonicalInput);
    }
    let descriptor_bytes = descriptor.canonical_bytes()?;
    let token_id_key = schedule.derive(KeyPurpose::TokenId)?;
    let occurrence_id = leftmost_16(&hmac_tag(&token_id_key, &[&descriptor_bytes])?);
    let auth_input = token_auth_input(descriptor.category, descriptor.session_id, &occurrence_id)?;
    let token_auth_key = schedule.derive(KeyPurpose::TokenAuth)?;
    let authentication = leftmost_16(&hmac_tag(&token_auth_key, &[&auth_input])?);
    Ok(format!(
        "{TOKEN_PREFIX}{}_{}_{}_{}{TOKEN_SUFFIX}",
        descriptor.category.as_str(),
        encode_base32_128(descriptor.session_id.as_bytes()),
        encode_base32_128(&occurrence_id),
        encode_base32_128(&authentication)
    ))
}

pub fn authenticate_token(
    schedule: &KeySchedule<'_>,
    parsed: ParsedToken,
) -> Result<AuthenticatedToken> {
    if !constant_time_equal(
        parsed.session_id.as_bytes(),
        schedule.session_id().as_bytes(),
    ) {
        return Err(Error::AuthenticationFailed);
    }
    let input = token_auth_input(parsed.category, parsed.session_id, &parsed.occurrence_id)?;
    let key = schedule.derive(KeyPurpose::TokenAuth)?;
    hmac_verify_left(&key, &[&input], &parsed.authentication)?;
    Ok(AuthenticatedToken(parsed))
}

fn token_auth_input(
    category: TokenCategory,
    session_id: SessionId,
    occurrence_id: &[u8; 16],
) -> Result<Vec<u8>> {
    let mut writer =
        CanonicalWriter::new("safeclone/rt1/token-auth-input", TOKEN_AUTH_INPUT_LIMIT)?;
    writer.u16(TOKEN_SUITE_ID)?;
    writer.u8(category as u8)?;
    writer.bytes(session_id.as_bytes())?;
    writer.bytes(occurrence_id)?;
    Ok(writer.finish())
}

pub fn valid_ruleset_id(value: &str) -> bool {
    value.strip_prefix("ruleset-sha256-").is_some_and(|digest| {
        digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    })
}

/// Pure helper used by create orchestration to reject exact and Windows-
/// casefold token collisions without changing token grammar.
#[derive(Default)]
pub struct TokenUniqueness {
    exact: BTreeSet<String>,
    windows_casefold: BTreeSet<String>,
}

impl TokenUniqueness {
    pub fn insert(&mut self, token: &str) -> Result<()> {
        parse_token(token)?;
        let folded = token.to_ascii_lowercase();
        if self.exact.contains(token) || self.windows_casefold.contains(&folded) {
            return Err(Error::InvalidToken);
        }
        self.exact.insert(token.to_owned());
        self.windows_casefold.insert(folded);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::roundtrip::crypto::SessionMasterSecret;

    const RULESET: &str =
        "ruleset-sha256-db05d116f06728ef64c5cdf7cc087df2f2f799459d2845a15e32479a1e8d1825";

    fn descriptor<'a>(session_id: SessionId, path: &'a [u8]) -> OccurrenceDescriptor<'a> {
        OccurrenceDescriptor {
            session_id,
            ruleset_id: RULESET,
            review_profile: ReviewProfile::StandardV2,
            entry_kind: EntryKind::RegularFile,
            canonical_original_relative_path: path,
            component_index: 0,
            component_kind: ComponentKind::Content,
            byte_span_start: 4,
            byte_span_end: 12,
            category: TokenCategory::Secret,
            occurrence_ordinal_within_component: 0,
            pre_token_anchor_commitment: [0x55; 32],
        }
    }

    #[test]
    fn engine_v3_profile_registry_is_exact_and_historical_values_are_not_reinterpreted() {
        assert_eq!(ENGINE_VERSION, "safeclone-roundtrip-engine-v3");
        assert_eq!(POLICY_ID, "roundtrip-v3");
        assert_eq!(TOKEN_SUITE_ID, 1);
        assert_eq!(ReviewProfile::StandardV1 as u8, 1);
        assert_eq!(ReviewProfile::StrictTokenFileV1 as u8, 2);
        assert_eq!(ReviewProfile::StandardV2 as u8, 3);
        assert_eq!(ReviewProfile::StrictTokenFilesV2 as u8, 4);
        assert_eq!(ReviewProfile::parse(0), None);
        assert_eq!(ReviewProfile::parse(1), Some(ReviewProfile::StandardV1));
        assert_eq!(
            ReviewProfile::parse(2),
            Some(ReviewProfile::StrictTokenFileV1)
        );
        assert_eq!(ReviewProfile::parse(3), Some(ReviewProfile::StandardV2));
        assert_eq!(
            ReviewProfile::parse(4),
            Some(ReviewProfile::StrictTokenFilesV2)
        );
        assert_eq!(ReviewProfile::parse(5), None);
        assert_eq!(ReviewProfile::default(), ReviewProfile::StandardV2);
        assert_eq!(ReviewProfile::StandardV2.external_label(), "standard-v2");
        assert_eq!(
            ReviewProfile::StrictTokenFilesV2.external_label(),
            "strict-token-files-v2"
        );

        let session_id = SessionId::from_bytes([0x42; 16]);
        let mut input = descriptor(session_id, b"synthetic/profile.txt");
        input
            .canonical_bytes()
            .expect("profile 3 is current authority");
        input.review_profile = ReviewProfile::StrictTokenFilesV2;
        input
            .canonical_bytes()
            .expect("profile 4 is current authority");
        for historical in [ReviewProfile::StandardV1, ReviewProfile::StrictTokenFileV1] {
            input.review_profile = historical;
            assert_eq!(input.canonical_bytes(), Err(Error::InvalidCanonicalInput));
        }
    }

    #[test]
    fn rfc4648_style_128_bit_vector_is_canonical() {
        let bytes = *b"abcdefghijklmnop";
        let encoded = encode_base32_128(&bytes);
        assert_eq!(encoded, "MFRGGZDFMZTWQ2LKNNWG23TPOA");
        assert_eq!(decode_base32_128(&encoded), Ok(bytes));
        for invalid in [
            "mFRGGZDFMZTWQ2LKNNWG23TPOA",
            "MFRGGZDFMZTWQ2LKNNWG23TPOA=",
            "MFRGGZDFMZTWQ2LKNNWG23TPO",
            "MFRGGZDFMZTWQ2LKNNWG23TPO!",
            "MFRGGZDFMZTWQ2LKNNWG23TP0A",
            "MFRGGZDFMZTWQ2LKNNWG23TPOB",
        ] {
            assert_eq!(decode_base32_128(invalid), Err(Error::InvalidToken));
        }
    }

    #[test]
    fn every_category_round_trips_but_parse_is_not_authentication() {
        let master = SessionMasterSecret::from_bytes([0x21; 32]);
        let session_id = SessionId::from_bytes([0x42; 16]);
        let schedule = KeySchedule::new(&master, session_id);
        for category in TokenCategory::ALL {
            let mut input = descriptor(session_id, b"synthetic/file.txt");
            input.category = category;
            let token = generate_token(&schedule, &input).expect("generate token");
            let parsed = parse_token(&token).expect("parse token");
            assert_eq!(parsed.category(), category);
            let authenticated = authenticate_token(&schedule, parsed).expect("authenticate token");
            assert_eq!(authenticated.category(), category);
        }
    }

    #[test]
    fn occurrence_and_session_changes_separate_tokens() {
        let master = SessionMasterSecret::from_bytes([0x21; 32]);
        let first_id = SessionId::from_bytes([0x42; 16]);
        let second_id = SessionId::from_bytes([0x43; 16]);
        let first_schedule = KeySchedule::new(&master, first_id);
        let second_schedule = KeySchedule::new(&master, second_id);
        let first = generate_token(&first_schedule, &descriptor(first_id, b"a/file.txt"))
            .expect("first token");
        let repeat = generate_token(&first_schedule, &descriptor(first_id, b"a/file.txt"))
            .expect("repeat token");
        let other_occurrence =
            generate_token(&first_schedule, &descriptor(first_id, b"b/file.txt"))
                .expect("other occurrence");
        let other_session = generate_token(&second_schedule, &descriptor(second_id, b"a/file.txt"))
            .expect("other session");
        assert_eq!(first, repeat);
        assert_ne!(first, other_occurrence);
        assert_ne!(first, other_session);
        assert_eq!(
            authenticate_token(&second_schedule, parse_token(&first).expect("parse replay")).err(),
            Some(Error::AuthenticationFailed)
        );
    }

    #[test]
    fn structural_and_authenticated_mutations_fail_closed() {
        let master = SessionMasterSecret::from_bytes([0x21; 32]);
        let session_id = SessionId::from_bytes([0x42; 16]);
        let schedule = KeySchedule::new(&master, session_id);
        let token = generate_token(&schedule, &descriptor(session_id, b"file.txt"))
            .expect("generate token");
        for malformed in [
            token.to_ascii_lowercase(),
            token.replacen("__SAFECLONE", "_SAFECLONE", 1),
            token.replacen("SAFECLONE", "SAFECLONF", 1),
            token.replacen(TOKEN_PREFIX, "__SAFECLONE_RT2_", 1),
            token.replacen(TOKEN_SUFFIX, "_", 1),
            token.replacen("SECRET", "UNKNOWN", 1),
            format!("x{token}"),
            format!("{token}x"),
        ] {
            assert_eq!(parse_token(&malformed).err(), Some(Error::InvalidToken));
        }

        let body = token
            .strip_prefix(TOKEN_PREFIX)
            .and_then(|value| value.strip_suffix(TOKEN_SUFFIX))
            .expect("generated grammar");
        let fields: Vec<&str> = body.split('_').collect();
        let mut mutations = vec![format!(
            "{TOKEN_PREFIX}EMAIL_{}_{}_{}{TOKEN_SUFFIX}",
            fields[1], fields[2], fields[3]
        )];
        for index in 1..=3 {
            let mut changed = fields
                .iter()
                .map(|field| (*field).to_owned())
                .collect::<Vec<_>>();
            let replacement = if changed[index].starts_with('A') {
                'B'
            } else {
                'A'
            };
            changed[index].replace_range(..1, &replacement.to_string());
            mutations.push(format!(
                "{TOKEN_PREFIX}{}_{}_{}_{}{TOKEN_SUFFIX}",
                changed[0], changed[1], changed[2], changed[3]
            ));
        }
        for mutated in mutations {
            let parsed = parse_token(&mutated).expect("mutation remains lexical");
            assert_eq!(
                authenticate_token(&schedule, parsed).err(),
                Some(Error::AuthenticationFailed)
            );
        }
    }

    #[test]
    fn token_uniqueness_rejects_exact_and_casefold_collisions() {
        let master = SessionMasterSecret::from_bytes([0x21; 32]);
        let session_id = SessionId::from_bytes([0x42; 16]);
        let schedule = KeySchedule::new(&master, session_id);
        let token = generate_token(&schedule, &descriptor(session_id, b"file.txt"))
            .expect("generate token");
        let mut inventory = TokenUniqueness::default();
        inventory.insert(&token).expect("first insert");
        assert_eq!(inventory.insert(&token), Err(Error::InvalidToken));
        assert_eq!(
            inventory.insert(&token.to_ascii_lowercase()),
            Err(Error::InvalidToken)
        );
    }

    #[test]
    fn generated_tokens_do_not_retrigger_public_detectors() {
        use std::ffi::OsStr;

        let master = SessionMasterSecret::from_bytes([0x21; 32]);
        let session_id = SessionId::from_bytes([0x42; 16]);
        let schedule = KeySchedule::new(&master, session_id);
        for category in TokenCategory::ALL {
            let mut input = descriptor(session_id, b"synthetic/file.txt");
            input.category = category;
            let token = generate_token(&schedule, &input).expect("generate token");

            let mut secrets = crate::secrets::Session::new(crate::secrets::Limits::default())
                .expect("compile secret rules");
            assert_eq!(
                secrets
                    .scan_file(&token, |findings| assert!(findings.is_empty()))
                    .expect("scan token as content"),
                0
            );

            let mut sensitive = crate::sensitive::Session::new(crate::sensitive::Limits::default())
                .expect("compile sensitive rules");
            assert_eq!(
                sensitive
                    .scan_file(&token, |findings| assert!(findings.is_empty()))
                    .expect("scan token as content"),
                0
            );

            let mut filename = crate::filename::Session::new(crate::filename::Limits::default());
            assert_eq!(
                filename
                    .scan_basename(OsStr::new(&token), |findings| {
                        assert!(findings.is_empty())
                    })
                    .expect("scan token as filename"),
                0
            );
        }
    }
}
