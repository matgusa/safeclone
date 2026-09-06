//! Session cryptographic suite and secret-memory wrappers.

use std::fmt;

use ctutils::CtEq;
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};

use super::{Error, Result};

type HmacSha256 = Hmac<Sha256>;

pub const SESSION_ID_BYTES: usize = 16;
pub const KEY_BYTES: usize = 32;
pub const TAG_BYTES: usize = 32;

pub const TOKEN_ID_INFO: &[u8] = b"safeclone/rt1/token-id";
pub const TOKEN_AUTH_INFO: &[u8] = b"safeclone/rt1/token-auth";
pub const TREE_COMMIT_INFO: &[u8] = b"safeclone/rt1/tree-commit";
pub const ANCHOR_COMMIT_INFO: &[u8] = b"safeclone/rt1/anchor-commit";
pub const EVENT_ID_INFO: &[u8] = b"safeclone/rt1/event-id";
pub const CAPSULE_MAC_INFO: &[u8] = b"safeclone/rt1/capsule-mac";
pub const MANIFEST_MAC_INFO: &[u8] = b"safeclone/rt1/manifest-mac";
pub const APPROVAL_MAC_INFO: &[u8] = b"safeclone/rt1/approval-mac";
pub const CANDIDATE_MARKER_INFO: &[u8] = b"safeclone/rt1/candidate-marker";
pub const TOMBSTONE_MAC_INFO: &[u8] = b"safeclone/rt1/tombstone-mac";

pub const KEY_INFO_LABELS: [&[u8]; 10] = [
    TOKEN_ID_INFO,
    TOKEN_AUTH_INFO,
    TREE_COMMIT_INFO,
    ANCHOR_COMMIT_INFO,
    EVENT_ID_INFO,
    CAPSULE_MAC_INFO,
    MANIFEST_MAC_INFO,
    APPROVAL_MAC_INFO,
    CANDIDATE_MARKER_INFO,
    TOMBSTONE_MAC_INFO,
];

#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SessionId([u8; SESSION_ID_BYTES]);

impl SessionId {
    pub const fn from_bytes(bytes: [u8; SESSION_ID_BYTES]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; SESSION_ID_BYTES] {
        &self.0
    }

    #[cfg(windows)]
    pub fn generate() -> Result<Self> {
        let mut bytes = [0u8; SESSION_ID_BYTES];
        system_random(&mut bytes)?;
        Ok(Self(bytes))
    }
}

impl fmt::Debug for SessionId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionId(..)")
    }
}

pub struct SessionMasterSecret([u8; KEY_BYTES]);

impl SessionMasterSecret {
    pub fn from_bytes(bytes: [u8; KEY_BYTES]) -> Self {
        Self(bytes)
    }

    #[cfg(windows)]
    pub fn generate() -> Result<Self> {
        let mut bytes = [0u8; KEY_BYTES];
        system_random(&mut bytes)?;
        Ok(Self(bytes))
    }

    pub(crate) const fn expose(&self) -> &[u8; KEY_BYTES] {
        &self.0
    }
}

impl fmt::Debug for SessionMasterSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionMasterSecret([REDACTED])")
    }
}

impl Drop for SessionMasterSecret {
    fn drop(&mut self) {
        secure_zero(&mut self.0);
    }
}

pub struct DerivedKey([u8; KEY_BYTES]);

impl DerivedKey {
    pub(crate) const fn expose(&self) -> &[u8; KEY_BYTES] {
        &self.0
    }

    #[cfg(test)]
    pub(crate) const fn from_test_bytes(bytes: [u8; KEY_BYTES]) -> Self {
        Self(bytes)
    }
}

impl fmt::Debug for DerivedKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DerivedKey([REDACTED])")
    }
}

impl Drop for DerivedKey {
    fn drop(&mut self) {
        secure_zero(&mut self.0);
    }
}

/// Heap bytes whose contents are cleared best-effort before deallocation.
pub(crate) struct SecretVec(Vec<u8>);

impl SecretVec {
    pub(crate) fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.0
    }

    pub(crate) fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl fmt::Debug for SecretVec {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretVec([REDACTED])")
    }
}

impl Drop for SecretVec {
    fn drop(&mut self) {
        secure_zero(&mut self.0);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyPurpose {
    TokenId,
    TokenAuth,
    TreeCommit,
    AnchorCommit,
    EventId,
    CapsuleMac,
    ManifestMac,
    ApprovalMac,
    CandidateMarker,
    TombstoneMac,
}

impl KeyPurpose {
    const fn info(self) -> &'static [u8] {
        match self {
            Self::TokenId => TOKEN_ID_INFO,
            Self::TokenAuth => TOKEN_AUTH_INFO,
            Self::TreeCommit => TREE_COMMIT_INFO,
            Self::AnchorCommit => ANCHOR_COMMIT_INFO,
            Self::EventId => EVENT_ID_INFO,
            Self::CapsuleMac => CAPSULE_MAC_INFO,
            Self::ManifestMac => MANIFEST_MAC_INFO,
            Self::ApprovalMac => APPROVAL_MAC_INFO,
            Self::CandidateMarker => CANDIDATE_MARKER_INFO,
            Self::TombstoneMac => TOMBSTONE_MAC_INFO,
        }
    }
}

pub struct KeySchedule<'a> {
    master: &'a SessionMasterSecret,
    session_id: SessionId,
}

impl<'a> KeySchedule<'a> {
    pub const fn new(master: &'a SessionMasterSecret, session_id: SessionId) -> Self {
        Self { master, session_id }
    }

    pub const fn session_id(&self) -> SessionId {
        self.session_id
    }

    pub fn derive(&self, purpose: KeyPurpose) -> Result<DerivedKey> {
        let mut output = [0u8; KEY_BYTES];
        hkdf_expand(
            self.master.expose(),
            self.session_id.as_bytes(),
            purpose.info(),
            &mut output,
        )?;
        Ok(DerivedKey(output))
    }
}

pub(crate) fn hmac_tag(key: &DerivedKey, parts: &[&[u8]]) -> Result<[u8; TAG_BYTES]> {
    hmac_tag_raw(key.expose(), parts)
}

/// Incremental HMAC for bounded filesystem streams. The derived key is copied
/// only into the MAC state and its wrapper is cleared immediately afterward.
pub(crate) struct HmacStream(HmacSha256);

impl HmacStream {
    pub(crate) fn new(schedule: &KeySchedule<'_>, purpose: KeyPurpose) -> Result<Self> {
        let key = schedule.derive(purpose)?;
        let mac =
            HmacSha256::new_from_slice(key.expose()).map_err(|_| Error::KeyDerivationFailed)?;
        Ok(Self(mac))
    }

    pub(crate) fn update(&mut self, bytes: &[u8]) {
        self.0.update(bytes);
    }

    pub(crate) fn finish(self) -> [u8; TAG_BYTES] {
        self.0.finalize().into_bytes().into()
    }
}

pub(crate) fn hmac_verify(key: &DerivedKey, parts: &[&[u8]], tag: &[u8]) -> Result<()> {
    let mut mac =
        HmacSha256::new_from_slice(key.expose()).map_err(|_| Error::KeyDerivationFailed)?;
    for part in parts {
        mac.update(part);
    }
    mac.verify_slice(tag)
        .map_err(|_| Error::AuthenticationFailed)
}

pub(crate) fn hmac_verify_left(key: &DerivedKey, parts: &[&[u8]], tag: &[u8]) -> Result<()> {
    let mut mac =
        HmacSha256::new_from_slice(key.expose()).map_err(|_| Error::KeyDerivationFailed)?;
    for part in parts {
        mac.update(part);
    }
    mac.verify_truncated_left(tag)
        .map_err(|_| Error::AuthenticationFailed)
}

pub(crate) fn leftmost_16(tag: &[u8; TAG_BYTES]) -> [u8; 16] {
    let mut output = [0u8; 16];
    output.copy_from_slice(&tag[..16]);
    output
}

pub(crate) fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    bool::from(left.ct_eq(right))
}

pub(crate) fn constant_time_equal_option_fixed<const N: usize>(
    left: Option<&[u8; N]>,
    right: Option<&[u8; N]>,
) -> bool {
    match (left, right) {
        (None, None) => true,
        (Some(left), Some(right)) => constant_time_equal(left, right),
        (None, Some(_)) | (Some(_), None) => false,
    }
}

/// SHA-256 for public, static compatibility descriptors only.
pub(crate) fn public_static_sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn hmac_tag_raw(key: &[u8], parts: &[&[u8]]) -> Result<[u8; TAG_BYTES]> {
    let mut mac = HmacSha256::new_from_slice(key).map_err(|_| Error::KeyDerivationFailed)?;
    for part in parts {
        mac.update(part);
    }
    Ok(mac.finalize().into_bytes().into())
}

fn hkdf_expand(ikm: &[u8], salt: &[u8], info: &[u8], output: &mut [u8]) -> Result<()> {
    Hkdf::<Sha256>::new(Some(salt), ikm)
        .expand(info, output)
        .map_err(|_| Error::KeyDerivationFailed)
}

#[cfg(windows)]
pub(crate) fn system_random(bytes: &mut [u8]) -> Result<()> {
    use windows_sys::Win32::Security::Cryptography::{
        BCryptGenRandom, BCRYPT_USE_SYSTEM_PREFERRED_RNG,
    };

    let length = u32::try_from(bytes.len()).map_err(|_| Error::BoundExceeded)?;
    // SAFETY: a null algorithm handle is required with
    // BCRYPT_USE_SYSTEM_PREFERRED_RNG and `bytes` is writable for `length`.
    let status = unsafe {
        BCryptGenRandom(
            std::ptr::null_mut(),
            bytes.as_mut_ptr(),
            length,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };
    if status >= 0 {
        Ok(())
    } else {
        secure_zero(bytes);
        Err(Error::RandomGenerationFailed)
    }
}

pub(crate) fn secure_zero(bytes: &mut [u8]) {
    // Windows declares SecureZeroMemory/RtlSecureZeroMemory as an inline
    // volatile store helper rather than a linkable Windows SDK symbol.
    // `windows-sys` 0.61.2 therefore has no binding. This is the same
    // best-effort volatile-store contract, followed by a compiler fence.
    for byte in bytes {
        // SAFETY: each pointer comes from a unique mutable reference and
        // remains live for the volatile write.
        unsafe { std::ptr::write_volatile(byte, 0) };
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(value: &str) -> Vec<u8> {
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let text = std::str::from_utf8(pair).expect("ASCII hex");
                u8::from_str_radix(text, 16).expect("valid hex")
            })
            .collect()
    }

    #[test]
    fn rfc5869_sha256_case_one_is_exact() {
        let ikm = vec![0x0b; 22];
        let salt = hex("000102030405060708090a0b0c");
        let info = hex("f0f1f2f3f4f5f6f7f8f9");
        let expected = hex("3cb25f25faacd57a90434f64d0362f2a\
             2d2d0a90cf1a5a4c5db02d56ecc4c5bf\
             34007208d5b887185865");
        let mut output = vec![0u8; expected.len()];
        hkdf_expand(&ikm, &salt, &info, &mut output).expect("HKDF vector");
        assert_eq!(output, expected);
    }

    #[test]
    fn rfc4231_sha256_case_one_is_exact() {
        let expected = hex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
        assert_eq!(
            hmac_tag_raw(&[0x0b; 20], &[b"Hi There"]).expect("HMAC vector"),
            expected.as_slice()
        );
    }

    #[test]
    fn key_schedule_is_domain_and_session_separated() {
        assert_eq!(KEY_INFO_LABELS.len(), 10);
        let master = SessionMasterSecret::from_bytes([0x42; 32]);
        let first = KeySchedule::new(&master, SessionId::from_bytes([0x11; 16]));
        let second = KeySchedule::new(&master, SessionId::from_bytes([0x12; 16]));
        let mut derived = Vec::new();
        for purpose in [
            KeyPurpose::TokenId,
            KeyPurpose::TokenAuth,
            KeyPurpose::TreeCommit,
            KeyPurpose::AnchorCommit,
            KeyPurpose::EventId,
            KeyPurpose::CapsuleMac,
            KeyPurpose::ManifestMac,
            KeyPurpose::ApprovalMac,
            KeyPurpose::CandidateMarker,
            KeyPurpose::TombstoneMac,
        ] {
            derived.push(first.derive(purpose).expect("derive").expose().to_owned());
        }
        derived.sort();
        derived.dedup();
        assert_eq!(derived.len(), 10);
        assert!(!constant_time_equal(
            first.derive(KeyPurpose::TokenId).expect("first").expose(),
            second.derive(KeyPurpose::TokenId).expect("second").expose()
        ));
    }

    #[test]
    fn optional_fixed_authority_comparison_keeps_presence_structural() {
        let left = [0x31; 32];
        let equal = [0x31; 32];
        let different = [0x32; 32];
        assert!(constant_time_equal_option_fixed::<32>(None, None));
        assert!(constant_time_equal_option_fixed(Some(&left), Some(&equal)));
        assert!(!constant_time_equal_option_fixed(
            Some(&left),
            Some(&different)
        ));
        assert!(!constant_time_equal_option_fixed(Some(&left), None));
        assert!(!constant_time_equal_option_fixed(None, Some(&left)));
    }

    #[test]
    fn secret_debug_is_redacted() {
        let master = SessionMasterSecret::from_bytes([0x41; 32]);
        let key = KeySchedule::new(&master, SessionId::from_bytes([0; 16]))
            .derive(KeyPurpose::TokenId)
            .expect("derive");
        assert!(!format!("{master:?}{key:?}").contains("414141"));
    }

    #[cfg(windows)]
    #[test]
    fn system_rng_produces_nonconstant_bytes() {
        let first = SessionMasterSecret::generate().expect("first secret");
        let second = SessionMasterSecret::generate().expect("second secret");
        assert!(!constant_time_equal(first.expose(), second.expose()));
    }
}
