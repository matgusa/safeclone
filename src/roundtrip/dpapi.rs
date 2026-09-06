//! CurrentUser DPAPI plus application-authenticated session envelopes.

use std::fmt;
use std::ptr;
use std::slice;

use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Security::Cryptography::{
    CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
};

use super::crypto::{
    constant_time_equal, hmac_tag, hmac_verify, secure_zero, DerivedKey, KeyPurpose, KeySchedule,
    SecretVec, SessionId, SessionMasterSecret, TAG_BYTES,
};
use super::ruleset;
use super::schema::{CapsuleV1, ClosedTombstoneV1};
use super::{Error, Result};

pub const OUTER_HEADER_BYTES: usize = 48;
pub const INNER_PREFIX_BYTES: usize = 78;
pub const HMAC_BYTES: usize = 32;
pub const MAX_CAPSULE_FILE_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_CAPSULE_INNER_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_MANIFEST_FILE_BYTES: usize = 256 * 1024 * 1024;
pub const MAX_MANIFEST_INNER_BYTES: usize = 128 * 1024 * 1024;
const OUTER_MAGIC: &[u8; 8] = b"SCRTDP1\0";
const INNER_MAGIC: &[u8; 8] = b"SCRTIN1\0";
const ENVELOPE_DOMAIN: &[u8] = b"safeclone/rt1/inner-envelope";
const DPAPI_ENTROPY_DOMAIN: &[u8] = b"safeclone/rt1/dpapi/";
const ENVELOPE_VERSION: u16 = 1;
const SUITE_ID: u16 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum EnvelopeRole {
    Capsule = 1,
    Manifest = 2,
}

impl EnvelopeRole {
    fn parse(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Capsule),
            2 => Some(Self::Manifest),
            _ => None,
        }
    }

    const fn file_limit(self) -> usize {
        match self {
            Self::Capsule => MAX_CAPSULE_FILE_BYTES,
            Self::Manifest => MAX_MANIFEST_FILE_BYTES,
        }
    }

    const fn inner_limit(self) -> usize {
        match self {
            Self::Capsule => MAX_CAPSULE_INNER_BYTES,
            Self::Manifest => MAX_MANIFEST_INNER_BYTES,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum KeyKind {
    ExternalSessionKey = 0,
    SessionMaster = 1,
    TombstoneMacKey = 2,
}

impl KeyKind {
    fn parse(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::ExternalSessionKey),
            1 => Some(Self::SessionMaster),
            2 => Some(Self::TombstoneMacKey),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OuterHeaderV1 {
    pub role: EnvelopeRole,
    pub session_id: SessionId,
    pub generation: u64,
    pub dpapi_blob_length: u64,
}

impl OuterHeaderV1 {
    pub fn encode(self) -> [u8; OUTER_HEADER_BYTES] {
        let mut output = [0u8; OUTER_HEADER_BYTES];
        output[..8].copy_from_slice(OUTER_MAGIC);
        output[8] = self.role as u8;
        output[9] = 0;
        output[10..12].copy_from_slice(&ENVELOPE_VERSION.to_be_bytes());
        output[12..14].copy_from_slice(&SUITE_ID.to_be_bytes());
        output[14..16].copy_from_slice(&0u16.to_be_bytes());
        output[16..32].copy_from_slice(self.session_id.as_bytes());
        output[32..40].copy_from_slice(&self.generation.to_be_bytes());
        output[40..48].copy_from_slice(&self.dpapi_blob_length.to_be_bytes());
        output
    }

    pub fn parse(file: &[u8], expected_role: EnvelopeRole) -> Result<(Self, &[u8])> {
        if file.len() < OUTER_HEADER_BYTES || file.len() > expected_role.file_limit() {
            return Err(Error::InvalidEnvelope);
        }
        let header = &file[..OUTER_HEADER_BYTES];
        if &header[..8] != OUTER_MAGIC
            || header[9] != 0
            || u16::from_be_bytes(
                header[10..12]
                    .try_into()
                    .map_err(|_| Error::InvalidEnvelope)?,
            ) != ENVELOPE_VERSION
            || u16::from_be_bytes(
                header[12..14]
                    .try_into()
                    .map_err(|_| Error::InvalidEnvelope)?,
            ) != SUITE_ID
            || u16::from_be_bytes(
                header[14..16]
                    .try_into()
                    .map_err(|_| Error::InvalidEnvelope)?,
            ) != 0
        {
            return Err(Error::InvalidEnvelope);
        }
        let role = EnvelopeRole::parse(header[8]).ok_or(Error::InvalidEnvelope)?;
        if role != expected_role {
            return Err(Error::InvalidEnvelope);
        }
        let session_id = SessionId::from_bytes(
            header[16..32]
                .try_into()
                .map_err(|_| Error::InvalidEnvelope)?,
        );
        let generation = u64::from_be_bytes(
            header[32..40]
                .try_into()
                .map_err(|_| Error::InvalidEnvelope)?,
        );
        if generation == 0 {
            return Err(Error::InvalidEnvelope);
        }
        let dpapi_blob_length = u64::from_be_bytes(
            header[40..48]
                .try_into()
                .map_err(|_| Error::InvalidEnvelope)?,
        );
        let blob_length = usize::try_from(dpapi_blob_length).map_err(|_| Error::InvalidEnvelope)?;
        let exact = OUTER_HEADER_BYTES
            .checked_add(blob_length)
            .ok_or(Error::InvalidEnvelope)?;
        if exact != file.len() {
            return Err(Error::InvalidEnvelope);
        }
        Ok((
            Self {
                role,
                session_id,
                generation,
                dpapi_blob_length,
            },
            &file[OUTER_HEADER_BYTES..],
        ))
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct InnerPrefixV1 {
    pub role: EnvelopeRole,
    pub key_kind: KeyKind,
    pub session_id: SessionId,
    pub generation: u64,
    pub previous_generation_tag: [u8; TAG_BYTES],
    pub key_material_length: u16,
    pub payload_length: u32,
}

impl fmt::Debug for InnerPrefixV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InnerPrefixV1")
            .field("role", &self.role)
            .field("key_kind", &self.key_kind)
            .field("session_id", &self.session_id)
            .field("generation", &self.generation)
            .field("previous_generation_tag", &"[REDACTED]")
            .field("key_material_length", &self.key_material_length)
            .field("payload_length", &self.payload_length)
            .finish()
    }
}

impl InnerPrefixV1 {
    pub fn encode(self) -> [u8; INNER_PREFIX_BYTES] {
        let mut output = [0u8; INNER_PREFIX_BYTES];
        output[..8].copy_from_slice(INNER_MAGIC);
        output[8] = self.role as u8;
        output[9] = self.key_kind as u8;
        output[10..12].copy_from_slice(&ENVELOPE_VERSION.to_be_bytes());
        output[12..14].copy_from_slice(&SUITE_ID.to_be_bytes());
        output[14..16].copy_from_slice(&0u16.to_be_bytes());
        output[16..32].copy_from_slice(self.session_id.as_bytes());
        output[32..40].copy_from_slice(&self.generation.to_be_bytes());
        output[40..72].copy_from_slice(&self.previous_generation_tag);
        output[72..74].copy_from_slice(&self.key_material_length.to_be_bytes());
        output[74..78].copy_from_slice(&self.payload_length.to_be_bytes());
        output
    }

    fn parse(inner: &[u8]) -> Result<Self> {
        if inner.len() < INNER_PREFIX_BYTES + HMAC_BYTES || &inner[..8] != INNER_MAGIC {
            return Err(Error::InvalidEnvelope);
        }
        let fixed = &inner[..INNER_PREFIX_BYTES];
        if u16::from_be_bytes(
            fixed[10..12]
                .try_into()
                .map_err(|_| Error::InvalidEnvelope)?,
        ) != ENVELOPE_VERSION
            || u16::from_be_bytes(
                fixed[12..14]
                    .try_into()
                    .map_err(|_| Error::InvalidEnvelope)?,
            ) != SUITE_ID
            || u16::from_be_bytes(
                fixed[14..16]
                    .try_into()
                    .map_err(|_| Error::InvalidEnvelope)?,
            ) != 0
        {
            return Err(Error::InvalidEnvelope);
        }
        let role = EnvelopeRole::parse(fixed[8]).ok_or(Error::InvalidEnvelope)?;
        let key_kind = KeyKind::parse(fixed[9]).ok_or(Error::InvalidEnvelope)?;
        let session_id = SessionId::from_bytes(
            fixed[16..32]
                .try_into()
                .map_err(|_| Error::InvalidEnvelope)?,
        );
        let generation = u64::from_be_bytes(
            fixed[32..40]
                .try_into()
                .map_err(|_| Error::InvalidEnvelope)?,
        );
        if generation == 0 {
            return Err(Error::InvalidEnvelope);
        }
        Ok(Self {
            role,
            key_kind,
            session_id,
            generation,
            previous_generation_tag: fixed[40..72]
                .try_into()
                .map_err(|_| Error::InvalidEnvelope)?,
            key_material_length: u16::from_be_bytes(
                fixed[72..74]
                    .try_into()
                    .map_err(|_| Error::InvalidEnvelope)?,
            ),
            payload_length: u32::from_be_bytes(
                fixed[74..78]
                    .try_into()
                    .map_err(|_| Error::InvalidEnvelope)?,
            ),
        })
    }
}

pub struct PrivateBytes(SecretVec);

impl PrivateBytes {
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl fmt::Debug for PrivateBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PrivateBytes([REDACTED])")
    }
}

/// Authenticated manifest plaintext plus the exact application HMAC that is
/// bound by ReviewAuthorityV1. Neither plaintext nor this wrapper implements
/// ordinary display formatting.
pub(crate) struct AuthenticatedManifestBytes {
    payload: PrivateBytes,
    commitment: [u8; TAG_BYTES],
}

impl AuthenticatedManifestBytes {
    pub(crate) fn as_bytes(&self) -> &[u8] {
        self.payload.as_bytes()
    }

    pub(crate) const fn commitment(&self) -> &[u8; TAG_BYTES] {
        &self.commitment
    }
}

pub(crate) struct ProtectedManifestBytes {
    bytes: Vec<u8>,
    commitment: [u8; TAG_BYTES],
}

impl ProtectedManifestBytes {
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub(crate) const fn commitment(&self) -> &[u8; TAG_BYTES] {
        &self.commitment
    }
}

pub struct AuthenticatedLiveCapsule {
    capsule: CapsuleV1,
    master: SessionMasterSecret,
    tag: [u8; TAG_BYTES],
}

impl AuthenticatedLiveCapsule {
    pub const fn capsule(&self) -> &CapsuleV1 {
        &self.capsule
    }

    pub const fn tag(&self) -> &[u8; TAG_BYTES] {
        &self.tag
    }

    pub fn key_schedule(&self) -> KeySchedule<'_> {
        KeySchedule::new(&self.master, self.capsule.session_id)
    }

    pub(crate) const fn master(&self) -> &SessionMasterSecret {
        &self.master
    }
}

pub struct AuthenticatedTombstone {
    tombstone: ClosedTombstoneV1,
    tag: [u8; TAG_BYTES],
}

impl AuthenticatedTombstone {
    pub const fn tombstone(&self) -> &ClosedTombstoneV1 {
        &self.tombstone
    }

    pub const fn tag(&self) -> &[u8; TAG_BYTES] {
        &self.tag
    }
}

struct ParsedInner<'a> {
    prefix: InnerPrefixV1,
    prefix_bytes: &'a [u8],
    key_material: &'a [u8],
    payload: &'a [u8],
    tag: &'a [u8],
}

pub fn protect_initial_live_capsule(
    master: &SessionMasterSecret,
    capsule: &CapsuleV1,
) -> Result<Vec<u8>> {
    if capsule.generation != 1 {
        return Err(Error::InvalidState);
    }
    validate_supported_capsule(capsule)?;
    protect_live(master, capsule, [0u8; TAG_BYTES])
}

pub fn protect_next_live_capsule(
    prior: &AuthenticatedLiveCapsule,
    capsule: &CapsuleV1,
) -> Result<Vec<u8>> {
    if capsule.session_id != prior.capsule.session_id
        || capsule.generation
            != prior
                .capsule
                .generation
                .checked_add(1)
                .ok_or(Error::InvalidState)?
    {
        return Err(Error::InvalidState);
    }
    validate_supported_capsule(capsule)?;
    validate_live_continuity(&prior.capsule, capsule)?;
    protect_live(prior.master(), capsule, prior.tag)
}

fn protect_live(
    master: &SessionMasterSecret,
    capsule: &CapsuleV1,
    previous_tag: [u8; TAG_BYTES],
) -> Result<Vec<u8>> {
    capsule.validate_capsule_state()?;
    let payload = capsule.encode_canonical()?;
    let prefix = InnerPrefixV1 {
        role: EnvelopeRole::Capsule,
        key_kind: KeyKind::SessionMaster,
        session_id: capsule.session_id,
        generation: capsule.generation,
        previous_generation_tag: previous_tag,
        key_material_length: 32,
        payload_length: u32::try_from(payload.len()).map_err(|_| Error::BoundExceeded)?,
    };
    let key = KeySchedule::new(master, capsule.session_id).derive(KeyPurpose::CapsuleMac)?;
    protect_authenticated(
        EnvelopeRole::Capsule,
        capsule.session_id,
        capsule.generation,
        prefix,
        master.expose(),
        &payload,
        &key,
    )
}

pub fn unprotect_live_capsule(
    file: &[u8],
    prior: Option<&AuthenticatedLiveCapsule>,
) -> Result<AuthenticatedLiveCapsule> {
    let (outer, mut inner) = unprotect_envelope(file, EnvelopeRole::Capsule)?;
    let parsed = parse_inner(inner.as_slice(), EnvelopeRole::Capsule)?;
    if parsed.prefix.key_kind != KeyKind::SessionMaster || parsed.key_material.len() != 32 {
        return Err(Error::InvalidEnvelope);
    }
    let mut master_bytes: [u8; 32] = parsed
        .key_material
        .try_into()
        .map_err(|_| Error::InvalidEnvelope)?;
    let master = SessionMasterSecret::from_bytes(master_bytes);
    secure_zero(&mut master_bytes);
    let key = KeySchedule::new(&master, outer.session_id).derive(KeyPurpose::CapsuleMac)?;
    verify_inner(&outer, &parsed, &key)?;
    compare_repeated(&outer, &parsed.prefix)?;
    match prior {
        None => {
            if outer.generation != 1
                || !constant_time_equal(&parsed.prefix.previous_generation_tag, &[0u8; TAG_BYTES])
            {
                return Err(Error::InvalidState);
            }
        }
        Some(prior) => {
            if outer.session_id != prior.capsule.session_id
                || outer.generation
                    != prior
                        .capsule
                        .generation
                        .checked_add(1)
                        .ok_or(Error::InvalidState)?
                || !constant_time_equal(&parsed.prefix.previous_generation_tag, &prior.tag)
                || !constant_time_equal(master.expose(), prior.master.expose())
            {
                return Err(Error::AuthenticationFailed);
            }
        }
    }
    let capsule = CapsuleV1::decode_canonical(parsed.payload)?;
    if capsule.session_id != outer.session_id || capsule.generation != outer.generation {
        return Err(Error::InvalidState);
    }
    validate_supported_capsule(&capsule)?;
    if let Some(prior) = prior {
        validate_live_continuity(&prior.capsule, &capsule)?;
    }
    let tag = parsed.tag.try_into().map_err(|_| Error::InvalidEnvelope)?;
    secure_zero(inner.as_mut_slice());
    Ok(AuthenticatedLiveCapsule {
        capsule,
        master,
        tag,
    })
}

pub fn protect_authenticated_manifest_bytes(
    owner: &AuthenticatedLiveCapsule,
    payload: &[u8],
) -> Result<Vec<u8>> {
    protect_manifest_for_generation(owner, owner.capsule.generation, payload)
}

/// Protects the review manifest for the next capsule generation, which is
/// its first owning/reference generation. This does not commit either file.
pub(crate) fn protect_next_review_manifest(
    owner: &AuthenticatedLiveCapsule,
    payload: &[u8],
) -> Result<ProtectedManifestBytes> {
    let generation = owner
        .capsule
        .generation
        .checked_add(1)
        .ok_or(Error::InvalidState)?;
    let bytes = protect_manifest_for_generation(owner, generation, payload)?;
    let authenticated =
        unprotect_manifest_authenticated_with_schedule(&owner.key_schedule(), generation, &bytes)?;
    if !constant_time_equal(authenticated.as_bytes(), payload) {
        return Err(Error::AuthenticationFailed);
    }
    Ok(ProtectedManifestBytes {
        bytes,
        commitment: *authenticated.commitment(),
    })
}

pub(crate) fn protect_next_apply_manifest(
    owner: &AuthenticatedLiveCapsule,
    payload: &[u8],
) -> Result<ProtectedManifestBytes> {
    protect_next_review_manifest(owner, payload)
}

fn protect_manifest_for_generation(
    owner: &AuthenticatedLiveCapsule,
    generation: u64,
    payload: &[u8],
) -> Result<Vec<u8>> {
    if payload.len() > MAX_MANIFEST_INNER_BYTES - INNER_PREFIX_BYTES - HMAC_BYTES {
        return Err(Error::BoundExceeded);
    }
    let prefix = InnerPrefixV1 {
        role: EnvelopeRole::Manifest,
        key_kind: KeyKind::ExternalSessionKey,
        session_id: owner.capsule.session_id,
        generation,
        previous_generation_tag: [0u8; TAG_BYTES],
        key_material_length: 0,
        payload_length: u32::try_from(payload.len()).map_err(|_| Error::BoundExceeded)?,
    };
    let key = owner.key_schedule().derive(KeyPurpose::ManifestMac)?;
    protect_authenticated(
        EnvelopeRole::Manifest,
        owner.capsule.session_id,
        generation,
        prefix,
        &[],
        payload,
        &key,
    )
}

pub fn unprotect_authenticated_manifest_bytes(
    owner: &AuthenticatedLiveCapsule,
    file: &[u8],
) -> Result<PrivateBytes> {
    unprotect_manifest_with_schedule(&owner.key_schedule(), owner.capsule.generation, file)
}

pub(crate) fn unprotect_manifest_with_schedule(
    schedule: &KeySchedule<'_>,
    expected_generation: u64,
    file: &[u8],
) -> Result<PrivateBytes> {
    Ok(
        unprotect_manifest_authenticated_with_schedule(schedule, expected_generation, file)?
            .payload,
    )
}

pub(crate) fn unprotect_manifest_authenticated_with_schedule(
    schedule: &KeySchedule<'_>,
    expected_generation: u64,
    file: &[u8],
) -> Result<AuthenticatedManifestBytes> {
    let (outer, mut inner) = unprotect_envelope(file, EnvelopeRole::Manifest)?;
    let parsed = parse_inner(inner.as_slice(), EnvelopeRole::Manifest)?;
    if parsed.prefix.key_kind != KeyKind::ExternalSessionKey
        || !parsed.key_material.is_empty()
        || !constant_time_equal(&parsed.prefix.previous_generation_tag, &[0u8; TAG_BYTES])
    {
        return Err(Error::InvalidEnvelope);
    }
    let key = schedule.derive(KeyPurpose::ManifestMac)?;
    verify_inner(&outer, &parsed, &key)?;
    compare_repeated(&outer, &parsed.prefix)?;
    if outer.session_id != schedule.session_id() || outer.generation != expected_generation {
        return Err(Error::AuthenticationFailed);
    }
    let payload = parsed.payload.to_vec();
    let commitment = parsed.tag.try_into().map_err(|_| Error::InvalidEnvelope)?;
    secure_zero(inner.as_mut_slice());
    Ok(AuthenticatedManifestBytes {
        payload: PrivateBytes(SecretVec::new(payload)),
        commitment,
    })
}

pub fn protect_closed_tombstone(
    prior: &AuthenticatedLiveCapsule,
    tombstone: &ClosedTombstoneV1,
) -> Result<Vec<u8>> {
    tombstone.validate()?;
    if tombstone.session_id != prior.capsule.session_id
        || tombstone.generation
            != prior
                .capsule
                .generation
                .checked_add(1)
                .ok_or(Error::InvalidState)?
        || tombstone.last_nonclosed_state != prior.capsule.session_state
        || tombstone.review_profile != prior.capsule.review_profile
        || tombstone.ruleset_id != prior.capsule.ruleset_id
    {
        return Err(Error::InvalidState);
    }
    let payload = tombstone.encode_canonical()?;
    let key = prior.key_schedule().derive(KeyPurpose::TombstoneMac)?;
    let prefix = InnerPrefixV1 {
        role: EnvelopeRole::Capsule,
        key_kind: KeyKind::TombstoneMacKey,
        session_id: tombstone.session_id,
        generation: tombstone.generation,
        previous_generation_tag: prior.tag,
        key_material_length: 32,
        payload_length: u32::try_from(payload.len()).map_err(|_| Error::BoundExceeded)?,
    };
    protect_authenticated(
        EnvelopeRole::Capsule,
        tombstone.session_id,
        tombstone.generation,
        prefix,
        key.expose(),
        &payload,
        &key,
    )
}

pub fn unprotect_closed_tombstone(
    prior: &AuthenticatedLiveCapsule,
    file: &[u8],
) -> Result<AuthenticatedTombstone> {
    let (outer, mut inner) = unprotect_envelope(file, EnvelopeRole::Capsule)?;
    let parsed = parse_inner(inner.as_slice(), EnvelopeRole::Capsule)?;
    if parsed.prefix.key_kind != KeyKind::TombstoneMacKey || parsed.key_material.len() != 32 {
        return Err(Error::InvalidEnvelope);
    }
    let expected_key = prior.key_schedule().derive(KeyPurpose::TombstoneMac)?;
    if !constant_time_equal(parsed.key_material, expected_key.expose())
        || !constant_time_equal(&parsed.prefix.previous_generation_tag, &prior.tag)
    {
        return Err(Error::AuthenticationFailed);
    }
    verify_inner(&outer, &parsed, &expected_key)?;
    compare_repeated(&outer, &parsed.prefix)?;
    if outer.session_id != prior.capsule.session_id
        || outer.generation
            != prior
                .capsule
                .generation
                .checked_add(1)
                .ok_or(Error::InvalidState)?
    {
        return Err(Error::AuthenticationFailed);
    }
    let tombstone = ClosedTombstoneV1::decode_canonical(parsed.payload)?;
    if tombstone.session_id != outer.session_id
        || tombstone.generation != outer.generation
        || tombstone.last_nonclosed_state != prior.capsule.session_state
        || tombstone.review_profile != prior.capsule.review_profile
        || tombstone.ruleset_id != prior.capsule.ruleset_id
    {
        return Err(Error::InvalidState);
    }
    let tag = parsed.tag.try_into().map_err(|_| Error::InvalidEnvelope)?;
    secure_zero(inner.as_mut_slice());
    Ok(AuthenticatedTombstone { tombstone, tag })
}

fn validate_supported_capsule(capsule: &CapsuleV1) -> Result<()> {
    if capsule.ruleset_id == ruleset::ruleset_id() {
        Ok(())
    } else {
        Err(Error::InvalidState)
    }
}

fn validate_live_continuity(prior: &CapsuleV1, next: &CapsuleV1) -> Result<()> {
    if next.review_profile == prior.review_profile
        && next.ruleset_id == prior.ruleset_id
        && constant_time_equal(
            &next.original_tree_commitment,
            &prior.original_tree_commitment,
        )
        && constant_time_equal(
            &next.baseline_ai_tree_commitment,
            &prior.baseline_ai_tree_commitment,
        )
        && next.baseline_counts == prior.baseline_counts
        && next.created_epoch_seconds == prior.created_epoch_seconds
        && constant_time_equal(
            &next.state_root_identity_commitment,
            &prior.state_root_identity_commitment,
        )
    {
        Ok(())
    } else {
        Err(Error::InvalidState)
    }
}

fn protect_authenticated(
    role: EnvelopeRole,
    session_id: SessionId,
    generation: u64,
    prefix: InnerPrefixV1,
    key_material: &[u8],
    payload: &[u8],
    key: &DerivedKey,
) -> Result<Vec<u8>> {
    if generation == 0
        || usize::from(prefix.key_material_length) != key_material.len()
        || usize::try_from(prefix.payload_length).map_err(|_| Error::BoundExceeded)?
            != payload.len()
    {
        return Err(Error::InvalidEnvelope);
    }
    let provisional_outer = OuterHeaderV1 {
        role,
        session_id,
        generation,
        dpapi_blob_length: 0,
    };
    let provisional_inner = build_inner(provisional_outer, prefix, key_material, payload, key)?;
    let mut provisional_blob = dpapi_protect(
        provisional_inner.as_slice(),
        &dpapi_entropy(role, session_id, generation),
    )?;
    let blob_length = provisional_blob.len();
    secure_zero(&mut provisional_blob);
    drop(provisional_inner);

    let outer = OuterHeaderV1 {
        role,
        session_id,
        generation,
        dpapi_blob_length: u64::try_from(blob_length).map_err(|_| Error::BoundExceeded)?,
    };
    let inner = build_inner(outer, prefix, key_material, payload, key)?;
    if inner.as_slice().len() > role.inner_limit() {
        return Err(Error::BoundExceeded);
    }
    let blob = dpapi_protect(
        inner.as_slice(),
        &dpapi_entropy(role, session_id, generation),
    )?;
    if blob.len() != blob_length {
        return Err(Error::DpapiFailed);
    }
    let total = OUTER_HEADER_BYTES
        .checked_add(blob.len())
        .ok_or(Error::BoundExceeded)?;
    if total > role.file_limit() {
        return Err(Error::BoundExceeded);
    }
    let mut file = Vec::new();
    file.try_reserve_exact(total)
        .map_err(|_| Error::BoundExceeded)?;
    file.extend_from_slice(&outer.encode());
    file.extend_from_slice(&blob);
    Ok(file)
}

fn build_inner(
    outer: OuterHeaderV1,
    prefix: InnerPrefixV1,
    key_material: &[u8],
    payload: &[u8],
    key: &DerivedKey,
) -> Result<SecretVec> {
    let outer_bytes = outer.encode();
    let prefix_bytes = prefix.encode();
    let tag = hmac_tag(
        key,
        &[
            ENVELOPE_DOMAIN,
            &outer_bytes,
            &prefix_bytes,
            key_material,
            payload,
        ],
    )?;
    let length = INNER_PREFIX_BYTES
        .checked_add(key_material.len())
        .and_then(|value| value.checked_add(payload.len()))
        .and_then(|value| value.checked_add(HMAC_BYTES))
        .ok_or(Error::BoundExceeded)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| Error::BoundExceeded)?;
    bytes.extend_from_slice(&prefix_bytes);
    bytes.extend_from_slice(key_material);
    bytes.extend_from_slice(payload);
    bytes.extend_from_slice(&tag);
    Ok(SecretVec::new(bytes))
}

fn unprotect_envelope(
    file: &[u8],
    expected_role: EnvelopeRole,
) -> Result<(OuterHeaderV1, SecretVec)> {
    let (outer, blob) = OuterHeaderV1::parse(file, expected_role)?;
    let inner = dpapi_unprotect(
        blob,
        &dpapi_entropy(outer.role, outer.session_id, outer.generation),
        outer.role.inner_limit(),
    )?;
    Ok((outer, inner))
}

fn parse_inner(inner: &[u8], expected_role: EnvelopeRole) -> Result<ParsedInner<'_>> {
    if inner.len() > expected_role.inner_limit() {
        return Err(Error::BoundExceeded);
    }
    let prefix = InnerPrefixV1::parse(inner)?;
    let key_end = INNER_PREFIX_BYTES
        .checked_add(usize::from(prefix.key_material_length))
        .ok_or(Error::InvalidEnvelope)?;
    let payload_end = key_end
        .checked_add(usize::try_from(prefix.payload_length).map_err(|_| Error::InvalidEnvelope)?)
        .ok_or(Error::InvalidEnvelope)?;
    let exact_end = payload_end
        .checked_add(HMAC_BYTES)
        .ok_or(Error::InvalidEnvelope)?;
    if exact_end != inner.len() {
        return Err(Error::InvalidEnvelope);
    }
    Ok(ParsedInner {
        prefix,
        prefix_bytes: &inner[..INNER_PREFIX_BYTES],
        key_material: &inner[INNER_PREFIX_BYTES..key_end],
        payload: &inner[key_end..payload_end],
        tag: &inner[payload_end..],
    })
}

fn verify_inner(outer: &OuterHeaderV1, parsed: &ParsedInner<'_>, key: &DerivedKey) -> Result<()> {
    let outer_bytes = outer.encode();
    hmac_verify(
        key,
        &[
            ENVELOPE_DOMAIN,
            &outer_bytes,
            parsed.prefix_bytes,
            parsed.key_material,
            parsed.payload,
        ],
        parsed.tag,
    )
}

fn compare_repeated(outer: &OuterHeaderV1, inner: &InnerPrefixV1) -> Result<()> {
    if outer.role != inner.role
        || outer.session_id != inner.session_id
        || outer.generation != inner.generation
    {
        return Err(Error::AuthenticationFailed);
    }
    Ok(())
}

fn dpapi_entropy(role: EnvelopeRole, session_id: SessionId, generation: u64) -> Vec<u8> {
    let mut entropy = Vec::with_capacity(DPAPI_ENTROPY_DOMAIN.len() + 1 + 2 + 16 + 8);
    entropy.extend_from_slice(DPAPI_ENTROPY_DOMAIN);
    entropy.push(role as u8);
    entropy.extend_from_slice(&ENVELOPE_VERSION.to_be_bytes());
    entropy.extend_from_slice(session_id.as_bytes());
    entropy.extend_from_slice(&generation.to_be_bytes());
    entropy
}

fn data_blob(bytes: &[u8]) -> Result<CRYPT_INTEGER_BLOB> {
    Ok(CRYPT_INTEGER_BLOB {
        cbData: u32::try_from(bytes.len()).map_err(|_| Error::BoundExceeded)?,
        pbData: bytes.as_ptr().cast_mut(),
    })
}

fn dpapi_protect(plaintext: &[u8], entropy: &[u8]) -> Result<Vec<u8>> {
    let input = data_blob(plaintext)?;
    let entropy = data_blob(entropy)?;
    let mut output = CRYPT_INTEGER_BLOB::default();
    // SAFETY: all input blobs reference live slices for their exact lengths;
    // output is initialized and released with LocalFree below. UI and machine
    // scope fallbacks are not requested.
    let protected = unsafe {
        CryptProtectData(
            &input,
            ptr::null(),
            &entropy,
            ptr::null(),
            ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };
    if protected == 0 {
        if !output.pbData.is_null() {
            // SAFETY: any non-null API output is LocalAlloc-owned even when
            // the call reports failure.
            let _ = unsafe { LocalFree(output.pbData.cast()) };
        }
        return Err(Error::DpapiFailed);
    }
    let result = copy_local_buffer(&output, usize::MAX);
    // SAFETY: DPAPI allocated this pointer with LocalAlloc.
    let _ = unsafe { LocalFree(output.pbData.cast()) };
    result
}

fn dpapi_unprotect(ciphertext: &[u8], entropy: &[u8], limit: usize) -> Result<SecretVec> {
    let input = data_blob(ciphertext)?;
    let entropy = data_blob(entropy)?;
    let mut description = ptr::null_mut();
    let mut output = CRYPT_INTEGER_BLOB::default();
    // SAFETY: input blobs reference live slices. Output and optional
    // description are released with LocalFree on every successful call.
    let unprotected = unsafe {
        CryptUnprotectData(
            &input,
            &mut description,
            &entropy,
            ptr::null(),
            ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };
    if unprotected == 0 {
        clear_and_free_blob(&mut output);
        if !description.is_null() {
            // SAFETY: any non-null DPAPI description is LocalAlloc-owned.
            let _ = unsafe { LocalFree(description.cast()) };
        }
        return Err(Error::DpapiFailed);
    }
    let result = copy_local_buffer(&output, limit).map(SecretVec::new);
    clear_and_free_blob(&mut output);
    if !description.is_null() {
        let _ = unsafe { LocalFree(description.cast()) };
    }
    result
}

fn clear_and_free_blob(blob: &mut CRYPT_INTEGER_BLOB) {
    if blob.pbData.is_null() {
        return;
    }
    let length = usize::try_from(blob.cbData).unwrap_or(0);
    // SAFETY: a non-null DPAPI output remains writable for cbData bytes until
    // LocalFree; clear it before release.
    let output_bytes = unsafe { slice::from_raw_parts_mut(blob.pbData, length) };
    secure_zero(output_bytes);
    // SAFETY: DPAPI allocated this pointer with LocalAlloc.
    let _ = unsafe { LocalFree(blob.pbData.cast()) };
    blob.pbData = ptr::null_mut();
    blob.cbData = 0;
}

fn copy_local_buffer(blob: &CRYPT_INTEGER_BLOB, limit: usize) -> Result<Vec<u8>> {
    let length = usize::try_from(blob.cbData).map_err(|_| Error::BoundExceeded)?;
    if length > limit || (length != 0 && blob.pbData.is_null()) {
        return Err(Error::BoundExceeded);
    }
    if length == 0 {
        return Ok(Vec::new());
    }
    let mut output = Vec::new();
    output
        .try_reserve_exact(length)
        .map_err(|_| Error::BoundExceeded)?;
    // SAFETY: DPAPI returned a live buffer for exactly cbData bytes.
    output.extend_from_slice(unsafe { slice::from_raw_parts(blob.pbData, length) });
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::roundtrip::schema::tests::{active_capsule, tombstone};
    use crate::roundtrip::token::ReviewProfile;

    fn mutate_dpapi_plaintext(protected: &[u8], mutate: impl FnOnce(&mut [u8])) -> Vec<u8> {
        let (outer, blob) =
            OuterHeaderV1::parse(protected, EnvelopeRole::Capsule).expect("parse outer");
        let entropy = dpapi_entropy(outer.role, outer.session_id, outer.generation);
        let mut inner = dpapi_unprotect(blob, &entropy, outer.role.inner_limit())
            .expect("unprotect test fixture");
        mutate(inner.as_mut_slice());
        let encrypted = dpapi_protect(inner.as_slice(), &entropy).expect("reprotect fixture");
        assert_eq!(encrypted.len(), blob.len());
        let mut output = outer.encode().to_vec();
        output.extend_from_slice(&encrypted);
        output
    }

    #[test]
    fn fixed_headers_have_exact_golden_bytes() {
        let outer = OuterHeaderV1 {
            role: EnvelopeRole::Capsule,
            session_id: SessionId::from_bytes([0x11; 16]),
            generation: 0x0102_0304_0506_0708,
            dpapi_blob_length: 0x1112_1314_1516_1718,
        };
        let bytes = outer.encode();
        assert_eq!(bytes.len(), 48);
        assert_eq!(&bytes[..16], b"SCRTDP1\0\x01\0\0\x01\0\x01\0\0");
        assert_eq!(
            &bytes[32..],
            &[1, 2, 3, 4, 5, 6, 7, 8, 17, 18, 19, 20, 21, 22, 23, 24]
        );

        let inner = InnerPrefixV1 {
            role: EnvelopeRole::Capsule,
            key_kind: KeyKind::SessionMaster,
            session_id: SessionId::from_bytes([0x11; 16]),
            generation: 1,
            previous_generation_tag: [0x22; 32],
            key_material_length: 32,
            payload_length: 0x0102_0304,
        }
        .encode();
        assert_eq!(inner.len(), 78);
        assert_eq!(&inner[..16], b"SCRTIN1\0\x01\x01\0\x01\0\x01\0\0");
        assert_eq!(&inner[72..], &[0, 32, 1, 2, 3, 4]);
    }

    #[test]
    fn deterministic_engine_v3_generation_inner_tag_is_exact() {
        let master = SessionMasterSecret::from_bytes([0x77; 32]);
        let capsule = active_capsule(1);
        let payload = capsule.encode_canonical().expect("v3 capsule payload");
        let schedule = KeySchedule::new(&master, capsule.session_id);
        let key = schedule
            .derive(KeyPurpose::CapsuleMac)
            .expect("capsule key");
        let outer = OuterHeaderV1 {
            role: EnvelopeRole::Capsule,
            session_id: capsule.session_id,
            generation: 1,
            dpapi_blob_length: 0,
        };
        let prefix = InnerPrefixV1 {
            role: EnvelopeRole::Capsule,
            key_kind: KeyKind::SessionMaster,
            session_id: capsule.session_id,
            generation: 1,
            previous_generation_tag: [0; 32],
            key_material_length: 32,
            payload_length: u32::try_from(payload.len()).expect("bounded capsule"),
        };
        let inner = build_inner(outer, prefix, master.expose(), &payload, &key)
            .expect("deterministic inner");
        let tag = &inner.as_slice()[inner.as_slice().len() - HMAC_BYTES..];
        assert_eq!(
            vector_hex(tag),
            "f35c7bd6988174fea7730bbae39f59303287cf2cfeeeaeb89eb9799ecc3d8975"
        );
    }

    #[test]
    fn authenticated_engine_v2_capsule_fixture_is_rejected_without_migration() {
        let master = SessionMasterSecret::from_bytes([0x77; 32]);
        let capsule = active_capsule(1);
        let mut payload = capsule.encode_canonical().expect("v3 capsule payload");
        replace_unique(
            &mut payload,
            b"safeclone-roundtrip-engine-v3",
            b"safeclone-roundtrip-engine-v2",
        );
        replace_unique(&mut payload, b"roundtrip-v3", b"roundtrip-v2");
        replace_unique(&mut payload, &[5, 3, 6], &[5, 1, 6]);
        let schedule = KeySchedule::new(&master, capsule.session_id);
        let key = schedule
            .derive(KeyPurpose::CapsuleMac)
            .expect("capsule key");
        let prefix = InnerPrefixV1 {
            role: EnvelopeRole::Capsule,
            key_kind: KeyKind::SessionMaster,
            session_id: capsule.session_id,
            generation: 1,
            previous_generation_tag: [0; 32],
            key_material_length: 32,
            payload_length: u32::try_from(payload.len()).expect("bounded legacy payload"),
        };
        let protected = protect_authenticated(
            EnvelopeRole::Capsule,
            capsule.session_id,
            1,
            prefix,
            master.expose(),
            &payload,
            &key,
        )
        .expect("authenticated legacy fixture");
        assert_eq!(
            unprotect_live_capsule(&protected, None).err(),
            Some(Error::InvalidSchema)
        );
    }

    fn replace_unique(bytes: &mut [u8], old: &[u8], new: &[u8]) {
        assert_eq!(old.len(), new.len(), "fixed-width mutation");
        let matches = bytes
            .windows(old.len())
            .enumerate()
            .filter_map(|(index, candidate)| (candidate == old).then_some(index))
            .collect::<Vec<_>>();
        assert_eq!(matches.len(), 1, "one fixed legacy field");
        bytes[matches[0]..matches[0] + old.len()].copy_from_slice(new);
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

    fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
        !needle.is_empty()
            && haystack
                .windows(needle.len())
                .any(|window| window == needle)
    }

    #[test]
    fn current_user_dpapi_live_manifest_and_tombstone_round_trip() {
        let context_canary = "RT2R-RELATIVE-CONTEXT-CANARY-6F02D9";
        let context_canary_utf16le = context_canary
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>();
        let master = SessionMasterSecret::from_bytes([0x77; 32]);
        let capsule = active_capsule(1);
        let protected = protect_initial_live_capsule(&master, &capsule).expect("protect live");
        let live = unprotect_live_capsule(&protected, None).expect("unprotect live");
        assert!(live.capsule() == &capsule);

        let manifest = b"\xa1\x01\x01";
        assert!(!contains_subslice(manifest, context_canary.as_bytes()));
        assert!(!contains_subslice(manifest, &context_canary_utf16le));
        let protected_manifest =
            protect_authenticated_manifest_bytes(&live, manifest).expect("protect manifest");
        assert_eq!(
            unprotect_authenticated_manifest_bytes(&live, &protected_manifest)
                .expect("unprotect manifest")
                .as_bytes(),
            manifest
        );

        let closed = tombstone(2);
        let closed_payload = closed.encode_canonical().expect("canonical tombstone");
        assert!(!contains_subslice(
            &closed_payload,
            context_canary.as_bytes()
        ));
        assert!(!contains_subslice(&closed_payload, &context_canary_utf16le));
        let protected_closed = protect_closed_tombstone(&live, &closed).expect("protect tombstone");
        assert!(
            unprotect_closed_tombstone(&live, &protected_closed)
                .expect("unprotect tombstone")
                .tombstone()
                == &closed
        );
    }

    #[test]
    fn corrupt_blob_wrong_entropy_and_structural_boundaries_fail_closed() {
        let master = SessionMasterSecret::from_bytes([0x77; 32]);
        let capsule = active_capsule(1);
        let protected = protect_initial_live_capsule(&master, &capsule).expect("protect live");
        for boundary in [0, 7, 8, 15, 16, 31, 32, 39, 40, 47, 48, protected.len() - 1] {
            assert!(unprotect_live_capsule(&protected[..boundary], None).is_err());
        }
        let mut corrupted = protected.clone();
        *corrupted.last_mut().expect("ciphertext byte") ^= 1;
        assert_eq!(
            unprotect_live_capsule(&corrupted, None).err(),
            Some(Error::DpapiFailed)
        );

        let mut extra = protected.clone();
        extra.push(0);
        assert_eq!(
            unprotect_live_capsule(&extra, None).err(),
            Some(Error::InvalidEnvelope)
        );
        for offset in [8usize, 9, 10, 12, 14, 16, 32, 40] {
            let mut outer_mutation = protected.clone();
            outer_mutation[offset] ^= 1;
            assert!(unprotect_live_capsule(&outer_mutation, None).is_err());
        }
        let mut length_plus_one = protected.clone();
        let declared = u64::from_be_bytes(length_plus_one[40..48].try_into().expect("length"));
        length_plus_one[40..48].copy_from_slice(&(declared + 1).to_be_bytes());
        assert_eq!(
            unprotect_live_capsule(&length_plus_one, None).err(),
            Some(Error::InvalidEnvelope)
        );

        let (outer, blob) =
            OuterHeaderV1::parse(&protected, EnvelopeRole::Capsule).expect("parse outer");
        assert_eq!(
            dpapi_unprotect(
                blob,
                &dpapi_entropy(outer.role, outer.session_id, outer.generation + 1),
                outer.role.inner_limit(),
            )
            .err(),
            Some(Error::DpapiFailed)
        );
    }

    #[test]
    fn application_envelope_detects_prefix_key_payload_and_tag_corruption() {
        let master = SessionMasterSecret::from_bytes([0x77; 32]);
        let protected =
            protect_initial_live_capsule(&master, &active_capsule(1)).expect("protect live");
        for offset in [0usize, 9, INNER_PREFIX_BYTES, INNER_PREFIX_BYTES + 32, {
            let (outer, blob) =
                OuterHeaderV1::parse(&protected, EnvelopeRole::Capsule).expect("outer");
            let inner = dpapi_unprotect(
                blob,
                &dpapi_entropy(outer.role, outer.session_id, outer.generation),
                outer.role.inner_limit(),
            )
            .expect("inner");
            inner.as_slice().len() - 1
        }] {
            let mutated = mutate_dpapi_plaintext(&protected, |inner| inner[offset] ^= 1);
            assert!(
                unprotect_live_capsule(&mutated, None).is_err(),
                "offset={offset}"
            );
        }
    }

    #[test]
    fn authenticated_but_invalid_cbor_is_rejected_after_hmac() {
        let master = SessionMasterSecret::from_bytes([0x77; 32]);
        let protected =
            protect_initial_live_capsule(&master, &active_capsule(1)).expect("protect live");
        let (outer, blob) = OuterHeaderV1::parse(&protected, EnvelopeRole::Capsule).expect("outer");
        let entropy = dpapi_entropy(outer.role, outer.session_id, outer.generation);
        let inner = dpapi_unprotect(blob, &entropy, outer.role.inner_limit()).expect("inner");
        let parsed = parse_inner(inner.as_slice(), EnvelopeRole::Capsule).expect("parse inner");
        let mut payload = parsed.payload.to_vec();
        payload[0] = 0xff;
        let master_bytes: [u8; 32] = parsed.key_material.try_into().expect("master bytes");
        let fixture_master = SessionMasterSecret::from_bytes(master_bytes);
        let key = KeySchedule::new(&fixture_master, outer.session_id)
            .derive(KeyPurpose::CapsuleMac)
            .expect("capsule key");
        let rebuilt = build_inner(
            outer,
            parsed.prefix,
            fixture_master.expose(),
            &payload,
            &key,
        )
        .expect("rebuild authenticated inner");
        let encrypted = dpapi_protect(rebuilt.as_slice(), &entropy).expect("reprotect");
        assert_eq!(encrypted.len(), blob.len());
        let mut invalid = outer.encode().to_vec();
        invalid.extend_from_slice(&encrypted);
        assert_eq!(
            unprotect_live_capsule(&invalid, None).err(),
            Some(Error::InvalidSchema)
        );
    }

    #[test]
    fn machine_scope_fallback_is_absent_from_source() {
        let source = include_str!("dpapi.rs");
        let forbidden = ["CRYPTPROTECT_", "LOCAL_MACHINE"].concat();
        assert!(!source.contains(&forbidden));
    }

    #[test]
    fn tombstone_requires_prior_derived_key_and_tag() {
        let first_master = SessionMasterSecret::from_bytes([0x77; 32]);
        let second_master = SessionMasterSecret::from_bytes([0x78; 32]);
        let capsule = active_capsule(1);
        let first = unprotect_live_capsule(
            &protect_initial_live_capsule(&first_master, &capsule).expect("first protect"),
            None,
        )
        .expect("first live");
        let second = unprotect_live_capsule(
            &protect_initial_live_capsule(&second_master, &capsule).expect("second protect"),
            None,
        )
        .expect("second live");
        let protected = protect_closed_tombstone(&first, &tombstone(2)).expect("close");
        assert_eq!(
            unprotect_closed_tombstone(&second, &protected).err(),
            Some(Error::AuthenticationFailed)
        );

        let mut alternate_capsule = capsule;
        alternate_capsule.orphan_count_at_commit = 1;
        let alternate = unprotect_live_capsule(
            &protect_initial_live_capsule(&first_master, &alternate_capsule)
                .expect("alternate protect"),
            None,
        )
        .expect("alternate live");
        assert_eq!(
            unprotect_closed_tombstone(&alternate, &protected).err(),
            Some(Error::AuthenticationFailed)
        );

        let payload = tombstone(2).encode_canonical().expect("tombstone CBOR");
        let arbitrary_key = first
            .key_schedule()
            .derive(KeyPurpose::TokenId)
            .expect("arbitrary self key");
        let prefix = InnerPrefixV1 {
            role: EnvelopeRole::Capsule,
            key_kind: KeyKind::TombstoneMacKey,
            session_id: first.capsule.session_id,
            generation: 2,
            previous_generation_tag: first.tag,
            key_material_length: 32,
            payload_length: u32::try_from(payload.len()).expect("bounded payload"),
        };
        let self_authenticated = protect_authenticated(
            EnvelopeRole::Capsule,
            first.capsule.session_id,
            2,
            prefix,
            arbitrary_key.expose(),
            &payload,
            &arbitrary_key,
        )
        .expect("self-authenticated fixture");
        assert_eq!(
            unprotect_closed_tombstone(&first, &self_authenticated).err(),
            Some(Error::AuthenticationFailed)
        );

        let (outer, blob) = OuterHeaderV1::parse(&protected, EnvelopeRole::Capsule).expect("outer");
        let inner = dpapi_unprotect(
            blob,
            &dpapi_entropy(outer.role, outer.session_id, outer.generation),
            outer.role.inner_limit(),
        )
        .expect("tombstone inner");
        let parsed = parse_inner(inner.as_slice(), EnvelopeRole::Capsule).expect("inner prefix");
        assert_eq!(parsed.prefix.key_kind, KeyKind::TombstoneMacKey);
        assert!(!constant_time_equal(
            parsed.key_material,
            first.master().expose()
        ));
    }

    #[test]
    fn live_chain_rejects_unsupported_ruleset_and_immutable_field_drift() {
        let master = SessionMasterSecret::from_bytes([0x77; 32]);
        let mut unsupported = active_capsule(1);
        unsupported.ruleset_id =
            "ruleset-sha256-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                .to_owned();
        assert_eq!(
            protect_initial_live_capsule(&master, &unsupported).err(),
            Some(Error::InvalidState)
        );

        let first_capsule = active_capsule(1);
        let first = unprotect_live_capsule(
            &protect_initial_live_capsule(&master, &first_capsule).expect("first protect"),
            None,
        )
        .expect("first live");
        let mut drifted = active_capsule(2);
        drifted.original_tree_commitment = [0x23; 32];
        assert_eq!(
            protect_next_live_capsule(&first, &drifted).err(),
            Some(Error::InvalidState)
        );

        let bypass =
            protect_live(first.master(), &drifted, first.tag).expect("authenticated drift fixture");
        assert_eq!(
            unprotect_live_capsule(&bypass, Some(&first)).err(),
            Some(Error::InvalidState)
        );

        let mut mismatched_close = tombstone(2);
        mismatched_close.review_profile = ReviewProfile::StrictTokenFilesV2;
        assert_eq!(
            protect_closed_tombstone(&first, &mismatched_close).err(),
            Some(Error::InvalidState)
        );
    }

    #[test]
    fn errors_and_secret_debug_are_raw_free() {
        let canary = b"RT1-PRIVATE-CANARY";
        let private = PrivateBytes(SecretVec::new(canary.to_vec()));
        assert!(!format!("{private:?}").contains("CANARY"));
        assert!(!format!("{:?}", Error::DpapiFailed).contains("CANARY"));
    }
}
