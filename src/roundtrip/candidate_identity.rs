//! Candidate physical-identity commitments.

use super::canonical::CanonicalWriter;
use super::crypto::{constant_time_equal, hmac_tag, KeyPurpose, KeySchedule};
use super::observe::CandidatePhysicalSource;
use super::{Error, Result};

const IDENTITY_SUITE: u16 = 1;
const MAX_PREIMAGE_BYTES: usize = 256;
const VOLUME_DOMAIN: &str = "safeclone/rt1/candidate-volume-identity-v1";
const ROOT_DOMAIN: &str = "safeclone/rt1/candidate-root-file-id-v1";

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) struct CandidatePhysicalCommitments {
    pub(crate) volume: [u8; 32],
    pub(crate) root: [u8; 32],
}

pub(super) fn derive(
    schedule: &KeySchedule<'_>,
    apply_id: [u8; 16],
    source: &CandidatePhysicalSource,
) -> Result<CandidatePhysicalCommitments> {
    let key = schedule.derive(KeyPurpose::TreeCommit)?;
    derive_with_key(schedule, apply_id, source, &key)
}

fn derive_with_key(
    schedule: &KeySchedule<'_>,
    apply_id: [u8; 16],
    source: &CandidatePhysicalSource,
    key: &super::crypto::DerivedKey,
) -> Result<CandidatePhysicalCommitments> {
    let volume = preimage(VOLUME_DOMAIN, schedule, apply_id, source, None)?;
    let root = preimage(
        ROOT_DOMAIN,
        schedule,
        apply_id,
        source,
        Some(source.root_file_id),
    )?;
    Ok(CandidatePhysicalCommitments {
        volume: hmac_tag(key, &[&volume])?,
        root: hmac_tag(key, &[&root])?,
    })
}

pub(super) fn verify(
    actual: CandidatePhysicalCommitments,
    expected_volume: &[u8; 32],
    expected_root: &[u8; 32],
) -> Result<()> {
    if !constant_time_equal(&actual.volume, expected_volume) {
        return Err(Error::CandidateVolumeIdentityMismatch);
    }
    if !constant_time_equal(&actual.root, expected_root) {
        return Err(Error::CandidateRootIdentityMismatch);
    }
    Ok(())
}

fn preimage(
    domain: &str,
    schedule: &KeySchedule<'_>,
    apply_id: [u8; 16],
    source: &CandidatePhysicalSource,
    file_id: Option<[u8; 16]>,
) -> Result<Vec<u8>> {
    let mut writer = CanonicalWriter::new(domain, MAX_PREIMAGE_BYTES)?;
    writer.u16(IDENTITY_SUITE)?;
    writer.bytes(schedule.session_id().as_bytes())?;
    writer.bytes(&apply_id)?;
    writer.bytes(&source.volume_guid)?;
    writer.u64_le(source.volume_serial_number)?;
    if let Some(file_id) = file_id {
        writer.bytes(&file_id)?;
    }
    Ok(writer.finish())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::roundtrip::crypto::{SessionId, SessionMasterSecret};

    fn decode_hex<const N: usize>(value: &str) -> [u8; N] {
        assert_eq!(value.len(), N * 2);
        let mut output = [0u8; N];
        for (index, byte) in output.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).expect("hex");
        }
        output
    }

    fn vector() -> (
        SessionMasterSecret,
        SessionId,
        [u8; 16],
        CandidatePhysicalSource,
    ) {
        (
            SessionMasterSecret::from_bytes(decode_hex(
                "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
            )),
            SessionId::from_bytes(decode_hex("101112131415161718191A1B1C1D1E1F")),
            decode_hex("A0A1A2A3A4A5A6A7A8A9AAABACADAEAF"),
            CandidatePhysicalSource {
                volume_guid: decode_hex("00112233445566778899AABBCCDDEEFF"),
                volume_serial_number: 0x0123_4567_89ab_cdef,
                root_file_id: decode_hex("F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF"),
            },
        )
    }

    #[test]
    fn physical_identity_golden_vectors_are_production_exact() {
        let (master, session_id, apply_id, source) = vector();
        let schedule = KeySchedule::new(&master, session_id);
        let key = super::super::crypto::DerivedKey::from_test_bytes(decode_hex(
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
        ));
        let commitments =
            derive_with_key(&schedule, apply_id, &source, &key).expect("identity commitments");
        assert_eq!(
            commitments.volume,
            decode_hex("3D4FE3C74D855FACED78C09CDDAFF16505A2FA1106C046628068A2FAA1AE4591")
        );
        assert_eq!(
            commitments.root,
            decode_hex("84EAE858331665A49F3CD6528D6CBCF40E8DC1CD92300038EBE9DE34111EB9A6")
        );
        assert_ne!(commitments.volume, commitments.root);
    }

    #[test]
    fn every_authority_role_has_the_accepted_change_semantics() {
        let (master, session_id, apply_id, source) = vector();
        let schedule = KeySchedule::new(&master, session_id);
        let baseline = derive(&schedule, apply_id, &source).expect("baseline");

        let mut changed_apply = apply_id;
        changed_apply[0] ^= 1;
        let apply = derive(&schedule, changed_apply, &source).expect("apply");
        assert_ne!(baseline.volume, apply.volume);
        assert_ne!(baseline.root, apply.root);

        let other_schedule = KeySchedule::new(
            &master,
            SessionId::from_bytes(decode_hex("111112131415161718191A1B1C1D1E1F")),
        );
        let session = derive(&other_schedule, apply_id, &source).expect("session");
        assert_ne!(baseline.volume, session.volume);
        assert_ne!(baseline.root, session.root);

        let mut changed_guid = CandidatePhysicalSource { ..source };
        changed_guid.volume_guid[0] ^= 1;
        let guid = derive(&schedule, apply_id, &changed_guid).expect("guid");
        assert_ne!(baseline.volume, guid.volume);
        assert_ne!(baseline.root, guid.root);

        let changed_serial = CandidatePhysicalSource {
            volume_serial_number: source.volume_serial_number ^ 1,
            ..source
        };
        let serial = derive(&schedule, apply_id, &changed_serial).expect("serial");
        assert_ne!(baseline.volume, serial.volume);
        assert_ne!(baseline.root, serial.root);

        let mut changed_file = CandidatePhysicalSource { ..source };
        changed_file.root_file_id[0] ^= 1;
        let file = derive(&schedule, apply_id, &changed_file).expect("file");
        assert_eq!(baseline.volume, file.volume);
        assert_ne!(baseline.root, file.root);
    }

    #[test]
    fn mismatches_are_role_specific_constant_time_and_raw_free() {
        let (master, session_id, apply_id, source) = vector();
        let schedule = KeySchedule::new(&master, session_id);
        let actual = derive(&schedule, apply_id, &source).expect("actual identity");
        let mut wrong_volume = actual.volume;
        wrong_volume[0] ^= 1;
        assert_eq!(
            verify(actual, &wrong_volume, &actual.root),
            Err(Error::CandidateVolumeIdentityMismatch)
        );
        let mut wrong_root = actual.root;
        wrong_root[0] ^= 1;
        assert_eq!(
            verify(actual, &actual.volume, &wrong_root),
            Err(Error::CandidateRootIdentityMismatch)
        );
        for error in [
            Error::CandidateVolumeIdentityMismatch,
            Error::CandidateRootIdentityMismatch,
        ] {
            let rendered = format!("{error:?} {error}");
            assert!(!rendered.contains("00112233"));
            assert!(!rendered.contains("01234567"));
            assert!(!rendered.contains("F0F1F2F3"));
        }
    }
}
