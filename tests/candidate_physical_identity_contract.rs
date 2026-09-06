use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

const IDENTITY_SUITE_V1: u16 = 1;
const VOLUME_DOMAIN: &str = "safeclone/rt1/candidate-volume-identity-v1";
const ROOT_DOMAIN: &str = "safeclone/rt1/candidate-root-file-id-v1";

#[derive(Clone, Copy)]
struct SyntheticIdentity {
    session_id: [u8; 16],
    apply_id: [u8; 16],
    volume_guid: [u8; 16],
    volume_serial_number: u64,
    file_id: [u8; 16],
}

fn canonical_bytes(bytes: &mut Vec<u8>, value: &[u8]) {
    bytes.extend_from_slice(
        &u32::try_from(value.len())
            .expect("model field length fits u32")
            .to_be_bytes(),
    );
    bytes.extend_from_slice(value);
}

fn identity_preimage(domain: &str, identity: &SyntheticIdentity, root: bool) -> Vec<u8> {
    let mut bytes = Vec::new();
    canonical_bytes(&mut bytes, domain.as_bytes());
    bytes.extend_from_slice(&IDENTITY_SUITE_V1.to_be_bytes());
    canonical_bytes(&mut bytes, &identity.session_id);
    canonical_bytes(&mut bytes, &identity.apply_id);
    canonical_bytes(&mut bytes, &identity.volume_guid);
    bytes.extend_from_slice(&identity.volume_serial_number.to_le_bytes());
    if root {
        canonical_bytes(&mut bytes, &identity.file_id);
    }
    bytes
}

fn hmac_sha256(key: &[u8; 32], preimage: &[u8]) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("fixed HMAC key");
    mac.update(preimage);
    mac.finalize().into_bytes().into()
}

fn volume_commitment(key: &[u8; 32], identity: &SyntheticIdentity) -> [u8; 32] {
    hmac_sha256(key, &identity_preimage(VOLUME_DOMAIN, identity, false))
}

fn root_commitment(key: &[u8; 32], identity: &SyntheticIdentity) -> [u8; 32] {
    hmac_sha256(key, &identity_preimage(ROOT_DOMAIN, identity, true))
}

fn parse_volume_guid_path(source: &str) -> Option<[u8; 16]> {
    let source = source.as_bytes();
    if source.len() != 49
        || &source[..11] != br"\\?\Volume{"
        || source[47] != b'}'
        || source[48] != b'\\'
    {
        return None;
    }

    let mut digits = [0u8; 32];
    let mut digit_count = 0usize;
    for (index, byte) in source[11..47].iter().copied().enumerate() {
        if matches!(index, 8 | 13 | 18 | 23) {
            if byte != b'-' {
                return None;
            }
            continue;
        }
        if !byte.is_ascii_hexdigit() {
            return None;
        }
        digits[digit_count] = byte;
        digit_count += 1;
    }
    if digit_count != digits.len() {
        return None;
    }

    let mut canonical = [0u8; 16];
    for (target, pair) in canonical.iter_mut().zip(digits.chunks_exact(2)) {
        *target = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
    }
    Some(canonical)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn decode_hex(source: &str) -> Vec<u8> {
    assert!(source.len().is_multiple_of(2), "even hexadecimal length");
    source
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            (hex_nibble(pair[0]).expect("valid hexadecimal") << 4)
                | hex_nibble(pair[1]).expect("valid hexadecimal")
        })
        .collect()
}

fn vector_key() -> [u8; 32] {
    std::array::from_fn(|index| u8::try_from(index).expect("key index fits u8"))
}

fn vector_identity() -> SyntheticIdentity {
    SyntheticIdentity {
        session_id: std::array::from_fn(|index| {
            0x10 + u8::try_from(index).expect("session index fits u8")
        }),
        apply_id: std::array::from_fn(|index| {
            0xA0 + u8::try_from(index).expect("apply index fits u8")
        }),
        volume_guid: parse_volume_guid_path(
            "\\\\?\\Volume{00112233-4455-6677-8899-aabbccddeeff}\\",
        )
        .expect("valid vector GUID path"),
        volume_serial_number: 0x0123_4567_89AB_CDEF,
        file_id: std::array::from_fn(|index| {
            0xF0 + u8::try_from(index).expect("file-id index fits u8")
        }),
    }
}

#[test]
fn candidate_physical_identity_v1_exact_golden_vectors_are_frozen() {
    let key = vector_key();
    let identity = vector_identity();

    let volume_preimage = decode_hex(concat!(
        "0000002A73616665636C6F6E652F7274312F63616E6469646174652D766F6C756D",
        "652D6964656E746974792D7631000100000010101112131415161718191A1B1C1D",
        "1E1F00000010A0A1A2A3A4A5A6A7A8A9AAABACADAEAF00000010001122334455",
        "66778899AABBCCDDEEFFEFCDAB8967452301"
    ));
    let root_preimage = decode_hex(concat!(
        "0000002773616665636C6F6E652F7274312F63616E6469646174652D726F6F742D",
        "66696C652D69642D7631000100000010101112131415161718191A1B1C1D1E1F00",
        "000010A0A1A2A3A4A5A6A7A8A9AAABACADAEAF0000001000112233445566778899",
        "AABBCCDDEEFFEFCDAB896745230100000010F0F1F2F3F4F5F6F7F8F9FAFBFCFD",
        "FEFF"
    ));
    assert_eq!(
        identity_preimage(VOLUME_DOMAIN, &identity, false),
        volume_preimage
    );
    assert_eq!(
        identity_preimage(ROOT_DOMAIN, &identity, true),
        root_preimage
    );
    assert_eq!(
        volume_commitment(&key, &identity).as_slice(),
        decode_hex("3D4FE3C74D855FACED78C09CDDAFF16505A2FA1106C046628068A2FAA1AE4591")
    );
    assert_eq!(
        root_commitment(&key, &identity).as_slice(),
        decode_hex("84EAE858331665A49F3CD6528D6CBCF40E8DC1CD92300038EBE9DE34111EB9A6")
    );
}

#[test]
fn candidate_physical_identity_v1_role_and_transaction_bindings_are_distinct() {
    let key = vector_key();
    let base = vector_identity();
    let base_volume = volume_commitment(&key, &base);
    let base_root = root_commitment(&key, &base);

    assert_eq!(base_volume, volume_commitment(&key, &base));
    assert_eq!(base_root, root_commitment(&key, &base));
    assert_ne!(base_volume, base_root);

    let mut changed = base;
    changed.apply_id[0] ^= 1;
    assert_ne!(base_volume, volume_commitment(&key, &changed));
    assert_ne!(base_root, root_commitment(&key, &changed));

    changed = base;
    changed.session_id[0] ^= 1;
    assert_ne!(base_volume, volume_commitment(&key, &changed));
    assert_ne!(base_root, root_commitment(&key, &changed));

    changed = base;
    changed.volume_guid[15] ^= 1;
    assert_ne!(base_volume, volume_commitment(&key, &changed));
    assert_ne!(base_root, root_commitment(&key, &changed));

    changed = base;
    changed.volume_serial_number ^= 1;
    assert_ne!(base_volume, volume_commitment(&key, &changed));
    assert_ne!(base_root, root_commitment(&key, &changed));

    changed = base;
    changed.file_id[0] ^= 1;
    assert_eq!(base_volume, volume_commitment(&key, &changed));
    assert_ne!(base_root, root_commitment(&key, &changed));

    let same_volume_different_root = changed;
    assert_eq!(
        base_volume,
        volume_commitment(&key, &same_volume_different_root)
    );
    assert_ne!(
        base_root,
        root_commitment(&key, &same_volume_different_root)
    );

    let mut different_volume_same_file = base;
    different_volume_same_file.volume_guid[0] ^= 1;
    assert_ne!(
        base_volume,
        volume_commitment(&key, &different_volume_same_file)
    );
    assert_ne!(
        base_root,
        root_commitment(&key, &different_volume_same_file)
    );
}

#[test]
fn textual_uuid_order_is_canonical_and_windows_guid_memory_order_is_not() {
    let lower = parse_volume_guid_path("\\\\?\\Volume{00112233-4455-6677-8899-aabbccddeeff}\\")
        .expect("lowercase GUID path");
    let upper = parse_volume_guid_path("\\\\?\\Volume{00112233-4455-6677-8899-AABBCCDDEEFF}\\")
        .expect("uppercase GUID path");
    assert_eq!(lower, upper);
    assert_eq!(
        lower,
        [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
            0xEE, 0xFF,
        ]
    );

    let windows_guid_memory_order = [
        0x33, 0x22, 0x11, 0x00, 0x55, 0x44, 0x77, 0x66, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
        0xFF,
    ];
    assert_ne!(lower, windows_guid_memory_order);

    let key = vector_key();
    let canonical = vector_identity();
    let mut memory_reinterpreted = canonical;
    memory_reinterpreted.volume_guid = windows_guid_memory_order;
    assert_ne!(
        volume_commitment(&key, &canonical),
        volume_commitment(&key, &memory_reinterpreted)
    );
    assert_ne!(
        root_commitment(&key, &canonical),
        root_commitment(&key, &memory_reinterpreted)
    );

    assert!(
        parse_volume_guid_path("\\\\?\\Volume{00112233-4455-6677-8899-aabbccddeeff}").is_none()
    );
    assert!(
        parse_volume_guid_path("\\\\?\\Volume{001122334455-6677-8899-aabbccddeeff}\\").is_none()
    );
}
