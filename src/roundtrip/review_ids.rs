//! Session-local opaque entry and anchor identifiers shared by review/approval.

use super::anchor::{PROTECTED_ANCHOR_VERSION, RELATIVE_CONTEXT_VERSION};
use super::baseline::StreamEncoder;
use super::crypto::{leftmost_16, KeyPurpose, KeySchedule};
use super::token::TokenCategory;
use super::{Error, Result};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReviewEntryKind {
    File,
    Directory,
}

fn entry_kind_code(kind: ReviewEntryKind) -> u8 {
    match kind {
        ReviewEntryKind::File => 1,
        ReviewEntryKind::Directory => 2,
    }
}

pub(crate) fn baseline_entry_id(
    schedule: &KeySchedule<'_>,
    original_tree_commitment: &[u8; 32],
    kind: ReviewEntryKind,
    canonical_original_relative_path: &[u8],
) -> Result<[u8; 16]> {
    if canonical_original_relative_path.is_empty() {
        return Err(Error::InvalidCanonicalInput);
    }
    let domain = match kind {
        ReviewEntryKind::File => b"safeclone/rt1/file-id".as_slice(),
        ReviewEntryKind::Directory => b"safeclone/rt1/directory-id".as_slice(),
    };
    let mut output = StreamEncoder::new(schedule, KeyPurpose::EventId, domain)?;
    output.bytes(schedule.session_id().as_bytes())?;
    output.bytes(original_tree_commitment)?;
    output.u8(entry_kind_code(kind));
    output.bytes(canonical_original_relative_path)?;
    Ok(leftmost_16(&output.finish()))
}

pub(crate) fn new_entry_id(
    schedule: &KeySchedule<'_>,
    review_id: &[u8; 16],
    kind: ReviewEntryKind,
    canonical_edited_safe_path: &[u8],
) -> Result<[u8; 16]> {
    if canonical_edited_safe_path.is_empty() {
        return Err(Error::InvalidCanonicalInput);
    }
    let mut output =
        StreamEncoder::new(schedule, KeyPurpose::EventId, b"safeclone/rt1/new-entry-id")?;
    output.bytes(schedule.session_id().as_bytes())?;
    output.bytes(review_id)?;
    output.u8(entry_kind_code(kind));
    output.bytes(canonical_edited_safe_path)?;
    Ok(leftmost_16(&output.finish()))
}

pub(crate) fn content_anchor_id(
    schedule: &KeySchedule<'_>,
    selected_radius: u8,
    final_anchor_commitment: &[u8; 32],
) -> Result<[u8; 16]> {
    if selected_radius == 0 {
        return Err(Error::InvalidCanonicalInput);
    }
    let mut output = StreamEncoder::new(
        schedule,
        KeyPurpose::AnchorCommit,
        b"safeclone/rt1/content-exact-context-v2-anchor-id",
    )?;
    output.u8(PROTECTED_ANCHOR_VERSION);
    output.u8(RELATIVE_CONTEXT_VERSION);
    output.u8(selected_radius);
    output.bytes(final_anchor_commitment)?;
    Ok(leftmost_16(&output.finish()))
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn path_anchor_id(
    schedule: &KeySchedule<'_>,
    original_tree_commitment: &[u8; 32],
    owning_entry_id: &[u8; 16],
    canonical_original_relative_path: &[u8],
    component_index: u32,
    token_start: u64,
    token_end: u64,
    oid: &[u8; 16],
    category: TokenCategory,
    exact_path_anchor_commitment: &[u8; 32],
) -> Result<[u8; 16]> {
    if canonical_original_relative_path.is_empty() || token_start >= token_end {
        return Err(Error::InvalidCanonicalInput);
    }
    let mut output = StreamEncoder::new(
        schedule,
        KeyPurpose::AnchorCommit,
        b"safeclone/rt1/path-component-v1-anchor-id",
    )?;
    output.bytes(original_tree_commitment)?;
    output.bytes(owning_entry_id)?;
    output.bytes(canonical_original_relative_path)?;
    output.u32(component_index);
    output.u64(token_start);
    output.u64(token_end);
    output.bytes(oid)?;
    output.u8(category as u8);
    output.bytes(exact_path_anchor_commitment)?;
    Ok(leftmost_16(&output.finish()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::roundtrip::crypto::{SessionId, SessionMasterSecret};
    use crate::roundtrip::token::ReviewProfile;

    #[test]
    fn entry_anchor_and_session_domains_are_separated() {
        let first_master = SessionMasterSecret::from_bytes([0x11; 32]);
        let second_master = SessionMasterSecret::from_bytes([0x12; 32]);
        let first = KeySchedule::new(&first_master, SessionId::from_bytes([0x21; 16]));
        let replay = KeySchedule::new(&first_master, SessionId::from_bytes([0x21; 16]));
        let other = KeySchedule::new(&second_master, SessionId::from_bytes([0x22; 16]));
        let original = [0x31; 32];
        let file =
            baseline_entry_id(&first, &original, ReviewEntryKind::File, b"a.txt").expect("file id");
        assert_eq!(
            file,
            baseline_entry_id(&replay, &original, ReviewEntryKind::File, b"a.txt")
                .expect("replay file id")
        );
        assert_ne!(
            file,
            baseline_entry_id(&other, &original, ReviewEntryKind::File, b"a.txt")
                .expect("other session")
        );
        assert_ne!(
            file,
            baseline_entry_id(&first, &original, ReviewEntryKind::Directory, b"a.txt")
                .expect("directory id")
        );
        assert_ne!(
            file,
            baseline_entry_id(&first, &original, ReviewEntryKind::File, b"b.txt")
                .expect("other path")
        );

        let review = [0x41; 16];
        let new_file =
            new_entry_id(&first, &review, ReviewEntryKind::File, b"new.txt").expect("new entry ID");
        assert_eq!(
            new_file,
            new_entry_id(&replay, &review, ReviewEntryKind::File, b"new.txt")
                .expect("new entry replay")
        );
        assert_ne!(
            new_file,
            new_entry_id(&first, &[0x42; 16], ReviewEntryKind::File, b"new.txt")
                .expect("new entry changed review")
        );
        assert_ne!(
            new_file,
            new_entry_id(&first, &review, ReviewEntryKind::File, b"moved.txt")
                .expect("new entry changed path")
        );
        assert_ne!(
            new_file,
            new_entry_id(&first, &review, ReviewEntryKind::Directory, b"new.txt")
                .expect("new entry changed kind")
        );

        let anchor = content_anchor_id(&first, 2, &[0x51; 32]).expect("content anchor ID");
        assert_eq!(
            anchor,
            content_anchor_id(&replay, 2, &[0x51; 32]).expect("content anchor replay")
        );
        assert_ne!(
            anchor,
            content_anchor_id(&first, 3, &[0x51; 32]).expect("changed radius")
        );
        assert_ne!(
            anchor,
            content_anchor_id(&first, 2, &[0x52; 32]).expect("changed exact authority")
        );
        assert_ne!(
            anchor,
            content_anchor_id(&other, 2, &[0x51; 32]).expect("cross-session anchor")
        );

        let path_anchor = path_anchor_id(
            &first,
            &original,
            &file,
            b"a.txt",
            0,
            1,
            5,
            &[0x61; 16],
            TokenCategory::Secret,
            &[0x62; 32],
        )
        .expect("path anchor ID");
        assert_eq!(
            path_anchor,
            path_anchor_id(
                &replay,
                &original,
                &file,
                b"a.txt",
                0,
                1,
                5,
                &[0x61; 16],
                TokenCategory::Secret,
                &[0x62; 32],
            )
            .expect("path anchor replay")
        );
        for changed in [
            path_anchor_id(
                &first,
                &original,
                &file,
                b"b.txt",
                0,
                1,
                5,
                &[0x61; 16],
                TokenCategory::Secret,
                &[0x62; 32],
            )
            .expect("path changed"),
            path_anchor_id(
                &first,
                &original,
                &file,
                b"a.txt",
                1,
                1,
                5,
                &[0x61; 16],
                TokenCategory::Secret,
                &[0x62; 32],
            )
            .expect("component changed"),
            path_anchor_id(
                &first,
                &original,
                &file,
                b"a.txt",
                0,
                2,
                5,
                &[0x61; 16],
                TokenCategory::Secret,
                &[0x62; 32],
            )
            .expect("span changed"),
            path_anchor_id(
                &first,
                &original,
                &file,
                b"a.txt",
                0,
                1,
                5,
                &[0x63; 16],
                TokenCategory::Secret,
                &[0x62; 32],
            )
            .expect("OID changed"),
            path_anchor_id(
                &first,
                &original,
                &file,
                b"a.txt",
                0,
                1,
                5,
                &[0x61; 16],
                TokenCategory::Email,
                &[0x62; 32],
            )
            .expect("category changed"),
            path_anchor_id(
                &other,
                &original,
                &file,
                b"a.txt",
                0,
                1,
                5,
                &[0x61; 16],
                TokenCategory::Secret,
                &[0x62; 32],
            )
            .expect("path anchor cross-session"),
        ] {
            assert_ne!(path_anchor, changed);
        }

        let approvals = crate::roundtrip::approval::empty_review_approval_set(
            &first,
            review,
            ReviewProfile::StandardV2,
            crate::roundtrip::ruleset::ruleset_id(),
        )
        .expect("fresh empty review approval set");
        assert_eq!(approvals.review_id, Some(review));
        assert!(approvals.records.is_empty());
        assert_ne!(approvals.approval_set_tag, [0; 32]);
    }
}
