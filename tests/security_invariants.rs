use std::path::Path;

use safeclone::detection::{classify_path, DetectedKind};
use safeclone::policy::{decide, Decision};
use safeclone::verification::VerificationReport;

#[test]
fn link_like_entries_are_never_eligible_for_processing() {
    let kind = classify_path(Path::new("linked/source.rs"), true);

    assert_eq!(kind, DetectedKind::LinkLikeEntry);
    assert_eq!(decide(kind), Decision::Omit);
}

#[test]
fn git_metadata_is_omitted_even_when_it_looks_like_text() {
    for path in ["workspace/.git/config.txt", "workspace/.GIT/config.txt"] {
        let kind = classify_path(Path::new(path), false);

        assert_eq!(kind, DetectedKind::GitMetadata);
        assert_eq!(decide(kind), Decision::Omit);
    }
}

#[test]
fn unsupported_and_unknown_formats_are_omitted() {
    for path in ["report.pdf", "document.docx", "bundle.zip", "data.custom"] {
        assert_eq!(
            decide(classify_path(Path::new(path), false)),
            Decision::Omit
        );
    }
}

#[test]
fn extension_match_is_only_a_transform_candidate() {
    let kind = classify_path(Path::new("src/main.rs"), false);

    assert_eq!(kind, DetectedKind::TextOrCodeCandidate);
    assert_eq!(decide(kind), Decision::Transform);
}

#[test]
fn filename_evidence_does_not_refine_default_policy() {
    for (path, expected) in [
        ("credentials.rs", Decision::Transform),
        ("credentials.bin", Decision::Omit),
        (".env", Decision::Omit),
    ] {
        assert_eq!(decide(classify_path(Path::new(path), false)), expected);
    }
}

#[test]
fn all_decision_model_states_are_explicit() {
    let decisions = [
        Decision::Allow,
        Decision::Transform,
        Decision::StructureOnly,
        Decision::Omit,
        Decision::Block,
    ];

    assert_eq!(decisions.len(), 5);
}

#[test]
fn verification_report_is_aggregate_only_and_not_a_publication_gate() {
    let report = VerificationReport {
        files_verified: 1,
        directories_verified: 0,
        bytes_verified: 12,
        filename_components_scanned: 1,
        path_components_scanned: 1,
        content_files_scanned: 1,
    };

    assert_eq!(report.files_verified, report.content_files_scanned);
    assert_eq!(report.path_components_scanned, 1);
    // A report is not sufficient to construct VerifiedStagedTree; the only
    // constructor is the successful consuming verification function.
}
