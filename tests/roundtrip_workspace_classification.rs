#![cfg(windows)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

use safeclone::roundtrip::classify::{
    classify_session, ClassificationDecision, ClassificationReport,
};
use safeclone::roundtrip::create::create_session;
use safeclone::roundtrip::token::{ReviewProfile, TOKEN_PREFIX};

static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

struct Fixture(PathBuf);

impl Fixture {
    fn new(profile: ReviewProfile) -> (Self, PathBuf, PathBuf, PathBuf) {
        Self::from_setup(profile, |original| {
            fs::create_dir_all(original.join("helpers")).expect("create Original fixture");
            fs::write(
                original.join("main.rs"),
                concat!(
                    "top-a\n",
                    "top-b\n",
                    "context-left\n",
                    "let credential = \"fixture.user@example.invalid\";\n",
                    "context-right\n",
                    "bottom-a\n",
                    "bottom-b\n"
                ),
            )
            .expect("write token-bearing source");
            fs::write(original.join("ordinary.txt"), "ordinary unique text\n")
                .expect("write ordinary source");
            fs::write(
                original.join("helpers").join("nested.txt"),
                "unique helper subtree\n",
            )
            .expect("write helper subtree");
            fs::write(original.join("opaque.bin"), b"opaque\0fixture")
                .expect("write omitted binary");
        })
    }

    fn from_setup(
        profile: ReviewProfile,
        setup: impl FnOnce(&Path),
    ) -> (Self, PathBuf, PathBuf, PathBuf) {
        let serial = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "safeclone-classification-classify-{}-{serial}",
            std::process::id()
        ));
        let original = root.join("OriginalWorkspace");
        let ai = root.join("AiWorkspaceLongFixtureName");
        let state = root.join("PrivateSessionDirectoryLongFixtureName");
        fs::create_dir_all(&original).expect("create Original fixture root");
        setup(&original);
        create_session(&original, &ai, &state, profile).expect("create session");
        (Self(root), original, ai, state)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn token(bytes: &[u8]) -> Vec<u8> {
    let start = bytes
        .windows(TOKEN_PREFIX.len())
        .position(|window| window == TOKEN_PREFIX.as_bytes())
        .expect("AI file contains token");
    let body = start + TOKEN_PREFIX.len();
    let suffix = bytes[body..]
        .windows(2)
        .position(|window| window == b"__")
        .expect("canonical token suffix");
    bytes[start..body + suffix + 2].to_vec()
}

fn replace_once(bytes: &[u8], from: &[u8], to: &[u8]) -> Vec<u8> {
    let start = bytes
        .windows(from.len())
        .position(|window| window == from)
        .expect("replacement input exists");
    let mut output = Vec::with_capacity(bytes.len() - from.len() + to.len());
    output.extend_from_slice(&bytes[..start]);
    output.extend_from_slice(to);
    output.extend_from_slice(&bytes[start + from.len()..]);
    output
}

fn snapshot(root: &Path) -> Vec<(String, Vec<u8>)> {
    fn walk(root: &Path, current: &Path, output: &mut Vec<(String, Vec<u8>)>) {
        let mut entries = fs::read_dir(current)
            .expect("read snapshot directory")
            .collect::<std::io::Result<Vec<_>>>()
            .expect("collect snapshot entries");
        entries.sort_by_key(fs::DirEntry::file_name);
        for entry in entries {
            let path = entry.path();
            let relative = path
                .strip_prefix(root)
                .expect("snapshot relative path")
                .to_string_lossy()
                .replace('\\', "/");
            if entry.file_type().expect("snapshot type").is_dir() {
                output.push((format!("{relative}/"), Vec::new()));
                walk(root, &path, output);
            } else {
                output.push((relative, fs::read(path).expect("read snapshot file")));
            }
        }
    }
    let mut output = Vec::new();
    walk(root, root, &mut output);
    output
}

fn classify(original: &Path, ai: &Path, state: &Path) -> ClassificationReport {
    classify_session(original, ai, state).expect("classify synthetic session")
}

fn assert_classification_reject(label: &str, original: &Path, ai: &Path, state: &Path) {
    let result = classify_session(original, ai, state);
    assert!(
        matches!(
            result,
            Ok(ClassificationReport {
                decision: ClassificationDecision::Reject,
                ..
            })
        ),
        "{label}: {result:?}"
    );
}

fn create_junction(target: &Path, junction: &Path) {
    let status = Command::new("cmd")
        .args(["/c", "mklink", "/J"])
        .arg(junction)
        .arg(target)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("run synthetic junction command");
    assert!(status.success(), "create synthetic junction");
}

#[test]
fn unchanged_and_ordinary_relative_edits_are_standard_automatic_and_read_only() {
    let (_fixture, original, ai, state) = Fixture::new(ReviewProfile::StandardV2);
    let original_before = snapshot(&original);
    let ai_before = snapshot(&ai);
    let state_before = snapshot(&state);
    let unchanged = classify(&original, &ai, &state);
    assert_eq!(
        unchanged.decision,
        ClassificationDecision::AutomaticEligible
    );
    assert_eq!(unchanged.primary_token_events, 1);
    assert_eq!(unchanged.approval_required_events, 0);
    assert_eq!(unchanged.rejected_events, 0);
    assert!(!unchanged.semantic_safety_assessed);
    assert_eq!(classify(&original, &ai, &state), unchanged);
    assert_eq!(snapshot(&original), original_before);
    assert_eq!(snapshot(&ai), ai_before);
    assert_eq!(snapshot(&state), state_before);

    let main = ai.join("main.rs");
    let baseline = fs::read_to_string(&main).expect("read AI main");
    fs::write(&main, format!("use synthetic::helper;\n{baseline}"))
        .expect("insert import before token");
    let inserted = classify(&original, &ai, &state);
    assert_eq!(inserted.decision, ClassificationDecision::AutomaticEligible);
    assert_eq!(inserted.primary_token_events, 1);
    assert_eq!(inserted.rejected_events, 0);
    assert!(inserted.file_events >= 1);

    fs::write(
        &main,
        baseline
            .replace(
                "top-a\ntop-b\ncontext-left\n",
                "top-a\ntop-b\nbottom-a\ncontext-left\n",
            )
            .replace("context-right\nbottom-a\n", "context-right\n"),
    )
    .expect("move intact protected block");
    let relocated = classify(&original, &ai, &state);
    assert_eq!(
        relocated.decision,
        ClassificationDecision::AutomaticEligible
    );
    assert_eq!(relocated.rejected_events, 0);
}

#[test]
fn token_context_structure_and_exact_deletion_have_distinct_decisions() {
    let (_fixture, original, ai, state) = Fixture::new(ReviewProfile::StandardV2);
    let main = ai.join("main.rs");
    let baseline = fs::read(&main).expect("read AI main");
    let canonical = token(&baseline);

    fs::write(
        &main,
        replace_once(&baseline, b"context-left", b"context-changed"),
    )
    .expect("change immediate context");
    assert_eq!(
        classify(&original, &ai, &state).decision,
        ClassificationDecision::Reject
    );

    fs::write(
        &main,
        [
            baseline.as_slice(),
            b"duplicate=".as_slice(),
            canonical.as_slice(),
            b"\n".as_slice(),
        ]
        .concat(),
    )
    .expect("duplicate canonical token");
    assert_eq!(
        classify(&original, &ai, &state).decision,
        ClassificationDecision::Reject
    );

    fs::write(&main, replace_once(&baseline, &canonical, b""))
        .expect("delete exact canonical token");
    let deleted = classify(&original, &ai, &state);
    assert_eq!(deleted.decision, ClassificationDecision::ApprovalRequired);
    assert!(deleted.approval_required_events >= 1);
    assert_eq!(deleted.rejected_events, 0);

    fs::write(&main, replace_once(&baseline, &canonical, b" "))
        .expect("delete token plus adjacent byte");
    assert_eq!(
        classify(&original, &ai, &state).decision,
        ClassificationDecision::Reject
    );

    let moved = replace_once(&baseline, &canonical, b"");
    fs::write(&main, moved).expect("remove token from original file");
    fs::write(
        ai.join("moved.rs"),
        [
            b"context-left\ncredential=".as_slice(),
            &canonical,
            b"\ncontext-right\n",
        ]
        .concat(),
    )
    .expect("move token to another file");
    assert_eq!(
        classify(&original, &ai, &state).decision,
        ClassificationDecision::Reject
    );
}

#[test]
fn file_tree_and_strict_profile_matrix_is_deterministic() {
    {
        let (_fixture, original, ai, state) = Fixture::new(ReviewProfile::StandardV2);
        fs::rename(ai.join("ordinary.txt"), ai.join("renamed.txt"))
            .expect("rename token-free file");
        let report = classify(&original, &ai, &state);
        assert_eq!(report.decision, ClassificationDecision::AutomaticEligible);
        assert!(report.file_events >= 1);
    }
    {
        let (_fixture, original, ai, state) = Fixture::new(ReviewProfile::StandardV2);
        fs::rename(ai.join("helpers"), ai.join("moved-helpers"))
            .expect("rename token-free subtree");
        let report = classify(&original, &ai, &state);
        assert_eq!(report.decision, ClassificationDecision::AutomaticEligible);
        assert!(report.directory_events >= 1);
    }
    {
        let (_fixture, original, ai, state) = Fixture::new(ReviewProfile::StandardV2);
        fs::remove_file(ai.join("ordinary.txt")).expect("delete token-free file");
        let report = classify(&original, &ai, &state);
        assert_eq!(report.decision, ClassificationDecision::ApprovalRequired);
        assert!(report.approval_required_events >= 1);
    }
    {
        let (_fixture, original, ai, state) = Fixture::new(ReviewProfile::StandardV2);
        fs::write(ai.join("new_helper.rs"), "pub fn helper() {}\n").expect("add safe text file");
        assert_eq!(
            classify(&original, &ai, &state).decision,
            ClassificationDecision::AutomaticEligible
        );
        fs::write(ai.join("opaque.bin"), b"safe-looking text")
            .expect("collide with original-only omitted path");
        assert_eq!(
            classify(&original, &ai, &state).decision,
            ClassificationDecision::Reject
        );
    }
    {
        let (_fixture, original, ai, state) = Fixture::new(ReviewProfile::StrictTokenFilesV2);
        let main = ai.join("main.rs");
        let baseline = fs::read_to_string(&main).expect("read Strict AI file");
        fs::write(&main, format!("use strict_fixture::helper;\n{baseline}"))
            .expect("edit Strict token-bearing file");
        let report = classify(&original, &ai, &state);
        assert_eq!(report.decision, ClassificationDecision::ApprovalRequired);
        assert_eq!(report.rejected_events, 0);
        assert!(report.approval_required_events >= 1);

        fs::write(&main, baseline.replace("context-left", "changed-context"))
            .expect("break Standard gate under Strict");
        let rejected = classify(&original, &ai, &state);
        assert_eq!(rejected.decision, ClassificationDecision::Reject);
        assert!(rejected.rejected_events >= 1);
    }
}

#[test]
fn detector_and_hostile_addition_matrix_rejects_without_masking_new_values() {
    let (_fixture, original, ai, state) = Fixture::new(ReviewProfile::StandardV2);
    let new_file = ai.join("new-data.txt");
    fs::write(
        ai.join("ordinary.txt"),
        "password = \"N0nLive_Fixture_4A7c9E2b\"\n",
    )
    .expect("write synthetic secret-like value into an existing file");
    assert_classification_reject(
        "new sensitive value in existing token-free file",
        &original,
        &ai,
        &state,
    );
    fs::write(ai.join("ordinary.txt"), "ordinary unique text\n").expect("restore ordinary file");
    let synthetic_my_number = synthetic_my_number("10000000000");
    let synthetic_corporate = synthetic_corporate_number("102030405060");
    let values = [
        "password = \"N0nLive_Fixture_4A7c9E2b\"".to_owned(),
        "another.fixture@example.invalid".to_owned(),
        "+1 (202) 555-0100".to_owned(),
        "090-0000-0000".to_owned(),
        "192.0.2.10".to_owned(),
        "123-4567".to_owned(),
        synthetic_my_number,
        synthetic_corporate,
    ];
    for value in values {
        fs::write(&new_file, format!("{value}\n")).expect("write synthetic detector value");
        assert_eq!(
            classify(&original, &ai, &state).decision,
            ClassificationDecision::Reject,
            "detector family must reject"
        );
    }
    fs::remove_file(&new_file).expect("remove detector file");
    fs::write(
        ai.join("fixture.user@example.invalid.txt"),
        "ordinary body\n",
    )
    .expect("write path-sensitive fixture");
    assert_eq!(
        classify(&original, &ai, &state).decision,
        ClassificationDecision::Reject
    );
}

#[test]
fn path_token_projection_and_nonprojected_movement_are_separate() {
    let serial = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "safeclone-classification-path-{}-{serial}",
        std::process::id()
    ));
    let fixture = Fixture(root.clone());
    let original = root.join("OriginalWorkspace");
    let ai = root.join("AiWorkspaceLongFixtureName");
    let state = root.join("PrivateSessionDirectoryLongFixtureName");
    fs::create_dir_all(&original).expect("create path-token Original");
    fs::write(original.join("endpoint-192.0.2.10.txt"), "ordinary body\n")
        .expect("write path-token source");
    create_session(&original, &ai, &state, ReviewProfile::StandardV2)
        .expect("create path-token session");
    let tokenized = fs::read_dir(&ai)
        .expect("read path-token AI")
        .next()
        .expect("one AI entry")
        .expect("read AI entry")
        .path();
    let name = tokenized
        .file_name()
        .and_then(|name| name.to_str())
        .expect("Unicode tokenized filename");
    let token = token(name.as_bytes());
    let projected_name = String::from_utf8(replace_once(name.as_bytes(), &token, b""))
        .expect("projected filename is UTF-8");
    fs::rename(&tokenized, ai.join(&projected_name)).expect("exact path-token deletion");
    let projected = classify(&original, &ai, &state);
    assert_eq!(projected.decision, ClassificationDecision::ApprovalRequired);
    assert_eq!(projected.rejected_events, 0);
    assert!(projected.file_events >= 1);

    fs::rename(ai.join(&projected_name), ai.join(format!("moved-{name}")))
        .expect("restore token at a moved boundary");
    assert_eq!(
        classify(&original, &ai, &state).decision,
        ClassificationDecision::Reject
    );
    drop(fixture);
}

#[test]
fn malformed_modified_category_sid_oid_and_duplicate_token_matrix_rejects() {
    let (_fixture, original, ai, state) = Fixture::new(ReviewProfile::StandardV2);
    let main = ai.join("main.rs");
    let baseline = fs::read(&main).expect("read token matrix baseline");
    let canonical = token(&baseline);
    let canonical_text = String::from_utf8(canonical.clone()).expect("canonical token ASCII");
    let body = canonical_text
        .strip_prefix(TOKEN_PREFIX)
        .and_then(|value| value.strip_suffix("__"))
        .expect("canonical body");
    let fields = body.split('_').collect::<Vec<_>>();
    assert_eq!(fields.len(), 4);

    let mutate_field = |index: usize| {
        let mut values = fields
            .iter()
            .map(|value| (*value).to_owned())
            .collect::<Vec<_>>();
        let mut bytes = values[index].as_bytes().to_vec();
        bytes[0] = if bytes[0] == b'A' { b'B' } else { b'A' };
        values[index] = String::from_utf8(bytes).expect("ASCII field mutation");
        format!("{TOKEN_PREFIX}{}__", values.join("_"))
    };
    let mutations = [
        canonical_text.replacen("_EMAIL_", "_IP_", 1),
        mutate_field(1),
        mutate_field(2),
        mutate_field(3),
        canonical_text.replacen(TOKEN_PREFIX, &TOKEN_PREFIX.to_ascii_lowercase(), 1),
        canonical_text[..canonical_text.len() - 8].to_owned(),
        format!(
            "{TOKEN_PREFIX}{}-{}_{}_{}__",
            fields[0], fields[1], fields[2], fields[3]
        ),
        format!(
            "{TOKEN_PREFIX}{}_{}_0_{}__",
            fields[0], fields[1], fields[3]
        ),
        format!(
            "{TOKEN_PREFIX}{}_{}_{}_{}=__",
            fields[0],
            fields[1],
            fields[2],
            &fields[3][..fields[3].len() - 1]
        ),
        format!(
            "{TOKEN_PREFIX}{}_{}_{}_{}X__",
            fields[0], fields[1], fields[2], fields[3]
        ),
    ];
    for mutation in mutations {
        fs::write(
            &main,
            replace_once(&baseline, &canonical, mutation.as_bytes()),
        )
        .expect("write token mutation");
        let report = classify(&original, &ai, &state);
        assert_eq!(report.decision, ClassificationDecision::Reject);
        assert_eq!(report.primary_token_events, 1);
        assert!(report.rejected_events >= 1);
    }

    fs::write(
        &main,
        [
            baseline.as_slice(),
            b"\nunrelated=".as_slice(),
            TOKEN_PREFIX.to_ascii_lowercase().as_bytes(),
            b"TRUNCATED".as_slice(),
        ]
        .concat(),
    )
    .expect("append unrelated malformed reserved form");
    let unrelated = classify(&original, &ai, &state);
    assert_eq!(unrelated.primary_token_events, 1);
    assert_eq!(unrelated.decision, ClassificationDecision::Reject);

    let overlapping = format!("{TOKEN_PREFIX}{canonical_text}");
    fs::write(
        &main,
        replace_once(&baseline, &canonical, overlapping.as_bytes()),
    )
    .expect("write overlapping reserved introducers");
    let overlapping = classify(&original, &ai, &state);
    assert_eq!(overlapping.primary_token_events, 1);
    assert_eq!(overlapping.decision, ClassificationDecision::Reject);

    let back_to_back = format!("{canonical_text}{canonical_text}");
    fs::write(
        &main,
        replace_once(&baseline, &canonical, back_to_back.as_bytes()),
    )
    .expect("write back-to-back known OID forms");
    let back_to_back = classify(&original, &ai, &state);
    assert_eq!(back_to_back.primary_token_events, 1);
    assert_eq!(back_to_back.decision, ClassificationDecision::Reject);
}

#[test]
fn hostile_binary_invalid_utf8_hardlink_ads_and_protected_additions_reject() {
    {
        let (_fixture, original, ai, state) = Fixture::new(ReviewProfile::StandardV2);
        fs::write(ai.join("archive.bin"), b"binary\0addition").expect("write binary addition");
        assert_classification_reject("binary addition", &original, &ai, &state);
    }
    {
        let (_fixture, original, ai, state) = Fixture::new(ReviewProfile::StandardV2);
        fs::write(ai.join("invalid.txt"), [0xff, 0xfe]).expect("write invalid UTF-8 addition");
        assert_classification_reject("invalid UTF-8 addition", &original, &ai, &state);
    }
    {
        let (_fixture, original, ai, state) = Fixture::new(ReviewProfile::StandardV2);
        fs::hard_link(ai.join("ordinary.txt"), ai.join("hard-link.txt"))
            .expect("create hard-link addition");
        assert_classification_reject("hard-link addition", &original, &ai, &state);
    }
    {
        let (_fixture, original, ai, state) = Fixture::new(ReviewProfile::StandardV2);
        let ads = format!("{}:synthetic", ai.join("ordinary.txt").display());
        fs::write(&ads, b"named stream").expect("create ADS addition");
        assert_classification_reject("ADS addition", &original, &ai, &state);
    }
    {
        let (_fixture, original, ai, state) = Fixture::new(ReviewProfile::StandardV2);
        fs::create_dir(ai.join(".git")).expect("create protected namespace addition");
        assert_classification_reject("protected namespace addition", &original, &ai, &state);
    }
}

#[test]
fn original_mismatch_produces_no_classification_report() {
    let (_fixture, original, ai, state) = Fixture::new(ReviewProfile::StandardV2);
    fs::write(original.join("ordinary.txt"), "changed Original\n")
        .expect("mutate Original fixture");
    let failure = classify_session(&original, &ai, &state).expect_err("Original mismatch fails");
    assert_eq!(
        failure.error(),
        safeclone::roundtrip::Error::OriginalBaselineMismatch
    );
    let rendered = format!("{failure:?} {failure}");
    for canary in ["changed Original", "ordinary.txt", "OriginalWorkspace"] {
        assert!(!rendered.contains(canary));
    }
}

#[test]
fn separated_protected_runs_preserve_order_but_swapping_runs_rejects() {
    let serial = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "safeclone-classification-order-{}-{serial}",
        std::process::id()
    ));
    let fixture = Fixture(root.clone());
    let original = root.join("OriginalWorkspace");
    let ai = root.join("AiWorkspaceLongFixtureName");
    let state = root.join("PrivateSessionDirectoryLongFixtureName");
    fs::create_dir_all(&original).expect("create order Original");
    fs::write(
        original.join("order.txt"),
        concat!(
            "left-one\n",
            "first=first.fixture@example.invalid\n",
            "right-one\n",
            "separator\n",
            "left-two\n",
            "second=second.fixture@example.invalid\n",
            "right-two\n"
        ),
    )
    .expect("write two-run source");
    create_session(&original, &ai, &state, ReviewProfile::StandardV2)
        .expect("create two-run session");
    let file = ai.join("order.txt");
    let safe = fs::read_to_string(&file).expect("read two-run AI file");
    let lines = safe.lines().collect::<Vec<_>>();
    let swapped = format!(
        "{}\n{}\n{}\nseparator\n{}\n{}\n{}\n",
        lines[4], lines[5], lines[6], lines[0], lines[1], lines[2]
    );
    fs::write(&file, swapped).expect("swap protected runs");
    let report = classify(&original, &ai, &state);
    assert_eq!(report.primary_token_events, 2);
    assert_eq!(report.decision, ClassificationDecision::Reject);
    drop(fixture);
}

#[test]
fn token_move_duplicate_projection_and_file_deletion_matrix_is_fail_closed() {
    let (_fixture, original, ai, state) = Fixture::new(ReviewProfile::StandardV2);
    let main = ai.join("main.rs");
    let baseline = fs::read(&main).expect("read token adversarial baseline");
    let canonical = token(&baseline);
    let canonical_text = String::from_utf8(canonical.clone()).expect("canonical token ASCII");

    let same_line = String::from_utf8(baseline.clone())
        .expect("UTF-8 baseline")
        .replace(
            &format!("let credential = \"{canonical_text}\";"),
            &format!("let credential = \"\"; // {canonical_text}"),
        );
    fs::write(&main, same_line).expect("move token within protected line");
    assert_classification_reject("same-line token move", &original, &ai, &state);

    let without = replace_once(&baseline, &canonical, b"");
    let different_context = [
        without.as_slice(),
        b"different-left\nrelocated=".as_slice(),
        canonical.as_slice(),
        b"\ndifferent-right\n".as_slice(),
    ]
    .concat();
    fs::write(&main, different_context).expect("move token into another context");
    assert_classification_reject("different-context token move", &original, &ai, &state);

    let mut bad_auth_one = canonical.clone();
    let auth_one = bad_auth_one.len() - 4;
    bad_auth_one[auth_one] = if bad_auth_one[auth_one] == b'A' {
        b'B'
    } else {
        b'A'
    };
    let mut bad_auth_two = canonical.clone();
    let auth_two = bad_auth_two.len() - 5;
    bad_auth_two[auth_two] = if bad_auth_two[auth_two] == b'C' {
        b'D'
    } else {
        b'C'
    };
    fs::write(
        &main,
        [
            baseline.as_slice(),
            b"bad-copy=".as_slice(),
            bad_auth_one.as_slice(),
            b"\n".as_slice(),
        ]
        .concat(),
    )
    .expect("add bad-tag duplicate beside authentic token");
    let authentic_and_bad = classify(&original, &ai, &state);
    assert_eq!(authentic_and_bad.primary_token_events, 1);
    assert_eq!(authentic_and_bad.decision, ClassificationDecision::Reject);

    fs::write(
        &main,
        [
            replace_once(&baseline, &canonical, &bad_auth_one).as_slice(),
            b"second-bad-copy=".as_slice(),
            bad_auth_two.as_slice(),
            b"\n".as_slice(),
        ]
        .concat(),
    )
    .expect("write two bad-tag forms carrying one known OID");
    let two_bad = classify(&original, &ai, &state);
    assert_eq!(two_bad.primary_token_events, 1);
    assert_eq!(two_bad.decision, ClassificationDecision::Reject);

    let exact_delete_plus_far_insert = [
        b"new-far-line-one\nnew-far-line-two\n".as_slice(),
        replace_once(&baseline, &canonical, b"").as_slice(),
    ]
    .concat();
    fs::write(&main, exact_delete_plus_far_insert)
        .expect("delete exact token and insert outside selected context");
    let projected = classify(&original, &ai, &state);
    assert_eq!(projected.primary_token_events, 1);
    assert_eq!(projected.decision, ClassificationDecision::ApprovalRequired);
    assert_eq!(projected.rejected_events, 0);

    fs::remove_file(&main).expect("delete complete token-bearing file");
    let deleted_file = classify(&original, &ai, &state);
    assert_eq!(deleted_file.primary_token_events, 1);
    assert_eq!(
        deleted_file.decision,
        ClassificationDecision::ApprovalRequired
    );
    assert_eq!(deleted_file.rejected_events, 0);
    assert!(deleted_file.approval_required_events >= 2);
}

#[test]
fn token_free_file_correspondence_uses_exact_unique_commitments_only() {
    {
        let (_fixture, original, ai, state) = Fixture::new(ReviewProfile::StandardV2);
        fs::write(ai.join("ordinary.txt"), "rewritten ordinary algorithm\n")
            .expect("modify same-path token-free file");
        let report = classify(&original, &ai, &state);
        assert_eq!(report.decision, ClassificationDecision::AutomaticEligible);
        assert!(report.file_events >= 1);
    }
    {
        let (_fixture, original, ai, state) = Fixture::new(ReviewProfile::StandardV2);
        fs::create_dir(ai.join("destination")).expect("create move destination");
        fs::rename(
            ai.join("ordinary.txt"),
            ai.join("destination").join("ordinary.txt"),
        )
        .expect("move unique token-free file");
        assert_eq!(
            classify(&original, &ai, &state).decision,
            ClassificationDecision::AutomaticEligible
        );
    }
    {
        let (_fixture, original, ai, state) = Fixture::new(ReviewProfile::StandardV2);
        let renamed = ai.join("renamed-and-edited.txt");
        fs::rename(ai.join("ordinary.txt"), &renamed).expect("rename token-free file");
        fs::write(&renamed, "content changed after rename\n").expect("edit renamed file");
        let report = classify(&original, &ai, &state);
        assert_eq!(report.decision, ClassificationDecision::ApprovalRequired);
        assert_eq!(report.rejected_events, 0);
    }
    {
        let (_fixture, original, ai, state) =
            Fixture::from_setup(ReviewProfile::StandardV2, |original| {
                fs::write(original.join("first.txt"), "identical\n").expect("write first twin");
                fs::write(original.join("second.txt"), "identical\n").expect("write second twin");
            });
        fs::rename(ai.join("first.txt"), ai.join("renamed-first.txt")).expect("rename first twin");
        fs::rename(ai.join("second.txt"), ai.join("renamed-second.txt"))
            .expect("rename second twin");
        let report = classify(&original, &ai, &state);
        assert_eq!(report.decision, ClassificationDecision::ApprovalRequired);
        assert_eq!(report.rejected_events, 0);
        assert_eq!(report.approval_required_events, 2);
    }
    {
        let (_fixture, original, ai, state) =
            Fixture::from_setup(ReviewProfile::StandardV2, |original| {
                fs::write(original.join("only.txt"), "identical\n").expect("write only source");
            });
        fs::rename(ai.join("only.txt"), ai.join("copy-one.txt")).expect("move exact copy");
        fs::copy(ai.join("copy-one.txt"), ai.join("copy-two.txt"))
            .expect("duplicate edited exact bytes");
        let report = classify(&original, &ai, &state);
        assert_eq!(report.decision, ClassificationDecision::ApprovalRequired);
        assert_eq!(report.rejected_events, 0);
        assert_eq!(report.approval_required_events, 1);
    }
}

#[test]
fn directory_add_delete_move_and_ambiguity_matrix_is_deterministic() {
    {
        let (_fixture, original, ai, state) =
            Fixture::from_setup(ReviewProfile::StandardV2, |original| {
                fs::write(original.join("root.txt"), "root\n").expect("write root file");
                fs::create_dir(original.join("empty")).expect("create empty baseline directory");
            });
        fs::remove_dir(ai.join("empty")).expect("delete empty directory");
        fs::create_dir(ai.join("added-empty")).expect("add empty directory");
        assert_eq!(
            classify(&original, &ai, &state).decision,
            ClassificationDecision::AutomaticEligible
        );
    }
    {
        let (_fixture, original, ai, state) = Fixture::new(ReviewProfile::StandardV2);
        let added = ai.join("added-tree");
        fs::create_dir(&added).expect("add nonempty directory");
        fs::write(added.join("new.txt"), "new ordinary text\n").expect("add child file");
        assert_eq!(
            classify(&original, &ai, &state).decision,
            ClassificationDecision::AutomaticEligible
        );
        fs::remove_dir_all(ai.join("helpers")).expect("delete nonempty token-free subtree");
        let deleted = classify(&original, &ai, &state);
        assert_eq!(deleted.decision, ClassificationDecision::ApprovalRequired);
        assert_eq!(deleted.rejected_events, 0);
    }
    {
        let (_fixture, original, ai, state) =
            Fixture::from_setup(ReviewProfile::StandardV2, |original| {
                fs::create_dir_all(original.join("left").join("helpers"))
                    .expect("create movable subtree");
                fs::write(
                    original.join("left").join("helpers").join("nested.txt"),
                    "unique subtree\n",
                )
                .expect("write movable subtree file");
                fs::write(
                    original.join("left").join("helpers.note"),
                    "lexically interposed sibling\n",
                )
                .expect("write interposed sibling file");
            });
        fs::create_dir(ai.join("right")).expect("create destination parent");
        fs::rename(
            ai.join("left").join("helpers"),
            ai.join("right").join("helpers"),
        )
        .expect("move unique token-free subtree");
        assert_eq!(
            classify(&original, &ai, &state).decision,
            ClassificationDecision::AutomaticEligible
        );
    }
    {
        let (_fixture, original, ai, state) =
            Fixture::from_setup(ReviewProfile::StandardV2, |original| {
                for directory in ["one", "two"] {
                    fs::create_dir(original.join(directory)).expect("create identical subtree");
                    fs::write(original.join(directory).join("same.txt"), "identical\n")
                        .expect("write identical subtree file");
                }
            });
        fs::rename(ai.join("one"), ai.join("three")).expect("rename first identical subtree");
        fs::rename(ai.join("two"), ai.join("four")).expect("rename second identical subtree");
        let ambiguous = classify(&original, &ai, &state);
        assert_eq!(ambiguous.decision, ClassificationDecision::ApprovalRequired);
        assert_eq!(ambiguous.rejected_events, 0);
        assert_eq!(ambiguous.approval_required_events, 2);
    }
}

#[test]
fn token_bearing_file_and_directory_movement_rejects_but_exact_path_deletion_projects() {
    {
        let (_fixture, original, ai, state) = Fixture::new(ReviewProfile::StandardV2);
        fs::rename(ai.join("main.rs"), ai.join("renamed-main.rs"))
            .expect("rename token-bearing file");
        assert_classification_reject("token-bearing file rename", &original, &ai, &state);
    }
    {
        let (_fixture, original, ai, state) =
            Fixture::from_setup(ReviewProfile::StandardV2, |original| {
                fs::create_dir(original.join("secure")).expect("create secure directory");
                fs::write(
                    original.join("secure").join("main.txt"),
                    "left\nvalue=directory.fixture@example.invalid\nright\n",
                )
                .expect("write directory content token");
            });
        fs::rename(ai.join("secure"), ai.join("renamed-secure"))
            .expect("rename directory containing content token");
        assert_classification_reject(
            "directory containing content token rename",
            &original,
            &ai,
            &state,
        );
    }
    {
        let (_fixture, original, ai, state) =
            Fixture::from_setup(ReviewProfile::StandardV2, |original| {
                let directory = original.join("service-192.0.2.10");
                fs::create_dir(&directory).expect("create path-token directory");
                fs::write(
                    directory.join("config.txt"),
                    "left\ncontact=descendant.fixture@example.invalid\nright\n",
                )
                .expect("write path-token child");
            });
        let tokenized = fs::read_dir(&ai)
            .expect("read path-token AI root")
            .next()
            .expect("one tokenized directory")
            .expect("read tokenized directory")
            .path();
        let name = tokenized
            .file_name()
            .and_then(|name| name.to_str())
            .expect("UTF-8 tokenized directory name");
        let path_token = token(name.as_bytes());
        let projected_name = String::from_utf8(replace_once(name.as_bytes(), &path_token, b""))
            .expect("projected directory name UTF-8");
        fs::rename(&tokenized, ai.join(&projected_name))
            .expect("delete exact directory-component token");
        let projected = classify(&original, &ai, &state);
        assert_eq!(projected.primary_token_events, 2);
        assert_eq!(projected.decision, ClassificationDecision::ApprovalRequired);
        assert_eq!(projected.rejected_events, 0);
        assert!(projected.directory_events >= 1);

        fs::rename(ai.join(&projected_name), ai.join(format!("moved-{name}")))
            .expect("move authentic path token to another component boundary");
        assert_classification_reject("token-bearing directory movement", &original, &ai, &state);
    }
}

#[test]
fn unsupported_and_reparse_additions_are_observed_without_following() {
    {
        let (_fixture, original, ai, state) = Fixture::new(ReviewProfile::StandardV2);
        fs::write(ai.join("unsupported.png"), "readable but unsupported\n")
            .expect("write unsupported extension");
        assert_classification_reject("unsupported extension", &original, &ai, &state);
    }
    {
        let (fixture, original, ai, state) = Fixture::new(ReviewProfile::StandardV2);
        let target = fixture.0.join("outside-reparse-target");
        fs::create_dir(&target).expect("create synthetic reparse target");
        fs::write(target.join("must-not-be-read.txt"), "outside\n")
            .expect("write reparse target canary");
        let junction = ai.join("unexpected-reparse");
        create_junction(&target, &junction);
        assert_classification_reject("reparse addition", &original, &ai, &state);
        fs::remove_dir(&junction).expect("remove junction without following");
    }
}

#[test]
fn original_only_collision_matrix_covers_leaf_and_topology_aliases() {
    let (_fixture, original, ai, state) =
        Fixture::from_setup(ReviewProfile::StandardV2, |original| {
            fs::write(original.join("visible.txt"), "ordinary\n").expect("write visible file");
            fs::write(original.join("binary.txt"), b"binary\0payload").expect("write binary file");
            fs::write(original.join("invalid.txt"), b"invalid\xffutf8")
                .expect("write invalid UTF-8 file");
            fs::write(original.join("unsupported.png"), "readable unsupported\n")
                .expect("write unsupported file");
            fs::write(
                original.join("credentials.txt"),
                "ordinary high-risk leaf\n",
            )
            .expect("write high-risk filename");
        });
    for omitted in [
        "binary.txt",
        "invalid.txt",
        "unsupported.png",
        "credentials.txt",
    ] {
        fs::write(ai.join(omitted), "edited collision\n").expect("add omitted-path collision");
        let report = classify(&original, &ai, &state);
        assert_eq!(report.decision, ClassificationDecision::Reject, "{omitted}");
        let rendered = format!("{report:?}");
        assert!(!rendered.contains(omitted));
        fs::remove_file(ai.join(omitted)).expect("remove omitted-path collision");
    }

    let topology = ai.join("binary.txt");
    fs::create_dir(&topology).expect("create ancestor/topology collision");
    fs::write(topology.join("child.txt"), "ordinary\n").expect("write topology child");
    assert_classification_reject("omitted topology collision", &original, &ai, &state);
}

fn synthetic_my_number(base: &str) -> String {
    let digits = base.as_bytes();
    let sum: u32 = digits
        .iter()
        .rev()
        .enumerate()
        .map(|(index, digit)| {
            let position = u32::try_from(index + 1).expect("small position");
            let weight = if position <= 6 {
                position + 1
            } else {
                position - 5
            };
            u32::from(digit - b'0') * weight
        })
        .sum();
    let remainder = sum % 11;
    let check = if remainder <= 1 { 0 } else { 11 - remainder };
    format!("{base}{check}")
}

fn synthetic_corporate_number(base: &str) -> String {
    let sum: u32 = base
        .as_bytes()
        .iter()
        .rev()
        .enumerate()
        .map(|(index, digit)| u32::from(digit - b'0') * if index % 2 == 0 { 1 } else { 2 })
        .sum();
    let remainder = sum % 9;
    let check = if remainder == 0 { 9 } else { 9 - remainder };
    format!("{check}{base}")
}
