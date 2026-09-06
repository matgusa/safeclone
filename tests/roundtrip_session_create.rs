#![cfg(windows)]

use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

use safeclone::roundtrip::create::{
    create_session, AiPublicationState, CreateFailure, CreateReport,
};
use safeclone::roundtrip::schema::SessionState;
use safeclone::roundtrip::token::{ReviewProfile, ENGINE_VERSION, POLICY_ID, TOKEN_PREFIX};
use safeclone::roundtrip::Error;

static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        let serial = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("safeclone-create-{}-{serial}", std::process::id()));
        fs::create_dir(&path).expect("create repository-external fixture root");
        Self(path)
    }

    fn paths(&self) -> (PathBuf, PathBuf, PathBuf) {
        (
            self.0.join("OriginalWorkspace"),
            self.0.join("AiWorkspaceLongFixtureName"),
            self.0.join("PrivateSessionDirectoryLongFixtureName"),
        )
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn read_tree(root: &Path, output: &mut Vec<(String, Vec<u8>)>, prefix: &str) {
    let mut entries = fs::read_dir(root)
        .expect("read synthetic AI tree")
        .collect::<std::io::Result<Vec<_>>>()
        .expect("collect entries");
    entries.sort_by_key(fs::DirEntry::file_name);
    for entry in entries {
        let name = entry
            .file_name()
            .into_string()
            .expect("Unicode fixture name");
        let relative = if prefix.is_empty() {
            name
        } else {
            format!("{prefix}/{name}")
        };
        if entry.file_type().expect("file type").is_dir() {
            read_tree(&entry.path(), output, &relative);
        } else {
            output.push((
                relative,
                fs::read(entry.path()).expect("read transformed fixture"),
            ));
        }
    }
}

fn basic_original(root: &Path) {
    fs::create_dir(root).expect("create basic original");
    fs::write(root.join("ordinary.txt"), b"ordinary synthetic text\n")
        .expect("write basic original");
}

fn create_basic_session(fixture: &Fixture) -> (PathBuf, PathBuf, PathBuf, CreateReport) {
    let (original, ai, state) = fixture.paths();
    basic_original(&original);
    let report = create_session(&original, &ai, &state, ReviewProfile::StandardV2)
        .expect("create basic round-trip session");
    (original, ai, state, report)
}

fn assert_definite(result: Result<CreateReport, CreateFailure>, error: Error) {
    assert_eq!(result, Err(CreateFailure::DefiniteFailure(error)));
}

fn assert_manual(result: Result<CreateReport, CreateFailure>, error: Error) {
    assert_eq!(result, Err(CreateFailure::ManualInspectionRequired(error)));
}

fn generation_count(state: &Path) -> usize {
    fs::read_dir(state)
        .expect("read private fixture")
        .map(|entry| {
            entry
                .expect("private entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .filter(|name| name.starts_with("capsule-") && name.ends_with(".scdp"))
        .count()
}

fn generation_leaf(state: &Path) -> PathBuf {
    fs::read_dir(state)
        .expect("read private fixture")
        .map(|entry| entry.expect("private entry").path())
        .find(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("capsule-") && name.ends_with(".scdp"))
        })
        .expect("generation leaf")
}

fn clear_directory(root: &Path) {
    for entry in fs::read_dir(root).expect("read controlled fixture directory") {
        let path = entry.expect("controlled fixture entry").path();
        if path.is_dir() {
            fs::remove_dir_all(path).expect("remove controlled fixture directory tree");
        } else {
            fs::remove_file(path).expect("remove controlled fixture file");
        }
    }
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

fn first_regular_file(root: &Path) -> PathBuf {
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(directory).expect("walk AI fixture") {
            let entry = entry.expect("AI entry");
            if entry.file_type().expect("AI type").is_dir() {
                pending.push(entry.path());
            } else {
                return entry.path();
            }
        }
    }
    panic!("AI fixture has no regular file")
}

fn extract_token(bytes: &[u8]) -> Vec<u8> {
    let start = bytes
        .windows(TOKEN_PREFIX.len())
        .position(|window| window == TOKEN_PREFIX.as_bytes())
        .expect("fixture contains token");
    let body = start + TOKEN_PREFIX.len();
    let suffix = bytes[body..]
        .windows(2)
        .position(|window| window == b"__")
        .expect("token suffix");
    bytes[start..body + suffix + 2].to_vec()
}

#[test]
fn enabled_ntfs_create_commits_generation_one_and_exact_replay_is_read_only() {
    let fixture = Fixture::new();
    let original = fixture.0.join("OriginalWorkspace");
    let ai = fixture.0.join("AiWorkspaceLongFixtureName");
    let state = fixture.0.join("PrivateSessionDirectoryLongFixtureName");
    fs::create_dir(&original).expect("create original");
    let token_directory = original.join("fixture.user+test@example.invalid");
    fs::create_dir(&token_directory).expect("create token directory");
    fs::write(
        token_directory.join("address-192.0.2.10.txt"),
        b"contact fixture.user+test@example.invalid\n",
    )
    .expect("write readable fixture");
    fs::write(original.join("zero.rs"), b"fn main() {}\n").expect("write zero finding");
    fs::write(original.join("opaque.bin"), b"opaque\0fixture").expect("write omitted binary");
    fs::create_dir(original.join("empty-directory")).expect("create empty directory");
    let mut source_before = Vec::new();
    read_tree(&original, &mut source_before, "");

    let created = create_session(&original, &ai, &state, ReviewProfile::StandardV2)
        .expect("new session create succeeds on the current local NTFS policy row");
    assert_eq!(created.engine_version, ENGINE_VERSION);
    assert_eq!(created.policy_id, POLICY_ID);
    assert_eq!(created.profile, ReviewProfile::StandardV2);
    assert_eq!(created.capsule_generation, 1);
    assert_eq!(created.session_state, SessionState::ActiveUnreviewed);
    assert_eq!(created.ai_publication, AiPublicationState::Published);
    assert!(!created.semantic_safety_assessed);
    assert!(!created.replayed);
    assert_eq!(created.baseline_counts.directories, 2);
    assert_eq!(created.baseline_counts.regular_files, 3);
    assert_eq!(created.baseline_counts.ai_visible_files, 2);
    assert_eq!(created.baseline_counts.omitted_files, 1);
    assert!(!ai.join("opaque.bin").exists());

    let mut output = Vec::new();
    read_tree(&ai, &mut output, "");
    assert_eq!(output.len(), 2);
    let rendered = output
        .iter()
        .flat_map(|(path, bytes)| [path.as_bytes(), bytes.as_slice()])
        .flatten()
        .copied()
        .collect::<Vec<_>>();
    assert!(rendered
        .windows(TOKEN_PREFIX.len())
        .any(|window| window == TOKEN_PREFIX.as_bytes()));
    assert!(!rendered
        .windows(b"fixture.user+test@example.invalid".len())
        .any(|window| window == b"fixture.user+test@example.invalid"));

    let replay = create_session(&original, &ai, &state, ReviewProfile::StandardV2)
        .expect("exact completed create replay succeeds");
    assert!(replay.replayed);
    assert_eq!(replay.session_id, created.session_id);
    assert_eq!(replay.baseline_counts, created.baseline_counts);
    assert_eq!(generation_count(&state), 1);
    let mut source_after = Vec::new();
    read_tree(&original, &mut source_after, "");
    assert_eq!(
        source_after, source_before,
        "OriginalWorkspace is immutable"
    );
}

#[test]
fn ambiguous_relative_anchor_rejects_before_either_output_root_exists() {
    let fixture = Fixture::new();
    let (original, ai, state) = fixture.paths();
    fs::create_dir(&original).expect("create ambiguous original");
    let mut text = String::new();
    for address in ["192.0.2.10", "192.0.2.11"] {
        for distance in (1..=16).rev() {
            text.push_str(&format!("shared-left-{distance}\n"));
        }
        text.push_str(&format!("credential = {address}\n"));
        for distance in 1..=16 {
            text.push_str(&format!("shared-right-{distance}\n"));
        }
    }
    fs::write(original.join("ambiguous.txt"), text).expect("write ambiguous fixture");

    assert_definite(
        create_session(&original, &ai, &state, ReviewProfile::StandardV2),
        Error::AnchorAmbiguous,
    );
    assert!(!ai.exists(), "AI root is not created");
    assert!(!state.exists(), "private-state root is not created");
}

#[test]
fn strict_token_files_v2_create_and_exact_replay_use_one_generation() {
    let fixture = Fixture::new();
    let (original, ai, state) = fixture.paths();
    fs::create_dir(&original).expect("create strict original");
    fs::write(
        original.join("strict.txt"),
        b"before\nendpoint = 192.0.2.44\nafter\n",
    )
    .expect("write strict token fixture");

    let created = create_session(&original, &ai, &state, ReviewProfile::StrictTokenFilesV2)
        .expect("strict v2 create");
    assert_eq!(created.profile, ReviewProfile::StrictTokenFilesV2);
    assert_eq!(created.engine_version, ENGINE_VERSION);
    assert_eq!(created.policy_id, POLICY_ID);
    assert_eq!(created.capsule_generation, 1);
    assert_eq!(generation_count(&state), 1);

    let replay = create_session(&original, &ai, &state, ReviewProfile::StrictTokenFilesV2)
        .expect("strict v2 exact replay");
    assert!(replay.replayed);
    assert_eq!(replay.session_id, created.session_id);
    assert_eq!(generation_count(&state), 1);
    assert_definite(
        create_session(&original, &ai, &state, ReviewProfile::StandardV2),
        Error::CreateConflict,
    );
}

#[test]
fn historical_profiles_reject_before_any_path_or_root_io() {
    for profile in [ReviewProfile::StandardV1, ReviewProfile::StrictTokenFileV1] {
        let fixture = Fixture::new();
        let (original, ai, state) = fixture.paths();
        assert_definite(
            create_session(&original, &ai, &state, profile),
            Error::InvalidState,
        );
        assert!(!original.exists());
        assert!(!ai.exists());
        assert!(!state.exists());
    }
}

#[test]
fn disposition_matrix_omits_original_only_files_but_commits_their_complete_bytes() {
    let fixture = Fixture::new();
    let (original, ai, state) = fixture.paths();
    fs::create_dir(&original).expect("create disposition original");
    fs::write(original.join("visible.txt"), b"ordinary readable text\n").expect("visible text");
    fs::write(original.join("binary.txt"), b"binary\0payload").expect("binary file");
    fs::write(original.join("invalid.txt"), b"invalid\xffutf8").expect("invalid UTF-8 file");
    fs::write(
        original.join("unsupported.png"),
        b"readable but unsupported",
    )
    .expect("unsupported file");
    fs::write(
        original.join("credentials.txt"),
        b"ordinary readable text\n",
    )
    .expect("high-risk filename file");

    let created = create_session(&original, &ai, &state, ReviewProfile::StandardV2)
        .expect("disposition session");
    assert_eq!(created.baseline_counts.regular_files, 5);
    assert_eq!(created.baseline_counts.ai_visible_files, 1);
    assert_eq!(created.baseline_counts.omitted_files, 4);
    assert!(ai.join("visible.txt").exists());
    for omitted in [
        "binary.txt",
        "invalid.txt",
        "unsupported.png",
        "credentials.txt",
    ] {
        assert!(!ai.join(omitted).exists(), "{omitted}");
    }

    fs::write(original.join("binary.txt"), b"changed\0payload")
        .expect("mutate controlled original-only fixture");
    assert_definite(
        create_session(&original, &ai, &state, ReviewProfile::StandardV2),
        Error::OriginalWorkspaceRejected,
    );
    assert_eq!(generation_count(&state), 1);
}

#[test]
fn reserved_introducer_rejects_every_original_content_and_name_class_before_roots() {
    enum Shape {
        Readable,
        Binary,
        InvalidUtf8,
        Unsupported,
        FileName,
        DirectoryName,
    }
    for shape in [
        Shape::Readable,
        Shape::Binary,
        Shape::InvalidUtf8,
        Shape::Unsupported,
        Shape::FileName,
        Shape::DirectoryName,
    ] {
        let fixture = Fixture::new();
        let (original, ai, state) = fixture.paths();
        fs::create_dir(&original).expect("create rejection original");
        match shape {
            Shape::Readable => fs::write(
                original.join("readable.txt"),
                b"prefix __safeclone_rt1_decoy suffix",
            )
            .expect("readable introducer"),
            Shape::Binary => fs::write(original.join("binary.bin"), b"\0__SAFECLONE_RT1_binary")
                .expect("binary introducer"),
            Shape::InvalidUtf8 => {
                fs::write(original.join("invalid.txt"), b"\xff__SaFeClOnE_rT1_invalid")
                    .expect("invalid UTF-8 introducer")
            }
            Shape::Unsupported => fs::write(
                original.join("unsupported.png"),
                b"__SAFECLONE_RT1_unsupported",
            )
            .expect("unsupported introducer"),
            Shape::FileName => {
                fs::write(original.join("__sAfEcLoNe_Rt1_filename.txt"), b"ordinary")
                    .expect("filename introducer")
            }
            Shape::DirectoryName => fs::create_dir(original.join("__SAFECLONE_rt1_directory"))
                .expect("directory introducer"),
        }
        assert_definite(
            create_session(&original, &ai, &state, ReviewProfile::StandardV2),
            Error::OriginalWorkspaceRejected,
        );
        assert!(!ai.exists());
        assert!(!state.exists());
    }
}

#[test]
fn original_hardlink_ads_git_and_oversize_shapes_reject_before_output_creation() {
    enum Shape {
        HardLink,
        FileAds,
        DirectoryAds,
        Reparse,
        Git,
        Depth,
        Oversize,
    }
    for shape in [
        Shape::HardLink,
        Shape::FileAds,
        Shape::DirectoryAds,
        Shape::Reparse,
        Shape::Git,
        Shape::Depth,
        Shape::Oversize,
    ] {
        let fixture = Fixture::new();
        let (original, ai, state) = fixture.paths();
        fs::create_dir(&original).expect("create hostile original");
        match shape {
            Shape::HardLink => {
                let first = original.join("first.txt");
                fs::write(&first, b"ordinary").expect("hard-link source");
                fs::hard_link(first, original.join("second.txt")).expect("synthetic hard link");
            }
            Shape::FileAds => {
                let file = original.join("ordinary.txt");
                fs::write(&file, b"ordinary").expect("ADS base file");
                fs::write(format!("{}:synthetic", file.display()), b"named stream")
                    .expect("synthetic file ADS");
            }
            Shape::DirectoryAds => {
                let directory = original.join("ordinary-directory");
                fs::create_dir(&directory).expect("ADS base directory");
                fs::write(
                    format!("{}:synthetic", directory.display()),
                    b"named stream",
                )
                .expect("synthetic directory ADS");
            }
            Shape::Reparse => {
                let target = fixture.0.join("reparse-target");
                fs::create_dir(&target).expect("create reparse target");
                create_junction(&target, &original.join("reparse-directory"));
            }
            Shape::Git => fs::create_dir(original.join(".GiT")).expect("synthetic git boundary"),
            Shape::Depth => {
                let deepest = (0..65).fold(original.clone(), |path, _| path.join("d"));
                fs::create_dir_all(deepest).expect("create depth-65 fixture");
            }
            Shape::Oversize => {
                let file = File::create(original.join("oversized.txt")).expect("oversize file");
                file.set_len(4 * 1024 * 1024 + 1)
                    .expect("set bounded oversize length");
            }
        }
        assert_definite(
            create_session(&original, &ai, &state, ReviewProfile::StandardV2),
            Error::OriginalWorkspaceRejected,
        );
        assert!(!ai.exists());
        assert!(!state.exists());
    }
}

#[test]
fn preexisting_root_matrix_never_adopts_repairs_or_merges() {
    {
        let fixture = Fixture::new();
        let (original, ai, state) = fixture.paths();
        basic_original(&original);
        fs::create_dir(&ai).expect("unrelated AI root");
        assert_definite(
            create_session(&original, &ai, &state, ReviewProfile::StandardV2),
            Error::CreateConflict,
        );
        assert!(!state.exists());
    }
    {
        let fixture = Fixture::new();
        let (original, ai, state) = fixture.paths();
        basic_original(&original);
        fs::create_dir(&state).expect("incomplete state root");
        assert_manual(
            create_session(&original, &ai, &state, ReviewProfile::StandardV2),
            Error::CreateIncomplete,
        );
        assert!(!ai.exists());
    }
    {
        let fixture = Fixture::new();
        let (original, ai, state) = fixture.paths();
        basic_original(&original);
        fs::create_dir(&ai).expect("partial AI root");
        fs::create_dir(&state).expect("incomplete state root");
        assert_manual(
            create_session(&original, &ai, &state, ReviewProfile::StandardV2),
            Error::CreateIncomplete,
        );
    }
    {
        let fixture = Fixture::new();
        let (original, ai, state) = fixture.paths();
        basic_original(&original);
        fs::create_dir(&state).expect("unrelated state root");
        fs::write(state.join("unrelated.txt"), b"unrelated").expect("unrelated state leaf");
        assert!(create_session(&original, &ai, &state, ReviewProfile::StandardV2).is_err());
        assert!(!ai.exists());
    }
}

#[test]
fn identity_and_virtual_namespace_overlap_reject_before_new_root_creation() {
    enum Shape {
        OriginalIsAi,
        OriginalIsState,
        SameOutput,
        AiInsideOriginal,
        StateInsideOriginal,
        CaseOnlyOutputs,
    }
    for shape in [
        Shape::OriginalIsAi,
        Shape::OriginalIsState,
        Shape::SameOutput,
        Shape::AiInsideOriginal,
        Shape::StateInsideOriginal,
        Shape::CaseOnlyOutputs,
    ] {
        let fixture = Fixture::new();
        let (original, default_ai, default_state) = fixture.paths();
        basic_original(&original);
        let (ai, state, expected) = match shape {
            Shape::OriginalIsAi => (
                original.clone(),
                default_state,
                Error::UnsafeWorkspaceOverlap,
            ),
            Shape::OriginalIsState => (default_ai, original.clone(), Error::UnsafeWorkspaceOverlap),
            Shape::SameOutput => (
                default_ai.clone(),
                default_ai,
                Error::UnsafeWorkspaceOverlap,
            ),
            Shape::AiInsideOriginal => (
                original.join("nested-ai"),
                default_state,
                Error::UnsafeWorkspaceOverlap,
            ),
            Shape::StateInsideOriginal => (
                default_ai,
                original.join("nested-state"),
                Error::UnsafeWorkspaceOverlap,
            ),
            Shape::CaseOnlyOutputs => (
                fixture.0.join("CaseOnlyOutputLongName"),
                fixture.0.join("caseonlyoutputlongname"),
                Error::AliasNamespaceAmbiguous,
            ),
        };
        assert_definite(
            create_session(&original, &ai, &state, ReviewProfile::StandardV2),
            expected,
        );
        if ai != original {
            assert!(!ai.exists());
        }
        if state != original {
            assert!(!state.exists());
        }
    }
}

#[test]
fn interruption_disk_states_c0_through_c9_are_classified_without_cleanup() {
    // C0: a pre-publication failure is definite and creates neither root.
    {
        let fixture = Fixture::new();
        let (original, ai, state) = fixture.paths();
        fs::create_dir(&original).expect("C0 original");
        fs::write(original.join("invalid.txt"), b"__SAFECLONE_RT1_C0").expect("C0 invalid input");
        assert_definite(
            create_session(&original, &ai, &state, ReviewProfile::StandardV2),
            Error::OriginalWorkspaceRejected,
        );
        assert!(!ai.exists() && !state.exists());
    }

    // C1: the state root exists but session.lock was never completed.
    {
        let fixture = Fixture::new();
        let (original, ai, state) = fixture.paths();
        basic_original(&original);
        fs::create_dir(&state).expect("C1 state root");
        assert_manual(
            create_session(&original, &ai, &state, ReviewProfile::StandardV2),
            Error::CreateIncomplete,
        );
        assert!(state.exists() && !ai.exists());
    }

    // C2: a valid lock remains, but the AI root was never created.
    {
        let fixture = Fixture::new();
        let (original, ai, state, _) = create_basic_session(&fixture);
        fs::remove_file(generation_leaf(&state)).expect("remove C2 generation");
        fs::remove_dir_all(&ai).expect("remove controlled C2 AI tree");
        assert_manual(
            create_session(&original, &ai, &state, ReviewProfile::StandardV2),
            Error::CreateIncomplete,
        );
        assert!(state.join("session.lock").exists() && !ai.exists());
    }

    // C3 through C7 all have a completed lock and no generation authority;
    // empty, partial, written, complete-unverified, and verified-looking AI
    // shapes remain manual and are never repaired or removed.
    for checkpoint in ["C3", "C4", "C5-before", "C5-after", "C6", "C7"] {
        let fixture = Fixture::new();
        let (original, ai, state, _) = create_basic_session(&fixture);
        fs::remove_file(generation_leaf(&state)).expect("remove precommit generation");
        if matches!(checkpoint, "C3" | "C4" | "C5-before" | "C5-after") {
            clear_directory(&ai);
        }
        match checkpoint {
            "C4" => {
                fs::create_dir(ai.join("partial-directory")).expect("create C4 partial directory")
            }
            "C5-before" => File::create(ai.join("partial.txt"))
                .map(drop)
                .expect("create C5 empty file"),
            "C5-after" => fs::write(ai.join("partial.txt"), b"partial AI bytes")
                .expect("write C5 partial file"),
            _ => {}
        }
        assert_manual(
            create_session(&original, &ai, &state, ReviewProfile::StandardV2),
            Error::CreateIncomplete,
        );
        assert!(state.join("session.lock").exists(), "{checkpoint}");
        assert!(ai.exists(), "{checkpoint}");
    }

    // C8: the exact generation writer's complete pending shape is a retained
    // private orphan, never adopted as generation authority.
    {
        let fixture = Fixture::new();
        let (original, ai, state, _) = create_basic_session(&fixture);
        fs::rename(
            generation_leaf(&state),
            state.join(".pending-AAAAAAAAAAAAAAAAAAAAAAAAAA.scdp"),
        )
        .expect("convert controlled generation to C8 pending shape");
        assert_manual(
            create_session(&original, &ai, &state, ReviewProfile::StandardV2),
            Error::PrivateOrphansPresent,
        );
        assert!(state
            .join(".pending-AAAAAAAAAAAAAAAAAAAAAAAAAA.scdp")
            .exists());
        assert!(ai.exists());
    }

    // C9: once the exclusive rename is fully provable, generation 1 is the
    // authority and exact create replay is read-only.
    {
        let fixture = Fixture::new();
        let (original, ai, state, created) = create_basic_session(&fixture);
        let replay = create_session(&original, &ai, &state, ReviewProfile::StandardV2)
            .expect("C9 exact replay");
        assert!(replay.replayed);
        assert_eq!(replay.session_id, created.session_id);
        assert_eq!(generation_count(&state), 1);
    }
}

#[test]
fn replay_rejects_edited_or_missing_ai_without_appending_or_rebuilding() {
    let fixture = Fixture::new();
    let (original, ai, state, created) = create_basic_session(&fixture);
    assert_eq!(generation_count(&state), 1);
    let target = first_regular_file(&ai);
    let original_bytes = fs::read(&target).expect("read AI file");
    fs::write(&target, b"edited after create").expect("edit AI file");
    assert_definite(
        create_session(&original, &ai, &state, ReviewProfile::StandardV2),
        Error::WorkspaceVerificationFailed,
    );
    assert_eq!(generation_count(&state), 1);
    assert_eq!(
        fs::read(&target).expect("edited file remains"),
        b"edited after create"
    );

    fs::write(&target, original_bytes).expect("restore controlled fixture");
    let replay = create_session(&original, &ai, &state, ReviewProfile::StandardV2)
        .expect("restored exact replay");
    assert!(replay.replayed);
    assert_eq!(replay.session_id, created.session_id);
    assert_eq!(generation_count(&state), 1);

    fs::remove_dir_all(&ai).expect("remove controlled AI fixture");
    assert_definite(
        create_session(&original, &ai, &state, ReviewProfile::StandardV2),
        Error::CreateConflict,
    );
    assert!(!ai.exists());
    assert_eq!(generation_count(&state), 1);
}

#[test]
fn independent_ai_verifier_rejects_token_content_and_namespace_adversaries() {
    let fixture = Fixture::new();
    let (original, ai, state, _) = create_basic_session_with_token(&fixture);
    let target = first_regular_file(&ai);
    let pristine = fs::read(&target).expect("read pristine token file");
    let token = extract_token(&pristine);

    let mut cases = Vec::new();
    let mut malformed = pristine.clone();
    malformed.extend_from_slice(b"__SAFECLONE_RT1_IP_NOT-CANONICAL__");
    cases.push(malformed);
    let mut raw = pristine.clone();
    raw.extend_from_slice(b" fixture.user+test@example.invalid");
    cases.push(raw);
    let mut duplicate = pristine.clone();
    duplicate.push(b' ');
    duplicate.extend_from_slice(&token);
    cases.push(duplicate);
    let mut invalid_utf8 = pristine.clone();
    invalid_utf8.push(0xff);
    cases.push(invalid_utf8);
    let mut binary = pristine.clone();
    binary.push(0);
    cases.push(binary);
    let mut wrong_auth = pristine.clone();
    let auth = wrong_auth
        .windows(token.len())
        .position(|window| window == token)
        .expect("token position");
    let last_auth = auth + token.len() - 3;
    wrong_auth[last_auth] = if wrong_auth[last_auth] == b'A' {
        b'B'
    } else {
        b'A'
    };
    cases.push(wrong_auth);

    for bytes in cases {
        fs::write(&target, bytes).expect("write controlled adversarial bytes");
        assert_definite(
            create_session(&original, &ai, &state, ReviewProfile::StandardV2),
            Error::WorkspaceVerificationFailed,
        );
        assert_eq!(generation_count(&state), 1);
        fs::write(&target, &pristine).expect("restore pristine AI bytes");
    }

    let unexpected = ai.join("unexpected.txt");
    fs::write(&unexpected, b"ordinary").expect("unexpected file");
    assert_replay_workspace_reject(&original, &ai, &state);
    fs::remove_file(&unexpected).expect("remove unexpected file");

    let unexpected_directory = ai.join("unexpected-directory");
    fs::create_dir(&unexpected_directory).expect("unexpected directory");
    assert_replay_workspace_reject(&original, &ai, &state);
    fs::remove_dir(&unexpected_directory).expect("remove unexpected directory");

    let shadow = ai.join("opaque.bin");
    fs::write(&shadow, b"omitted shadow").expect("omitted shadow");
    assert_replay_workspace_reject(&original, &ai, &state);
    fs::remove_file(&shadow).expect("remove omitted shadow");

    let hardlink = ai.join("unexpected-hardlink.txt");
    fs::hard_link(&target, &hardlink).expect("AI hard link");
    assert_definite(
        create_session(&original, &ai, &state, ReviewProfile::StandardV2),
        Error::AliasNamespaceAmbiguous,
    );
    assert_eq!(generation_count(&state), 1);
    fs::remove_file(&hardlink).expect("remove AI hard link");

    let ads = format!("{}:synthetic", target.display());
    fs::write(&ads, b"AI named stream").expect("AI ADS");
    assert_replay_workspace_reject(&original, &ai, &state);
    fs::remove_file(&ads).expect("remove AI ADS");

    let reparse_target = fixture.0.join("ai-reparse-target");
    fs::create_dir(&reparse_target).expect("create AI reparse target");
    let reparse = ai.join("unexpected-reparse");
    create_junction(&reparse_target, &reparse);
    assert_definite(
        create_session(&original, &ai, &state, ReviewProfile::StandardV2),
        Error::UnsupportedAliasNamespace,
    );
    assert_eq!(generation_count(&state), 1);
    fs::remove_dir(&reparse).expect("remove AI reparse point");

    let missing = target.with_extension("missing-fixture");
    fs::rename(&target, &missing).expect("move AI file out of expected name");
    assert_replay_workspace_reject(&original, &ai, &state);
    fs::rename(&missing, &target).expect("restore AI file name");

    let replay = create_session(&original, &ai, &state, ReviewProfile::StandardV2)
        .expect("all controlled mutations restored");
    assert!(replay.replayed);
    assert_eq!(generation_count(&state), 1);
}

fn create_basic_session_with_token(fixture: &Fixture) -> (PathBuf, PathBuf, PathBuf, CreateReport) {
    let (original, ai, state) = fixture.paths();
    fs::create_dir(&original).expect("create token original");
    fs::write(
        original.join("address-192.0.2.10.txt"),
        b"contact fixture.user+test@example.invalid\n",
    )
    .expect("write token source");
    fs::write(original.join("opaque.bin"), b"opaque\0fixture").expect("write omitted source");
    let report = create_session(&original, &ai, &state, ReviewProfile::StandardV2)
        .expect("create token session");
    (original, ai, state, report)
}

fn assert_replay_workspace_reject(original: &Path, ai: &Path, state: &Path) {
    assert_definite(
        create_session(original, ai, state, ReviewProfile::StandardV2),
        Error::WorkspaceVerificationFailed,
    );
    assert_eq!(generation_count(state), 1);
}
