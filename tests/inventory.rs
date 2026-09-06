#![cfg(windows)]

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use safeclone::inventory::InventoryError;
use safeclone::pipeline::{self, InspectError, InspectRequest};
use safeclone::LocalityError;

#[path = "support/product_output.rs"]
mod product_output;

static NEXT_ID: AtomicU64 = AtomicU64::new(0);

fn inspect(source: &Path) -> Result<pipeline::InspectReport, InspectError> {
    pipeline::execute_inspect(InspectRequest {
        source: source.to_owned(),
    })
}

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new(label: &str) -> Self {
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "safeclone-integration-{label}-{}-{id}",
            std::process::id()
        ));
        fs::create_dir(&path).expect("create isolated test directory");
        Self(path)
    }

    fn source(&self) -> PathBuf {
        self.0.join("source")
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn synthetic_my_number(base: &str) -> String {
    assert_eq!(base.len(), 11);
    let sum = base
        .bytes()
        .rev()
        .enumerate()
        .map(|(index, byte)| {
            let n = index as u32 + 1;
            let weight = if n <= 6 { n + 1 } else { n - 5 };
            u32::from(byte - b'0') * weight
        })
        .sum::<u32>();
    let remainder = sum % 11;
    let check = if remainder <= 1 { 0 } else { 11 - remainder };
    format!("{base}{check}")
}

fn synthetic_corporate_number(base: &str) -> String {
    assert_eq!(base.len(), 12);
    let sum = base
        .bytes()
        .rev()
        .enumerate()
        .map(|(index, byte)| {
            let weight = if index % 2 == 0 { 1 } else { 2 };
            u32::from(byte - b'0') * weight
        })
        .sum::<u32>();
    format!("{}{base}", 9 - (sum % 9))
}

fn synthetic_github_token(prefix: &str, body_len: usize) -> String {
    const ALPHABET: &[u8] = b"A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0UvWxYz_";
    let body = (0..body_len)
        .map(|index| ALPHABET[index % ALPHABET.len()])
        .collect::<Vec<_>>();
    format!(
        "{prefix}{}",
        String::from_utf8(body).expect("ASCII fixture")
    )
}

#[test]
fn inventories_ordinary_nested_directory_without_reading_content() {
    let fixture = TestDirectory::new("ordinary");
    let source = fixture.source();
    fs::create_dir(&source).expect("create source");
    fs::create_dir(source.join("nested")).expect("create nested directory");
    fs::write(source.join("main.rs"), b"sensitive source bytes").expect("write fixture");
    fs::write(source.join("nested/data.custom"), b"unknown").expect("write fixture");

    let before = fs::read(source.join("main.rs")).expect("read fixture before inventory");
    let inventory = inspect(&source).expect("inventory succeeds").inventory;
    let after = fs::read(source.join("main.rs")).expect("read fixture after inventory");

    assert_eq!(before, after);
    assert_eq!(inventory.total_entries, 3);
    assert_eq!(inventory.directories, 1);
    assert_eq!(inventory.regular_files, 2);
    assert_eq!(inventory.text_or_code_candidates, 1);
    assert_eq!(inventory.unknown_files, 1);
}

#[test]
fn git_subtree_is_counted_once_and_not_traversed() {
    let fixture = TestDirectory::new("git");
    let source = fixture.source();
    fs::create_dir(&source).expect("create source");
    fs::create_dir(source.join(".git")).expect("create git directory");
    fs::write(source.join(".git/secret.rs"), b"must not be visited").expect("write fixture");

    let inventory = inspect(&source).expect("inventory succeeds").inventory;

    assert_eq!(inventory.total_entries, 1);
    assert_eq!(inventory.git_metadata_entries, 1);
    assert_eq!(inventory.directories, 0);
    assert_eq!(inventory.regular_files, 0);
}

#[test]
fn unknown_and_unsupported_files_remain_counted() {
    let fixture = TestDirectory::new("unsupported");
    let source = fixture.source();
    fs::create_dir(&source).expect("create source");
    fs::write(source.join("report.pdf"), b"not parsed").expect("write fixture");
    fs::write(source.join("value.unknown"), b"not parsed").expect("write fixture");

    let inventory = inspect(&source).expect("inventory succeeds").inventory;

    assert_eq!(inventory.regular_files, 2);
    assert_eq!(inventory.unsupported_files, 1);
    assert_eq!(inventory.unknown_files, 1);
    assert_eq!(inventory.text_or_code_candidates, 0);
}

#[test]
fn depth_limit_breach_fails_closed() {
    let fixture = TestDirectory::new("depth-limit");
    let source = fixture.source();
    fs::create_dir(&source).expect("create source");
    let mut cursor = source.clone();
    for depth in 0..=64 {
        cursor = cursor.join(format!("child-{depth}"));
        fs::create_dir(&cursor).expect("create bounded nested directory");
    }

    assert_eq!(
        inspect(&source),
        Err(InspectError::Inventory(InventoryError::DepthLimitExceeded))
    );
}

#[test]
fn cli_report_contains_counts_but_not_the_raw_source_path() {
    let fixture = TestDirectory::new("raw-path-must-not-appear");
    let source = fixture.source();
    fs::create_dir(&source).expect("create source");
    let raw_email = "fixture.user+test@example.invalid";
    let raw_phone = "+12345678";
    let raw_jp_phone = "090-0000-0000";
    let raw_ip = "192.0.2.10";
    let raw_postal = "123-4567";
    let raw_my_number = synthetic_my_number("10000000000");
    let raw_corporate_number = synthetic_corporate_number("102030405060");
    let raw_content = format!(
        "password = \"N0nLive_Fixture_4A7c9E2b\"\n{raw_email}\n{raw_phone}\n{raw_jp_phone}\n{raw_ip}\n〒{raw_postal}\n{raw_my_number}\n{raw_corporate_number}"
    );
    fs::write(source.join("secrets.rs"), &raw_content).expect("write fixture");
    fs::write(source.join("confidential-report.pdf"), b"not read").expect("write fixture");
    fs::write(source.join("private-value.custom"), b"not read").expect("write fixture");
    fs::create_dir(source.join(".git")).expect("create git metadata directory");
    fs::write(source.join(".git/hidden-secret.rs"), b"must not be visited")
        .expect("write git fixture");
    let root_entries_before = fs::read_dir(&fixture.0).expect("list root before").count();
    let source_entries_before = fs::read_dir(&source).expect("list source before").count();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let code = safeclone::cli::run(
        ["inspect".into(), source.clone().into_os_string()],
        &mut stdout,
        &mut stderr,
    );

    assert_eq!(code, std::process::ExitCode::SUCCESS);
    let report = String::from_utf8(stdout).expect("report is UTF-8");
    product_output::assert_product_output(&report);
    assert!(report.contains("inventory_status=PASS"));
    assert!(report.contains("policy_id=default-strict-v1"));
    assert!(report.contains("inspection_only=true"));
    assert!(report.contains("sanitization_performed=false"));
    assert!(report.contains("text_or_code_candidates=1"));
    assert!(report.contains("unsupported_files=1"));
    assert!(report.contains("unknown_files=1"));
    assert!(report.contains("path_component_scan_candidates=3"));
    assert!(report.contains("path_component_uninspectable=0"));
    assert!(report.contains("path_component_components_with_findings=0"));
    assert!(report.contains("path_component_secret_findings=0"));
    assert!(report.contains("path_component_sensitive_findings=0"));
    assert!(report.contains("path_component_directory_components_with_findings=0"));
    assert!(report.contains("path_component_file_components_with_findings=0"));
    assert!(report.contains("filename_scan_candidates=3"));
    assert!(report.contains("filename_findings=1"));
    assert!(report.contains("filename_files_with_findings=1"));
    assert!(report.contains("filename_uninspectable=0"));
    assert!(report.contains("filename_environment_findings=0"));
    assert!(report.contains("filename_private_key_findings=0"));
    assert!(report.contains("filename_credential_findings=1"));
    assert!(report.contains("filename_auth_config_findings=0"));
    assert!(report.contains("policy_regular_files=3"));
    assert!(report.contains("decision_allow=0"));
    assert!(report.contains("decision_transform=1"));
    assert!(report.contains("decision_structure_only=0"));
    assert!(report.contains("decision_omit=2"));
    assert!(report.contains("decision_block=0"));
    assert!(report.contains("structural_excluded_link_like=0"));
    assert!(report.contains("structural_excluded_git=1"));
    assert!(report.contains("structural_excluded_special=0"));
    assert!(report.contains("content_candidates=1"));
    assert!(report.contains("content_readable_text=1"));
    assert!(report.contains("content_binary_like=0"));
    assert!(report.contains("content_invalid_utf8=0"));
    assert!(report.contains("content_oversized=0"));
    assert!(report.contains("content_hard_linked=0"));
    assert!(report.contains(&format!("content_bytes_inspected={}", raw_content.len())));
    assert!(report.contains("secret_scan_candidates=1"));
    assert!(report.contains("secret_findings=1"));
    assert!(report.contains("secret_files_with_findings=1"));
    assert!(report.contains("sensitive_scan_candidates=1"));
    assert!(report.contains("sensitive_findings=7"));
    assert!(report.contains("sensitive_files_with_findings=1"));
    assert!(report.contains("sensitive_email_findings=1"));
    assert!(report.contains("sensitive_phone_findings=1"));
    assert!(report.contains("sensitive_jp_phone_findings=1"));
    assert!(report.contains("sensitive_ip_findings=1"));
    assert!(report.contains("sensitive_jp_postal_findings=1"));
    assert!(report.contains("sensitive_my_number_candidate_findings=1"));
    assert!(report.contains("sensitive_corporate_number_candidate_findings=1"));
    assert!(!report.contains("secret_scan_status="));
    assert!(!report.contains("filename_status=PASS"));
    assert!(!report.contains("sensitive_status=PASS"));
    assert!(!report.contains("pii_status=PASS"));
    assert!(!report.contains("policy_status=PASS"));
    assert!(!report.contains("SAFE"));
    assert!(!report.contains("AI_SAFE"));
    assert!(!report.contains(source.to_string_lossy().as_ref()));
    for raw_name in [
        "secrets.rs",
        "confidential-report.pdf",
        "private-value.custom",
        "hidden-secret.rs",
    ] {
        assert!(!report.contains(raw_name));
    }
    for raw_value in [
        raw_content.as_str(),
        raw_email,
        raw_phone,
        raw_jp_phone,
        raw_ip,
        raw_postal,
        raw_my_number.as_str(),
        raw_corporate_number.as_str(),
    ] {
        assert!(!report.contains(raw_value));
    }
    assert_eq!(
        fs::read_to_string(source.join("secrets.rs")).expect("read source after inspection"),
        raw_content,
        "content inspection must not modify the source"
    );
    assert_eq!(
        fs::read_dir(&fixture.0).expect("list root after").count(),
        root_entries_before,
        "inspection must not create filesystem output"
    );
    assert_eq!(
        fs::read_dir(&source).expect("list source after").count(),
        source_entries_before,
        "inspection must not persist detector output"
    );
    assert!(stderr.is_empty());
}

#[test]
fn cli_reports_hard_links_without_exposing_raw_values() {
    let fixture = TestDirectory::new("hard-link-raw-values");
    let source = fixture.source();
    let outside = fixture.0.join("outside");
    fs::create_dir(&source).expect("create source");
    fs::create_dir(&outside).expect("create outside");
    let raw_name = "credentials.rs";
    let raw_email = "hard.linked@example.invalid";
    let raw_phone = "+81 90-1234-5678";
    let raw_jp_phone = "050-0000-0000";
    let raw_ip = "2001:db8::40";
    let raw_postal = "123-4567";
    let raw_my_number = synthetic_my_number("10000000000");
    let raw_corporate_number = synthetic_corporate_number("102030405060");
    let raw_content = format!(
        "password = \"HardLinked_N0nLive_4A7c9E2b\"\n{raw_email}\n{raw_phone}\n{raw_jp_phone}\n{raw_ip}\n{raw_postal}\n{raw_my_number}\n{raw_corporate_number}"
    );
    let external = outside.join("external-secret.rs");
    fs::write(&external, &raw_content).expect("write external fixture");
    fs::hard_link(&external, source.join(raw_name)).expect("create hard link");
    let source_before = fs::read(source.join(raw_name)).expect("read source before");
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let code = safeclone::cli::run(
        ["inspect".into(), source.clone().into_os_string()],
        &mut stdout,
        &mut stderr,
    );

    assert_eq!(code, std::process::ExitCode::SUCCESS);
    let report = String::from_utf8(stdout).expect("report is UTF-8");
    let error = String::from_utf8(stderr).expect("error is UTF-8");
    assert!(report.contains("content_candidates=1"));
    assert!(report.contains("content_readable_text=0"));
    assert!(report.contains("content_hard_linked=1"));
    assert!(report.contains("content_bytes_inspected=0"));
    assert!(report.contains("effective_transform=0"));
    assert!(report.contains("effective_omit=1"));
    assert!(report.contains("effective_unresolved=0"));
    assert!(report.contains("path_component_scan_candidates=1"));
    assert!(report.contains("path_component_uninspectable=0"));
    assert!(report.contains("path_component_components_with_findings=0"));
    assert!(report.contains("path_component_secret_findings=0"));
    assert!(report.contains("path_component_sensitive_findings=0"));
    assert!(report.contains("filename_scan_candidates=1"));
    assert!(report.contains("filename_findings=1"));
    assert!(report.contains("filename_files_with_findings=1"));
    assert!(report.contains("filename_uninspectable=0"));
    assert!(report.contains("filename_credential_findings=1"));
    assert!(report.contains("secret_scan_candidates=0"));
    assert!(report.contains("secret_findings=0"));
    assert!(report.contains("secret_files_with_findings=0"));
    assert!(report.contains("sensitive_scan_candidates=0"));
    assert!(report.contains("sensitive_findings=0"));
    assert!(report.contains("sensitive_files_with_findings=0"));
    assert!(report.contains("sensitive_jp_phone_findings=0"));
    assert!(report.contains("sensitive_jp_postal_findings=0"));
    assert!(report.contains("sensitive_my_number_candidate_findings=0"));
    assert!(report.contains("sensitive_corporate_number_candidate_findings=0"));
    assert!(report.contains("decision_transform=1"));
    assert!(!report.contains(raw_name));
    for raw_value in [
        raw_content.as_str(),
        raw_email,
        raw_phone,
        raw_jp_phone,
        raw_ip,
        raw_postal,
        raw_my_number.as_str(),
        raw_corporate_number.as_str(),
    ] {
        assert!(!report.contains(raw_value));
        assert!(!error.contains(raw_value));
    }
    assert!(!report.contains(source.to_string_lossy().as_ref()));
    assert!(!error.contains(raw_name));
    assert!(!error.contains(source.to_string_lossy().as_ref()));
    assert_eq!(
        fs::read(source.join(raw_name)).expect("read source after"),
        source_before,
        "inspection must not modify the hard-linked source entry"
    );
}

#[cfg(unix)]
#[test]
fn cli_counts_non_utf8_basename_without_lossy_scanning_or_reporting() {
    use std::os::unix::ffi::OsStringExt;

    let fixture = TestDirectory::new("non-utf8-basename");
    let source = fixture.source();
    fs::create_dir(&source).expect("create source");
    let raw_visible_prefix = ".env.invalid-";
    let raw_name = std::ffi::OsString::from_vec(b".env.invalid-\xff".to_vec());
    let path = source.join(&raw_name);
    fs::write(&path, b"source bytes remain unchanged").expect("write non-UTF-8 fixture");
    let source_before = fs::read(&path).expect("read source before");
    let entries_before = fs::read_dir(&source).expect("list source before").count();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let code = safeclone::cli::run(
        ["inspect".into(), source.clone().into_os_string()],
        &mut stdout,
        &mut stderr,
    );

    assert_eq!(code, std::process::ExitCode::SUCCESS);
    let report = String::from_utf8(stdout).expect("report is UTF-8");
    let error = String::from_utf8(stderr).expect("error is UTF-8");
    assert!(report.contains("regular_files=1"));
    assert!(report.contains("unknown_files=1"));
    assert!(report.contains("path_component_scan_candidates=0"));
    assert!(report.contains("path_component_uninspectable=1"));
    assert!(report.contains("path_component_components_with_findings=0"));
    assert!(report.contains("path_component_secret_findings=0"));
    assert!(report.contains("path_component_sensitive_findings=0"));
    assert!(report.contains("filename_scan_candidates=0"));
    assert!(report.contains("filename_uninspectable=1"));
    assert!(report.contains("filename_findings=0"));
    assert!(report.contains("filename_files_with_findings=0"));
    assert!(report.contains("decision_omit=1"));
    assert!(report.contains("effective_transform=0"));
    assert!(report.contains("effective_omit=1"));
    assert!(report.contains("effective_unresolved=0"));
    assert!(!report.contains(raw_visible_prefix));
    assert!(!report.contains('\u{fffd}'));
    assert!(!error.contains(raw_visible_prefix));
    assert!(!error.contains('\u{fffd}'));
    assert!(!report.contains(source.to_string_lossy().as_ref()));
    assert_eq!(fs::read(&path).expect("read source after"), source_before);
    assert_eq!(
        fs::read_dir(&source).expect("list source after").count(),
        entries_before,
        "inspection must not persist filename evidence"
    );
}

#[test]
fn cli_reports_path_component_evidence_without_policy_refinement() {
    let fixture = TestDirectory::new("path-component-evidence");
    let source = fixture.source();
    let customer = source.join("customer");
    let email_directory = customer.join("fixture.user@example.invalid");
    fs::create_dir(&source).expect("create source");
    fs::create_dir(&customer).expect("create customer directory");
    fs::create_dir(&email_directory).expect("create email directory");

    let raw_phone_name = "report_090-1234-5678.md";
    let raw_my_number = synthetic_my_number("10000000000");
    let raw_my_number_name = format!("{raw_my_number}.txt");
    let raw_provider_name = "ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8";
    let raw_filename_name = "credentials.key";
    fs::write(email_directory.join(raw_phone_name), b"").expect("write phone fixture");
    fs::write(email_directory.join(&raw_my_number_name), b"").expect("write identifier fixture");
    fs::write(email_directory.join(raw_provider_name), b"not parsed")
        .expect("write provider-like fixture");
    fs::write(email_directory.join("ordinary.rs"), b"").expect("write ordinary fixture");
    fs::write(email_directory.join(raw_filename_name), b"not parsed")
        .expect("write filename fixture");
    fs::create_dir(source.join(".git")).expect("create git directory");
    fs::write(
        source.join(".git/hidden@example.invalid"),
        b"must not be visited",
    )
    .expect("write git fixture");

    let source_entries_before = fs::read_dir(&source).expect("list source before").count();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let code = safeclone::cli::run(
        ["inspect".into(), source.clone().into_os_string()],
        &mut stdout,
        &mut stderr,
    );

    assert_eq!(code, std::process::ExitCode::SUCCESS);
    let report = String::from_utf8(stdout).expect("report is UTF-8");
    assert!(stderr.is_empty());
    product_output::assert_product_output(&report);
    assert!(report.contains("path_component_scan_candidates=7"));
    assert!(report.contains("path_component_uninspectable=0"));
    assert!(report.contains("path_component_components_with_findings=4"));
    assert!(report.contains("path_component_secret_findings=1"));
    assert!(report.contains("path_component_sensitive_findings=3"));
    assert!(report.contains("path_component_directory_components_with_findings=1"));
    assert!(report.contains("path_component_file_components_with_findings=3"));
    assert!(report.contains("filename_scan_candidates=5"));
    assert!(report.contains("filename_findings=2"));
    assert!(report.contains("filename_private_key_findings=1"));
    assert!(report.contains("filename_credential_findings=1"));
    assert!(report.contains("content_candidates=3"));
    assert!(report.contains("unknown_files=2"));
    assert!(report.contains("git_metadata_entries=1"));
    assert!(report.contains("effective_policy_plan=default-strict-v1"));
    assert!(report.contains("effective_transform=3"));
    assert!(report.contains("effective_omit=2"));
    assert!(report.contains("effective_unresolved=0"));
    assert!(report.contains("inspection_only=true"));
    assert!(report.contains("sanitization_performed=false"));
    for raw in [
        "fixture.user@example.invalid",
        raw_phone_name,
        raw_my_number_name.as_str(),
        raw_provider_name,
        raw_filename_name,
        "hidden@example.invalid",
    ] {
        assert!(!report.contains(raw), "raw component leaked: {raw}");
    }
    assert_eq!(
        fs::read_dir(&source).expect("list source after").count(),
        source_entries_before,
        "path evidence must not persist output"
    );
}

#[test]
fn cli_reports_github_token_family_in_content_and_path_evidence() {
    let fixture = TestDirectory::new("github-token-family");
    let source = fixture.source();
    let app_server = synthetic_github_token("ghs_", 36);
    let oauth = synthetic_github_token("gho_", 36);
    let fine_grained = synthetic_github_token("github_pat_", 82);
    let refresh = synthetic_github_token("ghr_", 36);
    fs::create_dir(&source).expect("create source");
    let token_directory = source.join(&app_server);
    fs::create_dir(&token_directory).expect("create token directory");
    for token in [&oauth, &fine_grained, &refresh] {
        fs::write(
            token_directory.join(format!("{token}.rs")),
            token.as_bytes(),
        )
        .expect("write synthetic token fixture");
    }
    let source_entries_before = fs::read_dir(&source).expect("list source before").count();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let code = safeclone::cli::run(
        ["inspect".into(), source.clone().into_os_string()],
        &mut stdout,
        &mut stderr,
    );

    assert_eq!(code, std::process::ExitCode::SUCCESS);
    let report = String::from_utf8(stdout).expect("report is UTF-8");
    assert!(stderr.is_empty());
    assert!(report.contains("path_component_scan_candidates=4"));
    assert!(report.contains("path_component_secret_findings=4"));
    assert!(report.contains("path_component_sensitive_findings=0"));
    assert!(report.contains("path_component_components_with_findings=4"));
    assert!(report.contains("path_component_directory_components_with_findings=1"));
    assert!(report.contains("path_component_file_components_with_findings=3"));
    assert!(report.contains("effective_transform=3"));
    assert!(report.contains("effective_omit=0"));
    assert!(report.contains("effective_unresolved=0"));
    assert!(report.contains("secret_scan_candidates=3"));
    assert!(report.contains("secret_findings=3"));
    assert!(report.contains("secret_files_with_findings=3"));
    assert!(report.contains("inspection_only=true"));
    assert!(report.contains("sanitization_performed=false"));
    for raw_token in [&app_server, &oauth, &fine_grained, &refresh] {
        assert!(!report.contains(raw_token), "raw token leaked: {raw_token}");
        assert!(!String::from_utf8_lossy(&stderr).contains(raw_token));
    }
    assert_eq!(
        fs::read_dir(&source).expect("list source after").count(),
        source_entries_before,
        "token evidence must not persist output"
    );
}

#[test]
fn cli_excludes_source_root_basename_from_path_evidence() {
    let fixture = TestDirectory::new("source-root-component");
    let source = fixture.0.join("fixture.user@example.invalid");
    fs::create_dir(&source).expect("create sensitive-looking source root");
    fs::write(source.join("ordinary.rs"), b"").expect("write ordinary fixture");
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let code = safeclone::cli::run(
        ["inspect".into(), source.clone().into_os_string()],
        &mut stdout,
        &mut stderr,
    );

    assert_eq!(code, std::process::ExitCode::SUCCESS);
    let report = String::from_utf8(stdout).expect("report is UTF-8");
    assert!(stderr.is_empty());
    assert!(report.contains("path_component_scan_candidates=1"));
    assert!(report.contains("path_component_uninspectable=0"));
    assert!(report.contains("path_component_components_with_findings=0"));
    assert!(!report.contains("fixture.user@example.invalid"));
}

#[cfg(unix)]
#[test]
fn cli_counts_non_utf8_directory_component_without_lossy_scanning() {
    use std::os::unix::ffi::OsStringExt;

    let fixture = TestDirectory::new("non-utf8-directory-component");
    let source = fixture.source();
    fs::create_dir(&source).expect("create source");
    let raw_visible_prefix = "fixture-";
    let raw_directory = std::ffi::OsString::from_vec(b"fixture-\xff@example.invalid".to_vec());
    let directory = source.join(&raw_directory);
    fs::create_dir(&directory).expect("create non-UTF-8 directory");
    fs::write(directory.join("ordinary.rs"), b"").expect("write nested fixture");
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let code = safeclone::cli::run(
        ["inspect".into(), source.clone().into_os_string()],
        &mut stdout,
        &mut stderr,
    );

    assert_eq!(code, std::process::ExitCode::SUCCESS);
    let report = String::from_utf8(stdout).expect("report is UTF-8");
    let error = String::from_utf8(stderr).expect("error is UTF-8");
    assert!(report.contains("path_component_scan_candidates=1"));
    assert!(report.contains("path_component_uninspectable=1"));
    assert!(report.contains("path_component_components_with_findings=0"));
    assert!(report.contains("effective_transform=1"));
    assert!(report.contains("effective_omit=0"));
    assert!(report.contains("effective_unresolved=1"));
    assert!(!report.contains(raw_visible_prefix));
    assert!(!report.contains('\u{fffd}'));
    assert!(!error.contains(raw_visible_prefix));
    assert!(!error.contains('\u{fffd}'));
}

#[test]
fn cli_secret_limit_failure_emits_no_raw_or_partial_report() {
    let fixture = TestDirectory::new("secret-limit-raw-values");
    let source = fixture.source();
    fs::create_dir(&source).expect("create source");
    let raw_name = "limit-triggering-secret-name.rs";
    let raw_secret = "N0nLive_Fixture_4A7c9E2b";
    let raw_content = format!("password = \"{raw_secret}\"\n").repeat(257);
    fs::write(source.join(raw_name), &raw_content).expect("write bounded limit fixture");
    let source_before = fs::read(source.join(raw_name)).expect("read source before");
    let entries_before = fs::read_dir(&source).expect("list source before").count();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let code = safeclone::cli::run(
        ["inspect".into(), source.clone().into_os_string()],
        &mut stdout,
        &mut stderr,
    );

    assert_eq!(code, std::process::ExitCode::from(2));
    assert!(
        stdout.is_empty(),
        "a failed run must not emit a partial report"
    );
    let error = String::from_utf8(stderr).expect("error is UTF-8");
    assert!(error.contains("secret finding per-file limit exceeded"));
    assert!(!error.contains(raw_name));
    assert!(!error.contains(raw_secret));
    assert!(!error.contains(source.to_string_lossy().as_ref()));
    assert_eq!(
        fs::read(source.join(raw_name)).expect("read source after"),
        source_before,
        "failed detection must not modify the source"
    );
    assert_eq!(
        fs::read_dir(&source).expect("list source after").count(),
        entries_before,
        "failed detection must not persist output"
    );
}

#[test]
fn cli_sensitive_limit_failure_emits_no_raw_or_partial_report() {
    let fixture = TestDirectory::new("sensitive-limit-raw-values");
    let source = fixture.source();
    fs::create_dir(&source).expect("create source");
    let raw_name = "limit-triggering-sensitive-name.rs";
    let raw_identifier = "fixture.user+limit@example.invalid";
    let raw_content = format!("{raw_identifier}\n").repeat(16_385);
    fs::write(source.join(raw_name), &raw_content).expect("write bounded limit fixture");
    let source_before = fs::read(source.join(raw_name)).expect("read source before");
    let entries_before = fs::read_dir(&source).expect("list source before").count();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let code = safeclone::cli::run(
        ["inspect".into(), source.clone().into_os_string()],
        &mut stdout,
        &mut stderr,
    );

    assert_eq!(code, std::process::ExitCode::from(2));
    assert!(
        stdout.is_empty(),
        "a failed run must not emit a partial report"
    );
    let error = String::from_utf8(stderr).expect("error is UTF-8");
    assert!(error.contains("sensitive identifier finding per-file limit exceeded"));
    assert!(!error.contains(raw_name));
    assert!(!error.contains(raw_identifier));
    assert!(!error.contains(source.to_string_lossy().as_ref()));
    assert_eq!(
        fs::read(source.join(raw_name)).expect("read source after"),
        source_before,
        "failed detection must not modify the source"
    );
    assert_eq!(
        fs::read_dir(&source).expect("list source after").count(),
        entries_before,
        "failed detection must not persist output"
    );
}

#[test]
fn failed_inventory_does_not_emit_a_policy_plan() {
    let fixture = TestDirectory::new("failed-inventory-no-plan");
    let source = fixture.0.join("missing-sensitive-source");
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let code = safeclone::cli::run(
        ["inspect".into(), source.clone().into_os_string()],
        &mut stdout,
        &mut stderr,
    );

    assert_eq!(code, std::process::ExitCode::from(2));
    assert!(stdout.is_empty());
    let error = String::from_utf8(stderr).expect("error is UTF-8");
    assert!(!error.contains("policy_id="));
    assert!(!error.contains("inventory_status=PASS"));
    assert!(!error.contains(source.to_string_lossy().as_ref()));
    assert!(!error.contains("missing-sensitive-source"));
}

#[cfg(unix)]
#[test]
fn unix_directory_symlink_is_not_followed_and_root_symlink_is_rejected() {
    use std::os::unix::fs::symlink;

    let fixture = TestDirectory::new("unix-symlink");
    let source = fixture.source();
    let outside = fixture.0.join("outside");
    fs::create_dir(&source).expect("create source");
    fs::create_dir(&outside).expect("create outside");
    fs::write(outside.join("secret.rs"), b"must not be visited").expect("write fixture");
    symlink(&outside, source.join("linked")).expect("create nested symlink");

    let inventory = inspect(&source).expect("inventory succeeds").inventory;
    assert_eq!(inventory.link_like_entries, 1);
    assert_eq!(inventory.regular_files, 0);

    let root_link = fixture.0.join("root-link");
    symlink(&source, &root_link).expect("create root symlink");
    assert_eq!(
        inspect(&root_link),
        Err(InspectError::Locality(LocalityError::CapabilityOpenFailed))
    );

    let parent_link = fixture.0.join("parent-link");
    symlink(&fixture.0, &parent_link).expect("create parent symlink");
    assert_eq!(
        inspect(&parent_link.join("source")),
        Err(InspectError::Locality(LocalityError::CapabilityOpenFailed))
    );
}

#[cfg(windows)]
fn create_junction(target: &Path, junction: &Path) {
    let status = std::process::Command::new("cmd")
        .args(["/c", "mklink", "/J"])
        .arg(junction)
        .arg(target)
        .status()
        .expect("run mklink");
    assert!(status.success(), "create junction fixture");
}

#[cfg(windows)]
#[test]
fn windows_junction_is_not_followed_and_root_junction_is_rejected() {
    let fixture = TestDirectory::new("windows-junction");
    let source = fixture.source();
    let outside = fixture.0.join("outside");
    fs::create_dir(&source).expect("create source");
    fs::create_dir(&outside).expect("create outside");
    fs::write(outside.join("secret.rs"), b"must not be visited").expect("write fixture");

    let nested = source.join("linked");
    create_junction(&outside, &nested);
    let inventory = inspect(&source).expect("inventory succeeds").inventory;
    assert_eq!(inventory.link_like_entries, 1);
    assert_eq!(inventory.regular_files, 0);
    fs::remove_dir(&nested).expect("remove nested junction without following it");

    let root_junction = fixture.0.join("root-junction");
    create_junction(&source, &root_junction);
    assert_eq!(
        inspect(&root_junction),
        Err(InspectError::Locality(LocalityError::CapabilityOpenFailed))
    );
    fs::remove_dir(&root_junction).expect("remove root junction without following it");

    let parent_junction = fixture.0.join("parent-junction");
    create_junction(&fixture.0, &parent_junction);
    assert_eq!(
        inspect(&parent_junction.join("source")),
        Err(InspectError::Locality(LocalityError::CapabilityOpenFailed))
    );
    fs::remove_dir(&parent_junction).expect("remove parent junction without following it");
}
