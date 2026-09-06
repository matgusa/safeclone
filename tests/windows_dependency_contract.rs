//! Lint-like tripwires for the Windows dependency boundary, not a Rust parser or
//! substitute for auditing changed APIs, dependency sources, and release std.
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use regex::Regex;
use sha2::{Digest, Sha256};

fn sources(root: &Path, directory: &Path, result: &mut BTreeMap<String, String>) {
    for entry in fs::read_dir(directory).unwrap() {
        let entry = entry.unwrap();
        assert!(!entry.file_type().unwrap().is_symlink());
        if entry.file_type().unwrap().is_dir() {
            sources(root, &entry.path(), result);
        } else if entry.path().extension().is_some_and(|ext| ext == "rs") {
            let path = entry.path();
            result.insert(
                path.strip_prefix(root)
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .replace('\\', "/"),
                fs::read_to_string(path).unwrap().replace("\r\n", "\n"),
            );
        }
    }
}

#[test]
fn windows_imports_and_locked_dependencies_require_an_explicit_reaudit() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = BTreeMap::new();
    sources(root, &root.join("src"), &mut files);
    let imports = Regex::new(r"(?s)\buse windows_sys::[^;]+;").unwrap();
    let mut inventory = String::new();
    for (path, source) in &files {
        for import in imports.find_iter(source) {
            let normalized: String = import.as_str().split_whitespace().collect();
            inventory.push_str(&format!("{path}: {normalized}\n"));
        }
    }
    assert_eq!(
        inventory,
        include_str!("support/windows_imports.txt").replace("\r\n", "\n"),
        "Windows binding change requires an edition/encoding audit, not blind snapshot renewal"
    );
    let mut digest = Sha256::new();
    for file in ["Cargo.toml", "Cargo.lock"] {
        digest.update(
            fs::read_to_string(root.join(file))
                .unwrap()
                .replace("\r\n", "\n"),
        );
    }
    assert_eq!(
        digest
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>(),
        include_str!("support/dependency_digest.txt").trim(),
        "dependency/feature changes require transitive Windows-boundary requalification"
    );
    assert!(
        !root.join("build.rs").exists(),
        "new build logic requires review"
    );
}

#[test]
fn native_argument_and_path_boundaries_forbid_edition_ansi_and_lossy_regressions() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = BTreeMap::new();
    sources(root, &root.join("src"), &mut files);
    // Scan complete sources, including tests, for new edition/ACP/FFI entry
    // points. The explicit code-page fixture probes belong only in tests/.
    let forbidden = Regex::new(concat!(
        r#"\bargs\s*\(\s*\)|\b(GetACP|GetOEMCP|CP_ACP|CP_OEMCP|CP_THREAD_ACP|"#,
        r#"MultiByteToWideChar|WideCharToMultiByte|CString|CStr|setlocale|"#,
        r#"GetProductInfo|EditionID|RtlGetVersion|VerifyVersionInfo[AW]|"#,
        r#"GetLocaleInfo[AWEx]*|CompareStringEx|LCMapString[AWEx]*|"#,
        r#"LoadLibrary[AWEx]*|GetProcAddress)\b|extern\s*\"(system|C)\"\s*\{"#,
        r#"|#\s*\[\s*link\b|\bwindows_link::|\b[A-Z][a-z][A-Za-z0-9]*A\s*\("#,
    ))
    .unwrap();
    for regression in [
        "std::env::args()",
        "env :: args ( )",
        "GetProductInfo(",
        "GetACP()",
        "CreateFileA(",
        "CString::new(path)",
        "MultiByteToWideChar(CP_ACP,",
        "extern \"system\" {",
    ] {
        assert!(forbidden.is_match(regression), "guard missed {regression}");
    }
    let lossy =
        Regex::new(r"\b(to_string_lossy|from_utf8_lossy|from_utf16_lossy|into_string)\s*\(")
            .unwrap();
    let reviewed_test_uses = BTreeMap::from([
        ("src/cli.rs", 3),
        ("src/pipeline.rs", 2),
        ("src/staging_tree.rs", 1),
        ("src/roundtrip/approve.rs", 2),
        ("src/roundtrip/close.rs", 1),
        ("src/roundtrip/create.rs", 2),
        ("src/roundtrip/reconstruct.rs", 2),
        ("src/roundtrip/review.rs", 6),
    ]);
    for (path, source) in &files {
        assert!(
            !forbidden.is_match(source),
            "new edition/encoding/FFI surface: {path}"
        );
        let occurrences: Vec<_> = lossy.find_iter(source).collect();
        assert_eq!(
            occurrences.len(),
            *reviewed_test_uses.get(path.as_str()).unwrap_or(&0),
            "lossy conversion surface changed: {path}"
        );
        for occurrence in occurrences {
            let test_start = source.find("mod tests {").expect("reviewed test-only use");
            assert!(
                occurrence.start() > test_start,
                "lossy production boundary: {path}"
            );
        }
    }
    let main = &files["src/main.rs"];
    assert!(main.contains("std::env::args_os().skip(1)"));
    let cli = files["src/cli.rs"].split("mod tests {").next().unwrap();
    assert!(!cli.contains("process::Command"));
    for bytes in [
        "write_all(report.as_bytes())",
        "write_all(line.as_bytes())",
        "write_all(diagnostic.as_bytes())",
        "write_all(message.as_bytes())",
    ] {
        assert!(
            cli.contains(bytes),
            "explicit output encoding boundary changed"
        );
    }
}
