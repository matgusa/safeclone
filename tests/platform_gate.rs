#![cfg(not(windows))]

use std::path::PathBuf;

use safeclone::pipeline::{
    execute_clone, execute_inspect, CloneError, CloneRequest, InspectError, InspectRequest,
};
use safeclone::LocalityError;

#[test]
fn inspect_is_unsupported_before_user_path_processing() {
    let source = PathBuf::from("relative-path-that-must-not-be-resolved");

    assert_eq!(
        execute_inspect(InspectRequest { source }),
        Err(InspectError::Locality(LocalityError::UnsupportedPlatform))
    );
}

#[test]
fn clone_is_unsupported_before_either_user_path_is_processed() {
    let source = PathBuf::from("relative-source-that-must-not-be-resolved");
    let output = PathBuf::from("relative-output-that-must-not-be-resolved");

    assert_eq!(
        execute_clone(CloneRequest { source, output }),
        Err(CloneError::Locality(LocalityError::UnsupportedPlatform))
    );
}

#[test]
fn cli_reports_a_raw_free_definite_failure() {
    let raw = "relative-private-path-that-must-not-be-resolved";
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let code = safeclone::cli::run(["inspect", raw], &mut stdout, &mut stderr);

    assert_eq!(code, std::process::ExitCode::from(2));
    assert!(stdout.is_empty());
    let stderr = String::from_utf8(stderr).expect("CLI diagnostics are UTF-8");
    assert!(stderr.contains("unsupported on this release platform"));
    assert!(!stderr.contains(raw));
}
