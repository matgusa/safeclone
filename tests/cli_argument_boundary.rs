//! Exercise the actual executable entry point, not just cli::run's generic
//! OsString parser. No filesystem target or remote endpoint is needed.
#![cfg(windows)]

use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use std::process::Command;

#[test]
fn nonunicode_command_line_arguments_are_rejected_without_panic_or_raw_evidence() {
    let mut wide: Vec<u16> = "synthetic-private-argument-canary-"
        .encode_utf16()
        .collect();
    for tail in [vec![0xd800], vec![0xdc00], vec![0xd800, 0x61, 0xdc00]] {
        let prefix_length = wide.len();
        wide.extend(tail);
        let nonunicode = OsString::from_wide(&wide);
        wide.truncate(prefix_length);
        for args in [
            vec![nonunicode.clone()],
            vec![OsString::from("session"), nonunicode.clone()],
            vec![
                OsString::from("session"),
                OsString::from("status"),
                nonunicode.clone(),
            ],
            vec![
                "session".into(),
                "create".into(),
                "o".into(),
                "a".into(),
                "--state".into(),
                "s".into(),
                "--profile".into(),
                nonunicode.clone(),
            ],
            vec![
                "session".into(),
                "approve".into(),
                "o".into(),
                "a".into(),
                "--state".into(),
                "s".into(),
                "--review-id".into(),
                nonunicode.clone(),
            ],
            vec![
                "session".into(),
                "close".into(),
                "--state".into(),
                "s".into(),
                "--acknowledge-incomplete".into(),
                nonunicode,
            ],
        ] {
            let binary = std::env::var_os("SAFECLONE_TEST_BINARY")
                .unwrap_or_else(|| env!("CARGO_BIN_EXE_safeclone").into());
            let output = Command::new(binary)
                .args(args)
                .output()
                .expect("run real CLI with synthetic non-Unicode argument");
            let stderr = String::from_utf8(output.stderr).expect("fixed UTF-8 error");
            println!(
                "ARGUMENT_BOUNDARY code={:?} raw_canary={} panic={}",
                output.status.code(),
                stderr.contains("synthetic-private-argument-canary"),
                stderr.contains("panicked")
            );
            assert_eq!(output.status.code(), Some(2), "raw-free definite rejection");
            assert!(output.stdout.is_empty());
            assert!(!stderr.contains("synthetic-private-argument-canary"));
            assert!(!stderr.contains("panicked") && !stderr.contains('\u{fffd}'));
        }
    }
}
