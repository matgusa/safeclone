use std::process::Command;

const GUIDE: &str = include_str!("../docs/usage.md");

#[test]
fn documented_cli_usage_matches_actual_binary_help() {
    let output = Command::new(env!("CARGO_BIN_EXE_safeclone"))
        .arg("--help")
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let help = String::from_utf8(output.stdout).unwrap();
    let usages: Vec<_> = help
        .lines()
        .filter(|line| line.starts_with("    safeclone "))
        .map(str::trim)
        .collect();
    assert_eq!(usages.len(), 9);
    for usage in usages {
        assert!(GUIDE.contains(usage), "documented command drift: {usage}");
    }
    for option in [
        "--profile",
        "--show-private-paths",
        "--review-id",
        "--event-id",
        "--reason-code",
        "--acknowledge-incomplete",
    ] {
        assert!(help.contains(option) && GUIDE.contains(option));
    }
    let version = Command::new(env!("CARGO_BIN_EXE_safeclone"))
        .arg("--version")
        .output()
        .unwrap();
    assert!(version.status.success());
    assert!(GUIDE.contains(String::from_utf8(version.stdout).unwrap().trim()));
}

#[test]
fn confidential_output_and_persistence_limits_remain_documented() {
    for warning in [
        "warning=confidential review output; do not send to AI or persist in public logs",
        "warning=sensitive candidate contains reconstructed plaintext; semantic safety was not assessed",
    ] {
        assert!(GUIDE.contains(warning));
        assert!(
            [include_str!("../src/cli.rs"), include_str!("../src/roundtrip/review.rs")]
                .iter()
                .any(|source| source.contains(warning))
        );
    }
    let security = include_str!("../docs/security-model.md")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    for limit in ["not secure erase", "CurrentUser", "physical power-loss"] {
        assert!(security.contains(limit));
    }
    let support = include_str!("../docs/support.md");
    for boundary in [
        "25H2 Home or Pro",
        "native x64",
        "ordinary-user",
        "fixed/local NTFS",
    ] {
        assert!(support.contains(boundary));
    }
}
