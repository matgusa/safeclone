use std::process::Command;

#[path = "support/product_output.rs"]
mod product_output;

fn output(argument: &str) -> String {
    let binary = std::env::var_os("SAFECLONE_TEST_BINARY")
        .unwrap_or_else(|| env!("CARGO_BIN_EXE_safeclone").into());
    let result = Command::new(binary).arg(argument).output().unwrap();
    assert!(result.status.success());
    assert!(result.stderr.is_empty());
    let text = String::from_utf8(result.stdout).unwrap();
    product_output::assert_product_output(&text);
    text
}

#[test]
fn executable_reports_product_capabilities_without_private_bookkeeping() {
    assert_eq!(output("--version"), "safeclone 0.1.0\n");
    let help = output("--help");
    assert!(help.contains("Show product capabilities and safety limits"));
    assert!(help.contains("Exit 3 means manual state; do not retry automatically."));
    let status = output("status");
    let expected = format!(
        "status_format=1\ninspect_enabled=true\nclone_enabled=true\nsanitization_enabled=true\npromotion_support=runtime-checked\nrelease_filesystem_scope=windows-local-ntfs\nfilesystem_commands_supported_on_this_platform={}\nnetwork=false\ntelemetry=false\nmaturity=experimental-mvp\n",
        cfg!(windows)
    );
    assert_eq!(status, expected);
}
