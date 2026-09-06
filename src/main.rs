use std::process::ExitCode;

fn main() -> ExitCode {
    safeclone::cli::run(
        std::env::args_os().skip(1),
        std::io::stdout(),
        std::io::stderr(),
    )
}
