use std::process::{Command, Output};

fn run(binary: &str, argument: &str) -> Output {
    Command::new(binary)
        .arg(argument)
        .output()
        .expect("run binary")
}

fn assert_help(binary: &str, name: &str) {
    let output = run(binary, "--help");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("UTF-8 help output");
    assert!(stdout.contains(&format!("Usage: {name}")), "{stdout}");
}

fn assert_version(binary: &str, name: &str) {
    let output = run(binary, "--version");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8(output.stdout)
            .expect("UTF-8 version output")
            .trim(),
        format!("{name} {}", env!("CARGO_PKG_VERSION"))
    );
}

#[test]
fn main_cli_supports_help_and_version() {
    let binary = env!("CARGO_BIN_EXE_ncda");
    assert_help(binary, "ncda");
    assert_version(binary, "ncda");
}

#[test]
fn benchmark_cli_supports_help_and_version() {
    let binary = env!("CARGO_BIN_EXE_ncda-bench");
    assert_help(binary, "ncda-bench");
    assert_version(binary, "ncda-bench");
}
