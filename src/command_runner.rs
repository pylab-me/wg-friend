use std::ffi::OsStr;
use std::io::Write;
use std::process::Command;
use std::process::Output;
use std::process::Stdio;

use anyhow::bail;
use anyhow::Context;
use anyhow::Result;

pub fn run(program: impl AsRef<OsStr>, args: &[&str]) -> Result<()> {
    let output = run_output(program.as_ref(), args)?;
    ensure_success(program.as_ref(), args, &output)
}

pub fn run_output(program: impl AsRef<OsStr>, args: &[&str]) -> Result<Output> {
    Command::new(program.as_ref())
        .args(args)
        .output()
        .with_context(|| format!("failed to execute {}", program.as_ref().to_string_lossy()))
}

pub fn run_capture(program: impl AsRef<OsStr>, args: &[&str]) -> Result<String> {
    let output = run_output(program.as_ref(), args)?;
    ensure_success(program.as_ref(), args, &output)?;
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

pub fn run_capture_with_input(
    program: impl AsRef<OsStr>,
    args: &[&str],
    input: &str,
) -> Result<String> {
    let mut child = Command::new(program.as_ref())
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("failed to execute {}", program.as_ref().to_string_lossy()))?;

    if let Some(stdin) = child.stdin.as_mut() {
        stdin.write_all(input.as_bytes()).with_context(|| {
            format!(
                "failed to write stdin for {}",
                program.as_ref().to_string_lossy()
            )
        })?;
    }

    let output = child
        .wait_with_output()
        .with_context(|| format!("failed to wait for {}", program.as_ref().to_string_lossy()))?;

    ensure_success(program.as_ref(), args, &output)?;
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

pub fn command_exists(name: &str) -> bool {
    Command::new("sh")
        .args([
            "-lc",
            &format!("command -v {} >/dev/null 2>&1", shell_escape(name)),
        ])
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

pub fn shell_capture(script: &str) -> Result<String> {
    run_capture("sh", &["-lc", script])
}

fn ensure_success(program: &OsStr, args: &[&str], output: &Output) -> Result<()> {
    if output.status.success() {
        return Ok(());
    }

    bail!(
        "command failed: {} {}\nstdout:\n{}\nstderr:\n{}",
        program.to_string_lossy(),
        args.join(" "),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn shell_escape(value: &str) -> String {
    value.replace('"', "\\\"")
}
