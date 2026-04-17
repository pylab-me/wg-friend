use anyhow::Result;

use crate::command_runner::run;
use crate::command_runner::run_capture;

pub fn start(service_name: &str) -> Result<()> {
    run("systemctl", &["start", service_name])
}

pub fn stop(service_name: &str) -> Result<()> {
    run("systemctl", &["stop", service_name])
}

pub fn restart(service_name: &str) -> Result<()> {
    run("systemctl", &["restart", service_name])
}

pub fn enable(service_name: &str) -> Result<()> {
    run("systemctl", &["enable", service_name])
}

pub fn disable(service_name: &str) -> Result<()> {
    run("systemctl", &["disable", service_name])
}

pub fn is_active(service_name: &str) -> Result<String> {
    run_capture("systemctl", &["is-active", service_name])
}

pub fn daemon_reload() -> Result<()> {
    run("systemctl", &["daemon-reload"])
}

pub fn status_text(service_name: &str) -> String {
    run_capture(
        "systemctl",
        &["status", service_name, "--no-pager", "--full"],
    )
    .unwrap_or_else(|error| format!("<failed: {error}>"))
}
