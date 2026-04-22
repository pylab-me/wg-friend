use std::fs;
use std::net::Ipv4Addr;
use std::path::Path;
use std::path::PathBuf;
use std::thread;
use std::time::Duration;
use std::time::Instant;

use anyhow::Context;
use anyhow::Result;
use anyhow::bail;

use crate::command_runner::command_exists;
use crate::command_runner::run;
use crate::command_runner::run_capture;
use crate::command_runner::run_output;
use crate::config::AppConfig;
use crate::config::InterfaceConfig;
use crate::ui::KvRow;
use crate::ui::{self};

const WG_QUICK_ONLY_KEYS: &[&str] = &[
    "Address",
    "DNS",
    "MTU",
    "Table",
    "PreUp",
    "PostUp",
    "PreDown",
    "PostDown",
    "SaveConfig",
];

#[derive(Clone, Debug, Default)]
pub struct IpBriefSummary {
    pub name: String,
    pub state: String,
    pub ipv4: Vec<String>,
    pub ipv6: Vec<String>,
}

pub fn ensure_root() -> Result<()> {
    if unsafe { libc_geteuid() } != 0 {
        bail!("this command must run as root")
    }
    Ok(())
}

pub fn ensure_required_commands() -> Result<()> {
    for command in ["ip", "wg", "systemctl", "sh"] {
        if !command_exists(command) {
            bail!("required command not found: {command}")
        }
    }
    Ok(())
}

pub fn ensure_boringtun_present(app: &AppConfig) -> Result<()> {
    if !app.boringtun_bin.exists() {
        bail!(
            "BoringTun binary not found: {}",
            app.boringtun_bin.display()
        )
    }
    Ok(())
}

pub fn ensure_tun_device() -> Result<()> {
    let tun_path = Path::new("/dev/net/tun");
    if tun_path.exists() {
        return Ok(());
    }

    fs::create_dir_all("/dev/net").context("failed to create /dev/net")?;
    run("mknod", &["/dev/net/tun", "c", "10", "200"])?;
    run("chmod", &["666", "/dev/net/tun"])?;
    Ok(())
}

pub fn ensure_paths(app: &AppConfig, iface: &InterfaceConfig) -> Result<()> {
    if let Some(parent) = app.log_file.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    fs::create_dir_all(&app.wg_run_dir)
        .with_context(|| format!("failed to create {}", app.wg_run_dir.display()))?;
    fs::create_dir_all(&iface.client_dir)
        .with_context(|| format!("failed to create {}", iface.client_dir.display()))?;
    fs::create_dir_all(app.instance_state_dir(&iface.interface)).with_context(|| {
        format!(
            "failed to create {}",
            app.instance_state_dir(&iface.interface).display()
        )
    })?;
    fs::create_dir_all(app.instance_clients_dir(&iface.interface)).with_context(|| {
        format!(
            "failed to create {}",
            app.instance_clients_dir(&iface.interface).display()
        )
    })?;
    fs::create_dir_all(app.instance_exports_dir(&iface.interface)).with_context(|| {
        format!(
            "failed to create {}",
            app.instance_exports_dir(&iface.interface).display()
        )
    })?;

    if !app.log_file.exists() {
        fs::write(&app.log_file, "")
            .with_context(|| format!("failed to create {}", app.log_file.display()))?;
    }
    Ok(())
}

pub fn ensure_config_exists(iface: &InterfaceConfig) -> Result<()> {
    if !iface.conf_file.exists() {
        bail!("WireGuard config not found: {}", iface.conf_file.display())
    }
    Ok(())
}

pub fn interface_exists(name: &str) -> bool {
    Path::new("/sys/class/net").join(name).exists()
}

pub fn wg_show_ready(name: &str) -> bool {
    run_output("wg", &["show", name])
        .map(|output| output.status.success())
        .unwrap_or(false)
}

pub fn wait_until<F>(label: &str, timeout: Duration, mut predicate: F) -> Result<()>
where
    F: FnMut() -> bool,
{
    let started = Instant::now();
    while started.elapsed() < timeout {
        if predicate() {
            return Ok(());
        }
        thread::sleep(Duration::from_secs(1));
    }
    bail!("timeout while waiting for {label}")
}

pub fn clean_wireguard_config(source: &Path) -> Result<PathBuf> {
    let content = fs::read_to_string(source)
        .with_context(|| format!("failed to read {}", source.display()))?;

    let filtered = content
        .lines()
        .filter(|line| !matches_wg_quick_only_key(line))
        .collect::<Vec<_>>()
        .join("\n");

    let path = std::env::temp_dir().join(format!("wg-friend-{}-clean.conf", std::process::id()));
    fs::write(&path, filtered).with_context(|| format!("failed to write {}", path.display()))?;
    Ok(path)
}

pub fn extract_config_value(source: &Path, key: &str) -> Result<Option<String>> {
    let content = fs::read_to_string(source)
        .with_context(|| format!("failed to read {}", source.display()))?;

    for raw_line in content.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('[') {
            continue;
        }

        let Some((left, right)) = line.split_once('=') else {
            continue;
        };

        if left.trim() == key {
            return Ok(Some(right.trim().to_string()));
        }
    }

    Ok(None)
}

pub fn print_header(title: &str) {
    ui::print_section(title);
}

pub fn print_kv(key: &str, value: impl AsRef<str>) {
    ui::print_kv_rows(&[KvRow::new(key, value.as_ref())]);
}

pub fn safe_capture(program: &str, args: &[&str]) -> String {
    match run_output(program, args) {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            if !stdout.is_empty() {
                stdout
            } else if !stderr.is_empty() {
                stderr
            } else {
                "<no output>".to_string()
            }
        }
        Err(error) => format!("<failed: {error}>"),
    }
}

pub fn safe_tail(path: &Path, lines: usize) -> String {
    let content = fs::read_to_string(path).unwrap_or_else(|_| String::new());
    let items: Vec<&str> = content.lines().collect();
    let start = items.len().saturating_sub(lines);
    items[start..].join("\n")
}

pub fn client_file_name_from_path(path: &Path) -> Option<String> {
    path.file_stem()
        .and_then(|item| item.to_str())
        .map(|item| item.to_string())
}

pub fn base_ip_from_cidr(value: &str) -> Option<Ipv4Addr> {
    let raw = value.split(',').next()?.trim();
    let ip = raw.split('/').next()?.trim();
    ip.parse::<Ipv4Addr>().ok()
}

pub fn ipv4_string(ip: Ipv4Addr, prefix: u8) -> String {
    format!("{ip}/{prefix}")
}

pub fn split_cidr(value: &str) -> Option<(Ipv4Addr, u8)> {
    let raw = value.split(',').next()?.trim();
    let (ip, prefix) = raw.split_once('/')?;
    Some((
        ip.trim().parse::<Ipv4Addr>().ok()?,
        prefix.trim().parse::<u8>().ok()?,
    ))
}

pub fn next_ipv4_in_same_subnet(base: Ipv4Addr, used: &[Ipv4Addr]) -> Option<Ipv4Addr> {
    let octets = base.octets();
    for host in 2u8..=254u8 {
        let candidate = Ipv4Addr::new(octets[0], octets[1], octets[2], host);
        if candidate == base {
            continue;
        }
        if !used.contains(&candidate) {
            return Some(candidate);
        }
    }
    None
}

pub fn ip_link_is_up(name: &str) -> bool {
    run_capture("ip", &["link", "show", "dev", name])
        .map(|text| {
            let first_line = text
                .lines()
                .find(|line| !line.trim().is_empty())
                .unwrap_or_default();
            let Some(flags) = first_line
                .split('<')
                .nth(1)
                .and_then(|part| part.split('>').next())
            else {
                return false;
            };
            flags
                .split(',')
                .map(|item| item.trim())
                .any(|flag| flag == "UP")
        })
        .unwrap_or(false)
}

pub fn ip_addr_has_inet(name: &str) -> bool {
    run_capture("ip", &["addr", "show", "dev", name])
        .map(|text| text.contains("inet "))
        .unwrap_or(false)
}

pub fn parse_ip_brief_addr(text: &str) -> Option<IpBriefSummary> {
    let line = text.lines().find(|line| !line.trim().is_empty())?.trim();
    if line.starts_with("<failed:") || line == "<no output>" {
        return None;
    }

    let parts = line.split_whitespace().collect::<Vec<_>>();
    if parts.len() < 3 {
        return None;
    }

    let mut summary = IpBriefSummary {
        name: parts[0].to_string(),
        state: parts[1].to_ascii_lowercase(),
        ipv4: Vec::new(),
        ipv6: Vec::new(),
    };

    for item in parts.iter().skip(2) {
        if item.contains(':') {
            summary.ipv6.push((*item).to_string());
        } else if item.contains('.') {
            summary.ipv4.push((*item).to_string());
        }
    }

    Some(summary)
}

pub fn kv_rows_from_pairs(pairs: Vec<(&str, String)>) -> Vec<KvRow> {
    pairs
        .into_iter()
        .map(|(key, value)| KvRow::new(key, value))
        .collect()
}

fn matches_wg_quick_only_key(line: &str) -> bool {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return false;
    }

    let Some((left, _)) = trimmed.split_once('=') else {
        return false;
    };

    let key = left.trim();
    WG_QUICK_ONLY_KEYS.iter().any(|item| item == &key)
}

#[cfg(target_os = "linux")]
unsafe fn libc_geteuid() -> u32 {
    unsafe extern "C" {
        fn geteuid() -> u32;
    }
    geteuid()
}

#[cfg(not(target_os = "linux"))]
unsafe fn libc_geteuid() -> u32 {
    1
}
