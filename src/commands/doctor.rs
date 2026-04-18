use anyhow::bail;
use anyhow::Result;

use super::server::resolve_server;
use crate::config::AppConfig;
use crate::ui::kv;
use crate::ui::Table;
use crate::ui::Tone;
use crate::ui::{self};
use crate::util::ensure_boringtun_present;
use crate::util::ensure_config_exists;
use crate::util::ensure_required_commands;
use crate::util::ensure_root;
use crate::util::ensure_tun_device;
use crate::util::interface_exists;
use crate::util::ip_addr_has_inet;
use crate::util::ip_link_is_up;
use crate::util::parse_ip_brief_addr;
use crate::util::safe_capture;
use crate::util::safe_tail;
use crate::wireguard::InterfaceData;
use crate::wireguard::WgRuntimeSummary;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CheckStatus {
    Pass,
    Warn,
    Fail,
}

impl CheckStatus {
    fn label(self) -> String {
        match self {
            Self::Pass => ui::badge("PASS", Tone::Good),
            Self::Warn => ui::badge("WARN", Tone::Warn),
            Self::Fail => ui::badge("FAIL", Tone::Bad),
        }
    }
}

#[derive(Clone, Debug)]
struct DoctorCheck {
    name: String,
    status: CheckStatus,
    detail: String,
}

impl DoctorCheck {
    fn pass(name: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            status: CheckStatus::Pass,
            detail: detail.into(),
        }
    }

    fn warn(name: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            status: CheckStatus::Warn,
            detail: detail.into(),
        }
    }

    fn fail(name: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            status: CheckStatus::Fail,
            detail: detail.into(),
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct DoctorCounts {
    pass: usize,
    warn: usize,
    fail: usize,
}

impl DoctorCounts {
    fn add(&mut self, status: CheckStatus) {
        match status {
            CheckStatus::Pass => self.pass += 1,
            CheckStatus::Warn => self.warn += 1,
            CheckStatus::Fail => self.fail += 1,
        }
    }

    fn total(self) -> usize {
        self.pass + self.warn + self.fail
    }
}

pub fn check(app: &AppConfig, interface: Option<String>) -> Result<()> {
    let iface = resolve_server(app, interface)?;

    let checks = vec![
        check_root(),
        check_required_commands(),
        check_config_exists(&iface.conf_file),
        check_boringtun_present(app),
        check_tun_device(),
    ];

    let counts = print_doctor_checks("doctor check", &checks);

    ui::print_section("doctor summary");
    ui::print_kv_rows(&vec![
        kv("interface", iface.interface),
        kv("config", iface.conf_file.display().to_string()),
        kv("boringtun", app.boringtun_bin.display().to_string()),
        kv("checks", counts.total().to_string()),
        kv("pass", ui::badge(&counts.pass.to_string(), Tone::Good)),
        kv("warn", ui::badge(&counts.warn.to_string(), Tone::Warn)),
        kv("fail", ui::badge(&counts.fail.to_string(), Tone::Bad)),
    ]);

    if counts.fail == 0 {
        ui::print_message("Local prerequisites look sane.", Tone::Good);
        Ok(())
    } else {
        bail!("doctor check found {} failing item(s)", counts.fail)
    }
}

pub fn run(app: &AppConfig, interface: Option<String>) -> Result<()> {
    let iface = resolve_server(app, interface)?;
    let service = app.service_name(&iface.interface);

    let interface_present = interface_exists(&iface.interface);
    let link_up = ip_link_is_up(&iface.interface);
    let addr_present = ip_addr_has_inet(&iface.interface);
    let wg_raw = safe_capture("wg", &["show", &iface.interface]);
    let wg_dump = safe_capture("wg", &["show", &iface.interface, "dump"]);
    let wg_ready = !wg_raw.starts_with("<failed:") && !wg_dump.starts_with("<failed:");
    let ip_brief = parse_ip_brief_addr(&safe_capture(
        "ip",
        &["-brief", "addr", "show", "dev", &iface.interface],
    ));
    let runtime = if wg_ready {
        Some(WgRuntimeSummary::parse_dump(&iface.interface, &wg_dump))
    } else {
        None
    };
    let service_state =
        crate::systemd::is_active(&service).unwrap_or_else(|_| "unknown".to_string());

    ui::print_section("doctor summary");
    ui::print_kv_rows(&vec![
        kv("service", service.clone()),
        kv("interface", iface.interface.clone()),
        kv("config", iface.conf_file.display().to_string()),
        kv("boringtun", app.boringtun_bin.display().to_string()),
        kv("log_file", app.log_file.display().to_string()),
        kv("client_dir", iface.client_dir.display().to_string()),
    ]);

    let checks = vec![
        check_config_exists(&iface.conf_file),
        check_service_state(&service_state, interface_present),
        check_interface_present(&iface.interface, interface_present),
        check_link_up(&iface.interface, interface_present, link_up),
        check_addr_present(&iface.interface, interface_present, addr_present),
        check_wg_show(&iface.interface, wg_ready),
        check_peer_count(
            runtime.as_ref().map(|item| item.peers.len()).unwrap_or(0),
            wg_ready,
        ),
    ];
    let counts = print_doctor_checks("doctor checks", &checks);

    ui::print_section("interface snapshot");
    ui::print_kv_rows(&vec![
        kv(
            "state",
            ip_brief
                .as_ref()
                .map(|item| ui::status_badge(&item.state))
                .unwrap_or_else(|| ui::status_badge("missing")),
        ),
        kv(
            "ipv4",
            ip_brief
                .as_ref()
                .map(|item| {
                    if item.ipv4.is_empty() {
                        "-".to_string()
                    } else {
                        item.ipv4.join(", ")
                    }
                })
                .unwrap_or_else(|| "-".to_string()),
        ),
        kv(
            "ipv6",
            ip_brief
                .as_ref()
                .map(|item| {
                    if item.ipv6.is_empty() {
                        "-".to_string()
                    } else {
                        item.ipv6.join(", ")
                    }
                })
                .unwrap_or_else(|| "-".to_string()),
        ),
        kv(
            "peer_count",
            runtime
                .as_ref()
                .map(|item| item.peers.len().to_string())
                .unwrap_or_else(|| "0".to_string()),
        ),
        kv("service_active", ui::status_badge(&service_state)),
    ]);

    ui::print_section("doctor verdict");
    ui::print_kv_rows(&vec![
        kv("checks", counts.total().to_string()),
        kv("pass", ui::badge(&counts.pass.to_string(), Tone::Good)),
        kv("warn", ui::badge(&counts.warn.to_string(), Tone::Warn)),
        kv("fail", ui::badge(&counts.fail.to_string(), Tone::Bad)),
    ]);
    if counts.fail == 0 && counts.warn == 0 {
        ui::print_message("Doctor sees a clean local state.", Tone::Good);
    } else if counts.fail == 0 {
        ui::print_message("Doctor found warnings but no hard failures.", Tone::Warn);
    } else {
        ui::print_message(
            "Doctor found hard failures. Review the evidence below.",
            Tone::Bad,
        );
    }

    ui::print_section("systemd status");
    ui::print_block(&safe_capture(
        "systemctl",
        &["status", &service, "--no-pager", "--full"],
    ));

    ui::print_section("journalctl recent");
    ui::print_block(&safe_capture(
        "journalctl",
        &["-u", &service, "-n", "80", "--no-pager"],
    ));

    ui::print_section("ip link");
    ui::print_block(&safe_capture("ip", &["link", "show", &iface.interface]));

    ui::print_section("ip addr");
    ui::print_block(&safe_capture(
        "ip",
        &["addr", "show", "dev", &iface.interface],
    ));

    ui::print_section("wg show");
    ui::print_block(&wg_raw);

    ui::print_section("wireguard runtime dir");
    ui::print_block(&safe_capture(
        "ls",
        &["-ld", app.wg_run_dir.to_str().unwrap_or("/run/wireguard")],
    ));
    ui::print_block(&safe_capture(
        "ls",
        &["-l", app.wg_run_dir.to_str().unwrap_or("/run/wireguard")],
    ));

    ui::print_section("client dir");
    ui::print_block(&safe_capture(
        "ls",
        &["-ld", iface.client_dir.to_str().unwrap_or("<invalid>")],
    ));
    ui::print_block(&safe_capture(
        "ls",
        &["-l", iface.client_dir.to_str().unwrap_or("<invalid>")],
    ));

    ui::print_section("local log tail");
    let tail = safe_tail(&app.log_file, 80);
    ui::print_block(&tail);

    if counts.fail > 0 {
        bail!("doctor run found {} failing item(s)", counts.fail);
    }

    Ok(())
}

pub fn mtu_probe(app: &AppConfig, interface: Option<String>) -> Result<()> {
    let iface = resolve_server(app, interface)?;
    ensure_config_exists(&iface)?;
    let data = InterfaceData::parse(&iface.conf_file)?;
    let current_mtu = data
        .interface_value("MTU")
        .unwrap_or(&app.default_mtu)
        .to_string();

    ui::print_section("doctor mtu-probe");
    ui::print_kv_rows(&vec![
        kv("interface", iface.interface.clone()),
        kv("config", iface.conf_file.display().to_string()),
        kv("current_mtu", current_mtu.clone()),
        kv("mode", "advisory"),
    ]);

    let mut table = Table::new(vec!["candidate".to_string(), "note".to_string()]);
    for (mtu, note) in [
        (
            "1420",
            "Default WireGuard starting point for many home NAT paths",
        ),
        (
            "1400",
            "First conservative step if HTTPS works inconsistently",
        ),
        (
            "1380",
            "Safer fallback when tunnel works but some sites stall",
        ),
        (
            "1360",
            "Aggressive fallback for difficult mobile or double-NAT paths",
        ),
    ] {
        let emphasis = if mtu == current_mtu { "current" } else { note };
        table.push_row(vec![mtu.to_string(), emphasis.to_string()]);
    }
    ui::print_table(&table);

    ui::print_message(
        "This command is advisory only. It does not mutate MTU or claim path-specific certainty.",
        Tone::Warn,
    );
    ui::print_message(
        "If handshake succeeds but HTTPS or large downloads fail, step down the MTU gradually: 1420 -> 1400 -> 1380 -> 1360.",
        Tone::Info,
    );
    ui::print_message(
        "After each MTU change, restart the interface and re-test a real client flow.",
        Tone::Muted,
    );
    Ok(())
}

fn print_doctor_checks(title: &str, checks: &[DoctorCheck]) -> DoctorCounts {
    let mut counts = DoctorCounts::default();
    let mut table = Table::new(vec![
        "status".to_string(),
        "check".to_string(),
        "detail".to_string(),
    ]);

    for check in checks {
        counts.add(check.status);
        table.push_row(vec![
            check.status.label(),
            check.name.clone(),
            check.detail.clone(),
        ]);
    }

    ui::print_section(title);
    ui::print_table(&table);
    counts
}

fn check_root() -> DoctorCheck {
    match ensure_root() {
        Ok(_) => DoctorCheck::pass("root privileges", "running as root"),
        Err(err) => DoctorCheck::fail("root privileges", err.to_string()),
    }
}

fn check_required_commands() -> DoctorCheck {
    match ensure_required_commands() {
        Ok(_) => DoctorCheck::pass(
            "required commands",
            "wg, ip, systemctl, journalctl, ls, install found",
        ),
        Err(err) => DoctorCheck::fail("required commands", err.to_string()),
    }
}

fn check_boringtun_present(app: &AppConfig) -> DoctorCheck {
    match ensure_boringtun_present(app) {
        Ok(_) => DoctorCheck::pass("boringtun binary", app.boringtun_bin.display().to_string()),
        Err(err) => DoctorCheck::fail("boringtun binary", err.to_string()),
    }
}

fn check_tun_device() -> DoctorCheck {
    match ensure_tun_device() {
        Ok(_) => DoctorCheck::pass("/dev/net/tun", "device is present"),
        Err(err) => DoctorCheck::fail("/dev/net/tun", err.to_string()),
    }
}

fn check_config_exists(path: &std::path::Path) -> DoctorCheck {
    if path.exists() {
        DoctorCheck::pass("config file", path.display().to_string())
    } else {
        DoctorCheck::fail("config file", format!("missing: {}", path.display()))
    }
}

fn check_service_state(state: &str, interface_present: bool) -> DoctorCheck {
    match state {
        "active" => DoctorCheck::pass("service state", "systemd reports active"),
        "activating" | "reloading" => {
            DoctorCheck::warn("service state", format!("systemd reports {state}"))
        }
        "inactive" if interface_present => DoctorCheck::warn(
            "service state",
            "service inactive, but interface still exists",
        ),
        "inactive" => DoctorCheck::warn("service state", "systemd reports inactive"),
        "failed" => DoctorCheck::fail("service state", "systemd reports failed"),
        other => DoctorCheck::warn("service state", format!("systemd reports {other}")),
    }
}

fn check_interface_present(interface: &str, present: bool) -> DoctorCheck {
    if present {
        DoctorCheck::pass("interface present", format!("{interface} exists"))
    } else {
        DoctorCheck::fail("interface present", format!("{interface} is missing"))
    }
}

fn check_link_up(interface: &str, interface_present: bool, link_up: bool) -> DoctorCheck {
    if !interface_present {
        DoctorCheck::fail(
            "link state",
            format!("{interface} missing, cannot inspect link state"),
        )
    } else if link_up {
        DoctorCheck::pass("link state", format!("{interface} is up"))
    } else {
        DoctorCheck::warn("link state", format!("{interface} exists but is not up"))
    }
}

fn check_addr_present(interface: &str, interface_present: bool, addr_present: bool) -> DoctorCheck {
    if !interface_present {
        DoctorCheck::fail(
            "ip address",
            format!("{interface} missing, cannot inspect addresses"),
        )
    } else if addr_present {
        DoctorCheck::pass(
            "ip address",
            format!("{interface} has at least one inet/inet6 address"),
        )
    } else {
        DoctorCheck::warn(
            "ip address",
            format!("{interface} has no inet/inet6 address assigned"),
        )
    }
}

fn check_wg_show(interface: &str, wg_ready: bool) -> DoctorCheck {
    if wg_ready {
        DoctorCheck::pass("wg show", format!("wg show {interface} succeeded"))
    } else {
        DoctorCheck::fail("wg show", format!("wg show {interface} failed"))
    }
}

fn check_peer_count(peer_count: usize, wg_ready: bool) -> DoctorCheck {
    if !wg_ready {
        DoctorCheck::fail("peer count", "wireguard runtime is not readable")
    } else if peer_count == 0 {
        DoctorCheck::warn("peer count", "no peers currently attached")
    } else {
        DoctorCheck::pass("peer count", format!("{peer_count} peer(s) visible"))
    }
}
