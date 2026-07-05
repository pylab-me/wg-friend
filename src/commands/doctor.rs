use anyhow::{Result, bail};

use super::server::resolve_server;
use crate::command_runner::{command_exists, run_output};
use crate::config::AppConfig;
use crate::ui::{
    Table, Tone, kv, {self},
};
use crate::util::{
    ensure_boringtun_present, ensure_config_exists, ensure_required_commands, ensure_root,
    ensure_tun_device, interface_exists, ip_addr_has_inet, ip_link_is_up, parse_ip_brief_addr,
    safe_capture, safe_tail,
};
use crate::wireguard::{InterfaceData, WgRuntimeSummary};

const ACTIVE_PROBE_DEFAULT_HOST: &str = "1.1.1.1";
const ACTIVE_PROBE_MIN_PAYLOAD: u16 = 1200;
const ACTIVE_PROBE_MAX_PAYLOAD: u16 = 1472;
const ACTIVE_PROBE_TIMEOUT_SECONDS: u16 = 1;
const ACTIVE_PROBE_REACHABILITY_PAYLOAD: u16 = 56;
const IPV4_ICMP_OVERHEAD: u16 = 28;
const WG_CONSERVATIVE_OVERHEAD: u16 = 80;
const WG_MIN_RECOMMENDED_MTU: u16 = 1280;
const WG_FALLBACK_RECOMMENDED_MTU: u16 = 1400;

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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProbeConfidence {
    Baseline,
    Degraded,
}

impl ProbeConfidence {
    fn as_str(self) -> &'static str {
        match self {
            Self::Baseline => "baseline",
            Self::Degraded => "degraded",
        }
    }
}

#[derive(Clone, Debug)]
struct ActiveMtuProbeResult {
    target: String,
    attempts: usize,
    largest_ok_payload: Option<u16>,
    smallest_fail_payload: Option<u16>,
    estimated_path_mtu: Option<u16>,
    recommended_mtu: u16,
    confidence: ProbeConfidence,
    reason: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PingProbeState {
    Success,
    Fail,
}

#[derive(Clone, Debug)]
struct PingProbeOutcome {
    state: PingProbeState,
    detail: String,
}

impl PingProbeOutcome {
    fn success(&self) -> bool {
        self.state == PingProbeState::Success
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

pub fn mtu_probe(
    app: &AppConfig,
    interface: Option<String>,
    active: bool,
    host: Option<String>,
) -> Result<()> {
    let iface = resolve_server(app, interface)?;
    ensure_config_exists(&iface)?;
    let data = InterfaceData::parse(&iface.conf_file)?;
    let current_mtu_raw = data.interface_value("MTU").unwrap_or(&app.default_mtu).to_string();
    let current_mtu = current_mtu_raw.parse::<u16>().ok();

    if !active {
        print_advisory_mtu_probe(
            &iface.interface,
            &iface.conf_file.display().to_string(),
            &current_mtu_raw,
        );
        return Ok(());
    }

    let target = host
        .map(|item| item.trim().to_string())
        .filter(|item| !item.is_empty())
        .unwrap_or_else(|| ACTIVE_PROBE_DEFAULT_HOST.to_string());

    let probe = run_active_mtu_probe(&target, current_mtu)?;
    print_active_mtu_probe(
        &iface.interface,
        &iface.conf_file.display().to_string(),
        &current_mtu_raw,
        &probe,
    );
    Ok(())
}

fn print_advisory_mtu_probe(interface: &str, config_path: &str, current_mtu: &str) {
    ui::print_section("doctor mtu-probe");
    ui::print_kv_rows(&vec![
        kv("interface", interface.to_string()),
        kv("config", config_path.to_string()),
        kv("current_mtu", current_mtu.to_string()),
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
        "Use '--active' to run an IPv4 DF probe. The default baseline target is 1.1.1.1.",
        Tone::Info,
    );
    ui::print_message(
        "If handshake succeeds but HTTPS or large downloads fail, step down the MTU gradually: 1420 -> 1400 -> 1380 -> 1360.",
        Tone::Muted,
    );
}

fn print_active_mtu_probe(
    interface: &str,
    config_path: &str,
    current_mtu: &str,
    probe: &ActiveMtuProbeResult,
) {
    ui::print_section("doctor mtu-probe");
    let mut rows = vec![
        kv("interface", interface.to_string()),
        kv("config", config_path.to_string()),
        kv("current_mtu", current_mtu.to_string()),
        kv("mode", "active"),
        kv("target", probe.target.clone()),
        kv("probe_family", "ipv4"),
        kv("attempts", probe.attempts.to_string()),
    ];

    if let Some(payload) = probe.largest_ok_payload {
        rows.push(kv("largest_ok_payload", payload.to_string()));
    } else {
        rows.push(kv("largest_ok_payload", "-"));
    }

    if let Some(payload) = probe.smallest_fail_payload {
        rows.push(kv("smallest_fail_payload", payload.to_string()));
    } else {
        rows.push(kv("smallest_fail_payload", "-"));
    }

    if let Some(path_mtu) = probe.estimated_path_mtu {
        rows.push(kv("estimated_path_mtu", path_mtu.to_string()));
    } else {
        rows.push(kv("estimated_path_mtu", "-"));
    }

    rows.push(kv("recommended_mtu", probe.recommended_mtu.to_string()));
    rows.push(kv(
        "confidence",
        ui::status_badge(probe.confidence.as_str()),
    ));
    rows.push(kv("reason", probe.reason.clone()));
    ui::print_kv_rows(&rows);

    ui::print_message(
        "This probe uses ICMPv4 DF packets against the selected target. It is advisory, not a universal MTU for every destination.",
        Tone::Warn,
    );
    ui::print_message(
        "recommended_mtu is derived conservatively as estimated_path_mtu minus 80 bytes of tunnel overhead.",
        Tone::Info,
    );
    if probe.confidence == ProbeConfidence::Degraded {
        ui::print_message(
            "The active probe did not produce a clean upper bound, so the recommendation fell back to a conservative value.",
            Tone::Muted,
        );
    }
}

fn run_active_mtu_probe(target: &str, current_mtu: Option<u16>) -> Result<ActiveMtuProbeResult> {
    if !command_exists("ping") {
        bail!("active mtu probe requires the 'ping' command")
    }

    let mut attempts = 0usize;
    attempts += 1;
    let reachability = probe_ping_once(target, ACTIVE_PROBE_REACHABILITY_PAYLOAD)?;
    if !reachability.success() {
        return Ok(ActiveMtuProbeResult {
            target: target.to_string(),
            attempts,
            largest_ok_payload: None,
            smallest_fail_payload: None,
            estimated_path_mtu: None,
            recommended_mtu: fallback_recommended_mtu(current_mtu),
            confidence: ProbeConfidence::Degraded,
            reason: format!(
                "active reachability probe failed before MTU search: {}",
                compact_probe_detail(&reachability.detail)
            ),
        });
    }

    let mut lower = ACTIVE_PROBE_MIN_PAYLOAD;
    let mut upper = ACTIVE_PROBE_MAX_PAYLOAD;
    let mut largest_ok_payload = None;
    let mut smallest_fail_payload = None;

    while lower <= upper {
        let payload = lower + ((upper - lower) / 2);
        attempts += 1;
        let outcome = probe_ping_once(target, payload)?;

        if outcome.success() {
            largest_ok_payload = Some(payload);
            if payload == ACTIVE_PROBE_MAX_PAYLOAD {
                break;
            }
            lower = payload.saturating_add(1);
        } else {
            smallest_fail_payload = Some(payload);
            if payload == 0 {
                break;
            }
            upper = payload.saturating_sub(1);
        }
    }

    let Some(largest_ok_payload) = largest_ok_payload else {
        return Ok(ActiveMtuProbeResult {
            target: target.to_string(),
            attempts,
            largest_ok_payload: None,
            smallest_fail_payload,
            estimated_path_mtu: None,
            recommended_mtu: fallback_recommended_mtu(current_mtu),
            confidence: ProbeConfidence::Degraded,
            reason: "active probe did not produce a clean upper bound".to_string(),
        });
    };

    let estimated_path_mtu = largest_ok_payload.saturating_add(IPV4_ICMP_OVERHEAD);
    let recommended_mtu = recommend_wireguard_mtu(estimated_path_mtu, current_mtu);
    let reason = if smallest_fail_payload.is_some() {
        "binary-search upper bound established against the selected target".to_string()
    } else {
        format!(
            "search ceiling reached at payload {}; path MTU is at least {}",
            ACTIVE_PROBE_MAX_PAYLOAD,
            ACTIVE_PROBE_MAX_PAYLOAD + IPV4_ICMP_OVERHEAD
        )
    };

    Ok(ActiveMtuProbeResult {
        target: target.to_string(),
        attempts,
        largest_ok_payload: Some(largest_ok_payload),
        smallest_fail_payload,
        estimated_path_mtu: Some(estimated_path_mtu),
        recommended_mtu,
        confidence: ProbeConfidence::Baseline,
        reason,
    })
}

fn probe_ping_once(target: &str, payload: u16) -> Result<PingProbeOutcome> {
    let payload_string = payload.to_string();
    let timeout_string = ACTIVE_PROBE_TIMEOUT_SECONDS.to_string();
    let args = vec![
        "-4".to_string(),
        "-M".to_string(),
        "do".to_string(),
        "-c".to_string(),
        "1".to_string(),
        "-W".to_string(),
        timeout_string,
        "-s".to_string(),
        payload_string,
        target.to_string(),
    ];
    let arg_refs = args.iter().map(|item| item.as_str()).collect::<Vec<_>>();
    let output = run_output("ping", &arg_refs)?;
    let detail = format_ping_probe_detail(&output.stdout, &output.stderr);
    let state = if output.status.success() {
        PingProbeState::Success
    } else {
        PingProbeState::Fail
    };
    Ok(PingProbeOutcome { state, detail })
}

fn format_ping_probe_detail(stdout: &[u8], stderr: &[u8]) -> String {
    let stdout_text = String::from_utf8_lossy(stdout);
    let stderr_text = String::from_utf8_lossy(stderr);

    let interesting = stdout_text.lines().chain(stderr_text.lines()).map(str::trim).find(|line| {
        let normalized = line.to_ascii_lowercase();
        !line.is_empty()
            && (normalized.contains("bytes from")
                || normalized.contains("packet loss")
                || normalized.contains("message too long")
                || normalized.contains("frag needed")
                || normalized.contains("mtu=")
                || normalized.contains("name or service not known")
                || normalized.contains("temporary failure in name resolution")
                || normalized.contains("destination host unreachable"))
    });

    interesting.unwrap_or("ping returned without a recognized detail").to_string()
}

fn compact_probe_detail(detail: &str) -> String {
    detail.trim().replace('\n', " | ")
}

fn recommend_wireguard_mtu(estimated_path_mtu: u16, current_mtu: Option<u16>) -> u16 {
    let recommended = estimated_path_mtu.saturating_sub(WG_CONSERVATIVE_OVERHEAD);
    let recommended = recommended.max(WG_MIN_RECOMMENDED_MTU);
    match current_mtu {
        Some(current) if current < recommended => current.max(WG_MIN_RECOMMENDED_MTU),
        _ => recommended,
    }
}

fn fallback_recommended_mtu(current_mtu: Option<u16>) -> u16 {
    match current_mtu {
        Some(current) => current.min(WG_FALLBACK_RECOMMENDED_MTU).max(WG_MIN_RECOMMENDED_MTU),
        None => WG_FALLBACK_RECOMMENDED_MTU,
    }
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
