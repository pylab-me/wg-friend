use anyhow::bail;
use anyhow::Result;

use super::server::resolve_server;
use crate::config::AppConfig;
use crate::ui::kv;
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
use crate::wireguard::WgRuntimeSummary;

pub fn check(app: &AppConfig, interface: Option<String>) -> Result<()> {
    ensure_root()?;
    ensure_required_commands()?;

    let iface = resolve_server(app, interface)?;
    ensure_config_exists(&iface)?;
    ensure_boringtun_present(app)?;
    ensure_tun_device()?;

    ui::print_section("doctor check");
    ui::print_kv_rows(&vec![
        kv("interface", iface.interface),
        kv("config", iface.conf_file.display().to_string()),
        kv("boringtun", app.boringtun_bin.display().to_string()),
        kv("result", ui::status_badge("ok")),
    ]);
    ui::print_message("Local prerequisites look sane.", Tone::Good);
    Ok(())
}

pub fn run(app: &AppConfig, interface: Option<String>) -> Result<()> {
    let iface = resolve_server(app, interface)?;
    let service = app.service_name(&iface.interface);

    let config_exists = iface.conf_file.exists();
    let interface_present = interface_exists(&iface.interface);
    let link_up = ip_link_is_up(&iface.interface);
    let addr_present = ip_addr_has_inet(&iface.interface);
    let wg_raw = safe_capture("wg", &["show", &iface.interface]);
    let wg_ready = !wg_raw.starts_with("<failed:");
    let ip_brief = parse_ip_brief_addr(&safe_capture(
        "ip",
        &["-brief", "addr", "show", "dev", &iface.interface],
    ));
    let runtime = if wg_ready {
        Some(WgRuntimeSummary::parse(&wg_raw))
    } else {
        None
    };

    ui::print_section("doctor summary");
    ui::print_kv_rows(&vec![
        kv("service", service.clone()),
        kv("interface", iface.interface.clone()),
        kv("config", iface.conf_file.display().to_string()),
        kv("boringtun", app.boringtun_bin.display().to_string()),
        kv("log_file", app.log_file.display().to_string()),
        kv("client_dir", iface.client_dir.display().to_string()),
    ]);

    ui::print_section("doctor phases");
    ui::print_kv_rows(&vec![
        kv("config_exists", ui::yes_no(config_exists)),
        kv("interface_present", ui::yes_no(interface_present)),
        kv("link_up", ui::yes_no(link_up)),
        kv("addr_present", ui::yes_no(addr_present)),
        kv("wg_show", ui::yes_no(wg_ready)),
        kv(
            "service_active",
            ui::status_badge(
                &crate::systemd::is_active(&service).unwrap_or_else(|_| "unknown".to_string()),
            ),
        ),
    ]);

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
    ]);

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

    if !iface.conf_file.exists() {
        bail!("config file is missing: {}", iface.conf_file.display());
    }

    Ok(())
}
