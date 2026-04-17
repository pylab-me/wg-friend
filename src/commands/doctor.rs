use anyhow::bail;
use anyhow::Result;

use super::server::resolve_server;
use crate::config::AppConfig;
use crate::util::ensure_boringtun_present;
use crate::util::ensure_config_exists;
use crate::util::ensure_required_commands;
use crate::util::ensure_root;
use crate::util::ensure_tun_device;
use crate::util::interface_exists;
use crate::util::ip_addr_has_inet;
use crate::util::ip_link_is_up;
use crate::util::print_header;
use crate::util::print_kv;
use crate::util::safe_capture;
use crate::util::safe_tail;

pub fn check(app: &AppConfig, interface: Option<String>) -> Result<()> {
    ensure_root()?;
    ensure_required_commands()?;

    let iface = resolve_server(app, interface)?;

    print_header("doctor check");
    print_kv("interface", &iface.interface);
    print_kv("config", iface.conf_file.display().to_string());
    print_kv("boringtun", app.boringtun_bin.display().to_string());

    ensure_config_exists(&iface)?;
    ensure_boringtun_present(app)?;
    ensure_tun_device()?;

    print_kv("result", "OK");
    println!("\nLocal prerequisites look sane.");
    Ok(())
}

pub fn run(app: &AppConfig, interface: Option<String>) -> Result<()> {
    let iface = resolve_server(app, interface)?;
    let service = app.service_name(&iface.interface);

    print_header("doctor summary");
    print_kv("service", &service);
    print_kv("interface", &iface.interface);
    print_kv("config", iface.conf_file.display().to_string());
    print_kv("boringtun", app.boringtun_bin.display().to_string());
    print_kv("log_file", app.log_file.display().to_string());
    print_kv("client_dir", iface.client_dir.display().to_string());

    print_header("doctor phases");
    print_kv(
        "config_exists",
        if iface.conf_file.exists() {
            "yes"
        } else {
            "no"
        },
    );
    print_kv(
        "interface_present",
        if interface_exists(&iface.interface) {
            "yes"
        } else {
            "no"
        },
    );
    print_kv(
        "link_up",
        if ip_link_is_up(&iface.interface) {
            "yes"
        } else {
            "no"
        },
    );
    print_kv(
        "addr_present",
        if ip_addr_has_inet(&iface.interface) {
            "yes"
        } else {
            "no"
        },
    );
    print_kv(
        "wg_show",
        if safe_capture("wg", &["show", &iface.interface]).starts_with("<failed:") {
            "no"
        } else {
            "yes"
        },
    );

    print_header("systemd status");
    println!(
        "{}",
        safe_capture("systemctl", &["status", &service, "--no-pager", "--full"])
    );

    print_header("journalctl recent");
    println!(
        "{}",
        safe_capture("journalctl", &["-u", &service, "-n", "80", "--no-pager"])
    );

    print_header("ip link");
    println!(
        "{}",
        safe_capture("ip", &["link", "show", &iface.interface])
    );

    print_header("ip addr");
    println!(
        "{}",
        safe_capture("ip", &["addr", "show", "dev", &iface.interface])
    );

    print_header("wg show");
    println!("{}", safe_capture("wg", &["show", &iface.interface]));

    print_header("wireguard runtime dir");
    println!(
        "{}",
        safe_capture(
            "ls",
            &["-ld", app.wg_run_dir.to_str().unwrap_or("/run/wireguard")]
        )
    );
    println!(
        "{}",
        safe_capture(
            "ls",
            &["-l", app.wg_run_dir.to_str().unwrap_or("/run/wireguard")]
        )
    );

    print_header("client dir");
    println!(
        "{}",
        safe_capture(
            "ls",
            &["-ld", iface.client_dir.to_str().unwrap_or("<invalid>")]
        )
    );
    println!(
        "{}",
        safe_capture(
            "ls",
            &["-l", iface.client_dir.to_str().unwrap_or("<invalid>")]
        )
    );

    print_header("local log tail");
    let tail = safe_tail(&app.log_file, 80);
    if tail.trim().is_empty() {
        println!("<empty>");
    } else {
        println!("{tail}");
    }

    if !iface.conf_file.exists() {
        bail!("config file is missing: {}", iface.conf_file.display());
    }

    Ok(())
}
