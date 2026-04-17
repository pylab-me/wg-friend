use std::fs;

use anyhow::Result;

use crate::command_runner::run;
use crate::command_runner::run_capture;
use crate::config::AppConfig;
use crate::ui::kv;
use crate::ui::{self};
use crate::util::clean_wireguard_config;
use crate::util::ensure_boringtun_present;
use crate::util::ensure_config_exists;
use crate::util::ensure_paths;
use crate::util::ensure_required_commands;
use crate::util::ensure_root;
use crate::util::ensure_tun_device;
use crate::util::extract_config_value;
use crate::util::interface_exists;
use crate::util::ip_addr_has_inet;
use crate::util::ip_link_is_up;
use crate::util::wait_until;
use crate::util::wg_show_ready;

pub fn preflight(app: &AppConfig, interface: String) -> Result<()> {
    ensure_root()?;
    ensure_required_commands()?;
    ensure_boringtun_present(app)?;
    ensure_tun_device()?;

    let iface = app.resolve_interface(Some(interface));
    ensure_paths(app, &iface)?;
    ensure_config_exists(&iface)?;

    ui::print_section("preflight");
    ui::print_kv_rows(&vec![
        kv("interface", iface.interface),
        kv("config", iface.conf_file.display().to_string()),
        kv("client_dir", iface.client_dir.display().to_string()),
        kv("boringtun", app.boringtun_bin.display().to_string()),
        kv("result", ui::status_badge("ok")),
    ]);
    Ok(())
}

pub fn configure(app: &AppConfig, interface: String) -> Result<()> {
    ensure_root()?;
    ensure_required_commands()?;

    let iface = app.resolve_interface(Some(interface));
    ensure_config_exists(&iface)?;

    wait_until("interface presence", app.interface_timeout, || {
        interface_exists(&iface.interface)
    })?;
    wait_until("WireGuard UAPI", app.uapi_timeout, || {
        wg_show_ready(&iface.interface)
    })?;

    let cleaned = clean_wireguard_config(&iface.conf_file)?;
    run(
        "wg",
        &[
            "setconf",
            &iface.interface,
            cleaned.to_str().unwrap_or_default(),
        ],
    )?;

    let address = extract_config_value(&iface.conf_file, "Address")?
        .unwrap_or_else(|| app.default_addr.clone());
    let mtu =
        extract_config_value(&iface.conf_file, "MTU")?.unwrap_or_else(|| app.default_mtu.clone());

    let current_addr =
        run_capture("ip", &["addr", "show", "dev", &iface.interface]).unwrap_or_default();
    let ip_token = address.split('/').next().unwrap_or(&address).to_string();

    if !current_addr.contains(&ip_token) {
        let _ = run(
            "ip",
            &[
                "address",
                "flush",
                "dev",
                &iface.interface,
                "scope",
                "global",
            ],
        );
        run("ip", &["address", "add", &address, "dev", &iface.interface])?;
    }

    run("ip", &["link", "set", "mtu", &mtu, "dev", &iface.interface])?;
    run("ip", &["link", "set", "up", "dev", &iface.interface])?;

    let _ = fs::remove_file(cleaned);

    ui::print_section("configure");
    ui::print_kv_rows(&vec![
        kv("interface", iface.interface),
        kv("address", address),
        kv("mtu", mtu),
        kv("result", ui::status_badge("ok")),
    ]);
    Ok(())
}

pub fn verify(app: &AppConfig, interface: String) -> Result<()> {
    ensure_root()?;
    ensure_required_commands()?;

    let iface = app.resolve_interface(Some(interface));

    wait_until("final interface readiness", app.ready_timeout, || {
        if !interface_exists(&iface.interface) {
            return false;
        }

        ip_link_is_up(&iface.interface)
            && ip_addr_has_inet(&iface.interface)
            && wg_show_ready(&iface.interface)
    })?;

    ui::print_section("verify");
    ui::print_kv_rows(&vec![
        kv("interface", iface.interface),
        kv("result", ui::status_badge("ready")),
    ]);
    Ok(())
}

pub fn cleanup(app: &AppConfig, interface: String) -> Result<()> {
    ensure_root()?;
    ensure_required_commands()?;

    let iface = app.resolve_interface(Some(interface));

    if interface_exists(&iface.interface) {
        let _ = run_capture("ip", &["link", "delete", &iface.interface]);
    }

    ui::print_section("cleanup");
    ui::print_kv_rows(&vec![
        kv("interface", iface.interface),
        kv("result", ui::status_badge("ok")),
    ]);
    Ok(())
}
