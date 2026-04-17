use std::path::PathBuf;

use anyhow::bail;
use anyhow::Result;

use crate::config::AppConfig;
use crate::config::InterfaceConfig;
use crate::prompt::ask_text;
use crate::prompt::ask_yes_no;
use crate::prompt::select_one;
use crate::state::discover_client_states;
use crate::state::save_server_state;
use crate::systemd;
use crate::ui::kv;
use crate::ui::Table;
use crate::ui::Tone;
use crate::ui::{self};
use crate::util::ensure_config_exists;
use crate::util::ensure_required_commands;
use crate::util::interface_exists;
use crate::util::parse_ip_brief_addr;
use crate::util::safe_capture;
use crate::wireguard::InterfaceData;
use crate::wireguard::WgRuntimeSummary;

pub fn list(app: &AppConfig) -> Result<()> {
    let items = app.discover_interfaces();

    ui::print_section("servers");
    if items.is_empty() {
        ui::print_message(
            &format!(
                "No server configs were found in {}.",
                app.conf_dir.display()
            ),
            Tone::Warn,
        );
        return Ok(());
    }

    let mut table = Table::new(vec![
        "interface".to_string(),
        "config".to_string(),
        "clients".to_string(),
    ]);
    for item in items {
        let iface = app.resolve_interface(Some(item.clone()));
        let client_count = discover_client_states(app, &item)
            .map(|items| items.len().to_string())
            .unwrap_or_else(|_| "?".to_string());
        table.push_row(vec![
            item,
            iface.conf_file.display().to_string(),
            client_count,
        ]);
    }
    ui::print_table(&table);
    Ok(())
}

pub fn show(app: &AppConfig, interface: Option<String>) -> Result<()> {
    let iface = resolve_server(app, interface)?;
    ensure_config_exists(&iface)?;
    let data = InterfaceData::parse(&iface.conf_file)?;

    ui::print_section("server");
    let canonical_clients = discover_client_states(app, &iface.interface).unwrap_or_default();
    ui::print_kv_rows(&vec![
        kv("interface", iface.interface.clone()),
        kv("config", iface.conf_file.display().to_string()),
        kv("service", app.service_name(&iface.interface)),
        kv(
            "address",
            data.interface_value("Address")
                .unwrap_or("<unset>")
                .to_string(),
        ),
        kv(
            "listen_port",
            data.server_listen_port().unwrap_or("<unset>").to_string(),
        ),
        kv(
            "mtu",
            data.interface_value("MTU").unwrap_or("<unset>").to_string(),
        ),
        kv("managed_complete", canonical_clients.len().to_string()),
        kv(
            "state_dir",
            app.instance_state_dir(&iface.interface)
                .display()
                .to_string(),
        ),
    ]);

    if !canonical_clients.is_empty() {
        ui::print_section("managed_complete clients");
        let mut table = Table::new(vec![
            "name".to_string(),
            "address".to_string(),
            "public_key".to_string(),
            "source".to_string(),
        ]);
        for client in canonical_clients {
            table.push_row(vec![
                client.name,
                client.address,
                ui::truncate_middle(&client.public_key, 20),
                client.source,
            ]);
        }
        ui::print_table(&table);
    }
    Ok(())
}

pub fn up(app: &AppConfig, interface: Option<String>) -> Result<()> {
    ensure_required_commands()?;
    ensure_unit_installed(app)?;
    let iface = resolve_server(app, interface)?;
    let service = app.service_name(&iface.interface);
    systemd::start(&service)?;

    ui::print_section("server up");
    ui::print_kv_rows(&vec![
        kv("interface", iface.interface.clone()),
        kv("service", service.clone()),
        kv("result", ui::status_badge("started")),
    ]);

    status(app, Some(iface.interface))
}

pub fn down(app: &AppConfig, interface: Option<String>) -> Result<()> {
    ensure_required_commands()?;
    ensure_unit_installed(app)?;
    let iface = resolve_server(app, interface)?;
    let service = app.service_name(&iface.interface);
    systemd::stop(&service)?;

    ui::print_section("server down");
    ui::print_kv_rows(&vec![
        kv("interface", iface.interface),
        kv("service", service),
        kv("result", ui::status_badge("stopped")),
    ]);
    Ok(())
}

pub fn restart(app: &AppConfig, interface: Option<String>) -> Result<()> {
    ensure_required_commands()?;
    ensure_unit_installed(app)?;
    let iface = resolve_server(app, interface)?;
    let service = app.service_name(&iface.interface);
    systemd::restart(&service)?;

    ui::print_section("server restart");
    ui::print_kv_rows(&vec![
        kv("interface", iface.interface.clone()),
        kv("service", service.clone()),
        kv("result", ui::status_badge("restarted")),
    ]);

    status(app, Some(iface.interface))
}

pub fn status(app: &AppConfig, interface: Option<String>) -> Result<()> {
    let iface = resolve_server(app, interface)?;
    let service = app.service_name(&iface.interface);
    let active = systemd::is_active(&service).unwrap_or_else(|_| "unknown".to_string());
    let enabled = systemd::is_enabled(&service).unwrap_or_else(|_| "unknown".to_string());

    ui::print_section("service");
    ui::print_kv_rows(&vec![
        kv("unit", service.clone()),
        kv("active", ui::status_badge(&active)),
        kv("enabled", ui::status_badge(&enabled)),
    ]);

    ui::print_section("interface");
    let brief = parse_ip_brief_addr(&safe_capture(
        "ip",
        &["-brief", "addr", "show", "dev", &iface.interface],
    ));
    let present = interface_exists(&iface.interface);
    let state = brief
        .as_ref()
        .map(|item| item.state.clone())
        .unwrap_or_else(|| "missing".to_string());
    let ipv4 = brief
        .as_ref()
        .map(|item| {
            if item.ipv4.is_empty() {
                "-".to_string()
            } else {
                item.ipv4.join(", ")
            }
        })
        .unwrap_or_else(|| "-".to_string());
    let ipv6 = brief
        .as_ref()
        .map(|item| {
            if item.ipv6.is_empty() {
                "-".to_string()
            } else {
                item.ipv6.join(", ")
            }
        })
        .unwrap_or_else(|| "-".to_string());

    ui::print_kv_rows(&vec![
        kv("name", iface.interface.clone()),
        kv("config", iface.conf_file.display().to_string()),
        kv("present", ui::yes_no(present)),
        kv("state", ui::status_badge(&state)),
        kv("ipv4", ipv4),
        kv("ipv6", ipv6),
    ]);

    ui::print_section("wireguard");
    let wg_raw = safe_capture("wg", &["show", &iface.interface]);
    if wg_raw.starts_with("<failed:") {
        ui::print_message(&wg_raw, Tone::Bad);
        return Ok(());
    }

    let runtime = WgRuntimeSummary::parse(&wg_raw);
    let config_data = InterfaceData::parse(&iface.conf_file).ok();
    let canonical_names =
        crate::commands::client::canonical_name_map(app, &iface.interface).unwrap_or_default();
    ui::print_kv_rows(&vec![
        kv(
            "interface",
            if runtime.interface.is_empty() {
                iface.interface.clone()
            } else {
                runtime.interface.clone()
            },
        ),
        kv(
            "listen_port",
            runtime
                .listen_port
                .clone()
                .unwrap_or_else(|| "-".to_string()),
        ),
        kv("peer_count", runtime.peers.len().to_string()),
    ]);

    if runtime.peers.is_empty() {
        ui::print_message("No peers are currently visible via `wg show`.", Tone::Warn);
        return Ok(());
    }

    ui::print_section("peers");
    let mut table = Table::new(vec![
        "name".to_string(),
        "public_key".to_string(),
        "endpoint".to_string(),
        "allowed_ips".to_string(),
        "handshake".to_string(),
    ]);
    for peer in runtime.peers {
        let name = canonical_names
            .get(&peer.public_key)
            .cloned()
            .or_else(|| {
                config_data
                    .as_ref()
                    .and_then(|data| data.managed_name_by_public_key(&peer.public_key))
            })
            .unwrap_or_else(|| format!("legacy:{}", ui::truncate_middle(&peer.public_key, 8)));
        table.push_row(vec![
            name,
            ui::truncate_middle(&peer.public_key, 18),
            peer.endpoint.unwrap_or_else(|| "-".to_string()),
            peer.allowed_ips.unwrap_or_else(|| "-".to_string()),
            peer.latest_handshake.unwrap_or_else(|| "-".to_string()),
        ]);
    }
    ui::print_table(&table);
    Ok(())
}

pub fn edit(app: &AppConfig, interface: Option<String>) -> Result<()> {
    let iface = resolve_server(app, interface)?;
    ensure_config_exists(&iface)?;
    let mut data = InterfaceData::parse(&iface.conf_file)?;

    ui::print_section("server edit");
    ui::print_kv_rows(&vec![
        kv("interface", iface.interface.clone()),
        kv("config", iface.conf_file.display().to_string()),
    ]);

    let current_address = data
        .interface_value("Address")
        .unwrap_or(&app.default_addr)
        .to_string();
    let current_mtu = data
        .interface_value("MTU")
        .unwrap_or(&app.default_mtu)
        .to_string();
    let current_port = data
        .interface_value("ListenPort")
        .unwrap_or("51820")
        .to_string();

    let next_address = ask_text("Address", Some(&current_address))?;
    let next_mtu = ask_text("MTU", Some(&current_mtu))?;
    let next_port = ask_text("ListenPort", Some(&current_port))?;

    ui::print_section("pending changes");
    ui::print_kv_rows(&vec![
        kv("address", next_address.clone()),
        kv("mtu", next_mtu.clone()),
        kv("listen_port", next_port.clone()),
    ]);

    if !ask_yes_no("Save changes", true)? {
        ui::print_message("No changes written.", Tone::Warn);
        return Ok(());
    }

    data.set_interface_value("Address", next_address);
    data.set_interface_value("MTU", next_mtu);
    data.set_interface_value("ListenPort", next_port);
    data.write_to(&iface.conf_file)?;
    save_server_state(app, &iface.interface, &data)?;

    ui::print_message(&format!("Saved {}.", iface.conf_file.display()), Tone::Good);
    Ok(())
}

pub fn resolve_server(app: &AppConfig, interface: Option<String>) -> Result<InterfaceConfig> {
    if interface.is_some() {
        return Ok(app.resolve_interface(interface));
    }

    let items = app.discover_interfaces();
    if items.is_empty() {
        return Ok(app.resolve_interface(None));
    }

    if items.len() == 1 {
        return Ok(app.resolve_interface(Some(items[0].clone())));
    }

    let chosen = select_one("Select server", &items)?;
    Ok(app.resolve_interface(Some(chosen)))
}

fn ensure_unit_installed(app: &AppConfig) -> Result<()> {
    let unit_path = PathBuf::from(format!(
        "/etc/systemd/system/{}@.service",
        app.systemd_unit_prefix
    ));
    if !unit_path.exists() {
        bail!(
            "systemd template is not installed: {}\nrun: sudo wg-friend service install",
            unit_path.display()
        );
    }
    Ok(())
}
