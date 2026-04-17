use std::path::PathBuf;

use anyhow::bail;
use anyhow::Result;

use crate::config::AppConfig;
use crate::config::InterfaceConfig;
use crate::prompt::ask_text;
use crate::prompt::ask_yes_no;
use crate::prompt::select_one;
use crate::systemd;
use crate::util::ensure_config_exists;
use crate::util::ensure_required_commands;
use crate::util::interface_exists;
use crate::util::print_header;
use crate::util::print_kv;
use crate::util::safe_capture;
use crate::wireguard::InterfaceData;

pub fn list(app: &AppConfig) -> Result<()> {
    print_header("servers");
    let items = app.discover_interfaces();
    if items.is_empty() {
        println!(
            "No server configs were found in {}.",
            app.conf_dir.display()
        );
        return Ok(());
    }

    for item in items {
        println!("- {item}");
    }
    Ok(())
}

pub fn show(app: &AppConfig, interface: Option<String>) -> Result<()> {
    let iface = resolve_server(app, interface)?;
    ensure_config_exists(&iface)?;
    let data = InterfaceData::parse(&iface.conf_file)?;

    print_header("server show");
    print_kv("interface", &iface.interface);
    print_kv("config", iface.conf_file.display().to_string());
    print_kv("service", app.service_name(&iface.interface));
    print_kv(
        "address",
        data.interface_value("Address").unwrap_or("<unset>"),
    );
    print_kv(
        "listen_port",
        data.server_listen_port().unwrap_or("<unset>"),
    );
    print_kv("mtu", data.interface_value("MTU").unwrap_or("<unset>"));
    print_kv("managed_clients", data.managed_clients().len().to_string());
    Ok(())
}

pub fn up(app: &AppConfig, interface: Option<String>) -> Result<()> {
    ensure_required_commands()?;
    ensure_unit_installed(app)?;
    let iface = resolve_server(app, interface)?;
    let service = app.service_name(&iface.interface);
    systemd::start(&service)?;
    println!("Started {service}.");
    status(app, Some(iface.interface))
}

pub fn down(app: &AppConfig, interface: Option<String>) -> Result<()> {
    ensure_required_commands()?;
    ensure_unit_installed(app)?;
    let iface = resolve_server(app, interface)?;
    let service = app.service_name(&iface.interface);
    systemd::stop(&service)?;
    println!("Stopped {service}.");
    Ok(())
}

pub fn restart(app: &AppConfig, interface: Option<String>) -> Result<()> {
    ensure_required_commands()?;
    ensure_unit_installed(app)?;
    let iface = resolve_server(app, interface)?;
    let service = app.service_name(&iface.interface);
    systemd::restart(&service)?;
    println!("Restarted {service}.");
    status(app, Some(iface.interface))
}

pub fn status(app: &AppConfig, interface: Option<String>) -> Result<()> {
    let iface = resolve_server(app, interface)?;
    let service = app.service_name(&iface.interface);

    print_header("service");
    print_kv("unit", &service);
    print_kv(
        "active",
        systemd::is_active(&service).unwrap_or_else(|_| "unknown".to_string()),
    );

    print_header("interface");
    print_kv("name", &iface.interface);
    print_kv("config", iface.conf_file.display().to_string());
    print_kv(
        "present",
        if interface_exists(&iface.interface) {
            "yes"
        } else {
            "no"
        },
    );
    println!(
        "{}",
        safe_capture("ip", &["-brief", "addr", "show", "dev", &iface.interface])
    );

    print_header("wireguard");
    println!("{}", safe_capture("wg", &["show", &iface.interface]));
    Ok(())
}

pub fn edit(app: &AppConfig, interface: Option<String>) -> Result<()> {
    let iface = resolve_server(app, interface)?;
    ensure_config_exists(&iface)?;
    let mut data = InterfaceData::parse(&iface.conf_file)?;

    print_header("server edit");
    print_kv("interface", &iface.interface);
    print_kv("config", iface.conf_file.display().to_string());

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

    print_header("pending changes");
    print_kv("address", &next_address);
    print_kv("mtu", &next_mtu);
    print_kv("listen_port", &next_port);

    if !ask_yes_no("Save changes", true)? {
        println!("No changes written.");
        return Ok(());
    }

    data.set_interface_value("Address", next_address);
    data.set_interface_value("MTU", next_mtu);
    data.set_interface_value("ListenPort", next_port);
    data.write_to(&iface.conf_file)?;

    println!("Saved {}.", iface.conf_file.display());
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
