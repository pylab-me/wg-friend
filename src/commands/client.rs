use std::fs;
use std::path::PathBuf;

use anyhow::bail;
use anyhow::Context;
use anyhow::Result;

use super::server::resolve_server;
use crate::command_runner::run_capture;
use crate::command_runner::run_capture_with_input;
use crate::config::AppConfig;
use crate::prompt::ask_text;
use crate::prompt::ask_yes_no;
use crate::prompt::select_one;
use crate::ui::kv;
use crate::ui::Table;
use crate::ui::Tone;
use crate::ui::{self};
use crate::util::client_file_name_from_path;
use crate::util::ensure_config_exists;
use crate::util::ensure_paths;
use crate::wireguard::render_client_config;
use crate::wireguard::InterfaceData;

pub fn list(app: &AppConfig, interface: Option<String>) -> Result<()> {
    let iface = resolve_server(app, interface)?;
    ensure_config_exists(&iface)?;
    let data = InterfaceData::parse(&iface.conf_file)?;
    let managed = data.managed_clients();

    ui::print_section("clients");
    ui::print_kv_rows(&vec![
        kv("server", iface.interface.clone()),
        kv("config", iface.conf_file.display().to_string()),
        kv("managed_clients", managed.len().to_string()),
    ]);

    if managed.is_empty() {
        ui::print_message("No managed clients found.", Tone::Warn);
        return Ok(());
    }

    let mut table = Table::new(vec![
        "name".to_string(),
        "allowed_ips".to_string(),
        "public_key".to_string(),
    ]);
    for name in managed {
        if let Some(peer) = data.managed_peer(&name) {
            table.push_row(vec![
                name,
                peer.values
                    .get("AllowedIPs")
                    .cloned()
                    .unwrap_or_else(|| "-".to_string()),
                ui::truncate_middle(
                    peer.values
                        .get("PublicKey")
                        .map(String::as_str)
                        .unwrap_or("-"),
                    20,
                ),
            ]);
        }
    }
    ui::print_table(&table);
    Ok(())
}

pub fn show(app: &AppConfig, interface: Option<String>, name: Option<String>) -> Result<()> {
    let iface = resolve_server(app, interface)?;
    ensure_config_exists(&iface)?;
    let data = InterfaceData::parse(&iface.conf_file)?;
    let name = resolve_client_name(&iface.interface, &data, name)?;
    let peer = data
        .managed_peer(&name)
        .ok_or_else(|| anyhow::anyhow!("managed client not found: {name}"))?;

    ui::print_section("client");
    ui::print_kv_rows(&vec![
        kv("server", iface.interface.clone()),
        kv("name", name.clone()),
        kv(
            "allowed_ips",
            peer.values
                .get("AllowedIPs")
                .cloned()
                .unwrap_or_else(|| "<unset>".to_string()),
        ),
        kv(
            "public_key",
            peer.values
                .get("PublicKey")
                .cloned()
                .unwrap_or_else(|| "<unset>".to_string()),
        ),
        kv(
            "keepalive",
            peer.values
                .get("PersistentKeepalive")
                .cloned()
                .unwrap_or_else(|| "<unset>".to_string()),
        ),
        kv(
            "client_file",
            app.client_file_path(&iface.interface, &name)
                .display()
                .to_string(),
        ),
    ]);
    Ok(())
}

pub fn add(
    app: &AppConfig,
    interface: Option<String>,
    name: Option<String>,
    address: Option<String>,
    dns: Option<String>,
    endpoint: Option<String>,
) -> Result<()> {
    let iface = resolve_server(app, interface)?;
    ensure_config_exists(&iface)?;
    ensure_paths(app, &iface)?;

    let mut data = InterfaceData::parse(&iface.conf_file)?;
    let name = match name {
        Some(value) => value,
        None => ask_text("Client name", None)?,
    };

    if data.managed_peer(&name).is_some() {
        bail!("managed client already exists: {name}")
    }

    let suggested_address = data.suggest_next_client_address()?;
    let address = match address {
        Some(value) => value,
        None => ask_text("IPv4 address", Some(&suggested_address))?,
    };

    let dns_hint = data
        .server_dns_hint()
        .unwrap_or_else(|| app.default_client_dns.clone());
    let dns = match dns {
        Some(value) => value,
        None => ask_text("DNS", Some(&dns_hint))?,
    };

    let endpoint = match endpoint {
        Some(value) => value,
        None => ask_text("Endpoint", Some(&app.default_client_endpoint))?,
    };

    ui::print_section("client add");
    ui::print_kv_rows(&vec![
        kv("server", iface.interface.clone()),
        kv("name", name.clone()),
        kv("address", address.clone()),
        kv("dns", dns.clone()),
        kv("endpoint", endpoint.clone()),
    ]);

    if !ask_yes_no("Create client", true)? {
        ui::print_message("No changes written.", Tone::Warn);
        return Ok(());
    }

    let private_key =
        run_capture("wg", &["genkey"]).context("failed to generate private key with wg genkey")?;
    let public_key = run_capture_with_input("wg", &["pubkey"], &format!("{private_key}\n"))
        .context("failed to derive public key with wg pubkey")?;
    let preshared_key = run_capture("wg", &["genpsk"])
        .context("failed to generate preshared key with wg genpsk")?;

    data.add_managed_peer(&name, &public_key, &address, &preshared_key);
    data.write_to(&iface.conf_file)?;

    let server_public_key = resolve_server_public_key(&iface.interface, &data)?;
    let client_text = render_client_config(
        &private_key,
        &address,
        &dns,
        &server_public_key,
        &endpoint,
        &preshared_key,
    );
    let client_file = app.client_file_path(&iface.interface, &name);
    if let Some(parent) = client_file.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    fs::write(&client_file, client_text)
        .with_context(|| format!("failed to write {}", client_file.display()))?;

    ui::print_section("client created");
    ui::print_kv_rows(&vec![
        kv("server", iface.interface),
        kv("name", name),
        kv("server_config", iface.conf_file.display().to_string()),
        kv("client_config", client_file.display().to_string()),
    ]);
    Ok(())
}

pub fn remove(app: &AppConfig, interface: Option<String>, name: Option<String>) -> Result<()> {
    let iface = resolve_server(app, interface)?;
    ensure_config_exists(&iface)?;

    let mut data = InterfaceData::parse(&iface.conf_file)?;
    let name = resolve_client_name(&iface.interface, &data, name)?;

    ui::print_section("client remove");
    ui::print_kv_rows(&vec![
        kv("server", iface.interface.clone()),
        kv("name", name.clone()),
    ]);

    if !ask_yes_no("Remove client", true)? {
        ui::print_message("No changes written.", Tone::Warn);
        return Ok(());
    }

    if !data.remove_managed_peer(&name) {
        bail!("managed client not found: {name}")
    }
    data.write_to(&iface.conf_file)?;

    let client_file = app.client_file_path(&iface.interface, &name);
    if client_file.exists() {
        fs::remove_file(&client_file)
            .with_context(|| format!("failed to remove {}", client_file.display()))?;
    }

    ui::print_message(
        &format!("Removed client {name} from {}.", iface.interface),
        Tone::Good,
    );
    Ok(())
}

pub fn export(
    app: &AppConfig,
    interface: Option<String>,
    name: Option<String>,
    output: Option<PathBuf>,
) -> Result<()> {
    let iface = resolve_server(app, interface)?;
    ensure_config_exists(&iface)?;
    let data = InterfaceData::parse(&iface.conf_file)?;
    let name = resolve_client_name(&iface.interface, &data, name)?;

    let source = app.client_file_path(&iface.interface, &name);
    if !source.exists() {
        bail!("client export file not found: {}", source.display())
    }

    let output = match output {
        Some(path) => path,
        None => PathBuf::from(format!("./{name}-{}.conf", iface.interface)),
    };

    fs::copy(&source, &output).with_context(|| {
        format!(
            "failed to copy {} to {}",
            source.display(),
            output.display()
        )
    })?;

    ui::print_section("client export");
    ui::print_kv_rows(&vec![
        kv("server", iface.interface),
        kv("name", name),
        kv("source", source.display().to_string()),
        kv("output", output.display().to_string()),
    ]);
    Ok(())
}

fn resolve_client_name(
    interface: &str,
    data: &InterfaceData,
    name: Option<String>,
) -> Result<String> {
    if let Some(name) = name {
        return Ok(name);
    }

    let items = data.managed_clients();
    if items.is_empty() {
        bail!("no managed clients found for {interface}")
    }
    if items.len() == 1 {
        return Ok(items[0].clone());
    }

    select_one("Select client", &items)
}

fn resolve_server_public_key(interface: &str, data: &InterfaceData) -> Result<String> {
    if let Some(private_key) = data.server_private_key() {
        return run_capture_with_input("wg", &["pubkey"], &format!("{private_key}\n"));
    }

    let key = run_capture("wg", &["show", interface, "public-key"]);
    match key {
        Ok(value) if !value.trim().is_empty() => Ok(value),
        Ok(_) => bail!("server public key is empty for {interface}"),
        Err(error) => bail!("failed to resolve server public key for {interface}: {error}"),
    }
}

#[allow(dead_code)]
fn discover_client_names(app: &AppConfig, interface: &str) -> Vec<String> {
    let dir = app
        .resolve_interface(Some(interface.to_string()))
        .client_dir;
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(_) => return Vec::new(),
    };

    let mut items = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        if path.extension().and_then(|item| item.to_str()) != Some("conf") {
            continue;
        }
        if let Some(name) = client_file_name_from_path(&path) {
            items.push(name);
        }
    }
    items.sort();
    items
}
