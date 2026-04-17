use std::fs;
use std::path::PathBuf;

use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use qrcode::render::unicode;
use qrcode::QrCode;

use super::server::resolve_server;
use crate::command_runner::run_capture;
use crate::command_runner::run_capture_with_input;
use crate::config::AppConfig;
use crate::prompt::ask_text;
use crate::prompt::ask_yes_no;
use crate::prompt::select_one;
use crate::state::discover_client_states;
use crate::state::load_client_state;
use crate::state::public_key_name_map;
use crate::state::remove_client_state;
use crate::state::save_client_state;
use crate::state::save_server_state;
use crate::state::write_import_report;
use crate::state::ClientState;
use crate::state::IgnoredImport;
use crate::state::LegacyClientConfig;
use crate::ui::kv;
use crate::ui::Table;
use crate::ui::Tone;
use crate::ui::{self};
use crate::util::ensure_config_exists;
use crate::util::ensure_paths;
use crate::util::safe_capture;
use crate::wireguard::render_client_config;
use crate::wireguard::InterfaceData;
use crate::wireguard::PeerConnectivityState;
use crate::wireguard::WgRuntimeSummary;

#[derive(Clone, Debug)]
struct ClientView {
    name: String,
    public_key: String,
    virtual_ip: String,
    remote_ip: String,
    rx: String,
    tx: String,
    last_seen: String,
    state: String,
    source: String,
    exportable: bool,
}

pub fn list(app: &AppConfig, interface: Option<String>) -> Result<()> {
    let iface = resolve_server(app, interface)?;
    ensure_config_exists(&iface)?;
    let runtime = read_runtime(&iface.interface);
    let states = discover_client_states(app, &iface.interface)?;
    let items = build_client_views(&states, runtime.as_ref());

    ui::print_section("clients");
    ui::print_kv_rows(&[
        kv("server", iface.interface.clone()),
        kv(
            "state_dir",
            app.instance_state_dir(&iface.interface)
                .display()
                .to_string(),
        ),
        kv("managed_complete", items.len().to_string()),
    ]);

    if items.is_empty() {
        ui::print_message(
            "No managed_complete clients were found in canonical state.",
            Tone::Warn,
        );
        ui::print_message(
            &format!("Try: wg-friend client import {}", iface.interface),
            Tone::Muted,
        );
        return Ok(());
    }

    let mut table = Table::new(vec![
        "name".to_string(),
        "remote_ip".to_string(),
        "virtual_ip".to_string(),
        "rx".to_string(),
        "tx".to_string(),
        "last_seen".to_string(),
        "state".to_string(),
        "source".to_string(),
    ]);
    for item in items {
        table.push_row(vec![
            item.name,
            item.remote_ip,
            item.virtual_ip,
            item.rx,
            item.tx,
            item.last_seen,
            ui::status_badge(&item.state),
            item.source,
        ]);
    }
    ui::print_table(&table);
    Ok(())
}

pub fn show(app: &AppConfig, interface: Option<String>, name: Option<String>) -> Result<()> {
    let iface = resolve_server(app, interface)?;
    ensure_config_exists(&iface)?;
    let runtime = read_runtime(&iface.interface);
    let states = discover_client_states(app, &iface.interface)?;
    let items = build_client_views(&states, runtime.as_ref());
    let client = resolve_client_view(&iface.interface, &items, name)?;
    let state = load_client_state(app, &iface.interface, &client.name)?;

    ui::print_section("client");
    ui::print_kv_rows(&[
        kv("server", iface.interface.clone()),
        kv("name", state.name),
        kv("source", state.source),
        kv("public_key", state.public_key),
        kv("virtual_ip", state.address),
        kv("remote_ip", client.remote_ip),
        kv("rx", client.rx),
        kv("tx", client.tx),
        kv("last_seen", client.last_seen),
        kv("state", ui::status_badge(&client.state)),
        kv("endpoint", state.endpoint),
        kv("dns", state.dns),
        kv("allowed_ips", state.allowed_ips),
        kv("exportable", ui::yes_no(client.exportable)),
        kv(
            "client_file",
            app.state_export_path(&iface.interface, &client.name)
                .display()
                .to_string(),
        ),
        kv(
            "state_file",
            app.state_client_meta_path(&iface.interface, &client.name)
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

    if load_client_state(app, &iface.interface, &name).is_ok() {
        bail!("managed_complete client already exists: {name}")
    }
    if data.managed_peer(&name).is_some() {
        bail!("server peer name already exists: {name}")
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
    ui::print_kv_rows(&[
        kv("server", iface.interface.clone()),
        kv("name", name.clone()),
        kv("address", address.clone()),
        kv("dns", dns.clone()),
        kv("endpoint", endpoint.clone()),
        kv(
            "state_dir",
            app.instance_state_dir(&iface.interface)
                .display()
                .to_string(),
        ),
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

    let export_path = app.state_export_path(&iface.interface, &name);
    if let Some(parent) = export_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    fs::write(&export_path, client_text)
        .with_context(|| format!("failed to write {}", export_path.display()))?;

    let client = ClientState {
        interface: iface.interface.clone(),
        name: name.clone(),
        source: "generated".to_string(),
        public_key: public_key.clone(),
        address: address.clone(),
        dns: dns.clone(),
        endpoint: endpoint.clone(),
        allowed_ips: "0.0.0.0/0".to_string(),
        server_public_key: server_public_key.clone(),
        preshared_key: preshared_key.clone(),
        persistent_keepalive: "25".to_string(),
        export_path: export_path.display().to_string(),
    };
    save_client_state(app, &client)?;
    save_server_state(app, &iface.interface, &data)?;

    ui::print_section("client created");
    ui::print_kv_rows(&[
        kv("server", iface.interface),
        kv("name", name),
        kv("public_key", public_key),
        kv("address", address),
        kv("client_file", export_path.display().to_string()),
    ]);
    Ok(())
}

pub fn import(app: &AppConfig, interface: Option<String>) -> Result<()> {
    let iface = resolve_server(app, interface)?;
    ensure_config_exists(&iface)?;
    ensure_paths(app, &iface)?;

    let mut data = InterfaceData::parse(&iface.conf_file)?;
    let legacy_dir = iface.client_dir.clone();

    ui::print_section("client import");
    ui::print_kv_rows(&[
        kv("server", iface.interface.clone()),
        kv("legacy_dir", legacy_dir.display().to_string()),
        kv(
            "state_dir",
            app.instance_state_dir(&iface.interface)
                .display()
                .to_string(),
        ),
    ]);

    if !legacy_dir.exists() {
        ui::print_message(
            "No legacy client export directory was found. Nothing to import.",
            Tone::Warn,
        );
        return Ok(());
    }

    let mut imported = Vec::new();
    let mut ignored = Vec::new();
    let mut changed = false;

    let mut entries = fs::read_dir(&legacy_dir)
        .with_context(|| format!("failed to read {}", legacy_dir.display()))?
        .flatten()
        .map(|entry| entry.path())
        .collect::<Vec<_>>();
    entries.sort();

    for path in entries {
        if !path.is_file() {
            continue;
        }
        if path.extension().and_then(|item| item.to_str()) != Some("conf") {
            continue;
        }

        let name = path
            .file_stem()
            .and_then(|item| item.to_str())
            .map(|item| item.to_string())
            .unwrap_or_else(|| "client".to_string());

        let legacy = match LegacyClientConfig::parse(&path) {
            Ok(item) => item,
            Err(error) => {
                ignored.push(IgnoredImport {
                    item: path.display().to_string(),
                    reason: error.to_string(),
                });
                continue;
            }
        };

        if let Err(error) = legacy.ensure_complete() {
            ignored.push(IgnoredImport {
                item: path.display().to_string(),
                reason: error.to_string(),
            });
            continue;
        }

        let private_key = legacy.private_key().unwrap_or_default().to_string();
        let public_key =
            match run_capture_with_input("wg", &["pubkey"], &format!("{private_key}\n")) {
                Ok(value) => value,
                Err(error) => {
                    ignored.push(IgnoredImport {
                        item: path.display().to_string(),
                        reason: format!("failed to derive public key: {error}"),
                    });
                    continue;
                }
            };

        let Some(peer) = data.peer_by_public_key(&public_key) else {
            ignored.push(IgnoredImport {
                item: path.display().to_string(),
                reason: "public key not found in server peer set".to_string(),
            });
            continue;
        };
        let peer_allowed_ips = peer.allowed_ips();
        let peer_preshared_key = peer.values.get("PresharedKey").cloned().unwrap_or_default();

        if let Some(existing) = data.managed_peer(&name) {
            if existing.public_key() != Some(public_key.as_str()) {
                ignored.push(IgnoredImport {
                    item: path.display().to_string(),
                    reason: format!("name '{}' already maps to another peer", name),
                });
                continue;
            }
        }

        if let Some(server_peer) = data.peer_by_public_key_mut(&public_key) {
            if server_peer.managed_name.as_deref() != Some(name.as_str()) {
                server_peer.managed_name = Some(name.clone());
                changed = true;
            }
        }

        let export_path = app.state_export_path(&iface.interface, &name);
        if let Some(parent) = export_path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
        fs::copy(&path, &export_path).with_context(|| {
            format!(
                "failed to copy {} to {}",
                path.display(),
                export_path.display()
            )
        })?;

        let client = ClientState {
            interface: iface.interface.clone(),
            name: name.clone(),
            source: "imported".to_string(),
            public_key: public_key.clone(),
            address: legacy.address().unwrap_or(&peer_allowed_ips).to_string(),
            dns: legacy.dns().unwrap_or(&app.default_client_dns).to_string(),
            endpoint: legacy
                .endpoint()
                .unwrap_or(&app.default_client_endpoint)
                .to_string(),
            allowed_ips: legacy.allowed_ips().unwrap_or("0.0.0.0/0").to_string(),
            server_public_key: legacy.server_public_key().unwrap_or_default().to_string(),
            preshared_key: if let Some(value) = legacy.preshared_key() {
                value.to_string()
            } else {
                peer_preshared_key.clone()
            },
            persistent_keepalive: legacy.persistent_keepalive().unwrap_or("25").to_string(),
            export_path: export_path.display().to_string(),
        };
        save_client_state(app, &client)?;
        imported.push(name);
    }

    if changed {
        data.write_to(&iface.conf_file)?;
    }
    save_server_state(app, &iface.interface, &data)?;
    write_import_report(app, &iface.interface, &imported, &ignored)?;

    ui::print_section("import result");
    ui::print_kv_rows(&[
        kv("imported", imported.len().to_string()),
        kv("ignored", ignored.len().to_string()),
        kv(
            "report",
            app.state_import_report_path(&iface.interface)
                .display()
                .to_string(),
        ),
    ]);

    if !imported.is_empty() {
        let mut table = Table::new(vec!["name".to_string(), "export".to_string()]);
        for name in &imported {
            table.push_row(vec![
                name.clone(),
                app.state_export_path(&iface.interface, name)
                    .display()
                    .to_string(),
            ]);
        }
        ui::print_section("imported clients");
        ui::print_table(&table);
    }

    if !ignored.is_empty() {
        let mut table = Table::new(vec!["item".to_string(), "reason".to_string()]);
        for item in &ignored {
            table.push_row(vec![item.item.clone(), item.reason.clone()]);
        }
        ui::print_section("ignored assets");
        ui::print_table(&table);
    }

    Ok(())
}

pub fn qrcode(app: &AppConfig, interface: Option<String>, name: Option<String>) -> Result<()> {
    let iface = resolve_server(app, interface)?;
    let state = resolve_complete_client_state(app, &iface.interface, name)?;
    let source = PathBuf::from(&state.export_path);
    if !source.exists() {
        bail!("client export file not found: {}", source.display())
    }

    let text = fs::read_to_string(&source)
        .with_context(|| format!("failed to read {}", source.display()))?;
    let code = QrCode::new(text.as_bytes()).context("failed to build QR code")?;

    ui::print_section("client qrcode");
    ui::print_kv_rows(&[
        kv("server", iface.interface),
        kv("name", state.name.clone()),
        kv("source", source.display().to_string()),
    ]);

    let rendered = code.render::<unicode::Dense1x2>().quiet_zone(false).build();
    println!("{rendered}");
    Ok(())
}

pub fn remove(app: &AppConfig, interface: Option<String>, name: Option<String>) -> Result<()> {
    let iface = resolve_server(app, interface)?;
    ensure_config_exists(&iface)?;
    let mut data = InterfaceData::parse(&iface.conf_file)?;
    let state = resolve_complete_client_state(app, &iface.interface, name)?;

    ui::print_section("client remove");
    ui::print_kv_rows(&[
        kv("server", iface.interface.clone()),
        kv("name", state.name.clone()),
        kv("public_key", state.public_key.clone()),
        kv("client_file", state.export_path.clone()),
    ]);

    if !ask_yes_no("Remove client", false)? {
        ui::print_message("No changes written.", Tone::Warn);
        return Ok(());
    }

    data.remove_managed_peer(&state.name);
    data.write_to(&iface.conf_file)?;
    remove_client_state(app, &iface.interface, &state.name)?;
    save_server_state(app, &iface.interface, &data)?;

    ui::print_section("client removed");
    ui::print_kv_rows(&[
        kv("server", iface.interface),
        kv("name", state.name),
        kv("result", ui::status_badge("removed")),
    ]);
    Ok(())
}

pub fn export(
    app: &AppConfig,
    interface: Option<String>,
    name: Option<String>,
    output: Option<PathBuf>,
) -> Result<()> {
    let iface = resolve_server(app, interface)?;
    let state = resolve_complete_client_state(app, &iface.interface, name)?;

    let source = PathBuf::from(&state.export_path);
    if !source.exists() {
        bail!("client export file not found: {}", source.display())
    }

    let output = match output {
        Some(path) => path,
        None => PathBuf::from(format!("./{}-{}.conf", state.name, iface.interface)),
    };

    fs::copy(&source, &output).with_context(|| {
        format!(
            "failed to copy {} to {}",
            source.display(),
            output.display()
        )
    })?;

    ui::print_section("client export");
    ui::print_kv_rows(&[
        kv("server", iface.interface),
        kv("name", state.name),
        kv("source", source.display().to_string()),
        kv("output", output.display().to_string()),
    ]);
    Ok(())
}

fn build_client_views(
    states: &[ClientState],
    runtime: Option<&WgRuntimeSummary>,
) -> Vec<ClientView> {
    let mut items = Vec::new();

    for state in states {
        let runtime_peer =
            runtime.and_then(|summary| summary.peer_by_public_key(&state.public_key));
        let (rx, tx, remote_ip, last_seen, item_state) = match runtime_peer {
            Some(item) => {
                let state = item.connectivity_state();
                (
                    item.rx_bytes_text(),
                    item.tx_bytes_text(),
                    item.endpoint
                        .clone()
                        .unwrap_or_else(|| "(none)".to_string()),
                    item.last_seen_text(),
                    state.as_str().to_string(),
                )
            }
            None => (
                "0B".to_string(),
                "0B".to_string(),
                "(none)".to_string(),
                "(not yet)".to_string(),
                PeerConnectivityState::Offline.as_str().to_string(),
            ),
        };

        items.push(ClientView {
            name: state.name.clone(),
            public_key: state.public_key.clone(),
            virtual_ip: state.address.clone(),
            remote_ip,
            rx,
            tx,
            last_seen,
            state: item_state,
            source: state.source.clone(),
            exportable: true,
        });
    }

    items.sort_by(|left, right| left.name.cmp(&right.name));
    items
}

fn read_runtime(interface: &str) -> Option<WgRuntimeSummary> {
    let raw = safe_capture("wg", &["show", interface]);
    if raw.starts_with("<failed:") {
        None
    } else {
        Some(WgRuntimeSummary::parse(&raw))
    }
}

fn resolve_client_view(
    interface: &str,
    items: &[ClientView],
    name: Option<String>,
) -> Result<ClientView> {
    if let Some(name) = name {
        let Some(item) = items.iter().find(|item| item.name == name) else {
            bail!(
                "managed_complete client not found for {}: {name}",
                interface
            )
        };
        return Ok(item.clone());
    }

    if items.is_empty() {
        bail!("no managed_complete clients found for {interface}")
    }
    if items.len() == 1 {
        return Ok(items[0].clone());
    }

    let options = items
        .iter()
        .map(|item| item.name.clone())
        .collect::<Vec<_>>();
    let selected = select_one("Select client", &options)?;
    let Some(item) = items.iter().find(|item| item.name == selected) else {
        bail!("selected client not found: {selected}")
    };
    Ok(item.clone())
}

fn resolve_complete_client_state(
    app: &AppConfig,
    interface: &str,
    name: Option<String>,
) -> Result<ClientState> {
    if let Some(name) = name {
        return load_client_state(app, interface, &name);
    }

    let items = discover_client_states(app, interface)?;
    if items.is_empty() {
        bail!("no managed_complete clients found for {interface}")
    }
    if items.len() == 1 {
        return Ok(items[0].clone());
    }

    let options = items
        .iter()
        .map(|item| item.name.clone())
        .collect::<Vec<_>>();
    let selected = select_one("Select client", &options)?;
    load_client_state(app, interface, &selected)
}

fn resolve_server_public_key(interface: &str, data: &InterfaceData) -> Result<String> {
    let private_key = data
        .server_private_key()
        .ok_or_else(|| anyhow::anyhow!("server config for {interface} is missing PrivateKey"))?
        .to_string();

    run_capture_with_input("wg", &["pubkey"], &format!("{private_key}\n"))
        .with_context(|| format!("failed to derive public key for server {interface}"))
}

pub fn canonical_name_map(
    app: &AppConfig,
    interface: &str,
) -> Result<std::collections::BTreeMap<String, String>> {
    public_key_name_map(app, interface)
}
