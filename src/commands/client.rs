use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;
use std::path::PathBuf;
use std::thread;
use std::time::Duration;

use anyhow::Context;
use anyhow::Result;
use anyhow::bail;
use qrcode::EcLevel;
use qrcode::QrCode;
use qrcode::render::unicode;

use super::server::resolve_server;
use crate::command_runner::run;
use crate::command_runner::run_capture;
use crate::command_runner::run_capture_with_input;
use crate::config::AppConfig;
use crate::prompt::ask_text;
use crate::prompt::ask_yes_no;
use crate::prompt::select_one;
use crate::state::ClientState;
use crate::state::IgnoredImport;
use crate::state::LegacyClientConfig;
use crate::state::discover_client_states;
use crate::state::load_client_state;
use crate::state::public_key_name_map;
use crate::state::remove_client_state;
use crate::state::rename_client_state;
use crate::state::save_client_state;
use crate::state::save_server_state;
use crate::state::write_import_report;
use crate::ui::Table;
use crate::ui::Tone;
use crate::ui::kv;
use crate::ui::{self};
use crate::util::base_ip_from_cidr;
use crate::util::clean_wireguard_config;
use crate::util::ensure_config_exists;
use crate::util::ensure_paths;
use crate::util::interface_exists;
use crate::util::safe_capture;
use crate::util::wg_show_ready;
use crate::wireguard::InterfaceData;
use crate::wireguard::PeerConnectivityState;
use crate::wireguard::WgRuntimePeer;
use crate::wireguard::WgRuntimeSummary;
use crate::wireguard::render_client_config;

#[derive(Clone, Debug)]
struct ClientView {
    name: String,
    virtual_ip: String,
    remote_ip: String,
    rx: String,
    tx: String,
    last_seen: String,
    state: String,
    source: String,
    exportable: bool,
}

#[derive(Clone, Debug)]
struct RuntimeClientSnapshot {
    remote_ip: String,
    rx: String,
    tx: String,
    last_seen: String,
    state: String,
}

#[derive(Clone, Debug)]
struct ImportCandidate {
    path: PathBuf,
    name: String,
    source: String,
}

pub fn list(app: &AppConfig, interface: Option<String>) -> Result<()> {
    let iface = resolve_server(app, interface)?;
    ensure_config_exists(&iface)?;
    let items = collect_client_views(app, &iface.interface)?;
    print_client_snapshot(app, &iface.interface, &items, "clients", false);
    Ok(())
}

pub fn stats(app: &AppConfig, interface: Option<String>, watch: Option<u64>) -> Result<()> {
    let iface = resolve_server(app, interface)?;
    ensure_config_exists(&iface)?;
    let interval = Duration::from_secs(watch.unwrap_or(0));

    loop {
        let items = collect_client_views(app, &iface.interface)?;
        if watch.is_some() {
            print!("\x1b[2J\x1b[H");
        }
        print_client_snapshot(app, &iface.interface, &items, "client stats", true);
        if watch.is_none() {
            break;
        }
        thread::sleep(interval);
    }
    Ok(())
}

pub fn show(app: &AppConfig, interface: Option<String>, name: Option<String>) -> Result<()> {
    let iface = resolve_server(app, interface)?;
    ensure_config_exists(&iface)?;
    let items = collect_client_views(app, &iface.interface)?;
    let client = resolve_client_view(&iface.interface, &items, name)?;
    let state = load_client_state(app, &iface.interface, &client.name)?;

    ui::print_section("client");
    ui::print_kv_rows(&[
        kv("server", iface.interface.clone()),
        kv("name", state.name),
        kv("enabled", ui::yes_no(state.enabled)),
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

    let peer_allowed_ip = peer_allowed_ip_from_address(&address)?;
    data.add_managed_peer_with_options(
        &name,
        &public_key,
        &peer_allowed_ip,
        &preshared_key,
        Some("25"),
    );
    data.write_to(&iface.conf_file)?;

    let server_public_key = resolve_server_public_key(&iface.interface, &data)?;
    let client_text = render_client_config(
        &private_key,
        &address,
        &dns,
        &server_public_key,
        &endpoint,
        "0.0.0.0/0",
        &preshared_key,
        "25",
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
        enabled: true,
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
    apply_runtime_config_if_ready(&iface.interface, &iface.conf_file)?;

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
    let server_public_key = resolve_server_public_key(&iface.interface, &data)?;

    ui::print_section("client import");
    ui::print_kv_rows(&[
        kv("server", iface.interface.clone()),
        kv("legacy_dir", legacy_dir.display().to_string()),
        kv("scan_root", app.conf_dir.display().to_string()),
        kv(
            "scan_strategy",
            "recursive content match under /etc/wireguard".to_string(),
        ),
        kv(
            "match_rule",
            "client fields complete + peer PublicKey matches server public key".to_string(),
        ),
        kv(
            "state_dir",
            app.instance_state_dir(&iface.interface)
                .display()
                .to_string(),
        ),
    ]);

    let candidates = discover_legacy_import_candidates(
        &app.conf_dir,
        &legacy_dir,
        &iface.conf_file,
        &server_public_key,
    )?;

    if candidates.is_empty() {
        ui::print_message(
            "No content-matched legacy client configs were found. Nothing to import.",
            Tone::Warn,
        );
        write_import_report(app, &iface.interface, &[], &[])?;
        return Ok(());
    }

    ui::print_section("matched legacy configs");
    let mut matched_table = Table::new(vec![
        "name".to_string(),
        "source".to_string(),
        "path".to_string(),
    ]);
    for candidate in &candidates {
        matched_table.push_row(vec![
            candidate.name.clone(),
            candidate.source.clone(),
            candidate.path.display().to_string(),
        ]);
    }
    ui::print_table(&matched_table);

    let mut imported = Vec::new();
    let mut ignored = Vec::new();
    let mut changed = false;
    let mut seen_public_keys = BTreeSet::new();

    for candidate in candidates {
        let legacy = match LegacyClientConfig::parse(&candidate.path) {
            Ok(item) => item,
            Err(error) => {
                ignored.push(IgnoredImport {
                    item: candidate.path.display().to_string(),
                    reason: error.to_string(),
                });
                continue;
            }
        };

        if let Err(error) = legacy.ensure_complete() {
            ignored.push(IgnoredImport {
                item: candidate.path.display().to_string(),
                reason: error.to_string(),
            });
            continue;
        }

        let private_key = legacy.private_key().unwrap_or_default().to_string();
        let public_key = run_capture_with_input("wg", &["pubkey"], &format!("{private_key}\n"))
            .with_context(|| {
                format!(
                    "failed to derive public key for {}",
                    candidate.path.display()
                )
            })?;

        if !seen_public_keys.insert(public_key.clone()) {
            ignored.push(IgnoredImport {
                item: candidate.path.display().to_string(),
                reason: "duplicate client public key already imported in this run".to_string(),
            });
            continue;
        }

        let Some(peer) = data.peer_by_public_key(&public_key).cloned() else {
            ignored.push(IgnoredImport {
                item: candidate.path.display().to_string(),
                reason: "server peer not found for imported public key".to_string(),
            });
            continue;
        };

        let name = peer
            .managed_name
            .clone()
            .unwrap_or_else(|| candidate.name.clone());
        let peer_allowed_ips = peer.allowed_ips();
        let peer_preshared_key = peer.values.get("PresharedKey").cloned().unwrap_or_default();
        let preshared_key = legacy
            .preshared_key()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
            .unwrap_or_else(|| peer_preshared_key.clone());
        let persistent_keepalive = legacy.persistent_keepalive().unwrap_or("25").to_string();
        let address = legacy.address().unwrap_or_default().to_string();
        let dns = legacy.dns().unwrap_or(&app.default_client_dns).to_string();
        let endpoint = legacy
            .endpoint()
            .unwrap_or(&app.default_client_endpoint)
            .to_string();
        let allowed_ips = legacy.allowed_ips().unwrap_or("0.0.0.0/0").to_string();
        let legacy_server_public_key = legacy.server_public_key().unwrap_or_default().to_string();

        if legacy_server_public_key != server_public_key {
            ignored.push(IgnoredImport {
                item: candidate.path.display().to_string(),
                reason: "legacy peer PublicKey does not match this server".to_string(),
            });
            continue;
        }

        if peer.managed_name.is_none() {
            data.adopt_peer(&public_key, &name)?;
            changed = true;
        }

        let export_path = app.state_export_path(&iface.interface, &name);
        if let Some(parent) = export_path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }

        let client_text = render_client_config(
            &private_key,
            &address,
            &dns,
            &legacy_server_public_key,
            &endpoint,
            &allowed_ips,
            &preshared_key,
            &persistent_keepalive,
        );
        validate_client_export_text(&export_path, &client_text)?;
        fs::write(&export_path, client_text)
            .with_context(|| format!("failed to write {}", export_path.display()))?;

        let source_label = candidate.source.clone();
        let client = ClientState {
            interface: iface.interface.clone(),
            name: name.clone(),
            enabled: true,
            source: format!("imported:{source_label}"),
            public_key: public_key.clone(),
            address: address.clone(),
            dns: dns.clone(),
            endpoint: endpoint.clone(),
            allowed_ips,
            server_public_key: legacy_server_public_key,
            preshared_key,
            persistent_keepalive,
            export_path: export_path.display().to_string(),
        };
        save_client_state(app, &client)?;
        imported.push(name);

        ui::print_message(
            &format!(
                "matched import: {} <= {} ({})",
                client.name,
                candidate.path.display(),
                candidate.source
            ),
            Tone::Good,
        );

        if peer_allowed_ips != peer_allowed_ip_from_address(&address)? {
            ui::print_message(
                &format!(
                    "import warning: server peer AllowedIPs={} but client Address={}",
                    peer_allowed_ips, address
                ),
                Tone::Warn,
            );
        }
    }

    if changed {
        data.write_to(&iface.conf_file)?;
    }
    save_server_state(app, &iface.interface, &data)?;
    write_import_report(app, &iface.interface, &imported, &ignored)?;
    if changed {
        apply_runtime_config_if_ready(&iface.interface, &iface.conf_file)?;
    }

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

pub fn rename(
    app: &AppConfig,
    interface: Option<String>,
    old_name: Option<String>,
    new_name: Option<String>,
) -> Result<()> {
    let iface = resolve_server(app, interface)?;
    ensure_config_exists(&iface)?;
    let items = discover_client_states(app, &iface.interface)?;
    let old_name = resolve_client_name(&iface.interface, &items, old_name)?;
    let mut state = load_client_state(app, &iface.interface, &old_name)?;
    let new_name = match new_name {
        Some(value) => value,
        None => ask_text("New client name", Some(&state.name))?,
    };
    if new_name == state.name {
        ui::print_message("Client name is unchanged.", Tone::Warn);
        return Ok(());
    }
    if load_client_state(app, &iface.interface, &new_name).is_ok() {
        bail!("managed_complete client already exists: {new_name}")
    }

    let mut data = InterfaceData::parse(&iface.conf_file)?;
    if state.enabled && data.managed_peer(&state.name).is_some() {
        data.rename_managed_peer(&state.name, &new_name)?;
        data.write_to(&iface.conf_file)?;
        save_server_state(app, &iface.interface, &data)?;
    }

    rename_client_state(app, &iface.interface, &state.name, &new_name)?;
    state.name = new_name.clone();
    state.export_path = app
        .state_export_path(&iface.interface, &new_name)
        .display()
        .to_string();
    save_client_state(app, &state)?;

    ui::print_section("client rename");
    ui::print_kv_rows(&[
        kv("server", iface.interface),
        kv("old_name", old_name),
        kv("new_name", new_name),
        kv("result", ui::status_badge("renamed")),
    ]);
    Ok(())
}

pub fn disable(app: &AppConfig, interface: Option<String>, name: Option<String>) -> Result<()> {
    let iface = resolve_server(app, interface)?;
    ensure_config_exists(&iface)?;
    let mut state = resolve_complete_client_state(app, &iface.interface, name)?;
    if !state.enabled {
        ui::print_message("Client is already disabled.", Tone::Warn);
        return Ok(());
    }

    let mut data = InterfaceData::parse(&iface.conf_file)?;
    let removed = data.remove_managed_peer(&state.name);
    state.enabled = false;
    save_client_state(app, &state)?;
    data.write_to(&iface.conf_file)?;
    save_server_state(app, &iface.interface, &data)?;
    apply_runtime_config_if_ready(&iface.interface, &iface.conf_file)?;

    ui::print_section("client disable");
    ui::print_kv_rows(&[
        kv("server", iface.interface),
        kv("name", state.name),
        kv("peer_removed", ui::yes_no(removed)),
        kv("result", ui::status_badge("disabled")),
    ]);
    Ok(())
}

pub fn enable(app: &AppConfig, interface: Option<String>, name: Option<String>) -> Result<()> {
    let iface = resolve_server(app, interface)?;
    ensure_config_exists(&iface)?;
    let mut state = resolve_complete_client_state(app, &iface.interface, name)?;
    if state.enabled {
        ui::print_message("Client is already enabled.", Tone::Warn);
        return Ok(());
    }

    let mut data = InterfaceData::parse(&iface.conf_file)?;
    if data.managed_peer(&state.name).is_some() {
        bail!(
            "managed peer already exists in server config: {}",
            state.name
        )
    }
    if data.peer_by_public_key(&state.public_key).is_some() {
        bail!("a peer with this public key already exists in server config")
    }
    let peer_allowed_ip = peer_allowed_ip_from_state(&state)?;
    let keepalive = if state.persistent_keepalive.trim().is_empty() {
        None
    } else {
        Some(state.persistent_keepalive.as_str())
    };
    data.add_managed_peer_with_options(
        &state.name,
        &state.public_key,
        &peer_allowed_ip,
        &state.preshared_key,
        keepalive,
    );
    data.write_to(&iface.conf_file)?;
    save_server_state(app, &iface.interface, &data)?;
    state.enabled = true;
    save_client_state(app, &state)?;
    apply_runtime_config_if_ready(&iface.interface, &iface.conf_file)?;

    ui::print_section("client enable");
    ui::print_kv_rows(&[
        kv("server", iface.interface),
        kv("name", state.name),
        kv("allowed_ip", peer_allowed_ip),
        kv("result", ui::status_badge("enabled")),
    ]);
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
    validate_client_export_matches_state(&source, &state, &text)?;
    let qr_payload = compact_client_config_for_qr(&text)
        .with_context(|| format!("failed to compact QR payload from {}", source.display()))?;
    validate_client_export_matches_state(&source, &state, &qr_payload)?;
    let code = QrCode::with_error_correction_level(qr_payload.as_bytes(), EcLevel::L)
        .context("failed to build QR code")?;

    ui::print_section("client qrcode");
    ui::print_kv_rows(&[
        kv("server", iface.interface),
        kv("name", state.name.clone()),
        kv("enabled", ui::yes_no(state.enabled)),
        kv("source", source.display().to_string()),
        kv("source_bytes", text.len().to_string()),
        kv("qr_payload_bytes", qr_payload.len().to_string()),
        kv("qr_modules", code.width().to_string()),
        kv("error_correction", "L".to_string()),
        kv("quiet_zone", "enabled".to_string()),
    ]);

    let rendered = code.render::<unicode::Dense1x2>().quiet_zone(true).build();
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
    apply_runtime_config_if_ready(&iface.interface, &iface.conf_file)?;

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

fn discover_legacy_import_candidates(
    conf_dir: &Path,
    legacy_dir: &Path,
    server_conf_file: &Path,
    server_public_key: &str,
) -> Result<Vec<ImportCandidate>> {
    let mut paths = Vec::new();
    collect_conf_files(conf_dir, &mut paths)?;
    paths.sort();
    paths.dedup();

    let mut names: BTreeMap<String, usize> = BTreeMap::new();
    let mut candidates = Vec::new();

    for path in paths {
        if same_path(&path, server_conf_file) {
            continue;
        }

        let Ok(legacy) = LegacyClientConfig::parse(&path) else {
            continue;
        };
        if legacy.ensure_complete().is_err() {
            continue;
        }
        if legacy.server_public_key() != Some(server_public_key) {
            continue;
        }

        let base_name = client_name_from_path(&path);
        let name = unique_candidate_name(&base_name, &mut names);
        let source = if path.starts_with(legacy_dir) {
            "legacy-dir+content-match"
        } else {
            "wireguard-content-match"
        }
        .to_string();

        candidates.push(ImportCandidate { path, name, source });
    }

    Ok(candidates)
}

fn collect_conf_files(root: &Path, items: &mut Vec<PathBuf>) -> Result<()> {
    if !root.exists() {
        return Ok(());
    }
    if root.is_file() {
        if root.extension().and_then(|item| item.to_str()) == Some("conf") {
            items.push(root.to_path_buf());
        }
        return Ok(());
    }

    let mut entries = fs::read_dir(root)
        .with_context(|| format!("failed to read {}", root.display()))?
        .flatten()
        .map(|entry| entry.path())
        .collect::<Vec<_>>();
    entries.sort();

    for path in entries {
        if path.is_dir() {
            collect_conf_files(&path, items)?;
        } else if path.extension().and_then(|item| item.to_str()) == Some("conf") {
            items.push(path);
        }
    }
    Ok(())
}

fn same_path(left: &Path, right: &Path) -> bool {
    match (left.canonicalize(), right.canonicalize()) {
        (Ok(left), Ok(right)) => left == right,
        _ => left == right,
    }
}

fn client_name_from_path(path: &Path) -> String {
    path.file_stem()
        .and_then(|item| item.to_str())
        .map(|item| item.trim())
        .filter(|item| !item.is_empty())
        .unwrap_or("client")
        .to_string()
}

fn unique_candidate_name(base: &str, names: &mut BTreeMap<String, usize>) -> String {
    let counter = names.entry(base.to_string()).or_insert(0);
    *counter += 1;
    if *counter == 1 {
        base.to_string()
    } else {
        format!("{base}-{counter}")
    }
}

fn compact_client_config_for_qr(text: &str) -> Result<String> {
    let legacy = LegacyClientConfig::parse_str(text)?;
    legacy.ensure_complete()?;

    let private_key = legacy.private_key().unwrap_or_default();
    let address = legacy.address().unwrap_or_default();
    let dns = legacy.dns().unwrap_or("");
    let server_public_key = legacy.server_public_key().unwrap_or_default();
    let endpoint = legacy.endpoint().unwrap_or_default();
    let allowed_ips = legacy.allowed_ips().unwrap_or("0.0.0.0/0");
    let preshared_key = legacy.preshared_key().unwrap_or("");
    let persistent_keepalive = legacy.persistent_keepalive().unwrap_or("25");

    Ok(compact_wireguard_text(&render_client_config(
        private_key,
        address,
        dns,
        server_public_key,
        endpoint,
        allowed_ips,
        preshared_key,
        persistent_keepalive,
    )))
}

fn compact_wireguard_text(text: &str) -> String {
    let mut out = Vec::new();
    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            out.push(line.to_string());
            continue;
        }
        if let Some((left, right)) = line.split_once('=') {
            let key = left.trim();
            let value = right.trim();
            if !key.is_empty() && !value.is_empty() {
                out.push(format!("{key}={value}"));
            }
        }
    }
    out.join("\n") + "\n"
}

fn validate_client_export_text(path: &Path, text: &str) -> Result<()> {
    let legacy = LegacyClientConfig::parse_str(text)
        .with_context(|| format!("failed to parse client export {}", path.display()))?;
    legacy
        .ensure_complete()
        .with_context(|| format!("client export is incomplete: {}", path.display()))?;
    Ok(())
}

fn validate_client_export_matches_state(
    path: &Path,
    state: &ClientState,
    text: &str,
) -> Result<()> {
    let legacy = LegacyClientConfig::parse_str(text)
        .with_context(|| format!("failed to parse client export {}", path.display()))?;
    legacy
        .ensure_complete()
        .with_context(|| format!("client export is incomplete: {}", path.display()))?;

    if legacy.address() != Some(state.address.as_str()) {
        bail!(
            "client export Address does not match canonical state for {}: {}",
            state.name,
            path.display()
        )
    }
    if legacy.server_public_key() != Some(state.server_public_key.as_str()) {
        bail!(
            "client export server PublicKey does not match canonical state for {}: {}",
            state.name,
            path.display()
        )
    }
    Ok(())
}

fn collect_client_views(app: &AppConfig, interface: &str) -> Result<Vec<ClientView>> {
    let runtime = read_runtime(interface);
    let states = discover_client_states(app, interface)?;
    Ok(build_client_views(&states, runtime.as_ref()))
}

fn print_client_snapshot(
    app: &AppConfig,
    interface: &str,
    items: &[ClientView],
    title: &str,
    include_runtime_counts: bool,
) {
    ui::print_section(title);
    let mut header = vec![
        kv("server", interface.to_string()),
        kv(
            "state_dir",
            app.instance_state_dir(interface).display().to_string(),
        ),
        kv("managed_complete", items.len().to_string()),
    ];
    if include_runtime_counts {
        let online = items.iter().filter(|item| item.state == "online").count();
        let probing = items.iter().filter(|item| item.state == "probing").count();
        let stale = items.iter().filter(|item| item.state == "stale").count();
        let disabled = items.iter().filter(|item| item.state == "disabled").count();
        header.push(kv("online", online.to_string()));
        header.push(kv("probing", probing.to_string()));
        header.push(kv("stale", stale.to_string()));
        header.push(kv("disabled", disabled.to_string()));
    }
    ui::print_kv_rows(&header);

    if items.is_empty() {
        ui::print_message(
            "No managed_complete clients were found in canonical state.",
            Tone::Warn,
        );
        ui::print_message(
            &format!("Try: wg-friend client import {}", interface),
            Tone::Muted,
        );
        return;
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
            item.name.clone(),
            item.remote_ip.clone(),
            item.virtual_ip.clone(),
            item.rx.clone(),
            item.tx.clone(),
            item.last_seen.clone(),
            ui::status_badge(&item.state),
            item.source.clone(),
        ]);
    }
    ui::print_table(&table);
}

fn build_client_views(
    states: &[ClientState],
    runtime: Option<&WgRuntimeSummary>,
) -> Vec<ClientView> {
    let mut items = Vec::new();

    for state in states {
        let snapshot = if state.enabled {
            runtime
                .and_then(|summary| summary.peer_by_public_key(&state.public_key))
                .map(runtime_snapshot)
                .unwrap_or_else(default_runtime_snapshot)
        } else {
            disabled_runtime_snapshot()
        };

        items.push(ClientView {
            name: state.name.clone(),
            virtual_ip: state.address.clone(),
            remote_ip: snapshot.remote_ip,
            rx: snapshot.rx,
            tx: snapshot.tx,
            last_seen: snapshot.last_seen,
            state: snapshot.state,
            source: state.source.clone(),
            exportable: true,
        });
    }

    items.sort_by(|left, right| left.name.cmp(&right.name));
    items
}

fn runtime_snapshot(peer: &WgRuntimePeer) -> RuntimeClientSnapshot {
    let connectivity_state = peer.connectivity_state();
    RuntimeClientSnapshot {
        remote_ip: peer
            .endpoint
            .clone()
            .unwrap_or_else(|| "(none)".to_string()),
        rx: peer.rx_bytes_text(),
        tx: peer.tx_bytes_text(),
        last_seen: peer.last_seen_text(),
        state: connectivity_state.as_str().to_string(),
    }
}

fn default_runtime_snapshot() -> RuntimeClientSnapshot {
    RuntimeClientSnapshot {
        remote_ip: "(none)".to_string(),
        rx: "0B".to_string(),
        tx: "0B".to_string(),
        last_seen: "(not yet)".to_string(),
        state: PeerConnectivityState::Offline.as_str().to_string(),
    }
}

fn disabled_runtime_snapshot() -> RuntimeClientSnapshot {
    RuntimeClientSnapshot {
        remote_ip: "(none)".to_string(),
        rx: "0B".to_string(),
        tx: "0B".to_string(),
        last_seen: "(disabled)".to_string(),
        state: PeerConnectivityState::Disabled.as_str().to_string(),
    }
}

fn read_runtime(interface: &str) -> Option<WgRuntimeSummary> {
    let raw = safe_capture("wg", &["show", interface, "dump"]);
    if raw.starts_with("<failed:") {
        None
    } else {
        Some(WgRuntimeSummary::parse_dump(interface, &raw))
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

fn resolve_client_name(
    interface: &str,
    items: &[ClientState],
    name: Option<String>,
) -> Result<String> {
    if let Some(name) = name {
        return Ok(name);
    }
    if items.is_empty() {
        bail!("no managed_complete clients found for {interface}")
    }
    if items.len() == 1 {
        return Ok(items[0].name.clone());
    }
    let options = items
        .iter()
        .map(|item| item.name.clone())
        .collect::<Vec<_>>();
    select_one("Select client", &options)
}

fn resolve_server_public_key(interface: &str, data: &InterfaceData) -> Result<String> {
    let private_key = data
        .server_private_key()
        .ok_or_else(|| anyhow::anyhow!("server config for {interface} is missing PrivateKey"))?
        .to_string();

    run_capture_with_input("wg", &["pubkey"], &format!("{private_key}\n"))
        .with_context(|| format!("failed to derive public key for server {interface}"))
}

fn peer_allowed_ip_from_address(address: &str) -> Result<String> {
    let ip = base_ip_from_cidr(address)
        .ok_or_else(|| anyhow::anyhow!("failed to parse client address as IPv4 CIDR: {address}"))?;
    Ok(format!("{ip}/32"))
}

fn peer_allowed_ip_from_state(state: &ClientState) -> Result<String> {
    peer_allowed_ip_from_address(&state.address)
}

fn apply_runtime_config_if_ready(interface: &str, conf_file: &std::path::Path) -> Result<()> {
    if !interface_exists(interface) || !wg_show_ready(interface) {
        return Ok(());
    }
    let cleaned = clean_wireguard_config(conf_file)?;
    let cleaned_path = cleaned.display().to_string();
    let result = run("wg", &["setconf", interface, &cleaned_path]);
    let _ = fs::remove_file(&cleaned);
    result
}

pub fn canonical_name_map(
    app: &AppConfig,
    interface: &str,
) -> Result<std::collections::BTreeMap<String, String>> {
    public_key_name_map(app, interface)
}
