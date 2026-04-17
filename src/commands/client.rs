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
use crate::ui::kv;
use crate::ui::Table;
use crate::ui::Tone;
use crate::ui::{self};
use crate::util::ensure_config_exists;
use crate::util::ensure_paths;
use crate::util::safe_capture;
use crate::wireguard::render_client_config;
use crate::wireguard::InterfaceData;
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
    model: String,
    is_managed: bool,
}

pub fn list(app: &AppConfig, interface: Option<String>) -> Result<()> {
    let iface = resolve_server(app, interface)?;
    ensure_config_exists(&iface)?;
    let data = InterfaceData::parse(&iface.conf_file)?;
    let runtime = read_runtime(&iface.interface);
    let items = build_client_views(&data, runtime.as_ref());

    ui::print_section("clients");
    ui::print_kv_rows(&[
        kv("server", iface.interface.clone()),
        kv("config", iface.conf_file.display().to_string()),
        kv("managed_clients", data.managed_clients().len().to_string()),
        kv("total_peers", items.len().to_string()),
    ]);

    if items.is_empty() {
        ui::print_message(
            "No peers were found in the local WireGuard config.",
            Tone::Warn,
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
        "model".to_string(),
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
            item.model,
        ]);
    }
    ui::print_table(&table);
    Ok(())
}

pub fn show(app: &AppConfig, interface: Option<String>, name: Option<String>) -> Result<()> {
    let iface = resolve_server(app, interface)?;
    ensure_config_exists(&iface)?;
    let data = InterfaceData::parse(&iface.conf_file)?;
    let runtime = read_runtime(&iface.interface);
    let items = build_client_views(&data, runtime.as_ref());
    let client = resolve_client_view(&iface.interface, &items, name)?;

    ui::print_section("client");
    ui::print_kv_rows(&[
        kv("server", iface.interface.clone()),
        kv("name", client.name.clone()),
        kv("public_key", client.public_key.clone()),
        kv("virtual_ip", client.virtual_ip.clone()),
        kv("remote_ip", client.remote_ip.clone()),
        kv("rx", client.rx.clone()),
        kv("tx", client.tx.clone()),
        kv("last_seen", client.last_seen.clone()),
        kv("state", ui::status_badge(&client.state)),
        kv("model", client.model.clone()),
        kv(
            "client_file",
            if client.is_managed {
                app.client_file_path(&iface.interface, &client.name)
                    .display()
                    .to_string()
            } else {
                "-".to_string()
            },
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
    ui::print_kv_rows(&[
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
    ui::print_kv_rows(&[
        kv("server", iface.interface),
        kv("name", name),
        kv("server_config", iface.conf_file.display().to_string()),
        kv("client_config", client_file.display().to_string()),
    ]);
    Ok(())
}

pub fn adopt(
    app: &AppConfig,
    interface: Option<String>,
    public_key: Option<String>,
    name: Option<String>,
) -> Result<()> {
    let iface = resolve_server(app, interface)?;
    ensure_config_exists(&iface)?;

    let mut data = InterfaceData::parse(&iface.conf_file)?;
    let unmanaged = data.unmanaged_peers();
    if unmanaged.is_empty() {
        bail!(
            "no unmanaged peers are available to adopt for {}",
            iface.interface
        )
    }

    let selected_public_key = match public_key {
        Some(value) => value,
        None => select_unmanaged_public_key(&unmanaged)?,
    };

    let default_name = data
        .peer_by_public_key(&selected_public_key)
        .map(default_adopted_name)
        .unwrap_or_else(|| format!("client-{}", short_key(&selected_public_key)));
    let name = match name {
        Some(value) => value,
        None => ask_text("Adopted client name", Some(&default_name))?,
    };

    ui::print_section("client adopt");
    ui::print_kv_rows(&[
        kv("server", iface.interface.clone()),
        kv("public_key", selected_public_key.clone()),
        kv("name", name.clone()),
    ]);

    if !ask_yes_no("Adopt peer", true)? {
        ui::print_message("No changes written.", Tone::Warn);
        return Ok(());
    }

    data.adopt_peer(&selected_public_key, &name)?;
    data.write_to(&iface.conf_file)?;

    ui::print_message(
        &format!(
            "Adopted peer {selected_public_key} into managed client {name} on {}.",
            iface.interface
        ),
        Tone::Good,
    );
    Ok(())
}

pub fn qrcode(app: &AppConfig, interface: Option<String>, name: Option<String>) -> Result<()> {
    let iface = resolve_server(app, interface)?;
    ensure_config_exists(&iface)?;
    let data = InterfaceData::parse(&iface.conf_file)?;
    let managed_name = resolve_managed_client_name(&iface.interface, &data, name)?;

    let client_file = app.client_file_path(&iface.interface, &managed_name);
    if !client_file.exists() {
        bail!(
            "client export file not found: {}\nAdopted legacy peers do not have an exported client config until you create one.",
            client_file.display()
        )
    }

    let content = fs::read_to_string(&client_file)
        .with_context(|| format!("failed to read {}", client_file.display()))?;
    let qr = QrCode::new(content.as_bytes()).context("failed to render QR code")?;
    let image = qr.render::<unicode::Dense1x2>().quiet_zone(false).build();

    ui::print_section("client qrcode");
    ui::print_kv_rows(&[
        kv("server", iface.interface),
        kv("name", managed_name),
        kv("source", client_file.display().to_string()),
    ]);
    println!("{image}");
    Ok(())
}

pub fn remove(app: &AppConfig, interface: Option<String>, name: Option<String>) -> Result<()> {
    let iface = resolve_server(app, interface)?;
    ensure_config_exists(&iface)?;

    let mut data = InterfaceData::parse(&iface.conf_file)?;
    let name = resolve_managed_client_name(&iface.interface, &data, name)?;

    ui::print_section("client remove");
    ui::print_kv_rows(&[
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
    let name = resolve_managed_client_name(&iface.interface, &data, name)?;

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
    ui::print_kv_rows(&[
        kv("server", iface.interface),
        kv("name", name),
        kv("source", source.display().to_string()),
        kv("output", output.display().to_string()),
    ]);
    Ok(())
}

fn build_client_views(data: &InterfaceData, runtime: Option<&WgRuntimeSummary>) -> Vec<ClientView> {
    let mut items = Vec::new();

    for peer in &data.peers {
        let public_key = peer.public_key().unwrap_or("-").to_string();
        let runtime_peer = runtime.and_then(|summary| summary.peer_by_public_key(&public_key));
        let (rx, tx, remote_ip, last_seen, state) = match runtime_peer {
            Some(item) => (
                item.rx_bytes_text(),
                item.tx_bytes_text(),
                item.endpoint
                    .clone()
                    .unwrap_or_else(|| "(none)".to_string()),
                item.last_seen_text(),
                if item.endpoint.is_some() {
                    "online".to_string()
                } else {
                    "offline".to_string()
                },
            ),
            None => (
                "0B".to_string(),
                "0B".to_string(),
                "(none)".to_string(),
                "(not yet)".to_string(),
                "offline".to_string(),
            ),
        };

        let is_managed = peer.managed_name.is_some();
        let name = peer
            .managed_name
            .clone()
            .unwrap_or_else(|| format!("legacy:{}", short_key(&public_key)));

        items.push(ClientView {
            name,
            public_key,
            virtual_ip: peer.allowed_ips(),
            remote_ip,
            rx,
            tx,
            last_seen,
            state,
            model: if is_managed {
                "managed".to_string()
            } else {
                "legacy".to_string()
            },
            is_managed,
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
            bail!("client not found for {}: {name}", interface)
        };
        return Ok(item.clone());
    }

    if items.is_empty() {
        bail!("no peers found for {interface}")
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

fn resolve_managed_client_name(
    interface: &str,
    data: &InterfaceData,
    name: Option<String>,
) -> Result<String> {
    if let Some(name) = name {
        if data.managed_peer(&name).is_none() {
            bail!("managed client not found for {interface}: {name}")
        }
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
    let private_key = data
        .server_private_key()
        .ok_or_else(|| anyhow::anyhow!("server config for {interface} is missing PrivateKey"))?
        .to_string();

    run_capture_with_input("wg", &["pubkey"], &format!("{private_key}\n"))
        .with_context(|| format!("failed to derive public key for server {interface}"))
}

fn short_key(value: &str) -> String {
    ui::truncate_middle(value, 12)
}

fn default_adopted_name(peer: &crate::wireguard::PeerEntry) -> String {
    if let Some(ip) = peer.allowed_ip() {
        let octet = ip.octets()[3];
        return format!("client-{octet}");
    }

    peer.public_key()
        .map(|key| format!("client-{}", short_key(key).replace('…', "")))
        .unwrap_or_else(|| "client-adopted".to_string())
}

fn select_unmanaged_public_key(peers: &[&crate::wireguard::PeerEntry]) -> Result<String> {
    ui::print_section("adoptable peers");
    let mut table = Table::new(vec!["public_key".to_string(), "allowed_ips".to_string()]);
    for peer in peers {
        table.push_row(vec![
            peer.public_key()
                .map(short_key)
                .unwrap_or_else(|| "-".to_string()),
            peer.allowed_ips(),
        ]);
    }
    ui::print_table(&table);

    let mut options = Vec::new();
    let mut mapping = Vec::new();
    for peer in peers {
        let public_key = peer.public_key().unwrap_or("-").to_string();
        let label = format!("{} {}", short_key(&public_key), peer.allowed_ips());
        options.push(label);
        mapping.push(public_key);
    }

    let selected = select_one("Select peer to adopt", &options)?;
    let Some(index) = options.iter().position(|item| item == &selected) else {
        bail!("selected peer was not found")
    };
    Ok(mapping[index].clone())
}
