use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use anyhow::Context;
use anyhow::Result;
use anyhow::bail;

use crate::config::AppConfig;
use crate::wireguard::InterfaceData;

#[derive(Clone, Debug)]
pub struct ClientState {
    pub interface: String,
    pub name: String,
    pub enabled: bool,
    pub source: String,
    pub public_key: String,
    pub address: String,
    pub dns: String,
    pub endpoint: String,
    pub allowed_ips: String,
    pub server_public_key: String,
    pub preshared_key: String,
    pub persistent_keepalive: String,
    pub export_path: String,
}

#[derive(Clone, Debug)]
pub struct ServerState {
    pub interface: String,
    pub conf_path: String,
    pub address: String,
    pub listen_port: String,
    pub mtu: String,
}

#[derive(Clone, Debug, Default)]
pub struct LegacyClientConfig {
    interface: BTreeMap<String, String>,
    peer: BTreeMap<String, String>,
}

#[derive(Clone, Debug)]
pub struct IgnoredImport {
    pub item: String,
    pub reason: String,
}

impl ClientState {
    pub fn write_to(&self, path: &Path) -> Result<()> {
        let content = format!(
            concat!(
                "interface = \"{}\"\n",
                "name = \"{}\"\n",
                "enabled = {}\n",
                "source = \"{}\"\n",
                "public_key = \"{}\"\n",
                "address = \"{}\"\n",
                "dns = \"{}\"\n",
                "endpoint = \"{}\"\n",
                "allowed_ips = \"{}\"\n",
                "server_public_key = \"{}\"\n",
                "preshared_key = \"{}\"\n",
                "persistent_keepalive = \"{}\"\n",
                "export_path = \"{}\"\n"
            ),
            toml_escape(&self.interface),
            toml_escape(&self.name),
            if self.enabled { "true" } else { "false" },
            toml_escape(&self.source),
            toml_escape(&self.public_key),
            toml_escape(&self.address),
            toml_escape(&self.dns),
            toml_escape(&self.endpoint),
            toml_escape(&self.allowed_ips),
            toml_escape(&self.server_public_key),
            toml_escape(&self.preshared_key),
            toml_escape(&self.persistent_keepalive),
            toml_escape(&self.export_path),
        );
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
        fs::write(path, content).with_context(|| format!("failed to write {}", path.display()))?;
        Ok(())
    }

    pub fn parse(path: &Path) -> Result<Self> {
        let text = fs::read_to_string(path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        let values = parse_simple_toml(&text);
        Ok(Self {
            interface: required_value(&values, "interface", path)?,
            name: required_value(&values, "name", path)?,
            enabled: values.get("enabled").map(|v| v == "true").unwrap_or(true),
            source: required_value(&values, "source", path)?,
            public_key: required_value(&values, "public_key", path)?,
            address: required_value(&values, "address", path)?,
            dns: values
                .get("dns")
                .cloned()
                .unwrap_or_else(|| "-".to_string()),
            endpoint: values
                .get("endpoint")
                .cloned()
                .unwrap_or_else(|| "-".to_string()),
            allowed_ips: values
                .get("allowed_ips")
                .cloned()
                .unwrap_or_else(|| "0.0.0.0/0".to_string()),
            server_public_key: required_value(&values, "server_public_key", path)?,
            preshared_key: values.get("preshared_key").cloned().unwrap_or_default(),
            persistent_keepalive: values
                .get("persistent_keepalive")
                .cloned()
                .unwrap_or_else(|| "25".to_string()),
            export_path: required_value(&values, "export_path", path)?,
        })
    }
}

impl ServerState {
    pub fn write_to(&self, path: &Path) -> Result<()> {
        let content = format!(
            concat!(
                "interface = \"{}\"\n",
                "conf_path = \"{}\"\n",
                "address = \"{}\"\n",
                "listen_port = \"{}\"\n",
                "mtu = \"{}\"\n"
            ),
            toml_escape(&self.interface),
            toml_escape(&self.conf_path),
            toml_escape(&self.address),
            toml_escape(&self.listen_port),
            toml_escape(&self.mtu),
        );
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
        fs::write(path, content).with_context(|| format!("failed to write {}", path.display()))?;
        Ok(())
    }
}

impl LegacyClientConfig {
    pub fn parse(path: &Path) -> Result<Self> {
        let text = fs::read_to_string(path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        Self::parse_str(&text)
    }

    pub fn parse_str(text: &str) -> Result<Self> {
        let mut interface = BTreeMap::new();
        let mut peer = BTreeMap::new();
        let mut current = String::new();

        for raw_line in text.lines() {
            let line = raw_line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if line.starts_with('[') && line.ends_with(']') {
                current = line.trim_matches(&['[', ']'][..]).to_string();
                continue;
            }
            let Some((left, right)) = line.split_once('=') else {
                continue;
            };
            let key = left.trim().to_string();
            let value = right.trim().to_string();
            match current.as_str() {
                "Interface" => {
                    interface.insert(key, value);
                }
                "Peer" => {
                    peer.insert(key, value);
                }
                _ => {}
            }
        }

        Ok(Self { interface, peer })
    }

    pub fn ensure_complete(&self) -> Result<()> {
        for key in ["PrivateKey", "Address"] {
            require_non_empty(&self.interface, "Interface", key)?;
        }
        for key in ["PublicKey", "AllowedIPs", "Endpoint"] {
            require_non_empty(&self.peer, "Peer", key)?;
        }
        Ok(())
    }

    pub fn private_key(&self) -> Option<&str> {
        self.interface.get("PrivateKey").map(String::as_str)
    }

    pub fn address(&self) -> Option<&str> {
        self.interface.get("Address").map(String::as_str)
    }

    pub fn dns(&self) -> Option<&str> {
        self.interface.get("DNS").map(String::as_str)
    }

    pub fn server_public_key(&self) -> Option<&str> {
        self.peer.get("PublicKey").map(String::as_str)
    }

    pub fn endpoint(&self) -> Option<&str> {
        self.peer.get("Endpoint").map(String::as_str)
    }

    pub fn allowed_ips(&self) -> Option<&str> {
        self.peer.get("AllowedIPs").map(String::as_str)
    }

    pub fn preshared_key(&self) -> Option<&str> {
        self.peer.get("PresharedKey").map(String::as_str)
    }

    pub fn persistent_keepalive(&self) -> Option<&str> {
        self.peer.get("PersistentKeepalive").map(String::as_str)
    }
}

pub fn discover_client_states(app: &AppConfig, interface: &str) -> Result<Vec<ClientState>> {
    let dir = app.instance_clients_dir(interface);
    if !dir.exists() {
        return Ok(Vec::new());
    }

    let mut items = Vec::new();
    for entry in fs::read_dir(&dir).with_context(|| format!("failed to read {}", dir.display()))? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        if path.extension().and_then(|item| item.to_str()) != Some("toml") {
            continue;
        }
        items.push(ClientState::parse(&path)?);
    }
    items.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(items)
}

pub fn load_client_state(app: &AppConfig, interface: &str, name: &str) -> Result<ClientState> {
    let path = app.state_client_meta_path(interface, name);
    if !path.exists() {
        bail!(
            "managed_complete client not found for {}: {name}",
            interface
        )
    }
    ClientState::parse(&path)
}

pub fn save_client_state(app: &AppConfig, client: &ClientState) -> Result<()> {
    client.write_to(&app.state_client_meta_path(&client.interface, &client.name))
}

pub fn rename_client_state(
    app: &AppConfig,
    interface: &str,
    old_name: &str,
    new_name: &str,
) -> Result<()> {
    let old_meta = app.state_client_meta_path(interface, old_name);
    let old_export = app.state_export_path(interface, old_name);
    let new_meta = app.state_client_meta_path(interface, new_name);
    let new_export = app.state_export_path(interface, new_name);

    if !old_meta.exists() {
        bail!(
            "managed_complete client not found for {}: {}",
            interface,
            old_name
        )
    }
    if new_meta.exists() {
        bail!(
            "managed_complete client already exists for {}: {}",
            interface,
            new_name
        )
    }

    if let Some(parent) = new_meta.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    if let Some(parent) = new_export.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }

    fs::rename(&old_meta, &new_meta).with_context(|| {
        format!(
            "failed to rename {} to {}",
            old_meta.display(),
            new_meta.display()
        )
    })?;
    if old_export.exists() {
        fs::rename(&old_export, &new_export).with_context(|| {
            format!(
                "failed to rename {} to {}",
                old_export.display(),
                new_export.display()
            )
        })?;
    }
    Ok(())
}

pub fn remove_client_state(app: &AppConfig, interface: &str, name: &str) -> Result<()> {
    let meta = app.state_client_meta_path(interface, name);
    let export = app.state_export_path(interface, name);
    if meta.exists() {
        fs::remove_file(&meta).with_context(|| format!("failed to remove {}", meta.display()))?;
    }
    if export.exists() {
        fs::remove_file(&export)
            .with_context(|| format!("failed to remove {}", export.display()))?;
    }
    Ok(())
}

pub fn public_key_name_map(app: &AppConfig, interface: &str) -> Result<BTreeMap<String, String>> {
    let mut items = BTreeMap::new();
    for client in discover_client_states(app, interface)? {
        items.insert(client.public_key.clone(), client.name.clone());
    }
    Ok(items)
}

pub fn save_server_state(app: &AppConfig, interface: &str, data: &InterfaceData) -> Result<()> {
    let state = ServerState {
        interface: interface.to_string(),
        conf_path: app
            .resolve_interface(Some(interface.to_string()))
            .conf_file
            .display()
            .to_string(),
        address: data
            .interface_value("Address")
            .unwrap_or("<unset>")
            .to_string(),
        listen_port: data.server_listen_port().unwrap_or("<unset>").to_string(),
        mtu: data.interface_value("MTU").unwrap_or("<unset>").to_string(),
    };
    state.write_to(&app.state_server_path(interface))
}

pub fn write_import_report(
    app: &AppConfig,
    interface: &str,
    imported: &[String],
    ignored: &[IgnoredImport],
) -> Result<()> {
    let mut text = String::new();
    text.push_str("{\n");
    text.push_str("  \"imported\": [\n");
    for (idx, item) in imported.iter().enumerate() {
        let suffix = if idx + 1 == imported.len() { "" } else { "," };
        text.push_str(&format!("    \"{}\"{}\n", json_escape(item), suffix));
    }
    text.push_str("  ],\n");
    text.push_str("  \"ignored\": [\n");
    for (idx, item) in ignored.iter().enumerate() {
        let suffix = if idx + 1 == ignored.len() { "" } else { "," };
        text.push_str(&format!(
            "    {{ \"item\": \"{}\", \"reason\": \"{}\" }}{}\n",
            json_escape(&item.item),
            json_escape(&item.reason),
            suffix
        ));
    }
    text.push_str("  ]\n");
    text.push_str("}\n");

    let path = app.state_import_report_path(interface);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    fs::write(&path, text).with_context(|| format!("failed to write {}", path.display()))?;
    Ok(())
}

fn require_non_empty(values: &BTreeMap<String, String>, section: &str, key: &str) -> Result<()> {
    match values.get(key).map(|value| value.trim()) {
        Some(value) if !value.is_empty() => Ok(()),
        _ => bail!("missing [{}] {}", section, key),
    }
}

fn parse_simple_toml(text: &str) -> BTreeMap<String, String> {
    let mut values = BTreeMap::new();
    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('[') {
            continue;
        }
        let Some((left, right)) = line.split_once('=') else {
            continue;
        };
        let key = left.trim().to_string();
        let value = right
            .trim()
            .trim_matches('"')
            .replace("\\\"", "\"")
            .replace("\\\\", "\\");
        values.insert(key, value);
    }
    values
}

fn required_value(values: &BTreeMap<String, String>, key: &str, path: &Path) -> Result<String> {
    values
        .get(key)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("missing '{}' in {}", key, path.display()))
}

fn toml_escape(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

fn json_escape(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}
