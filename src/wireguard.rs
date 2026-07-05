use std::collections::BTreeMap;
use std::fs;
use std::net::Ipv4Addr;
use std::path::Path;

use anyhow::Context;
use anyhow::Result;
use anyhow::bail;

use crate::util::base_ip_from_cidr;
use crate::util::ipv4_string;
use crate::util::next_ipv4_in_same_subnet;
use crate::util::split_cidr;

const MANAGED_NAME_PREFIX: &str = "# wg-friend-client:";

#[derive(Clone, Debug)]
pub struct InterfaceData {
    pub interface: BTreeMap<String, String>,
    pub peers: Vec<PeerEntry>,
}

#[derive(Clone, Debug)]
pub struct PeerEntry {
    pub managed_name: Option<String>,
    pub values: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Default)]
pub struct WgRuntimeSummary {
    pub interface: String,
    pub listen_port: Option<String>,
    pub peers: Vec<WgRuntimePeer>,
}

#[derive(Clone, Debug, Default)]
pub struct WgRuntimePeer {
    pub public_key: String,
    pub preshared_key: Option<String>,
    pub endpoint: Option<String>,
    pub allowed_ips: Option<String>,
    /// For BoringTun user-space deployments, `wg show <iface> dump` exposes the
    /// latest handshake column as a small integer that behaves like an age in
    /// seconds rather than a Unix epoch timestamp. We keep the historical field
    /// name to limit churn, but interpret it as an age value downstream.
    pub latest_handshake_epoch: Option<u64>,
    pub transfer_rx_bytes: Option<u64>,
    pub transfer_tx_bytes: Option<u64>,
    pub persistent_keepalive: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeerConnectivityState {
    Offline,
    Probing,
    Stale,
    Online,
    Disabled,
}

impl PeerConnectivityState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Offline => "offline",
            Self::Probing => "probing",
            Self::Stale => "stale",
            Self::Online => "online",
            Self::Disabled => "disabled",
        }
    }
}

impl InterfaceData {
    pub fn parse(path: &Path) -> Result<Self> {
        let content = fs::read_to_string(path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        Self::parse_str(&content)
    }

    pub fn parse_str(content: &str) -> Result<Self> {
        let mut interface = BTreeMap::new();
        let mut peers = Vec::new();
        let mut current_section: Option<String> = None;
        let mut current_peer: Option<PeerEntry> = None;
        let mut pending_managed_name: Option<String> = None;

        for raw_line in content.lines() {
            let line = raw_line.trim();
            if line.is_empty() {
                continue;
            }

            if let Some(name) = parse_managed_name(line) {
                pending_managed_name = Some(name.to_string());
                continue;
            }

            if line.starts_with('#') {
                continue;
            }

            if line.starts_with('[') && line.ends_with(']') {
                if current_section.as_deref() == Some("Peer") {
                    if let Some(peer) = current_peer.take() {
                        peers.push(peer);
                    }
                }

                let section = line.trim_matches(&['[', ']'][..]).to_string();
                current_section = Some(section.clone());
                if section == "Peer" {
                    current_peer = Some(PeerEntry {
                        managed_name: pending_managed_name.take(),
                        values: BTreeMap::new(),
                    });
                }
                continue;
            }

            let Some((left, right)) = line.split_once('=') else {
                continue;
            };
            let key = left.trim().to_string();
            let value = right.trim().to_string();

            match current_section.as_deref() {
                Some("Interface") => {
                    interface.insert(key, value);
                }
                Some("Peer") => {
                    if let Some(peer) = current_peer.as_mut() {
                        peer.values.insert(key, value);
                    }
                }
                _ => {}
            }
        }

        if current_section.as_deref() == Some("Peer") {
            if let Some(peer) = current_peer.take() {
                peers.push(peer);
            }
        }

        if interface.is_empty() {
            bail!("missing [Interface] section")
        }

        Ok(Self { interface, peers })
    }

    pub fn write_to(&self, path: &Path) -> Result<()> {
        let mut out = String::new();
        out.push_str("[Interface]\n");
        for (key, value) in &self.interface {
            out.push_str(&format!("{key} = {value}\n"));
        }

        for peer in &self.peers {
            out.push('\n');
            if let Some(name) = &peer.managed_name {
                out.push_str(&format!("{MANAGED_NAME_PREFIX} {name}\n"));
            }
            out.push_str("[Peer]\n");
            for (key, value) in &peer.values {
                out.push_str(&format!("{key} = {value}\n"));
            }
        }

        fs::write(path, out).with_context(|| format!("failed to write {}", path.display()))?;
        Ok(())
    }

    pub fn interface_value(&self, key: &str) -> Option<&str> {
        self.interface.get(key).map(|value| value.as_str())
    }

    pub fn set_interface_value(&mut self, key: &str, value: String) {
        self.interface.insert(key.to_string(), value);
    }

    pub fn managed_clients(&self) -> Vec<String> {
        let mut items = self
            .peers
            .iter()
            .filter_map(|peer| peer.managed_name.clone())
            .collect::<Vec<_>>();
        items.sort();
        items
    }

    pub fn managed_peer(&self, name: &str) -> Option<&PeerEntry> {
        self.peers
            .iter()
            .find(|peer| peer.managed_name.as_deref() == Some(name))
    }

    pub fn managed_peer_mut(&mut self, name: &str) -> Option<&mut PeerEntry> {
        self.peers
            .iter_mut()
            .find(|peer| peer.managed_name.as_deref() == Some(name))
    }

    pub fn peer_by_public_key(&self, public_key: &str) -> Option<&PeerEntry> {
        self.peers
            .iter()
            .find(|peer| peer.public_key() == Some(public_key))
    }

    pub fn peer_by_public_key_mut(&mut self, public_key: &str) -> Option<&mut PeerEntry> {
        self.peers
            .iter_mut()
            .find(|peer| peer.public_key() == Some(public_key))
    }

    pub fn unmanaged_peers(&self) -> Vec<&PeerEntry> {
        self.peers
            .iter()
            .filter(|peer| peer.managed_name.is_none())
            .collect::<Vec<_>>()
    }

    pub fn add_managed_peer(
        &mut self,
        name: &str,
        public_key: &str,
        address: &str,
        preshared_key: &str,
    ) {
        self.add_managed_peer_with_options(name, public_key, address, preshared_key, Some("25"));
    }

    pub fn adopt_peer(&mut self, public_key: &str, name: &str) -> Result<()> {
        if self.managed_peer(name).is_some() {
            bail!("managed client already exists: {name}")
        }
        let Some(peer) = self.peer_by_public_key_mut(public_key) else {
            bail!("peer not found for public key: {public_key}")
        };
        if peer.managed_name.is_some() {
            bail!("peer is already managed")
        }
        peer.managed_name = Some(name.to_string());
        Ok(())
    }

    pub fn rename_managed_peer(&mut self, old_name: &str, new_name: &str) -> Result<()> {
        if self.managed_peer(new_name).is_some() {
            bail!("managed client already exists: {new_name}")
        }
        let Some(peer) = self.managed_peer_mut(old_name) else {
            bail!("managed client not found: {old_name}")
        };
        peer.managed_name = Some(new_name.to_string());
        Ok(())
    }

    pub fn add_managed_peer_with_options(
        &mut self,
        name: &str,
        public_key: &str,
        address: &str,
        preshared_key: &str,
        persistent_keepalive: Option<&str>,
    ) {
        let mut values = BTreeMap::new();
        values.insert("AllowedIPs".to_string(), address.to_string());
        values.insert(
            "PersistentKeepalive".to_string(),
            persistent_keepalive.unwrap_or("25").to_string(),
        );
        if !preshared_key.trim().is_empty() {
            values.insert("PresharedKey".to_string(), preshared_key.to_string());
        }
        values.insert("PublicKey".to_string(), public_key.to_string());

        self.peers.push(PeerEntry {
            managed_name: Some(name.to_string()),
            values,
        });
    }

    pub fn remove_managed_peer(&mut self, name: &str) -> bool {
        let before = self.peers.len();
        self.peers
            .retain(|peer| peer.managed_name.as_deref() != Some(name));
        self.peers.len() != before
    }

    pub fn suggest_next_client_address(&self) -> Result<String> {
        let server_addr = self
            .interface_value("Address")
            .ok_or_else(|| anyhow::anyhow!("server config is missing Address"))?;
        let (base, prefix) = split_cidr(server_addr)
            .ok_or_else(|| anyhow::anyhow!("failed to parse server Address as IPv4 CIDR"))?;

        let mut used = Vec::new();
        used.push(base);
        for peer in &self.peers {
            let Some(value) = peer.values.get("AllowedIPs") else {
                continue;
            };
            if let Some(ip) = base_ip_from_cidr(value) {
                used.push(ip);
            }
        }

        let Some(next_ip) = next_ipv4_in_same_subnet(base, &used) else {
            bail!("no free IPv4 address found in the server subnet")
        };
        Ok(ipv4_string(next_ip, prefix))
    }

    pub fn server_dns_hint(&self) -> Option<String> {
        self.interface_value("Address")
            .and_then(base_ip_from_cidr)
            .map(|ip| ip.to_string())
    }

    pub fn server_private_key(&self) -> Option<&str> {
        self.interface_value("PrivateKey")
    }

    pub fn server_listen_port(&self) -> Option<&str> {
        self.interface_value("ListenPort")
    }

    pub fn managed_name_by_public_key(&self, public_key: &str) -> Option<String> {
        self.peers.iter().find_map(|peer| {
            let key = peer.values.get("PublicKey")?;
            if key == public_key {
                peer.managed_name.clone()
            } else {
                None
            }
        })
    }
}

impl PeerEntry {
    pub fn allowed_ip(&self) -> Option<Ipv4Addr> {
        self.values
            .get("AllowedIPs")
            .and_then(|value| base_ip_from_cidr(value))
    }

    pub fn public_key(&self) -> Option<&str> {
        self.values.get("PublicKey").map(|value| value.as_str())
    }

    pub fn allowed_ips(&self) -> String {
        self.values
            .get("AllowedIPs")
            .cloned()
            .unwrap_or_else(|| "-".to_string())
    }
}

impl WgRuntimeSummary {
    pub fn parse_dump(interface: &str, text: &str) -> Self {
        let mut summary = WgRuntimeSummary {
            interface: interface.to_string(),
            ..Default::default()
        };

        for (index, raw_line) in text.lines().enumerate() {
            let line = raw_line.trim();
            if line.is_empty() {
                continue;
            }

            let fields: Vec<&str> = line.split('\t').collect();
            if index == 0 {
                if let Some(listen_port) = fields.get(2).copied() {
                    let listen_port = listen_port.trim();
                    if !listen_port.is_empty() && listen_port != "0" {
                        summary.listen_port = Some(listen_port.to_string());
                    }
                }
                continue;
            }

            let Some(public_key) = fields.get(0).copied() else {
                continue;
            };
            if public_key.trim().is_empty() {
                continue;
            }

            summary.peers.push(WgRuntimePeer {
                public_key: public_key.trim().to_string(),
                preshared_key: normalize_dump_value(fields.get(1).copied()),
                endpoint: normalize_dump_value(fields.get(2).copied()),
                allowed_ips: normalize_dump_value(fields.get(3).copied()),
                latest_handshake_epoch: parse_dump_u64(fields.get(4).copied()),
                transfer_rx_bytes: parse_dump_u64(fields.get(5).copied()),
                transfer_tx_bytes: parse_dump_u64(fields.get(6).copied()),
                persistent_keepalive: normalize_dump_keepalive(fields.get(7).copied()),
            });
        }

        summary
    }

    pub fn peer_by_public_key(&self, public_key: &str) -> Option<&WgRuntimePeer> {
        self.peers.iter().find(|peer| peer.public_key == public_key)
    }
}

impl WgRuntimePeer {
    pub fn rx_bytes_text(&self) -> String {
        self.transfer_rx_bytes
            .map(format_byte_count)
            .unwrap_or_else(|| "0B".to_string())
    }

    pub fn tx_bytes_text(&self) -> String {
        self.transfer_tx_bytes
            .map(format_byte_count)
            .unwrap_or_else(|| "0B".to_string())
    }

    pub fn last_seen_text(&self) -> String {
        match self.handshake_observation() {
            HandshakeObservation::Never => "(not yet)".to_string(),
            HandshakeObservation::Seen { display_text, .. } => display_text,
        }
    }

    pub fn connectivity_state(&self) -> PeerConnectivityState {
        match self.handshake_observation() {
            HandshakeObservation::Seen { age_secs, .. } if age_secs <= 180 => {
                PeerConnectivityState::Online
            }
            HandshakeObservation::Seen { .. } => PeerConnectivityState::Stale,
            HandshakeObservation::Never if self.endpoint.is_some() => {
                PeerConnectivityState::Probing
            }
            HandshakeObservation::Never => PeerConnectivityState::Offline,
        }
    }

    fn handshake_observation(&self) -> HandshakeObservation {
        // On the current BoringTun path we intentionally interpret the dump value
        // as "seconds since the latest successful handshake", not as a Unix epoch.
        // A zero value still means "not yet".
        match self.latest_handshake_epoch {
            Some(0) | None => HandshakeObservation::Never,
            Some(age_secs) => HandshakeObservation::Seen {
                age_secs,
                display_text: format_age(age_secs),
            },
        }
    }
}

#[derive(Clone, Debug)]
enum HandshakeObservation {
    Never,
    Seen { age_secs: u64, display_text: String },
}

fn normalize_dump_value(value: Option<&str>) -> Option<String> {
    let value = value?.trim();
    if value.is_empty() || value == "(none)" || value == "off" {
        return None;
    }
    Some(value.to_string())
}

fn normalize_dump_keepalive(value: Option<&str>) -> Option<String> {
    let value = normalize_dump_value(value)?;
    if value == "0" {
        return None;
    }
    Some(value)
}

fn parse_dump_u64(value: Option<&str>) -> Option<u64> {
    let value = value?.trim();
    if value.is_empty() || value == "(none)" {
        return None;
    }
    value.parse::<u64>().ok()
}

fn format_age(age_secs: u64) -> String {
    if age_secs == 0 {
        return "just now".to_string();
    }

    let units = [
        (30 * 24 * 60 * 60, "month", "months"),
        (7 * 24 * 60 * 60, "week", "weeks"),
        (24 * 60 * 60, "day", "days"),
        (60 * 60, "hour", "hours"),
        (60, "minute", "minutes"),
        (1, "second", "seconds"),
    ];

    let mut remaining = age_secs;
    let mut parts: Vec<String> = Vec::new();
    for (unit_secs, singular, plural) in units {
        if remaining < unit_secs {
            continue;
        }
        let count = remaining / unit_secs;
        remaining %= unit_secs;
        let label = if count == 1 { singular } else { plural };
        parts.push(format!("{count} {label}"));
        if parts.len() == 2 {
            break;
        }
    }

    if parts.is_empty() {
        "just now".to_string()
    } else {
        format!("{} ago", parts.join(", "))
    }
}

fn format_byte_count(bytes: u64) -> String {
    const KIB: f64 = 1024.0;
    const MIB: f64 = 1024.0 * 1024.0;
    const GIB: f64 = 1024.0 * 1024.0 * 1024.0;

    if bytes == 0 {
        return "0B".to_string();
    }
    let bytes_f = bytes as f64;
    if bytes_f >= GIB {
        return format!("{:.2} GiB", bytes_f / GIB);
    }
    if bytes_f >= MIB {
        return format!("{:.2} MiB", bytes_f / MIB);
    }
    if bytes_f >= KIB {
        return format!("{:.2} KiB", bytes_f / KIB);
    }
    format!("{} B", bytes)
}

pub fn render_client_config(
    private_key: &str,
    address: &str,
    dns: &str,
    server_public_key: &str,
    endpoint: &str,
    allowed_ips: &str,
    preshared_key: &str,
    persistent_keepalive: &str,
) -> String {
    let mut out = String::new();
    out.push_str("[Interface]\n");
    out.push_str(&format!("PrivateKey = {private_key}\n"));
    out.push_str(&format!("Address = {address}\n"));
    if !dns.trim().is_empty() {
        out.push_str(&format!("DNS = {dns}\n"));
    }

    out.push_str("\n[Peer]\n");
    out.push_str(&format!("PublicKey = {server_public_key}\n"));
    if !preshared_key.trim().is_empty() {
        out.push_str(&format!("PresharedKey = {preshared_key}\n"));
    }
    out.push_str(&format!("AllowedIPs = {allowed_ips}\n"));
    out.push_str(&format!("Endpoint = {endpoint}\n"));
    if !persistent_keepalive.trim().is_empty() && persistent_keepalive.trim() != "0" {
        out.push_str(&format!("PersistentKeepalive = {persistent_keepalive}\n"));
    }
    out
}

fn parse_managed_name(line: &str) -> Option<&str> {
    line.strip_prefix(MANAGED_NAME_PREFIX)
        .map(|value| value.trim())
}
