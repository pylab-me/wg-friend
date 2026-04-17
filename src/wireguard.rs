use std::collections::BTreeMap;
use std::fs;
use std::net::Ipv4Addr;
use std::path::Path;

use anyhow::bail;
use anyhow::Context;
use anyhow::Result;

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
    pub latest_handshake: Option<String>,
    pub transfer: Option<String>,
    pub persistent_keepalive: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeerConnectivityState {
    Offline,
    Probing,
    Stale,
    Online,
}

impl PeerConnectivityState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Offline => "offline",
            Self::Probing => "probing",
            Self::Stale => "stale",
            Self::Online => "online",
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
        let mut values = BTreeMap::new();
        values.insert("AllowedIPs".to_string(), address.to_string());
        values.insert("PersistentKeepalive".to_string(), "25".to_string());
        values.insert("PresharedKey".to_string(), preshared_key.to_string());
        values.insert("PublicKey".to_string(), public_key.to_string());

        self.peers.push(PeerEntry {
            managed_name: Some(name.to_string()),
            values,
        });
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
    pub fn parse(text: &str) -> Self {
        let mut summary = WgRuntimeSummary::default();
        let mut current_peer: Option<WgRuntimePeer> = None;

        for raw_line in text.lines() {
            let line = raw_line.trim();
            if line.is_empty() {
                continue;
            }

            if let Some(value) = line.strip_prefix("interface:") {
                summary.interface = value.trim().to_string();
                continue;
            }

            if let Some(value) = line.strip_prefix("listening port:") {
                summary.listen_port = Some(value.trim().to_string());
                continue;
            }

            if let Some(value) = line.strip_prefix("peer:") {
                if let Some(peer) = current_peer.take() {
                    summary.peers.push(peer);
                }
                current_peer = Some(WgRuntimePeer {
                    public_key: value.trim().to_string(),
                    ..Default::default()
                });
                continue;
            }

            let Some(peer) = current_peer.as_mut() else {
                continue;
            };

            if let Some(value) = line.strip_prefix("preshared key:") {
                peer.preshared_key = Some(value.trim().to_string());
            } else if let Some(value) = line.strip_prefix("endpoint:") {
                peer.endpoint = Some(value.trim().to_string());
            } else if let Some(value) = line.strip_prefix("allowed ips:") {
                peer.allowed_ips = Some(value.trim().to_string());
            } else if let Some(value) = line.strip_prefix("latest handshake:") {
                peer.latest_handshake = Some(value.trim().to_string());
            } else if let Some(value) = line.strip_prefix("transfer:") {
                peer.transfer = Some(value.trim().to_string());
            } else if let Some(value) = line.strip_prefix("persistent keepalive:") {
                peer.persistent_keepalive = Some(value.trim().to_string());
            }
        }

        if let Some(peer) = current_peer.take() {
            summary.peers.push(peer);
        }

        summary
    }

    pub fn peer_by_public_key(&self, public_key: &str) -> Option<&WgRuntimePeer> {
        self.peers.iter().find(|peer| peer.public_key == public_key)
    }
}

impl WgRuntimePeer {
    pub fn rx_bytes_text(&self) -> String {
        self.transfer_parts().0
    }

    pub fn tx_bytes_text(&self) -> String {
        self.transfer_parts().1
    }

    pub fn handshake_age_secs(&self) -> Option<u64> {
        self.handshake_observation().age_secs
    }

    pub fn last_seen_text(&self) -> String {
        self.handshake_observation().display_text
    }

    pub fn connectivity_state(&self) -> PeerConnectivityState {
        let observation = self.handshake_observation();
        match observation.age_secs {
            Some(age) if age <= 180 => PeerConnectivityState::Online,
            Some(_) => PeerConnectivityState::Stale,
            None if self.endpoint.is_some() => PeerConnectivityState::Probing,
            None => PeerConnectivityState::Offline,
        }
    }

    fn handshake_observation(&self) -> HandshakeObservation {
        parse_handshake_observation(self.latest_handshake.as_deref())
    }

    pub fn transfer_parts(&self) -> (String, String) {
        let Some(raw) = self.transfer.as_deref() else {
            return ("0B".to_string(), "0B".to_string());
        };

        let mut parts = raw.split(',');
        let received = parts.next().unwrap_or("0B").trim();
        let sent = parts.next().unwrap_or("0B").trim();
        (
            received
                .strip_suffix(" received")
                .unwrap_or(received)
                .trim()
                .to_string(),
            sent.strip_suffix(" sent")
                .unwrap_or(sent)
                .trim()
                .to_string(),
        )
    }
}

#[derive(Clone, Debug)]
struct HandshakeObservation {
    age_secs: Option<u64>,
    display_text: String,
}

fn parse_handshake_observation(raw: Option<&str>) -> HandshakeObservation {
    let Some(raw) = raw.map(str::trim) else {
        return HandshakeObservation {
            age_secs: None,
            display_text: "(not yet)".to_string(),
        };
    };

    match parse_handshake_age_secs(raw) {
        Some(age_secs) => HandshakeObservation {
            age_secs: Some(age_secs),
            display_text: raw.to_string(),
        },
        None => HandshakeObservation {
            age_secs: None,
            display_text: "(not yet)".to_string(),
        },
    }
}

fn parse_handshake_age_secs(raw: &str) -> Option<u64> {
    let normalized = raw.trim().to_ascii_lowercase();
    if normalized.is_empty()
        || normalized == "never"
        || normalized == "(not yet)"
        || normalized == "0"
        || normalized.contains("not yet")
        || normalized.contains("year")
        || normalized.contains("1970")
        || normalized.contains("epoch")
    {
        return None;
    }
    if normalized == "now" || normalized == "just now" {
        return Some(0);
    }

    let compact = normalized.strip_suffix(" ago").unwrap_or(&normalized);
    let mut total_secs = 0u64;
    let mut parsed_any = false;

    for part in compact.split(',') {
        let trimmed = part.trim();
        if trimmed.is_empty() {
            continue;
        }
        let mut pieces = trimmed.split_whitespace();
        let number_text = pieces.next()?;
        let number = number_text.parse::<u64>().ok()?;
        let unit = pieces.next()?;

        let unit_secs = if unit.starts_with("second") {
            1
        } else if unit.starts_with("minute") {
            60
        } else if unit.starts_with("hour") {
            60 * 60
        } else if unit.starts_with("day") {
            24 * 60 * 60
        } else if unit.starts_with("week") {
            7 * 24 * 60 * 60
        } else if unit.starts_with("month") {
            30 * 24 * 60 * 60
        } else {
            return None;
        };

        parsed_any = true;
        total_secs = total_secs.saturating_add(number.saturating_mul(unit_secs));
    }

    parsed_any.then_some(total_secs)
}

pub fn render_client_config(
    private_key: &str,
    address: &str,
    dns: &str,
    server_public_key: &str,
    endpoint: &str,
    preshared_key: &str,
) -> String {
    format!(
        "[Interface]\nPrivateKey = {private_key}\nAddress = {address}\nDNS = {dns}\n\n[Peer]\nPublicKey = {server_public_key}\nPresharedKey = {preshared_key}\nAllowedIPs = 0.0.0.0/0\nEndpoint = {endpoint}\nPersistentKeepalive = 25\n"
    )
}

fn parse_managed_name(line: &str) -> Option<&str> {
    line.strip_prefix(MANAGED_NAME_PREFIX)
        .map(|value| value.trim())
}
