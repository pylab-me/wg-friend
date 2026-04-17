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
