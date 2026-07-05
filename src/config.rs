use std::env;
use std::path::PathBuf;
use std::time::Duration;

#[derive(Clone, Debug)]
pub struct AppConfig {
    pub default_interface: String,
    pub boringtun_bin: PathBuf,
    pub conf_dir: PathBuf,
    pub state_dir: PathBuf,
    pub wg_run_dir: PathBuf,
    pub log_file: PathBuf,
    pub env_file: PathBuf,
    pub default_addr: String,
    pub default_mtu: String,
    pub default_client_dns: String,
    pub default_client_endpoint: String,
    pub client_subdir_name: String,
    pub process_timeout: Duration,
    pub interface_timeout: Duration,
    pub uapi_timeout: Duration,
    pub ready_timeout: Duration,
    pub systemd_unit_prefix: String,
}

#[derive(Clone, Debug)]
pub struct InterfaceConfig {
    pub interface: String,
    pub conf_file: PathBuf,
    pub client_dir: PathBuf,
}

impl AppConfig {
    pub fn from_env() -> Self {
        Self {
            default_interface: env::var("WG_FRIEND_DEFAULT_INTERFACE")
                .unwrap_or_else(|_| "wg0".to_string()),
            boringtun_bin: PathBuf::from(
                env::var("WG_FRIEND_BORINGTUN_BIN")
                    .unwrap_or_else(|_| "/usr/bin/boringtun-cli".to_string()),
            ),
            conf_dir: PathBuf::from(
                env::var("WG_FRIEND_CONF_DIR").unwrap_or_else(|_| "/etc/wireguard".to_string()),
            ),
            state_dir: PathBuf::from(
                env::var("WG_FRIEND_STATE_DIR").unwrap_or_else(|_| "/etc/wg-friend".to_string()),
            ),
            wg_run_dir: PathBuf::from(
                env::var("WG_FRIEND_WG_RUN_DIR").unwrap_or_else(|_| "/run/wireguard".to_string()),
            ),
            log_file: PathBuf::from(
                env::var("WG_FRIEND_LOG_FILE")
                    .unwrap_or_else(|_| "/var/log/wg-friend.log".to_string()),
            ),
            env_file: PathBuf::from(
                env::var("WG_FRIEND_ENV_FILE")
                    .unwrap_or_else(|_| "/etc/default/wg-friend".to_string()),
            ),
            default_addr: env::var("WG_FRIEND_DEFAULT_ADDR")
                .unwrap_or_else(|_| "10.6.0.1/24".to_string()),
            default_mtu: env::var("WG_FRIEND_DEFAULT_MTU").unwrap_or_else(|_| "1420".to_string()),
            default_client_dns: env::var("WG_FRIEND_DEFAULT_CLIENT_DNS")
                .unwrap_or_else(|_| "10.6.0.1".to_string()),
            default_client_endpoint: env::var("WG_FRIEND_DEFAULT_CLIENT_ENDPOINT")
                .unwrap_or_else(|_| "CHANGE_ME:51820".to_string()),
            client_subdir_name: env::var("WG_FRIEND_CLIENT_SUBDIR")
                .unwrap_or_else(|_| "clients".to_string()),
            process_timeout: duration_from_env("WG_FRIEND_PROCESS_TIMEOUT_SECONDS", 3),
            interface_timeout: duration_from_env("WG_FRIEND_INTERFACE_TIMEOUT_SECONDS", 10),
            uapi_timeout: duration_from_env("WG_FRIEND_UAPI_TIMEOUT_SECONDS", 10),
            ready_timeout: duration_from_env("WG_FRIEND_READY_TIMEOUT_SECONDS", 10),
            systemd_unit_prefix: env::var("WG_FRIEND_SYSTEMD_UNIT_PREFIX")
                .unwrap_or_else(|_| "wg-friend".to_string()),
        }
    }

    pub fn resolve_interface(&self, interface: Option<String>) -> InterfaceConfig {
        let interface = interface.unwrap_or_else(|| self.default_interface.clone());
        let conf_file = self.conf_dir.join(format!("{interface}.conf"));
        let client_dir = self
            .conf_dir
            .join(&self.client_subdir_name)
            .join(&interface);
        InterfaceConfig {
            interface,
            conf_file,
            client_dir,
        }
    }

    pub fn service_name(&self, interface: &str) -> String {
        format!("{}@{}.service", self.systemd_unit_prefix, interface)
    }

    pub fn instance_state_dir(&self, interface: &str) -> PathBuf {
        self.state_dir.join("instances").join(interface)
    }

    pub fn instance_clients_dir(&self, interface: &str) -> PathBuf {
        self.instance_state_dir(interface).join("clients")
    }

    pub fn instance_exports_dir(&self, interface: &str) -> PathBuf {
        self.instance_state_dir(interface).join("exports")
    }

    pub fn state_server_path(&self, interface: &str) -> PathBuf {
        self.instance_state_dir(interface).join("server.toml")
    }

    pub fn state_client_meta_path(&self, interface: &str, name: &str) -> PathBuf {
        self.instance_clients_dir(interface)
            .join(format!("{name}.toml"))
    }

    pub fn state_export_path(&self, interface: &str, name: &str) -> PathBuf {
        self.instance_exports_dir(interface)
            .join(format!("{name}.conf"))
    }

    pub fn state_import_report_path(&self, interface: &str) -> PathBuf {
        self.instance_state_dir(interface)
            .join("import-report.json")
    }

    pub fn discover_interfaces(&self) -> Vec<String> {
        let entries = match std::fs::read_dir(&self.conf_dir) {
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
            let Some(stem) = path.file_stem().and_then(|item| item.to_str()) else {
                continue;
            };
            items.push(stem.to_string());
        }
        items.sort();
        items
    }
}

fn duration_from_env(name: &str, default_seconds: u64) -> Duration {
    let seconds = env::var(name)
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(default_seconds);
    Duration::from_secs(seconds)
}
