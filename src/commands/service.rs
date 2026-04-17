use std::fs;
use std::path::PathBuf;

use anyhow::Context;
use anyhow::Result;

use super::server::resolve_server;
use crate::config::AppConfig;
use crate::systemd;
use crate::util::ensure_required_commands;
use crate::util::ensure_root;
use crate::util::print_header;
use crate::util::print_kv;

pub fn install(app: &AppConfig) -> Result<()> {
    ensure_root()?;
    ensure_required_commands()?;

    let exe = std::env::current_exe().context("failed to locate current executable")?;
    let unit_path = PathBuf::from(format!(
        "/etc/systemd/system/{}@.service",
        app.systemd_unit_prefix
    ));

    let unit_content = format!(
        r#"[Unit]
Description=wg-friend managed WireGuard interface %I via BoringTun
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=-{env_file}
ExecStartPre={exe} internal preflight --interface %I
ExecStart={boringtun} -f --disable-drop-privileges %I
ExecStartPost={exe} internal configure --interface %I
ExecStartPost={exe} internal verify --interface %I
ExecStopPost={exe} internal cleanup --interface %I
Restart=on-failure
RestartSec=2

[Install]
WantedBy=multi-user.target
"#,
        env_file = app.env_file.display(),
        exe = exe.display(),
        boringtun = app.boringtun_bin.display(),
    );

    fs::write(&unit_path, unit_content)
        .with_context(|| format!("failed to write {}", unit_path.display()))?;

    if !app.env_file.exists() {
        let env_content = format!(
            concat!(
                "WG_FRIEND_DEFAULT_INTERFACE={}\n",
                "WG_FRIEND_BORINGTUN_BIN={}\n",
                "WG_FRIEND_CONF_DIR={}\n",
                "WG_FRIEND_WG_RUN_DIR={}\n",
                "WG_FRIEND_LOG_FILE={}\n",
                "WG_FRIEND_DEFAULT_ADDR={}\n",
                "WG_FRIEND_DEFAULT_MTU={}\n",
                "WG_FRIEND_DEFAULT_CLIENT_DNS={}\n",
                "WG_FRIEND_DEFAULT_CLIENT_ENDPOINT={}\n",
                "WG_FRIEND_CLIENT_SUBDIR={}\n",
                "WG_LOG_LEVEL=info\n",
                "WG_THREADS=2\n",
                "WG_FRIEND_PROCESS_TIMEOUT_SECONDS={}\n",
                "WG_FRIEND_INTERFACE_TIMEOUT_SECONDS={}\n",
                "WG_FRIEND_UAPI_TIMEOUT_SECONDS={}\n",
                "WG_FRIEND_READY_TIMEOUT_SECONDS={}\n"
            ),
            app.default_interface,
            app.boringtun_bin.display(),
            app.conf_dir.display(),
            app.wg_run_dir.display(),
            app.log_file.display(),
            app.default_addr,
            app.default_mtu,
            app.default_client_dns,
            app.default_client_endpoint,
            app.client_subdir_name,
            app.process_timeout.as_secs(),
            app.interface_timeout.as_secs(),
            app.uapi_timeout.as_secs(),
            app.ready_timeout.as_secs(),
        );

        if let Some(parent) = app.env_file.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }

        fs::write(&app.env_file, env_content)
            .with_context(|| format!("failed to write {}", app.env_file.display()))?;
    }

    systemd::daemon_reload()?;

    print_header("service install");
    print_kv("unit", unit_path.display().to_string());
    print_kv("env", app.env_file.display().to_string());
    println!("\nInstalled the systemd template. Example:");
    println!("  sudo wg-friend service enable {}", app.default_interface);
    println!("  sudo wg-friend server up {}", app.default_interface);
    Ok(())
}

pub fn status(app: &AppConfig, interface: Option<String>) -> Result<()> {
    let iface = resolve_server(app, interface)?;
    let service = app.service_name(&iface.interface);

    print_header("service status");
    print_kv("unit", &service);
    print_kv(
        "active",
        systemd::is_active(&service).unwrap_or_else(|_| "unknown".to_string()),
    );
    println!("\n{}", systemd::status_text(&service));
    Ok(())
}

pub fn enable(app: &AppConfig, interface: Option<String>) -> Result<()> {
    ensure_root()?;
    ensure_required_commands()?;
    let iface = resolve_server(app, interface)?;
    let service = app.service_name(&iface.interface);
    systemd::enable(&service)?;
    println!("Enabled {service}.");
    Ok(())
}

pub fn disable(app: &AppConfig, interface: Option<String>) -> Result<()> {
    ensure_root()?;
    ensure_required_commands()?;
    let iface = resolve_server(app, interface)?;
    let service = app.service_name(&iface.interface);
    systemd::disable(&service)?;
    println!("Disabled {service}.");
    Ok(())
}
