use std::fs;
use std::path::PathBuf;

use anyhow::Context;
use anyhow::Result;

use super::server::resolve_server;
use crate::config::AppConfig;
use crate::prompt::ask_yes_no;
use crate::systemd;
use crate::ui::kv;
use crate::ui::Tone;
use crate::ui::{self};
use crate::util::ensure_required_commands;
use crate::util::ensure_root;

pub fn install(app: &AppConfig) -> Result<()> {
    ensure_root()?;
    ensure_required_commands()?;

    let exe = std::env::current_exe().context("failed to locate current executable")?;
    let unit_path = unit_path(app);

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

    ui::print_section("service install");
    ui::print_kv_rows(&vec![
        kv("unit", unit_path.display().to_string()),
        kv("env", app.env_file.display().to_string()),
        kv("default_interface", app.default_interface.clone()),
        kv("binary", exe.display().to_string()),
    ]);
    ui::print_message("Installed the systemd template.", Tone::Good);
    println!(
        "  sudo {} service enable {}",
        exe.display(),
        app.default_interface
    );
    println!(
        "  sudo {} server up {}",
        exe.display(),
        app.default_interface
    );
    Ok(())
}

pub fn uninstall(
    app: &AppConfig,
    interface: Option<String>,
    keep_env: bool,
    keep_generated: bool,
    keep_log: bool,
    yes: bool,
) -> Result<()> {
    ensure_root()?;
    ensure_required_commands()?;

    let iface = resolve_server(app, interface)?;
    let service = app.service_name(&iface.interface);
    let unit_path = unit_path(app);

    if !yes {
        let confirmed = ask_yes_no(
            &format!(
                "Remove wg-friend systemd integration for {} and delete generated files?",
                iface.interface
            ),
            false,
        )?;
        if !confirmed {
            ui::print_message("Nothing changed.", Tone::Warn);
            return Ok(());
        }
    }

    let _ = systemd::stop(&service);
    let _ = systemd::disable(&service);

    let mut removed = Vec::new();
    let mut kept = Vec::new();

    if unit_path.exists() {
        fs::remove_file(&unit_path)
            .with_context(|| format!("failed to remove {}", unit_path.display()))?;
        removed.push(("unit".to_string(), unit_path.display().to_string()));
    }

    if keep_env {
        kept.push(("env".to_string(), app.env_file.display().to_string()));
    } else if app.env_file.exists() {
        fs::remove_file(&app.env_file)
            .with_context(|| format!("failed to remove {}", app.env_file.display()))?;
        removed.push(("env".to_string(), app.env_file.display().to_string()));
    }

    if keep_generated {
        kept.push((
            "client_dir".to_string(),
            iface.client_dir.display().to_string(),
        ));
    } else if iface.client_dir.exists() {
        fs::remove_dir_all(&iface.client_dir)
            .with_context(|| format!("failed to remove {}", iface.client_dir.display()))?;
        removed.push((
            "client_dir".to_string(),
            iface.client_dir.display().to_string(),
        ));
    }

    if keep_log {
        kept.push(("log_file".to_string(), app.log_file.display().to_string()));
    } else if app.log_file.exists() {
        fs::remove_file(&app.log_file)
            .with_context(|| format!("failed to remove {}", app.log_file.display()))?;
        removed.push(("log_file".to_string(), app.log_file.display().to_string()));
    }

    systemd::daemon_reload()?;

    ui::print_section("service uninstall");
    ui::print_kv_rows(&vec![
        kv("interface", iface.interface),
        kv("service", service),
        kv("result", ui::status_badge("removed")),
    ]);

    if !removed.is_empty() {
        ui::print_section("removed");
        ui::print_kv_rows(
            &removed
                .iter()
                .map(|(key, value)| kv(key.clone(), value.clone()))
                .collect::<Vec<_>>(),
        );
    }

    if !kept.is_empty() {
        ui::print_section("kept");
        ui::print_kv_rows(
            &kept
                .iter()
                .map(|(key, value)| kv(key.clone(), value.clone()))
                .collect::<Vec<_>>(),
        );
    }

    Ok(())
}

pub fn status(app: &AppConfig, interface: Option<String>) -> Result<()> {
    let iface = resolve_server(app, interface)?;
    let service = app.service_name(&iface.interface);
    let active = systemd::is_active(&service).unwrap_or_else(|_| "unknown".to_string());
    let enabled = systemd::is_enabled(&service).unwrap_or_else(|_| "unknown".to_string());

    ui::print_section("service");
    ui::print_kv_rows(&vec![
        kv("unit", service.clone()),
        kv("active", ui::status_badge(&active)),
        kv("enabled", ui::status_badge(&enabled)),
        kv("config", iface.conf_file.display().to_string()),
    ]);

    ui::print_section("systemctl status");
    ui::print_block(&systemd::status_text(&service));
    Ok(())
}

pub fn enable(app: &AppConfig, interface: Option<String>) -> Result<()> {
    ensure_root()?;
    ensure_required_commands()?;
    let iface = resolve_server(app, interface)?;
    let service = app.service_name(&iface.interface);
    systemd::enable(&service)?;
    ui::print_section("service enable");
    ui::print_kv_rows(&vec![
        kv("unit", service),
        kv("result", ui::status_badge("enabled")),
    ]);
    Ok(())
}

pub fn disable(app: &AppConfig, interface: Option<String>) -> Result<()> {
    ensure_root()?;
    ensure_required_commands()?;
    let iface = resolve_server(app, interface)?;
    let service = app.service_name(&iface.interface);
    systemd::disable(&service)?;
    ui::print_section("service disable");
    ui::print_kv_rows(&vec![
        kv("unit", service),
        kv("result", ui::status_badge("disabled")),
    ]);
    Ok(())
}

fn unit_path(app: &AppConfig) -> PathBuf {
    PathBuf::from(format!(
        "/etc/systemd/system/{}@.service",
        app.systemd_unit_prefix
    ))
}
