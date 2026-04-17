use std::path::PathBuf;

use clap::Parser;
use clap::Subcommand;

#[derive(Parser, Debug)]
#[command(name = "wg-friend")]
#[command(version)]
#[command(author = "Ricky <mail.me@pylab.me>")]
#[command(about = "Semantic WireGuard/BoringTun lifecycle and client helper")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Manage semantic WireGuard/BoringTun server lifecycle.
    Server {
        #[command(subcommand)]
        command: ServerCommands,
    },
    /// Manage complete clients, canonical exports, and runtime identity.
    Client {
        #[command(subcommand)]
        command: ClientCommands,
    },
    /// Manage systemd integration for wg-friend instances.
    Service {
        #[command(subcommand)]
        command: ServiceCommands,
    },
    /// Run production-friendly diagnostics for service, interface, and WireGuard runtime state.
    Doctor {
        #[command(subcommand)]
        command: DoctorCommands,
    },
    /// Internal helper phases used by systemd.
    #[command(hide = true)]
    Internal {
        #[command(subcommand)]
        command: InternalCommands,
    },
}

#[derive(Subcommand, Debug)]
pub enum ServerCommands {
    /// List server configs discovered under the config directory.
    List,
    /// Show config and runtime summary for one server.
    Show { interface: Option<String> },
    /// Start the server service.
    Up { interface: Option<String> },
    /// Stop the server service.
    Down { interface: Option<String> },
    /// Restart the server service.
    Restart { interface: Option<String> },
    /// Show service + interface status.
    Status { interface: Option<String> },
    /// Interactively edit a small set of server fields.
    Edit { interface: Option<String> },
}

#[derive(Subcommand, Debug)]
pub enum ClientCommands {
    /// List clients in a PiVPN-like runtime view.
    List { interface: Option<String> },
    /// Show one client with config and runtime details.
    Show {
        interface: Option<String>,
        name: Option<String>,
    },
    /// Add a managed_complete client and write canonical state + export.
    Add {
        interface: Option<String>,
        name: Option<String>,
        #[arg(long)]
        address: Option<String>,
        #[arg(long)]
        dns: Option<String>,
        #[arg(long)]
        endpoint: Option<String>,
    },
    /// Import complete local client assets into canonical wg-friend state.
    Import { interface: Option<String> },
    /// Render an exported client config as a terminal QR code.
    Qrcode {
        interface: Option<String>,
        name: Option<String>,
    },
    /// Remove a managed client peer and delete its exported config.
    Remove {
        interface: Option<String>,
        name: Option<String>,
    },
    /// Copy an exported client config to another path.
    Export {
        interface: Option<String>,
        name: Option<String>,
        #[arg(long)]
        output: Option<PathBuf>,
    },
}

#[derive(Subcommand, Debug)]
pub enum ServiceCommands {
    /// Install the systemd template and the default env file.
    Install,
    /// Remove the systemd template and optionally clean generated wg-friend files.
    Uninstall {
        interface: Option<String>,
        #[arg(long)]
        keep_env: bool,
        #[arg(long)]
        keep_generated: bool,
        #[arg(long)]
        keep_log: bool,
        #[arg(long)]
        yes: bool,
    },
    /// Show current systemd unit status for a server.
    Status { interface: Option<String> },
    /// Enable the systemd unit for a server.
    Enable { interface: Option<String> },
    /// Disable the systemd unit for a server.
    Disable { interface: Option<String> },
}

#[derive(Subcommand, Debug)]
pub enum DoctorCommands {
    /// Run the full diagnostic bundle.
    Run { interface: Option<String> },
    /// Validate local prerequisites only.
    Check { interface: Option<String> },
}

#[derive(Subcommand, Debug)]
pub enum InternalCommands {
    Preflight {
        #[arg(long)]
        interface: String,
    },
    Configure {
        #[arg(long)]
        interface: String,
    },
    Verify {
        #[arg(long)]
        interface: String,
    },
    Cleanup {
        #[arg(long)]
        interface: String,
    },
}
