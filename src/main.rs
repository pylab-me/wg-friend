mod cli;
mod command_runner;
mod commands;
mod config;
mod prompt;
mod systemd;
mod ui;
mod util;
mod wireguard;

use anyhow::Result;
use clap::Parser;

use crate::cli::Cli;
use crate::cli::ClientCommands;
use crate::cli::Commands;
use crate::cli::DoctorCommands;
use crate::cli::InternalCommands;
use crate::cli::ServerCommands;
use crate::cli::ServiceCommands;
use crate::config::AppConfig;

fn main() {
    if let Some(code) = maybe_handle_boundary_hint() {
        std::process::exit(code);
    }

    if let Err(error) = run() {
        eprintln!("[ERROR] {error:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    let app = AppConfig::from_env();

    match cli.command {
        Commands::Server { command } => match command {
            ServerCommands::List => commands::server::list(&app),
            ServerCommands::Show { interface } => commands::server::show(&app, interface),
            ServerCommands::Up { interface } => commands::server::up(&app, interface),
            ServerCommands::Down { interface } => commands::server::down(&app, interface),
            ServerCommands::Restart { interface } => commands::server::restart(&app, interface),
            ServerCommands::Status { interface } => commands::server::status(&app, interface),
            ServerCommands::Edit { interface } => commands::server::edit(&app, interface),
        },
        Commands::Client { command } => match command {
            ClientCommands::List { interface } => commands::client::list(&app, interface),
            ClientCommands::Show { interface, name } => {
                commands::client::show(&app, interface, name)
            }
            ClientCommands::Add {
                interface,
                name,
                address,
                dns,
                endpoint,
            } => commands::client::add(&app, interface, name, address, dns, endpoint),
            ClientCommands::Remove { interface, name } => {
                commands::client::remove(&app, interface, name)
            }
            ClientCommands::Export {
                interface,
                name,
                output,
            } => commands::client::export(&app, interface, name, output),
        },
        Commands::Service { command } => match command {
            ServiceCommands::Install => commands::service::install(&app),
            ServiceCommands::Uninstall {
                interface,
                keep_env,
                keep_generated,
                keep_log,
                yes,
            } => commands::service::uninstall(
                &app,
                interface,
                keep_env,
                keep_generated,
                keep_log,
                yes,
            ),
            ServiceCommands::Status { interface } => commands::service::status(&app, interface),
            ServiceCommands::Enable { interface } => commands::service::enable(&app, interface),
            ServiceCommands::Disable { interface } => commands::service::disable(&app, interface),
        },
        Commands::Doctor { command } => match command {
            DoctorCommands::Run { interface } => commands::doctor::run(&app, interface),
            DoctorCommands::Check { interface } => commands::doctor::check(&app, interface),
        },
        Commands::Internal { command } => match command {
            InternalCommands::Preflight { interface } => {
                commands::internal::preflight(&app, interface)
            }
            InternalCommands::Configure { interface } => {
                commands::internal::configure(&app, interface)
            }
            InternalCommands::Verify { interface } => commands::internal::verify(&app, interface),
            InternalCommands::Cleanup { interface } => commands::internal::cleanup(&app, interface),
        },
    }
}

fn maybe_handle_boundary_hint() -> Option<i32> {
    let args = std::env::args().collect::<Vec<_>>();
    if args.len() < 3 {
        return None;
    }

    if args.get(1).map(String::as_str) != Some("service") {
        return None;
    }

    let Some(subcommand) = args.get(2).map(String::as_str) else {
        return None;
    };

    let Some(program) = args.first() else {
        return None;
    };

    match subcommand {
        "up" | "down" | "restart" => {
            eprintln!(
                "'{} service {}' is not supported.\nUse: {} server {} [interface]",
                program, subcommand, program, subcommand
            );
            Some(2)
        }
        _ => None,
    }
}
