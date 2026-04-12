use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "certforge", about = "ACME certificate manager with DANE and systemd integration")]
pub struct Cli {
    /// Config file path
    #[arg(short, long, default_value = "/etc/certforge/config.toml")]
    pub config: PathBuf,

    /// Increase verbosity (-v, -vv, -vvv)
    #[arg(short, long, action = clap::ArgAction::Count)]
    pub verbose: u8,

    /// Show what would be done without making changes
    #[arg(short = 'n', long)]
    pub dry_run: bool,

    /// State directory
    #[arg(long, default_value = "/var/lib/certforge")]
    pub state_dir: PathBuf,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Check all certificates and renew those expiring soon
    Renew {
        /// Only renew the named certificate
        #[arg(long)]
        name: Option<String>,

        /// Force renewal even if not expiring soon
        #[arg(long)]
        force: bool,
    },

    /// Show status of all configured certificates
    Status {
        /// Only show status for the named certificate
        #[arg(long)]
        name: Option<String>,
    },

    /// Force-issue a specific certificate
    Issue {
        /// Certificate name
        #[arg(long)]
        name: String,
    },

    /// Force-(re)publish DANE TLSA records
    DanePublish {
        /// Only publish for the named certificate
        #[arg(long)]
        name: Option<String>,
    },

    /// Query and verify published TLSA records against current certs
    DaneCheck {
        /// Only check the named certificate
        #[arg(long)]
        name: Option<String>,
    },

    /// Validate configuration file
    ConfigCheck,

    /// Print systemd-creds encrypt commands for initial setup
    Init,

    /// Manage ACME account
    Account {
        #[command(subcommand)]
        action: AccountAction,
    },
}

#[derive(Subcommand)]
pub enum AccountAction {
    /// Create a new ACME account
    Create,
    /// Show account information
    Show,
    /// Deactivate the account
    Deactivate,
}
