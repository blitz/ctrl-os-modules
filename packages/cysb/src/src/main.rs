mod cert;
mod init_ca;
mod create_signing_key;


use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

/// Manage the Secure Boot keys of Cyberus Linux.
#[derive(Debug, Parser)]
#[command(version, about)]
struct Cli {
    /// Increase the log verbosity. Can be given multiple times.
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    verbose: u8,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Create a new Secure Boot CA: PK, KEK and db CA.
    InitCA(init_ca::Opts),

    /// Create a new key for signing UEFI binaries.
    ///
    /// The key's certificate is issued by the db CA. Firmware boots binaries signed with this key, because the db CA
    /// certificate is enrolled in db.
    CreateSigningKey(create_signing_key::Opts),
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Warnings and errors are always shown. Each -v adds info, debug and
    // trace messages.
    stderrlog::new()
        .module(module_path!())
        .verbosity(usize::from(cli.verbose) + 1)
        .init()
        .context("Failed to initialize logging")?;

    match cli.command {
        Command::InitCA(opts) => opts.run().context("Failed to initialize CA"),
        Command::CreateSigningKey(opts) => opts.run().context("Failed to create signing key"),
    }
}
