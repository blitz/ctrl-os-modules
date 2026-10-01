mod init_ca;

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
    }
}
