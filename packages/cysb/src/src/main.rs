mod cert;
mod create_signing_key;
mod init_ca;
mod issue_signing_certificate;
mod verify;

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
    /// This creates the key and a certificate signing request (CSR). Use issue-signing-certificate to turn the CSR
    /// into a certificate.
    CreateSigningKey(create_signing_key::Opts),

    /// Issue a certificate for a key that signs UEFI binaries.
    ///
    /// The certificate is issued by the db CA. Firmware boots binaries signed with the key, because the db CA
    /// certificate is enrolled in db.
    IssueSigningCertificate(issue_signing_certificate::Opts),

    /// Verify the signatures of UEFI binaries.
    ///
    /// A binary passes if it is signed by a key which is trusted by the given certificate.
    Verify(verify::Opts),
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
        Command::IssueSigningCertificate(opts) => {
            opts.run().context("Failed to issue signing certificate")
        }
        Command::Verify(opts) => opts.run().context("Failed to verify signatures"),
    }
}
