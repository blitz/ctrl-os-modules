//! Verify the signatures of UEFI binaries.
//!
//! The actual verification is done by sbverify from sbsigntools.
use std::{
    io::{ErrorKind, Write},
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{Context, Result, bail};
use clap::Args;
use tempfile::NamedTempFile;

use crate::cert;

/// Verify the signatures of UEFI binaries.
#[derive(Debug, Args)]
pub struct Opts {
    /// The db CA certificate in PEM or DER format.
    #[arg(short, long)]
    certificate: PathBuf,

    /// UEFI binaries to verify.
    #[arg(required = true)]
    files: Vec<PathBuf>,
}

impl Opts {
    pub fn run(&self) -> Result<()> {
        check_sbverify()?;

        // sbverify only reads certificates in PEM format, so we hand it a PEM copy of the certificate.
        let certificate = cert::read_certificate(&self.certificate)?;
        let mut pem_file =
            NamedTempFile::new().context("Failed to create temporary certificate file")?;
        pem_file
            .write_all(&certificate.to_pem()?)
            .context("Failed to write temporary certificate file")?;

        // We want to try to verify all files regardless of whether some are signed or not.
        let results = self
            .files
            .iter()
            .map(|f| -> Result<()> {
                print!("Verifying {}: ", f.display());
                verify_file(pem_file.path(), f).inspect_err(|e| println!(" FAILED: {}", e))?;
                println!("OK");
                Ok(())
            })
            .collect::<Vec<Result<()>>>();

        if results.into_iter().any(|r| r.is_err()) {
            bail!("Verification failed");
        }
        Ok(())
    }
}

/// Check whether sbverify can be executed and give actionable error messages.
fn check_sbverify() -> Result<()> {
    match Command::new("sbverify").arg("--version").output() {
        Ok(output) if output.status.success() => Ok(()),
        Ok(output) => bail!(
            "sbverify --version failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ),
        Err(err) if err.kind() == ErrorKind::NotFound => bail!(
            "sbverify was not found. Install sbsigntools: \
             nix-shell -p sbsigntool"
        ),
        Err(err) => Err(err).context("Failed to execute sbverify"),
    }
}

/// Verify the signature of a single binary with sbverify.
fn verify_file(certificate: &Path, file: &Path) -> Result<()> {
    let output = Command::new("sbverify")
        .arg("--cert")
        .arg(certificate)
        .arg(file)
        .output()
        .context("Failed to execute sbverify")?;

    if output.status.success() {
        return Ok(());
    }

    // sbverify prints its reasons to both stdout and stderr.
    let message = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    bail!("{}", message.trim_end());
}
