//! Verify the signatures of UEFI binaries.
use std::path::PathBuf;

use anyhow::Result;
use clap::Args;

/// Verify the signatures of UEFI binaries.
#[derive(Debug, Args)]
pub struct Opts {
    /// Certificate the signatures must chain up to, e.g. the db CA certificate.
    #[arg(short, long)]
    certificate: PathBuf,

    /// UEFI binaries to verify.
    #[arg(required = true)]
    files: Vec<PathBuf>,
}

impl Opts {
    pub fn run(&self) -> Result<()> {
        todo!("verify signatures")
    }
}
