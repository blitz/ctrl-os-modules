//! Create a new Secure Boot CA.
//!
//! This creates the Platform Key (PK), the Key Exchange Key (KEK) and the database CA (db CA). PK signs updates of PK
//! and KEK, KEK signs updates of db and dbx. All three keys are meant to be kept offline.
//!
//! The db CA certificate is enrolled in db, but the db CA does not sign UEFI binaries itself. Instead, it issues
//! certificates for signing keys, which are typically generated in an HSM. Firmware accepts binaries signed by these
//! keys, because their certificates are trusted by the db CA. Signing keys can thus be replaced without updating db.
use std::path::PathBuf;

use anyhow::Result;
use clap::Args;

/// Create a new Secure Boot CA.
#[derive(Debug, Args)]
pub struct Opts {
    /// Directory to write the keys and certificates to.
    #[arg(short, long)]
    output_directory: PathBuf,
}

impl Opts {
    pub fn run(&self) -> Result<()> {
        todo!(
            "create PK, KEK and db CA in {}",
            self.output_directory.display()
        )
    }
}
