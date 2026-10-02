//! Create an enrollment package for systemd-boot.
//!
//! systemd-boot can enroll Secure Boot keys from the ESP while the firmware is in setup mode. It expects the signed
//! variable updates in `loader/keys/<name>/` as `PK.auth`, `KEK.auth`, `db.auth` and optionally `dbx.auth`. Whether it
//! does so automatically is controlled by `secure-boot-enroll` in `loader.conf`.
//!
//! The package contains:
//!
//! - `PK.auth`: the PK certificate, signed by the PK key.
//! - `KEK.auth`: the KEK certificate, signed by the PK key.
//! - `db.auth`: the db CA certificate, signed by the KEK key.
//!
//! There is no `dbx.auth`, because there is nothing to forbid yet.
use std::path::PathBuf;

use anyhow::Result;
use clap::Args;
use uuid::Uuid;

/// Create an enrollment package for systemd-boot.
#[derive(Debug, Args)]
pub struct Opts {
    /// Owner GUID of our entries in the variables, as created by init-ca in public/guid.txt.
    #[arg(long)]
    owner_guid: Uuid,

    /// Private key of the PK, e.g. private/pk.key as created by init-ca. Signs the updates of PK and KEK.
    #[arg(long)]
    pk_key: PathBuf,

    /// Certificate of the PK, e.g. public/pk.crt as created by init-ca. Enrolled in PK.
    #[arg(long)]
    pk_certificate: PathBuf,

    /// Private key of the KEK, e.g. private/kek.key as created by init-ca. Signs the update of db.
    #[arg(long)]
    kek_key: PathBuf,

    /// Certificate of the KEK, e.g. public/kek.crt as created by init-ca. Enrolled in KEK.
    #[arg(long)]
    kek_certificate: PathBuf,

    /// Certificate of the db CA, e.g. public/db-ca.crt as created by init-ca. Enrolled in db.
    #[arg(long)]
    db_ca_certificate: PathBuf,

    /// Name of the enrollment package. systemd-boot shows it in its menu.
    #[arg(long, default_value = "cyberus")]
    name: String,

    /// Directory to write the package to. It is laid out like an ESP, i.e. the files end up in
    /// loader/keys/<NAME>/ below it.
    #[arg(short, long)]
    output_directory: PathBuf,
}

impl Opts {
    pub fn run(&self) -> Result<()> {
        todo!("create enrollment package")
    }
}
