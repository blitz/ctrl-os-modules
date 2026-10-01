//! Create a new Secure Boot CA.
//!
//! # UEFI variables
//!
//! Secure Boot is configured by four UEFI variables:
//!
//! - `PK` (Platform Key) holds exactly one certificate. The holder of this key may update `PK` and `KEK`.
//! - `KEK` (Key Exchange Key) holds any number of certificates. The key of any of them may update `db` and `dbx`.
//! - `db` (signature database) holds certificates and hashes that allow UEFI binaries to run.
//! - `dbx` (forbidden signature database) holds certificates and hashes that forbid UEFI binaries from running. It
//!   takes precedence over `db`.
//!
//! Firmware only runs a UEFI binary if it is not forbidden by `dbx`, and either its hash is in `db` or it is signed by a
//! key whose certificate is in `db` or was issued by a certificate in `db`.
//!
//! # Keys
//!
//! This command creates three keys, each an RSA key with a self-signed certificate. Each certificate is intended to be
//! enrolled as an entry in one of the variables above:
//!
//! - The PK key. Its certificate is the single entry in `PK`.
//! - The KEK key. Its certificate is one entry in `KEK`, possibly next to others, such as Microsoft's.
//! - The db CA key. Its certificate is one entry in `db`. It does not sign UEFI binaries itself. Instead, it issues
//!   certificates for signing keys, which are typically generated in an HSM. Firmware accepts binaries signed by these
//!   keys, because their certificates were issued by a certificate in `db`. Signing keys can thus be replaced without
//!   updating `db`.
//!
//! All three keys are meant to be kept offline.
use std::{
    fs::{self, DirBuilder},
    os::unix::fs::DirBuilderExt,
    path::PathBuf,
};

use anyhow::{Context, Result};
use clap::Args;
use log::info;
use openssl::{
    asn1::Asn1Time,
    hash::MessageDigest,
    pkey::{PKey, Private},
    x509::X509,
    x509::extension::{AuthorityKeyIdentifier, BasicConstraints, KeyUsage, SubjectKeyIdentifier},
};

use crate::cert;

/// Firmware does not check certificate expiry, because it has no trusted time source. The validity period only
/// matters to tools such as sbverify and must cover all certificates issued by the db CA.
const VALIDITY_DAYS: u32 = 20 /* years */ * 365;

/// Create a new Secure Boot CA.
#[derive(Debug, Args)]
pub struct Opts {
    /// Directory to write the keys and certificates to.
    #[arg(short, long)]
    output_directory: PathBuf,
}

impl Opts {
    pub fn run(&self) -> Result<()> {
        let private_dir = self.output_directory.join("private");
        let public_dir = self.output_directory.join("public");

        fs::create_dir_all(&self.output_directory)
            .with_context(|| format!("Failed to create {}", self.output_directory.display()))?;

        // This fails if the directory already exists, so we never overwrite existing keys.
        DirBuilder::new()
            .mode(0o700)
            .create(&private_dir)
            .with_context(|| format!("Failed to create {}", private_dir.display()))?;

        fs::create_dir_all(&public_dir)
            .with_context(|| format!("Failed to create {}", public_dir.display()))?;

        // The boolean indicates whether the key issues certificates.
        let keys = [
            ("PK", "Secure Boot PK", false),
            ("KEK", "Secure Boot KEK", false),
            ("db-ca", "Secure Boot db CA", true),
        ];

        for (name, common_name, issues_certificates) in keys {
            let key_file = private_dir.join(format!("{name}.key"));
            let cert_file = public_dir.join(format!("{name}.crt"));

            info!("Creating {common_name}: key={} cert={}", key_file.display(), cert_file.display());

            let (key, cert) = create_self_signed(common_name, issues_certificates)
                .with_context(|| format!("Failed to create {common_name}"))?;

            std::fs::write(
                &private_dir.join(format!("{name}.key")),
                &key.private_key_to_pem_pkcs8()?,
            )?;
            std::fs::write(&public_dir.join(format!("{name}.crt")), &cert.to_pem()?)?;
        }

        Ok(())
    }
}

/// Create an RSA key and a self-signed CA certificate for it.
///
/// If `issues_certificates` is set, the key may only sign certificates and the certificates it issues cannot be CAs
/// themselves. Otherwise, the key is not restricted.
fn create_self_signed(
    common_name: &str,
    issues_certificates: bool,
) -> Result<(PKey<Private>, X509)> {
    let key = cert::generate_key()?;
    let name = cert::name(common_name)?;
    let serial = cert::random_serial()?;

    let not_before = Asn1Time::days_from_now(0)?;
    let not_after = Asn1Time::days_from_now(VALIDITY_DAYS)?;

    let mut builder = X509::builder()?;

    // X.509 v3, which is required to add extensions. Yes, 2 indicates version 3.
    builder.set_version(2)?;

    builder.set_serial_number(&serial)?;
    builder.set_subject_name(&name)?;
    builder.set_issuer_name(&name)?;
    builder.set_pubkey(&key)?;
    builder.set_not_before(&not_before)?;
    builder.set_not_after(&not_after)?;

    // Mark the certificate as a CA certificate.
    let mut basic_constraints = BasicConstraints::new();
    basic_constraints.critical().ca();
    if issues_certificates {
        // Tell verifiers that no CA may follow this certificate in a chain.
        basic_constraints.pathlen(0);
    }
    builder.append_extension(basic_constraints.build()?)?;

    if issues_certificates {
        builder.append_extension(
            KeyUsage::new()
                .critical()
                .key_cert_sign()
                .crl_sign()
                .build()?,
        )?;
    }

    // CA certificates must have this.
    let subject_key_id = SubjectKeyIdentifier::new().build(&builder.x509v3_context(None, None))?;
    builder.append_extension(subject_key_id)?;

    let authority_key_id = AuthorityKeyIdentifier::new()
        .keyid(true)
        .build(&builder.x509v3_context(None, None))?;
    builder.append_extension(authority_key_id)?;

    // Self-sign the certificate.
    builder.sign(&key, MessageDigest::sha256())?;

    Ok((key, builder.build()))
}
