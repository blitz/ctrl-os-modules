//! Create a key for signing UEFI binaries.
//!
//! The key gets a certificate issued by the db CA. The certificate does not need to be enrolled in `db`, because it
//! is embedded in every signed binary and firmware checks that it was issued by the db CA certificate in `db`.
use std::{fs, os::unix::fs::DirBuilderExt, path::PathBuf};

use anyhow::{Context, Result, ensure};
use clap::Args;
use log::info;
use openssl::{
    asn1::Asn1Time,
    hash::MessageDigest,
    pkey::{PKey, Private},
    x509::X509,
    x509::extension::{
        AuthorityKeyIdentifier, BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectKeyIdentifier,
    },
};

use crate::cert;

/// Firmware does not check certificate expiry. Tools such as sbverify do, so this must not exceed the validity of the
/// db CA certificate.
const VALIDITY_DAYS: u32 = 5 /* years */ * 365;

/// Create a new key for signing UEFI binaries.
#[derive(Debug, Args)]
pub struct Opts {
    /// Private key of the db CA. This is the private/db-ca.key as created by init-ca.
    #[arg(long)]
    db_ca_key: PathBuf,

    /// Certificate of the db CA. This is the public/db-ca.crt as created by init-ca.
    #[arg(long)]
    db_ca_certificate: PathBuf,

    /// Directory to write the key and certificate to. Must not exist yet.
    #[arg(short, long)]
    output_directory: PathBuf,

    /// Common name of the certificate.
    #[arg(long, default_value = "Secure Boot Signing Key")]
    common_name: String,
}

impl Opts {
    pub fn run(&self) -> Result<()> {
        let ca_key_file = &self.db_ca_key;
        let ca_cert_file = &self.db_ca_certificate;

        let ca_key = PKey::private_key_from_pem(
            &fs::read(&ca_key_file)
                .with_context(|| format!("Failed to read {}", ca_key_file.display()))?,
        )?;
        let ca_cert = X509::from_pem(
            &fs::read(&ca_cert_file)
                .with_context(|| format!("Failed to read {}", ca_cert_file.display()))?,
        )?;

        // Sanity check whether the given key and certificate match.
        ensure!(
            ca_cert.public_key()?.public_eq(&ca_key),
            "{} does not belong to {}",
            ca_key_file.display(),
            ca_cert_file.display()
        );

        // The directory contains the private key. This fails if the directory already exists, so we never overwrite
        // existing keys.
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&self.output_directory)
            .with_context(|| format!("Failed to create {}", self.output_directory.display()))?;

        let key_file = self.output_directory.join("signing.key");
        let cert_file = self.output_directory.join("signing.crt");

        info!(
            "Creating {}: key={} cert={}",
            self.common_name,
            key_file.display(),
            cert_file.display()
        );

        let (key, cert) = create_signing_key(&self.common_name, &ca_key, &ca_cert)?;

        // The serial number identifies the certificate, e.g. when it needs to be revoked via dbx.
        info!(
            "Issued certificate with serial number {}",
            cert.serial_number().to_bn()?.to_hex_str()?
        );

        fs::write(&key_file, key.private_key_to_pem_pkcs8()?)
            .with_context(|| format!("Failed to write {}", key_file.display()))?;
        fs::write(&cert_file, cert.to_pem()?)
            .with_context(|| format!("Failed to write {}", cert_file.display()))?;

        Ok(())
    }
}

/// Create an RSA key and a code signing certificate for it, issued by the given CA.
fn create_signing_key(
    common_name: &str,
    ca_key: &PKey<Private>,
    ca_cert: &X509,
) -> Result<(PKey<Private>, X509)> {
    let key = cert::generate_key()?;
    let name = cert::name(common_name)?;
    let serial = cert::random_serial()?;

    let not_before = Asn1Time::days_from_now(0)?;
    let not_after = Asn1Time::days_from_now(VALIDITY_DAYS)?;

    ensure!(
        not_after.as_ref() <= ca_cert.not_after(),
        "The signing certificate would be valid longer than the db CA certificate"
    );

    let mut builder = X509::builder()?;

    // X.509 v3, which is required to add extensions. Yes, 2 indicates version 3.
    builder.set_version(2)?;

    builder.set_serial_number(&serial)?;
    builder.set_subject_name(&name)?;
    builder.set_issuer_name(ca_cert.subject_name())?;
    builder.set_pubkey(&key)?;
    builder.set_not_before(&not_before)?;
    builder.set_not_after(&not_after)?;

    // Mark the certificate as not being a CA certificate.
    builder.append_extension(BasicConstraints::new().critical().build()?)?;

    // The key may only sign, and only code.
    builder.append_extension(KeyUsage::new().critical().digital_signature().build()?)?;
    builder.append_extension(ExtendedKeyUsage::new().code_signing().build()?)?;

    let subject_key_id =
        SubjectKeyIdentifier::new().build(&builder.x509v3_context(Some(ca_cert), None))?;
    builder.append_extension(subject_key_id)?;

    // Identifies the db CA key, which helps verifiers find the issuer.
    let authority_key_id = AuthorityKeyIdentifier::new()
        .keyid(true)
        .build(&builder.x509v3_context(Some(ca_cert), None))?;
    builder.append_extension(authority_key_id)?;

    builder.sign(ca_key, MessageDigest::sha256())?;

    Ok((key, builder.build()))
}
