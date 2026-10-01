//! Helpers for creating keys and certificates.
use anyhow::Result;
use openssl::{
    asn1::Asn1Integer,
    bn::{BigNum, MsbOption},
    pkey::{PKey, Private},
    rsa::Rsa,
    x509::{X509Name, X509NameBuilder},
};

/// Should be enough for any use case. Harvest and decrypt later is not a concern, because nothing is encrypted with
/// these keys. Once attacks become relevant, systems can be migrated to stronger keys.
const RSA_KEY_BITS: u32 = 2048;

/// Generate a new RSA key.
pub fn generate_key() -> Result<PKey<Private>> {
    Ok(PKey::from_rsa(Rsa::generate(RSA_KEY_BITS)?)?)
}

/// Create a name that only consists of a common name.
pub fn name(common_name: &str) -> Result<X509Name> {
    let mut name = X509NameBuilder::new()?;
    name.append_entry_by_text("CN", common_name)?;
    Ok(name.build())
}

/// Create a random serial number.
pub fn random_serial() -> Result<Asn1Integer> {
    // A cryptographically secure random number is okay as the serial number.
    let mut serial = BigNum::new()?;
    serial.rand(128, MsbOption::MAYBE_ZERO, false)?;
    Ok(serial.to_asn1_integer()?)
}
