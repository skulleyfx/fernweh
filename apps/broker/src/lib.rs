//! PLANK remote broker (bestdayever fork, docs: bde-linux `docs/plank-broker.md` §10).
//!
//! Two binaries share this crate:
//! * `plank-broker` — unprivileged public API (login, host list, connect).
//! * `plank-broker-relay` — CAP_NET_ADMIN helper owning the nftables DNAT leases.

pub mod ad;
pub mod api;
pub mod audit;
pub mod broker;
pub mod config;
pub mod device;
pub mod diagnostics;
pub mod support_diagnostics;
pub mod directory;
pub mod enrol;
pub mod hbac;
pub mod kerberos;
pub mod mac_admission;
#[cfg(feature = "system")]
pub mod ldap;
#[cfg(feature = "system")]
pub mod mit;
pub mod passkey;
pub mod pins;
pub mod probe;
pub mod ratelimit;
pub mod relay;
pub mod sessions;
pub mod totp;
pub mod updates;
pub mod util;

#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_ad;
#[cfg(test)]
mod tests_enrol;

/// SHA-256 (lower-case hex) over the SubjectPublicKeyInfo DER of the first
/// certificate in `pem` — the value PLANK clients pin for the broker.
pub fn spki_sha256_hex(pem: &[u8]) -> anyhow::Result<String> {
    use rustls::pki_types::pem::PemObject;
    let der = rustls::pki_types::CertificateDer::pem_slice_iter(pem)
        .next()
        .ok_or_else(|| anyhow::anyhow!("no certificate in PEM input"))??;
    let (_, cert) =
        x509_parser::parse_x509_certificate(der.as_ref()).map_err(|e| anyhow::anyhow!("parse certificate: {e}"))?;
    Ok(hex::encode(util::sha256(cert.tbs_certificate.subject_pki.raw)))
}
