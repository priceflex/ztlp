//! The Windows Root store exactly as browsers see it.
//!
//! `rustls_native_certs::load_native_certs()` uses `SSL_CERT_FILE` /
//! `SSL_CERT_DIR` *instead of* the OS store when either is set. TRS PCs get
//! `SSL_CERT_FILE` machine-wide from the Z2LS (Ruby/Chef) agent, so the
//! desktop app's HTTPS check saw only that bundle and reported the ZTLP root
//! "not trusted" while Chrome/Edge (which never read that variable) loaded
//! every `.ztlp` site fine. This reads the store directly, with the same
//! filter rustls-native-certs applies (server-auth usable, time-valid).
#![cfg(windows)]

use rustls::pki_types::CertificateDer;

/// Every root in the current user's view of the Windows Root store (which
/// includes LocalMachine\Root), ignoring `SSL_CERT_FILE` / `SSL_CERT_DIR`.
pub fn windows_root_certs() -> Vec<CertificateDer<'static>> {
    use schannel::cert_context::ValidUses;
    use schannel::cert_store::CertStore;
    const PKIX_SERVER_AUTH: &str = "1.3.6.1.5.5.7.3.1";
    let Ok(store) = CertStore::open_current_user("ROOT") else {
        return Vec::new();
    };
    store
        .certs()
        .filter(|c| {
            let usable = match c.valid_uses() {
                Ok(ValidUses::All) => true,
                Ok(ValidUses::Oids(oids)) => oids.iter().any(|o| o == PKIX_SERVER_AUTH),
                Err(_) => false,
            };
            usable && c.is_time_valid().unwrap_or(false)
        })
        .map(|c| CertificateDer::from(c.to_der().to_vec()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_roots_ignore_ssl_cert_file() {
        let dir = std::env::temp_dir().join(format!("ztlp-os-trust-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let chain = crate::agent::machine_setup::generate_ca_chain(
            "ZTLP env-only root",
            "ZTLP env-only int",
        )
        .unwrap();
        let file = dir.join("only.pem");
        std::fs::write(&file, &chain.root_cert).unwrap();
        let only: Vec<CertificateDer<'static>> =
            rustls_pemfile::certs(&mut chain.root_cert.as_bytes())
                .map(|c| c.unwrap())
                .collect();
        let before = std::env::var_os("SSL_CERT_FILE");
        std::env::set_var("SSL_CERT_FILE", &file);
        let got = windows_root_certs();
        match before {
            Some(v) => std::env::set_var("SSL_CERT_FILE", v),
            None => std::env::remove_var("SSL_CERT_FILE"),
        }
        let _ = std::fs::remove_dir_all(&dir);
        assert!(
            got.len() > 5,
            "the Windows Root store has many roots; got {}",
            got.len()
        );
        assert!(
            !got.contains(&only[0]),
            "the SSL_CERT_FILE-only root must not appear"
        );
    }
}
