#![allow(dead_code)]

use std::path::PathBuf;

use crate::error::Error;
use crate::net::socket::WithSocket;
use crate::net::Socket;

#[cfg(feature = "_tls-rustls")]
mod tls_rustls;

#[cfg(feature = "_tls-native-tls")]
mod tls_native_tls;

mod util;

#[cfg(all(
    feature = "rss-exclusive-explicit-roots",
    feature = "_tls-native-tls"
))]
compile_error!(
    "rss-exclusive-explicit-roots cannot be combined with native-tls because native roots are ambient"
);

/// Compile-time witness that this SQLx build makes an explicitly configured root bundle
/// exclusive instead of overlaying it onto ambient WebPKI roots.
///
/// This is an RSS downstream capability and is intentionally unavailable without the matching
/// Cargo feature, so production consumers fail to compile if the audited patch is removed.
#[cfg(feature = "rss-exclusive-explicit-roots")]
#[derive(Clone, Copy, Debug)]
pub struct ExclusiveExplicitRoots(());

/// Obtain the downstream exclusive-root capability witness.
#[cfg(feature = "rss-exclusive-explicit-roots")]
pub const fn exclusive_explicit_roots() -> ExclusiveExplicitRoots {
    ExclusiveExplicitRoots(())
}

/// X.509 Certificate input, either a file path or a PEM encoded inline certificate(s).
#[derive(Clone, Debug)]
pub enum CertificateInput {
    /// PEM encoded certificate(s)
    Inline(Vec<u8>),
    /// Path to a file containing PEM encoded certificate(s)
    File(PathBuf),
}

impl From<String> for CertificateInput {
    fn from(value: String) -> Self {
        // Leading and trailing whitespace/newlines
        let trimmed = value.trim();

        // Heuristic for PEM encoded inputs:
        // https://tools.ietf.org/html/rfc7468
        if trimmed.starts_with("-----BEGIN") && trimmed.ends_with("-----") {
            CertificateInput::Inline(value.as_bytes().to_vec())
        } else {
            CertificateInput::File(PathBuf::from(value))
        }
    }
}

impl CertificateInput {
    async fn data(&self) -> Result<Vec<u8>, std::io::Error> {
        use crate::fs;
        match self {
            CertificateInput::Inline(v) => Ok(v.clone()),
            CertificateInput::File(path) => fs::read(path).await,
        }
    }
}

impl std::fmt::Display for CertificateInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CertificateInput::Inline(v) => write!(f, "{}", String::from_utf8_lossy(v.as_slice())),
            CertificateInput::File(path) => write!(f, "file: {}", path.display()),
        }
    }
}

pub struct TlsConfig<'a> {
    pub accept_invalid_certs: bool,
    pub accept_invalid_hostnames: bool,
    pub hostname: &'a str,
    pub root_cert_path: Option<&'a CertificateInput>,
    pub client_cert_path: Option<&'a CertificateInput>,
    pub client_key_path: Option<&'a CertificateInput>,
}

pub async fn handshake<S, Ws>(
    socket: S,
    config: TlsConfig<'_>,
    with_socket: Ws,
) -> crate::Result<Ws::Output>
where
    S: Socket,
    Ws: WithSocket,
{
    #[cfg(feature = "_tls-native-tls")]
    return Ok(with_socket
        .with_socket(tls_native_tls::handshake(socket, config).await?)
        .await);

    #[cfg(all(feature = "_tls-rustls", not(feature = "_tls-native-tls")))]
    return Ok(with_socket
        .with_socket(tls_rustls::handshake(socket, config).await?)
        .await);

    #[cfg(not(any(feature = "_tls-native-tls", feature = "_tls-rustls")))]
    {
        drop((socket, config, with_socket));
        panic!("one of the `runtime-*-native-tls` or `runtime-*-rustls` features must be enabled")
    }
}

pub fn available() -> bool {
    cfg!(any(feature = "_tls-native-tls", feature = "_tls-rustls"))
}

pub fn error_if_unavailable() -> crate::Result<()> {
    if !available() {
        return Err(Error::tls(
            "TLS upgrade required by connect options \
                    but SQLx was built without TLS support enabled",
        ));
    }

    Ok(())
}
