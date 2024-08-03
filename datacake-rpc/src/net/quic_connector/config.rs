use std::fmt::Display;
use std::io;
use std::io::BufReader;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use quinn::{ClientConfig, ServerConfig};


#[derive(Debug, thiserror::Error)]
/// A error that prevented the system from reading and parsing a given pem file.
pub enum CreateCertStoreError {
    #[error("IO Error: {0}")]
    /// An IO error that occurred while attempting to read the perm file.
    Io(#[from] io::Error),
    #[error("Rustls Error: {0}")]
    /// A Rustls error the occurred when attempting to add a cert to the store.
    Rustls(#[from] rustls::Error),
}


#[derive(Clone, Debug)]
/// The QUIC client connect config.
///
/// Both insecure and secure (TLS) connections are supported.
pub enum ClientConnectConfig {
    /// The client will accept any server TLS configure, self-signed or otherwise.
    Insecure {
        /// The address the client should connect to.
        addr: SocketAddr,
    },
    /// The client will use full TLS configuration and expect valid server certificates.
    Secure {
        /// The address the client should connect to.
        addr: SocketAddr,
        /// The server name that will be present in the certificates.
        server_name: String,
        /// A set of TLS certificates to be added to the clients root store.
        certificates: rustls::RootCertStore,
    },
}

impl ClientConnectConfig {
    /// Create a new insecure client config
    ///
    /// **WARNING:**
    /// In this configuration the client will accept *any* certificate presented by
    /// the server, it is *always* valid. This should not be used in production.
    pub fn insecure(addr: SocketAddr) -> Self {
        Self::Insecure { addr }
    }

    /// Creates a new secure config using the given root certificate store.
    pub fn secure_with_store(
        addr: SocketAddr,
        server_name: impl Display,
        store: rustls::RootCertStore,
    ) -> Self {
        Self::Secure {
            addr,
            server_name: server_name.to_string(),
            certificates: store
        }
    }

    /// Attempt to create a new secure config using the given PEM file
    /// containing the file certificates.
    pub fn secure_from_pem(
        addr: SocketAddr,
        server_name: impl Display,
        file_path: impl AsRef<Path>,
    ) -> Result<Self, CreateCertStoreError> {
        let file = std::fs::File::open(file_path)?;
        let mut reader = BufReader::new(file);

        let mut store = rustls::RootCertStore::empty();
        for cert in rustls_pemfile::certs(&mut reader) {
            let cert = cert?;
            store.add(&rustls::Certificate(cert.to_vec()))?;
        }

        Ok(Self::secure_with_store(addr, server_name, store))
    }

    /// Attempt to create a new secure config using the OS native root store.
    ///
    /// If the `SSL_CERT_FILE` environment variable is set, certificates (in PEM format) are read
    /// from that file instead.
    /// This function fails in a platform-specific way, expressed in a [io::Error].
    /// This function can be expensive: on some platforms it involves loading and parsing
    /// a ~300KB disk file. It's therefore prudent to call this sparingly.
    pub fn secure_from_native_roots(addr: SocketAddr, server_name: impl Display) -> Result<Self, CreateCertStoreError> {
        let mut store = rustls::RootCertStore::empty();

        for item in rustls_native_certs::load_native_certs()? {
            store.add(&rustls::Certificate(item.to_vec()))?;
        }

        Ok(Self::secure_with_store(addr, server_name, store))
    }

    /// The socket address to connect to.
    pub fn connect_addr(&self) -> SocketAddr {
        match self {
            Self::Insecure { addr } => *addr,
            Self::Secure { addr, .. } => *addr,
        }
    }

    /// Returns the configured server name.
    pub(crate) fn server_name(&self) -> &str {
        match self {
            Self::Insecure { .. } => "localhost",
            Self::Secure { server_name, .. } => server_name.as_str(),
        }
    }

    /// Creates a new quinn client config using the configured crypto.
    pub(crate) fn client_config(&self) -> ClientConfig {
        match self {
            Self::Insecure { .. } => {
                let crypto = rustls::ClientConfig::builder()
                    .with_safe_defaults()
                    .with_custom_certificate_verifier(SkipServerVerification::new())
                    .with_no_client_auth();

                ClientConfig::new(Arc::new(crypto))
            },
            Self::Secure { certificates, .. } => {
                ClientConfig::with_root_certificates(certificates.clone())
            },
        }
    }
}


#[derive(Clone, Debug)]
/// The QUIC server listen config.
///
/// Both insecure and secure (TLS) connections are supported.
///
/// **NOTE:**
/// Insecure still involves the TLS pipeline, the server will just generate a new
/// self-signed certificate.
pub struct ServerListenConfig {
    /// The listen address for the server.
    addr: SocketAddr,

    /// The private key to be used.
    private_key: rustls::PrivateKey,

    /// A set of TLS certificates to be added to the server's certificate chain.
    certificates: Vec<rustls::Certificate>,
}

impl ServerListenConfig {
    /// Creates a new insecure server config.
    ///
    /// Internally this generates a self-signed certificate and assumes clients will
    /// accept it.
    pub fn insecure(listen_addr: SocketAddr) -> Self {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let private_key = rustls::PrivateKey(cert.serialize_private_key_der());
        let certificates = vec![rustls::Certificate(cert.serialize_der().unwrap())];

        Self::secure_with_certs_and_key(listen_addr, certificates, private_key)
    }

    /// Creates a new secure server config using the provided certs and private key.
    pub fn secure_with_certs_and_key(
        listen_addr: SocketAddr,
        certificates: Vec<rustls::Certificate>,
        private_key: rustls::PrivateKey,
    ) -> Self {
        Self {
            addr: listen_addr,
            certificates,
            private_key,
        }
    }

    /// Creates a new quinn server config using the configured crypto.
    pub(crate) fn server_config(&self) -> ServerConfig {
        ServerConfig::with_single_cert(self.certificates.clone(), self.private_key.clone())
            .expect("Create server config using validated config")
    }
}

struct SkipServerVerification;

impl SkipServerVerification {
    fn new() -> Arc<Self> {
        Arc::new(Self)
    }
}

impl rustls::client::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::Certificate,
        _intermediates: &[rustls::Certificate],
        _server_name: &rustls::ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: std::time::SystemTime,
    ) -> Result<rustls::client::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::ServerCertVerified::assertion())
    }
}