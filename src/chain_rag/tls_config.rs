// Updated TLS constants
const TLS_VERSION: rustls::ProtocolVersion = rustls::ProtocolVersion::TLSv1_3;
const ALLOWED_CIPHER_SUITES: &[rustls::CipherSuite] = &[
    rustls::CipherSuite::TLS13_AES_256_GCM_SHA384,
    rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
];

pub struct TlsManager {
    server_config: Arc<RwLock<ServerConfig>>,
    client_config: Arc<RwLock<ClientConfig>>,
    cert_path: PathBuf,
    key_path: PathBuf,
    client_ca_path: Option<PathBuf>,  // Added for mTLS
    client_cert_path: Option<PathBuf>, // Added for mTLS client auth
    client_key_path: Option<PathBuf>,  // Added for mTLS client auth
    metrics: Arc<MetricsStore>,
    error_handler: Arc<ErrorHandler>,
}

impl TlsManager {
    pub async fn new_with_mtls(
        cert_path: PathBuf,
        key_path: PathBuf,
        client_ca_path: PathBuf,      // CA for validating client certs
        client_cert_path: PathBuf,    // Client cert for outbound connections
        client_key_path: PathBuf,     // Client key for outbound connections
        metrics: Arc<MetricsStore>,
        error_handler: Arc<ErrorHandler>,
    ) -> Result<Self, TlsError> {
        let manager = Self {
            server_config: Arc::new(RwLock::new(ServerConfig::builder()
                .with_safe_defaults()
                .with_client_cert_verifier(Arc::new(
                    rustls::server::AllowAnyAuthenticatedClient::new(
                        Self::load_trust_store(&client_ca_path)?
                    )
                ))
                .with_single_cert(vec![], vec![].into())
                .map_err(|e| TlsError::Config(e.to_string()))?)),
            client_config: Arc::new(RwLock::new(ClientConfig::builder()
                .with_safe_defaults()
                .with_root_certificates(rustls::RootCertStore::empty())
                .with_single_cert(vec![], vec![].into())
                .map_err(|e| TlsError::Config(e.to_string()))?)),
            cert_path,
            key_path,
            client_ca_path: Some(client_ca_path),
            client_cert_path: Some(client_cert_path),
            client_key_path: Some(client_key_path),
            metrics,
            error_handler,
        };
        
        manager.load_certificates().await?;
        manager.configure_server_mtls().await?;
        manager.configure_client_mtls().await?;
        
        Ok(manager)
    }

    async fn configure_server_mtls(&self) -> Result<(), TlsError> {
        let mut config = self.server_config.write().await;
        
        // Force TLS 1.3 only
        config.versions = vec![TLS_VERSION];
        
        // Restrict cipher suites to most secure TLS 1.3 options
        config.cipher_suites = ALLOWED_CIPHER_SUITES.to_vec();
        
        // Configure session cache
        config.session_storage = ServerSessionMemoryCache::new(SESSION_CACHE_CAPACITY);
        
        // Configure ticket lifetime
        config.ticketer = rustls::Ticketer::new()
            .map_err(|e| TlsError::Config(e.to_string()))?;
            
        // Set ALPN protocols
        config.alpn_protocols = ALPN_PROTOCOLS.iter()
            .map(|p| p.to_vec())
            .collect();
            
        // Set maximum fragment size
        config.max_fragment_size = Some(MAX_FRAGMENT_SIZE);

        // Require client authentication if CA path is set
        if let Some(ca_path) = &self.client_ca_path {
            let client_auth = rustls::server::AllowAnyAuthenticatedClient::new(
                Self::load_trust_store(ca_path)?
            );
            config.client_cert_verifier = Some(Arc::new(client_auth));
        }
        
        self.metrics.record_server_configured().await;
        Ok(())
    }

    async fn configure_client_mtls(&self) -> Result<(), TlsError> {
        let mut config = self.client_config.write().await;
        
        // Force TLS 1.3 only
        config.versions = vec![TLS_VERSION];
        
        // Restrict cipher suites to most secure TLS 1.3 options
        config.cipher_suites = ALLOWED_CIPHER_SUITES.to_vec();
        
        // Configure root certificates
        let mut root_store = rustls::RootCertStore::empty();
        root_store.add_server_trust_anchors(
            webpki_roots::TLS_SERVER_ROOTS
                .0
                .iter()
                .map(|ta| {
                    rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
                        ta.subject,
                        ta.spki,
                        ta.name_constraints,
                    )
                })
        );
        
        config.root_store = root_store;
        
        // Load client certificate and key if paths are set
        if let (Some(cert_path), Some(key_path)) = (&self.client_cert_path, &self.client_key_path) {
            let cert_chain = Self::load_certificates(cert_path)?;
            let key = Self::load_private_key(key_path)?;
            config.set_single_client_cert(cert_chain, key)
                .map_err(|e| TlsError::Config(e.to_string()))?;
        }
        
        // Configure ALPN
        config.alpn_protocols = ALPN_PROTOCOLS.iter()
            .map(|p| p.to_vec())
            .collect();
            
        // Enable SNI
        config.enable_sni = true;
        
        // Configure session cache
        config.session_storage = Arc::new(rustls::client::ServerSessionMemoryCache::new(SESSION_CACHE_CAPACITY));
        
        self.metrics.record_client_configured().await;
        Ok(())
    }

    fn load_trust_store(path: &Path) -> Result<rustls::RootCertStore, TlsError> {
        let mut store = rustls::RootCertStore::empty();
        let cert_file = File::open(path)?;
        let mut reader = BufReader::new(cert_file);
        
        let certs = rustls_pemfile::certs(&mut reader)
            .map_err(|e| TlsError::Certificate(e.to_string()))?;
            
        for cert in certs {
            store.add(&rustls::Certificate(cert))
                .map_err(|e| TlsError::Certificate(e.to_string()))?;
        }
        
        Ok(store)
    }

    // ... rest of the implementation ...
} 