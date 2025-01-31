use std::sync::Arc;
use tokio::sync::RwLock;
use wasmtime::{Engine, Store, Module, Instance};

pub struct UnifiedVMSystem {
    // Single Firecracker VM containing everything
    database: Arc<DatabaseInstance>,
    model_system: Arc<ModelSystem>,
    wasm_frontend: Arc<WasmInterface>,
    secure_client: Arc<RwLock<SecureClientConnection>>,
    metrics: Arc<MetricsStore>,
}

struct SecureClientConnection {
    client_cert: Certificate,
    vsock_channel: VsockStream,
    session_key: [u8; 32],
}

struct WasmInterface {
    engine: Engine,
    store: Store<()>,
    instance: Instance,
    // Bridges WASM to both DB and Model
    db_bridge: DatabaseBridge,
    model_bridge: ModelBridge,
}

struct DatabaseInstance {
    storage: Arc<RwLock<StorageEngine>>,
    query_engine: QueryEngine,
    // Direct connection to model system
    model_interface: ModelInterface,
}

struct ModelSystem {
    models: Vec<Box<dyn Model>>,
    // Direct connection to database
    db_interface: DatabaseInterface,
    // Training and inference state
    state: Arc<RwLock<ModelState>>,
}

impl UnifiedVMSystem {
    pub async fn new(cert: Certificate) -> Result<Self> {
        // Initialize everything within the same VM space
        let database = DatabaseInstance::new();
        let model_system = ModelSystem::new(&database);
        
        // Setup secure client connection
        let secure_client = SecureClientConnection::new(cert);
        
        // Initialize WASM frontend
        let wasm_frontend = WasmInterface::new(&database, &model_system);

        Ok(Self {
            database: Arc::new(database),
            model_system: Arc::new(model_system),
            wasm_frontend: Arc::new(wasm_frontend),
            secure_client: Arc::new(RwLock::new(secure_client)),
            metrics: Arc::new(MetricsStore::new()?),
        })
    }

    pub async fn handle_client_request(&self, request: ClientRequest) -> Result<Response> {
        // Verify client certificate
        let client = self.secure_client.read().await;
        if !client.verify_cert() {
            return Err(Error::Unauthorized);
        }

        match request {
            ClientRequest::ModelOperation(op) => {
                self.model_system.handle_operation(op).await
            }
            ClientRequest::DatabaseQuery(query) => {
                self.database.handle_query(query).await
            }
            ClientRequest::WasmCall(call) => {
                self.wasm_frontend.handle_call(call).await
            }
        }
    }
}

impl SecureClientConnection {
    fn new(cert: Certificate) -> Self {
        // Setup secure vsock channel with certificate authentication
        let vsock = VsockStream::connect(VSOCK_CID, VSOCK_PORT).unwrap();
        
        Self {
            client_cert: cert,
            vsock_channel: vsock,
            session_key: generate_session_key(),
        }
    }

    fn verify_cert(&self) -> bool {
        // Verify client certificate against trusted CA
        self.client_cert.verify()
    }
}

impl ModelSystem {
    fn new(db: &DatabaseInstance) -> Self {
        // Initialize models with direct database access
        let db_interface = DatabaseInterface::new(db);
        
        Self {
            models: load_models(),
            db_interface,
            state: Arc::new(RwLock::new(ModelState::new())),
        }
    }

    async fn handle_operation(&self, op: ModelOperation) -> Result<Response> {
        // Direct model operations with database access
        match op {
            ModelOperation::Train(data) => {
                self.train_with_db_access(data).await
            }
            ModelOperation::Infer(input) => {
                self.infer_with_db_access(input).await
            }
        }
    }
} 