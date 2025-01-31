use std::path::PathBuf;
use tokio::process::Command;
use ssh2::Session;
use std::net::TcpStream;

pub struct DeployConfig {
    firecracker_config: FirecrackerConfig,
    remote_path: PathBuf,
    cert_path: PathBuf,
    remote_addr: String,
    remote_user: String,
}

#[derive(Debug)]
struct FirecrackerConfig {
    vcpu_count: u8,
    mem_size_mib: u32,
    kernel_image_path: PathBuf,
    root_drive_path: PathBuf,
}

impl DeployConfig {
    pub fn new(remote: &str, user: &str, cert: &str) -> Self {
        Self {
            firecracker_config: FirecrackerConfig::default(),
            remote_path: PathBuf::from("/var/lib/firecracker"),
            cert_path: PathBuf::from(cert),
            remote_addr: remote.to_string(),
            remote_user: user.to_string(),
        }
    }

    pub async fn deploy(&self) -> Result<()> {
        // Establish SSH connection
        let tcp = TcpStream::connect(&self.remote_addr)?;
        let mut sess = Session::new()?;
        sess.set_tcp_stream(tcp);
        sess.handshake()?;
        
        // Authenticate with certificate
        sess.userauth_pubkey_file(
            &self.remote_user,
            None,
            &self.cert_path,
            None
        )?;

        // Transfer system files
        self.transfer_files(&sess)?;
        
        // Configure and start Firecracker
        self.start_firecracker(&sess).await?;
        
        // Verify system is running
        self.verify_deployment(&sess).await?;
        
        Ok(())
    }

    async fn start_firecracker(&self, sess: &Session) -> Result<()> {
        let cmd = format!(
            "firecracker \
            --api-sock /tmp/firecracker.socket \
            --config-file {}/config.json",
            self.remote_path.display()
        );
        
        let mut channel = sess.channel_session()?;
        channel.exec(&cmd)?;
        
        // Wait for startup
        let mut buffer = String::new();
        channel.read_to_string(&mut buffer)?;
        
        if !buffer.contains("Starting instance") {
            return Err(Error::StartupFailed);
        }
        
        Ok(())
    }

    async fn transfer_files(&self, sess: &Session) -> Result<()> {
        let files = [
            "chain_rag",
            "config.json",
            "kernel",
            "rootfs.ext4"
        ];
        
        for file in files {
            let mut remote_file = sess.scp_send(
                &self.remote_path.join(file),
                0o644,
                0,
                None
            )?;
            
            let local_data = std::fs::read(file)?;
            remote_file.write_all(&local_data)?;
            
            // Proper resource cleanup
            remote_file.send_eof()?;
            remote_file.wait_eof()?;
            remote_file.close()?;
            remote_file.wait_close()?;
        }
        Ok(())
    }

    async fn verify_deployment(&self, sess: &Session) -> Result<()> {
        // Check system is responsive
        let mut channel = sess.channel_session()?;
        channel.exec("curl -s http://localhost:8000/health")?;
        
        let mut response = String::new();
        channel.read_to_string(&mut response)?;
        
        if !response.contains("\"status\":\"healthy\"") {
            return Err(Error::HealthCheckFailed);
        }
        
        Ok(())
    }
} 