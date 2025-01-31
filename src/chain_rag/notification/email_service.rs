use std::sync::Arc;
use tokio::sync::RwLock;
use serde::{Serialize, Deserialize};
use crate::error::error_system::SystemError;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailConfig {
    smtp_server: String,
    smtp_port: u16,
    username: String,
    password: String,
    from_address: String,
    security_level: SecurityLevel,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecurityLevel {
    TLS,
    STARTTLS,
    None,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailMessage {
    to: Vec<String>,
    subject: String,
    body: String,
    priority: EmailPriority,
    attachments: Vec<EmailAttachment>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EmailPriority {
    Critical,
    High,
    Normal,
    Low,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailAttachment {
    name: String,
    content_type: String,
    data: Vec<u8>,
}

#[derive(Debug)]
pub struct EmailService {
    config: Arc<RwLock<EmailConfig>>,
    primary_client: Arc<EmailClient>,
    backup_client: Arc<EmailClient>,
    retry_config: RetryConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryConfig {
    max_retries: u32,
    retry_delay: u64,
    failover_threshold: u32,
}

impl EmailService {
    pub async fn new(
        primary_config: EmailConfig,
        backup_config: EmailConfig,
        retry_config: RetryConfig
    ) -> Result<Self, SystemError> {
        let primary_client = EmailClient::new(&primary_config).await?;
        let backup_client = EmailClient::new(&backup_config).await?;
        
        Ok(Self {
            config: Arc::new(RwLock::new(primary_config)),
            primary_client: Arc::new(primary_client),
            backup_client: Arc::new(backup_client),
            retry_config,
        })
    }

    pub async fn send_critical_notification(
        &self,
        subject: &str,
        message: &str,
        attachments: Option<Vec<EmailAttachment>>,
    ) -> Result<(), SystemError> {
        let config = self.config.read().await;
        
        let email = EmailMessage {
            to: vec![config.from_address.clone()], // Send to admin
            subject: format!("CRITICAL: {}", subject),
            body: message.to_string(),
            priority: EmailPriority::Critical,
            attachments: attachments.unwrap_or_default(),
        };

        self.send_email(email).await
    }

    pub async fn send_security_alert(
        &self,
        alert_type: &str,
        details: &str,
        attachments: Option<Vec<EmailAttachment>>,
    ) -> Result<(), SystemError> {
        let config = self.config.read().await;
        
        let email = EmailMessage {
            to: vec![config.from_address.clone()],
            subject: format!("Security Alert: {}", alert_type),
            body: details.to_string(),
            priority: EmailPriority::High,
            attachments: attachments.unwrap_or_default(),
        };

        self.send_email(email).await
    }

    pub async fn send_performance_warning(
        &self,
        warning_type: &str,
        details: &str,
    ) -> Result<(), SystemError> {
        let config = self.config.read().await;
        
        let email = EmailMessage {
            to: vec![config.from_address.clone()],
            subject: format!("Performance Warning: {}", warning_type),
            body: details.to_string(),
            priority: EmailPriority::Normal,
            attachments: vec![],
        };

        self.send_email(email).await
    }

    pub async fn send_email(&self, email: EmailMessage) -> Result<(), SystemError> {
        self.validate_email(&email).await?;
        
        let mut retries = 0;
        let mut use_backup = false;
        
        loop {
            let result = if !use_backup {
                self.primary_client.send(email.clone()).await
            } else {
                self.backup_client.send(email.clone()).await
            };

            match result {
                Ok(_) => return Ok(()),
                Err(e) => {
                    retries += 1;
                    if retries >= self.retry_config.max_retries {
                        if !use_backup {
                            use_backup = true;
                            retries = 0;
                            continue;
                        }
                        return Err(e);
                    }
                    tokio::time::sleep(
                        std::time::Duration::from_millis(self.retry_config.retry_delay)
                    ).await;
                }
            }
        }
    }

    async fn validate_email(&self, email: &EmailMessage) -> Result<(), SystemError> {
        // Check recipients
        if email.to.is_empty() {
            return Err(SystemError::EmailError("No recipients specified".into()));
        }

        // Validate email addresses
        for address in &email.to {
            if !self.is_valid_email(address) {
                return Err(SystemError::EmailError(
                    format!("Invalid email address: {}", address)
                ));
            }
        }

        // Check content
        if email.subject.is_empty() {
            return Err(SystemError::EmailError("Empty subject".into()));
        }
        if email.body.is_empty() {
            return Err(SystemError::EmailError("Empty body".into()));
        }

        // Validate attachments
        for attachment in &email.attachments {
            if attachment.data.is_empty() {
                return Err(SystemError::EmailError(
                    format!("Empty attachment: {}", attachment.name)
                ));
            }
        }

        Ok(())
    }

    fn is_valid_email(&self, email: &str) -> bool {
        // Basic email validation
        email.contains('@') && email.contains('.')
    }
}

#[derive(Debug)]
struct EmailClient {
    config: EmailConfig,
    failures: Arc<RwLock<FailureMetrics>>,
}

#[derive(Debug, Default)]
struct FailureMetrics {
    consecutive_failures: u32,
    last_failure: Option<chrono::DateTime<chrono::Utc>>,
    total_failures: u64,
}

impl EmailClient {
    async fn new(config: &EmailConfig) -> Result<Self, SystemError> {
        Ok(Self {
            config: config.clone(),
            failures: Arc::new(RwLock::new(FailureMetrics::default())),
        })
    }

    async fn send(&self, email: EmailMessage) -> Result<(), SystemError> {
        match self.attempt_send(&email).await {
            Ok(_) => {
                // Reset failure metrics on success
                let mut metrics = self.failures.write().await;
                metrics.consecutive_failures = 0;
                Ok(())
            }
            Err(e) => {
                // Update failure metrics
                let mut metrics = self.failures.write().await;
                metrics.consecutive_failures += 1;
                metrics.total_failures += 1;
                metrics.last_failure = Some(chrono::Utc::now());
                Err(e)
            }
        }
    }

    async fn attempt_send(&self, email: &EmailMessage) -> Result<(), SystemError> {
        // Actual SMTP implementation would go here
        // For now, just log the attempt
        tracing::info!(
            "Attempting to send email via {}: subject={}, priority={:?}, recipients={}",
            self.config.smtp_server,
            email.subject,
            email.priority,
            email.to.join(", ")
        );
        
        Ok(())
    }

    async fn is_healthy(&self) -> bool {
        let metrics = self.failures.read().await;
        metrics.consecutive_failures < 3
    }
}

// Integration with CoRAG
impl CoRAG {
    pub async fn send_notification(
        &self,
        subject: &str,
        message: &str,
        priority: EmailPriority,
    ) -> Result<(), SystemError> {
        let email = EmailMessage {
            to: vec![self.config.admin_email.clone()],
            subject: subject.to_string(),
            body: message.to_string(),
            priority,
            attachments: vec![],
        };

        self.email_service.send_email(email).await
    }

    pub async fn handle_system_event(&self, event: SystemEvent) -> Result<(), SystemError> {
        match event {
            SystemEvent::Critical(msg) => {
                self.send_notification(
                    "Critical System Event",
                    &msg,
                    EmailPriority::Critical
                ).await?;
            },
            SystemEvent::SecurityAlert(alert) => {
                self.send_notification(
                    "Security Alert",
                    &format!("Security alert: {:?}", alert),
                    EmailPriority::High
                ).await?;
            },
            // ... handle other events ...
        }
        Ok(())
    }
}
