use wasm_bindgen::prelude::*;
use std::sync::Arc;
use tokio::sync::RwLock;
use chrono::{DateTime, Utc, Duration};
use serde::{Serialize, Deserialize};
use dashmap::DashMap;
use lettre::{
    transport::smtp::authentication::Credentials,
    AsyncSmtpTransport, AsyncTransport, Tokio1Executor, Message,
};

const RETENTION_DAYS: i64 = 90;
const MAX_BATCH_SIZE: usize = 1000;
const EMAIL_RETRY_ATTEMPTS: u32 = 3;

#[derive(Clone, Serialize, Deserialize)]
pub struct LogConfig {
    email: String,
    smtp_server: String,
    smtp_port: u16,
    smtp_username: String,
    smtp_password: String,
    export_frequency_hours: u32,
    alert_on_critical: bool,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ErrorLog {
    timestamp: DateTime<Utc>,
    level: ErrorLevel,
    message: String,
    context: HashMap<String, String>,
    stack_trace: Option<String>,
    exported: bool,
}

#[derive(Clone, Serialize, Deserialize, PartialEq)]
pub enum ErrorLevel {
    Critical,
    Error,
    Warning,
}

#[wasm_bindgen]
pub struct ErrorLogger {
    logs: Arc<DashMap<String, Vec<ErrorLog>>>,
    config: Arc<RwLock<LogConfig>>,
    email_transport: Arc<RwLock<Option<AsyncSmtpTransport<Tokio1Executor>>>>,
}

#[wasm_bindgen]
impl ErrorLogger {
    #[wasm_bindgen(constructor)]
    pub fn new(initial_config: JsValue) -> Result<ErrorLogger, JsValue> {
        let config: LogConfig = serde_wasm_bindgen::from_value(initial_config)?;
        let logger = ErrorLogger {
            logs: Arc::new(DashMap::new()),
            config: Arc::new(RwLock::new(config.clone())),
            email_transport: Arc::new(RwLock::new(None)),
        };

        logger.initialize_email_transport().await?;
        logger.start_maintenance_tasks();
        Ok(logger)
    }

    async fn initialize_email_transport(&self) -> Result<(), JsValue> {
        let config = self.config.read().await;
        let creds = Credentials::new(
            config.smtp_username.clone(),
            config.smtp_password.clone(),
        );

        let transport = AsyncSmtpTransport::<Tokio1Executor>::relay(&config.smtp_server)
            .map_err(|e| JsValue::from_str(&format!("SMTP setup error: {}", e)))?
            .port(config.smtp_port)
            .credentials(creds)
            .build();

        *self.email_transport.write().await = Some(transport);
        Ok(())
    }

    #[wasm_bindgen]
    pub async fn update_config(&self, new_config: JsValue) -> Result<(), JsValue> {
        let config: LogConfig = serde_wasm_bindgen::from_value(new_config)?;
        *self.config.write().await = config;
        self.initialize_email_transport().await
    }

    #[wasm_bindgen]
    pub async fn log_error(
        &self,
        namespace: String,
        level: String,
        message: String,
        context: JsValue,
        stack_trace: Option<String>,
    ) -> Result<(), JsValue> {
        let level = match level.to_lowercase().as_str() {
            "critical" => ErrorLevel::Critical,
            "error" => ErrorLevel::Error,
            "warning" => ErrorLevel::Warning,
            _ => return Err(JsValue::from_str("Invalid error level")),
        };

        let context: HashMap<String, String> = serde_wasm_bindgen::from_value(context)?;
        let timestamp = Utc::now();

        let log = ErrorLog {
            timestamp,
            level: level.clone(),
            message,
            context,
            stack_trace,
            exported: false,
        };

        // Store the log
        self.logs
            .entry(namespace.clone())
            .or_default()
            .push(log.clone());

        // Send immediate alert for critical errors if configured
        if level == ErrorLevel::Critical {
            let config = self.config.read().await;
            if config.alert_on_critical {
                self.send_error_email(&[log], "Critical Error Alert").await?;
            }
        }

        Ok(())
    }

    async fn send_error_email(
        &self,
        logs: &[ErrorLog],
        subject: &str,
    ) -> Result<(), JsValue> {
        let config = self.config.read().await;
        let transport = self.email_transport.read().await;

        if let Some(transport) = transport.as_ref() {
            let email_body = self.format_email_body(logs);
            
            let email = Message::builder()
                .from("error-logger@system.internal".parse().unwrap())
                .to(config.email.parse().unwrap())
                .subject(subject)
                .body(email_body)
                .map_err(|e| JsValue::from_str(&format!("Email creation error: {}", e)))?;

            for attempt in 0..EMAIL_RETRY_ATTEMPTS {
                match transport.send(email.clone()).await {
                    Ok(_) => return Ok(()),
                    Err(e) if attempt < EMAIL_RETRY_ATTEMPTS - 1 => {
                        tokio::time::sleep(std::time::Duration::from_secs(5 * (attempt + 1) as u64)).await;
                    },
                    Err(e) => return Err(JsValue::from_str(&format!("Email send error: {}", e))),
                }
            }
        }
        Ok(())
    }

    fn format_email_body(&self, logs: &[ErrorLog]) -> String {
        let mut body = String::from("Error Log Export\n\n");
        
        for log in logs {
            body.push_str(&format!(
                "Timestamp: {}\nLevel: {:?}\nMessage: {}\nContext: {:?}\n",
                log.timestamp, log.level, log.message, log.context
            ));
            
            if let Some(stack) = &log.stack_trace {
                body.push_str(&format!("Stack Trace:\n{}\n", stack));
            }
            
            body.push_str("\n---\n\n");
        }
        
        body
    }

    fn start_maintenance_tasks(&self) {
        let logger = Arc::new(self.clone());
        
        // Cleanup task
        tokio::spawn({
            let logger = logger.clone();
            async move {
                let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600 * 24)); // Daily
                loop {
                    interval.tick().await;
                    if let Err(e) = logger.cleanup_old_logs().await {
                        web_sys::console::error_1(&e);
                    }
                }
            }
        });

        // Export task
        tokio::spawn({
            let logger = logger.clone();
            async move {
                loop {
                    let export_interval = {
                        let config = logger.config.read().await;
                        std::time::Duration::from_secs(3600 * config.export_frequency_hours as u64)
                    };
                    tokio::time::sleep(export_interval).await;
                    
                    if let Err(e) = logger.export_logs().await {
                        web_sys::console::error_1(&e);
                    }
                }
            }
        });
    }

    async fn cleanup_old_logs(&self) -> Result<(), JsValue> {
        let cutoff = Utc::now() - Duration::days(RETENTION_DAYS);
        
        for mut namespace_logs in self.logs.iter_mut() {
            namespace_logs.retain(|log| log.timestamp > cutoff);
        }
        
        Ok(())
    }

    async fn export_logs(&self) -> Result<(), JsValue> {
        for namespace_logs in self.logs.iter_mut() {
            let unexported: Vec<ErrorLog> = namespace_logs
                .iter()
                .filter(|log| !log.exported)
                .cloned()
                .collect();

            // Export in batches
            for chunk in unexported.chunks(MAX_BATCH_SIZE) {
                self.send_error_email(
                    chunk,
                    &format!("Error Log Export - {}", namespace_logs.key())
                ).await?;

                // Mark as exported
                for log in chunk {
                    if let Some(entry) = namespace_logs.iter_mut().find(|l| 
                        l.timestamp == log.timestamp && 
                        l.message == log.message
                    ) {
                        entry.exported = true;
                    }
                }
            }
        }
        
        Ok(())
    }

    #[wasm_bindgen]
    pub fn get_logs(
        &self,
        namespace: String,
        start_date: Option<String>,
        end_date: Option<String>,
        level: Option<String>,
    ) -> Result<JsValue, JsValue> {
        let start = start_date
            .and_then(|d| DateTime::parse_from_rfc3339(&d).ok())
            .map(|d| d.with_timezone(&Utc))
            .unwrap_or_else(|| Utc::now() - Duration::days(RETENTION_DAYS));

        let end = end_date
            .and_then(|d| DateTime::parse_from_rfc3339(&d).ok())
            .map(|d| d.with_timezone(&Utc))
            .unwrap_or_else(|| Utc::now());

        let level_filter = level.map(|l| match l.to_lowercase().as_str() {
            "critical" => ErrorLevel::Critical,
            "error" => ErrorLevel::Error,
            "warning" => ErrorLevel::Warning,
            _ => ErrorLevel::Warning,
        });

        if let Some(logs) = self.logs.get(&namespace) {
            let filtered: Vec<&ErrorLog> = logs
                .iter()
                .filter(|log| {
                    log.timestamp >= start &&
                    log.timestamp <= end &&
                    level_filter.as_ref().map_or(true, |l| l == &log.level)
                })
                .collect();

            Ok(serde_wasm_bindgen::to_value(&filtered)?)
        } else {
            Ok(serde_wasm_bindgen::to_value(&Vec::<ErrorLog>::new())?)
        }
    }
}

impl Drop for ErrorLogger {
    fn drop(&mut self) {
        self.logs.clear();
    }
}
