use wasm_bindgen::prelude::*;
use serde::{Serialize, Deserialize};
use std::sync::Arc;

#[wasm_bindgen]
#[derive(Serialize, Deserialize)]
pub struct WebInterface {
    system_control: Arc<SystemControl>,
    theme: Arc<RwLock<Theme>>,
    layout: Arc<RwLock<Layout>>,
}

#[derive(Serialize, Deserialize)]
struct Theme {
    dark_mode: bool,
    primary_color: String,
    background_color: String,
    text_color: String,
}

#[derive(Serialize, Deserialize)]
struct Layout {
    sidebar_visible: bool,
    active_dashboard: String,
    panels: Vec<Panel>,
}

#[derive(Serialize, Deserialize)]
struct Panel {
    id: String,
    panel_type: PanelType,
    title: String,
    position: Position,
    config: serde_json::Value,
}

#[derive(Serialize, Deserialize)]
enum PanelType {
    Metrics,
    Graph,
    Table,
    Logs,
    Controls,
    Status,
}

#[wasm_bindgen]
impl WebInterface {
    #[wasm_bindgen(constructor)]
    pub fn new(system_control: Arc<SystemControl>) -> Self {
        Self {
            system_control,
            theme: Arc::new(RwLock::new(Theme::default())),
            layout: Arc::new(RwLock::new(Layout::default())),
        }
    }

    #[wasm_bindgen]
    pub async fn initialize_login_page(&self) -> Result<JsValue, JsValue> {
        let login_config = LoginPageConfig {
            title: "Chain RAG System",
            logo_url: "/assets/logo.svg",
            background_color: self.theme.read().await.background_color.clone(),
            form_fields: vec![
                FormField {
                    name: "password",
                    field_type: "password",
                    placeholder: "Enter admin password",
                    required: true,
                }
            ],
        };

        Ok(serde_wasm_bindgen::to_value(&login_config)?)
    }

    #[wasm_bindgen]
    pub async fn login(&self, password: &str) -> Result<JsValue, JsValue> {
        // Login via system control
        let session = self.system_control.login(password).await?;

        // Initialize default dashboard layout
        self.initialize_dashboard_layout().await?;

        Ok(session)
    }

    #[wasm_bindgen]
    pub async fn get_dashboard_config(&self, session_id: &str) -> Result<JsValue, JsValue> {
        self.system_control.verify_session(session_id).await?;

        let dashboard_config = DashboardConfig {
            layout: (*self.layout.read().await).clone(),
            theme: (*self.theme.read().await).clone(),
            available_panels: vec![
                PanelConfig {
                    type_name: "metrics",
                    title: "System Metrics",
                    description: "Real-time system metrics and statistics",
                    icon: "chart-line",
                },
                PanelConfig {
                    type_name: "controls",
                    title: "System Controls",
                    description: "System management and control interface",
                    icon: "sliders",
                },
                // Add other available panels...
            ],
        };

        Ok(serde_wasm_bindgen::to_value(&dashboard_config)?)
    }

    #[wasm_bindgen]
    pub async fn update_panel_data(&self, session_id: &str, panel_id: &str) -> Result<JsValue, JsValue> {
        self.system_control.verify_session(session_id).await?;

        let panel = self.get_panel(panel_id).await?;
        let data = match panel.panel_type {
            PanelType::Metrics => {
                self.system_control.access_interface(session_id, "Metrics").await?
            },
            PanelType::Controls => {
                self.system_control.access_interface(session_id, "Controls").await?
            },
            // Handle other panel types...
        };

        Ok(data)
    }

    #[wasm_bindgen]
    pub async fn toggle_theme(&self, session_id: &str) -> Result<(), JsValue> {
        self.system_control.verify_session(session_id).await?;
        
        let mut theme = self.theme.write().await;
        theme.dark_mode = !theme.dark_mode;
        theme.update_colors();
        
        Ok(())
    }
}

impl Theme {
    fn default() -> Self {
        Self {
            dark_mode: true,
            primary_color: "#3D7EF8".to_string(),
            background_color: "#0B0F19".to_string(),
            text_color: "#D8D9DA".to_string(),
        }
    }

    fn update_colors(&mut self) {
        if self.dark_mode {
            self.background_color = "#0B0F19".to_string();
            self.text_color = "#D8D9DA".to_string();
        } else {
            self.background_color = "#F7F8FA".to_string();
            self.text_color = "#222222".to_string();
        }
    }
} 