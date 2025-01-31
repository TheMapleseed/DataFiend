use wasm_bindgen::prelude::*;
use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc, Duration};
use std::sync::Arc;

#[derive(Serialize, Deserialize)]
pub enum Command {
    Query(QueryCommand),
    Export(ExportCommand),
    Analyze(AnalyzeCommand),
    System(SystemCommand),
}

#[derive(Serialize, Deserialize)]
pub enum QueryCommand {
    ErrorHistory {
        start_time: Option<DateTime<Utc>>,
        end_time: Option<DateTime<Utc>>,
        error_type: Option<String>,
        severity: Option<String>,
        limit: Option<usize>,
    },
    Pattern {
        timeframe: Duration,
        min_occurrences: u32,
    },
    Statistics {
        group_by: String,
        metric: String,
    },
}

#[wasm_bindgen]
pub struct CommandInterface {
    error_map: Arc<ErrorHeatmap>,
    history: Arc<ErrorHistory>,
    metrics: Arc<MetricsStore>,
}

#[wasm_bindgen]
impl CommandInterface {
    #[wasm_bindgen(constructor)]
    pub fn new(
        error_map: Arc<ErrorHeatmap>,
        history: Arc<ErrorHistory>,
        metrics: Arc<MetricsStore>,
    ) -> Self {
        Self {
            error_map,
            history,
            metrics,
        }
    }

    #[wasm_bindgen]
    pub fn execute_command(&self, command_str: &str) -> Result<JsValue, JsValue> {
        let command = self.parse_command(command_str)?;
        
        match command {
            Command::Query(query) => self.handle_query(query),
            Command::Export(export) => self.handle_export(export),
            Command::Analyze(analyze) => self.handle_analyze(analyze),
            Command::System(system) => self.handle_system(system),
        }
    }

    fn handle_query(&self, query: QueryCommand) -> Result<JsValue, JsValue> {
        match query {
            QueryCommand::ErrorHistory { 
                start_time, 
                end_time, 
                error_type, 
                severity,
                limit 
            } => {
                let results = self.history.query(
                    start_time.unwrap_or_else(|| Utc::now() - Duration::hours(24)),
                    end_time.unwrap_or_else(|| Utc::now()),
                    error_type.as_deref(),
                    severity.as_deref(),
                    limit.unwrap_or(100)
                ).await?;

                Ok(serde_wasm_bindgen::to_value(&results)?)
            },
            QueryCommand::Pattern { timeframe, min_occurrences } => {
                let patterns = self.history.find_patterns(timeframe, min_occurrences).await?;
                Ok(serde_wasm_bindgen::to_value(&patterns)?)
            },
            QueryCommand::Statistics { group_by, metric } => {
                let stats = self.metrics.get_statistics(&group_by, &metric).await?;
                Ok(serde_wasm_bindgen::to_value(&stats)?)
            }
        }
    }

    #[wasm_bindgen]
    pub fn get_command_suggestions(&self, partial_command: &str) -> Result<JsValue, JsValue> {
        let suggestions = self.suggest_commands(partial_command);
        Ok(serde_wasm_bindgen::to_value(&suggestions)?)
    }

    fn suggest_commands(&self, partial: &str) -> Vec<String> {
        let commands = vec![
            "query errors",
            "query patterns",
            "query stats",
            "export csv",
            "export json",
            "analyze trends",
            "analyze correlations",
            "system status",
            "system refresh",
        ];

        commands.into_iter()
            .filter(|cmd| cmd.starts_with(partial))
            .map(String::from)
            .collect()
    }

    fn parse_command(&self, cmd_str: &str) -> Result<Command, JsValue> {
        let parts: Vec<&str> = cmd_str.split_whitespace().collect();
        if parts.is_empty() {
            return Err(JsValue::from_str("Empty command"));
        }

        match parts[0] {
            "query" => self.parse_query_command(&parts[1..]),
            "export" => self.parse_export_command(&parts[1..]),
            "analyze" => self.parse_analyze_command(&parts[1..]),
            "system" => self.parse_system_command(&parts[1..]),
            _ => Err(JsValue::from_str("Unknown command")),
        }
    }

    #[wasm_bindgen]
    pub fn get_command_help(&self, command: Option<String>) -> String {
        match command.as_deref() {
            Some("query") => r#"
                Query Commands:
                query errors [--from <time>] [--to <time>] [--type <error_type>] [--severity <level>] [--limit <n>]
                query patterns [--timeframe <duration>] [--min-occurrences <n>]
                query stats [--group-by <field>] [--metric <name>]
            "#.to_string(),
            Some("export") => r#"
                Export Commands:
                export csv [--from <time>] [--to <time>] [--fields <field1,field2,...>]
                export json [--pretty] [--fields <field1,field2,...>]
            "#.to_string(),
            // ... more command help
            None => "Available commands: query, export, analyze, system\nUse 'help <command>' for detailed help.".to_string(),
            _ => "Unknown command".to_string(),
        }
    }
} 