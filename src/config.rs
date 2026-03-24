use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScannerConfig {
    pub agent_name: String,
    pub skills_dir: String,
    pub config_path: String,
    pub guardrails_dir: Option<String>,
    pub scan_interval_secs: u64,
    pub store_url: Option<String>,
    pub webhook_url: Option<String>,
    pub listen_port: u16,
    #[serde(default)]
    pub frameworks: Vec<String>,
}

impl Default for ScannerConfig {
    fn default() -> Self {
        Self {
            agent_name: "openclaw".into(),
            skills_dir: "/opt/openclaw/skills".into(),
            config_path: "/opt/openclaw/config.json".into(),
            guardrails_dir: None,
            scan_interval_secs: 300,
            store_url: None,
            webhook_url: None,
            listen_port: 9090,
            frameworks: vec![],
        }
    }
}
