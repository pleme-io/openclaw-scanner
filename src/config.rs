use async_graphql::SimpleObject;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema, SimpleObject)]
pub struct ScannerConfig {
    pub agent_name: String,
    pub skills_dir: String,
    pub config_path: String,
    pub guardrails_dir: Option<String>,
    /// Path to the agent binary for `agent_binary` layer hashing.
    pub binary_path: Option<String>,
    /// Path/source for `agent_models` layer hashing.
    pub models_path: Option<String>,
    /// Path/source for `agent_runtime` layer hashing.
    pub runtime_path: Option<String>,
    /// Path/source for `agent_mcp_servers` layer hashing.
    pub mcp_servers_path: Option<String>,
    /// Path/source for `agent_dependencies` layer hashing (e.g. SBOM or lockfile).
    pub dependencies_path: Option<String>,
    /// Path/source for `agent_certificates` layer hashing.
    pub certificates_path: Option<String>,
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
            binary_path: None,
            models_path: None,
            runtime_path: None,
            mcp_servers_path: None,
            dependencies_path: None,
            certificates_path: None,
            scan_interval_secs: 300,
            store_url: None,
            webhook_url: None,
            listen_port: 9090,
            frameworks: vec![],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_has_sensible_values() {
        let config = ScannerConfig::default();
        assert_eq!(config.agent_name, "openclaw");
        assert_eq!(config.skills_dir, "/opt/openclaw/skills");
        assert_eq!(config.config_path, "/opt/openclaw/config.json");
        assert_eq!(config.scan_interval_secs, 300);
        assert_eq!(config.listen_port, 9090);
        assert!(config.guardrails_dir.is_none());
        assert!(config.binary_path.is_none());
        assert!(config.models_path.is_none());
        assert!(config.runtime_path.is_none());
        assert!(config.mcp_servers_path.is_none());
        assert!(config.dependencies_path.is_none());
        assert!(config.certificates_path.is_none());
        assert!(config.store_url.is_none());
        assert!(config.webhook_url.is_none());
        assert!(config.frameworks.is_empty());
    }

    #[test]
    fn config_serde_roundtrip() {
        let config = ScannerConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: ScannerConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.agent_name, config.agent_name);
        assert_eq!(deserialized.skills_dir, config.skills_dir);
        assert_eq!(deserialized.config_path, config.config_path);
        assert_eq!(deserialized.scan_interval_secs, config.scan_interval_secs);
        assert_eq!(deserialized.listen_port, config.listen_port);
        assert_eq!(deserialized.guardrails_dir, config.guardrails_dir);
        assert_eq!(deserialized.frameworks, config.frameworks);
    }

    #[test]
    fn config_with_all_optional_paths() {
        let config = ScannerConfig {
            guardrails_dir: Some("/opt/guardrails".into()),
            binary_path: Some("/usr/bin/agent".into()),
            models_path: Some("/opt/models".into()),
            runtime_path: Some("/opt/runtime".into()),
            mcp_servers_path: Some("/opt/mcp".into()),
            dependencies_path: Some("/opt/deps/lockfile".into()),
            certificates_path: Some("/opt/certs".into()),
            store_url: Some("https://store.example.com".into()),
            webhook_url: Some("https://hooks.example.com/alert".into()),
            frameworks: vec!["nist_800_53".into(), "soc2".into()],
            ..ScannerConfig::default()
        };
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: ScannerConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.guardrails_dir.as_deref(), Some("/opt/guardrails"));
        assert_eq!(deserialized.binary_path.as_deref(), Some("/usr/bin/agent"));
        assert_eq!(deserialized.models_path.as_deref(), Some("/opt/models"));
        assert_eq!(deserialized.runtime_path.as_deref(), Some("/opt/runtime"));
        assert_eq!(deserialized.mcp_servers_path.as_deref(), Some("/opt/mcp"));
        assert_eq!(deserialized.dependencies_path.as_deref(), Some("/opt/deps/lockfile"));
        assert_eq!(deserialized.certificates_path.as_deref(), Some("/opt/certs"));
        assert_eq!(deserialized.store_url.as_deref(), Some("https://store.example.com"));
        assert_eq!(deserialized.webhook_url.as_deref(), Some("https://hooks.example.com/alert"));
        assert_eq!(deserialized.frameworks, vec!["nist_800_53", "soc2"]);
    }

    #[test]
    fn config_schema_generation() {
        let schema = schemars::schema_for!(ScannerConfig);
        let json = serde_json::to_string_pretty(&schema).unwrap();
        assert!(json.contains("ScannerConfig"));
        assert!(json.contains("agent_name"));
        assert!(json.contains("skills_dir"));
        assert!(json.contains("scan_interval_secs"));
    }
}
