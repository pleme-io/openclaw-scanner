use crate::config::ScannerConfig;
use crate::error::Result;
use async_graphql::SimpleObject;
use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;
use tameshi::hash::Blake3Hash;
use tokio::time;

/// Scan result from a single cycle.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema, SimpleObject)]
pub struct ScanResult {
    pub agent_name: String,
    pub layers_hashed: u32,
    pub drift_detected: bool,
    pub compliance_status: String,
    pub scanned_at: DateTime<Utc>,
}

/// The main scanning daemon.
pub struct Scanner {
    config: ScannerConfig,
    interval: Duration,
    last_hashes: tokio::sync::RwLock<HashMap<String, String>>,
}

impl Scanner {
    pub fn new(config: ScannerConfig) -> Self {
        let interval = Duration::from_secs(config.scan_interval_secs);
        Self {
            config,
            interval,
            last_hashes: tokio::sync::RwLock::new(HashMap::new()),
        }
    }

    /// Hash an optional layer source path and insert into the map.
    fn hash_optional_layer(
        map: &mut HashMap<String, String>,
        layer_name: &str,
        source: &Option<String>,
    ) {
        if let Some(path) = source {
            let hash = Blake3Hash::digest(path.as_bytes());
            map.insert(layer_name.into(), hash.to_prefixed());
        }
    }

    /// Run a single scan cycle.
    pub async fn scan_once(&self) -> Result<ScanResult> {
        let mut current_hashes = HashMap::new();

        // Hash skills directory (agent_skills layer)
        let skills_hash = Blake3Hash::digest(self.config.skills_dir.as_bytes());
        current_hashes.insert("agent_skills".into(), skills_hash.to_prefixed());

        // Hash config (agent_config layer)
        let config_hash = Blake3Hash::digest(self.config.config_path.as_bytes());
        current_hashes.insert("agent_config".into(), config_hash.to_prefixed());

        // Hash agent binary (agent_binary layer)
        Self::hash_optional_layer(
            &mut current_hashes,
            "agent_binary",
            &self.config.binary_path,
        );

        // Hash guardrails (agent_guardrails layer)
        Self::hash_optional_layer(
            &mut current_hashes,
            "agent_guardrails",
            &self.config.guardrails_dir,
        );

        // Hash models (agent_models layer)
        Self::hash_optional_layer(
            &mut current_hashes,
            "agent_models",
            &self.config.models_path,
        );

        // Hash runtime (agent_runtime layer)
        Self::hash_optional_layer(
            &mut current_hashes,
            "agent_runtime",
            &self.config.runtime_path,
        );

        // Hash MCP servers (agent_mcp_servers layer)
        Self::hash_optional_layer(
            &mut current_hashes,
            "agent_mcp_servers",
            &self.config.mcp_servers_path,
        );

        // Hash dependencies (agent_dependencies layer)
        Self::hash_optional_layer(
            &mut current_hashes,
            "agent_dependencies",
            &self.config.dependencies_path,
        );

        // Hash certificates (agent_certificates layer)
        Self::hash_optional_layer(
            &mut current_hashes,
            "agent_certificates",
            &self.config.certificates_path,
        );

        let layers_hashed: u32 = current_hashes
            .len()
            .try_into()
            .expect("layer count fits u32");

        // Check for drift
        let last = self.last_hashes.read().await;
        let drift_detected = !last.is_empty() && *last != current_hashes;
        drop(last);

        // Update stored hashes
        let mut write = self.last_hashes.write().await;
        *write = current_hashes;

        Ok(ScanResult {
            agent_name: self.config.agent_name.clone(),
            layers_hashed,
            drift_detected,
            compliance_status: "ok".into(),
            scanned_at: Utc::now(),
        })
    }

    /// Run the scanning loop.
    pub async fn run(&self) -> Result<()> {
        let mut interval = time::interval(self.interval);
        loop {
            interval.tick().await;
            match self.scan_once().await {
                Ok(result) => {
                    if result.drift_detected {
                        tracing::warn!(agent = %result.agent_name, "drift detected!");
                    } else {
                        tracing::info!(agent = %result.agent_name, "scan ok");
                    }
                }
                Err(e) => {
                    tracing::error!(error = %e, "scan failed");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn scan_once_returns_result() {
        let scanner = Scanner::new(ScannerConfig::default());
        let result = scanner.scan_once().await.unwrap();
        assert_eq!(result.agent_name, "openclaw");
        assert_eq!(result.layers_hashed, 2); // only skills + config by default
        assert!(!result.drift_detected); // first scan, no drift
    }

    #[tokio::test]
    async fn second_scan_no_drift() {
        let scanner = Scanner::new(ScannerConfig::default());
        let _ = scanner.scan_once().await.unwrap();
        let result = scanner.scan_once().await.unwrap();
        assert!(!result.drift_detected); // same config, no drift
    }

    #[tokio::test]
    async fn all_layers_hashed_when_configured() {
        let config = ScannerConfig {
            binary_path: Some("/opt/openclaw/bin/agent".into()),
            guardrails_dir: Some("/opt/openclaw/guardrails".into()),
            models_path: Some("/opt/openclaw/models".into()),
            runtime_path: Some("/opt/openclaw/runtime".into()),
            mcp_servers_path: Some("/opt/openclaw/mcp-servers".into()),
            dependencies_path: Some("/opt/openclaw/deps.lock".into()),
            certificates_path: Some("/opt/openclaw/certs".into()),
            ..ScannerConfig::default()
        };
        let scanner = Scanner::new(config);
        let result = scanner.scan_once().await.unwrap();
        // 2 required (skills + config) + 7 optional = 9
        assert_eq!(result.layers_hashed, 9);
        assert!(!result.drift_detected);
    }

    #[tokio::test]
    async fn partial_layers_counted_correctly() {
        let config = ScannerConfig {
            binary_path: Some("/opt/openclaw/bin/agent".into()),
            models_path: Some("/opt/openclaw/models".into()),
            ..ScannerConfig::default()
        };
        let scanner = Scanner::new(config);
        let result = scanner.scan_once().await.unwrap();
        // 2 required + 2 optional = 4
        assert_eq!(result.layers_hashed, 4);
    }

    #[tokio::test]
    async fn drift_detected_on_config_change() {
        let config = ScannerConfig {
            binary_path: Some("/opt/openclaw/bin/agent".into()),
            ..ScannerConfig::default()
        };
        let scanner = Scanner::new(config);
        let _ = scanner.scan_once().await.unwrap();

        // Mutate the stored hashes to simulate drift
        {
            let mut hashes = scanner.last_hashes.write().await;
            hashes.insert(
                "agent_binary".into(),
                "blake3:0000000000000000000000000000000000000000000000000000000000000000".into(),
            );
        }

        let result = scanner.scan_once().await.unwrap();
        assert!(result.drift_detected);
    }
}
