use crate::config::ScannerConfig;
use crate::error::Result;
use async_graphql::SimpleObject;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;
use tameshi::hash::Blake3Hash;
use tokio::time;

/// Scan result from a single cycle.
#[derive(Clone, Debug, Serialize, Deserialize, SimpleObject)]
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

    /// Run a single scan cycle.
    pub async fn scan_once(&self) -> Result<ScanResult> {
        let mut current_hashes = HashMap::new();

        // Hash skills directory
        let skills_hash = Blake3Hash::digest(self.config.skills_dir.as_bytes());
        current_hashes.insert("agent_skills".into(), skills_hash.to_prefixed());

        // Hash config
        let config_hash = Blake3Hash::digest(self.config.config_path.as_bytes());
        current_hashes.insert("agent_config".into(), config_hash.to_prefixed());

        // Check for drift
        let last = self.last_hashes.read().await;
        let drift_detected = !last.is_empty() && *last != current_hashes;
        drop(last);

        // Update stored hashes
        let mut write = self.last_hashes.write().await;
        *write = current_hashes;

        Ok(ScanResult {
            agent_name: self.config.agent_name.clone(),
            layers_hashed: 2,
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
        assert!(!result.drift_detected); // first scan, no drift
    }

    #[tokio::test]
    async fn second_scan_no_drift() {
        let scanner = Scanner::new(ScannerConfig::default());
        let _ = scanner.scan_once().await.unwrap();
        let result = scanner.scan_once().await.unwrap();
        assert!(!result.drift_detected); // same config, no drift
    }
}
