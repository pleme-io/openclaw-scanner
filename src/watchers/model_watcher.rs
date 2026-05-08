use async_graphql::SimpleObject;
use crate::error::Result;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::Duration;
use tokio::sync::mpsc;

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema, SimpleObject)]
pub struct ModelChangeEvent {
    pub provider: String,
    pub model_id: String,
}

/// Configuration for the model watcher polling loop.
pub struct ModelWatcherConfig {
    /// Path to the models configuration file. If `None`, the watcher is a no-op.
    pub models_config_path: Option<PathBuf>,
    /// How often to poll the file for changes.
    pub poll_interval: Duration,
}

impl Default for ModelWatcherConfig {
    fn default() -> Self {
        Self {
            models_config_path: None,
            poll_interval: Duration::from_secs(30),
        }
    }
}

/// Watch a models configuration file for changes by polling its BLAKE3 hash.
///
/// If `config.models_config_path` is `None`, returns `Ok(())` immediately.
/// Otherwise spawns a tokio task that reads the file at the configured interval,
/// hashes it, and emits a `ModelChangeEvent` when the hash changes.
pub async fn watch_models(
    config: ModelWatcherConfig,
    tx: mpsc::Sender<ModelChangeEvent>,
) -> Result<()> {
    let path = match config.models_config_path {
        Some(p) => p,
        None => {
            tracing::info!("model watcher: no config path, skipping");
            return Ok(());
        }
    };

    let poll_interval = config.poll_interval;

    tokio::spawn(async move {
        let mut last_hash: Option<String> = None;
        loop {
            tokio::time::sleep(poll_interval).await;

            let contents = match tokio::fs::read_to_string(&path).await {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!(error = %e, "model watcher: failed to read config");
                    continue;
                }
            };

            let hash = blake3::hash(contents.as_bytes()).to_hex().to_string();

            if let Some(ref prev) = last_hash {
                if *prev != hash {
                    tracing::info!("model configuration changed");
                    let event = ModelChangeEvent {
                        provider: "config".into(),
                        model_id: path.display().to_string(),
                    };
                    if tx.send(event).await.is_err() {
                        tracing::debug!("model watcher: receiver dropped, stopping");
                        return;
                    }
                }
            }

            last_hash = Some(hash);
        }
    });

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn model_change_event_serde_roundtrip() {
        let event = ModelChangeEvent {
            provider: "openai".to_string(),
            model_id: "gpt-4o".to_string(),
        };
        let json = serde_json::to_string(&event).unwrap();
        let deserialized: ModelChangeEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.provider, event.provider);
        assert_eq!(deserialized.model_id, event.model_id);
    }

    #[test]
    fn model_change_event_fields() {
        let event = ModelChangeEvent {
            provider: "anthropic".to_string(),
            model_id: "claude-opus-4-6".to_string(),
        };
        assert_eq!(event.provider, "anthropic");
        assert_eq!(event.model_id, "claude-opus-4-6");
        let debug = format!("{event:?}");
        assert!(debug.contains("ModelChangeEvent"));
        assert!(debug.contains("anthropic"));
    }

    #[test]
    fn default_model_watcher_config() {
        let config = ModelWatcherConfig::default();
        assert!(config.models_config_path.is_none());
        assert_eq!(config.poll_interval, Duration::from_secs(30));
    }

    #[tokio::test]
    async fn watch_models_no_config_returns_ok() {
        let (tx, _rx) = tokio::sync::mpsc::channel(16);
        let config = ModelWatcherConfig::default();
        let result = watch_models(config, tx).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn watch_models_detects_change() {
        let dir = tempfile::tempdir().unwrap();
        let models_file = dir.path().join("models.json");
        std::fs::write(
            &models_file,
            r#"{"provider":"openai","model":"gpt-4o"}"#,
        )
        .unwrap();

        let (tx, mut rx) = tokio::sync::mpsc::channel(16);
        let config = ModelWatcherConfig {
            models_config_path: Some(models_file.clone()),
            poll_interval: Duration::from_millis(50),
        };
        watch_models(config, tx).await.unwrap();

        // Wait for first poll (establishes baseline)
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Modify the file
        std::fs::write(
            &models_file,
            r#"{"provider":"anthropic","model":"claude"}"#,
        )
        .unwrap();

        // Wait for second poll to detect change
        let event = tokio::time::timeout(Duration::from_secs(5), rx.recv()).await;
        assert!(event.is_ok());
        assert!(event.unwrap().is_some());
    }

    #[tokio::test]
    async fn watch_models_no_event_when_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        let models_file = dir.path().join("stable.json");
        std::fs::write(&models_file, r#"{"provider":"openai"}"#).unwrap();

        let (tx, mut rx) = tokio::sync::mpsc::channel(16);
        let config = ModelWatcherConfig {
            models_config_path: Some(models_file),
            poll_interval: Duration::from_millis(50),
        };
        watch_models(config, tx).await.unwrap();

        // Wait for several polls without modifying the file
        tokio::time::sleep(Duration::from_millis(250)).await;

        // No events should be queued
        let event = tokio::time::timeout(Duration::from_millis(100), rx.recv()).await;
        assert!(event.is_err(), "expected timeout (no change event)");
    }
}
