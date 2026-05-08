use crate::error::{Result, ScannerError};
use async_graphql::SimpleObject;
use notify::{Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::mpsc as std_mpsc;
use tokio::sync::mpsc;

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema, SimpleObject)]
pub struct ConfigChangeEvent {
    pub path: String,
}

/// Watch a config path for modifications and creations.
///
/// If the path is a file, watches the parent directory (non-recursive) so that
/// file-level events are captured. If the path is a directory, watches it
/// directly. Forwards matching events through the async mpsc sender.
///
/// The watcher runs in a background tokio task and this function returns
/// immediately after spawning it.
pub async fn watch_config(path: &Path, tx: mpsc::Sender<ConfigChangeEvent>) -> Result<()> {
    let (notify_tx, notify_rx) = std_mpsc::channel::<notify::Result<Event>>();

    let mut watcher = RecommendedWatcher::new(notify_tx, Config::default())
        .map_err(|e| ScannerError::Watcher(format!("failed to create config watcher: {e}")))?;

    // If path is a file, watch its parent directory; if a directory, watch it directly.
    let watch_path = if path.is_file() {
        path.parent().unwrap_or(path).to_path_buf()
    } else {
        path.to_path_buf()
    };

    watcher
        .watch(&watch_path, RecursiveMode::NonRecursive)
        .map_err(|e| ScannerError::Watcher(format!("failed to watch {}: {e}", watch_path.display())))?;

    tracing::info!(path = %watch_path.display(), "config watcher started");

    tokio::task::spawn_blocking(move || {
        // Keep `watcher` alive for the lifetime of this blocking task.
        let _watcher = watcher;

        for event_result in notify_rx {
            let event = match event_result {
                Ok(e) => e,
                Err(e) => {
                    tracing::warn!(error = %e, "config watcher notify error");
                    continue;
                }
            };

            let dominated = matches!(
                event.kind,
                EventKind::Modify(_) | EventKind::Create(_)
            );

            if !dominated {
                continue;
            }

            for event_path in &event.paths {
                let change = ConfigChangeEvent {
                    path: event_path.display().to_string(),
                };
                if tx.blocking_send(change).is_err() {
                    tracing::debug!("config watcher: receiver dropped, stopping");
                    return;
                }
            }
        }
    });

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_change_event_serde_roundtrip() {
        let event = ConfigChangeEvent {
            path: "/etc/openclaw/config.json".to_string(),
        };
        let json = serde_json::to_string(&event).unwrap();
        let deserialized: ConfigChangeEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.path, event.path);
    }

    #[test]
    fn config_change_event_has_path() {
        let event = ConfigChangeEvent {
            path: "/tmp/test.yaml".to_string(),
        };
        assert_eq!(event.path, "/tmp/test.yaml");
        let debug = format!("{event:?}");
        assert!(debug.contains("ConfigChangeEvent"));
        assert!(debug.contains("/tmp/test.yaml"));
    }

    #[tokio::test]
    async fn watch_detects_file_modification() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("config.json");
        std::fs::write(&file_path, "{}").unwrap();

        let (tx, mut rx) = tokio::sync::mpsc::channel(16);
        watch_config(file_path.as_path(), tx).await.unwrap();

        // Give watcher time to register
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        // Modify the file
        std::fs::write(&file_path, "{\"updated\": true}").unwrap();

        // Should receive an event
        let event = tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv()).await;
        assert!(event.is_ok());
        let event = event.unwrap().unwrap();
        assert!(event.path.contains("config.json"));
    }

    #[tokio::test]
    async fn watch_detects_file_creation() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("new-config.json");

        let (tx, mut rx) = tokio::sync::mpsc::channel(16);
        // Watch the directory, not the file (file doesn't exist yet)
        watch_config(dir.path(), tx).await.unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        std::fs::write(&file_path, "{}").unwrap();

        let event = tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv()).await;
        assert!(event.is_ok());
    }
}
