use crate::error::{Result, ScannerError};
use notify::{Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::mpsc as std_mpsc;
use tokio::sync::mpsc;

/// Watch event for skill directory changes.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SkillEvent {
    Added(String),
    Modified(String),
    Removed(String),
}

/// Extract a skill name from a file path's stem.
///
/// For example, `/skills/code-review.yaml` yields `"code-review"`.
fn skill_name_from_path(path: &Path) -> Option<String> {
    path.file_stem()
        .and_then(|s| s.to_str())
        .map(String::from)
}

/// Map a `notify::EventKind` to a `SkillEvent` constructor.
fn event_kind_to_skill_event(kind: &EventKind, name: String) -> Option<SkillEvent> {
    match kind {
        EventKind::Create(_) => Some(SkillEvent::Added(name)),
        EventKind::Modify(_) => Some(SkillEvent::Modified(name)),
        EventKind::Remove(_) => Some(SkillEvent::Removed(name)),
        _ => None,
    }
}

/// Watch a skills directory recursively for changes.
///
/// Creates a `notify::RecommendedWatcher` on the given directory and maps
/// filesystem events to `SkillEvent` variants. The watcher runs in a
/// background blocking task and this function returns immediately.
pub async fn watch_skills(dir: &Path, tx: mpsc::Sender<SkillEvent>) -> Result<()> {
    let (notify_tx, notify_rx) = std_mpsc::channel::<notify::Result<Event>>();

    let mut watcher = RecommendedWatcher::new(notify_tx, Config::default())
        .map_err(|e| ScannerError::Watcher(format!("failed to create skill watcher: {e}")))?;

    watcher
        .watch(dir, RecursiveMode::Recursive)
        .map_err(|e| ScannerError::Watcher(format!("failed to watch {}: {e}", dir.display())))?;

    tracing::info!(dir = %dir.display(), "skill watcher started");

    tokio::task::spawn_blocking(move || {
        // Keep `watcher` alive for the lifetime of this blocking task.
        let _watcher = watcher;

        for event_result in notify_rx {
            let event = match event_result {
                Ok(e) => e,
                Err(e) => {
                    tracing::warn!(error = %e, "skill watcher notify error");
                    continue;
                }
            };

            for event_path in &event.paths {
                let name = match skill_name_from_path(event_path) {
                    Some(n) => n,
                    None => continue,
                };

                let skill_event = match event_kind_to_skill_event(&event.kind, name) {
                    Some(e) => e,
                    None => continue,
                };

                if tx.blocking_send(skill_event).is_err() {
                    tracing::debug!("skill watcher: receiver dropped, stopping");
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
    fn skill_event_serde_roundtrip() {
        let variants = vec![
            SkillEvent::Added("new-skill".into()),
            SkillEvent::Modified("existing-skill".into()),
            SkillEvent::Removed("old-skill".into()),
        ];
        for event in variants {
            let json = serde_json::to_string(&event).unwrap();
            let deserialized: SkillEvent = serde_json::from_str(&json).unwrap();
            assert_eq!(
                serde_json::to_value(&deserialized).unwrap(),
                serde_json::to_value(&event).unwrap(),
            );
        }
    }

    #[test]
    fn skill_event_variants_distinct() {
        let added = serde_json::to_string(&SkillEvent::Added("s".into())).unwrap();
        let modified = serde_json::to_string(&SkillEvent::Modified("s".into())).unwrap();
        let removed = serde_json::to_string(&SkillEvent::Removed("s".into())).unwrap();
        assert_ne!(added, modified);
        assert_ne!(modified, removed);
        assert_ne!(added, removed);
    }

    #[test]
    fn skill_added_contains_name() {
        let event = SkillEvent::Added("code-review".into());
        match &event {
            SkillEvent::Added(name) => assert_eq!(name, "code-review"),
            _ => panic!("expected Added variant"),
        }
    }

    #[test]
    fn skill_name_extraction_from_path() {
        let path = Path::new("/skills/code-review.yaml");
        assert_eq!(skill_name_from_path(path), Some("code-review".into()));
    }

    #[test]
    fn skill_name_extraction_no_extension() {
        let path = Path::new("/skills/my-skill");
        assert_eq!(skill_name_from_path(path), Some("my-skill".into()));
    }

    #[test]
    fn skill_name_extraction_nested_path() {
        let path = Path::new("/opt/openclaw/skills/sub/deep-skill.json");
        assert_eq!(skill_name_from_path(path), Some("deep-skill".into()));
    }

    #[tokio::test]
    async fn watch_detects_skill_added() {
        let dir = tempfile::tempdir().unwrap();
        let (tx, mut rx) = tokio::sync::mpsc::channel(16);
        watch_skills(dir.path(), tx).await.unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        std::fs::write(dir.path().join("new-skill.yaml"), "name: new-skill").unwrap();

        let event = tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv()).await;
        assert!(event.is_ok());
        if let Some(SkillEvent::Added(name) | SkillEvent::Modified(name)) = event.unwrap() {
            assert_eq!(name, "new-skill");
        }
    }

    #[tokio::test]
    async fn watch_extracts_skill_name_from_stem() {
        let dir = tempfile::tempdir().unwrap();
        let (tx, mut rx) = tokio::sync::mpsc::channel(16);
        watch_skills(dir.path(), tx).await.unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        std::fs::write(dir.path().join("code-review.yaml"), "test").unwrap();

        let event = tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv()).await;
        assert!(event.is_ok());
        match event.unwrap().unwrap() {
            SkillEvent::Added(name) | SkillEvent::Modified(name) => {
                assert_eq!(name, "code-review");
            }
            SkillEvent::Removed(_) => {}
        }
    }
}
