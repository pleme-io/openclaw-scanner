use crate::error::Result;
use std::path::Path;
use tokio::sync::mpsc;

/// Watch event for skill directory changes.
#[derive(Clone, Debug)]
pub enum SkillEvent {
    Added(String),
    Modified(String),
    Removed(String),
}

/// Watch a skills directory for changes.
pub async fn watch_skills(
    _dir: &Path,
    tx: mpsc::Sender<SkillEvent>,
) -> Result<()> {
    // Placeholder — real impl uses notify crate
    tracing::info!("skill watcher started");
    let _ = tx;
    Ok(())
}
