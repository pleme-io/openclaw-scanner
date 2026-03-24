use crate::error::Result;
use std::path::Path;
use tokio::sync::mpsc;

#[derive(Clone, Debug)]
pub struct ConfigChangeEvent {
    pub path: String,
}

pub async fn watch_config(
    _path: &Path,
    tx: mpsc::Sender<ConfigChangeEvent>,
) -> Result<()> {
    tracing::info!("config watcher started");
    let _ = tx;
    Ok(())
}
