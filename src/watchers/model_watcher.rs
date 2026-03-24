use crate::error::Result;
use tokio::sync::mpsc;

#[derive(Clone, Debug)]
pub struct ModelChangeEvent {
    pub provider: String,
    pub model_id: String,
}

pub async fn watch_models(
    tx: mpsc::Sender<ModelChangeEvent>,
) -> Result<()> {
    tracing::info!("model watcher started");
    let _ = tx;
    Ok(())
}
