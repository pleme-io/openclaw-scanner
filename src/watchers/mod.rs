pub mod config_watcher;
pub mod falco_watcher;
pub mod model_watcher;
pub mod skill_watcher;

/// Trait for background watchers that can be started as async tasks.
pub trait Watcher: Send {
    /// Human-readable name of this watcher.
    fn name(&self) -> &str;

    /// Start the watcher, returning a join handle for the background task.
    fn start(self) -> tokio::task::JoinHandle<crate::error::Result<()>>;
}
