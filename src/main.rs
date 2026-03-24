use clap::Parser;

#[derive(Parser)]
#[command(name = "openclaw-scanner", about = "Continuous compliance scanner")]
struct Cli {
    /// Path to scanner config file
    #[arg(long)]
    config: Option<String>,

    /// Scan interval in seconds
    #[arg(long, default_value = "300")]
    interval: u64,

    /// Status API port
    #[arg(long, default_value = "9090")]
    port: u16,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();

    let config = openclaw_scanner::config::ScannerConfig {
        scan_interval_secs: cli.interval,
        listen_port: cli.port,
        ..Default::default()
    };

    tracing::info!(agent = %config.agent_name, "starting scanner");

    let scanner = openclaw_scanner::daemon::Scanner::new(config);
    if let Err(e) = scanner.run().await {
        tracing::error!(error = %e, "scanner failed");
    }
}
