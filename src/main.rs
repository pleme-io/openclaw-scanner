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

    // Spawn the HTTP status server alongside the daemon loop. Without
    // this, kubelet probes (chart default: HTTP /health on the port
    // exposed by `--port`) get connection-refused and crashloop the
    // pod even though the daemon itself is healthy. The router is
    // already defined in `api::routes` — just needs an axum::serve.
    let listen_addr = format!("0.0.0.0:{}", cli.port);
    let listener = match tokio::net::TcpListener::bind(&listen_addr).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!(error = %e, addr = %listen_addr, "failed to bind status port");
            std::process::exit(1);
        }
    };
    tracing::info!(addr = %listen_addr, "scanner status API listening");

    let api = tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, openclaw_scanner::api::routes::router()).await {
            tracing::error!(error = %e, "status API failed");
        }
    });

    let scanner = openclaw_scanner::daemon::Scanner::new(config);
    let daemon = tokio::spawn(async move {
        if let Err(e) = scanner.run().await {
            tracing::error!(error = %e, "scanner failed");
        }
    });

    tokio::select! {
        _ = api => tracing::warn!("status API exited"),
        _ = daemon => tracing::warn!("scanner daemon exited"),
    }
}
