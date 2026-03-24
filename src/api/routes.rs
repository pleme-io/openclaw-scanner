use axum::{Json, routing::get};

pub fn router() -> axum::Router {
    axum::Router::new()
        .route("/health", get(health))
        .route("/api/v1/status", get(status))
}

async fn health() -> &'static str {
    "ok"
}

async fn status() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "running",
        "version": env!("CARGO_PKG_VERSION"),
    }))
}
