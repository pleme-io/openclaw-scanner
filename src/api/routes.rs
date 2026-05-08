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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    #[tokio::test]
    async fn router_has_health_route() {
        let app = router();
        let request = Request::builder()
            .uri("/health")
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn router_has_status_route() {
        let app = router();
        let request = Request::builder()
            .uri("/api/v1/status")
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
}
