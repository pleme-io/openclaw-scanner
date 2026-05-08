use crate::error::Result;

/// Send a drift alert to a webhook URL.
pub async fn send_webhook_alert(url: &str, payload: &serde_json::Value) -> Result<()> {
    let client = reqwest::Client::new();
    client.post(url).json(payload).send().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn webhook_payload_is_json() {
        let payload = serde_json::json!({
            "alert_type": "drift",
            "agent_name": "test-agent",
            "layers_changed": ["agent_binary"],
        });
        assert!(payload.is_object());
        assert_eq!(payload["alert_type"], "drift");
        assert_eq!(payload["agent_name"], "test-agent");
        assert!(payload["layers_changed"].is_array());
    }

    #[test]
    fn send_webhook_alert_returns_future() {
        // Verify the async function exists and produces a Future<Output = Result<()>>.
        // We cannot await it without a real server, but the future is constructable.
        let payload = serde_json::json!({"test": true});
        let fut = super::send_webhook_alert("http://localhost:0/nonexistent", &payload);
        // Confirm the future type is correct by dropping it (never polled).
        drop(fut);
    }
}
