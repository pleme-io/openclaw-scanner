use crate::error::Result;

/// Send a drift alert to a webhook URL.
pub async fn send_webhook_alert(url: &str, payload: &serde_json::Value) -> Result<()> {
    let client = reqwest::Client::new();
    client.post(url).json(payload).send().await?;
    Ok(())
}
