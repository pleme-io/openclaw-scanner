//! OPA assessor — evaluates Open Policy Agent Rego policies against attestation data.

use async_graphql::SimpleObject;
use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use tameshi::hash::Blake3Hash;
use thiserror::Error;

/// Errors specific to OPA assessment.
#[derive(Debug, Error)]
pub enum OpaError {
    #[error("OPA request failed: {0}")]
    RequestFailed(String),
    #[error("OPA response parse error: {0}")]
    ParseError(String),
    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),
}

/// Configuration for the OPA assessor.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema, SimpleObject)]
pub struct OpaConfig {
    /// Base URL of the OPA server.
    #[serde(default = "default_opa_url")]
    pub opa_url: String,
    /// Policy path to evaluate (e.g., `/v1/data/openclaw/allow`).
    pub policy_path: String,
    /// Optional BLAKE3 hash of the policy bundle for integrity tracking.
    pub bundle_hash: Option<String>,
}

fn default_opa_url() -> String {
    "http://localhost:8181".into()
}

/// Result of an OPA policy evaluation.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema, SimpleObject)]
pub struct OpaResult {
    /// Whether the policy allows the attestation.
    pub allowed: bool,
    /// List of violation messages from the policy.
    pub violations: Vec<String>,
    /// BLAKE3 hash of the policy response for auditability.
    pub policy_hash: String,
    /// Optional BLAKE3 hash of the policy bundle (propagated from config).
    pub bundle_hash: Option<String>,
    /// Timestamp of evaluation.
    pub evaluated_at: DateTime<Utc>,
}

/// Assessor that evaluates OPA Rego policies against attestation data.
#[derive(Clone, Debug)]
pub struct OpaAssessor {
    config: OpaConfig,
}

/// Internal representation of the OPA REST response.
#[derive(Debug, Deserialize)]
struct OpaResponse {
    result: Option<OpaDecision>,
}

#[derive(Debug, Deserialize)]
struct OpaDecision {
    #[serde(default)]
    allow: bool,
    #[serde(default)]
    violations: Vec<String>,
}

impl OpaAssessor {
    /// Create a new `OpaAssessor` from the given config.
    #[must_use]
    pub fn new(config: OpaConfig) -> Self {
        Self { config }
    }

    /// Evaluate the configured OPA policy against the provided attestation data.
    ///
    /// Sends a POST to the OPA REST API, parses the decision, and computes a
    /// BLAKE3 hash of the raw response body for auditability.
    ///
    /// # Errors
    ///
    /// Returns `OpaError::Http` on transport failure, `OpaError::RequestFailed`
    /// if the OPA server returns a non-success status, or `OpaError::ParseError`
    /// if the response body cannot be parsed.
    pub async fn evaluate(
        &self,
        attestation_data: &serde_json::Value,
    ) -> Result<OpaResult, OpaError> {
        let url = format!("{}{}", self.config.opa_url, self.config.policy_path);
        let input_body = serde_json::json!({ "input": attestation_data });

        let client = reqwest::Client::new();
        let response = client.post(&url).json(&input_body).send().await?;

        if !response.status().is_success() {
            return Err(OpaError::RequestFailed(format!(
                "OPA returned status {}",
                response.status()
            )));
        }

        let body_bytes = response.bytes().await?;
        let policy_hash = Blake3Hash::digest(&body_bytes).to_prefixed();

        let opa_response: OpaResponse = serde_json::from_slice(&body_bytes)
            .map_err(|e| OpaError::ParseError(e.to_string()))?;

        let decision = opa_response.result.unwrap_or(OpaDecision {
            allow: false,
            violations: vec!["no result from OPA".into()],
        });

        Ok(OpaResult {
            allowed: decision.allow,
            violations: decision.violations,
            policy_hash,
            bundle_hash: self.config.bundle_hash.clone(),
            evaluated_at: Utc::now(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_defaults() {
        let json = r#"{"policy_path": "/v1/data/openclaw/allow"}"#;
        let config: OpaConfig = serde_json::from_str(json).expect("deserialize");
        assert_eq!(config.opa_url, "http://localhost:8181");
        assert_eq!(config.policy_path, "/v1/data/openclaw/allow");
        assert!(config.bundle_hash.is_none());
    }

    #[test]
    fn result_serde_roundtrip() {
        let result = OpaResult {
            allowed: false,
            violations: vec!["missing attestation layer".into()],
            policy_hash: Blake3Hash::digest(b"policy-body").to_prefixed(),
            bundle_hash: Some(Blake3Hash::digest(b"bundle-content").to_prefixed()),
            evaluated_at: Utc::now(),
        };
        let json = serde_json::to_string(&result).expect("serialize");
        let deser: OpaResult = serde_json::from_str(&json).expect("deserialize");
        assert!(!deser.allowed);
        assert_eq!(deser.violations.len(), 1);
        assert_eq!(deser.policy_hash, result.policy_hash);
        assert!(deser.policy_hash.starts_with("blake3:"));
        assert!(deser.bundle_hash.is_some());
        assert!(deser.bundle_hash.unwrap().starts_with("blake3:"));
    }

    #[test]
    fn result_serde_roundtrip_no_bundle_hash() {
        let result = OpaResult {
            allowed: true,
            violations: vec![],
            policy_hash: Blake3Hash::digest(b"policy-body").to_prefixed(),
            bundle_hash: None,
            evaluated_at: Utc::now(),
        };
        let json = serde_json::to_string(&result).expect("serialize");
        let deser: OpaResult = serde_json::from_str(&json).expect("deserialize");
        assert!(deser.allowed);
        assert!(deser.bundle_hash.is_none());
    }

    #[test]
    fn violation_detection() {
        let response_json = r#"{"result": {"allow": false, "violations": ["no sbom", "expired cert"]}}"#;
        let parsed: OpaResponse = serde_json::from_str(response_json).expect("parse");
        let decision = parsed.result.expect("has result");
        assert!(!decision.allow);
        assert_eq!(decision.violations.len(), 2);
        assert_eq!(decision.violations[0], "no sbom");
        assert_eq!(decision.violations[1], "expired cert");
    }

    #[test]
    fn missing_result_yields_deny() {
        let response_json = r#"{}"#;
        let parsed: OpaResponse = serde_json::from_str(response_json).expect("parse");
        assert!(parsed.result.is_none());
    }
}
