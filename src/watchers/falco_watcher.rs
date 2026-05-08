//! Falco watcher — subscribes to Falco gRPC output stream for runtime anomaly detection.
//!
//! When a Falco alert exceeds the configured priority threshold,
//! this watcher signals that a re-attestation should be triggered.

use async_graphql::SimpleObject;
use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Configuration for the Falco watcher.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema, SimpleObject)]
pub struct FalcoConfig {
    /// Falco gRPC endpoint.
    #[serde(default = "default_falco_url")]
    pub falco_url: String,
    /// Minimum priority level that triggers processing (e.g., "WARNING", "ERROR", "CRITICAL").
    #[serde(default = "default_priority_threshold")]
    pub priority_threshold: String,
    /// Whether to trigger re-attestation when an alert exceeds the threshold.
    #[serde(default = "default_re_attest_on_alert")]
    pub re_attest_on_alert: bool,
}

fn default_falco_url() -> String {
    "localhost:5060".into()
}

fn default_priority_threshold() -> String {
    "WARNING".into()
}

const fn default_re_attest_on_alert() -> bool {
    true
}

/// A Falco alert received from the gRPC stream.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema, SimpleObject)]
pub struct FalcoAlert {
    /// Name of the Falco rule that fired.
    pub rule: String,
    /// Priority level of the alert (e.g., "EMERGENCY", "ALERT", "CRITICAL",
    /// "ERROR", "WARNING", "NOTICE", "INFORMATIONAL", "DEBUG").
    pub priority: String,
    /// Human-readable output from the rule.
    pub output: String,
    /// Timestamp of the alert.
    pub timestamp: DateTime<Utc>,
    /// Hostname where the alert originated.
    pub hostname: Option<String>,
}

/// Watcher that monitors Falco gRPC output for runtime anomalies.
#[derive(Clone, Debug)]
pub struct FalcoWatcher {
    config: FalcoConfig,
}

/// Priority levels ordered from most to least severe.
const PRIORITY_ORDER: &[&str] = &[
    "EMERGENCY",
    "ALERT",
    "CRITICAL",
    "ERROR",
    "WARNING",
    "NOTICE",
    "INFORMATIONAL",
    "DEBUG",
];

impl FalcoWatcher {
    /// Create a new `FalcoWatcher` from the given config.
    #[must_use]
    pub fn new(config: FalcoConfig) -> Self {
        Self { config }
    }

    /// Returns the watcher configuration.
    #[must_use]
    pub fn config(&self) -> &FalcoConfig {
        &self.config
    }

    /// Determine whether a given alert should trigger re-attestation.
    ///
    /// An alert triggers re-attestation when:
    /// 1. `re_attest_on_alert` is enabled in the config.
    /// 2. The alert's priority meets or exceeds the configured threshold.
    #[must_use]
    pub fn should_trigger_reattestation(&self, alert: &FalcoAlert) -> bool {
        if !self.config.re_attest_on_alert {
            return false;
        }
        priority_meets_threshold(&alert.priority, &self.config.priority_threshold)
    }
}

/// Check whether `priority` is at least as severe as `threshold`.
///
/// Unknown priorities are treated as less severe than all known priorities.
fn priority_meets_threshold(priority: &str, threshold: &str) -> bool {
    let priority_upper = priority.to_uppercase();
    let threshold_upper = threshold.to_uppercase();

    let priority_idx = PRIORITY_ORDER
        .iter()
        .position(|&p| p == priority_upper);
    let threshold_idx = PRIORITY_ORDER
        .iter()
        .position(|&p| p == threshold_upper);

    match (priority_idx, threshold_idx) {
        (Some(p), Some(t)) => p <= t,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_alert(priority: &str) -> FalcoAlert {
        FalcoAlert {
            rule: "test_rule".into(),
            priority: priority.into(),
            output: "test output".into(),
            timestamp: Utc::now(),
            hostname: Some("node-1".into()),
        }
    }

    #[test]
    fn config_defaults() {
        let json = "{}";
        let config: FalcoConfig = serde_json::from_str(json).expect("deserialize");
        assert_eq!(config.falco_url, "localhost:5060");
        assert_eq!(config.priority_threshold, "WARNING");
        assert!(config.re_attest_on_alert);
    }

    #[test]
    fn priority_filtering_triggers_above_threshold() {
        let config = FalcoConfig {
            falco_url: "localhost:5060".into(),
            priority_threshold: "WARNING".into(),
            re_attest_on_alert: true,
        };
        let watcher = FalcoWatcher::new(config);

        // CRITICAL is more severe than WARNING -> should trigger
        assert!(watcher.should_trigger_reattestation(&make_alert("CRITICAL")));
        // ERROR is more severe than WARNING -> should trigger
        assert!(watcher.should_trigger_reattestation(&make_alert("ERROR")));
        // WARNING equals threshold -> should trigger
        assert!(watcher.should_trigger_reattestation(&make_alert("WARNING")));
        // NOTICE is less severe than WARNING -> should NOT trigger
        assert!(!watcher.should_trigger_reattestation(&make_alert("NOTICE")));
        // DEBUG is less severe -> should NOT trigger
        assert!(!watcher.should_trigger_reattestation(&make_alert("DEBUG")));
    }

    #[test]
    fn re_attest_disabled_never_triggers() {
        let config = FalcoConfig {
            falco_url: "localhost:5060".into(),
            priority_threshold: "WARNING".into(),
            re_attest_on_alert: false,
        };
        let watcher = FalcoWatcher::new(config);

        assert!(!watcher.should_trigger_reattestation(&make_alert("EMERGENCY")));
        assert!(!watcher.should_trigger_reattestation(&make_alert("CRITICAL")));
    }

    #[test]
    fn alert_serde_roundtrip() {
        let alert = make_alert("ERROR");
        let json = serde_json::to_string(&alert).expect("serialize");
        let deser: FalcoAlert = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(deser.rule, "test_rule");
        assert_eq!(deser.priority, "ERROR");
        assert_eq!(deser.hostname, Some("node-1".into()));
    }

    #[test]
    fn case_insensitive_priority() {
        let config = FalcoConfig {
            falco_url: "localhost:5060".into(),
            priority_threshold: "warning".into(),
            re_attest_on_alert: true,
        };
        let watcher = FalcoWatcher::new(config);
        assert!(watcher.should_trigger_reattestation(&make_alert("Error")));
    }
}
