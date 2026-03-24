use chrono::Utc;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditEntry {
    pub timestamp: String,
    pub event_type: String,
    pub agent_name: String,
    pub details: serde_json::Value,
}

/// Append an entry to the audit log.
pub fn create_audit_entry(
    event_type: &str,
    agent_name: &str,
    details: serde_json::Value,
) -> AuditEntry {
    AuditEntry {
        timestamp: Utc::now().to_rfc3339(),
        event_type: event_type.into(),
        agent_name: agent_name.into(),
        details,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_entry() {
        let entry = create_audit_entry("scan", "agent1", serde_json::json!({"drift": false}));
        assert_eq!(entry.event_type, "scan");
        assert_eq!(entry.agent_name, "agent1");
    }
}
