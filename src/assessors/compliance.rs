use async_graphql::SimpleObject;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Result of a compliance assessment.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema, SimpleObject)]
pub struct ComplianceAssessment {
    pub framework: String,
    pub passed: bool,
    pub controls_checked: u32,
    pub controls_passed: u32,
    pub details: Vec<String>,
}

/// Run compliance assessment for given frameworks.
pub fn assess_compliance(frameworks: &[String]) -> Vec<ComplianceAssessment> {
    frameworks
        .iter()
        .map(|f| ComplianceAssessment {
            framework: f.clone(),
            passed: true, // default until framework-specific logic is added
            controls_checked: 0,
            controls_passed: 0,
            details: vec![],
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assess_returns_per_framework() {
        let result = assess_compliance(&["nist_ai_rmf".into(), "eu_ai_act".into()]);
        assert_eq!(result.len(), 2);
    }
}
