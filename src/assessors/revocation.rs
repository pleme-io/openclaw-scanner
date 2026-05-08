use crate::error::{Result, ScannerError};
use serde::Deserialize;
use std::future::Future;

/// A single entry from the skill store API.
#[derive(Debug, Deserialize)]
struct SkillStoreEntry {
    id: String,
    status: String,
}

/// Trait for revocation checking, enabling mock implementations in tests.
pub trait RevocationChecker: Send + Sync {
    /// Check which of the given skill IDs have been revoked.
    fn check_revocations(
        &self,
        skill_ids: &[String],
    ) -> impl Future<Output = Result<Vec<String>>> + Send;
}

/// HTTP-based revocation checker that calls the skill store API.
pub struct HttpRevocationChecker {
    store_url: String,
    client: reqwest::Client,
}

impl HttpRevocationChecker {
    #[must_use]
    pub fn new(store_url: &str) -> Self {
        Self {
            store_url: store_url.to_string(),
            client: reqwest::Client::new(),
        }
    }
}

impl RevocationChecker for HttpRevocationChecker {
    async fn check_revocations(&self, skill_ids: &[String]) -> Result<Vec<String>> {
        if skill_ids.is_empty() {
            return Ok(vec![]);
        }

        let url = format!("{}/api/v1/skills", self.store_url);
        let response = self.client.get(&url).send().await?;

        if !response.status().is_success() {
            return Err(ScannerError::Assessment(format!(
                "skill store returned status {}",
                response.status()
            )));
        }

        let entries: Vec<SkillStoreEntry> = response.json().await?;

        let revoked: Vec<String> = entries
            .into_iter()
            .filter(|e| e.status == "revoked" && skill_ids.contains(&e.id))
            .map(|e| e.id)
            .collect();

        Ok(revoked)
    }
}

/// Mock revocation checker for testing.
pub struct MockRevocationChecker {
    revoked_ids: Vec<String>,
}

impl MockRevocationChecker {
    #[must_use]
    pub fn new(revoked_ids: Vec<String>) -> Self {
        Self { revoked_ids }
    }
}

impl RevocationChecker for MockRevocationChecker {
    async fn check_revocations(&self, skill_ids: &[String]) -> Result<Vec<String>> {
        if skill_ids.is_empty() {
            return Ok(vec![]);
        }
        Ok(self
            .revoked_ids
            .iter()
            .filter(|id| skill_ids.contains(id))
            .cloned()
            .collect())
    }
}

/// Convenience function that maintains the original API signature.
///
/// Creates an `HttpRevocationChecker` and delegates to it.
pub async fn check_revocations(store_url: &str, skill_ids: &[String]) -> Result<Vec<String>> {
    let checker = HttpRevocationChecker::new(store_url);
    checker.check_revocations(skill_ids).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn check_revocations_returns_empty_for_no_skills() {
        let result = check_revocations("https://store.example.com", &[])
            .await
            .unwrap();
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn mock_revoked_found() {
        let checker =
            MockRevocationChecker::new(vec!["skill-a".into(), "skill-c".into()]);
        let result = checker
            .check_revocations(&["skill-a".into(), "skill-b".into()])
            .await
            .unwrap();
        assert_eq!(result, vec!["skill-a".to_string()]);
    }

    #[tokio::test]
    async fn mock_all_active() {
        let checker = MockRevocationChecker::new(vec![]);
        let result = checker
            .check_revocations(&["skill-a".into(), "skill-b".into()])
            .await
            .unwrap();
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn mock_empty_input_skips() {
        let checker = MockRevocationChecker::new(vec!["skill-a".into()]);
        let result = checker.check_revocations(&[]).await.unwrap();
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn mock_unknown_ids_filtered() {
        let checker = MockRevocationChecker::new(vec!["skill-x".into()]);
        let result = checker
            .check_revocations(&["skill-a".into(), "skill-b".into()])
            .await
            .unwrap();
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn mock_multiple_revoked() {
        let checker = MockRevocationChecker::new(vec![
            "skill-a".into(),
            "skill-b".into(),
            "skill-c".into(),
        ]);
        let result = checker
            .check_revocations(&["skill-a".into(), "skill-b".into(), "skill-d".into()])
            .await
            .unwrap();
        assert_eq!(result.len(), 2);
        assert!(result.contains(&"skill-a".to_string()));
        assert!(result.contains(&"skill-b".to_string()));
    }
}
