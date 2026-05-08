//! SBOM assessor — runs Syft to generate a Software Bill of Materials,
//! hashes the output, and feeds the result to the tameshi `AgentDependencies` layer.

use async_graphql::SimpleObject;
use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use tameshi::hash::Blake3Hash;
use thiserror::Error;

/// Errors specific to SBOM assessment.
#[derive(Debug, Error)]
pub enum SbomError {
    #[error("syft execution failed: {0}")]
    SyftFailed(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// Configuration for the SBOM assessor.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema, SimpleObject)]
pub struct SbomConfig {
    /// Path to the target to scan (container image, directory, archive).
    pub target_path: String,
    /// Path to the syft binary.
    #[serde(default = "default_syft_binary")]
    pub syft_binary: String,
    /// SBOM output format passed to `syft -o`.
    #[serde(default = "default_sbom_format")]
    pub sbom_format: String,
}

fn default_syft_binary() -> String {
    "syft".into()
}

fn default_sbom_format() -> String {
    "cyclonedx-json".into()
}

/// Result of an SBOM assessment.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema, SimpleObject)]
pub struct SbomResult {
    /// BLAKE3 hash of the raw SBOM output.
    pub sbom_hash: String,
    /// Number of dependencies discovered by Syft.
    pub dependency_count: usize,
    /// Format the SBOM was generated in.
    pub format: String,
    /// Timestamp of generation.
    pub generated_at: DateTime<Utc>,
}

/// Assessor that invokes Syft and hashes the resulting SBOM.
#[derive(Clone, Debug)]
pub struct SbomAssessor {
    config: SbomConfig,
}

impl SbomAssessor {
    /// Create a new `SbomAssessor` from the given config.
    #[must_use]
    pub fn new(config: SbomConfig) -> Self {
        Self { config }
    }

    /// Run the SBOM assessment.
    ///
    /// Executes syft against the configured target, captures its stdout,
    /// computes a BLAKE3 hash, and returns the result.
    ///
    /// # Errors
    ///
    /// Returns `SbomError::SyftFailed` if syft exits with a non-zero code,
    /// or `SbomError::Io` if the subprocess cannot be spawned.
    pub async fn assess(&self) -> Result<SbomResult, SbomError> {
        let output = tokio::process::Command::new(&self.config.syft_binary)
            .arg(&self.config.target_path)
            .arg("-o")
            .arg(&self.config.sbom_format)
            .output()
            .await?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(SbomError::SyftFailed(stderr.into_owned()));
        }

        let sbom_hash = Blake3Hash::digest(&output.stdout).to_prefixed();

        // Rough dependency count: count top-level `"name"` keys in JSON output.
        let dependency_count = count_dependencies(&output.stdout);

        Ok(SbomResult {
            sbom_hash,
            dependency_count,
            format: self.config.sbom_format.clone(),
            generated_at: Utc::now(),
        })
    }
}

/// Rough heuristic: count occurrences of `"name":` in JSON output to estimate
/// the number of components/dependencies.
fn count_dependencies(raw: &[u8]) -> usize {
    let text = String::from_utf8_lossy(raw);
    text.matches("\"name\":").count()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_defaults() {
        let json = r#"{"target_path": "/app"}"#;
        let config: SbomConfig = serde_json::from_str(json).expect("deserialize");
        assert_eq!(config.syft_binary, "syft");
        assert_eq!(config.sbom_format, "cyclonedx-json");
        assert_eq!(config.target_path, "/app");
    }

    #[test]
    fn result_serde_roundtrip() {
        let result = SbomResult {
            sbom_hash: Blake3Hash::digest(b"test-sbom").to_prefixed(),
            dependency_count: 42,
            format: "cyclonedx-json".into(),
            generated_at: Utc::now(),
        };
        let json = serde_json::to_string(&result).expect("serialize");
        let deser: SbomResult = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(deser.sbom_hash, result.sbom_hash);
        assert_eq!(deser.dependency_count, 42);
        assert!(deser.sbom_hash.starts_with("blake3:"));
    }

    #[test]
    fn hash_determinism() {
        let content = b"identical sbom content";
        let h1 = Blake3Hash::digest(content).to_prefixed();
        let h2 = Blake3Hash::digest(content).to_prefixed();
        assert_eq!(h1, h2);

        let h3 = Blake3Hash::digest(b"different content").to_prefixed();
        assert_ne!(h1, h3);
    }

    #[test]
    fn count_dependencies_works() {
        let raw = br#"{"components":[{"name":"foo"},{"name":"bar"},{"name":"baz"}]}"#;
        assert_eq!(count_dependencies(raw), 3);
    }
}
