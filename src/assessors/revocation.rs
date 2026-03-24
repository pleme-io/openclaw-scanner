use crate::error::Result;

/// Check if any active skills have been revoked in the store.
pub async fn check_revocations(
    _store_url: &str,
    _skill_ids: &[String],
) -> Result<Vec<String>> {
    // Placeholder — real impl calls store API
    Ok(vec![])
}
