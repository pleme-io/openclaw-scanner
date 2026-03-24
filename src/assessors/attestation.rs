use tameshi::hash::Blake3Hash;

/// Re-attest a layer by hashing its current content.
pub fn reattest_layer(layer_name: &str, content: &[u8]) -> String {
    let hash = Blake3Hash::digest(content);
    tracing::debug!(layer = layer_name, hash = %hash.to_prefixed(), "layer re-attested");
    hash.to_prefixed()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reattest_deterministic() {
        let h1 = reattest_layer("test", b"content");
        let h2 = reattest_layer("test", b"content");
        assert_eq!(h1, h2);
    }

    #[test]
    fn reattest_changes_with_content() {
        let h1 = reattest_layer("test", b"content1");
        let h2 = reattest_layer("test", b"content2");
        assert_ne!(h1, h2);
    }
}
