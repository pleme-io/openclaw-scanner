//! Continuous re-attestation — Phase 10.
//!
//! Re-runs the skill-evidence collector chain against an Active
//! `CompliantListing<SkillKind>` and detects drift. Any mismatch
//! between a recomputed evidence hash and the listing's bound hash
//! signals that the underlying skill has changed since publish — the
//! scanner emits a `DriftDetected` event and the listing is moved to
//! `Quarantined` (manual operator review) or `Revoked` (auto, when
//! drift severity is critical).
//!
//! Phase 10 scope: the typed primitives + verification logic. The
//! actual subscription loop (HTTP/WebSocket to the store, periodic
//! poll) lives in `daemon.rs` and gets wired in Phase 10b.

use serde::{Deserialize, Serialize};

/// Typed verdict from re-attesting a single Active listing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReattestationVerdict {
    /// Every collector report's evidence hash matches the bound value
    /// in the listing's verdicts. Listing remains Active.
    NoDrift {
        listing_id: String,
        rescanned_at: chrono::DateTime<chrono::Utc>,
    },
    /// Source / scanner output / SBOM changed since publish. Listing
    /// must be moved to Quarantined for operator review.
    Drift {
        listing_id: String,
        rescanned_at: chrono::DateTime<chrono::Utc>,
        drift_evidence: Vec<DriftEvidence>,
    },
    /// Listing's underlying source was deleted / publisher revoked /
    /// store entry corrupt. Auto-revoke.
    Unrecoverable {
        listing_id: String,
        rescanned_at: chrono::DateTime<chrono::Utc>,
        reason: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DriftEvidence {
    pub collector_id: String,
    pub control_id: String,
    pub bound_hash: String,
    pub recomputed_hash: String,
}

/// Compare each `(collector_id, evidence_hash)` pair from a re-run
/// against the bound values in the listing's verdicts. Returns drift
/// evidence for every mismatch.
///
/// Inputs:
/// - `bound`: `(control_id, expected evidence_hash hex)` pairs lifted
///   from the listing's verdicts at admission time.
/// - `recomputed`: same shape, freshly produced by re-running collectors.
#[must_use]
pub fn diff_evidence(
    bound: &[(String, String)],
    recomputed: &[(String, String)],
) -> Vec<DriftEvidence> {
    let mut drift = Vec::new();
    for (control_id, recomp_hash) in recomputed {
        let bound_hash = bound
            .iter()
            .find(|(c, _)| c == control_id)
            .map(|(_, h)| h.clone());
        match bound_hash {
            Some(bh) if bh == *recomp_hash => continue, // match, no drift
            Some(bh) => drift.push(DriftEvidence {
                collector_id: "unknown".into(),
                control_id: control_id.clone(),
                bound_hash: bh,
                recomputed_hash: recomp_hash.clone(),
            }),
            None => drift.push(DriftEvidence {
                collector_id: "unknown".into(),
                control_id: control_id.clone(),
                bound_hash: "<not bound>".into(),
                recomputed_hash: recomp_hash.clone(),
            }),
        }
    }
    drift
}

/// Top-level re-attestation entry: given a listing's bound evidence +
/// its re-run output, decide the listing's new lifecycle state.
#[must_use]
pub fn reattest(
    listing_id: &str,
    bound_evidence: &[(String, String)],
    recomputed_evidence: &[(String, String)],
) -> ReattestationVerdict {
    let drift = diff_evidence(bound_evidence, recomputed_evidence);
    let now = chrono::Utc::now();
    if drift.is_empty() {
        ReattestationVerdict::NoDrift {
            listing_id: listing_id.to_string(),
            rescanned_at: now,
        }
    } else {
        ReattestationVerdict::Drift {
            listing_id: listing_id.to_string(),
            rescanned_at: now,
            drift_evidence: drift,
        }
    }
}

/// Recommended next state for a listing given its re-attestation verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecommendedAction {
    KeepActive,
    Quarantine,
    Revoke,
}

#[must_use]
pub fn recommend_action(verdict: &ReattestationVerdict) -> RecommendedAction {
    match verdict {
        ReattestationVerdict::NoDrift { .. } => RecommendedAction::KeepActive,
        ReattestationVerdict::Drift { drift_evidence, .. } => {
            // Phase 10 policy: any drift = quarantine. Operators
            // re-publish a fresh CompliantListing if the change was
            // intentional. Phase 10b adds severity grading
            // (e.g., capability-scope drift = auto-revoke since it's a
            // privilege escalation; SBOM drift could be acceptable for
            // patch upgrades).
            if drift_evidence.is_empty() {
                RecommendedAction::KeepActive
            } else {
                RecommendedAction::Quarantine
            }
        }
        ReattestationVerdict::Unrecoverable { .. } => RecommendedAction::Revoke,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair(c: &str, h: &str) -> (String, String) {
        (c.to_string(), h.to_string())
    }

    #[test]
    fn no_drift_when_evidence_matches() {
        let bound = vec![pair("AC-2", "aaaa"), pair("SC-7", "bbbb")];
        let recomp = vec![pair("AC-2", "aaaa"), pair("SC-7", "bbbb")];
        let v = reattest("alice/test", &bound, &recomp);
        assert!(matches!(v, ReattestationVerdict::NoDrift { .. }));
        assert_eq!(recommend_action(&v), RecommendedAction::KeepActive);
    }

    #[test]
    fn drift_detected_on_mismatch() {
        let bound = vec![pair("AC-2", "aaaa")];
        let recomp = vec![pair("AC-2", "ffff")]; // changed!
        let v = reattest("alice/test", &bound, &recomp);
        match &v {
            ReattestationVerdict::Drift { drift_evidence, .. } => {
                assert_eq!(drift_evidence.len(), 1);
                assert_eq!(drift_evidence[0].control_id, "AC-2");
                assert_eq!(drift_evidence[0].bound_hash, "aaaa");
                assert_eq!(drift_evidence[0].recomputed_hash, "ffff");
            }
            _ => panic!("expected Drift verdict"),
        }
        assert_eq!(recommend_action(&v), RecommendedAction::Quarantine);
    }

    #[test]
    fn new_unbound_control_is_drift() {
        let bound = vec![pair("AC-2", "aaaa")];
        let recomp = vec![pair("AC-2", "aaaa"), pair("NEW.CTRL", "cccc")];
        let v = reattest("x", &bound, &recomp);
        assert!(matches!(v, ReattestationVerdict::Drift { .. }));
    }

    #[test]
    fn unrecoverable_recommends_revoke() {
        let v = ReattestationVerdict::Unrecoverable {
            listing_id: "x".into(),
            rescanned_at: chrono::Utc::now(),
            reason: "source deleted".into(),
        };
        assert_eq!(recommend_action(&v), RecommendedAction::Revoke);
    }
}
