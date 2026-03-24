use std::sync::atomic::{AtomicU64, Ordering};

/// Scanner metrics for Prometheus export.
pub struct ScannerMetrics {
    pub scans_total: AtomicU64,
    pub drift_events_total: AtomicU64,
    pub compliance_failures_total: AtomicU64,
}

impl ScannerMetrics {
    pub fn new() -> Self {
        Self {
            scans_total: AtomicU64::new(0),
            drift_events_total: AtomicU64::new(0),
            compliance_failures_total: AtomicU64::new(0),
        }
    }

    pub fn record_scan(&self) {
        self.scans_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_drift(&self) {
        self.drift_events_total.fetch_add(1, Ordering::Relaxed);
    }
}

impl Default for ScannerMetrics {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metrics_increment() {
        let m = ScannerMetrics::new();
        m.record_scan();
        m.record_scan();
        assert_eq!(m.scans_total.load(Ordering::Relaxed), 2);
    }
}
