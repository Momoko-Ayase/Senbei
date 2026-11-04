//! Shared Android resource ceilings for extraction, restoration, and archives.
//!
//! These bounds reject an attacker-controlled size before the corresponding
//! allocation or file growth. They are per-allocation and per-task accounting
//! caps, not a measurement of peak resident memory: decoder scratch, Huffman
//! tables, and mapped inputs can exist at the same time.

/// Default ceiling for one ZIP entry, one decoder output, one writer source or
/// destination, one artifact read, and the restored output image.
pub const DEFAULT_MAX_ENTRY_BYTES: u64 = 2 << 30;
/// Default ceiling for the sum of retained or temporary bytes charged by one
/// extraction, restoration, or archive task.
pub const DEFAULT_MAX_TOTAL_BYTES: u64 = 8 << 30;
/// Default ceiling for ZIP entries and decoded stage-2 records in one task.
pub const DEFAULT_MAX_ENTRIES: usize = 100_000;
/// Default nesting ceiling. Depth `0` is the outermost container or stream, and
/// a depth equal to this value is still allowed.
pub const DEFAULT_MAX_DEPTH: usize = 32;

/// Overridable ceilings shared by Android extraction, restoration, and I/O.
///
/// Archive code uses the same type: `max_entry_bytes` bounds one streamed ZIP
/// entry, `max_total_bytes` bounds the sum of those entries, `max_entries`
/// bounds the entry count including nested archives, and `max_depth` bounds
/// archive nesting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResourceLimits {
    pub max_entry_bytes: u64,
    pub max_total_bytes: u64,
    pub max_entries: usize,
    pub max_depth: usize,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            max_entry_bytes: DEFAULT_MAX_ENTRY_BYTES,
            max_total_bytes: DEFAULT_MAX_TOTAL_BYTES,
            max_entries: DEFAULT_MAX_ENTRIES,
            max_depth: DEFAULT_MAX_DEPTH,
        }
    }
}

impl ResourceLimits {
    /// Numeric output ceiling passed into the crypto crate.
    #[must_use]
    pub fn output_limit(self) -> senbei_crypto::android::OutputLimit {
        senbei_crypto::android::OutputLimit {
            max_output_bytes: self.max_entry_bytes,
        }
    }

    /// Reject one allocation, entry, or output before it is reserved.
    pub fn check_entry_bytes(self, bytes: u64) -> std::result::Result<(), LimitExceeded> {
        if bytes > self.max_entry_bytes {
            return Err(LimitExceeded::Entry {
                requested: bytes,
                limit: self.max_entry_bytes,
            });
        }
        Ok(())
    }

    /// Reject a declared entry or record count before those records are stored.
    pub fn check_entries(self, count: usize) -> std::result::Result<(), LimitExceeded> {
        if count > self.max_entries {
            return Err(LimitExceeded::Entries {
                requested: count,
                limit: self.max_entries,
            });
        }
        Ok(())
    }

    /// Reject a nested container or stream whose depth exceeds the ceiling.
    ///
    /// `depth` is zero for the outermost item. `max_depth` itself is accepted.
    pub fn check_depth(self, depth: usize) -> std::result::Result<(), LimitExceeded> {
        if depth > self.max_depth {
            return Err(LimitExceeded::Depth {
                requested: depth,
                limit: self.max_depth,
            });
        }
        Ok(())
    }
}

/// A size or count that would exceed a [`ResourceLimits`] ceiling.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LimitExceeded {
    /// One entry or allocation is larger than `max_entry_bytes`.
    #[error("resource limit: entry of {requested} bytes exceeds the {limit}-byte ceiling")]
    Entry { requested: u64, limit: u64 },
    /// Charging more bytes would pass `max_total_bytes`.
    #[error(
        "resource limit: task total of {requested} bytes exceeds the {limit}-byte ceiling (adding {adding} bytes)"
    )]
    Total {
        requested: u64,
        adding: u64,
        limit: u64,
    },
    /// An entry or record count passed `max_entries`.
    #[error("resource limit: {requested} entries exceed the ceiling of {limit}")]
    Entries { requested: usize, limit: usize },
    /// Nesting passed `max_depth`.
    #[error("resource limit: nesting depth {requested} exceeds the ceiling of {limit}")]
    Depth { requested: usize, limit: usize },
}

/// Running sum of retained or temporary bytes for one task.
///
/// Each call starts its own budget at zero. Charging checks the single-entry
/// ceiling and the task total, but it does not account for buffers that were
/// never charged, so it is not a peak-RSS budget.
#[derive(Debug, Clone)]
pub struct ByteBudget {
    limits: ResourceLimits,
    used: u64,
}

impl ByteBudget {
    #[must_use]
    pub fn new(limits: &ResourceLimits) -> Self {
        Self {
            limits: *limits,
            used: 0,
        }
    }

    #[must_use]
    pub fn used(&self) -> u64 {
        self.used
    }

    /// Reject `bytes` against the single-entry ceiling without charging it.
    pub fn check_entry(&self, bytes: u64) -> std::result::Result<(), LimitExceeded> {
        self.limits.check_entry_bytes(bytes)
    }

    /// Charge `bytes` against both the single-entry ceiling and the task total.
    pub fn charge(&mut self, bytes: u64) -> std::result::Result<(), LimitExceeded> {
        self.check_entry(bytes)?;
        self.charge_total(bytes)
    }

    /// Charge `bytes` against the task total only.
    ///
    /// Use this for a sum of pieces that were each already checked against the
    /// single-entry ceiling, such as several decoded records in one stream.
    pub fn charge_total(&mut self, bytes: u64) -> std::result::Result<(), LimitExceeded> {
        let requested = self
            .used
            .checked_add(bytes)
            .filter(|total| *total <= self.limits.max_total_bytes);
        match requested {
            Some(total) => {
                self.used = total;
                Ok(())
            }
            None => Err(LimitExceeded::Total {
                requested: self.used.saturating_add(bytes),
                adding: bytes,
                limit: self.limits.max_total_bytes,
            }),
        }
    }
}

/// Running count of entries or decoded records for one task.
#[derive(Debug, Clone)]
pub struct EntryBudget {
    limits: ResourceLimits,
    used: usize,
}

impl EntryBudget {
    #[must_use]
    pub fn new(limits: &ResourceLimits) -> Self {
        Self {
            limits: *limits,
            used: 0,
        }
    }

    #[must_use]
    pub fn used(&self) -> usize {
        self.used
    }

    /// Charge `count` additional entries against `max_entries`.
    pub fn charge(&mut self, count: usize) -> std::result::Result<(), LimitExceeded> {
        let requested = self
            .used
            .checked_add(count)
            .filter(|total| *total <= self.limits.max_entries);
        match requested {
            Some(total) => {
                self.used = total;
                Ok(())
            }
            None => Err(LimitExceeded::Entries {
                requested: self.used.saturating_add(count),
                limit: self.limits.max_entries,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_the_documented_ceilings() {
        let limits = ResourceLimits::default();
        assert_eq!(limits.max_entry_bytes, 2 << 30);
        assert_eq!(limits.max_total_bytes, 8 << 30);
        assert_eq!(limits.max_entries, 100_000);
        assert_eq!(limits.max_depth, 32);
        assert!(limits.check_entry_bytes(limits.max_entry_bytes).is_ok());
        assert!(limits.check_entries(limits.max_entries).is_ok());
        assert!(limits.check_depth(limits.max_depth).is_ok());
        assert!(
            limits
                .check_entry_bytes(limits.max_entry_bytes + 1)
                .is_err()
        );
        assert!(limits.check_depth(limits.max_depth + 1).is_err());
    }

    #[test]
    fn byte_budget_accepts_the_boundary_and_rejects_the_next_byte() {
        let limits = ResourceLimits {
            max_entry_bytes: 4,
            max_total_bytes: 8,
            max_entries: 2,
            max_depth: 1,
        };
        let mut budget = ByteBudget::new(&limits);
        budget.charge(4).unwrap();
        budget.charge_total(4).unwrap();
        assert_eq!(budget.used(), 8);
        assert!(matches!(
            budget.charge(5),
            Err(LimitExceeded::Entry { requested: 5, .. })
        ));
        assert!(matches!(
            budget.charge_total(1),
            Err(LimitExceeded::Total { .. })
        ));
        assert_eq!(budget.used(), 8);
    }

    #[test]
    fn entry_budget_rejects_the_count_past_the_ceiling() {
        let limits = ResourceLimits {
            max_entries: 2,
            ..ResourceLimits::default()
        };
        let mut budget = EntryBudget::new(&limits);
        budget.charge(2).unwrap();
        assert!(matches!(
            budget.charge(1),
            Err(LimitExceeded::Entries {
                requested: 3,
                limit: 2
            })
        ));
    }
}
