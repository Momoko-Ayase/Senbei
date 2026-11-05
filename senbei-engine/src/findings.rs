//! A bounded sink for post-recovery structural diagnostics.
//!
//! Every walker in the integrity and ELF-verification passes visits a table
//! whose entry count comes from the output's own headers. The entry loops are
//! already capped, but a corrupt table can make *every* entry a defect — a
//! relocation block of 32 Ki entries of an undefined type, a thunk table whose
//! names are all ciphertext, a `.rela.dyn` whose symbols all fall out of range.
//! Formatting one message per row allocates a string per row, so a crafted
//! image could exhaust memory long before the entry cap is reached.
//!
//! [`Findings`] bounds that: a caller creating one per directory/table gets at
//! most [`MAX_PER_TABLE`] messages plus a single line saying how many were
//! withheld. Real images have a handful of findings at most, so the cap never
//! hides anything a reader would act on — and the "suppressed" line means a
//! truncated list is never mistaken for an exhaustive one.

/// Maximum messages one table may contribute.
pub(crate) const MAX_PER_TABLE: usize = 16;

/// A message sink that stops recording — and stops the caller's expensive
/// per-entry work — once it is full.
pub(crate) struct Findings<'a> {
    out: &'a mut Vec<String>,
    budget: usize,
    suppressed: usize,
    /// A walker queried [`Findings::wants_more`] on a full sink, i.e. it
    /// abandoned rows it never examined. Distinct from `suppressed`, which
    /// counts messages that were formatted and dropped.
    skipped: bool,
    /// Drop everything and record nothing. Used by a walk that only needs a
    /// count (e.g. comparing an IAT's length against its lookup table), so it
    /// allocates nothing at all and never reports suppression.
    silent: bool,
}

impl<'a> Findings<'a> {
    /// A recording sink with room for [`MAX_PER_TABLE`] messages.
    pub(crate) fn new(out: &'a mut Vec<String>) -> Self {
        Self {
            out,
            budget: MAX_PER_TABLE,
            suppressed: 0,
            skipped: false,
            silent: false,
        }
    }

    /// A discard-everything sink borrowing the same output as `self`, for a
    /// sub-walk that only needs a count (the IAT-vs-lookup comparison).
    pub(crate) fn silenced(&mut self) -> Findings<'_> {
        Findings {
            out: self.out,
            budget: 0,
            suppressed: 0,
            skipped: false,
            silent: true,
        }
    }

    pub(crate) fn push(&mut self, message: impl Into<String>) {
        if self.silent {
            return;
        }
        if self.budget == 0 {
            self.suppressed += 1;
            return;
        }
        self.budget -= 1;
        self.out.push(message.into());
    }

    /// True while a further per-entry finding would still be recorded.
    ///
    /// Walkers gate the per-entry work on this so that once the report is full
    /// they stop classifying names / decoding entries instead of computing
    /// strings that would be dropped. Asking a full sink is itself the signal
    /// that rows were left unexamined: a walker that breaks out here never
    /// reaches [`Findings::push`], so nothing would otherwise record that the
    /// list is truncated. That is why this takes `&mut self` — the query marks
    /// the truncation, so [`Findings::finish`] can still say so.
    pub(crate) fn wants_more(&mut self) -> bool {
        if self.silent {
            return false;
        }
        if self.budget == 0 {
            self.skipped = true;
            return false;
        }
        true
    }

    /// Close the sink.
    ///
    /// Emits an exact count only for messages that were actually formatted and
    /// dropped. When a walker instead stopped early (its remaining rows were
    /// never checked, so no count exists to report), emits a generic line — the
    /// reader must not mistake a full list for an exhaustive one.
    pub(crate) fn finish(self) {
        if self.suppressed != 0 {
            self.out.push(format!(
                "{} further defect(s) in this table were suppressed",
                self.suppressed
            ));
        }
        if self.skipped {
            self.out
                .push("remaining entries in this table were not checked".to_owned());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sink_caps_messages_and_reports_the_remainder() {
        let mut out = Vec::new();
        let mut findings = Findings::new(&mut out);
        for index in 0..(MAX_PER_TABLE + 5) {
            findings.push(format!("defect {index}"));
        }
        findings.finish();
        assert_eq!(out.len(), MAX_PER_TABLE + 1, "{out:?}");
        assert!(out[MAX_PER_TABLE].contains("5 further defect(s)"));
    }

    #[test]
    fn sink_without_overflow_adds_no_summary_line() {
        let mut out = Vec::new();
        let mut findings = Findings::new(&mut out);
        findings.push("only defect");
        findings.finish();
        assert_eq!(out, ["only defect"]);
    }

    #[test]
    fn full_sink_stops_requesting_per_entry_work() {
        let mut out = Vec::new();
        let mut findings = Findings::new(&mut out);
        assert!(findings.wants_more());
        for index in 0..MAX_PER_TABLE {
            findings.push(format!("defect {index}"));
        }
        assert!(
            !findings.wants_more(),
            "a full sink must stop per-entry work"
        );
        findings.finish();
    }

    #[test]
    fn silent_sink_records_nothing_and_allocates_no_summary() {
        let mut out = Vec::new();
        {
            let mut parent = Findings::new(&mut out);
            let mut findings = parent.silenced();
            assert!(!findings.wants_more());
            for index in 0..(MAX_PER_TABLE * 4) {
                findings.push(format!("defect {index}"));
            }
            findings.finish();
        }
        assert!(out.is_empty(), "{out:?}");
    }

    #[test]
    fn early_exit_on_a_full_sink_still_marks_the_list_as_truncated() {
        // A walker that stops at `wants_more()` never calls `push`, so there is
        // no count to report — but the list is not exhaustive and `finish` must
        // say so, otherwise 16 findings look like the whole story.
        let mut out = Vec::new();
        let mut findings = Findings::new(&mut out);
        for index in 0..MAX_PER_TABLE {
            findings.push(format!("defect {index}"));
        }
        assert!(!findings.wants_more());
        findings.finish();
        assert_eq!(out.len(), MAX_PER_TABLE + 1, "{out:?}");
        assert_eq!(
            out[MAX_PER_TABLE], "remaining entries in this table were not checked",
            "a skipped tail gets a generic line, not an invented count"
        );
        assert!(
            !out[MAX_PER_TABLE].contains("0 further"),
            "a skipped tail must not claim a suppression count"
        );
    }

    #[test]
    fn sink_below_cap_marks_no_truncation_when_polled() {
        // Polling `wants_more` while there is budget must not by itself imply
        // truncation.
        let mut out = Vec::new();
        let mut findings = Findings::new(&mut out);
        for _ in 0..MAX_PER_TABLE {
            assert!(findings.wants_more());
            findings.push("defect");
        }
        findings.finish();
        assert_eq!(out.len(), MAX_PER_TABLE, "{out:?}");
        assert!(out.iter().all(|line| line.starts_with("defect")), "{out:?}");
    }

    #[test]
    fn dropped_messages_and_skipped_rows_report_both() {
        // A walker that both formatted-too-many and then gave up gets the exact
        // count for the dropped strings and the generic line for the unread
        // rows, in that order.
        let mut out = Vec::new();
        let mut findings = Findings::new(&mut out);
        for index in 0..(MAX_PER_TABLE + 3) {
            findings.push(format!("defect {index}"));
        }
        assert!(!findings.wants_more());
        findings.finish();
        assert_eq!(out.len(), MAX_PER_TABLE + 2, "{out:?}");
        assert!(
            out[MAX_PER_TABLE].contains("3 further defect(s)"),
            "{out:?}"
        );
        assert_eq!(
            out[MAX_PER_TABLE + 1],
            "remaining entries in this table were not checked"
        );
    }

    #[test]
    fn silent_sink_polling_marks_no_truncation() {
        let mut out = Vec::new();
        {
            let mut parent = Findings::new(&mut out);
            let mut findings = parent.silenced();
            assert!(!findings.wants_more());
            findings.finish();
        }
        assert!(out.is_empty(), "{out:?}");
    }

    #[test]
    fn zero_length_table_produces_nothing() {
        let mut out = Vec::new();
        Findings::new(&mut out).finish();
        assert!(out.is_empty());
    }
}
