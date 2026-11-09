//! Live progress and cancellation for front ends that show a run as it happens.
//!
//! The CLI prints its own lines and uses neither. A front end attaches both to
//! the [`Collector`](crate::report::Collector) it passes to a reporting run.

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::report::InputReport;

/// Receives a run's progress on the thread doing the work. Every method has an
/// empty default, so an observer implements only what it shows.
pub trait RunObserver: Send + Sync {
    /// The scan finished: `inputs` targets were found and will be processed.
    fn scanned(&self, _inputs: usize) {}

    /// Work on `path` began.
    fn input_started(&self, _path: &Path) {}

    /// A verbose pipeline event for the input being processed. Sent only when
    /// the run was started with `verbose`.
    fn progress(&self, _event: &senbei_engine::progress::Event) {}

    /// One input finished, as recorded before a dry run or an inspection
    /// drops its outputs. The files named by `outputs` and by each entry's
    /// `output` exist for the duration of this call; a dry run or an
    /// inspection deletes them when the run ends.
    fn produced(&self, _input: &InputReport) {}

    /// One input finished. This is the report the run keeps for it.
    fn input_finished(&self, _input: &InputReport) {}
}

/// A request to stop a run, checked before each input.
///
/// Cancelling never interrupts an input mid-recovery: the input in progress
/// finishes and is reported, and no later input starts.
#[derive(Debug, Clone, Default)]
pub struct CancelToken(Arc<AtomicBool>);

impl CancelToken {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn cancel(&self) {
        self.0.store(true, Ordering::Relaxed);
    }

    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Relaxed)
    }
}
