//! Scoped, bounded recovery trace for research inspection.
//!
//! A full static recovery is the only place that can report the values a
//! protection header merely declares: the chosen layout, stage seeds, key
//! offsets, decryptor tables, and per-section outcomes. [`with_research_trace`]
//! installs a thread-local sink around an existing recovery call, so the
//! pipelines can publish those values without changing their control flow or
//! their output bytes.
//!
//! The sink is deliberately small:
//!
//! * It belongs to the calling thread for the duration of the closure. Events
//!   emitted by worker threads are not collected (workers do not mutate shared
//!   pipeline state, and collecting there would need synchronization).
//! * It is bounded. Once the event limit is reached, further events are
//!   dropped and counted; the trace records that it is truncated rather than
//!   pretending the tail is absent.
//! * Emitting is a no-op when no sink is installed, so pipeline code can call
//!   the helpers unconditionally.
//!
//! Events carry an [`AddressSpace`] whenever an offset is reported. A working
//! image RVA, a decrypted payload offset, and a protected-file offset are not
//! interchangeable; naming the space keeps research output from silently
//! mixing them.

use std::cell::RefCell;

use serde::Serialize;

/// Event budget for one trace. A normal recovery emits a few dozen events;
/// the limit only exists so a corrupt or adversarial input cannot make the
/// research path allocate without bound.
pub(crate) const DEFAULT_MAX_EVENTS: usize = 4096;

/// Which address space an offset belongs to. Every offset is an absolute
/// position in its own space; none is an offset relative to another.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AddressSpace {
    /// Absolute byte position in the protected input file the caller supplied.
    /// Use this for every input-file position, including the protection
    /// header/key-table cells at `0x1000..0x1020`.
    FileOffset,
    /// Absolute byte position inside the protected header/key-table region,
    /// measured from the start of the input file (not the region). Retained
    /// for producers that want to distinguish that region; it is not limited
    /// to the first 4 KiB and it is never a region-relative offset.
    ProtectedHeaderOffset,
    /// Offset relative to the decrypted payload base (`info[3]`). Converting
    /// to a working-image RVA is `info[3] + DecodedPayloadOffset`; the value
    /// alone is not an RVA.
    DecodedPayloadOffset,
    /// RVA of the working image (same numbering as a mapped PE).
    WorkingImageRva,
}

/// Recovery stage that produced an event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResearchStage {
    Header,
    Payload,
    Pe32Shell,
    Pe32Stages,
    ExeStage1,
    ExeStage2,
    ExeStage3,
    ExeStage4,
    ExeStage5,
    Sections,
    Imports,
    Tls,
    Output,
    DllStages,
    Finalize,
}

/// Event payload. Scalars cover every observed field; `Range` is the common
/// `(start, length)` descriptor shape; `U32s` is a short word list (key
/// offsets, descriptor tuples) whose length is bounded by the caller.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TraceValue {
    U32(u32),
    U64(u64),
    Bool(bool),
    Text(String),
    U32s(Vec<u32>),
    Range { start: u64, length: u64 },
}

/// Address attached to an event, with the space that makes it unambiguous.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct TraceAddress {
    pub space: AddressSpace,
    pub offset: u64,
}

/// One traced recovery fact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ResearchEvent {
    pub stage: ResearchStage,
    pub name: &'static str,
    pub value: TraceValue,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<TraceAddress>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<&'static str>,
}

/// Bounded collection of events from one scoped recovery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ResearchTrace {
    pub events: Vec<ResearchEvent>,
    /// True when at least one event did not fit the limit.
    pub truncated: bool,
    /// Number of events dropped after the limit was reached.
    pub dropped: u64,
    pub limit: usize,
}

impl ResearchTrace {
    fn empty() -> Self {
        Self {
            events: Vec::new(),
            truncated: false,
            dropped: 0,
            limit: DEFAULT_MAX_EVENTS,
        }
    }
}

struct TraceSink {
    events: Vec<ResearchEvent>,
    dropped: u64,
    limit: usize,
}

impl TraceSink {
    fn new(limit: usize) -> Self {
        Self {
            events: Vec::new(),
            dropped: 0,
            limit,
        }
    }

    fn push(&mut self, event: ResearchEvent) {
        if self.events.len() < self.limit {
            self.events.push(event);
        } else {
            self.dropped = self.dropped.saturating_add(1);
        }
    }

    fn finish(self) -> ResearchTrace {
        ResearchTrace {
            events: self.events,
            truncated: self.dropped > 0,
            dropped: self.dropped,
            limit: self.limit,
        }
    }
}

thread_local! {
    static SINK: RefCell<Option<TraceSink>> = const { RefCell::new(None) };
}

/// Install a trace sink for the duration of `f`, returning the trace and the
/// closure result. Nested calls are scoped: the inner call collects only its
/// own events, and the outer sink resumes untouched afterward.
///
/// If `f` panics, the outer sink state is still restored by the guard; events
/// collected by the panicking scope are discarded.
pub fn with_research_trace<R>(f: impl FnOnce() -> R) -> (ResearchTrace, R) {
    with_research_trace_limited(DEFAULT_MAX_EVENTS, f)
}

/// [`with_research_trace`] with an explicit event budget. A zero budget
/// records no events but still reports `limit`/`dropped`, so callers can tell
/// "not collected" from "nothing discovered".
pub fn with_research_trace_limited<R>(
    max_events: usize,
    f: impl FnOnce() -> R,
) -> (ResearchTrace, R) {
    let guard = SinkGuard::install(max_events);
    let result = f();
    let trace = guard.finish();
    (trace, result)
}

struct SinkGuard {
    previous: Option<TraceSink>,
}

impl SinkGuard {
    fn install(max_events: usize) -> Self {
        let previous = SINK.with(|cell| cell.borrow_mut().take());
        SINK.with(|cell| *cell.borrow_mut() = Some(TraceSink::new(max_events)));
        Self { previous }
    }

    /// Take the collected events. Restoration of the previous sink is left to
    /// `Drop`, which runs exactly once whether `f` returned or unwound.
    fn finish(self) -> ResearchTrace {
        let sink = SINK.with(|cell| cell.borrow_mut().take());
        sink.map_or_else(ResearchTrace::empty, TraceSink::finish)
    }
}

impl Drop for SinkGuard {
    fn drop(&mut self) {
        // Always replace, including with `None`: an outermost scope that
        // unwinds must not leave its sink installed for the rest of the
        // thread's life. On the normal path `finish` has already taken the
        // current sink, so this only restores the enclosing one.
        SINK.with(|cell| *cell.borrow_mut() = self.previous.take());
    }
}

/// True when a trace is active on this thread. Use it to skip building values
/// that only the trace consumes (snapshots, `Vec`s of derived fields).
pub(crate) fn trace_enabled() -> bool {
    SINK.with(|cell| cell.borrow().is_some())
}

fn push(event: ResearchEvent) {
    SINK.with(|cell| {
        if let Some(sink) = cell.borrow_mut().as_mut() {
            sink.push(event);
        }
    });
}

/// Record an event without an address.
pub(crate) fn emit(stage: ResearchStage, name: &'static str, value: TraceValue) {
    push(ResearchEvent {
        stage,
        name,
        value,
        address: None,
        note: None,
    });
}

/// Record an event whose value is an offset in `space`.
pub(crate) fn emit_at(
    stage: ResearchStage,
    name: &'static str,
    value: TraceValue,
    space: AddressSpace,
    offset: u64,
) {
    push(ResearchEvent {
        stage,
        name,
        value,
        address: Some(TraceAddress { space, offset }),
        note: None,
    });
}

/// Record an event with a short fixed explanation.
pub(crate) fn emit_note(
    stage: ResearchStage,
    name: &'static str,
    value: TraceValue,
    note: &'static str,
) {
    push(ResearchEvent {
        stage,
        name,
        value,
        address: None,
        note: Some(note),
    });
}

/// Record a short text fact (candidate verdict, layout choice). Not for key
/// material or byte dumps.
pub(crate) fn emit_text(stage: ResearchStage, name: &'static str, text: impl Into<String>) {
    emit(stage, name, TraceValue::Text(text.into()));
}

pub(crate) fn emit_u32(stage: ResearchStage, name: &'static str, value: u32) {
    emit(stage, name, TraceValue::U32(value));
}

pub(crate) fn emit_u32_at(
    stage: ResearchStage,
    name: &'static str,
    value: u32,
    space: AddressSpace,
    offset: u64,
) {
    emit_at(stage, name, TraceValue::U32(value), space, offset);
}

pub(crate) fn emit_u64(stage: ResearchStage, name: &'static str, value: u64) {
    emit(stage, name, TraceValue::U64(value));
}

pub(crate) fn emit_bool(stage: ResearchStage, name: &'static str, value: bool) {
    emit(stage, name, TraceValue::Bool(value));
}

pub(crate) fn emit_u32s(stage: ResearchStage, name: &'static str, values: Vec<u32>) {
    emit(stage, name, TraceValue::U32s(values));
}

/// Record a `[start, start + length)` range in `space`.
pub(crate) fn emit_range(
    stage: ResearchStage,
    name: &'static str,
    space: AddressSpace,
    start: u64,
    length: u64,
) {
    push(ResearchEvent {
        stage,
        name,
        value: TraceValue::Range { start, length },
        address: Some(TraceAddress {
            space,
            offset: start,
        }),
        note: None,
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An outermost scope that unwinds must not leave its sink installed.
    #[test]
    fn outermost_unwind_clears_the_sink() {
        let caught = crate::catch_unwind_quiet(|| {
            let _ = with_research_trace(|| {
                emit_u32(ResearchStage::Header, "before_panic", 1);
                panic!("escaped scope");
            });
        });
        assert!(caught.is_err());
        assert!(!trace_enabled(), "an unwound scope must not keep a sink");

        // A later ordinary trace still works and collects only its own event.
        let (trace, ()) = with_research_trace(|| {
            emit_u32(ResearchStage::Header, "after", 2);
        });
        assert_eq!(
            trace
                .events
                .iter()
                .map(|event| event.name)
                .collect::<Vec<_>>(),
            ["after"]
        );
        assert!(!trace_enabled());
    }

    #[test]
    fn no_sink_means_no_collection() {
        assert!(!trace_enabled());
        emit_u32(ResearchStage::Header, "ignored", 1);
        let (trace, value) = with_research_trace(|| 7u32);
        assert_eq!(value, 7);
        assert!(trace.events.is_empty());
        assert!(!trace.truncated);
        assert!(!trace_enabled());
    }

    #[test]
    fn events_keep_stage_value_and_provenance() {
        let (trace, ()) = with_research_trace(|| {
            assert!(trace_enabled());
            emit_at(
                ResearchStage::Payload,
                "payload_source",
                TraceValue::U32(0x4E0),
                AddressSpace::FileOffset,
                0x14E0,
            );
            emit_range(
                ResearchStage::Sections,
                "block",
                AddressSpace::WorkingImageRva,
                0x1000,
                0x200,
            );
            emit_note(
                ResearchStage::Output,
                "layout",
                TraceValue::Text("compact".into()),
                "selected",
            );
            emit_u32s(ResearchStage::ExeStage2, "key_offsets", vec![1, 2, 3, 4]);
            emit_bool(ResearchStage::Finalize, "new_layout", true);
            emit_u64(ResearchStage::Finalize, "output_len", 0x2000);
        });
        assert_eq!(trace.events.len(), 6);
        assert_eq!(trace.events[0].stage, ResearchStage::Payload);
        assert_eq!(trace.events[0].name, "payload_source");
        assert_eq!(trace.events[0].value, TraceValue::U32(0x4E0));
        assert_eq!(
            trace.events[0].address,
            Some(TraceAddress {
                space: AddressSpace::FileOffset,
                offset: 0x14E0
            })
        );
        assert_eq!(
            trace.events[1].address,
            Some(TraceAddress {
                space: AddressSpace::WorkingImageRva,
                offset: 0x1000
            })
        );
        assert_eq!(
            trace.events[1].value,
            TraceValue::Range {
                start: 0x1000,
                length: 0x200
            }
        );
        assert_eq!(trace.events[2].note, Some("selected"));
        assert_eq!(trace.events[3].value, TraceValue::U32s(vec![1, 2, 3, 4]));
        assert_eq!(trace.events[4].value, TraceValue::Bool(true));
        assert_eq!(trace.events[5].value, TraceValue::U64(0x2000));
        assert!(!trace.truncated);
    }

    #[test]
    fn nested_traces_are_scoped_and_the_outer_sink_resumes() {
        let (outer, inner) = with_research_trace(|| {
            emit_u32(ResearchStage::Header, "outer_before", 1);
            let inner = with_research_trace(|| {
                emit_u32(ResearchStage::Header, "inner", 2);
            });
            assert!(trace_enabled(), "outer sink must be restored");
            emit_u32(ResearchStage::Header, "outer_after", 3);
            inner
        });
        assert_eq!(
            inner
                .0
                .events
                .iter()
                .map(|event| event.name)
                .collect::<Vec<_>>(),
            ["inner"]
        );
        assert_eq!(
            outer
                .events
                .iter()
                .map(|event| event.name)
                .collect::<Vec<_>>(),
            ["outer_before", "outer_after"]
        );
        assert!(!trace_enabled());
    }

    #[test]
    fn full_sink_drops_and_reports_truncation() {
        let (trace, ()) = with_research_trace(|| {
            for index in 0..=DEFAULT_MAX_EVENTS {
                emit_u32(
                    ResearchStage::Header,
                    "event",
                    u32::try_from(index).expect("fits"),
                );
            }
        });
        assert_eq!(trace.events.len(), DEFAULT_MAX_EVENTS);
        assert_eq!(trace.limit, DEFAULT_MAX_EVENTS);
        assert_eq!(trace.dropped, 1);
        assert!(trace.truncated);
    }

    #[test]
    fn explicit_budget_limits_and_reports_drops() {
        let (trace, ()) = with_research_trace_limited(2, || {
            emit_u32(ResearchStage::Header, "a", 1);
            emit_u32(ResearchStage::Header, "b", 2);
            emit_u32(ResearchStage::Header, "c", 3);
        });
        assert_eq!(trace.limit, 2);
        assert_eq!(trace.events.len(), 2);
        assert_eq!(trace.dropped, 1);
        assert!(trace.truncated);

        let (trace, ()) = with_research_trace_limited(0, || {
            emit_u32(ResearchStage::Header, "a", 1);
        });
        assert_eq!(trace.limit, 0);
        assert!(trace.events.is_empty());
        assert_eq!(trace.dropped, 1);
        assert!(trace.truncated);
    }

    #[test]
    fn serialized_trace_uses_snake_case_and_omits_empty_provenance() {
        let (trace, ()) = with_research_trace(|| {
            emit_u32_at(
                ResearchStage::ExeStage5,
                "file_lfsr",
                0x1234,
                AddressSpace::WorkingImageRva,
                0x1234,
            );
            emit_u32(ResearchStage::Finalize, "output_len", 0x2000);
        });
        let value = serde_json::to_value(&trace).expect("trace serializes");
        assert_eq!(value["limit"], DEFAULT_MAX_EVENTS);
        assert_eq!(value["events"][0]["stage"], "exe_stage5");
        assert_eq!(
            value["events"][0]["value"],
            serde_json::json!({"u32": 0x1234})
        );
        assert_eq!(value["events"][0]["address"]["space"], "working_image_rva");
        assert_eq!(value["events"][0]["address"]["offset"], 0x1234);
        assert!(value["events"][1].get("address").is_none());
        assert!(value["events"][1].get("note").is_none());
    }
}
