//! Verbose progress from the recovery pipelines.
//!
//! With `verbose` on, a pipeline reports each step and its technical detail
//! lines here instead of printing them. A front end installs a sink for its
//! thread with [`with_sink`] and receives them as [`Event`]s. Without a sink
//! they print as they always have: Windows pipelines to stdout, the Android
//! pipeline to stderr, step titles in the process language
//! ([`senbei_i18n::current`]). Detail lines are technical and stay English.

use std::cell::RefCell;
use std::fmt;

use senbei_i18n::{Localize, Step};

/// One verbose progress event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// A pipeline step. `position` is `(n, total)` for the numbered Windows
    /// steps and `None` for the Android stages.
    Step {
        step: Step,
        position: Option<(u8, u8)>,
    },
    /// A technical detail line in English, with its leading indentation.
    Detail(String),
}

type Sink = Box<dyn FnMut(&Event)>;

thread_local! {
    static SINK: RefCell<Option<Sink>> = const { RefCell::new(None) };
}

/// Send this thread's progress events to `sink` while `f` runs.
///
/// The previous sink, if any, is restored afterwards, also on panic.
/// Recovery runs on the calling thread, so events from parallel helpers are
/// never lost; the pipelines report only from the thread that called them.
pub fn with_sink<R>(sink: impl FnMut(&Event) + 'static, f: impl FnOnce() -> R) -> R {
    struct Restore(Option<Sink>);
    impl Drop for Restore {
        fn drop(&mut self) {
            let previous = self.0.take();
            SINK.with(|slot| *slot.borrow_mut() = previous);
        }
    }
    let previous = SINK.with(|slot| slot.borrow_mut().replace(Box::new(sink)));
    let _restore = Restore(previous);
    f()
}

/// Deliver `event` to this thread's sink. False when none is installed, in
/// which case the caller prints the line itself.
pub fn emit(event: &Event) -> bool {
    SINK.with(|slot| match slot.borrow_mut().as_mut() {
        Some(sink) => {
            sink(event);
            true
        }
        None => false,
    })
}

/// A numbered Windows pipeline step.
pub(crate) fn step(n: u8, total: u8, step: Step) {
    let event = Event::Step {
        step,
        position: Some((n, total)),
    };
    if !emit(&event)
        && let Event::Step { step, .. } = &event
    {
        println!("[{n}/{total}] {}", step.localize(senbei_i18n::current()));
    }
}

/// A Windows detail line.
pub(crate) fn detail(args: fmt::Arguments<'_>) {
    if !emit(&Event::Detail(args.to_string())) {
        println!("{args}");
    }
}

/// An Android pipeline stage.
pub(crate) fn stage(step: Step) {
    let event = Event::Step {
        step,
        position: None,
    };
    if !emit(&event)
        && let Event::Step { step, .. } = &event
    {
        eprintln!("{}", step.localize(senbei_i18n::current()));
    }
}

/// An Android detail line.
pub(crate) fn detail_err(args: fmt::Arguments<'_>) {
    if !emit(&Event::Detail(args.to_string())) {
        eprintln!("{args}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[test]
    fn a_sink_receives_events_and_is_removed_afterwards() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let sink_seen = Arc::clone(&seen);
        with_sink(
            move |event| sink_seen.lock().unwrap().push(event.clone()),
            || {
                step(1, 9, Step::DecryptHeader);
                detail(format_args!("  info[0] key = 0x{:08X}", 0x1234));
                stage(Step::AndroidPrimary);
            },
        );
        assert_eq!(
            *seen.lock().unwrap(),
            [
                Event::Step {
                    step: Step::DecryptHeader,
                    position: Some((1, 9)),
                },
                Event::Detail("  info[0] key = 0x00001234".to_owned()),
                Event::Step {
                    step: Step::AndroidPrimary,
                    position: None,
                },
            ]
        );
        assert!(!emit(&Event::Detail(String::new())));
    }

    #[test]
    fn nested_sinks_restore_the_outer_one_even_after_a_panic() {
        let outer = Arc::new(Mutex::new(0));
        let counted = Arc::clone(&outer);
        with_sink(
            move |_| *counted.lock().unwrap() += 1,
            || {
                let failed = std::panic::catch_unwind(|| {
                    with_sink(|_| {}, || panic!("synthetic unwind"));
                });
                assert!(failed.is_err());
                detail(format_args!("after"));
            },
        );
        assert_eq!(*outer.lock().unwrap(), 1);
    }
}
