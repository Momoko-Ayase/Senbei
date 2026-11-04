//! Thread-scoped panic capture shared by the engines and native orchestration.

use std::cell::RefCell;
use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub(crate) struct PanicCapture(Arc<Mutex<Option<PanicDetails>>>);

#[derive(Clone)]
pub(crate) struct PanicDetails {
    pub message: String,
    pub file: String,
    pub line: u32,
    pub column: u32,
}

thread_local! {
    static ACTIVE_PANIC_CAPTURE: RefCell<Option<PanicCapture>> = const { RefCell::new(None) };
}

struct PanicCaptureGuard(Option<PanicCapture>);

impl Drop for PanicCaptureGuard {
    fn drop(&mut self) {
        ACTIVE_PANIC_CAPTURE.with(|slot| {
            slot.replace(self.0.take());
        });
    }
}

impl PanicCapture {
    pub(crate) fn new() -> Self {
        Self(Arc::new(Mutex::new(None)))
    }

    fn record(&self, info: &std::panic::PanicHookInfo<'_>) {
        let location = info.location();
        let details = PanicDetails {
            message: panic_message(info.payload()),
            file: location
                .map(|value| value.file().to_owned())
                .unwrap_or_else(|| "<unknown>".to_owned()),
            line: location.map_or(0, std::panic::Location::line),
            column: location.map_or(0, std::panic::Location::column),
        };
        let mut captured = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if captured.is_none() {
            *captured = Some(details);
        }
    }

    pub(crate) fn details(&self, payload: &(dyn std::any::Any + Send)) -> PanicDetails {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
            .unwrap_or_else(|| PanicDetails {
                message: panic_message(payload),
                file: "<unknown>".to_owned(),
                line: 0,
                column: 0,
            })
    }

    pub(crate) fn merge_from(&self, other: &Self) {
        let details = other
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let Some(details) = details else { return };
        let mut captured = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if captured.is_none() {
            *captured = Some(details);
        }
    }
}

fn panic_message(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(message) = payload.downcast_ref::<&str>() {
        (*message).to_owned()
    } else if let Some(message) = payload.downcast_ref::<String>() {
        message.clone()
    } else {
        "non-string panic payload".to_owned()
    }
}

pub(crate) fn install_hook() {
    static INSTALL: std::sync::Once = std::sync::Once::new();
    INSTALL.call_once(|| {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            let capture = ACTIVE_PANIC_CAPTURE
                .try_with(|slot| slot.try_borrow().ok().and_then(|slot| slot.clone()))
                .ok()
                .flatten();
            if let Some(capture) = capture {
                capture.record(info);
                // WebAssembly unwinding is unavailable: retain the browser's
                // diagnostic hook before the unrecoverable trap.
                #[cfg(target_arch = "wasm32")]
                previous(info);
            } else {
                previous(info);
            }
        }));
    });
}

pub(crate) fn current_panic_capture() -> Option<PanicCapture> {
    ACTIVE_PANIC_CAPTURE.with(|slot| slot.borrow().clone())
}

pub(crate) fn with_panic_capture<R>(capture: Option<PanicCapture>, f: impl FnOnce() -> R) -> R {
    let previous = ACTIVE_PANIC_CAPTURE.with(|slot| slot.replace(capture));
    let _guard = PanicCaptureGuard(previous);
    f()
}

/// Catch a native per-file panic without printing the process panic hook.
///
/// Suppression applies only to this thread and scope. The process hook is
/// installed once, chains to the host hook outside captures, and is never
/// replaced or restored by individual jobs. Nested engine captures and their
/// worker-thread diagnostics continue to work independently.
///
/// Allocation aborts and WebAssembly traps cannot be caught.
pub fn catch_unwind_quiet<R>(f: impl FnOnce() -> R) -> std::thread::Result<R> {
    install_hook();
    with_panic_capture(Some(PanicCapture::new()), || {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(f))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nested_captures_restore_the_outer_scope() {
        install_hook();
        let outer = PanicCapture::new();
        with_panic_capture(Some(outer.clone()), || {
            assert!(catch_unwind_quiet(|| panic!("inner panic")).is_err());
            let payload = std::panic::catch_unwind(|| panic!("outer panic")).unwrap_err();
            assert_eq!(outer.details(payload.as_ref()).message, "outer panic");
        });
        assert!(current_panic_capture().is_none());
    }

    #[test]
    fn captures_are_thread_local_and_unwind_safe() {
        install_hook();
        let workers: Vec<_> = (0..8)
            .map(|index| {
                std::thread::spawn(move || {
                    let capture = PanicCapture::new();
                    let payload = with_panic_capture(Some(capture.clone()), || {
                        std::panic::catch_unwind(|| panic!("worker {index}"))
                    })
                    .unwrap_err();
                    assert!(current_panic_capture().is_none());
                    let details = capture.details(payload.as_ref());
                    assert_eq!(details.message, format!("worker {index}"));
                    assert!(details.file.ends_with("panic_capture.rs"));
                    assert!(details.line > 0);
                    assert!(details.column > 0);
                })
            })
            .collect();
        for worker in workers {
            worker.join().unwrap();
        }
    }
}
